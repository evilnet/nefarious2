/*
 * store_job_cmocka.c - a read of a store, run on the thread pool
 *
 * store_job.c moves a long store read (the federated SEARCH responder's
 * scan) off the main loop.  What can go wrong is all in who runs what,
 * where and how often, so that is what these cases pin down:
 *
 *  - no pool, or a pool that is not running: the job runs on the caller,
 *    unmuted, and is answered before store_job_start() returns;
 *  - a running pool: run() on a worker with its logging muted (and the
 *    worker handed back unmuted), done() on the main thread;
 *  - the cap: one worker stays free of reads, the jobs over the cap wait
 *    in order, and past STORE_JOBS_WAIT_MAX a job runs on the caller;
 *  - the link gone while a job waits, is queued in the pool, or runs: the
 *    job loses its link, and one no worker has started never runs;
 *  - the store closing (store_jobs_quiesce): waits for the job a worker is
 *    running, cancels the rest, and nothing runs afterwards;
 *  - the pool shutting down with a job still queued: abandoned and
 *    answered once, never run.
 *
 * In every case: exactly one of run() and abandon(), then done() exactly
 * once.  Links the REAL ../store_job.o and ../thread_pool.o; the store is
 * a counter.  Clean under -fsanitize=thread.
 */
#include "config.h"

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#include "ircd_log.h"
#include "store_job.h"
#include "thread_pool.h"

/* ------------------------------------------------------------------ */
/* The ircd around the two objects                                     */
/* ------------------------------------------------------------------ */

int log_inassert;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

static __thread int thread_muted;

void log_thread_mute(int on) { thread_muted = on ? 1 : 0; }
int log_thread_muted(void) { return thread_muted; }

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  (void)type; (void)file; (void)line;
  return malloc(len);
}

void *DoMallocZero(size_t len, const char *type, const char *file, int line)
{
  (void)type; (void)file; (void)line;
  return calloc(1, len);
}

/* ------------------------------------------------------------------ */
/* A job that records who called what                                  */
/* ------------------------------------------------------------------ */

/** Guards every record below: run() writes them from a worker. */
static pthread_mutex_t rec_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rec_cond = PTHREAD_COND_INITIALIZER;
/** While closed, run() (and a blocker task) waits inside. */
static int gate_open;
static int inside;          /**< run() calls waiting at the gate or past it */
static int running_now, running_max;
static int run_seq;         /**< run() calls started so far */
static int done_seq;        /**< done() calls so far */
static int store_closed;    /**< set when the test "closes the store" */
static int ran_after_close; /**< a run() started after that */

struct TJob {
  struct StoreJob job;      /* first: the module hands this back */
  int runs, abandons, dones;
  int run_order;            /**< 1-based run() start order */
  int done_order;
  int done_ran;             /**< done()'s @a ran */
  const void *done_link;    /**< the link as done() saw it */
  int run_on_main, run_muted;
  int done_on_main;
  int handle;               /**< the "store handle": 1 while held */
};

static pthread_t main_thread;

static void t_run(struct StoreJob *j)
{
  struct TJob *t = (struct TJob *)j;

  pthread_mutex_lock(&rec_mutex);
  t->runs++;
  t->run_order = ++run_seq;
  t->run_on_main = pthread_equal(pthread_self(), main_thread);
  t->run_muted = log_thread_muted();
  if (store_closed)
    ran_after_close++;
  inside++;
  if (++running_now > running_max)
    running_max = running_now;
  pthread_cond_broadcast(&rec_cond);
  /* The main thread never waits: it is the one that opens the gate. */
  while (!gate_open && !t->run_on_main)
    pthread_cond_wait(&rec_cond, &rec_mutex);
  running_now--;
  t->handle--;              /* run() gives the handle back */
  pthread_mutex_unlock(&rec_mutex);
}

static void t_abandon(struct StoreJob *j)
{
  struct TJob *t = (struct TJob *)j;

  assert_true(pthread_equal(pthread_self(), main_thread));
  pthread_mutex_lock(&rec_mutex);
  t->abandons++;
  t->handle--;
  pthread_mutex_unlock(&rec_mutex);
}

static void t_done(struct StoreJob *j, int ran)
{
  struct TJob *t = (struct TJob *)j;

  pthread_mutex_lock(&rec_mutex);
  t->dones++;
  t->done_order = ++done_seq;
  t->done_ran = ran;
  t->done_link = j->link;
  t->done_on_main = pthread_equal(pthread_self(), main_thread);
  pthread_mutex_unlock(&rec_mutex);
}

static const struct StoreJobOps t_ops = { t_run, t_abandon, t_done };

static void tjob_init(struct TJob *t, const void *link)
{
  memset(t, 0, sizeof(*t));
  t->job.ops = &t_ops;
  t->job.link = link;
  t->handle = 1;
}

/** One of run() and abandon(), done() once, the handle given back once. */
static void assert_finished(struct TJob *t, int ran)
{
  pthread_mutex_lock(&rec_mutex);
  assert_int_equal(t->dones, 1);
  assert_int_equal(t->runs, ran ? 1 : 0);
  assert_int_equal(t->abandons, ran ? 0 : 1);
  assert_int_equal(t->done_ran, ran ? 1 : 0);
  assert_int_equal(t->handle, 0);
  assert_true(t->done_on_main);
  pthread_mutex_unlock(&rec_mutex);
}

static void set_gate(int open)
{
  pthread_mutex_lock(&rec_mutex);
  gate_open = open;
  pthread_cond_broadcast(&rec_cond);
  pthread_mutex_unlock(&rec_mutex);
}

/** Wait until @a n run() calls (or blockers) are inside. */
static void wait_inside(int n)
{
  pthread_mutex_lock(&rec_mutex);
  while (inside < n)
    pthread_cond_wait(&rec_cond, &rec_mutex);
  pthread_mutex_unlock(&rec_mutex);
}

static int dones_of(struct TJob *t)
{
  int n;

  pthread_mutex_lock(&rec_mutex);
  n = t->dones;
  pthread_mutex_unlock(&rec_mutex);
  return n;
}

/** The main loop: deliver finished jobs until @a t is answered. */
static void poll_until_done(struct TJob *t)
{
  int spins = 0;

  while (!dones_of(t)) {
    thread_pool_poll();
    usleep(1000);
    assert_true(++spins < 20000);   /* 20 s: a job was lost */
  }
}

/** A task that is not a store job (a password check): holds a worker at
 * the gate. */
static void *blocker_work(void *arg)
{
  pthread_mutex_lock(&rec_mutex);
  inside++;
  pthread_cond_broadcast(&rec_cond);
  while (!gate_open)
    pthread_cond_wait(&rec_cond, &rec_mutex);
  pthread_mutex_unlock(&rec_mutex);
  return arg;
}

static int blockers_done;

static void blocker_done(void *result, void *ctx)
{
  (void)result; (void)ctx;
  blockers_done++;
}

static void hold_workers(int n)
{
  static int token;
  int i, before;

  pthread_mutex_lock(&rec_mutex);
  before = inside;
  pthread_mutex_unlock(&rec_mutex);
  for (i = 0; i < n; i++)
    assert_int_equal(thread_pool_submit(blocker_work, &token, blocker_done, NULL), 0);
  wait_inside(before + n);
}

/** Opens the gate after a delay, from another thread. */
static void *open_gate_later(void *arg)
{
  usleep(*(int *)arg * 1000);
  set_gate(1);
  return NULL;
}

static int case_setup(void **state)
{
  (void)state;
  main_thread = pthread_self();
  gate_open = 1;
  inside = running_now = running_max = run_seq = done_seq = 0;
  store_closed = ran_after_close = 0;
  blockers_done = 0;
  return 0;
}

static int case_teardown(void **state)
{
  unsigned int in_pool, waiting;

  (void)state;
  set_gate(1);
  thread_pool_shutdown();
  store_jobs_count(&in_pool, &waiting);
  assert_int_equal(in_pool, 0);
  assert_int_equal(waiting, 0);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** No pool: the read as it was -- on the caller, unmuted, answered before
 * store_job_start() returns. */
static void without_a_pool_the_job_runs_on_the_caller(void **state)
{
  struct TJob t;
  int link;

  (void)state;
  assert_int_equal(thread_pool_is_running(), 0);
  assert_int_equal(store_jobs_cap(), 0);
  tjob_init(&t, &link);
  store_job_start(&t.job);

  assert_finished(&t, 1);
  assert_true(t.run_on_main);
  assert_false(t.run_muted);
  assert_ptr_equal(t.done_link, &link);
}

/** A worker task that reports whether its thread is muted. */
static void *muted_probe(void *arg)
{
  pthread_mutex_lock(&rec_mutex);
  *(int *)arg = log_thread_muted();
  pthread_mutex_unlock(&rec_mutex);
  return arg;
}

static void probe_done(void *result, void *ctx)
{
  struct TJob *t = (struct TJob *)ctx;

  (void)result;
  pthread_mutex_lock(&rec_mutex);
  t->dones++;
  pthread_mutex_unlock(&rec_mutex);
}

/** A running pool: run() on a worker, muted; done() on the main thread;
 * and the worker goes back to the pool unmuted (the next task on it may be
 * a password check, which logs as it always did). */
static void with_a_pool_the_job_runs_on_a_muted_worker(void **state)
{
  struct TJob t, probe;
  int link, muted = -1;

  (void)state;
  assert_int_equal(thread_pool_init(1), 0);
  assert_int_equal(store_jobs_cap(), 1);
  tjob_init(&t, &link);
  store_job_start(&t.job);
  poll_until_done(&t);

  assert_finished(&t, 1);
  assert_false(t.run_on_main);
  assert_true(t.run_muted);
  assert_ptr_equal(t.done_link, &link);
  assert_int_equal(log_thread_muted(), 0);      /* the main thread never is */

  /* The pool's one worker, after the job. */
  tjob_init(&probe, NULL);
  assert_int_equal(thread_pool_submit(muted_probe, &muted, probe_done, &probe), 0);
  poll_until_done(&probe);
  assert_int_equal(muted, 0);
}

/** The cap is one worker fewer than the pool has: with every place taken
 * the next jobs wait here, not in the pool and not on the main thread. */
static void the_cap_leaves_a_worker_free(void **state)
{
  struct TJob t[6];
  unsigned int in_pool, waiting;
  int i, link;

  (void)state;
  assert_int_equal(thread_pool_init(4), 0);
  assert_int_equal(store_jobs_cap(), 3);
  set_gate(0);
  for (i = 0; i < 6; i++) {
    tjob_init(&t[i], &link);
    store_job_start(&t[i].job);
  }
  wait_inside(3);
  store_jobs_count(&in_pool, &waiting);
  assert_int_equal(in_pool, 3);
  assert_int_equal(waiting, 3);
  for (i = 0; i < 6; i++)
    assert_int_equal(dones_of(&t[i]), 0);

  /* The fourth worker is free: a password check runs at once. */
  hold_workers(1);

  set_gate(1);
  for (i = 0; i < 6; i++)
    poll_until_done(&t[i]);
  for (i = 0; i < 6; i++) {
    assert_finished(&t[i], 1);
    assert_false(t[i].run_on_main);
  }
  pthread_mutex_lock(&rec_mutex);
  assert_true(running_max <= 3);
  pthread_mutex_unlock(&rec_mutex);
}

/** The jobs over the cap enter the pool in the order they were started. */
static void waiting_jobs_run_in_order(void **state)
{
  struct TJob t[5];
  int i, link;

  (void)state;
  assert_int_equal(thread_pool_init(2), 0);
  assert_int_equal(store_jobs_cap(), 1);
  set_gate(0);
  for (i = 0; i < 5; i++) {
    tjob_init(&t[i], &link);
    store_job_start(&t[i].job);
  }
  wait_inside(1);
  set_gate(1);
  for (i = 0; i < 5; i++)
    poll_until_done(&t[i]);
  for (i = 0; i < 5; i++) {
    assert_finished(&t[i], 1);
    assert_int_equal(t[i].run_order, i + 1);
    assert_int_equal(t[i].done_order, i + 1);
  }
  pthread_mutex_lock(&rec_mutex);
  assert_int_equal(running_max, 1);
  pthread_mutex_unlock(&rec_mutex);
}

/** Past STORE_JOBS_WAIT_MAX waiting jobs the next one runs on the caller,
 * as every job did before: the main loop slows, which is what holds the
 * requests back. */
static void past_the_waiting_room_a_job_runs_on_the_caller(void **state)
{
  static struct TJob t[STORE_JOBS_WAIT_MAX + 2];
  unsigned int in_pool, waiting;
  int i, link;

  (void)state;
  assert_int_equal(thread_pool_init(2), 0);
  set_gate(0);
  for (i = 0; i < STORE_JOBS_WAIT_MAX + 1; i++) {
    tjob_init(&t[i], &link);
    store_job_start(&t[i].job);
  }
  wait_inside(1);
  store_jobs_count(&in_pool, &waiting);
  assert_int_equal(in_pool, 1);
  assert_int_equal(waiting, STORE_JOBS_WAIT_MAX);

  i = STORE_JOBS_WAIT_MAX + 1;
  tjob_init(&t[i], &link);
  store_job_start(&t[i].job);
  assert_finished(&t[i], 1);
  assert_true(t[i].run_on_main);
  assert_false(t[i].run_muted);

  set_gate(1);
  for (i = 0; i < STORE_JOBS_WAIT_MAX + 1; i++)
    poll_until_done(&t[i]);
  for (i = 0; i < STORE_JOBS_WAIT_MAX + 1; i++) {
    assert_finished(&t[i], 1);
    assert_false(t[i].run_on_main);
  }
}

/** The pool refuses the job (its queue is full of password checks): the
 * job runs on the caller. */
static void a_job_the_pool_refuses_runs_on_the_caller(void **state)
{
  struct TJob t;
  int i, link;
  static int token;

  (void)state;
  assert_int_equal(thread_pool_init(2), 0);
  set_gate(0);
  hold_workers(2);
  for (i = 0; i < THREAD_POOL_MAX_PENDING; i++)
    assert_int_equal(thread_pool_submit(blocker_work, &token, blocker_done, NULL), 0);
  assert_int_equal(thread_pool_submit(blocker_work, &token, blocker_done, NULL), -1);

  tjob_init(&t, &link);
  store_job_start(&t.job);
  assert_finished(&t, 1);
  assert_true(t.run_on_main);
}

/** The server the answer was for leaves.  A job waiting here is dropped at
 * once; one queued in the pool is cancelled there and never runs; one a
 * worker is running finishes and is answered with no link.  Another
 * server's job is untouched. */
static void a_job_whose_link_left_is_not_answered(void **state)
{
  struct TJob running, queued, waiting, other;
  int gone, stays;
  unsigned int in_pool, nwait;

  (void)state;
  assert_int_equal(thread_pool_init(3), 0);
  assert_int_equal(store_jobs_cap(), 2);
  set_gate(0);

  tjob_init(&running, &gone);
  store_job_start(&running.job);
  wait_inside(1);
  hold_workers(2);                     /* inside is 3: every worker held */
  tjob_init(&queued, &gone);
  store_job_start(&queued.job);        /* in the pool, behind the blockers */
  tjob_init(&waiting, &gone);
  store_job_start(&waiting.job);       /* over the cap */
  tjob_init(&other, &stays);
  store_job_start(&other.job);         /* over the cap too */
  store_jobs_count(&in_pool, &nwait);
  assert_int_equal(in_pool, 2);
  assert_int_equal(nwait, 2);

  store_jobs_link_gone(&gone);

  assert_finished(&waiting, 0);        /* dropped here and now */
  assert_null(waiting.done_link);
  assert_int_equal(queued.abandons, 1);/* its handle is back already */
  assert_int_equal(dones_of(&queued), 0);
  assert_int_equal(dones_of(&running), 0);
  assert_int_equal(dones_of(&other), 0);

  set_gate(1);
  poll_until_done(&running);
  poll_until_done(&queued);
  poll_until_done(&other);

  assert_finished(&running, 1);        /* the read was under way */
  assert_null(running.done_link);      /* ...and has nobody to go to */
  assert_finished(&queued, 0);
  assert_null(queued.done_link);
  assert_finished(&other, 1);
  assert_ptr_equal(other.done_link, &stays);

  /* A second leave of the same server finds nothing. */
  store_jobs_link_gone(&gone);
}

/** The store is about to close.  store_jobs_quiesce() returns only when
 * the job a worker is running has left run(); the queued and the waiting
 * ones are cancelled and never run, their handles back before it returns.
 * The job that ran is still answered afterwards. */
static void the_store_closes_only_after_the_running_job(void **state)
{
  struct TJob running, queued, waiting;
  pthread_t opener;
  int link, delay_ms = 150;
  struct timespec t0, t1;

  (void)state;
  assert_int_equal(thread_pool_init(3), 0);
  set_gate(0);
  tjob_init(&running, &link);
  store_job_start(&running.job);
  wait_inside(1);
  hold_workers(2);
  tjob_init(&queued, &link);
  store_job_start(&queued.job);
  tjob_init(&waiting, &link);
  store_job_start(&waiting.job);

  clock_gettime(CLOCK_MONOTONIC, &t0);
  assert_int_equal(pthread_create(&opener, NULL, open_gate_later, &delay_ms), 0);
  store_jobs_quiesce();
  clock_gettime(CLOCK_MONOTONIC, &t1);

  /* The running job is out of run(): its handle is back. */
  pthread_mutex_lock(&rec_mutex);
  assert_int_equal(running.runs, 1);
  assert_int_equal(running.handle, 0);
  assert_int_equal(queued.handle, 0);
  assert_int_equal(queued.abandons, 1);
  assert_int_equal(waiting.handle, 0);
  store_closed = 1;                    /* the caller closes the store now */
  pthread_mutex_unlock(&rec_mutex);
  assert_true((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000
              >= delay_ms - 20);
  assert_finished(&waiting, 0);
  pthread_join(opener, NULL);

  poll_until_done(&running);
  poll_until_done(&queued);
  assert_finished(&running, 1);
  assert_ptr_equal(running.done_link, &link);
  assert_finished(&queued, 0);
  pthread_mutex_lock(&rec_mutex);
  assert_int_equal(ran_after_close, 0);
  pthread_mutex_unlock(&rec_mutex);
}

/** As the ircd stops: quiesce (the stores close), then the pool shuts
 * down with the cancelled job still in its queue.  The pool discards it
 * (a NULL result); it is answered once and not abandoned a second
 * time. */
static void a_cancelled_job_survives_the_pool_shutdown(void **state)
{
  struct TJob queued;
  pthread_t opener;
  int link, delay_ms = 100;

  (void)state;
  assert_int_equal(thread_pool_init(2), 0);
  set_gate(0);
  hold_workers(2);
  tjob_init(&queued, &link);
  store_job_start(&queued.job);

  store_jobs_quiesce();                /* nothing running: returns at once */
  assert_int_equal(queued.abandons, 1);
  store_closed = 1;

  assert_int_equal(pthread_create(&opener, NULL, open_gate_later, &delay_ms), 0);
  thread_pool_shutdown();              /* takes the queue, then waits */
  pthread_join(opener, NULL);

  assert_finished(&queued, 0);
  assert_int_equal(ran_after_close, 0);
}

/** The pool shuts down with a job queued and one waiting, and nobody
 * closed the store first (not the ircd's order, but nothing forbids it).
 * The queued one comes back unrun: abandoned and answered once.  The
 * waiting one has no pool to go to and runs on the main thread. */
static void a_pool_shutdown_frees_a_queued_job_once(void **state)
{
  struct TJob queued, waiting;
  pthread_t opener;
  int link, delay_ms = 100;

  (void)state;
  assert_int_equal(thread_pool_init(2), 0);
  assert_int_equal(store_jobs_cap(), 1);
  set_gate(0);
  hold_workers(2);
  tjob_init(&queued, &link);
  store_job_start(&queued.job);
  tjob_init(&waiting, &link);
  store_job_start(&waiting.job);

  assert_int_equal(pthread_create(&opener, NULL, open_gate_later, &delay_ms), 0);
  thread_pool_shutdown();
  pthread_join(opener, NULL);

  assert_finished(&queued, 0);
  assert_ptr_equal(queued.done_link, &link);
  assert_finished(&waiting, 1);
  assert_true(waiting.run_on_main);
  assert_int_equal(blockers_done, 2);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(without_a_pool_the_job_runs_on_the_caller,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(with_a_pool_the_job_runs_on_a_muted_worker,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(the_cap_leaves_a_worker_free,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(waiting_jobs_run_in_order,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(past_the_waiting_room_a_job_runs_on_the_caller,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_job_the_pool_refuses_runs_on_the_caller,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_job_whose_link_left_is_not_answered,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(the_store_closes_only_after_the_running_job,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_cancelled_job_survives_the_pool_shutdown,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_pool_shutdown_frees_a_queued_job_once,
                                    case_setup, case_teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
