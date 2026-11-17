/*
 * alloc_nomem_cmocka.c - an allocation that fails off the main thread
 * never runs the out-of-memory handler.
 *
 * The handler (ircd.c outofmemory()) restarts the server: main-thread
 * work that, run on a thread pool worker, hung in history_shutdown()
 * waiting for the caller's own store job, and took every later DIE,
 * SIGTERM and RESTART with it.  DoMalloc() and its siblings therefore
 * call the handler on the thread that set it and on no other; anywhere
 * else they write one line to stderr and _exit().
 *
 * Links the REAL ../ircd_alloc.o.  malloc() and realloc() are wrapped
 * (-Wl,--wrap) to fail on request, _exit() to record the status and end
 * the calling thread instead of the process, write() to keep what goes
 * to descriptor 2.  The handler set here stands for outofmemory(): it
 * counts its calls.
 */
#include "config.h"

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cmocka.h>

#include "ircd_alloc.h"

void debug(int level, const char *form, ...) {}
int log_inassert;

/* ------------------------------------------------------------------ */
/* The wrapped world                                                   */
/* ------------------------------------------------------------------ */

static int fail_alloc;          /**< malloc() and realloc() return NULL */
static int handler_calls;       /**< the out-of-memory handler ran */
static pthread_t handler_thread;
static int exit_calls;          /**< _exit() was called ... */
static int exit_status = -1;    /**< ... with this ... */
static pthread_t exit_thread;   /**< ... on this thread */
static char stderr_text[256];   /**< what write(2, ...) was given */

void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size)
{
  return fail_alloc ? NULL : __real_malloc(size);
}

void *__real_realloc(void *p, size_t size);
void *__wrap_realloc(void *p, size_t size)
{
  return fail_alloc ? NULL : __real_realloc(p, size);
}

/** The process would be gone: end the thread, which is all a test can
 * do and all the caller may rely on (nothing after _exit() runs). */
void __wrap__exit(int status)
{
  exit_calls++;
  exit_status = status;
  exit_thread = pthread_self();
  pthread_exit(NULL);
}

ssize_t __real_write(int fd, const void *buf, size_t n);
ssize_t __wrap_write(int fd, const void *buf, size_t n)
{
  if (fd == 2) {
    size_t have = strlen(stderr_text);

    if (n > sizeof(stderr_text) - 1 - have)
      n = sizeof(stderr_text) - 1 - have;
    memcpy(stderr_text + have, buf, n);
    stderr_text[have + n] = '\0';
    return (ssize_t)n;
  }
  return __real_write(fd, buf, n);
}

/** outofmemory()'s stand-in.  The real one never returns to a caller
 * that goes on (it restarts); this one does, and DoMalloc() then hands
 * back NULL. */
static void handler(void)
{
  handler_calls++;
  handler_thread = pthread_self();
}

static int setup(void **state)
{
  fail_alloc = 0;
  handler_calls = 0;
  exit_calls = 0;
  exit_status = -1;
  stderr_text[0] = '\0';
  set_nomem_handler(handler);   /* this thread is the main thread */
  return 0;
}

static int teardown(void **state)
{
  fail_alloc = 0;
  return 0;
}

/* ------------------------------------------------------------------ */
/* What a worker does                                                  */
/* ------------------------------------------------------------------ */

enum { W_MALLOC, W_CALLOC, W_REALLOC };

struct work {
  int which;
  int returned;     /**< the allocation came back to the caller */
  void *block;
};

static void *worker(void *arg)
{
  struct work *w = (struct work *)arg;

  switch (w->which) {
  case W_MALLOC:
    w->block = MyMalloc(64);
    break;
  case W_CALLOC:
    w->block = MyCalloc(4, 16);
    break;
  default:
    w->block = MyRealloc(w->block, 128);
    break;
  }
  w->returned = 1;
  return NULL;
}

static void run_worker(struct work *w)
{
  pthread_t th;

  assert_int_equal(pthread_create(&th, NULL, worker, w), 0);
  /* The join is the proof the thread is not stuck anywhere. */
  assert_int_equal(pthread_join(th, NULL), 0);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** The reviewer's case: a worker's failed allocation does not reach the
 * handler (so not server_restart()); the process ends there instead. */
static void a_failed_allocation_on_a_worker_never_runs_the_handler(void **state)
{
  static const int kinds[] = { W_MALLOC, W_CALLOC, W_REALLOC };
  size_t i;

  for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
    struct work w = { kinds[i], 0, NULL };

    exit_calls = 0;
    exit_status = -1;
    stderr_text[0] = '\0';
    fail_alloc = 1;
    run_worker(&w);
    fail_alloc = 0;

    assert_int_equal(handler_calls, 0);
    assert_int_equal(exit_calls, 1);
    assert_int_equal(exit_status, 1);
    assert_false(pthread_equal(exit_thread, pthread_self()));
    /* Nothing after the failure ran on the worker: no NULL block went
     * back to code that does not check for one. */
    assert_int_equal(w.returned, 0);
    assert_string_equal(stderr_text,
                        "ircd: out of memory off the main thread, exiting\n");
  }
}

/** The main thread keeps its handler: the restart is its work. */
static void a_failed_allocation_on_the_main_thread_runs_the_handler(void **state)
{
  void *p;

  fail_alloc = 1;
  p = MyMalloc(64);
  fail_alloc = 0;

  assert_null(p);
  assert_int_equal(handler_calls, 1);
  assert_true(pthread_equal(handler_thread, pthread_self()));
  assert_int_equal(exit_calls, 0);
  assert_string_equal(stderr_text, "");
}

/** And an allocation that succeeds on a worker is an allocation. */
static void a_worker_allocates_as_before(void **state)
{
  struct work w = { W_MALLOC, 0, NULL };

  run_worker(&w);
  assert_int_equal(w.returned, 1);
  assert_non_null(w.block);
  w.which = W_REALLOC;
  w.returned = 0;
  run_worker(&w);
  assert_int_equal(w.returned, 1);
  assert_non_null(w.block);
  MyFree(w.block);
  assert_int_equal(handler_calls, 0);
  assert_int_equal(exit_calls, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(a_failed_allocation_on_a_worker_never_runs_the_handler, setup, teardown),
    cmocka_unit_test_setup_teardown(a_failed_allocation_on_the_main_thread_runs_the_handler, setup, teardown),
    cmocka_unit_test_setup_teardown(a_worker_allocates_as_before, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
