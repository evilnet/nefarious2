/*
 * history_view_cmocka.c - a history walk on a thread pool worker
 *
 * The federated SEARCH responder scans the store on a worker (m_chathistory.c
 * struct SearchJob, store_job.h).  This runs the REAL history.c on a real
 * RocksDB store, with the real store_job.o and thread_pool.o, and checks
 * what the worker walk rests on:
 *
 *  - a walk through a view (history_view_open) returns the store as it
 *    was when the view was opened, whatever was stored since;
 *  - a match stays hidden when it was redacted in the view or is redacted
 *    now: a REDACT stored after the view hides it, and so does a
 *    redaction a trim has since deleted with its message;
 *  - a walk on a worker returns exactly the rows the same walk returned on
 *    the main thread at that moment, while the main thread keeps storing
 *    rows, redacting and moving its clock;
 *  - the worker walk reads no main-thread state: every stub below that
 *    stands for it (the channel table, features, the log, the notices)
 *    fails the test when a thread other than the main one calls it;
 *  - history_shutdown() with walks under way and jobs waiting: returns
 *    only once the running walks are out of the store, the others never
 *    run, and every view is given back before the store closes.
 *
 * Built with -fsanitize=thread it is also the data-race check of that
 * path (the Makefile's plain build runs it as an ordinary suite).  The
 * search's own row hook is static in m_chathistory.c; the hook here does
 * what it does to the store: match on the text, then look the match's
 * redaction up.
 */
#include "config.h"

#include <dirent.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cmocka.h>

#include "channel.h"
#include "client.h"
#include "crdt_hlc.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "send.h"
#include "store_job.h"
#include "thread_pool.h"

/* ------------------------------------------------------------------ */
/* The ircd around history.c: main-thread state, every piece of it     */
/* ------------------------------------------------------------------ */

static pthread_t main_thread;
/** Calls into main-thread state from another thread (must stay 0). */
static int off_main_calls;

static void main_only(void)
{
  if (!pthread_equal(pthread_self(), main_thread))
    __atomic_add_fetch(&off_main_calls, 1, __ATOMIC_SEQ_CST);
}

int log_inassert;
static __thread int thread_muted;

void log_thread_mute(int on) { thread_muted = on ? 1 : 0; }
int log_thread_muted(void) { return thread_muted; }

/* As log_vwrite(): a muted thread's line is dropped before anything
 * shared is touched; an unmuted one is the main thread's business. */
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
  if (log_thread_muted())
    return;
  main_only();
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
  if (log_thread_muted())
    return;
  main_only();
}

/* The main thread's clock: the main thread writes it while the workers
 * walk, so a worker that read it would be a data race under TSan. */
time_t CurrentTime;
time_t TSoffset;
struct Channel *GlobalChannelList;

/** CHATHISTORY_RETENTION, in days; 0 keeps everything (the rows here are
 * stamped 2023, so 1 puts all of them past retention). */
static int retention_days;

int feature_int(enum Feature feat)
{
  main_only();
  switch (feat) {
  case FEAT_HISTORY_MAP_SIZE_MB: return 64;
  case FEAT_CHATHISTORY_RETENTION: return retention_days;
  default: return 0;
  }
}

int feature_bool(enum Feature feat)
{
  (void)feat;
  main_only();
  return 0;
}

struct Channel *hSeekChannel(const char *name)
{
  (void)name;
  main_only();
  return NULL;
}

int channel_has_local_member(const struct Channel *chptr)
{
  (void)chptr;
  main_only();
  return 0;
}

int channel_store_open(const struct Channel *chptr)
{
  (void)chptr;
  main_only();
  return 0;
}

void chathistory_fed_report(struct Client *to) { (void)to; main_only(); }
void presence_shutdown(void) { main_only(); }

int send_reply(struct Client *to, int reply, ...)
{
  (void)to; (void)reply;
  main_only();
  return 0;
}

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  (void)one; (void)mask; (void)pattern;
  main_only();
}

struct Timer *timer_init(struct Timer *timer)
{
  main_only();
  memset(timer, 0, sizeof(*timer));
  return timer;
}

void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{
  (void)timer; (void)call; (void)data; (void)type; (void)value;
  main_only();
}

void timer_del(struct Timer *timer) { (void)timer; main_only(); }

static struct HLC test_hlc = { 1700000000000ULL, 0, 1 };

const struct HLC *hlc_global(void) { main_only(); return &test_hlc; }
uint64_t hlc_wall_clock_ms(void) { main_only(); return test_hlc.physical_ms; }
uint64_t hlc_max_forward_ms(void) { main_only(); return 60000; }
uint64_t hlc_reference_now_ms(const struct HLC *local, uint64_t wall_ms)
{
  (void)local;
  main_only();
  return wall_ms;
}

/* ------------------------------------------------------------------ */
/* The store                                                           */
/* ------------------------------------------------------------------ */

#define TARGET "#walk"
#define BASE_SEC 1700000000UL

static char store_dir[512];
static int next_row;

static void rm_rf(const char *path)
{
  DIR *d = opendir(path);
  struct dirent *e;
  char buf[1024];

  if (!d) {
    unlink(path);
    return;
  }
  while ((e = readdir(d)) != NULL) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    snprintf(buf, sizeof buf, "%s/%s", path, e->d_name);
    rm_rf(buf);
  }
  closedir(d);
  rmdir(path);
}

static void row_stamp(int i, char *ts, size_t n)
{
  snprintf(ts, n, "%lu.%03d", BASE_SEC + (unsigned long)(i / 1000), i % 1000);
}

/** Store row @a i: every third one carries the needle. */
static void store_row(int i)
{
  char msgid[32], ts[HISTORY_TIMESTAMP_LEN], text[64];

  snprintf(msgid, sizeof msgid, "row%07d", i);
  row_stamp(i, ts, sizeof ts);
  snprintf(text, sizeof text, i % 3 == 0 ? "a needle in row %d" : "hay %d", i);
  assert_int_equal(history_store_message(msgid, ts, TARGET, NULL,
                                         "nick!user@host", "acct",
                                         i % 7 == 0 ? HISTORY_NOTICE : HISTORY_PRIVMSG,
                                         text, NULL, NULL), 0);
}

static void store_rows(int n)
{
  while (n-- > 0)
    store_row(next_row++);
}

/** Redact row @a i: a REDACT row whose content names it. */
static void redact_row(int i)
{
  char msgid[32], ts[HISTORY_TIMESTAMP_LEN], content[64];

  snprintf(msgid, sizeof msgid, "red%07d", i);
  row_stamp(next_row++, ts, sizeof ts);
  snprintf(content, sizeof content, "row%07d :gone", i);
  assert_int_equal(history_store_message(msgid, ts, TARGET, NULL,
                                         "op!user@host", "opacct",
                                         HISTORY_REDACT, content, NULL, NULL), 0);
}

/* ------------------------------------------------------------------ */
/* The walk, as the search does it                                     */
/* ------------------------------------------------------------------ */

struct Match {
  const char *text;
  struct HistoryView *view; /**< the walk's view, or NULL */
  int slow_us;              /**< sleep per row examined (the shutdown case) */
  int rows_seen;
};

static int started_walks;   /**< walks that have examined a row (atomic) */

static int match_hook(const struct HistoryMessage *msg, int reverse, void *ctx,
                      int64_t *skip_to)
{
  struct Match *m = (struct Match *)ctx;

  (void)reverse; (void)skip_to;
  if (m->rows_seen++ == 0)
    __atomic_add_fetch(&started_walks, 1, __ATOMIC_SEQ_CST);
  if (m->slow_us)
    usleep(m->slow_us);
  if (msg->type != HISTORY_PRIVMSG && msg->type != HISTORY_NOTICE)
    return 0;
  if (!strstr(msg->content, m->text))
    return 0;
  if (history_message_is_redacted_view(m->view, TARGET, msg->msgid) != 0)
    return 0;
  return 1;
}

struct Walk {
  struct Match match;
  struct HistoryRowFilter filter;
  int count;
  struct HistoryMessage *rows;
};

static void walk_init(struct Walk *w, struct HistoryView *view, int scan_max)
{
  memset(w, 0, sizeof(*w));
  w->match.text = "needle";
  w->match.view = view;
  w->filter.fn = match_hook;
  w->filter.ctx = &w->match;
  w->filter.scan_max = scan_max;
  w->filter.view = view;
  w->filter.live_inc_set = 1;   /* the caller read it: no channel lookup */
  w->filter.live_inc = 0;
}

/** BEFORE from past every row, newest @a limit matches. */
static void walk_run(struct Walk *w, int limit)
{
  w->count = history_query_before(TARGET, HISTORY_REF_TIMESTAMP, "1800000000.000",
                                  limit, &w->rows, &w->filter);
}

static void assert_same_rows(const struct Walk *a, const struct Walk *b)
{
  const struct HistoryMessage *x = a->rows, *y = b->rows;

  assert_int_equal(a->count, b->count);
  assert_int_equal(a->filter.scanned, b->filter.scanned);
  assert_int_equal(a->filter.truncated, b->filter.truncated);
  for (; x && y; x = x->next, y = y->next) {
    assert_string_equal(x->msgid, y->msgid);
    assert_string_equal(x->timestamp, y->timestamp);
    assert_string_equal(x->content, y->content);
    assert_string_equal(x->sender, y->sender);
    assert_int_equal(x->type, y->type);
  }
  assert_null(x);
  assert_null(y);
}

/* ------------------------------------------------------------------ */
/* The walk as a store job                                             */
/* ------------------------------------------------------------------ */

static int open_views;      /**< views opened and not yet closed (atomic) */

static struct HistoryView *view_open(void)
{
  struct HistoryView *v = history_view_open();

  assert_non_null(v);
  __atomic_add_fetch(&open_views, 1, __ATOMIC_SEQ_CST);
  return v;
}

static void view_close(struct HistoryView *v)
{
  history_view_close(v);
  __atomic_sub_fetch(&open_views, 1, __ATOMIC_SEQ_CST);
}

struct WalkJob {
  struct StoreJob job;      /* first */
  struct Walk walk;
  struct HistoryView *view;
  int limit;
  int ran_on_main;          /**< written by run(), read after done() */
  int done, ran;
};

static void wj_run(struct StoreJob *j)
{
  struct WalkJob *wj = (struct WalkJob *)j;

  wj->ran_on_main = pthread_equal(pthread_self(), main_thread);
  walk_run(&wj->walk, wj->limit);
  view_close(wj->view);
  wj->view = NULL;
}

static void wj_abandon(struct StoreJob *j)
{
  struct WalkJob *wj = (struct WalkJob *)j;

  view_close(wj->view);
  wj->view = NULL;
}

static void wj_done(struct StoreJob *j, int ran)
{
  struct WalkJob *wj = (struct WalkJob *)j;

  wj->done++;
  wj->ran = ran;
}

static const struct StoreJobOps wj_ops = { wj_run, wj_abandon, wj_done };

static void wj_init(struct WalkJob *wj, struct HistoryView *view, int limit,
                    int scan_max)
{
  static int link;

  memset(wj, 0, sizeof(*wj));
  wj->job.ops = &wj_ops;
  wj->job.link = &link;
  wj->view = view;
  wj->limit = limit;
  walk_init(&wj->walk, view, scan_max);
}

static void poll_until(const int *flag)
{
  int spins = 0;

  while (!*flag) {
    thread_pool_poll();
    usleep(500);
    assert_true(++spins < 120000);
  }
}

static int case_setup(void **state)
{
  const char *tmp = getenv("TMPDIR");

  (void)state;
  main_thread = pthread_self();
  off_main_calls = 0;
  started_walks = 0;
  open_views = 0;
  next_row = 0;
  retention_days = 0;
  snprintf(store_dir, sizeof store_dir, "%s/histviewXXXXXX",
           tmp && *tmp ? tmp : "/tmp");
  assert_non_null(mkdtemp(store_dir));
  assert_int_equal(history_init(store_dir), 0);
  assert_int_equal(history_is_available(), 1);
  return 0;
}

static int case_teardown(void **state)
{
  (void)state;
  history_shutdown();
  thread_pool_shutdown();
  rm_rf(store_dir);
  assert_int_equal(__atomic_load_n(&off_main_calls, __ATOMIC_SEQ_CST), 0);
  assert_int_equal(__atomic_load_n(&open_views, __ATOMIC_SEQ_CST), 0);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** A view is the store at the moment it was opened: rows stored later are
 * not in a walk through it, and are in a walk that takes its own
 * snapshot.  A redaction is the exception, on the safe side: it is looked
 * up when the walk reaches the match, so one stored later still hides. */
static void a_view_walk_reads_the_store_as_it_was(void **state)
{
  struct HistoryView *view;
  struct Walk at_view, later, now;
  const struct HistoryMessage *m;

  (void)state;
  store_rows(300);                         /* rows 0..299, needles 0,3,..,297 */
  view = view_open();
  walk_init(&at_view, view, 0);
  walk_run(&at_view, 5);
  assert_int_equal(at_view.count, 5);
  assert_string_equal(at_view.rows->msgid, "row0000285");

  store_rows(30);                          /* rows 300..329: four more needles */
  walk_init(&later, view, 0);
  walk_run(&later, 5);
  assert_same_rows(&later, &at_view);      /* the view has not moved */

  walk_init(&now, NULL, 0);
  walk_run(&now, 5);
  assert_int_equal(now.count, 5);
  for (m = now.rows; m->next; m = m->next)
    ;
  assert_string_equal(m->msgid, "row0000327");

  redact_row(297);                         /* after the view was opened */
  history_free_messages(later.rows);
  walk_init(&later, view, 0);
  walk_run(&later, 5);
  assert_int_equal(later.count, 5);        /* the next match takes its place */
  assert_string_equal(later.rows->msgid, "row0000282");
  for (m = later.rows; m; m = m->next)
    assert_string_not_equal(m->msgid, "row0000297");

  view_close(view);
  history_free_messages(at_view.rows);
  history_free_messages(later.rows);
  history_free_messages(now.rows);
}

/** A trim that runs after the view was opened deletes a redacted message
 * together with its REDACT row and the reply-index entry that links them
 * (history_trim.c, delete_redacted_parent).  The view still holds the
 * message; the store as it is now no longer says it was redacted.  A walk
 * that asked only the store as it is now returned the message.  The
 * lookup a view walk uses (history_message_is_redacted_view) asks the
 * view too, and the message stays hidden. */
static void a_trimmed_redaction_still_hides_in_the_view(void **state)
{
  struct HistoryView *view;
  struct Walk before, after;
  const struct HistoryMessage *m;
  int i;

  (void)state;
  store_rows(30);                          /* needles 0,3,..,27 */
  redact_row(27);
  view = view_open();
  walk_init(&before, view, 0);
  walk_run(&before, 50);
  assert_int_equal(before.count, 9);
  for (m = before.rows; m; m = m->next)
    assert_string_not_equal(m->msgid, "row0000027");

  retention_days = 1;
  history_trim_start();
  for (i = 0; i < 10; i++)
    history_trim_tick(i == 0);
  retention_days = 0;
  /* The trim took the redaction with the row: the store as it is now
   * does not know row 27, redacted or not. */
  assert_int_equal(history_message_is_redacted(TARGET, "row0000027"), 0);
  assert_int_equal(history_message_is_redacted_view(view, TARGET, "row0000027"), 1);
  assert_int_equal(history_message_is_redacted_view(view, TARGET, "row0000024"), 0);

  walk_init(&after, view, 0);
  walk_run(&after, 50);
  assert_same_rows(&after, &before);       /* row 27 still hidden */

  view_close(view);
  history_free_messages(before.rows);
  history_free_messages(after.rows);
}

/** The walk a worker runs returns what the main thread's walk returned
 * through the same view, while the main thread goes on storing rows
 * (needles among them), redacting old rows no walk here reaches, and
 * moving its clock.  Some walks hit their scan budget: the truncation and
 * the rows examined match too. */
#define ROUNDS 40
static void a_worker_walk_returns_what_the_main_thread_walk_did(void **state)
{
  static struct WalkJob jobs[ROUNDS];
  static struct Walk expect[ROUNDS];
  int i, on_workers = 0;

  (void)state;
  assert_int_equal(thread_pool_init(4), 0);
  store_rows(3000);

  for (i = 0; i < ROUNDS; i++) {
    struct HistoryView *view = view_open();
    int limit = 10 + i, scan_max = (i % 4 == 0) ? 20 : 2500;

    walk_init(&expect[i], view, scan_max);
    walk_run(&expect[i], limit);
    assert_true(expect[i].count > 0);

    wj_init(&jobs[i], view, limit, scan_max);
    store_job_start(&jobs[i].job);

    /* The main loop goes on beside the walk. */
    store_rows(25);
    redact_row(i * 3);
    CurrentTime++;
    TSoffset = i;
    test_hlc.physical_ms += 25;
    thread_pool_poll();
  }

  for (i = 0; i < ROUNDS; i++)
    poll_until(&jobs[i].done);
  for (i = 0; i < ROUNDS; i++) {
    assert_int_equal(jobs[i].done, 1);
    assert_int_equal(jobs[i].ran, 1);
    assert_same_rows(&jobs[i].walk, &expect[i]);
    if (!jobs[i].ran_on_main)
      on_workers++;
    history_free_messages(jobs[i].walk.rows);
    history_free_messages(expect[i].rows);
  }
  /* Every one of them left the main thread (40 is under the waiting
   * room); otherwise this proved nothing. */
  assert_int_equal(on_workers, ROUNDS);
  assert_int_equal(expect[0].filter.truncated, 1);
  assert_int_equal(expect[1].filter.truncated, 0);
}

/** DIE with walks under way: history_shutdown() waits for the walks the
 * workers are in, the jobs that had not started never run, and every view
 * is back before the store closes. */
static void the_store_closes_after_the_walks_under_way(void **state)
{
  static struct WalkJob jobs[6];
  int i, ran = 0, dropped = 0;

  (void)state;
  assert_int_equal(thread_pool_init(3), 0);      /* two walks at once */
  store_rows(600);
  for (i = 0; i < 6; i++) {
    wj_init(&jobs[i], view_open(), 50, 0);
    jobs[i].walk.match.slow_us = 500;            /* 600 rows: ~0.3 s a walk */
    store_job_start(&jobs[i].job);
  }
  while (__atomic_load_n(&started_walks, __ATOMIC_SEQ_CST) < 2)
    usleep(200);

  history_shutdown();

  /* Nothing holds a view, and nothing is in the store. */
  assert_int_equal(history_is_available(), 0);
  assert_int_equal(__atomic_load_n(&open_views, __ATOMIC_SEQ_CST), 0);
  assert_int_equal(__atomic_load_n(&started_walks, __ATOMIC_SEQ_CST), 2);

  thread_pool_shutdown();
  for (i = 0; i < 6; i++) {
    assert_int_equal(jobs[i].done, 1);
    assert_null(jobs[i].view);
    if (jobs[i].ran) {
      ran++;
      assert_int_equal(jobs[i].walk.count, 50);  /* the walk was not cut */
      assert_false(jobs[i].ran_on_main);
    } else {
      dropped++;
      assert_int_equal(jobs[i].walk.match.rows_seen, 0);
    }
    history_free_messages(jobs[i].walk.rows);
  }
  assert_int_equal(ran, 2);
  assert_int_equal(dropped, 4);
  assert_int_equal(__atomic_load_n(&started_walks, __ATOMIC_SEQ_CST), 2);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(a_view_walk_reads_the_store_as_it_was,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_trimmed_redaction_still_hides_in_the_view,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(a_worker_walk_returns_what_the_main_thread_walk_did,
                                    case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(the_store_closes_after_the_walks_under_way,
                                    case_setup, case_teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
