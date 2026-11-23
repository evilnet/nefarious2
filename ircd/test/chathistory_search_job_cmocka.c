/*
 * chathistory_search_job_cmocka.c - the federated SEARCH responder's job
 *
 * A storage server answers another server's SEARCH (CH Q <target> S ...)
 * with a scan that runs on a thread pool worker (struct SearchJob in
 * m_chathistory.c, on store_job.c).  The scan itself -- the walk through
 * a view, beside the main thread's writes -- is history_view_cmocka's;
 * who runs a job, where and how often is store_job_cmocka's.  This is
 * the part between them, with the REAL code of both ends:
 *
 *  - the copy-in: ms_chathistory() parses the line and puts everything
 *    the scan needs in the job -- nothing of it points into the line;
 *  - search_job_done(): the rows and E <reqid> <n>; T when the scan
 *    budget cut the scan, or the limit was cut to what a requester keeps
 *    and was filled; E <reqid> 0 U when the store could not be read;
 *    nothing at all when the asking server has left;
 *  - the handles: the view and the presence filter given back once,
 *    whichever of those happened.
 *
 * m_chathistory.c is included, compiled with -ffunction-sections and
 * linked with --gc-sections (as auth_recheck_cmocka does s_auth.c), so
 * the program keeps ms_chathistory() and what it reaches.  The S path
 * runs for real; so do the L, A and R page paths, as far as the row
 * limit a page query carries goes (the cases at the end: their walks
 * are a table too).  The other subcommands' world is named at the end of
 * this file so the program links, and fails the case if it is reached.
 * The real ../store_job.o runs the jobs.  The thread pool is the test's:
 * thread_pool_submit() keeps the task, and a case runs the work function
 * and the callback itself, on this thread, in the order it wants -- the
 * link leaves before the worker, between the worker and the callback, or
 * not at all.  The store is a table: history_query_before() here walks
 * it newest first through the job's own row hook (search_row_hook, the
 * real one), under its scan budget.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../m_chathistory.c"

#include "thread_pool.h"

/* ------------------------------------------------------------------ */
/* The ircd around the job                                             */
/* ------------------------------------------------------------------ */

time_t CurrentTime = 1700009999;
int log_inassert;
struct Client me;

static struct Client origin;      /**< the asking server, numeric CD */
static struct Client other;       /**< what its numeric names after it left */
static struct Client requester;   /**< the user the SEARCH is for, CDAAB */
static struct User requester_user;
static struct Client *origin_now; /**< what FindNServer("CD") finds */

struct Client *FindNServer(const char *numeric)
{
  if (!strcmp(numeric, "AB"))
    return &me;
  if (!strcmp(numeric, "CD"))
    return origin_now;
  return NULL;
}

struct Client *findNUser(const char *yxx)
{
  return strcmp(yxx, "CDAAB") ? NULL : &requester;
}

static int warnings;              /**< log_write() at L_WARNING */
static char last_warning[512];

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  va_list vl;

  if (severity != L_WARNING)
    return;
  warnings++;
  va_start(vl, fmt);
  ircd_vsnprintf(0, last_warning, sizeof(last_warning), fmt, vl);
  va_end(vl);
}

void debug(int level, const char *form, ...) {}
static int muted;
void log_thread_mute(int on) { muted = on; }
int log_thread_muted(void) { return muted; }
int feature_int(enum Feature feat) { return 100; }  /* CHATHISTORY_MAX */
int feature_bool(enum Feature feat) { return 0; }

/* ---- what the server sends ---- */

#define LINES_MAX 600
static char *lines[LINES_MAX];
static int nlines;
static int misdirected;           /**< a line from or to the wrong party */

static void line_keep(struct Client *from, struct Client *to,
                      const char *pattern, va_list vl)
{
  char buf[1024];

  if (from != &me || to != &origin)
    misdirected++;
  ircd_vsnprintf(0, buf, sizeof(buf), pattern, vl);
  assert_true(nlines < LINES_MAX);
  lines[nlines++] = strdup(buf);
}

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  line_keep(from, to, pattern, vl);
  va_end(vl);
}

void sendcmdto_one_ctags(struct Client *from, const char *cmd, const char *tok,
                         struct Client *to, uint64_t time_ms, const char *msgid,
                         const char *client_tags, const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  line_keep(from, to, pattern, vl);
  va_end(vl);
}

/* ---- the thread pool: the case is the worker and the main loop ---- */

static int pool_on;
static struct {
  thread_pool_work_func work;
  void *arg;
  thread_pool_callback cb;
  void *ctx;
  void *result;
} task;
static int tasks;                 /**< thread_pool_submit() calls */

int thread_pool_is_running(void) { return pool_on; }
int thread_pool_workers(void) { return pool_on ? 4 : 0; }

int thread_pool_submit(thread_pool_work_func work, void *arg,
                       thread_pool_callback cb, void *ctx)
{
  tasks++;
  task.work = work;
  task.arg = arg;
  task.cb = cb;
  task.ctx = ctx;
  return 0;
}

/** The job the last line put in the pool. */
static struct SearchJob *the_job(void)
{
  assert_int_equal(tasks, 1);
  return (struct SearchJob *)task.arg;
}

static void worker_runs(void)   { task.result = task.work(task.arg); }
static void callback_runs(void) { task.cb(task.result, task.ctx); }

/* ---- the store: a table, newest row last ---- */

struct Row {
  const char *msgid;
  const char *ts;
  enum HistoryMessageType type;
  const char *sender;
  const char *account;
  const char *content;
};

static const struct Row few_rows[] = {
  { "AB-1", "1700000001.000", HISTORY_PRIVMSG, "ann!a@h", "ann", "a needle here" },
  { "AB-2", "1700000002.000", HISTORY_PRIVMSG, "bob!b@h", "", "nothing to see" },
  { "AB-3", "1700000003.000", HISTORY_PRIVMSG, "ann!a@h", "ann", "second NEEDLE" },
  { "AB-4", "1700000004.000", HISTORY_JOIN,    "cat!c@h", "", "needle" },
  { "AB-5", "1700000005.000", HISTORY_NOTICE,  "ann!a@h", "ann", "needle three" },
  { "AB-6", "1700000006.000", HISTORY_PRIVMSG, "annie!a@h", "", "needle, not ann's" },
};

static const struct Row *rows;    /**< NULL: nrows made-up rows, AB-1 up */
static int nrows;
static int hay_rows;              /**< the oldest this many of them match nothing */
static size_t hay_len;            /**< 0: a hay row says "hay"; else this many bytes */
static int rows_read;             /**< rows the walk read */
static int walks;                 /**< history_query_before() calls */
static int walk_fails;            /**< the next walk returns -1 */
static const char *redacted_id;   /**< this row is redacted ... */
static const char *unread_id;     /**< ... this one's redaction cannot be read */
static int freed_rows;

/** What the walk was given, copied when it ran. */
static struct {
  char target[CHANNELLEN + 1];
  char before[HISTORY_TIMESTAMP_LEN];
  enum HistoryRefType ref_type;
  int limit;
  struct HistoryRowFilter filter;
  struct SearchMatch sm;
  char text[128];
} seen;

static struct HistoryView *the_view = (struct HistoryView *)&walks;
static struct HistoryView *lookup_view;   /**< the view a redaction lookup got */
static int view_fails, views_open, views_closed;

struct HistoryView *history_view_open(void)
{
  if (view_fails)
    return NULL;
  views_open++;
  return the_view;
}

void history_view_close(struct HistoryView *view)
{
  if (view) {
    assert_ptr_equal(view, the_view);
    views_closed++;
  }
}

int history_is_available(void) { return 1; }
time_t history_live_incarnation(const char *target) { return 1699990000; }

uint64_t history_parse_ms(const char *ts)
{
  unsigned long sec = 0, ms = 0;

  if (!ts || sscanf(ts, "%lu.%3lu", &sec, &ms) < 1)
    return 0;
  return (uint64_t)sec * 1000 + ms;
}

int history_message_is_redacted_view(struct HistoryView *view,
                                     const char *target, const char *msgid)
{
  lookup_view = view;
  if (unread_id && !strcmp(msgid, unread_id))
    return -1;
  return redacted_id && !strcmp(msgid, redacted_id);
}

void history_free_messages(struct HistoryMessage *list)
{
  struct HistoryMessage *next;

  for (; list; list = next) {
    next = list->next;
    free(list);
    freed_rows++;
  }
}

static void row_fill(struct HistoryMessage *m, int i)
{
  memset(m, 0, sizeof(*m));
  if (rows) {
    strcpy(m->msgid, rows[i].msgid);
    strcpy(m->timestamp, rows[i].ts);
    m->type = rows[i].type;
    strcpy(m->sender, rows[i].sender);
    strcpy(m->account, rows[i].account);
    strcpy(m->content, rows[i].content);
  } else {
    snprintf(m->msgid, sizeof(m->msgid), "AB-%d", i + 1);
    snprintf(m->timestamp, sizeof(m->timestamp), "%d.000", 1700000001 + i);
    m->type = HISTORY_PRIVMSG;
    strcpy(m->sender, "ann!a@h");
    if (i >= hay_rows)
      strcpy(m->content, "needle");
    else if (!hay_len)
      strcpy(m->content, "hay");
    else {
      memset(m->content, 'h', hay_len);
      m->content[hay_len] = '\0';
    }
  }
  rows_read++;
}

/** The walk: newest first through the filter's hook, the newest @a limit
 * kept rows returned oldest first -- history_query_internal()'s contract
 * for BEFORE, as far as the search uses it. */
int history_query_before(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result,
                         struct HistoryRowFilter *filter)
{
  struct SearchMatch *sm = (struct SearchMatch *)filter->ctx;
  int i, count = 0;

  walks++;
  snprintf(seen.target, sizeof(seen.target), "%s", target);
  snprintf(seen.before, sizeof(seen.before), "%s", reference);
  seen.ref_type = ref_type;
  seen.limit = limit;
  seen.filter = *filter;
  seen.sm = *sm;
  snprintf(seen.text, sizeof(seen.text), "%s", sm->text ? sm->text : "");

  *result = NULL;
  if (walk_fails)
    return -1;
  for (i = nrows - 1; i >= 0 && count < limit; i--) {
    struct HistoryMessage m, *keep;
    int64_t skip_to = 0;
    int v;

    if (filter->scanned >= filter->scan_max) {
      filter->truncated = 1;
      break;
    }
    filter->scanned++;
    row_fill(&m, i);
    v = filter->fn(&m, 1, filter->ctx, &skip_to);
    if (v < 0)
      break;
    if (v == 0)
      continue;
    keep = (struct HistoryMessage *)malloc(sizeof(*keep));
    *keep = m;
    keep->next = *result;
    *result = keep;
    count++;
  }
  return count;
}

/* ---- the requester's presence ---- */

static struct PresenceQueryFilter *the_pf = (struct PresenceQueryFilter *)&tasks;
static int pf_opens, pf_closes, pf_open_fails;
static int presence_calls;
static char presence_target[CHANNELLEN + 1];

/** Presence: the requester saw everything from AB-2 on. */
static int presence_fn(const struct HistoryMessage *msg, int reverse,
                       void *ctx, int64_t *skip_to)
{
  presence_calls++;
  assert_ptr_equal(ctx, the_pf);
  return strcmp(msg->msgid, "AB-1") ? 1 : -1;
}

static struct HistoryRowFilter presence_hook;

struct PresenceQueryFilter *presence_query_filter_open(struct Client *sptr,
                                                       const char *target,
                                                       int ops_override,
                                                       int *rc)
{
  assert_ptr_equal(sptr, &requester);
  assert_int_equal(ops_override, 0);
  snprintf(presence_target, sizeof(presence_target), "%s", target);
  if (pf_open_fails) {
    *rc = -1;
    return NULL;
  }
  *rc = 0;
  pf_opens++;
  return the_pf;
}

struct HistoryRowFilter *presence_query_filter_hook(struct PresenceQueryFilter *pf)
{
  if (!pf)
    return NULL;
  memset(&presence_hook, 0, sizeof(presence_hook));
  presence_hook.fn = presence_fn;
  presence_hook.ctx = pf;
  return &presence_hook;
}

void presence_query_filter_close(struct PresenceQueryFilter *pf)
{
  if (pf) {
    assert_ptr_equal(pf, the_pf);
    pf_closes++;
  }
}

/* ------------------------------------------------------------------ */
/* A CH Q S line                                                       */
/* ------------------------------------------------------------------ */

/** CH Q <target> S <before> <limit> <reqid> <dest> <after> <requester>
 * <type mask> :<selectors>, as search_fed_start() sends it.  Every
 * parameter is a copy the case overwrites once ms_chathistory() has
 * returned: a job that kept a pointer into the line reads X's. */
static void q_s(const char *target, const char *before, const char *limit,
                const char *after, const char *req, const char *mask,
                const char *sel)
{
  static char buf[12][512];
  const char *in[12] = { "CD", "Q", target, "S", before, limit, "CD7", "AB",
                         after, req, mask, sel };
  char *parv[13];
  int i;

  for (i = 0; i < 12; i++) {
    snprintf(buf[i], sizeof(buf[i]), "%s", in[i]);
    parv[i] = buf[i];
  }
  parv[12] = NULL;
  assert_int_equal(ms_chathistory(&origin, &origin, 12, parv), 0);
  for (i = 0; i < 12; i++)
    memset(buf[i], 'X', sizeof(buf[i]) - 1);
}

/** The usual line: needles, newest 50 before 1700000100, no requester. */
static void q_s_needle(void)
{
  q_s("#chan", "1700000100.000", "50", "*", "*", "0", "text=needle");
}

static void assert_lines(int n, ...)
{
  va_list vl;
  int i;

  va_start(vl, n);
  for (i = 0; i < n; i++) {
    const char *want = va_arg(vl, const char *);

    assert_true(i < nlines);
    assert_string_equal(lines[i], want);
  }
  va_end(vl);
  assert_int_equal(nlines, n);
  assert_int_equal(misdirected, 0);
}

/** Nothing of a job is left: the view and the presence filter went back
 * once each, and the store module holds nothing. */
static void assert_all_given_back(void)
{
  unsigned int in_pool, waiting;

  store_jobs_count(&in_pool, &waiting);
  assert_int_equal(in_pool, 0);
  assert_int_equal(waiting, 0);
  assert_int_equal(views_closed, views_open);
  assert_int_equal(pf_closes, pf_opens);
}

static int setup(void **state)
{
  memset(&me, 0, sizeof(me));
  memset(&origin, 0, sizeof(origin));
  memset(&other, 0, sizeof(other));
  memset(&requester, 0, sizeof(requester));
  memset(&requester_user, 0, sizeof(requester_user));
  cli_status(&me) = STAT_ME;
  strcpy(cli_yxx(&me), "AB");
  strcpy(cli_name(&me), "store.test");
  cli_status(&origin) = STAT_SERVER;
  strcpy(cli_yxx(&origin), "CD");
  strcpy(cli_name(&origin), "asking.test");
  cli_status(&other) = STAT_SERVER;
  strcpy(cli_yxx(&other), "CD");
  cli_status(&requester) = STAT_USER;
  cli_user(&requester) = &requester_user;
  strcpy(requester_user.account, "ann");
  SetFlag(&requester, FLAG_ACCOUNT);
  origin_now = &origin;

  pool_on = 1;
  tasks = 0;
  memset(&task, 0, sizeof(task));
  rows = few_rows;
  nrows = (int)(sizeof(few_rows) / sizeof(few_rows[0]));
  hay_rows = 0;
  hay_len = 0;
  rows_read = 0;
  walks = walk_fails = freed_rows = 0;
  redacted_id = unread_id = NULL;
  memset(&seen, 0, sizeof(seen));
  lookup_view = NULL;
  view_fails = views_open = views_closed = 0;
  pf_opens = pf_closes = pf_open_fails = presence_calls = 0;
  warnings = 0;
  last_warning[0] = '\0';
  nlines = misdirected = 0;
  return 0;
}

static int teardown(void **state)
{
  while (nlines > 0)
    free(lines[--nlines]);
  return 0;
}

/* ------------------------------------------------------------------ */
/* The copy-in                                                         */
/* ------------------------------------------------------------------ */

/** Everything the scan needs is in the job when ms_chathistory() returns,
 * as of then, and none of it is the line's memory. */
static void the_line_is_copied_into_the_job(void **state)
{
  struct SearchJob *sj;

  q_s("#chan", "1700000100.250", "50", "1700000001.500", "PCDAAB", "5",
      "from=ann text=a\\sneedle\\\\x");
  sj = the_job();

  /* Nothing ran and nothing was said: the scan is the worker's. */
  assert_int_equal(walks, 0);
  assert_int_equal(nlines, 0);

  assert_ptr_equal(sj->job.link, &origin);
  assert_string_equal(sj->origin_yxx, "CD");
  assert_string_equal(sj->reqid, "CD7");
  assert_string_equal(sj->target, "#chan");
  assert_string_equal(sj->before, "1700000100.250");
  assert_int_equal(sj->limit, 50);
  assert_int_equal(sj->clamped, 0);
  /* The selectors, unescaped; the text lives in the job. */
  assert_string_equal(sj->sm.from, "ann");
  assert_string_equal(sj->sm.text, "a needle\\x");
  assert_true(sj->sm.text >= sj->sel && sj->sm.text < sj->sel + sizeof(sj->sel));
  assert_true(sj->sm.after_ms == 1700000001500LL);
  /* The requester's presence (its hook and context travel as they are),
   * its type mask, the veto; the channel's incarnation and the view. */
  assert_string_equal(presence_target, "#chan");
  assert_ptr_equal(sj->pf, the_pf);
  assert_ptr_equal(sj->base.fn, presence_fn);
  assert_ptr_equal(sj->base.ctx, the_pf);
  assert_int_equal(sj->base.type_mask, 5);
  assert_ptr_equal(sj->base.veto, typing_only_veto);
  assert_int_equal(sj->base.live_inc_set, 1);
  assert_true(sj->base.live_inc == 1699990000);
  assert_ptr_equal(sj->view, the_view);
  assert_ptr_equal(sj->base.view, the_view);
  assert_int_equal(views_open, 1);
  assert_int_equal(views_closed, 0);

  /* The line is X's by now (q_s): the walk still gets what it said. */
  worker_runs();
  assert_int_equal(walks, 1);
  assert_string_equal(seen.target, "#chan");
  assert_string_equal(seen.before, "1700000100.250");
  assert_int_equal(seen.ref_type, HISTORY_REF_TIMESTAMP);
  assert_int_equal(seen.limit, 50);
  assert_ptr_equal(seen.filter.fn, search_row_hook);
  assert_int_equal(seen.filter.scan_max, SEARCH_SCAN_MAX);
  assert_int_equal(seen.filter.type_mask, 5);
  assert_ptr_equal(seen.filter.veto, typing_only_veto);
  assert_ptr_equal(seen.filter.view, the_view);
  assert_int_equal(seen.filter.live_inc_set, 1);
  assert_true(seen.filter.live_inc == 1699990000);
  assert_ptr_equal(seen.sm.presence_fn, presence_fn);
  assert_ptr_equal(seen.sm.view, the_view);
  assert_string_equal(seen.sm.from, "ann");
  assert_string_equal(seen.text, "a needle\\x");
  assert_true(presence_calls > 0);
  /* run() gave the view back; the presence filter is done()'s. */
  assert_int_equal(views_closed, 1);
  assert_int_equal(pf_closes, 0);

  callback_runs();
  assert_lines(1, "E CD7 0");
  assert_all_given_back();
}

/** A requester with no account, or none named: no presence filter, the
 * bare filter with the type mask and the veto. */
static void without_a_requester_the_walk_is_unfiltered(void **state)
{
  struct SearchJob *sj;

  q_s("#chan", "1700000100.000", "50", "*", "*", "0", "text=needle");
  sj = the_job();
  assert_null(sj->pf);
  assert_null(sj->base.fn);
  assert_int_equal(sj->base.type_mask, 0);
  assert_ptr_equal(sj->base.veto, typing_only_veto);
  assert_true(sj->sm.after_ms == 0);
  assert_string_equal(sj->sm.from, "");
  assert_int_equal(pf_opens, 0);
  worker_runs();
  callback_runs();
  assert_all_given_back();
}

/** The limit is the asking server's word: cut to what a requester keeps
 * for one request, and the answer says so (T) when that was filled. */
static void the_limit_is_cut_to_what_a_requester_keeps(void **state)
{
  struct SearchJob *sj;

  rows = NULL;
  nrows = MAX_FED_MESSAGES + 100;
  q_s("#chan", "1800000000.000", "2000000000", "*", "*", "0", "text=needle");
  sj = the_job();
  assert_int_equal(sj->limit, MAX_FED_MESSAGES);
  assert_int_equal(sj->clamped, 1);
  worker_runs();
  assert_int_equal(seen.limit, MAX_FED_MESSAGES);
  assert_int_equal(sj->count, MAX_FED_MESSAGES);
  callback_runs();
  /* The newest MAX_FED_MESSAGES, oldest of them first. */
  assert_int_equal(nlines, MAX_FED_MESSAGES + 1);
  assert_non_null(strstr(lines[0], " AB-101 "));
  assert_non_null(strstr(lines[MAX_FED_MESSAGES - 1], " AB-600 "));
  assert_string_equal(lines[MAX_FED_MESSAGES], "E CD7 500 T");
  assert_int_equal(freed_rows, MAX_FED_MESSAGES);
  assert_all_given_back();
}

/** A limit a requester can keep is not touched, and filling it is not T. */
static void a_limit_within_the_bound_is_kept(void **state)
{
  struct SearchJob *sj;

  rows = NULL;
  nrows = MAX_FED_MESSAGES + 100;
  q_s("#chan", "1800000000.000", "500", "*", "*", "0", "text=needle");
  sj = the_job();
  assert_int_equal(sj->limit, MAX_FED_MESSAGES);
  assert_int_equal(sj->clamped, 0);
  worker_runs();
  callback_runs();
  assert_int_equal(nlines, MAX_FED_MESSAGES + 1);
  assert_string_equal(lines[MAX_FED_MESSAGES], "E CD7 500");
  assert_all_given_back();
}

/** A line without <before> is answered at once, empty, and the presence
 * filter opened for it is closed. */
static void a_line_without_before_is_answered_empty(void **state)
{
  q_s("#chan", "*", "50", "*", "PCDAAB", "0", "text=needle");
  assert_int_equal(tasks, 0);
  assert_int_equal(walks, 0);
  assert_lines(1, "E CD7 0");
  assert_int_equal(pf_opens, 1);
  assert_all_given_back();
}

/* ------------------------------------------------------------------ */
/* The answer                                                          */
/* ------------------------------------------------------------------ */

/** The rows, oldest first, then E with their count.  The selectors are
 * the real hook's: text anywhere and caseless, from= a whole nick, a
 * JOIN row never. */
static void done_sends_the_rows_then_E(void **state)
{
  q_s_needle();
  the_job();
  worker_runs();
  assert_int_equal(nlines, 0);          /* the worker sends nothing */
  callback_runs();
  assert_lines(5,
               "R CD7 AB-1 1700000001.000 0 ann!a@h ann :a needle here",
               "R CD7 AB-3 1700000003.000 0 ann!a@h ann :second NEEDLE",
               "R CD7 AB-5 1700000005.000 1 ann!a@h ann :needle three",
               "R CD7 AB-6 1700000006.000 0 annie!a@h * :needle, not ann's",
               "E CD7 4");
  assert_int_equal(freed_rows, 4);
  assert_int_equal(warnings, 0);
  assert_all_given_back();
}

static void done_with_from_and_a_floor(void **state)
{
  q_s("#chan", "1700000100.000", "50", "1700000002.000", "*", "0",
      "from=ann text=needle");
  the_job();
  worker_runs();
  callback_runs();
  assert_lines(3,
               "R CD7 AB-3 1700000003.000 0 ann!a@h ann :second NEEDLE",
               "R CD7 AB-5 1700000005.000 1 ann!a@h ann :needle three",
               "E CD7 2");
  assert_all_given_back();
}

/** The requester's presence decides first: nothing from before it saw. */
static void done_with_the_requesters_presence(void **state)
{
  q_s("#chan", "1700000100.000", "50", "*", "PCDAAB", "0", "text=needle");
  the_job();
  worker_runs();
  callback_runs();
  assert_lines(4,
               "R CD7 AB-3 1700000003.000 0 ann!a@h ann :second NEEDLE",
               "R CD7 AB-5 1700000005.000 1 ann!a@h ann :needle three",
               "R CD7 AB-6 1700000006.000 0 annie!a@h * :needle, not ann's",
               "E CD7 3");
  assert_all_given_back();
}

/** A requester whose presence cannot be opened gets the empty answer the
 * origin would give, at once. */
static void a_presence_that_fails_closed_answers_empty(void **state)
{
  pf_open_fails = 1;
  q_s("#chan", "1700000100.000", "50", "*", "PCDAAB", "0", "text=needle");
  assert_int_equal(tasks, 0);
  assert_lines(1, "E CD7 0");
  assert_all_given_back();
}

/** A redacted match is not a row; the lookup goes through the job's
 * view.  One whose redaction cannot be read is hidden too, and the main
 * thread says so once. */
static void done_hides_a_redacted_match(void **state)
{
  redacted_id = "AB-3";
  unread_id = "AB-5";
  q_s_needle();
  the_job();
  worker_runs();
  assert_ptr_equal(lookup_view, the_view);
  assert_int_equal(warnings, 0);        /* the worker does not log */
  callback_runs();
  assert_lines(3,
               "R CD7 AB-1 1700000001.000 0 ann!a@h ann :a needle here",
               "R CD7 AB-6 1700000006.000 0 annie!a@h * :needle, not ann's",
               "E CD7 2");
  assert_int_equal(warnings, 1);
  assert_non_null(strstr(last_warning, "1 match(es) not shown"));
  assert_all_given_back();
}

/** The scan budget cut the scan: the rows it found, and T. */
static void done_with_T_when_the_budget_cut_the_scan(void **state)
{
  struct SearchJob *sj;

  /* Three matches, then more hay than the budget. */
  rows = NULL;
  nrows = SEARCH_SCAN_MAX + 10;
  hay_rows = nrows - 3;
  q_s("#chan", "1800000000.000", "50", "*", "*", "0", "text=needle");
  sj = the_job();
  worker_runs();
  assert_int_equal(sj->count, 3);
  assert_int_equal(sj->truncated, 1);
  assert_int_equal(sj->budget_left, 0);
  callback_runs();
  assert_int_equal(nlines, 4);
  assert_non_null(strstr(lines[0], " AB-50008 "));
  assert_non_null(strstr(lines[2], " AB-50010 "));
  assert_string_equal(lines[3], "E CD7 3 T");
  assert_all_given_back();
}

/** #161: the budget is also bytes.  Rows of 4000 bytes, more of them
 * than the byte budget reads and far fewer than the row budget: the scan
 * ends when the bytes run out, with rows to spare, and says so with T as
 * when the row budget runs out. */
static void done_with_T_when_the_byte_budget_cut_the_scan(void **state)
{
  struct SearchJob *sj;

  assert_true(4000 < HISTORY_CONTENT_LEN);
  rows = NULL;
  hay_len = 4000;
  nrows = (int)(SEARCH_SCAN_BYTES / 4000) + 1000;
  assert_true(nrows < SEARCH_SCAN_MAX);
  hay_rows = nrows - 3;
  q_s("#chan", "1800000000.000", "50", "*", "*", "0", "text=needle");
  sj = the_job();
  worker_runs();
  assert_int_equal(sj->count, 3);
  assert_int_equal(sj->truncated, 1);
  assert_true(sj->budget_left > 0);
  /* The bytes read: the budget, then the row that found it spent. */
  assert_true(rows_read <= (int)(SEARCH_SCAN_BYTES / 4000) + 5);
  assert_true(rows_read < nrows);
  callback_runs();
  assert_int_equal(nlines, 4);
  assert_string_equal(lines[3], "E CD7 3 T");
  assert_all_given_back();
}

/** An ordinary search -- the whole row budget of 200-byte rows -- is
 * not cut by the byte budget. */
static void ordinary_rows_are_not_cut_by_the_byte_budget(void **state)
{
  struct SearchJob *sj;

  rows = NULL;
  hay_len = 200;
  nrows = SEARCH_SCAN_MAX;
  hay_rows = nrows - 3;
  q_s("#chan", "1800000000.000", "50", "*", "*", "0", "text=needle");
  sj = the_job();
  worker_runs();
  assert_int_equal(rows_read, nrows);
  assert_int_equal(sj->count, 3);
  assert_int_equal(sj->truncated, 0);
  callback_runs();
  assert_string_equal(lines[3], "E CD7 3");
  assert_all_given_back();
}

/** #164: `before` is "at or before".  The walk's reference excludes its
 * own millisecond, so SEARCH hands it the millisecond after. */
static void the_before_bound_takes_in_its_millisecond(void **state)
{
  char b[HISTORY_TIMESTAMP_LEN];

  search_before_bound("1700000100.250", b, sizeof(b));
  assert_string_equal(b, "1700000100.251");
  search_before_bound("1700000100.999", b, sizeof(b));
  assert_string_equal(b, "1700000101.000");
  search_before_bound("1700000100.000", b, sizeof(b));
  assert_string_equal(b, "1700000100.001");
  /* In place, as m_search calls it. */
  strcpy(b, "1700000100.250");
  search_before_bound(b, b, sizeof(b));
  assert_string_equal(b, "1700000100.251");
}

/** The store could not be read: E 0 U, no row, and the one log line a
 * failed read leaves (the worker's own are dropped). */
static void done_with_a_store_error_says_U(void **state)
{
  walk_fails = 1;
  q_s_needle();
  the_job();
  worker_runs();
  assert_int_equal(warnings, 0);
  callback_runs();
  assert_lines(1, "E CD7 0 U");
  assert_int_equal(warnings, 1);
  assert_non_null(strstr(last_warning, "could not read the store"));
  assert_non_null(strstr(last_warning, "asking.test"));
  assert_all_given_back();
}

/** No snapshot to be had: the same answer, at once, with no job. */
static void without_a_view_the_answer_is_U(void **state)
{
  view_fails = 1;
  q_s("#chan", "1700000100.000", "50", "*", "PCDAAB", "0", "text=needle");
  assert_int_equal(tasks, 0);
  assert_int_equal(walks, 0);
  assert_lines(1, "E CD7 0 U");
  assert_int_equal(pf_closes, 1);
  assert_all_given_back();
}

/** No pool: the scan runs inside ms_chathistory(), as it always did. */
static void without_a_pool_the_line_is_answered_at_once(void **state)
{
  pool_on = 0;
  q_s_needle();
  assert_int_equal(tasks, 0);
  assert_int_equal(walks, 1);
  assert_int_equal(nlines, 5);
  assert_string_equal(lines[4], "E CD7 4");
  assert_all_given_back();
}

/* ------------------------------------------------------------------ */
/* The asking server has left                                          */
/* ------------------------------------------------------------------ */

/** It left before a worker took the job (chathistory_fed_cleanup_link ->
 * store_jobs_link_gone): the scan never runs, the view goes back on the
 * main thread, and nothing is sent. */
static void a_job_whose_server_left_first_never_runs(void **state)
{
  q_s("#chan", "1700000100.000", "50", "*", "PCDAAB", "0", "text=needle");
  the_job();
  store_jobs_link_gone(&origin);
  assert_int_equal(views_closed, 1);    /* abandoned, here */
  origin_now = NULL;

  worker_runs();                        /* the worker reaches it: cancelled */
  assert_int_equal(walks, 0);
  callback_runs();
  assert_int_equal(nlines, 0);
  assert_int_equal(warnings, 0);
  assert_all_given_back();
}

/** It left while the worker was scanning, or between the scan and the
 * callback: the rows are freed and nothing is sent. */
static void a_job_whose_server_left_after_the_scan_sends_nothing(void **state)
{
  q_s("#chan", "1700000100.000", "50", "*", "PCDAAB", "0", "text=needle");
  the_job();
  worker_runs();
  assert_int_equal(walks, 1);
  store_jobs_link_gone(&origin);
  origin_now = NULL;
  callback_runs();
  assert_int_equal(nlines, 0);
  assert_int_equal(freed_rows, 3);
  assert_all_given_back();
}

/** The same with a store error: no E 0 U to nobody, and the log line
 * names no server. */
static void a_failed_scan_for_a_server_that_left_sends_nothing(void **state)
{
  walk_fails = 1;
  q_s_needle();
  the_job();
  worker_runs();
  store_jobs_link_gone(&origin);
  callback_runs();
  assert_int_equal(nlines, 0);
  assert_int_equal(warnings, 1);
  assert_non_null(strstr(last_warning, "a server that has left"));
  assert_all_given_back();
}

/** done() looks twice: a link nobody cleared, whose numeric now names
 * another server (or none), is not answered either. */
static void done_checks_the_numeric_again(void **state)
{
  q_s_needle();
  the_job();
  worker_runs();
  origin_now = &other;
  callback_runs();
  assert_int_equal(nlines, 0);
  assert_int_equal(freed_rows, 4);
  assert_all_given_back();
}

/* ------------------------------------------------------------------ */
/* The row limit of a page query (L, A, R)                             */
/* ------------------------------------------------------------------ */

/* The page walks, as far as the limit goes: the table's rows, oldest
 * first; L keeps the newest @a limit of them, A the oldest.  The page
 * path runs synchronously: no job, no presence (no P/F requester). */
static int page_walk(int limit, int newest, struct HistoryMessage **result)
{
  struct HistoryMessage *tail = NULL;
  int i, first, n;

  walks++;
  seen.limit = limit;
  *result = NULL;
  n = limit < nrows ? limit : nrows;
  if (n <= 0)
    return 0;
  first = newest ? nrows - n : 0;
  for (i = first; i < first + n; i++) {
    struct HistoryMessage *m = (struct HistoryMessage *)malloc(sizeof(*m));

    row_fill(m, i);
    if (tail)
      tail->next = m;
    else
      *result = m;
    tail = m;
  }
  return n;
}

int history_query_latest(const char *p0, enum HistoryRefType p1, const char *p2, int limit,
                         struct HistoryMessage **result, struct HistoryRowFilter *p5)
{
  return page_walk(limit, 1, result);
}

int history_query_after(const char *p0, enum HistoryRefType p1, const char *p2, int limit,
                        struct HistoryMessage **result, struct HistoryRowFilter *p5)
{
  return page_walk(limit, 0, result);
}

/** AROUND: only what it was asked for; nothing found, both sides open. */
int history_query_around(const char *p0, enum HistoryRefType p1, const char *p2, int limit,
                         struct HistoryMessage **result, struct HistoryRowFilter *p5,
                         int *exhausted)
{
  walks++;
  seen.limit = limit;
  *result = NULL;
  if (exhausted)
    *exhausted = 0;
  return 0;
}

int history_attach_context(const char *p0, struct HistoryMessage *p1) { return 0; }

/** CH Q <target> <sub> <ref> <limit> <reqid> <dest> * * 0, as
 * start_fed_query() sends a page query, addressed to this server. */
static void q_page(const char *sub, const char *limit)
{
  static char buf[11][64];
  const char *in[11] = { "CD", "Q", "#chan", sub, "*", limit, "CD7", "AB",
                         "*", "*", "0" };
  char *parv[12];
  int i;

  for (i = 0; i < 11; i++) {
    snprintf(buf[i], sizeof(buf[i]), "%s", in[i]);
    parv[i] = buf[i];
  }
  parv[11] = NULL;
  assert_int_equal(ms_chathistory(&origin, &origin, 11, parv), 0);
}

/** The limit text, as the responder answers it. */
static void the_page_limit_is_read_into_a_bounded_range(void **state)
{
  int clamped;

  assert_int_equal(fed_limit_clamp("50", &clamped), 50);
  assert_int_equal(clamped, 0);
  assert_int_equal(fed_limit_clamp("500", &clamped), MAX_FED_MESSAGES);
  assert_int_equal(clamped, 0);
  assert_int_equal(fed_limit_clamp("501", &clamped), MAX_FED_MESSAGES);
  assert_int_equal(clamped, 1);
  assert_int_equal(fed_limit_clamp("2147483647", &clamped), MAX_FED_MESSAGES);
  assert_int_equal(clamped, 1);
  assert_int_equal(fed_limit_clamp("99999999999999999999", &clamped), MAX_FED_MESSAGES);
  assert_int_equal(clamped, 1);
  assert_int_equal(fed_limit_clamp("0", &clamped), 0);
  assert_int_equal(clamped, 0);
  assert_int_equal(fed_limit_clamp("-5", &clamped), 0);
  assert_int_equal(clamped, 0);
  assert_int_equal(fed_limit_clamp("-99999999999999999999", &clamped), 0);
  assert_int_equal(clamped, 0);
  assert_int_equal(fed_limit_clamp("", &clamped), 0);
  assert_int_equal(fed_limit_clamp("x", &clamped), 0);
}

/** A LATEST page asked for more than a requester keeps walks
 * MAX_FED_MESSAGES + 1 (the probe), sends the newest MAX_FED_MESSAGES and
 * says it was cut: T, and U -- the requester's page cannot hold what it
 * asked for, as when it dropped the rows past its own cap itself. */
static void a_page_limit_past_the_bound_is_cut(void **state)
{
  rows = NULL;
  nrows = MAX_FED_MESSAGES + 100;
  q_page("L", "100000");
  assert_int_equal(walks, 1);
  assert_int_equal(seen.limit, MAX_FED_MESSAGES + 1);
  assert_int_equal(nlines, MAX_FED_MESSAGES + 1);
  assert_non_null(strstr(lines[0], " AB-101 "));
  assert_non_null(strstr(lines[MAX_FED_MESSAGES - 1], " AB-600 "));
  assert_string_equal(lines[MAX_FED_MESSAGES], "E CD7 500 TU");
  assert_int_equal(freed_rows, MAX_FED_MESSAGES + 1);
}

/** A limit past INT_MAX, or at it, is the same: no overflow of the probe
 * (it used to walk nothing and answer a bare E, "nothing here"). */
static void a_page_limit_past_int_max_is_cut(void **state)
{
  rows = NULL;
  nrows = 20;
  q_page("L", "99999999999");
  assert_int_equal(seen.limit, MAX_FED_MESSAGES + 1);
  assert_int_equal(nlines, 21);
  assert_string_equal(lines[20], "E CD7 20");
  teardown(state);
  setup(state);
  rows = NULL;
  nrows = 20;
  q_page("L", "2147483647");
  assert_int_equal(seen.limit, MAX_FED_MESSAGES + 1);
  assert_int_equal(nlines, 21);
  assert_string_equal(lines[20], "E CD7 20");
}

/** The bound itself is no cut: filled, it is T alone, as before. */
static void a_page_limit_at_the_bound_is_kept(void **state)
{
  rows = NULL;
  nrows = MAX_FED_MESSAGES + 100;
  q_page("L", "500");
  assert_int_equal(seen.limit, MAX_FED_MESSAGES + 1);
  assert_int_equal(nlines, MAX_FED_MESSAGES + 1);
  assert_string_equal(lines[MAX_FED_MESSAGES], "E CD7 500 T");
}

/** A negative limit asks for nothing: no row, and T when there are rows
 * (it used to answer a bare E, "nothing here"). */
static void a_negative_page_limit_sends_no_row(void **state)
{
  q_page("L", "-5");
  assert_int_equal(seen.limit, 1);
  assert_lines(1, "E CD7 0 T");
}

/** AFTER with a limit of 0: the probe row is not sent (the trim kept it). */
static void an_after_page_of_limit_0_sends_no_row(void **state)
{
  q_page("A", "0");
  assert_int_equal(seen.limit, 1);
  assert_lines(1, "E CD7 0 T");
  assert_int_equal(freed_rows, 1);
}

/** AROUND is bounded too (it has no probe: its two halves are). */
static void an_around_page_limit_past_the_bound_is_cut(void **state)
{
  q_page("R", "100000");
  assert_int_equal(seen.limit, MAX_FED_MESSAGES);
  assert_lines(1, "E CD7 0 T");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(the_line_is_copied_into_the_job, setup, teardown),
    cmocka_unit_test_setup_teardown(without_a_requester_the_walk_is_unfiltered, setup, teardown),
    cmocka_unit_test_setup_teardown(the_limit_is_cut_to_what_a_requester_keeps, setup, teardown),
    cmocka_unit_test_setup_teardown(a_limit_within_the_bound_is_kept, setup, teardown),
    cmocka_unit_test_setup_teardown(a_line_without_before_is_answered_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(done_sends_the_rows_then_E, setup, teardown),
    cmocka_unit_test_setup_teardown(done_with_from_and_a_floor, setup, teardown),
    cmocka_unit_test_setup_teardown(done_with_the_requesters_presence, setup, teardown),
    cmocka_unit_test_setup_teardown(a_presence_that_fails_closed_answers_empty, setup, teardown),
    cmocka_unit_test_setup_teardown(done_hides_a_redacted_match, setup, teardown),
    cmocka_unit_test_setup_teardown(done_with_T_when_the_budget_cut_the_scan, setup, teardown),
    cmocka_unit_test_setup_teardown(done_with_T_when_the_byte_budget_cut_the_scan, setup, teardown),
    cmocka_unit_test_setup_teardown(ordinary_rows_are_not_cut_by_the_byte_budget, setup, teardown),
    cmocka_unit_test_setup_teardown(the_before_bound_takes_in_its_millisecond, setup, teardown),
    cmocka_unit_test_setup_teardown(done_with_a_store_error_says_U, setup, teardown),
    cmocka_unit_test_setup_teardown(without_a_view_the_answer_is_U, setup, teardown),
    cmocka_unit_test_setup_teardown(without_a_pool_the_line_is_answered_at_once, setup, teardown),
    cmocka_unit_test_setup_teardown(a_job_whose_server_left_first_never_runs, setup, teardown),
    cmocka_unit_test_setup_teardown(a_job_whose_server_left_after_the_scan_sends_nothing, setup, teardown),
    cmocka_unit_test_setup_teardown(a_failed_scan_for_a_server_that_left_sends_nothing, setup, teardown),
    cmocka_unit_test_setup_teardown(done_checks_the_numeric_again, setup, teardown),
    cmocka_unit_test_setup_teardown(the_page_limit_is_read_into_a_bounded_range, setup, teardown),
    cmocka_unit_test_setup_teardown(a_page_limit_past_the_bound_is_cut, setup, teardown),
    cmocka_unit_test_setup_teardown(a_page_limit_past_int_max_is_cut, setup, teardown),
    cmocka_unit_test_setup_teardown(a_page_limit_at_the_bound_is_kept, setup, teardown),
    cmocka_unit_test_setup_teardown(a_negative_page_limit_sends_no_row, setup, teardown),
    cmocka_unit_test_setup_teardown(an_after_page_of_limit_0_sends_no_row, setup, teardown),
    cmocka_unit_test_setup_teardown(an_around_page_limit_past_the_bound_is_cut, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}

/* ------------------------------------------------------------------ */
/* The rest of the ircd                                                */
/* ------------------------------------------------------------------ */

/* What ms_chathistory()'s other subcommands, and the requester's side of
 * a federated query, call.  The S path and the page-limit cases reach
 * none of it: a case that gets here has left the path under test. */
static void never(const char *what) __attribute__((noreturn));
static void never(const char *what)
{
  print_error("%s() reached: not the SEARCH responder's path\n", what);
  abort();
}

void add_isupport_i(const char *p0, int p1) { never("add_isupport_i"); }
unsigned int base64toint(const char *p0) { never("base64toint"); }
unsigned int ch_ad_features(const char *p0) { never("ch_ad_features"); }
size_t ch_ad_letters(const char *p0, char *p1, size_t p2) { never("ch_ad_letters"); }
unsigned int ch_e_flags(const char *p0) { never("ch_e_flags"); }
int chathistory_ephemeral_has_target(struct Client *p0, const char *p1) { never("chathistory_ephemeral_has_target"); }
int chathistory_ephemeral_targets(struct Client *p0, uint64_t p1, struct HistoryTarget **p2) { never("chathistory_ephemeral_targets"); }
size_t client_find_by_session_id(const char *p0, struct Client **p1, size_t p2) { never("client_find_by_session_id"); }
void del_isupport(const char *p0) { never("del_isupport"); }
struct ConfItem *find_conf_byhost(struct SLink *p0, const char *p1, int p2) { never("find_conf_byhost"); }
struct Membership *find_member_link(struct Channel *p0, const struct Client *p1) { never("find_member_link"); }
struct Channel *hSeekChannel(const char *p0) { never("hSeekChannel"); }
struct Client *hSeekClient(const char *p0, int p1) { never("hSeekClient"); }
int history_between_descending(const char *p0, enum HistoryRefType p1, const char *p2, enum HistoryRefType p3, const char *p4) { never("history_between_descending"); }
int history_deserialize_record(const void *p0, size_t p1, struct HistoryMessage *p2) { never("history_deserialize_record"); }
char *history_forward_split(char *p0, char **p1) { never("history_forward_split"); }
void history_format_ms(char *buf, size_t n, uint64_t ms)
{
  snprintf(buf, n, "%lu.%03lu", (unsigned long)(ms / 1000), (unsigned long)(ms % 1000));
}
void history_free_targets(struct HistoryTarget *p0) { never("history_free_targets"); }
int history_has_channel(const char *p0) { never("history_has_channel"); }
int history_has_msgid(const char *p0) { never("history_has_msgid"); }
int history_identity_pm_targets(const char *p0, uint64_t p1, uint64_t p2, int p3, int p4, struct HistoryTarget **p5, history_target_filter_fn p6, void *p7) { never("history_identity_pm_targets"); }
int history_lookup_message(const char *p0, const char *p1, struct HistoryMessage **p2) { never("history_lookup_message"); }
int history_ref_to_unix(const char *p0, char *p1, size_t p2) { never("history_ref_to_unix"); }
int history_lookup_live_message(const char *p0, const char *p1, struct HistoryMessage **p2) { never("history_lookup_live_message"); }
int history_msgid_ref_timestamp(const char *p0, const char *p1, char *p2) { never("history_msgid_ref_timestamp"); }
void history_pm_identity(struct Client *p0, char *p1, size_t p2) { never("history_pm_identity"); }
int history_pm_identity_matches(struct Client *p0, const char *p1, size_t p2) { never("history_pm_identity_matches"); }
int history_pm_index_whole(void) { never("history_pm_index_whole"); }
int history_pm_target_has_sessid(const char *p0, const char *p1) { never("history_pm_target_has_sessid"); }
int history_query_between(const char *p0, enum HistoryRefType p1, const char *p2, enum HistoryRefType p3, const char *p4, int p5, struct HistoryMessage **p6, struct HistoryRowFilter *p7) { never("history_query_between"); }
void history_recv_link_up(void) { never("history_recv_link_up"); }
void history_recv_peers_linked(int p0) { never("history_recv_peers_linked"); }
int history_redact_index_scan(uint64_t p0, int p1, history_rdx_cb p2, void *p3, int *p4) { never("history_redact_index_scan"); }
int history_redact_lookup(struct HistoryRedactLookup *p0, const char *p1, const char *p2, int p3) { never("history_redact_lookup"); }
void history_redact_lookup_close(struct HistoryRedactLookup *p0) { never("history_redact_lookup_close"); }
struct HistoryRedactLookup *history_redact_lookup_open(void) { never("history_redact_lookup_open"); }
int history_redact_message(const char *p0, const char *p1) { never("history_redact_message"); }
uint64_t history_redact_watermark_get(void) { never("history_redact_watermark_get"); }
int history_redact_watermark_set(uint64_t p0) { never("history_redact_watermark_set"); }
int history_store_message(const char *p0, const char *p1, const char *p2, const char *p3, const char *p4, const char *p5, enum HistoryMessageType p6, const char *p7, const char *p8, const char *p9) { never("history_store_message"); }
int history_target_latest(const char *p0, char *p1, size_t p2) { never("history_target_latest"); }
int history_unix_to_iso(const char *p0, char *p1, size_t p2) { never("history_unix_to_iso"); }
int htc_owner_key(char *p0, size_t p1, const char *p2, const struct irc_in_addr *p3, const char *p4) { never("htc_owner_key"); }
const char *inttobase64(char *p0, unsigned int p1, unsigned int p2) { never("inttobase64"); }
const char *presence_anchor_for(const struct Client *p0, int *p1) { never("presence_anchor_for"); }
int presence_filter_messages(struct Client *p0, const char *p1, struct HistoryMessage **p2, int p3, int p4) { never("presence_filter_messages"); }
int presence_was_present(const char *p0, int p1, const char *p2, int64_t p3) { never("presence_was_present"); }
int rdx_reply_parse(int p0, char **p1, struct rdx_reply *p2) { never("rdx_reply_parse"); }
enum rdx_retry rdx_retry_decide(enum rdx_wm p0, int p1) { never("rdx_retry_decide"); }
int rdx_retry_next_delay(int p0) { never("rdx_retry_next_delay"); }
enum rdx_wm rdx_watermark_decide(int p0, int p1, int p2, int p3, uint64_t p4, uint64_t p5, uint64_t *p6) { never("rdx_watermark_decide"); }
int redact_apply_row(struct Client *p0, struct Channel *p1, const char *p2, const char *p3, uint64_t p4, const char *p5, const char *p6, const char *p7, int p8) { never("redact_apply_row"); }
int redact_row_judge(const char *p0, const char *p1) { never("redact_row_judge"); }
int replay_pm_display_nick(struct Client *p0, const char *p1, char *p2, size_t p3) { never("replay_pm_display_nick"); }
struct PmNickMap *replay_pm_nick_map(struct Client *p0) { never("replay_pm_nick_map"); }
int replay_pm_nick_map_find(const struct PmNickMap *p0, const char *p1, char *p2, size_t p3) { never("replay_pm_nick_map_find"); }
void replay_pm_nick_map_free(struct PmNickMap *p0) { never("replay_pm_nick_map_free"); }
int replay_pm_pair_for_nick(struct Client *p0, const char *p1, char *p2, size_t p3) { never("replay_pm_pair_for_nick"); }
void replay_start_batch(struct Client *p0, const char *p1, struct HistoryMessage *p2, int p3, int p4, const char *p5, int p6, const char *p7, unsigned int p8) { never("replay_start_batch"); }
void send_isupport_update(void) { never("send_isupport_update"); }
void sendcmdto_serv_butone_v3(struct Client *p0, const char *p1, const char *p2, struct Client *p3, const char *p4, ...) { never("sendcmdto_serv_butone_v3"); }
void sendrawto_one(struct Client *p0, const char *p1, ...) { never("sendrawto_one"); }
void timer_add(struct Timer *p0, EventCallBack p1, void *p2, enum TimerType p3, time_t p4) { never("timer_add"); }
void timer_del(struct Timer *p0) { never("timer_del"); }
struct Timer *timer_init(struct Timer *p0) { never("timer_init"); }
