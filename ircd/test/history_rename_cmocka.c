/*
 * history_rename_cmocka.c - chathistory follows a channel RENAME
 * (include/history_rename.h): the renames record and the walk over a
 * channel's rows under every name it has had.
 *
 * One spec, two backends, as db_api_cmocka.c: compiled plain it links
 * the in-memory store (fake_db.o) as history_rename_cmocka; compiled
 * with -DHREN_REAL it links RocksDB (../db_rocksdb.o) against a
 * mkdtemp()'d env as history_rename_rocksdb_cmocka, where the restart
 * test closes the env and opens it again.
 *
 * Rows are real ones: keyed by htc_msg_key, encoded by
 * history_serialize_record with the channel's incarnation.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "history.h"
#include "history_record.h"
#include "history_rename.h"
#include "history_trim_codec.h"

#ifdef HREN_REAL
#include <dirent.h>
#include <unistd.h>
#else
#include "fake_db.h"
#endif

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

static struct db_env *env;
static struct db_cf  *ren;    /* the renames CF */
static struct db_cf  *msgs;   /* the messages CF */
static struct db_cf  *mids;   /* the msgid index CF */

/* The renamed channel's creation timestamp, and a stranger's. */
#define INC   1700000000ULL
#define INC2  1700009000ULL
/* Row and rename times: milliseconds after INC. */
#define MS(n) (INC * 1000ULL + (uint64_t)(n))

#ifdef HREN_REAL
static char g_tmpdir[64];

static void rm_rf(const char *path)
{
  DIR *d = opendir(path);
  struct dirent *e;
  char buf[512];

  if (!d) {
    unlink(path);
    return;
  }
  while ((e = readdir(d)) != NULL) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    snprintf(buf, sizeof buf, "%s/%s", path, e->d_name);
    unlink(buf);
  }
  closedir(d);
  rmdir(path);
}
#endif

static void open_cfs(void)
{
  assert_int_equal(db_cf_open(env, "renames", NULL, &ren), DB_OK);
  assert_int_equal(db_cf_open(env, "messages", NULL, &msgs), DB_OK);
  assert_int_equal(db_cf_open(env, "msgid_index", NULL, &mids), DB_OK);
}

static int test_setup(void **state)
{
  (void)state;
#ifdef HREN_REAL
  {
    static const char tmpl[] = "/tmp/hrenXXXXXX";
    char *r;
    memcpy(g_tmpdir, tmpl, sizeof tmpl);
    r = mkdtemp(g_tmpdir);
    assert_non_null(r);
    assert_int_equal(db_env_open(g_tmpdir, NULL, 8, &env), DB_OK);
  }
#else
  env = fake_db_new();
  assert_non_null(env);
#endif
  open_cfs();
  return 0;
}

static int test_teardown(void **state)
{
  (void)state;
#ifdef HREN_REAL
  db_env_close(env);
  rm_rf(g_tmpdir);
#else
  fake_db_free(env);
#endif
  env = NULL;
  ren = msgs = mids = NULL;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void fmt_ms(char *buf, size_t size, uint64_t ms)
{
  snprintf(buf, size, "%llu.%03llu", (unsigned long long)(ms / 1000),
           (unsigned long long)(ms % 1000));
}

/* Store one PRIVMSG row under @a name at @a ms, of incarnation @a inc. */
static void put_row(const char *name, uint64_t ms, const char *msgid,
                    uint64_t inc)
{
  char key[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char val[1024], ts[HISTORY_TIMESTAMP_LEN];
  struct db_writebatch *wb;
  int kl, vl;

  fmt_ms(ts, sizeof ts, ms);
  kl = htc_msg_key(key, sizeof key, name, ts, msgid);
  assert_true(kl > 0);
  vl = history_serialize_record(val, sizeof val, HISTORY_PRIVMSG,
                                "nick!user@host.example", "acct", msgid,
                                NULL, NULL, (time_t)inc);
  assert_true(vl > 0);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(db_writebatch_put(wb, msgs, key, (size_t)kl, val, (size_t)vl), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
}

/* The msgid index's row for it, as history.c stores one with each row. */
static void put_mid(const char *name, uint64_t ms, const char *msgid)
{
  char key[HISTORY_MSGID_LEN + CHANNELLEN + 4], ts[HISTORY_TIMESTAMP_LEN];
  struct db_writebatch *wb;
  int kl;

  fmt_ms(ts, sizeof ts, ms);
  kl = htc_msgid_key(key, sizeof key, msgid, name);
  assert_true(kl > 0);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(db_writebatch_put(wb, mids, key, (size_t)kl, ts, strlen(ts)), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
}

/* The stamped incarnation of a stored row, as history.c reads it. */
static uint64_t row_inc(const void *val, size_t vlen)
{
  struct HistoryMessage m;

  memset(&m, 0, sizeof m);
  if (history_deserialize_record(val, vlen, &m) != 0)
    return 0;
  return (uint64_t)m.incarnation;
}

/* One collected walk: the msgids in the order the walk gave them, and
 * the target each row's key named. */
struct walked {
  int n;
  char msgid[32][HISTORY_MSGID_LEN];
  char target[32][CHANNELLEN + 1];
};

static void collect(struct hren_iter *it, struct walked *w)
{
  size_t kl;
  const void *k = hren_iter_key(it, &kl);
  char ts[HISTORY_TIMESTAMP_LEN];

  assert_non_null(k);
  assert_true(w->n < 32);
  assert_int_equal(htc_msg_key_parse(k, kl, w->target[w->n], CHANNELLEN + 1,
                                     ts, sizeof ts,
                                     w->msgid[w->n], HISTORY_MSGID_LEN), 0);
  w->n++;
}

static struct hren_iter *open_walk(const char *target, uint64_t inc)
{
  struct hren_span span;
  struct hren_iter *it;

  assert_true(hren_lookup(env, ren, NULL, target, inc, 0, &span) >= 0);
  it = hren_iter_open(env, msgs, NULL, target, &span, row_inc);
  assert_non_null(it);
  return it;
}

/* LATEST: history_query_internal's reverse walk -- seek the far future,
 * fall back to the last row, step back -- newest first, at most
 * @a limit rows before the key at @a from_ms (0 = the end). */
static void walk_back(const char *target, uint64_t inc, uint64_t from_ms,
                      int limit, struct walked *w)
{
  struct hren_iter *it = open_walk(target, inc);
  char key[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8], ts[HISTORY_TIMESTAMP_LEN];
  int kl, rc;

  memset(w, 0, sizeof *w);
  if (from_ms)
    fmt_ms(ts, sizeof ts, from_ms);
  else
    snprintf(ts, sizeof ts, "32503680000.000");
  kl = htc_msg_key(key, sizeof key, target, ts, NULL);
  assert_true(kl > 0);
  rc = hren_iter_seek(it, key, (size_t)kl);
  if (rc == DB_NOTFOUND)
    rc = hren_iter_seek_last(it);
  else if (rc == DB_OK)
    rc = hren_iter_prev(it);
  while (rc == DB_OK && hren_iter_valid(it) && w->n < limit) {
    collect(it, w);
    rc = hren_iter_prev(it);
  }
  assert_true(rc == DB_OK || rc == DB_NOTFOUND);
  hren_iter_close(it);
}

/* AFTER: forwards from the first row at or after @a from_ms. */
static void walk_fwd(const char *target, uint64_t inc, uint64_t from_ms,
                     int limit, struct walked *w)
{
  struct hren_iter *it = open_walk(target, inc);
  char key[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8], ts[HISTORY_TIMESTAMP_LEN];
  int kl, rc;

  memset(w, 0, sizeof *w);
  fmt_ms(ts, sizeof ts, from_ms);
  kl = htc_msg_key(key, sizeof key, target, ts, NULL);
  assert_true(kl > 0);
  rc = hren_iter_seek(it, key, (size_t)kl);
  while (rc == DB_OK && hren_iter_valid(it) && w->n < limit) {
    collect(it, w);
    rc = hren_iter_next(it);
  }
  assert_true(rc == DB_OK || rc == DB_NOTFOUND);
  hren_iter_close(it);
}

static void assert_walk(const struct walked *w, const char *expect)
{
  char got[32 * HISTORY_MSGID_LEN];
  int i;

  got[0] = '\0';
  for (i = 0; i < w->n; i++) {
    if (i)
      strcat(got, " ");
    strcat(got, w->msgid[i]);
  }
  assert_string_equal(got, expect);
}

static int span_of(const char *name, uint64_t inc, struct hren_span *span)
{
  return hren_lookup(env, ren, NULL, name, inc, 0, span);
}

/* ------------------------------------------------------------------ */
/* The record                                                          */
/* ------------------------------------------------------------------ */

static void test_note_and_lookup(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(span_of("#new", INC, &span), 0);
  assert_int_equal(hren_note(env, ren, "#Old[x]", "#New", INC, MS(5000), 0, NULL), 0);
  /* Any spelling of the current name finds it; the earlier name is held
   * folded, as the rows' keys are. */
  assert_int_equal(span_of("#NEW", INC, &span), 1);
  assert_string_equal(span.seg[0].name, "#old{x}");
  assert_true(span.seg[0].incarnation == INC);
  assert_true(span.seg[0].until_ms == MS(5000));
  /* The old name has no earlier names of its own. */
  assert_int_equal(span_of("#old[x]", INC, &span), 0);
  /* Bad input writes nothing. */
  assert_int_equal(hren_note(env, ren, "", "#new", INC, MS(1), 0, NULL), -1);
  assert_int_equal(hren_note(env, ren, "#a", "#b", 0, MS(1), 0, NULL), -1);
  assert_int_equal(hren_note(env, ren, "#a", NULL, INC, MS(1), 0, NULL), -1);
}

/* Two spellings of one name are one key: the rows are where they were. */
static void test_case_only_rename_is_nothing(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#Chan", "#chan", INC, MS(1), 0, NULL), 0);
  assert_int_equal(span_of("#chan", INC, &span), 0);
}

/* #a -> #b -> #c: all of it is #c's, the last name left first; #b's
 * record went with the channel. */
static void test_chain_is_flattened(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#b", "#c", INC, MS(2000), 0, NULL), 0);
  assert_int_equal(span_of("#c", INC, &span), 2);
  assert_string_equal(span.seg[0].name, "#b");
  assert_true(span.seg[0].until_ms == MS(2000));
  assert_string_equal(span.seg[1].name, "#a");
  assert_true(span.seg[1].until_ms == MS(1000));
  assert_int_equal(span_of("#b", INC, &span), 0);
  assert_int_equal(span_of("#a", INC, &span), 0);
}

/* #a -> #b -> #a, over and over: never an entry for the record's own
 * name, one entry per other name, with the latest time it was left. */
static void test_loop_stays_bounded(void **state)
{
  struct hren_span span;
  int i;
  (void)state;

  for (i = 0; i < 50; i++) {
    assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(1000 + 2 * i), 0, NULL), 0);
    assert_int_equal(span_of("#b", INC, &span), 1);
    assert_string_equal(span.seg[0].name, "#a");
    assert_true(span.seg[0].until_ms == MS(1000 + 2 * i));
    assert_int_equal(hren_note(env, ren, "#b", "#a", INC, MS(1001 + 2 * i), 0, NULL), 0);
    assert_int_equal(span_of("#a", INC, &span), 1);
    assert_string_equal(span.seg[0].name, "#b");
    assert_true(span.seg[0].until_ms == MS(1001 + 2 * i));
    assert_int_equal(span_of("#b", INC, &span), 0);
  }
}

/* More names than an incarnation keeps: the earliest leave first. */
static void test_cap_keeps_the_latest(void **state)
{
  struct hren_span span;
  char from[16], to[16];
  int i;
  (void)state;

  for (i = 0; i < HREN_MAX_SEGS + 10; i++) {
    snprintf(from, sizeof from, "#n%d", i);
    snprintf(to, sizeof to, "#n%d", i + 1);
    assert_int_equal(hren_note(env, ren, from, to, INC, MS(1000 + i), 0, NULL), 0);
  }
  snprintf(to, sizeof to, "#n%d", HREN_MAX_SEGS + 10);
  assert_int_equal(span_of(to, INC, &span), HREN_MAX_SEGS);
  snprintf(from, sizeof from, "#n%d", HREN_MAX_SEGS + 9);
  assert_string_equal(span.seg[0].name, from);
  snprintf(from, sizeof from, "#n%d", 10);
  assert_string_equal(span.seg[HREN_MAX_SEGS - 1].name, from);
  for (i = 1; i < span.count; i++)
    assert_true(span.seg[i - 1].until_ms > span.seg[i].until_ms);
}

/* A name's record holds each incarnation's entries apart. */
static void test_incarnations_apart(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#a", "#x", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#q", "#x", INC2, MS(9999000), 0, NULL), 0);
  assert_int_equal(span_of("#x", INC, &span), 1);
  assert_string_equal(span.seg[0].name, "#a");
  assert_int_equal(span_of("#x", INC2, &span), 1);
  assert_string_equal(span.seg[0].name, "#q");
  assert_int_equal(span_of("#x", 12345, &span), 0);
  /* No live channel: every incarnation's. */
  assert_int_equal(span_of("#x", 0, &span), 2);
  /* The second incarnation moves on; the first one's entry stays. */
  assert_int_equal(hren_note(env, ren, "#x", "#y", INC2, MS(9999500), 0, NULL), 0);
  assert_int_equal(span_of("#y", INC2, &span), 2);
  assert_string_equal(span.seg[0].name, "#x");
  assert_string_equal(span.seg[1].name, "#q");
  assert_int_equal(span_of("#x", 0, &span), 1);
  assert_string_equal(span.seg[0].name, "#a");
}

/* An entry behind the retention floor names rows that have aged out. */
static void test_floor_drops_aged_entries(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#b", "#c", INC, MS(2000), 0, NULL), 0);
  assert_int_equal(hren_lookup(env, ren, NULL, "#c", INC, MS(1500), &span), 1);
  assert_string_equal(span.seg[0].name, "#b");
  assert_int_equal(hren_lookup(env, ren, NULL, "#c", INC, MS(2500), &span), 0);
  /* A rename with a floor drops what is behind it from the record. */
  assert_int_equal(hren_note(env, ren, "#c", "#d", INC, MS(3000), MS(1500), NULL), 0);
  assert_int_equal(span_of("#d", INC, &span), 2);
  assert_string_equal(span.seg[0].name, "#c");
  assert_string_equal(span.seg[1].name, "#b");
  /* The sweep drops the rest, and the record with its last entry. */
  assert_int_equal(hren_sweep(env, ren, MS(2500)), 1);
  assert_int_equal(span_of("#d", INC, &span), 1);
  assert_int_equal(hren_sweep(env, ren, MS(3500)), 1);
  assert_int_equal(span_of("#d", INC, &span), 0);
  assert_int_equal(db_exists(env, ren, "#d", 2, NULL), DB_NOTFOUND);
  assert_int_equal(hren_sweep(env, ren, MS(3500)), 0);
}

static void test_forget(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#a", "#x", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#q", "#x", INC2, MS(9999000), 0, NULL), 0);
  assert_int_equal(hren_forget(env, ren, "#X", INC), 0);
  assert_int_equal(span_of("#x", INC, &span), 0);
  assert_int_equal(span_of("#x", INC2, &span), 1);
  assert_int_equal(hren_forget(env, ren, "#x", INC2), 0);
  assert_int_equal(db_exists(env, ren, "#x", 2, NULL), DB_NOTFOUND);
  assert_int_equal(hren_forget(env, ren, "#nothing", INC), 0);
}

/* A value this build cannot read is no earlier names, not an error that
 * fails every query of the channel. */
static void test_unreadable_record(void **state)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  struct hren_span span;
  (void)state;

  assert_int_equal(db_writebatch_put(wb, ren, "#z", 2, "\x7f" "junk", 5), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
  assert_int_equal(span_of("#z", INC, &span), 0);
  /* A rename onto it replaces it. */
  assert_int_equal(hren_note(env, ren, "#y", "#z", INC, MS(1), 0, NULL), 0);
  assert_int_equal(span_of("#z", INC, &span), 1);
}


/* Each entry says when the channel took the name: the time it left the
 * one before, 0 for the name it was made under, and for a name it had
 * twice the later stay.  (Which name the channel had at a given time,
 * for strict presence.) */
static void test_since_is_when_the_name_was_taken(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#b", "#c", INC, MS(2000), 0, NULL), 0);
  assert_int_equal(span_of("#c", INC, &span), 2);
  assert_string_equal(span.seg[0].name, "#b");
  assert_true(span.seg[0].since_ms == MS(1000));
  assert_true(span.seg[0].until_ms == MS(2000));
  assert_string_equal(span.seg[1].name, "#a");
  assert_true(span.seg[1].since_ms == 0);
  /* back to #a and on to #d: #a's entry is its second stay, and its
   * first (up to 1000) is in no entry */
  assert_int_equal(hren_note(env, ren, "#c", "#a", INC, MS(3000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#a", "#d", INC, MS(4000), 0, NULL), 0);
  assert_int_equal(span_of("#d", INC, &span), 3);
  assert_string_equal(span.seg[0].name, "#a");
  assert_true(span.seg[0].since_ms == MS(3000));
  assert_true(span.seg[0].until_ms == MS(4000));
  assert_string_equal(span.seg[1].name, "#c");
  assert_true(span.seg[1].since_ms == MS(2000));
  assert_string_equal(span.seg[2].name, "#b");
  assert_true(span.seg[2].since_ms == MS(1000));
  /* a crossing hands the times over as they are */
  assert_int_equal(hren_note(env, ren, "#d", "#y", INC, MS(5000), 0, NULL), 0);
  assert_int_equal(hren_handover(env, ren, "#d", "#y", "#x", INC, 0, NULL), 1);
  assert_int_equal(span_of("#x", INC, &span), HREN_MAX_SEGS);
  assert_string_equal(span.seg[0].name, "#d");
  assert_true(span.seg[0].since_ms == MS(4000));
  assert_true(span.seg[0].until_ms == MS(5000));
}

/* The cap says how many of the channel's names it dropped. */
static void test_cap_reports_what_it_drops(void **state)
{
  char from[16], to[16];
  int i, dropped;
  (void)state;

  for (i = 0; i < HREN_MAX_SEGS + 3; i++) {
    snprintf(from, sizeof from, "#n%d", i);
    snprintf(to, sizeof to, "#n%d", i + 1);
    dropped = -1;
    assert_int_equal(hren_note(env, ren, from, to, INC, MS(1000 + i), 0, &dropped), 0);
    assert_int_equal(dropped, i < HREN_MAX_SEGS ? 0 : 1);
  }
}

/* A channel renamed into a name does not inherit what that name's record
 * holds for a dead channel created in the same second: the record's
 * entries of the arriving incarnation are that other channel's (the
 * arriving one's are all in the record of the name it leaves). */
static void test_arrival_does_not_inherit_a_same_second_channel(void **state)
{
  struct hren_span span;
  struct walked w;
  (void)state;

  /* the dead channel: #q -> #new, then gone */
  put_row("#q", MS(500), "q1", INC);
  assert_int_equal(hren_note(env, ren, "#q", "#new", INC, MS(1000), 0, NULL), 0);
  /* another dead one, of another second: its entry may stay (no read of
   * the arriving channel returns it) */
  assert_int_equal(hren_note(env, ren, "#r", "#new", INC2, MS(9999000), 0, NULL), 0);
  /* the live channel, created in the dead one's second, arrives */
  put_row("#z", MS(4000), "z1", INC);
  assert_int_equal(hren_note(env, ren, "#z", "#new", INC, MS(5000), 0, NULL), 0);

  assert_int_equal(span_of("#new", INC, &span), 1);
  assert_string_equal(span.seg[0].name, "#z");
  walk_back("#new", INC, 0, 10, &w);
  assert_walk(&w, "z1");
  assert_int_equal(span_of("#new", INC2, &span), 1);
  assert_string_equal(span.seg[0].name, "#r");
}

/* Two relocations of #old cross.  A store that recorded the winner (#x)
 * first has #old and the names before it with #x.  One that recorded the
 * loser (#y) first hands them over: the same record, with the time #old
 * was left, and nothing of it left with #y. */
static void test_crossing_ends_the_same_in_both_orders(void **state)
{
  struct hren_span win, span;
  int dropped = -1;
  (void)state;

  /* winner first */
  assert_int_equal(hren_note(env, ren, "#w-older", "#w-old", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#w-old", "#w-x", INC, MS(2000), 0, NULL), 0);
  assert_int_equal(span_of("#w-x", INC, &win), 2);

  /* loser first: the loser's relocation at 2000, the winner's heard at
   * 2600 */
  assert_int_equal(hren_note(env, ren, "#l-older", "#l-old", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#l-old", "#l-y", INC, MS(2000), 0, NULL), 0);
  /* a dead channel of the same second once left an entry at the winner's
   * name: not inherited */
  assert_int_equal(hren_note(env, ren, "#dead", "#l-x", INC, MS(100), 0, NULL), 0);
  assert_int_equal(hren_handover(env, ren, "#l-old", "#l-y", "#l-x", INC, 0, &dropped), 1);
  assert_int_equal(dropped, 0);

  assert_int_equal(span_of("#l-x", INC, &span), win.count);
  assert_string_equal(span.seg[0].name, "#l-old");
  assert_true(span.seg[0].until_ms == win.seg[0].until_ms);   /* 2000, not 2600 */
  assert_string_equal(span.seg[1].name, "#l-older");
  assert_true(span.seg[1].until_ms == win.seg[1].until_ms);
  assert_int_equal(span_of("#l-y", INC, &span), 0);
  assert_int_equal(span_of("#l-old", INC, &span), 0);
  /* heard again: nothing left to hand over */
  assert_int_equal(hren_handover(env, ren, "#l-old", "#l-y", "#l-x", INC, 0, NULL), 0);
  assert_int_equal(span_of("#l-x", INC, &span), 2);
}

/* The loser's channel was renamed on before the winner was heard: what it
 * gained since stays with it, as on a store that heard the winner first
 * (there the loser never had the rest). */
static void test_crossing_loser_keeps_its_own_later_names(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#older", "#old", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#old", "#y", INC, MS(2000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#y", "#y2", INC, MS(2300), 0, NULL), 0);
  assert_int_equal(hren_handover(env, ren, "#old", "#y2", "#x", INC, 0, NULL), 1);
  assert_int_equal(span_of("#x", INC, &span), 2);
  assert_string_equal(span.seg[0].name, "#old");
  assert_true(span.seg[0].until_ms == MS(2000));
  assert_string_equal(span.seg[1].name, "#older");
  assert_int_equal(span_of("#y2", INC, &span), 1);
  assert_string_equal(span.seg[0].name, "#y");
  /* bad input */
  assert_int_equal(hren_handover(env, ren, "#old", "#y2", "#x", 0, 0, NULL), -1);
  assert_int_equal(hren_handover(env, ren, "#old", "", "#x", INC, 0, NULL), -1);
}

/* Which rows under two names are one channel's: what the trim engine
 * asks before a REDACT row takes an original under another name with it. */
static void test_same_channel(void **state)
{
  (void)state;

  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#a", MS(500), INC), 0);
  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_same_channel(env, ren, "#B", MS(1500), "#A", MS(500), INC), 1);
  assert_int_equal(hren_same_channel(env, ren, "#a", MS(500), "#b", MS(1500), INC), 1);
  /* a row under #a from after the channel left it is the next #a's */
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#a", MS(1200), INC), 0);
  /* another incarnation, another name */
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#a", MS(500), INC2), 0);
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#c", MS(500), INC), 0);
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#a", MS(500), 0), 0);

  /* The channel moved on: the record that joins #a and #b is #c's now. */
  assert_int_equal(hren_note(env, ren, "#b", "#c", INC, MS(2000), 0, NULL), 0);
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#a", MS(500), INC), 1);
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(2500), "#a", MS(500), INC), 0);
  assert_int_equal(hren_same_channel(env, ren, "#c", MS(2500), "#a", MS(500), INC), 1);
  /* And back to #a: the record is #a's own, its rows of any time. */
  assert_int_equal(hren_note(env, ren, "#c", "#a", INC, MS(3000), 0, NULL), 0);
  assert_int_equal(hren_same_channel(env, ren, "#b", MS(1500), "#a", MS(500), INC), 1);
  assert_int_equal(hren_same_channel(env, ren, "#a", MS(3500), "#b", MS(1500), INC), 1);
  assert_int_equal(hren_same_channel(env, ren, "#a", MS(3500), "#b", MS(2500), INC), 0);
}

/* The original a REDACT row under the new name redacts, stored under the
 * old one. */
static void test_find_parent_under_an_earlier_name(void **state)
{
  char name[CHANNELLEN + 1], ts[HISTORY_TIMESTAMP_LEN], want[HISTORY_TIMESTAMP_LEN];
  (void)state;

  put_row("#old", MS(500), "p1", INC);
  put_mid("#old", MS(500), "p1");
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(1000), 0, NULL), 0);
  /* the same msgid under names that are not this channel's */
  put_row("#evil", MS(400), "p1", INC);
  put_mid("#evil", MS(400), "p1");

  fmt_ms(want, sizeof want, MS(500));
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#New", MS(1500),
                                    INC, "p1", name, ts, sizeof ts), 1);
  assert_string_equal(name, "#old");
  assert_string_equal(ts, want);

  /* not for a REDACT row of another incarnation, or of a stranger */
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#new", MS(1500),
                                    INC2, "p1", name, ts, sizeof ts), 0);
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#other", MS(1500),
                                    INC, "p1", name, ts, sizeof ts), 0);
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#new", MS(1500),
                                    INC, "nope", name, ts, sizeof ts), 0);
  /* a row of the old name's NEXT channel (another incarnation) is not it */
  put_row("#old", MS(1200), "p2", INC2);
  put_mid("#old", MS(1200), "p2");
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#new", MS(1500),
                                    INC, "p2", name, ts, sizeof ts), 0);
  /* an index row whose message is gone */
  put_mid("#old", MS(600), "p3");
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#new", MS(1500),
                                    INC, "p3", name, ts, sizeof ts), 0);
}

static void test_drop(void **state)
{
  struct hren_span span;
  (void)state;

  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_drop(env, ren, "#B"), 0);
  assert_int_equal(span_of("#b", 0, &span), 0);
  assert_int_equal(hren_drop(env, ren, "#b"), 0);
  assert_int_equal(hren_drop(env, ren, ""), -1);
}

#ifndef HREN_REAL
/* A store that fails: every answer shows less, never another channel's
 * rows.  (Injected faults: the in-memory store only.) */
static void test_read_errors_fail_safe(void **state)
{
  struct hren_span span;
  char name[CHANNELLEN + 1], ts[HISTORY_TIMESTAMP_LEN];
  (void)state;

  /* a dead same-second channel's entry at #new, and the live channel's
   * earlier name */
  assert_int_equal(hren_note(env, ren, "#q", "#new", INC, MS(1000), 0, NULL), 0);
  assert_int_equal(hren_note(env, ren, "#older", "#old", INC, MS(2000), 0, NULL), 0);

  /* a lookup that cannot read is an error, not "never renamed" */
  fake_db_fail_get_at(env, 1);
  assert_int_equal(span_of("#new", INC, &span), -1);
  assert_int_equal(span.count, 0);
  fake_db_fail_get_at(env, 1);
  assert_int_equal(hren_same_channel(env, ren, "#new", MS(1), "#q", MS(1), INC), -1);
  put_row("#q", MS(500), "p1", INC);
  put_mid("#q", MS(500), "p1");
  fake_db_fail_get_at(env, 1);
  assert_int_equal(hren_find_parent(env, ren, mids, msgs, row_inc, "#new", MS(1500),
                                    INC, "p1", name, ts, sizeof ts), -1);

  /* the write failed: nothing changed */
  fake_db_fail_next_commit(env);
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(3000), 0, NULL), -1);
  assert_int_equal(span_of("#old", INC, &span), 1);

  /* the new name's record cannot be read: replaced, the dead channel's
   * entry with it */
  fake_db_fail_get_at(env, 1);
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(3000), 0, NULL), 0);
  assert_int_equal(span_of("#new", INC, &span), 2);
  assert_string_equal(span.seg[0].name, "#old");
  assert_string_equal(span.seg[1].name, "#older");

  /* the old name's record cannot be read: the channel keeps the name it
   * left, and the old name's record goes */
  assert_int_equal(hren_note(env, ren, "#new", "#mid", INC, MS(4000), 0, NULL), 0);
  fake_db_fail_get_at(env, 2);
  assert_int_equal(hren_note(env, ren, "#mid", "#last", INC, MS(5000), 0, NULL), 1);
  assert_int_equal(span_of("#last", INC, &span), 1);
  assert_string_equal(span.seg[0].name, "#mid");
  /* (when it took that name is not known: no time maps to it) */
  assert_true(span.seg[0].since_ms == span.seg[0].until_ms);
  assert_int_equal(span_of("#mid", 0, &span), 0);

  /* a handover that cannot read changes nothing */
  fake_db_fail_get_at(env, 1);
  assert_int_equal(hren_handover(env, ren, "#mid", "#last", "#won", INC, 0, NULL), -1);
  assert_int_equal(span_of("#last", INC, &span), 1);
}
#endif

/* ------------------------------------------------------------------ */
/* The walk                                                            */
/* ------------------------------------------------------------------ */

/* No rename: the walk is the target's own rows, and only those. */
static void test_walk_without_rename(void **state)
{
  struct walked w;
  (void)state;

  put_row("#a", MS(100), "a1", INC);
  put_row("#a", MS(200), "a2", INC);
  put_row("#aa", MS(150), "x1", INC);
  put_row("#", MS(150), "x2", INC);
  walk_back("#a", INC, 0, 10, &w);
  assert_walk(&w, "a2 a1");
  walk_fwd("#a", INC, MS(0), 10, &w);
  assert_walk(&w, "a1 a2");
}

/* The issue: after #old -> #new, #new's history starts with #old's rows,
 * presented under the current name, in one time order. */
static void test_walk_follows_rename(void **state)
{
  struct walked w;
  int i;
  (void)state;

  put_row("#old", MS(100), "o1", INC);
  put_row("#old", MS(200), "o2", INC);
  put_row("#old", MS(300), "o3", INC);
  assert_int_equal(hren_note(env, ren, "#old", "#New", INC, MS(400), 0, NULL), 0);
  put_row("#New", MS(500), "n1", INC);
  put_row("#New", MS(600), "n2", INC);

  walk_back("#New", INC, 0, 10, &w);
  assert_walk(&w, "n2 n1 o3 o2 o1");
  for (i = 0; i < w.n; i++)
    assert_string_equal(w.target[i], "#new");
  walk_fwd("#New", INC, MS(0), 10, &w);
  assert_walk(&w, "o1 o2 o3 n1 n2");
  for (i = 0; i < w.n; i++)
    assert_string_equal(w.target[i], "#new");
  /* The old name is not the new one's: nothing follows back. */
  walk_back("#old", INC, 0, 10, &w);
  assert_walk(&w, "o3 o2 o1");
}

/* Limits and cursors across the boundary. */
static void test_walk_limit_across_boundary(void **state)
{
  struct walked w;
  (void)state;

  put_row("#old", MS(100), "o1", INC);
  put_row("#old", MS(200), "o2", INC);
  put_row("#old", MS(300), "o3", INC);
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(400), 0, NULL), 0);
  put_row("#new", MS(500), "n1", INC);
  put_row("#new", MS(600), "n2", INC);

  /* LATEST * 3: the two new rows and the newest old one. */
  walk_back("#new", INC, 0, 3, &w);
  assert_walk(&w, "n2 n1 o3");
  /* BEFORE the first new row: old rows only, newest first. */
  walk_back("#new", INC, MS(500), 2, &w);
  assert_walk(&w, "o3 o2");
  /* BEFORE a time inside the old rows. */
  walk_back("#new", INC, MS(250), 10, &w);
  assert_walk(&w, "o2 o1");
  /* AFTER a time inside the old rows, across the boundary. */
  walk_fwd("#new", INC, MS(150), 3, &w);
  assert_walk(&w, "o2 o3 n1");
  /* AFTER the last old row. */
  walk_fwd("#new", INC, MS(301), 10, &w);
  assert_walk(&w, "n1 n2");
  /* Past everything. */
  walk_fwd("#new", INC, MS(700), 10, &w);
  assert_walk(&w, "");
  walk_back("#new", INC, MS(50), 10, &w);
  assert_walk(&w, "");
}

/* Rows of two names that interleave in time (a row relayed late, clocks
 * apart) still come in one time order, and a step may turn around. */
static void test_walk_interleaved_and_turning(void **state)
{
  struct hren_iter *it;
  struct walked w;
  char key[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8], ts[HISTORY_TIMESTAMP_LEN];
  int kl;
  (void)state;

  put_row("#old", MS(100), "o1", INC);
  put_row("#old", MS(300), "o3", INC);
  put_row("#old", MS(500), "o5", INC);
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(600), 0, NULL), 0);
  put_row("#new", MS(200), "n2", INC);
  put_row("#new", MS(400), "n4", INC);
  put_row("#new", MS(700), "n7", INC);

  walk_back("#new", INC, 0, 10, &w);
  assert_walk(&w, "n7 o5 n4 o3 n2 o1");
  walk_fwd("#new", INC, MS(0), 10, &w);
  assert_walk(&w, "o1 n2 o3 n4 o5 n7");

  /* Forwards to o3, on to n4, back to o3, n2, then forwards again. */
  it = open_walk("#new", INC);
  fmt_ms(ts, sizeof ts, MS(250));
  kl = htc_msg_key(key, sizeof key, "#new", ts, NULL);
  memset(&w, 0, sizeof w);
  assert_int_equal(hren_iter_seek(it, key, (size_t)kl), DB_OK);
  collect(it, &w);
  assert_int_equal(hren_iter_next(it), DB_OK);
  collect(it, &w);
  assert_int_equal(hren_iter_prev(it), DB_OK);
  collect(it, &w);
  assert_int_equal(hren_iter_prev(it), DB_OK);
  collect(it, &w);
  assert_int_equal(hren_iter_next(it), DB_OK);
  collect(it, &w);
  assert_int_equal(hren_iter_prev(it), DB_OK);
  assert_int_equal(hren_iter_prev(it), DB_OK);
  collect(it, &w);
  assert_int_equal(hren_iter_prev(it), DB_NOTFOUND);
  assert_false(hren_iter_valid(it));
  assert_walk(&w, "o3 n4 o3 n2 o3 o1");
  /* First and last. */
  memset(&w, 0, sizeof w);
  assert_int_equal(hren_iter_seek_first(it), DB_OK);
  collect(it, &w);
  assert_non_null(hren_iter_seg(it));
  assert_int_equal(hren_iter_seek_last(it), DB_OK);
  collect(it, &w);
  assert_null(hren_iter_seg(it));
  assert_int_equal(hren_iter_next(it), DB_NOTFOUND);
  assert_walk(&w, "o1 n7");
  hren_iter_close(it);
}

/* #a -> #b -> #c: all of it is #c's history. */
static void test_walk_chain(void **state)
{
  struct walked w;
  int i;
  (void)state;

  put_row("#a", MS(100), "a1", INC);
  put_row("#a", MS(200), "a2", INC);
  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(300), 0, NULL), 0);
  put_row("#b", MS(400), "b1", INC);
  walk_back("#b", INC, 0, 10, &w);
  assert_walk(&w, "b1 a2 a1");
  assert_int_equal(hren_note(env, ren, "#b", "#c", INC, MS(500), 0, NULL), 0);
  put_row("#c", MS(600), "c1", INC);
  put_row("#c", MS(700), "c2", INC);

  walk_back("#c", INC, 0, 10, &w);
  assert_walk(&w, "c2 c1 b1 a2 a1");
  for (i = 0; i < w.n; i++)
    assert_string_equal(w.target[i], "#c");
  walk_back("#c", INC, 0, 4, &w);
  assert_walk(&w, "c2 c1 b1 a2");
  walk_fwd("#c", INC, MS(150), 3, &w);
  assert_walk(&w, "a2 b1 c1");
}

/* #a -> #b -> #a: #a has its own rows from both of its times and #b's
 * in between, each once. */
static void test_walk_there_and_back(void **state)
{
  struct walked w;
  (void)state;

  put_row("#a", MS(100), "a1", INC);
  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(200), 0, NULL), 0);
  put_row("#b", MS(300), "b1", INC);
  assert_int_equal(hren_note(env, ren, "#b", "#a", INC, MS(400), 0, NULL), 0);
  put_row("#a", MS(500), "a2", INC);
  walk_back("#a", INC, 0, 10, &w);
  assert_walk(&w, "a2 b1 a1");
  walk_fwd("#a", INC, MS(0), 10, &w);
  assert_walk(&w, "a1 b1 a2");
}

/* A stranger makes a channel under the old name: another creation
 * timestamp.  Its rows are not the renamed channel's history, whenever
 * they were stored; nor are rows of an incarnation the name had before.
 * And the renamed channel's rows are not the stranger's: its name has no
 * record, and history.c's own incarnation test hides them. */
static void test_walk_excludes_recreated_old_name(void **state)
{
  struct hren_span span;
  struct walked w;
  (void)state;

  put_row("#old", MS(100), "o1", INC);
  put_row("#old", MS(200), "o2", INC);
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(400), 0, NULL), 0);
  put_row("#new", MS(500), "n1", INC);
  /* The stranger's channel: created later, rows after the rename. */
  put_row("#old", (INC2 * 1000ULL) + 100, "s1", INC2);
  put_row("#old", (INC2 * 1000ULL) + 200, "s2", INC2);
  put_row("#new", (INC2 * 1000ULL) + 300, "n2", INC);
  /* A row of another incarnation inside the segment's own time range (a
   * split's losing side), and one that carries no incarnation. */
  put_row("#old", MS(150), "x1", INC - 500);
  put_row("#old", MS(160), "x2", 0);

  walk_back("#new", INC, 0, 10, &w);
  assert_walk(&w, "n2 n1 o2 o1");
  walk_fwd("#new", INC, MS(0), 10, &w);
  assert_walk(&w, "o1 o2 n1 n2");
  /* The stranger's #old has no earlier names. */
  assert_int_equal(span_of("#old", INC2, &span), 0);
}

/* A relocation leaves the old channel alive as a tombstone with the same
 * creation timestamp: what it stores after the move is its own. */
static void test_walk_stops_at_rename_time(void **state)
{
  struct walked w;
  (void)state;

  put_row("#old", MS(100), "o1", INC);
  put_row("#old", MS(400), "o2", INC);   /* stamped at the rename's ms */
  assert_int_equal(hren_note(env, ren, "#old", "#new", INC, MS(400), 0, NULL), 0);
  put_row("#old", MS(401), "t1", INC);
  put_row("#old", MS(900), "t2", INC);
  put_row("#new", MS(500), "n1", INC);

  walk_back("#new", INC, 0, 10, &w);
  assert_walk(&w, "n1 o2 o1");
  walk_fwd("#new", INC, MS(0), 10, &w);
  assert_walk(&w, "o1 o2 n1");
  /* A cursor past the segment's end, inside the tombstone's rows. */
  walk_back("#new", INC, MS(450), 10, &w);
  assert_walk(&w, "o2 o1");
}

/* The record is a stored row: it is there after the env is closed and
 * opened again (the RocksDB build; the in-memory store has no restart). */
static void test_survives_restart(void **state)
{
  struct hren_span span;
  struct walked w;
  (void)state;

  put_row("#a", MS(100), "a1", INC);
  assert_int_equal(hren_note(env, ren, "#a", "#b", INC, MS(200), 0, NULL), 0);
  put_row("#b", MS(300), "b1", INC);
  assert_int_equal(hren_note(env, ren, "#b", "#c", INC, MS(400), 0, NULL), 0);
  put_row("#c", MS(500), "c1", INC);

#ifdef HREN_REAL
  db_env_close(env);
  assert_int_equal(db_env_open(g_tmpdir, NULL, 8, &env), DB_OK);
  open_cfs();
#endif

  assert_int_equal(span_of("#c", INC, &span), 2);
  assert_string_equal(span.seg[0].name, "#b");
  assert_string_equal(span.seg[1].name, "#a");
  walk_back("#c", INC, 0, 10, &w);
  assert_walk(&w, "c1 b1 a1");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(test_note_and_lookup, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_case_only_rename_is_nothing, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_chain_is_flattened, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_loop_stays_bounded, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_cap_keeps_the_latest, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_incarnations_apart, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_floor_drops_aged_entries, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_forget, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_unreadable_record, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_since_is_when_the_name_was_taken, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_cap_reports_what_it_drops, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_arrival_does_not_inherit_a_same_second_channel, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_crossing_ends_the_same_in_both_orders, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_crossing_loser_keeps_its_own_later_names, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_same_channel, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_find_parent_under_an_earlier_name, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_drop, test_setup, test_teardown),
#ifndef HREN_REAL
    cmocka_unit_test_setup_teardown(test_read_errors_fail_safe, test_setup, test_teardown),
#endif
    cmocka_unit_test_setup_teardown(test_walk_without_rename, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_follows_rename, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_limit_across_boundary, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_interleaved_and_turning, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_chain, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_there_and_back, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_excludes_recreated_old_name, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_walk_stops_at_rename_time, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_survives_restart, test_setup, test_teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
