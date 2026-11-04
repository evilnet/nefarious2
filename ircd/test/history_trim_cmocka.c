/*
 * history_trim_cmocka.c - the chathistory trim engine (ircd/history_trim.c)
 * against the in-memory storage fake (ircd/test/fake_db.c): index staging,
 * the sliced boot accounting scan, budgeted slices, the one delete function
 * every path goes through, and the touched-target cleanup.
 *
 * Links ../history_trim.o, the codec (../history_trim_codec.o), the redact
 * index key builder (../redact_index.o), db_casefold/ircd_string for name
 * folding, ../ircd_alloc.o and fake_db.o -- no RocksDB, no running ircd.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cmocka.h>

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "history_trim.h"
#include "history_trim_codec.h"
#include "redact_index.h"
#include "fake_db.h"

/* ------------------------------------------------------------------ */
/* Fixture: one fake env, the ten column families, a fake clock        */
/* ------------------------------------------------------------------ */

static struct db_env *env;
static struct htrim_store st;

static uint64_t fake_us;
static uint64_t step_us;

/** Monotonic fake clock: every read advances it by step_us. */
static uint64_t fake_clock(void)
{
  fake_us += step_us;
  return fake_us;
}

#define MAX_EMPTIED 16
static int  emptied_calls;
static int  emptied_count;
static char emptied_names[MAX_EMPTIED][HTC_TARGET_MAX];

static void on_emptied(const char **targets, int count)
{
  int i;
  emptied_calls++;
  emptied_count = count;
  for (i = 0; i < count && i < MAX_EMPTIED; i++)
    snprintf(emptied_names[i], sizeof emptied_names[i], "%s", targets[i]);
}

/** The test value format: account|flags|reply|redact|payload. */
static int parse_cb(const void *val, size_t vlen, struct htrim_row_info *out)
{
  char buf[256];
  char *f[5];
  char *p;
  int n = 0;

  if (!val || vlen >= sizeof buf || !out)
    return -1;
  memcpy(buf, val, vlen);
  buf[vlen] = '\0';
  p = buf;
  while (n < 5) {
    f[n++] = p;
    p = strchr(p, '|');
    if (!p)
      break;
    *p++ = '\0';
  }
  if (n < 5)
    return -1;
  memset(out, 0, sizeof *out);
  snprintf(out->account, sizeof out->account, "%s", f[0]);
  out->flags = (unsigned char)atoi(f[1]);
  snprintf(out->reply_parent, sizeof out->reply_parent, "%s", f[2]);
  snprintf(out->redact_parent, sizeof out->redact_parent, "%s", f[3]);
  return 0;
}

static void open_cf(const char *name, struct db_cf **out)
{
  assert_int_equal(DB_OK, db_cf_open(env, name, NULL, out));
  assert_non_null(*out);
}

static int setup(void **state)
{
  (void)state;
  env = fake_db_new();
  assert_non_null(env);
  memset(&st, 0, sizeof st);
  st.env = env;
  open_cf("messages", &st.messages);
  open_cf("msgid_index", &st.msgid);
  open_cf("targets", &st.targets);
  open_cf("reply_index", &st.reply);
  open_cf("redact_index", &st.redact);
  open_cf("ml_content", &st.ml_content);
  open_cf("ml_paste_secrets", &st.ml_paste);
  open_cf("by_time", &st.by_time);
  open_cf("by_owner", &st.by_owner);
  open_cf("default", &st.meta);
  fake_us = 0;
  step_us = 0;
  emptied_calls = 0;
  emptied_count = 0;
  memset(emptied_names, 0, sizeof emptied_names);
  assert_int_equal(0, htrim_init(&st, parse_cb, fake_clock, on_emptied));
  return 0;
}

static void stderr_restore(void);

static int teardown(void **state)
{
  (void)state;
  stderr_restore();                    /* a failed capture test */
  htrim_shutdown();
  fake_db_free(env);
  env = NULL;
  return 0;
}

/** A restart: the in-memory state goes, the store stays. */
static void reboot(void)
{
  htrim_shutdown();
  assert_int_equal(0, htrim_init(&st, parse_cb, fake_clock, on_emptied));
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static struct htrim_params params(unsigned int slice_ms)
{
  struct htrim_params p;
  memset(&p, 0, sizeof p);
  p.slice_ms = slice_ms;
  return p;
}

static int key_exists(struct db_cf *cf, const void *k, size_t kl)
{
  return db_exists(env, cf, k, kl, NULL) == DB_OK;
}

static int bt_of(char *buf, size_t size, const char *target, const char *ts,
                 const char *msgid)
{
  int n = htc_bt_key(buf, size, htc_parse_ms(ts), target, msgid);
  assert_true(n > 0);
  return n;
}

/** The test value (parse_cb's format), padded with 'x' to 80 bytes. */
static void test_value(char val[81], const char *account, unsigned char flags,
                       const char *reply_parent, const char *redact_parent)
{
  int n = snprintf(val, 81, "%s|%u|%s|%s|", account, (unsigned)flags,
                   reply_parent, redact_parent);
  assert_true(n > 0 && n < 80);
  memset(val + n, 'x', 80 - (size_t)n);
  val[80] = '\0';
}

/** Stage what the store path writes for one row except its by_time and
 * by_owner rows: the messages row (@a val, @a vlen bytes), both msgid-index
 * forms, its reply_index entries, its redact_index row (HTC_F_REDACT), its
 * multiline content (@a ml_len bytes) and a paste row (HTC_F_ML).
 * @return the messages key length. */
static int stage_message_rows(struct db_writebatch *wb, const char *target,
                              const char *ts, const char *msgid,
                              const char *val, size_t vlen, unsigned char flags,
                              const char *reply_parent, const char *redact_parent,
                              size_t ml_len)
{
  char mk[HTC_MSG_KEY_MAX], ik[HTC_MSG_KEY_MAX], rk[HTC_MSG_KEY_MAX];
  int mkl, ikl, n;

  mkl = htc_msg_key(mk, sizeof mk, target, ts, msgid);
  assert_true(mkl > 0);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.messages, mk, (size_t)mkl, val, vlen));

  ikl = htc_msgid_key(ik, sizeof ik, msgid, target);
  assert_true(ikl > 0);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.msgid, ik, (size_t)ikl, ts, strlen(ts)));
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.msgid, msgid, strlen(msgid), ts, strlen(ts)));

  if (reply_parent[0]) {
    n = htc_reply_child_key(rk, sizeof rk, target, reply_parent, ts, msgid);
    assert_true(n > 0);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.reply, rk, (size_t)n, "", 0));
  }
  if (redact_parent[0]) {
    n = htc_reply_child_key(rk, sizeof rk, target, redact_parent, ts, msgid);
    assert_true(n > 0);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.reply, rk, (size_t)n, "", 0));
  }
  if (flags & HTC_F_REDACT) {
    unsigned char xk[RDX_KEY_MAX];
    n = rdx_key_build(xk, sizeof xk, htc_parse_ms(ts), msgid);
    assert_true(n > 0);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.redact, xk, (size_t)n, "r", 1));
  }
  if (flags & HTC_F_ML) {
    char content[512];
    char paste[HTC_MSGID_MAX + 16];
    assert_true(ml_len < sizeof content);
    memset(content, 'm', ml_len);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.ml_content, msgid, strlen(msgid),
                                              content, ml_len));
    snprintf(paste, sizeof paste, "%s-sekret", msgid);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.ml_paste, paste, strlen(paste),
                                              msgid, strlen(msgid)));
  }
  return mkl;
}

/** Write what the store path writes for one row, then index it through
 * htrim_stage_index in the same batch, commit, and htrim_note_stored. */
static void seed_row(const char *target, const char *ts, const char *msgid,
                     const char *owner, unsigned char flags,
                     const char *reply_parent, const char *redact_parent,
                     size_t ml_len, struct htc_rec *rec_out)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  char val[81];
  struct htc_rec rec;
  size_t bolen = 0;
  int mkl, btl;

  assert_non_null(wb);
  test_value(val, owner, flags, reply_parent, redact_parent);
  mkl = stage_message_rows(wb, target, ts, msgid, val, 80, flags,
                           reply_parent, redact_parent, ml_len);

  btl = bt_of(bt, sizeof bt, target, ts, msgid);
  memset(&rec, 0, sizeof rec);
  rec.flags = flags;
  snprintf(rec.ts, sizeof rec.ts, "%s", ts);
  snprintf(rec.owner, sizeof rec.owner, "%s", owner);
  snprintf(rec.reply_parent, sizeof rec.reply_parent, "%s", reply_parent);
  snprintf(rec.redact_parent, sizeof rec.redact_parent, "%s", redact_parent);
  rec.bytes = htc_row_bytes((size_t)mkl, 80, (flags & HTC_F_ML) ? ml_len : 0,
                            (size_t)btl, strlen(owner));
  assert_int_equal(0, htrim_stage_index(wb, htc_parse_ms(ts), target, msgid, &rec,
                                        bo, sizeof bo, &bolen));
  assert_true(bolen > 0);
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  htrim_note_stored(owner, bo, bolen, rec.bytes);
  if (rec_out)
    *rec_out = rec;
}

/** Plain message row: no flags, no parents, no multiline content. */
static void seed_plain(const char *target, const char *ts, const char *msgid,
                       const char *owner, struct htc_rec *rec_out)
{
  seed_row(target, ts, msgid, owner, 0, "", "", 0, rec_out);
}

/** A row stored before by_time existed (or by an older binary): what the
 * store path writes, value @a val (@a vlen bytes), without its by_time and
 * by_owner rows.  @return the size the backfill must charge it, owned by
 * @a owner_len bytes of owner key. */
static uint32_t seed_legacy_raw(const char *target, const char *ts, const char *msgid,
                                const char *val, size_t vlen, unsigned char flags,
                                const char *reply_parent, const char *redact_parent,
                                size_t ml_len, size_t owner_len)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  char bt[HTC_BT_KEY_MAX];
  int mkl, btl;

  assert_non_null(wb);
  mkl = stage_message_rows(wb, target, ts, msgid, val, vlen, flags,
                           reply_parent, redact_parent, ml_len);
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  btl = bt_of(bt, sizeof bt, target, ts, msgid);
  return htc_row_bytes((size_t)mkl, vlen, (flags & HTC_F_ML) ? ml_len : 0,
                       (size_t)btl, owner_len);
}

/** seed_row's rows minus by_time/by_owner, for @a account ("" = none):
 * the backfill owns it as "a:" + fold(account), or "-". */
static uint32_t seed_legacy_row(const char *target, const char *ts, const char *msgid,
                                const char *account, unsigned char flags,
                                const char *reply_parent, const char *redact_parent,
                                size_t ml_len)
{
  char val[81];
  test_value(val, account, flags, reply_parent, redact_parent);
  return seed_legacy_raw(target, ts, msgid, val, 80, flags, reply_parent,
                         redact_parent, ml_len,
                         account[0] ? 2 + strlen(account) : 1);
}

static void put_meta(const char *key, const char *val)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.meta, key, strlen(key), val, strlen(val)));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
}

/** @return 1 when meta row @a key holds exactly @a val, 0 when it holds
 * something else, -1 when there is no such row. */
static int meta_is(const char *key, const char *val)
{
  struct db_val v = { NULL, 0 };
  int same;
  if (db_get(env, st.meta, key, strlen(key), NULL, &v) != DB_OK)
    return -1;
  same = v.len == strlen(val) && memcmp(v.base, val, v.len) == 0;
  db_val_free(&v);
  return same;
}

/** The marker a finished backfill leaves, for the tests of the other
 * phases (a pending backfill would take slices from them).  Call before
 * the engine starts (then reboot()). */
static void seed_backfill_done(void)
{
  put_meta(HTRIM_META_BACKFILL_DONE, "done");
}

static void seed_targets(const char *target, const char *stamp)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  char k[HTC_MSG_KEY_MAX];
  int n = htc_msg_key(k, sizeof k, target, NULL, NULL);   /* fold(t) \0 */
  assert_true(n > 1);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.targets, k, (size_t)n - 1,
                                            stamp, strlen(stamp)));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
}

static int targets_has(const char *target)
{
  char k[HTC_MSG_KEY_MAX];
  int n = htc_msg_key(k, sizeof k, target, NULL, NULL);
  assert_true(n > 1);
  return key_exists(st.targets, k, (size_t)n - 1);
}

/** Read a row's by_time record back from the CF. */
static void get_rec(const char *target, const char *ts, const char *msgid,
                    struct htc_rec *out)
{
  char bt[HTC_BT_KEY_MAX];
  struct db_val v = { NULL, 0 };
  int btl = bt_of(bt, sizeof bt, target, ts, msgid);
  assert_int_equal(DB_OK, db_get(env, st.by_time, bt, (size_t)btl, NULL, &v));
  assert_int_equal(0, htc_rec_parse(v.base, v.len, out));
  db_val_free(&v);
}

/** Stage one row's delete on @a s (rec read back from by_time). */
static void stage_del(struct htrim_slice *s, enum htrim_path path,
                      const char *target, const char *ts, const char *msgid,
                      int counted)
{
  char bt[HTC_BT_KEY_MAX];
  struct htc_rec rec;
  int btl = bt_of(bt, sizeof bt, target, ts, msgid);
  get_rec(target, ts, msgid, &rec);
  assert_int_equal(0, htrim_delete_row(s, path, bt, (size_t)btl, &rec, counted));
}

/** Delete one row in its own unbudgeted slice; returns the commit result. */
static int del_row(enum htrim_path path, const char *target, const char *ts,
                   const char *msgid, int counted)
{
  struct htrim_slice *s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, path, target, ts, msgid, counted);
  return htrim_slice_commit(s);
}

/** Finish the boot accounting scan (so stores/deletes apply directly). */
static void load_acct(void)
{
  struct htrim_params p = params(0);
  int i;
  for (i = 0; i < 1000 && !htrim_acct_loaded(); i++)
    assert_true(htrim_run_slice(&p) >= 0);
  assert_int_equal(1, htrim_acct_loaded());
}

/** The backfill tests' clock and retention: now 1700000000000 ms, 7 days. */
#define BF_NOW_S 1700000000ULL
static struct htrim_params bf_params(unsigned int slice_ms)
{
  struct htrim_params p = params(slice_ms);
  p.now_ms = BF_NOW_S * 1000ULL;
  p.retention_days = 7;
  return p;
}

/** A stored timestamp @a days days (plus @a secs seconds) before now. */
static const char *ts_ago(char *buf, size_t size, int days, int secs)
{
  snprintf(buf, size, "%llu.000",
           (unsigned long long)(BF_NOW_S - (uint64_t)days * 86400u - (uint64_t)secs));
  return buf;
}

/** Accounting loaded, the backfill still to run over the rows seeded
 * next.  load_acct() on the empty store also finishes the (empty)
 * backfill, so it is reopened the way a downgrade window reopens it: a
 * row newer than the (never stamped) alive time. */
static void load_acct_backfill_pending(void)
{
  load_acct();
  assert_int_equal(1, htrim_backfill_done());
  htrim_check_index_gap(1, 0);
  assert_int_equal(0, htrim_backfill_done());
}

static int run_until_idle(const struct htrim_params *p)
{
  int i, rc = 1;
  for (i = 0; i < 1000 && rc == 1; i++)
    rc = htrim_run_slice(p);
  assert_int_equal(0, rc);
  return i;
}

/** Every owner's total (and the global total, and the owner count) equals
 * the sum of its by_owner values read straight from the CF. */
static void assert_acct_matches_cf(void)
{
  struct db_iter *it = db_iter_open(env, st.by_owner, NULL);
  char cur[HTC_OWNER_MAX] = "";
  uint64_t cur_sum = 0, all = 0;
  size_t owners = 0;
  int rc;

  assert_non_null(it);
  for (rc = db_iter_seek_first(it); rc == DB_OK; rc = db_iter_next(it)) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    char owner[HTC_OWNER_MAX];
    uint32_t b;
    assert_int_equal(0, htc_bo_split(k, kl, owner, sizeof owner, NULL, NULL));
    assert_int_equal(0, htc_size_parse(v, vl, &b));
    if (strcmp(owner, cur) != 0) {
      if (cur[0])
        assert_int_equal(cur_sum, htc_acct_owner(htrim_acct(), cur));
      snprintf(cur, sizeof cur, "%s", owner);
      cur_sum = 0;
      owners++;
    }
    cur_sum += b;
    all += b;
  }
  if (cur[0])
    assert_int_equal(cur_sum, htc_acct_owner(htrim_acct(), cur));
  db_iter_close(it);
  assert_int_equal(all, htc_acct_total(htrim_acct()));
  assert_int_equal(owners, htc_acct_count(htrim_acct()));
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_stage_index_writes_both(void **state)
{
  struct htc_rec rec, got;
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  struct db_val v = { NULL, 0 };
  uint32_t b = 0;
  int btl, bol;
  (void)state;

  seed_row("#t", "1000.000", "M1", "a:bob", 0, "", "", 0, &rec);

  btl = htc_bt_key(bt, sizeof bt, 1000000, "#t", "M1");
  assert_true(btl > 0);
  assert_int_equal(DB_OK, db_get(env, st.by_time, bt, (size_t)btl, NULL, &v));
  assert_int_equal(0, htc_rec_parse(v.base, v.len, &got));
  db_val_free(&v);
  assert_string_equal("a:bob", got.owner);
  assert_string_equal("1000.000", got.ts);
  assert_int_equal(rec.bytes, got.bytes);

  bol = htc_bo_key(bo, sizeof bo, "a:bob", bt, (size_t)btl);
  assert_true(bol > 0);
  assert_int_equal(DB_OK, db_get(env, st.by_owner, bo, (size_t)bol, NULL, &v));
  assert_int_equal(0, htc_size_parse(v.base, v.len, &b));
  db_val_free(&v);
  assert_int_equal(rec.bytes, b);
  assert_int_equal(1, fake_db_rows(st.by_time));
  assert_int_equal(1, fake_db_rows(st.by_owner));
}

static void test_acct_scan_loads_totals(void **state)
{
  struct htc_rec r[5];
  struct htrim_params p = params(0);
  (void)state;

  seed_plain("#t", "100.000", "B1", "a:bob", &r[0]);
  seed_plain("#t", "101.000", "B2", "a:bob", &r[1]);
  seed_plain("#u", "102.000", "B3", "a:bob", &r[2]);
  seed_plain("#t", "103.000", "N1", "-", &r[3]);
  seed_plain("#u", "104.000", "N2", "-", &r[4]);
  reboot();                                    /* the rows were there at boot */
  assert_int_equal(0, htrim_acct_loaded());

  run_until_idle(&p);
  assert_int_equal(1, htrim_acct_loaded());
  assert_int_equal((uint64_t)r[0].bytes + r[1].bytes + r[2].bytes,
                   htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal((uint64_t)r[3].bytes + r[4].bytes,
                   htc_acct_owner(htrim_acct(), "-"));
  assert_int_equal((uint64_t)r[0].bytes + r[1].bytes + r[2].bytes + r[3].bytes + r[4].bytes,
                   htc_acct_total(htrim_acct()));
}

/* Review Focus 2: the boot scan racing stores and deletes.  The scan is
 * left mid-way (20 of ~100 by_owner entries read) while rows are stored
 * and deleted on both sides of its cursor.  Applying a delta for a key the
 * scan has not reached double-counts a store (a:zzz, and a:b50's row stored
 * before the scan began); applying one for a deleted key it has not reached
 * subtracts bytes it never added -- visible on a:b19, the owner the cursor
 * sits inside (its second boot row S2 lies ahead of the cursor); dropping a
 * delta behind the cursor loses it for good ('-', a:b05, and the cursor
 * key itself: the rule is bo_key <= cursor). */
static void test_acct_scan_concurrent_store_and_delete(void **state)
{
  struct htrim_params p = params(20);
  struct htc_rec dash[5], b05, strad1;
  char ts[32], mid[32], owner[16], strad[HTC_OWNER_MAX];
  uint64_t first20 = 0, dash_sum = 0;
  struct db_iter *it;
  struct htrim_slice *s;
  int i, rc;
  (void)state;

  for (i = 0; i < 100; i++) {
    snprintf(ts, sizeof ts, "%d.000", 1000 + i);
    snprintf(mid, sizeof mid, "M%02d", i);
    snprintf(owner, sizeof owner, "a:b%02d", i);
    seed_plain("#t", ts, mid, owner, i == 5 ? &b05 : i == 19 ? &strad1 : NULL);
  }
  /* a:b19's second boot row: sorts right after M19, the scan's 20th key. */
  seed_plain("#t", "3000.000", "S2", "a:b19", NULL);
  seed_backfill_done();              /* every slice below is a scan slice */
  reboot();

  /* A store before the scan has started: the scan will read it. */
  seed_plain("#u", "1500.000", "PRE", "a:b50", NULL);

  step_us = 1000;                    /* 1 ms per clock read; 20 ms slices */
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(0, htrim_acct_loaded());
  assert_int_equal(HTRIM_PH_ACCTSCAN, htrim_stats()->last_phase);

  /* Exactly 20 entries were read: the first 20 by_owner keys. */
  it = db_iter_open(env, st.by_owner, NULL);
  assert_non_null(it);
  for (i = 0, rc = db_iter_seek_first(it); i < 20 && rc == DB_OK; i++, rc = db_iter_next(it)) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    uint32_t b;
    assert_int_equal(0, htc_size_parse(v, vl, &b));
    first20 += b;
    if (i == 19)
      assert_int_equal(0, htc_bo_split(k, kl, strad, sizeof strad, NULL, NULL));
  }
  db_iter_close(it);
  assert_int_equal(20, i);
  assert_int_equal(first20, htc_acct_total(htrim_acct()));
  assert_string_equal("a:b19", strad);
  assert_int_equal(strad1.bytes, htc_acct_owner(htrim_acct(), "a:b19"));

  /* Stores on both sides of the cursor. */
  for (i = 0; i < 5; i++) {
    snprintf(ts, sizeof ts, "%d.000", 2000 + i);
    snprintf(mid, sizeof mid, "Z%d", i);
    seed_plain("#t", ts, mid, "a:zzz", NULL);            /* ahead of the cursor */
    snprintf(mid, sizeof mid, "D%d", i);
    seed_plain("#u", ts, mid, "-", &dash[i]);            /* behind it */
    dash_sum += dash[i].bytes;
  }

  /* Deletes behind the cursor, ahead of it, and ahead of it inside the
   * owner the scan has partly counted. */
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "1005.000", "M05", 1);   /* behind */
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "1090.000", "M90", 1);   /* ahead */
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "3000.000", "S2", 1);    /* ahead, a:b19 */
  assert_int_equal(3, htrim_slice_commit(s));

  /* Mid-scan state: only the deltas behind the cursor landed. */
  assert_int_equal(0, htrim_acct_loaded());
  assert_int_equal(dash_sum, htc_acct_owner(htrim_acct(), "-"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:zzz"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:b05"));
  assert_int_equal(strad1.bytes, htc_acct_owner(htrim_acct(), "a:b19"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:b50"));
  assert_int_equal(first20 - b05.bytes + dash_sum, htc_acct_total(htrim_acct()));

  /* The boundary: the cursor key itself was counted (bo_key <= cursor). */
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "1019.000", "M19", 1));
  assert_int_equal(0, htrim_acct_loaded());
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:b19"));
  assert_int_equal(first20 - b05.bytes - strad1.bytes + dash_sum,
                   htc_acct_total(htrim_acct()));

  run_until_idle(&p);
  assert_int_equal(1, htrim_acct_loaded());
  assert_acct_matches_cf();
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:b05"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:b90"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:b19"));
  assert_true(htc_acct_owner(htrim_acct(), "a:b50") > 0);
  assert_true(htc_acct_owner(htrim_acct(), "a:zzz") > 0);
}

static void test_delete_row_removes_every_index(void **state)
{
  struct htc_rec rec, other;
  char k[HTC_MSG_KEY_MAX], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  unsigned char xk[RDX_KEY_MAX];
  uint64_t before;
  int n, btl;
  (void)state;

  load_acct();
  seed_plain("#u", "50.000", "O1", "a:bob", &other);
  seed_row("#t", "100.000", "M1", "a:bob", HTC_F_REDACT | HTC_F_ML, "P0", "P1", 300, &rec);
  before = htc_acct_owner(htrim_acct(), "a:bob");
  assert_int_equal((uint64_t)other.bytes + rec.bytes, before);
  assert_int_equal(2, fake_db_rows(st.messages));
  assert_int_equal(4, fake_db_rows(st.msgid));
  assert_int_equal(2, fake_db_rows(st.reply));
  assert_int_equal(1, fake_db_rows(st.redact));
  assert_int_equal(1, fake_db_rows(st.ml_content));
  assert_int_equal(1, fake_db_rows(st.ml_paste));
  assert_int_equal(2, fake_db_rows(st.by_time));
  assert_int_equal(2, fake_db_rows(st.by_owner));

  assert_int_equal(1, del_row(HTRIM_PATH_OWNER, "#t", "100.000", "M1", 1));

  n = htc_msg_key(k, sizeof k, "#t", "100.000", "M1");
  assert_false(key_exists(st.messages, k, (size_t)n));
  n = htc_msgid_key(k, sizeof k, "M1", "#t");
  assert_false(key_exists(st.msgid, k, (size_t)n));
  assert_false(key_exists(st.msgid, "M1", 2));
  n = htc_reply_child_key(k, sizeof k, "#t", "P0", "100.000", "M1");
  assert_false(key_exists(st.reply, k, (size_t)n));
  n = htc_reply_child_key(k, sizeof k, "#t", "P1", "100.000", "M1");
  assert_false(key_exists(st.reply, k, (size_t)n));
  n = rdx_key_build(xk, sizeof xk, 100000, "M1");
  assert_false(key_exists(st.redact, xk, (size_t)n));
  assert_false(key_exists(st.ml_content, "M1", 2));
  assert_false(key_exists(st.ml_paste, "M1-sekret", 9));
  btl = bt_of(bt, sizeof bt, "#t", "100.000", "M1");
  assert_false(key_exists(st.by_time, bt, (size_t)btl));
  n = htc_bo_key(bo, sizeof bo, "a:bob", bt, (size_t)btl);
  assert_false(key_exists(st.by_owner, bo, (size_t)n));

  /* Only the other row's rows are left. */
  assert_int_equal(1, fake_db_rows(st.messages));
  assert_int_equal(2, fake_db_rows(st.msgid));
  assert_int_equal(0, fake_db_rows(st.reply));
  assert_int_equal(0, fake_db_rows(st.redact));
  assert_int_equal(0, fake_db_rows(st.ml_content));
  assert_int_equal(0, fake_db_rows(st.ml_paste));
  assert_int_equal(1, fake_db_rows(st.by_time));
  assert_int_equal(1, fake_db_rows(st.by_owner));

  assert_int_equal(before - rec.bytes, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
}

static void test_delete_noncanonical_ts(void **state)
{
  char k[HTC_MSG_KEY_MAX];
  int n;
  (void)state;

  seed_plain("#t", "1700000000.5", "M1", "a:bob", NULL);
  n = htc_msg_key(k, sizeof k, "#t", "1700000000.5", "M1");
  assert_true(key_exists(st.messages, k, (size_t)n));
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "1700000000.5", "M1", 1));
  assert_false(key_exists(st.messages, k, (size_t)n));
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_int_equal(0, fake_db_rows(st.by_time));
}

static void test_delete_parent_keeps_newer_child(void **state)
{
  char k[HTC_MSG_KEY_MAX];
  int n;
  (void)state;

  seed_plain("#t", "100.000", "P", "a:bob", NULL);
  seed_row("#t", "200.000", "C", "a:ann", 0, "P", "", 0, NULL);
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "100.000", "P", 1));

  n = htc_msg_key(k, sizeof k, "#t", "200.000", "C");
  assert_true(key_exists(st.messages, k, (size_t)n));
  n = htc_msgid_key(k, sizeof k, "C", "#t");
  assert_true(key_exists(st.msgid, k, (size_t)n));
  assert_true(key_exists(st.msgid, "C", 1));
  assert_true(key_exists(st.reply, "#t\0P\0" "200.000\0C",
                         sizeof("#t\0P\0" "200.000\0C") - 1));
  assert_int_equal(1, fake_db_rows(st.messages));
  assert_int_equal(1, fake_db_rows(st.reply));
}

static void test_delete_paste_by_value(void **state)
{
  struct db_writebatch *wb;
  (void)state;

  seed_row("#t", "100.000", "M1", "a:bob", HTC_F_ML, "", "", 40, NULL);
  wb = db_writebatch_new(env);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.ml_paste, "M1-s3cret", 9, "M1", 2));
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.ml_paste, "M1-x-k", 6, "M1-x", 4));
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.ml_paste, "M10-k", 5, "M10", 3));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  assert_int_equal(4, fake_db_rows(st.ml_paste));

  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "100.000", "M1", 1));
  assert_false(key_exists(st.ml_paste, "M1-s3cret", 9));
  assert_false(key_exists(st.ml_paste, "M1-sekret", 9));
  assert_true(key_exists(st.ml_paste, "M1-x-k", 6));
  assert_true(key_exists(st.ml_paste, "M10-k", 5));
  assert_int_equal(2, fake_db_rows(st.ml_paste));
}

/* A by_time row the engine cannot read must still leave the head: only
 * the engine-owned rows (by_time, and by_owner when the record names the
 * owner) go, it counts under its path, and the walk goes on to the next. */
static void test_delete_malformed_advances(void **state)
{
  struct htrim_slice *s;
  struct htc_rec rec, bad, good;
  struct db_writebatch *wb;
  struct db_iter *it;
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], rv[HTC_REC_MAX];
  char k[HTC_MSG_KEY_MAX];
  unsigned char sz[4];
  int btl, bol, rvl, rc, n, seen = 0;
  (void)state;

  load_acct();
  seed_plain("#t", "100.000", "M1", "a:bob", &good);          /* the next row */
  seed_plain("#t", "60.000", "M3", "a:bob", &rec);            /* record goes bad */

  wb = db_writebatch_new(env);
  /* (b) a by_time key that does not parse (no target separator), with a
   *     readable record naming its owner, and its by_owner row. */
  memset(&bad, 0, sizeof bad);
  bad.bytes = 77;
  snprintf(bad.ts, sizeof bad.ts, "0.001");
  snprintf(bad.owner, sizeof bad.owner, "a:bob");
  htc_be64((unsigned char *)bt, 1);
  memcpy(bt + 8, "#t", 2);
  btl = 10;
  rvl = htc_rec_pack(rv, sizeof rv, &bad);
  assert_true(rvl > 0);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_time, bt, (size_t)btl, rv, (size_t)rvl));
  bol = htc_bo_key(bo, sizeof bo, "a:bob", bt, (size_t)btl);
  assert_true(bol > 0);
  htc_size_pack(sz, 77);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, 4));
  /* (a) a well-formed key whose record does not parse. */
  btl = bt_of(bt, sizeof bt, "#t", "50.000", "BAD2");
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_time, bt, (size_t)btl, "garbage", 7));
  /* (c) M3's record loses its ts. */
  btl = bt_of(bt, sizeof bt, "#t", "60.000", "M3");
  rec.ts[0] = '\0';
  rvl = htc_rec_pack(rv, sizeof rv, &rec);
  assert_true(rvl > 0);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_time, bt, (size_t)btl, rv, (size_t)rvl));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  htrim_note_stored("a:bob", bo, (size_t)bol, 77);
  assert_int_equal(4, fake_db_rows(st.by_time));

  /* A head walk: every row is deleted, readable or not. */
  s = htrim_slice_begin(0);
  assert_non_null(s);
  it = db_iter_open(env, st.by_time, NULL);
  assert_non_null(it);
  for (rc = db_iter_seek_first(it); rc == DB_OK; rc = db_iter_next(it)) {
    size_t kl, vl;
    const void *kp = db_iter_key(it, &kl);
    const void *vp = db_iter_value(it, &vl);
    struct htc_rec r;
    int parsed = htc_rec_parse(vp, vl, &r) == 0;
    assert_int_equal(0, htrim_delete_row(s, HTRIM_PATH_AGEOUT, kp, kl,
                                         parsed ? &r : NULL, 1));
    seen++;
  }
  db_iter_close(it);
  assert_int_equal(4, seen);
  assert_int_equal(4, htrim_slice_commit(s));

  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(0, fake_db_rows(st.by_owner));
  assert_int_equal(4, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  /* The good row went whole; the unreadable record's message row is not
   * the engine's to guess at, so it stays. */
  n = htc_msg_key(k, sizeof k, "#t", "100.000", "M1");
  assert_false(key_exists(st.messages, k, (size_t)n));
  n = htc_msg_key(k, sizeof k, "#t", "60.000", "M3");
  assert_true(key_exists(st.messages, k, (size_t)n));
  assert_int_equal(1, fake_db_rows(st.messages));
  assert_int_equal(2, fake_db_rows(st.msgid));               /* M3's two rows */
  assert_acct_matches_cf();
  assert_int_equal(0, htc_acct_total(htrim_acct()));
  (void)good;
}

/* A failed batch op poisons the slice: -2 from then on, and a commit that
 * applies nothing. */
static void test_delete_poisoned_slice(void **state)
{
  struct htrim_slice *s;
  uint64_t total;
  (void)state;

  load_acct();
  seed_plain("#t", "100.000", "M1", "a:bob", NULL);
  seed_plain("#t", "200.000", "M2", "a:bob", NULL);
  total = htc_acct_total(htrim_acct());

  s = htrim_slice_begin(0);
  assert_non_null(s);
  fake_db_fail_next_batch_op(env);
  {
    char bt[HTC_BT_KEY_MAX];
    struct htc_rec rec;
    int btl = bt_of(bt, sizeof bt, "#t", "100.000", "M1");
    get_rec("#t", "100.000", "M1", &rec);
    assert_int_equal(-2, htrim_delete_row(s, HTRIM_PATH_AGEOUT, bt, (size_t)btl, &rec, 1));
    btl = bt_of(bt, sizeof bt, "#t", "200.000", "M2");
    get_rec("#t", "200.000", "M2", &rec);
    assert_int_equal(-2, htrim_delete_row(s, HTRIM_PATH_AGEOUT, bt, (size_t)btl, &rec, 1));
    /* An invalid call stays -1. */
    assert_int_equal(-1, htrim_delete_row(s, HTRIM_PATH_COUNT, bt, (size_t)btl, &rec, 1));
  }
  assert_int_equal(-1, htrim_slice_commit(s));
  assert_int_equal(2, fake_db_rows(st.messages));
  assert_int_equal(2, fake_db_rows(st.by_time));
  assert_int_equal(total, htc_acct_total(htrim_acct()));
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
}

static void test_commit_failure_keeps_everything(void **state)
{
  struct htrim_slice *s;
  uint64_t owner_before, total_before;
  uint64_t deleted_before[HTRIM_PATH_COUNT];
  size_t rows[10];
  struct db_cf *cfs[10];
  unsigned int opens;
  int i;
  (void)state;

  load_acct();
  seed_row("#t", "100.000", "M1", "a:bob", HTC_F_REDACT | HTC_F_ML, "P0", "P1", 30, NULL);
  seed_plain("#t", "200.000", "M2", "a:bob", NULL);
  seed_targets("#t", "200.000");
  owner_before = htc_acct_owner(htrim_acct(), "a:bob");
  total_before = htc_acct_total(htrim_acct());
  memcpy(deleted_before, htrim_stats()->deleted, sizeof deleted_before);
  cfs[0] = st.messages; cfs[1] = st.msgid; cfs[2] = st.targets; cfs[3] = st.reply;
  cfs[4] = st.redact; cfs[5] = st.ml_content; cfs[6] = st.ml_paste;
  cfs[7] = st.by_time; cfs[8] = st.by_owner; cfs[9] = st.meta;
  for (i = 0; i < 10; i++)
    rows[i] = fake_db_rows(cfs[i]);

  opens = fake_db_iter_opens(st.messages);
  fake_db_fail_next_commit(env);
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "100.000", "M1", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "200.000", "M2", 1);
  assert_int_equal(-1, htrim_slice_commit(s));

  assert_int_equal(owner_before, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal(total_before, htc_acct_total(htrim_acct()));
  for (i = 0; i < 10; i++)
    assert_int_equal(rows[i], fake_db_rows(cfs[i]));
  for (i = 0; i < HTRIM_PATH_COUNT; i++)
    assert_int_equal(deleted_before[i], htrim_stats()->deleted[i]);
  assert_int_equal(0, emptied_calls);
  assert_true(targets_has("#t"));
  assert_int_equal(opens, fake_db_iter_opens(st.messages));   /* no cleanup ran */
}

static void test_uncounted_delete(void **state)
{
  uint64_t owner_before, total_before;
  (void)state;

  load_acct();
  seed_plain("#t", "100.000", "M1", "a:bob", NULL);
  owner_before = htc_acct_owner(htrim_acct(), "a:bob");
  total_before = htc_acct_total(htrim_acct());
  assert_true(owner_before > 0);

  assert_int_equal(1, del_row(HTRIM_PATH_INCARNATION, "#t", "100.000", "M1", 0));
  assert_int_equal(owner_before, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal(total_before, htc_acct_total(htrim_acct()));
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_int_equal(0, fake_db_rows(st.msgid));
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(0, fake_db_rows(st.by_owner));
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_INCARNATION]);
}

static void test_cleanup_removes_empty_target(void **state)
{
  struct htrim_slice *s;
  (void)state;

  seed_plain("#t", "100.000", "T1", "a:bob", NULL);
  seed_plain("#t", "200.000", "T2", "a:bob", NULL);
  seed_targets("#t", "200.000");
  /* A touched target whose newest row goes but an older one stays. */
  seed_plain("#u", "100.000", "U1", "a:bob", NULL);
  seed_plain("#u", "300.000", "U3", "a:bob", NULL);
  seed_targets("#u", "300.000");
  /* Emptied, touched non-adjacently: the newest of its deletes counts. */
  seed_plain("#w", "100.000", "W1", "a:bob", NULL);
  seed_plain("#w", "150.000", "W2", "a:bob", NULL);
  seed_targets("#w", "150.000");
  /* Emptied, its stamp older than its rows (rows that do not bump it),
   * touched twice non-adjacently: checked and reported once. */
  seed_plain("#x", "200.000", "X2", "a:bob", NULL);
  seed_plain("#x", "300.000", "X3", "a:bob", NULL);
  seed_targets("#x", "100.000");

  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "100.000", "T1", 1);   /* oldest first, */
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "200.000", "T2", 1);   /* as age-out goes */
  stage_del(s, HTRIM_PATH_AGEOUT, "#w", "100.000", "W1", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#x", "200.000", "X2", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#u", "300.000", "U3", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#w", "150.000", "W2", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#x", "300.000", "X3", 1);
  assert_int_equal(7, htrim_slice_commit(s));

  assert_int_equal(1, emptied_calls);
  assert_int_equal(3, emptied_count);
  assert_string_equal("#t", emptied_names[0]);
  assert_string_equal("#w", emptied_names[1]);
  assert_string_equal("#x", emptied_names[2]);
  assert_false(targets_has("#t"));
  assert_false(targets_has("#w"));
  assert_false(targets_has("#x"));
  assert_true(targets_has("#u"));
  assert_int_equal(1, fake_db_rows(st.targets));
}

/* Review Focus 5: the stamp says a newer row exists, so the commit must
 * not seek the target's messages range (on RocksDB that seek walks every
 * head tombstone the drain has left so far). */
static void test_cleanup_skips_when_newest_not_deleted(void **state)
{
  unsigned int opens;
  (void)state;

  seed_plain("#t", "100.000", "T1", "a:bob", NULL);
  seed_plain("#t", "200.000", "T2", "a:bob", NULL);
  seed_targets("#t", "200.000");

  opens = fake_db_iter_opens(st.messages);
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "100.000", "T1", 1));
  assert_int_equal(opens, fake_db_iter_opens(st.messages));
  assert_int_equal(0, emptied_calls);
  assert_true(targets_has("#t"));
}

/* Review Focus 5, the stamp that does not help: JOIN/PART/QUIT/... rows do
 * not bump the targets stamp, so a target whose newest rows are such rows
 * reaches the emptiness check on every slice of its drain.  The check must
 * seek the LIVE tail (seek_last), never the head (seek_first), which on
 * RocksDB walks every tombstone the drain has left so far. */
static void test_cleanup_seeks_tail_not_head(void **state)
{
  unsigned int firsts, lasts;
  (void)state;

  seed_plain("#t", "200.000", "T2", "a:bob", NULL);
  seed_plain("#t", "300.000", "T3", "a:bob", NULL);
  seed_targets("#t", "100.000");            /* older than every row */

  firsts = fake_db_seek_firsts(st.messages);
  lasts = fake_db_seek_lasts(st.messages);
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "200.000", "T2", 1));
  assert_int_equal(firsts, fake_db_seek_firsts(st.messages));
  assert_int_equal(lasts + 1, fake_db_seek_lasts(st.messages));
  assert_int_equal(0, emptied_calls);
  assert_true(targets_has("#t"));

  /* The last row goes: one tail seek finds the range empty. */
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#t", "300.000", "T3", 1));
  assert_int_equal(firsts, fake_db_seek_firsts(st.messages));
  assert_int_equal(lasts + 2, fake_db_seek_lasts(st.messages));
  assert_int_equal(1, emptied_calls);
  assert_string_equal("#t", emptied_names[0]);
  assert_false(targets_has("#t"));
}

/* A cleanup that cannot finish leaves its targets keys for Task 8's sweep,
 * and says so -- it never reports a target it did not remove. */
static void test_cleanup_failure_wants_sweep(void **state)
{
  struct htrim_slice *s;
  (void)state;

  seed_plain("#t", "100.000", "T1", "a:bob", NULL);
  seed_plain("#t", "200.000", "T2", "a:bob", NULL);
  seed_targets("#t", "200.000");
  assert_int_equal(0, htrim_tsweep_wanted());

  /* The slice commits; the cleanup's own batch (the 2nd commit) fails. */
  fake_db_fail_commit_at(env, 2);
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "100.000", "T1", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "200.000", "T2", 1);
  assert_int_equal(2, htrim_slice_commit(s));
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_int_equal(0, emptied_calls);
  assert_true(targets_has("#t"));
  assert_int_equal(1, htrim_tsweep_wanted());
  htrim_tsweep_clear();
  assert_int_equal(0, htrim_tsweep_wanted());

  /* An emptiness check that cannot read the target wants the sweep too. */
  seed_plain("#u", "100.000", "U1", "a:bob", NULL);
  seed_targets("#u", "100.000");
  fake_db_fail_next_iter_open(env);
  assert_int_equal(1, del_row(HTRIM_PATH_AGEOUT, "#u", "100.000", "U1", 1));
  assert_int_equal(0, emptied_calls);
  assert_true(targets_has("#u"));
  assert_int_equal(1, htrim_tsweep_wanted());
}

static void test_cleanup_no_targets_entry(void **state)
{
  struct htrim_slice *s;
  unsigned int opens;
  (void)state;

  seed_plain("#t", "100.000", "T1", "a:bob", NULL);
  seed_plain("#t", "200.000", "T2", "a:bob", NULL);
  opens = fake_db_iter_opens(st.messages);

  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "100.000", "T1", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "200.000", "T2", 1);
  assert_int_equal(2, htrim_slice_commit(s));

  assert_int_equal(0, emptied_calls);
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_int_equal(opens, fake_db_iter_opens(st.messages));
}

static void test_slice_budget(void **state)
{
  struct htrim_slice *s;
  int i;
  (void)state;

  step_us = 1000;
  s = htrim_slice_begin(5);
  assert_non_null(s);
  for (i = 0; i < 4; i++)
    assert_false(htrim_slice_expired(s));
  assert_true(htrim_slice_expired(s));
  htrim_slice_abort(s);
}

static void test_run_slice_scan_then_idle(void **state)
{
  struct htrim_params p = params(15);
  const struct htrim_stats *stats;
  int i;
  (void)state;

  seed_backfill_done();              /* the scan is the only phase with work */
  reboot();
  step_us = 250;
  assert_int_equal(0, htrim_acct_loaded());
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(1, htrim_acct_loaded());
  stats = htrim_stats();
  assert_int_equal(HTRIM_PH_ACCTSCAN, stats->last_phase);
  assert_int_equal(250, stats->last_slice_us);      /* begin -> end of cleanup */
  assert_int_equal(250, stats->max_slice_us);
  for (i = 0; i < HTRIM_PATH_COUNT; i++)
    assert_int_equal(0, stats->deleted[i]);
  htrim_reset_max_slice();
  assert_int_equal(0, htrim_stats()->max_slice_us);
  assert_int_equal(0, htrim_run_slice(&p));        /* still idle */
}

/* A slice whose phase fails is still a slice the main loop paid for. */
static void test_run_slice_error_recorded(void **state)
{
  struct htrim_params p = params(15);
  (void)state;

  seed_backfill_done();              /* the failing slice is the scan's */
  reboot();
  step_us = 300;
  fake_db_fail_next_iter_open(env);
  assert_int_equal(-1, htrim_run_slice(&p));
  assert_int_equal(0, htrim_acct_loaded());
  assert_int_equal(HTRIM_PH_ACCTSCAN, htrim_stats()->last_phase);
  assert_int_equal(300, htrim_stats()->last_slice_us);
  assert_int_equal(300, htrim_stats()->max_slice_us);
  assert_int_equal(0, htrim_run_slice(&p));          /* the next one recovers */
  assert_int_equal(1, htrim_acct_loaded());
}

/* ------------------------------------------------------------------ */
/* The backfill (Task 6)                                               */
/* ------------------------------------------------------------------ */

static void test_backfill_indexes_in_retention(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htc_rec r;
  char t1[32], t2[32];
  uint32_t b1, b2;
  (void)state;

  load_acct_backfill_pending();
  b1 = seed_legacy_row("#t", ts_ago(t1, sizeof t1, 1, 0), "L1", "Bob", 0, "", "", 0);
  b2 = seed_legacy_row("#u", ts_ago(t2, sizeof t2, 2, 0), "L2", "", 0, "", "", 0);
  assert_int_equal(0, fake_db_rows(st.by_time));

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(2, htrim_backfill_rows());
  assert_int_equal(2, fake_db_rows(st.by_time));
  assert_int_equal(2, fake_db_rows(st.by_owner));
  get_rec("#t", t1, "L1", &r);
  assert_string_equal("a:bob", r.owner);
  assert_string_equal(t1, r.ts);
  assert_int_equal(b1, r.bytes);
  get_rec("#u", t2, "L2", &r);
  assert_string_equal("-", r.owner);
  assert_int_equal(b2, r.bytes);
  assert_int_equal(b1, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal(b2, htc_acct_owner(htrim_acct(), "-"));
  assert_int_equal((uint64_t)b1 + b2, htc_acct_total(htrim_acct()));
  assert_acct_matches_cf();
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_BACKFILL]);
  assert_int_equal(2, fake_db_rows(st.messages));
}

/* A row past retention that was never indexed is deleted in full by the
 * backfill (age-out walks by_time and would never see it), uncounted:
 * it was never in the totals.  A row exactly at the cutoff stays. */
static void test_backfill_ages_out_old_uncounted(void **state)
{
  struct htrim_params p = bf_params(0);
  char tk[32], told[32], tcut[32];
  uint64_t before;
  uint32_t bcut;
  (void)state;

  load_acct_backfill_pending();
  /* An indexed row of the same owner: an uncounted delete leaves it be. */
  seed_plain("#k", ts_ago(tk, sizeof tk, 1, 0), "K1", "a:bob", NULL);
  before = htc_acct_total(htrim_acct());
  assert_true(before > 0);
  seed_legacy_row("#t", ts_ago(told, sizeof told, 8, 0), "OLD", "Bob",
                  HTC_F_REDACT | HTC_F_ML, "P0", "P1", 300);
  bcut = seed_legacy_row("#c", ts_ago(tcut, sizeof tcut, 7, 0), "CUT", "Cy", 0, "", "", 0);
  assert_int_equal(3, fake_db_rows(st.messages));

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_BACKFILL]);
  /* Every row of OLD is gone; K1's and CUT's stay. */
  assert_int_equal(2, fake_db_rows(st.messages));
  assert_int_equal(4, fake_db_rows(st.msgid));
  assert_int_equal(0, fake_db_rows(st.reply));
  assert_int_equal(0, fake_db_rows(st.redact));
  assert_int_equal(0, fake_db_rows(st.ml_content));
  assert_int_equal(0, fake_db_rows(st.ml_paste));
  assert_int_equal(2, fake_db_rows(st.by_time));
  assert_int_equal(2, fake_db_rows(st.by_owner));
  assert_int_equal(before, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal(bcut, htc_acct_owner(htrim_acct(), "a:cy"));
  assert_int_equal(before + bcut, htc_acct_total(htrim_acct()));
  assert_acct_matches_cf();
}

/* Review Focus 3: a row the store path already indexed (and counted) is
 * skipped, never indexed or counted a second time. */
static void test_backfill_skips_indexed(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htc_rec rec, got;
  char ti[32], tl[32];
  uint64_t total, bob;
  uint32_t bl;
  (void)state;

  load_acct_backfill_pending();
  /* The indexed row's value names "a:bob" as its account: were it parsed
   * again it would land under a third owner, "a:a:bob". */
  seed_plain("#t", ts_ago(ti, sizeof ti, 1, 10), "I1", "a:bob", &rec);
  total = htc_acct_total(htrim_acct());
  bob = htc_acct_owner(htrim_acct(), "a:bob");
  assert_int_equal(rec.bytes, bob);
  bl = seed_legacy_row("#t", ts_ago(tl, sizeof tl, 1, 0), "L1", "Bob", 0, "", "", 0);

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(2, htrim_backfill_rows());          /* both walked */
  assert_int_equal(total + bl, htc_acct_total(htrim_acct()));
  assert_int_equal(bob + bl, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:a:bob"));
  assert_int_equal(2, fake_db_rows(st.by_time));
  assert_int_equal(2, fake_db_rows(st.by_owner));
  get_rec("#t", ti, "I1", &got);
  assert_int_equal(rec.bytes, got.bytes);
  assert_string_equal("a:bob", got.owner);
  assert_acct_matches_cf();
}

/* Review Focus 3: a restart mid-backfill resumes at the persisted cursor:
 * no row is skipped, none is walked twice. */
static void test_backfill_resumes_after_restart(void **state)
{
  struct htrim_params p = bf_params(10);
  char ts[32], mid[16];
  size_t first;
  int i;
  (void)state;

  load_acct_backfill_pending();
  for (i = 0; i < 50; i++) {
    snprintf(mid, sizeof mid, "R%02d", i);
    seed_legacy_row("#t", ts_ago(ts, sizeof ts, 1, 100 - i), mid, "Bob", 0, "", "", 0);
  }

  step_us = 1000;                      /* 1 ms per clock read; 10 ms slices */
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(HTRIM_PH_BACKFILL, htrim_stats()->last_phase);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(HTRIM_PH_BACKFILL, htrim_stats()->last_phase);
  first = htrim_backfill_rows();
  assert_true(first > 0 && first < 50);
  assert_int_equal(first, fake_db_rows(st.by_time));
  assert_int_equal(0, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));   /* a cursor row */
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));

  htrim_shutdown();
  assert_int_equal(0, htrim_init(&st, parse_cb, fake_clock, on_emptied));
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(0, htrim_backfill_rows());

  step_us = 0;
  p = bf_params(0);
  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(50 - first, htrim_backfill_rows());   /* from the cursor on */
  assert_int_equal(50, fake_db_rows(st.by_time));
  assert_int_equal(50, fake_db_rows(st.by_owner));
  assert_int_equal(1, htrim_acct_loaded());
  assert_acct_matches_cf();
  assert_int_equal(1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));
}

static void test_backfill_done_skips_next_boot(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32];
  unsigned int opens;
  (void)state;

  seed_legacy_row("#t", ts_ago(ts, sizeof ts, 1, 0), "L1", "Bob", 0, "", "", 0);
  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());

  reboot();
  assert_int_equal(1, htrim_backfill_done());
  opens = fake_db_iter_opens(st.messages);
  assert_true(htrim_run_slice(&p) >= 0);
  assert_int_equal(HTRIM_PH_ACCTSCAN, htrim_stats()->last_phase);
  run_until_idle(&p);
  assert_int_equal(opens, fake_db_iter_opens(st.messages));
  assert_int_equal(0, htrim_backfill_rows());
}

/* A multiline row's size counts its ml_content blob, as the store path's. */
static void test_backfill_ml_counts_blob(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htc_rec r;
  char ts[32], bt[HTC_BT_KEY_MAX], mk[HTC_MSG_KEY_MAX];
  uint32_t b;
  int btl, mkl;
  (void)state;

  load_acct_backfill_pending();
  b = seed_legacy_row("#t", ts_ago(ts, sizeof ts, 1, 0), "ML1", "Bob", HTC_F_ML, "", "", 300);
  run_until_idle(&p);
  get_rec("#t", ts, "ML1", &r);
  assert_int_equal(b, r.bytes);
  assert_true(r.flags & HTC_F_ML);
  btl = bt_of(bt, sizeof bt, "#t", ts, "ML1");
  mkl = htc_msg_key(mk, sizeof mk, "#t", ts, "ML1");
  assert_int_equal(300, r.bytes - htc_row_bytes((size_t)mkl, 80, 0, (size_t)btl, 5));
  assert_int_equal(b, htc_acct_owner(htrim_acct(), "a:bob"));
}

/* A value the parse callback cannot read is still indexed: owner "-",
 * no flags, no parents.  A key the engine cannot rebuild byte for byte
 * (here an unfolded target) is left alone: indexing it would let age-out
 * drop its index rows while THE delete missed the message row. */
static void test_backfill_parse_failure(void **state)
{
  struct htrim_params p = bf_params(0);
  struct db_writebatch *wb;
  struct htc_rec r;
  char ts[32], uk[64];
  uint32_t b;
  int ukl;
  (void)state;

  load_acct_backfill_pending();
  b = seed_legacy_raw("#t", ts_ago(ts, sizeof ts, 1, 0), "PF", "garbage", 7, 0, "", "", 0, 1);
  ukl = snprintf(uk, sizeof uk, "#U%c%s%cUF", '\0', ts, '\0');
  assert_true(ukl > 0);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.messages, uk, (size_t)ukl, "Bob|0|||x", 9));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(2, htrim_backfill_rows());
  assert_int_equal(1, fake_db_rows(st.by_time));
  assert_int_equal(2, fake_db_rows(st.messages));
  assert_true(key_exists(st.messages, uk, (size_t)ukl));
  get_rec("#t", ts, "PF", &r);
  assert_string_equal("-", r.owner);
  assert_int_equal(0, r.flags);
  assert_string_equal("", r.reply_parent);
  assert_string_equal("", r.redact_parent);
  assert_int_equal(b, r.bytes);
  assert_int_equal(b, htc_acct_owner(htrim_acct(), "-"));
  assert_int_equal(b, htc_acct_total(htrim_acct()));
}

/* Review Focus 3: rows an older binary wrote after the backfill finished
 * (a downgrade window) are newer than the last alive stamp plus the slack:
 * the done marker goes and the backfill runs again. */
static void test_index_gap_reruns_backfill(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32];
  (void)state;

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));

  htrim_stamp_alive(1000);
  assert_int_equal(1, meta_is(HTRIM_META_ALIVE, "1000"));
  htrim_check_index_gap(1000 + 600000, 600000);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));
  htrim_check_index_gap(1000 + 600001, 600000);
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));

  /* Persisted: a restart before the re-run still runs it. */
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  /* Still a gap against the persisted alive 1000, but no walk state is
   * left to reset: nothing is reset (and nothing logged). */
  assert_int_equal(0, htrim_check_index_gap(1000 + 600001, 600000));
  assert_int_equal(0, htrim_backfill_done());
  seed_legacy_row("#t", ts_ago(ts, sizeof ts, 1, 0), "G1", "Bob", 0, "", "", 0);
  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, fake_db_rows(st.by_time));
  reboot();
  htrim_check_index_gap(1000 + 600000, 600000);    /* the persisted alive is 1000 */
  assert_int_equal(1, htrim_backfill_done());
}

/* Review Focus 3, an unfinished walk: this binary stops with its cursor at
 * K, an older binary stores rows (some sort before K), this binary comes
 * back.  Resuming at K would never walk them, and the done marker plus
 * fresh alive stamps would then hide them for good: the gap check resets
 * the cursor too, and the walk restarts from the first key. */
static void test_index_gap_resets_unfinished_walk(void **state)
{
  struct htrim_params p = bf_params(5);
  struct htc_rec r;
  char ts[32], told[32], mid[16];
  int i;
  (void)state;

  load_acct_backfill_pending();
  for (i = 0; i < 20; i++) {
    snprintf(mid, sizeof mid, "R%02d", i);
    seed_legacy_row("#t", ts_ago(ts, sizeof ts, 1, 100 - i), mid, "Bob", 0, "", "", 0);
  }
  htrim_stamp_alive(1000);
  step_us = 1000;                      /* 1 ms per clock read; 5 ms slices */
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(HTRIM_PH_BACKFILL, htrim_stats()->last_phase);
  assert_true(fake_db_rows(st.by_time) > 0 && fake_db_rows(st.by_time) < 20);
  assert_int_equal(0, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));   /* a cursor row */

  /* The older binary's row: "#a" sorts before the cursor inside "#t". */
  seed_legacy_row("#a", ts_ago(told, sizeof told, 0, 60), "OLDBIN", "Ann", 0, "", "", 0);
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  htrim_check_index_gap(1000 + 600001, 600000);
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));

  step_us = 0;
  p = bf_params(0);
  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(21, htrim_backfill_rows());       /* from the first key */
  assert_int_equal(21, fake_db_rows(st.by_time));
  get_rec("#a", told, "OLDBIN", &r);
  assert_string_equal("a:ann", r.owner);
  assert_acct_matches_cf();
}

/* A reset the store would not take is reported: the caller then withholds
 * this start's alive stamp, so a crash before the re-run's first slice
 * commits leaves the gap for the next start to find again. */
static void test_index_gap_reset_failure_reported(void **state)
{
  struct htrim_params p = bf_params(0);
  (void)state;

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  htrim_stamp_alive(1000);

  fake_db_fail_next_commit(env);
  assert_int_equal(-1, htrim_check_index_gap(1000 + 600001, 600000));
  assert_int_equal(0, htrim_backfill_done());           /* this start re-runs */
  assert_int_equal(1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));
  assert_int_equal(1, meta_is(HTRIM_META_ALIVE, "1000"));

  reboot();                            /* a crash before any slice committed */
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, htrim_check_index_gap(1000 + 600001, 600000));
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));
  assert_int_equal(0, htrim_check_index_gap(1000 + 600001, 600000));   /* nothing left */
  assert_int_equal(0, htrim_check_index_gap(1000, 600000));           /* no gap */
}

/* A meta row that cannot be read is not a missing row: an unreadable
 * cursor beside a done marker (a re-run whose marker delete did not
 * commit) is an unfinished walk, and so is an unreadable done marker.
 * Either way the walk runs again from the first key. */
static void test_meta_read_error_means_not_done(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], ck[HTC_MSG_KEY_MAX];
  int ckl;
  (void)state;

  seed_legacy_row("#a", ts_ago(ts, sizeof ts, 1, 0), "A1", "Ann", 0, "", "", 0);
  seed_legacy_row("#z", ts_ago(ts, sizeof ts, 1, 0), "Z1", "Zed", 0, "", "", 0);
  ckl = htc_msg_key(ck, sizeof ck, "#m", ts, "M1");     /* a cursor between them */
  assert_true(ckl > 0);
  put_meta(HTRIM_META_BACKFILL_DONE, "done");
  {
    struct db_writebatch *wb = db_writebatch_new(env);
    assert_non_null(wb);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.meta, HTRIM_META_BACKFILL_CURSOR,
                                              strlen(HTRIM_META_BACKFILL_CURSOR), ck, (size_t)ckl));
    assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
    db_writebatch_destroy(wb);
  }

  fake_db_fail_get_at(env, 1);         /* init's first read: the cursor */
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(2, htrim_backfill_rows());          /* "#a" too: from the first key */
  assert_int_equal(2, fake_db_rows(st.by_time));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));

  /* Done, no cursor: the done marker's read (init's second) fails. */
  fake_db_fail_get_at(env, 2);
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  reboot();
  assert_int_equal(1, htrim_backfill_done());          /* readable again: done */

  /* A gap while the walk state was unreadable: the store's marker and
   * cursor may still be there, so the reset deletes them. */
  put_meta(HTRIM_META_BACKFILL_CURSOR, "#m");
  htrim_stamp_alive(1000);
  fake_db_fail_get_at(env, 1);
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(1, htrim_check_index_gap(1000 + 600001, 600000));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_CURSOR, ""));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));

  /* The same with only the done marker there, and it unreadable. */
  put_meta(HTRIM_META_BACKFILL_DONE, "done");
  fake_db_fail_get_at(env, 2);
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(1, htrim_check_index_gap(1000 + 600001, 600000));
  assert_int_equal(-1, meta_is(HTRIM_META_BACKFILL_DONE, "done"));
}

/* The rows the round-trip guard leaves alone are never trimmed: the walk
 * names the first five keys (non-printable bytes hex-escaped), then the
 * count.  test_stub's log_write writes to stderr. */
static int stderr_saved = -1;

static void stderr_capture(FILE **tmp)
{
  *tmp = tmpfile();
  assert_non_null(*tmp);
  fflush(stderr);
  stderr_saved = dup(2);
  assert_true(stderr_saved >= 0);
  assert_true(dup2(fileno(*tmp), 2) >= 0);
}

static void stderr_restore(void)
{
  if (stderr_saved < 0)
    return;
  fflush(stderr);
  dup2(stderr_saved, 2);
  close(stderr_saved);
  stderr_saved = -1;
}

static int count_of(const char *hay, const char *needle)
{
  int n = 0;
  const char *p = hay;
  while ((p = strstr(p, needle)) != NULL) {
    n++;
    p += strlen(needle);
  }
  return n;
}

static void test_backfill_logs_first_unindexable_keys(void **state)
{
  struct htrim_params p = bf_params(3);   /* a few keys per slice: the limit is per walk */
  struct db_writebatch *wb;
  char ts[32], k[64], want[96], log[8192];
  FILE *tmp;
  size_t n;
  int i, kl;
  (void)state;

  ts_ago(ts, sizeof ts, 1, 0);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  for (i = 0; i < 7; i++) {            /* unfolded targets: not rebuildable */
    kl = snprintf(k, sizeof k, "#U%d%c%s%cU%cF", i, '\0', ts, '\0', i == 0 ? '\x01' : 'x');
    assert_true(kl > 0);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.messages, k, (size_t)kl, "Bob|0|||x", 9));
  }
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);

  stderr_capture(&tmp);
  step_us = 1000;                      /* 1 ms per clock read; 3 ms slices */
  run_until_idle(&p);
  stderr_restore();
  rewind(tmp);
  n = fread(log, 1, sizeof log - 1, tmp);
  log[n] = '\0';
  fclose(tmp);

  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_true(htrim_stats()->max_slice_us > 0);
  assert_int_equal(5, count_of(log, "cannot be indexed"));
  snprintf(want, sizeof want, "'#U0\\x00%s\\x00U\\x01F'", ts);
  assert_non_null(strstr(log, want));
  snprintf(want, sizeof want, "'#U4\\x00%s\\x00UxF'", ts);
  assert_non_null(strstr(log, want));
  assert_null(strstr(log, "'#U5"));
  assert_null(strstr(log, "'#U6"));
  assert_non_null(strstr(log, "7 rows have a key the trim index cannot hold"));
}

/* Both phases pending: consecutive slices take turns (round-robin), not
 * one phase running to exhaustion first. */
static void test_run_slice_rotation(void **state)
{
  struct htrim_params p = bf_params(5);
  enum htrim_phase ph1, ph2;
  char ts[32], mid[16];
  int i;
  (void)state;

  for (i = 0; i < 30; i++) {
    snprintf(mid, sizeof mid, "I%02d", i);
    seed_plain("#i", ts_ago(ts, sizeof ts, 1, 100 - i), mid, "a:ann", NULL);
    snprintf(mid, sizeof mid, "L%02d", i);
    seed_legacy_row("#l", ts_ago(ts, sizeof ts, 1, 100 - i), mid, "Bob", 0, "", "", 0);
  }
  reboot();
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(0, htrim_acct_loaded());

  step_us = 1000;                      /* 1 ms per clock read; 5 ms slices */
  assert_int_equal(1, htrim_run_slice(&p));
  ph1 = htrim_stats()->last_phase;
  assert_int_equal(1, htrim_run_slice(&p));
  ph2 = htrim_stats()->last_phase;
  assert_true(ph1 == HTRIM_PH_BACKFILL || ph1 == HTRIM_PH_ACCTSCAN);
  assert_true(ph2 == HTRIM_PH_BACKFILL || ph2 == HTRIM_PH_ACCTSCAN);
  assert_true(ph1 != ph2);
  assert_int_equal(0, htrim_backfill_done());        /* neither ran out of work */
  assert_int_equal(0, htrim_acct_loaded());

  run_until_idle(&p);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, htrim_acct_loaded());
  assert_int_equal(60, fake_db_rows(st.by_time));
  assert_acct_matches_cf();
}

/* ------------------------------------------------------------------ */
/* Age-out (Task 7)                                                    */
/* ------------------------------------------------------------------ */

/** The age-out tests' starting point: a finished backfill (its marker in
 * the store before the engine starts) and a finished accounting scan, so
 * age-out is the only phase with work. */
static void ageout_ready(void)
{
  seed_backfill_done();
  reboot();
  load_acct();
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(0, htrim_ageout_pending());
}

/** A pass start under @a p, then slices until idle. */
static void ageout_pass(const struct htrim_params *p)
{
  htrim_pass_start(p);
  run_until_idle(p);
  assert_int_equal(0, htrim_ageout_pending());
}

/** Whether every row the store path wrote for (target, ts, msgid) is
 * there (@a want 1) or gone (@a want 0): its messages row, both msgid
 * forms, its reply_index entries as a child, its redact_index row
 * (HTC_F_REDACT), its multiline content and paste row (HTC_F_ML), its
 * by_time row and its by_owner row. */
static void assert_row_rows(const char *target, const char *ts, const char *msgid,
                            const char *owner, unsigned char flags,
                            const char *reply_parent, const char *redact_parent,
                            int want)
{
  char k[HTC_MSG_KEY_MAX], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], paste[HTC_MSGID_MAX + 16];
  unsigned char xk[RDX_KEY_MAX];
  int n, btl;

  n = htc_msg_key(k, sizeof k, target, ts, msgid);
  assert_int_equal(want, key_exists(st.messages, k, (size_t)n));
  n = htc_msgid_key(k, sizeof k, msgid, target);
  assert_int_equal(want, key_exists(st.msgid, k, (size_t)n));
  assert_int_equal(want, key_exists(st.msgid, msgid, strlen(msgid)));
  if (reply_parent[0]) {
    n = htc_reply_child_key(k, sizeof k, target, reply_parent, ts, msgid);
    assert_int_equal(want, key_exists(st.reply, k, (size_t)n));
  }
  if (redact_parent[0]) {
    n = htc_reply_child_key(k, sizeof k, target, redact_parent, ts, msgid);
    assert_int_equal(want, key_exists(st.reply, k, (size_t)n));
  }
  if (flags & HTC_F_REDACT) {
    n = rdx_key_build(xk, sizeof xk, htc_parse_ms(ts), msgid);
    assert_int_equal(want, key_exists(st.redact, xk, (size_t)n));
  }
  if (flags & HTC_F_ML) {
    assert_int_equal(want, key_exists(st.ml_content, msgid, strlen(msgid)));
    snprintf(paste, sizeof paste, "%s-sekret", msgid);
    assert_int_equal(want, key_exists(st.ml_paste, paste, strlen(paste)));
  }
  btl = bt_of(bt, sizeof bt, target, ts, msgid);
  assert_int_equal(want, key_exists(st.by_time, bt, (size_t)btl));
  n = htc_bo_key(bo, sizeof bo, owner, bt, (size_t)btl);
  assert_int_equal(want, key_exists(st.by_owner, bo, (size_t)n));
}

/* Rows past retention go with every index row; a row inside it stays
 * whole; the totals lose exactly the deleted rows' bytes. */
static void test_ageout_below_cutoff_only(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htc_rec ra, rb, rk;
  char ta[32], tb[32], tk[32];
  uint64_t total;
  (void)state;

  ageout_ready();
  ts_ago(ta, sizeof ta, 8, 0);
  ts_ago(tb, sizeof tb, 8, 0);
  ts_ago(tk, sizeof tk, 6, 0);
  seed_row("#a", ta, "A8", "a:ann", HTC_F_REDACT | HTC_F_ML, "P0", "P1", 40, &ra);
  seed_row("#b", tb, "B8", "a:bob", 0, "P2", "", 0, &rb);
  seed_row("#a", tk, "A6", "a:ann", 0, "", "", 0, &rk);
  seed_targets("#a", tk);
  seed_targets("#b", tb);
  total = htc_acct_total(htrim_acct());
  assert_int_equal((uint64_t)ra.bytes + rb.bytes + rk.bytes, total);

  /* Nothing runs before a pass starts. */
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(3, fake_db_rows(st.by_time));

  htrim_pass_start(&p);
  assert_int_equal(1, htrim_ageout_pending());
  run_until_idle(&p);
  assert_int_equal(0, htrim_ageout_pending());
  assert_int_equal(HTRIM_PH_AGEOUT, htrim_stats()->last_phase);

  assert_row_rows("#a", ta, "A8", "a:ann", HTC_F_REDACT | HTC_F_ML, "P0", "P1", 0);
  assert_row_rows("#b", tb, "B8", "a:bob", 0, "P2", "", 0);
  assert_row_rows("#a", tk, "A6", "a:ann", 0, "", "", 1);
  assert_int_equal(1, fake_db_rows(st.messages));
  assert_int_equal(2, fake_db_rows(st.msgid));
  assert_int_equal(0, fake_db_rows(st.reply));
  assert_int_equal(0, fake_db_rows(st.redact));
  assert_int_equal(0, fake_db_rows(st.ml_content));
  assert_int_equal(0, fake_db_rows(st.ml_paste));
  assert_int_equal(1, fake_db_rows(st.by_time));
  assert_int_equal(1, fake_db_rows(st.by_owner));

  assert_int_equal(2, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(total - ra.bytes - rb.bytes, htc_acct_total(htrim_acct()));
  assert_int_equal(rk.bytes, htc_acct_owner(htrim_acct(), "a:ann"));
  assert_int_equal(0, htc_acct_owner(htrim_acct(), "a:bob"));
  assert_acct_matches_cf();
  /* "#b" lost its only row; "#a" keeps its newer one. */
  assert_int_equal(1, emptied_calls);
  assert_int_equal(1, emptied_count);
  assert_string_equal("#b", emptied_names[0]);
  assert_true(targets_has("#a"));
  assert_false(targets_has("#b"));
  /* The first key the pass read: the oldest row. */
  assert_int_equal(htc_parse_ms(ta), htrim_stats()->oldest_seen_ms);

  /* A pass at retention 0 has no work. */
  p.retention_days = 0;
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_ageout_pending());
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(1, fake_db_rows(st.by_time));
}

/* The cutoff ms itself is kept (as the old purge kept it); one ms older
 * goes. */
static void test_ageout_keeps_cutoff_ms(void **state)
{
  struct htrim_params p = bf_params(0);
  uint64_t cutoff_ms = p.now_ms - 7ULL * 86400ULL * 1000ULL;
  char tcut[32], tolder[32];
  (void)state;

  ageout_ready();
  snprintf(tcut, sizeof tcut, "%llu.000", (unsigned long long)(cutoff_ms / 1000));
  snprintf(tolder, sizeof tolder, "%llu.999", (unsigned long long)(cutoff_ms / 1000 - 1));
  assert_int_equal(cutoff_ms, htc_parse_ms(tcut));
  assert_int_equal(cutoff_ms - 1, htc_parse_ms(tolder));
  seed_plain("#t", tcut, "CUT", "a:bob", NULL);
  seed_plain("#t", tolder, "OLD", "a:bob", NULL);

  ageout_pass(&p);
  assert_row_rows("#t", tcut, "CUT", "a:bob", 0, "", "", 1);
  assert_row_rows("#t", tolder, "OLD", "a:bob", 0, "", "", 0);
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
}

/* A budgeted slice deletes until its budget is spent; a slice stopped by
 * the budget reports work only when another entry exists. */
static void test_ageout_budget(void **state)
{
  struct htrim_params p = bf_params(5);
  char ts[32], mid[16];
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i < 30; i++) {
    snprintf(mid, sizeof mid, "R%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  /* A row inside retention: in by_time, past the walk's upper bound. */
  seed_plain("#t", ts_ago(ts, sizeof ts, 1, 0), "NEW", "a:bob", NULL);

  step_us = 1000;                      /* 1 ms per clock read; 5 ms slices */
  htrim_pass_start(&p);
  for (i = 1; i <= 5; i++) {
    assert_int_equal(1, htrim_run_slice(&p));
    assert_int_equal(HTRIM_PH_AGEOUT, htrim_stats()->last_phase);
    assert_int_equal((uint64_t)(5 * i), htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
    assert_int_equal(31 - 5 * i, fake_db_rows(st.by_time));
    assert_int_equal(1, htrim_ageout_pending());
  }
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(30, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(1, fake_db_rows(st.by_time));
  assert_int_equal(1, fake_db_rows(st.messages));
  assert_int_equal(0, htrim_ageout_pending());
  assert_int_equal(0, htrim_run_slice(&p));
  assert_acct_matches_cf();
}

/* A slice whose commit fails deletes nothing: every row survives whole
 * (no row loses only some of its index rows), the cursor stays, and the
 * next slices pick the same rows up again. */
static void test_ageout_failed_commit_is_whole_rows(void **state)
{
  struct htrim_params p = bf_params(3);
  char ts[10][32], mid[16], rp[16];
  uint64_t total_before;
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i < 10; i++) {
    snprintf(mid, sizeof mid, "W%d", i);
    snprintf(rp, sizeof rp, "P%d", i);
    seed_row("#t", ts_ago(ts[i], sizeof ts[i], 8, 100 - i), mid, "a:bob",
             HTC_F_REDACT | HTC_F_ML, rp, "Q", 30, NULL);
  }

  step_us = 1000;                      /* 1 ms per clock read; 3 ms slices */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(3, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  total_before = htc_acct_total(htrim_acct());

  fake_db_fail_next_commit(env);
  assert_int_equal(-1, htrim_run_slice(&p));
  assert_int_equal(3, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(total_before, htc_acct_total(htrim_acct()));
  assert_int_equal(1, htrim_ageout_pending());
  for (i = 0; i < 10; i++) {
    snprintf(mid, sizeof mid, "W%d", i);
    snprintf(rp, sizeof rp, "P%d", i);
    assert_row_rows("#t", ts[i], mid, "a:bob", HTC_F_REDACT | HTC_F_ML, rp, "Q", i >= 3);
  }
  assert_int_equal(7, fake_db_rows(st.by_time));

  run_until_idle(&p);
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_int_equal(0, fake_db_rows(st.msgid));
  assert_int_equal(0, fake_db_rows(st.reply));
  assert_int_equal(0, fake_db_rows(st.redact));
  assert_int_equal(0, fake_db_rows(st.ml_content));
  assert_int_equal(0, fake_db_rows(st.ml_paste));
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(0, fake_db_rows(st.by_owner));
  assert_int_equal(0, htc_acct_total(htrim_acct()));
}

/* Review Focus 5: a long single-target drain checks the target for
 * emptiness ONCE -- when the slice deleting its newest (stamped) row
 * commits -- never per slice (each such check walks every head tombstone
 * the drain has left so far). */
static void test_ageout_single_target_one_emptiness_check(void **state)
{
  struct htrim_params p = bf_params(10);
  char ts[32], newest[32], mid[16];
  int i, slices;
  (void)state;

  ageout_ready();
  for (i = 0; i < 1000; i++) {
    snprintf(mid, sizeof mid, "B%04d", i);
    seed_plain("#big", ts_ago(ts, sizeof ts, 8, 1000 - i), mid, "a:bob", NULL);
  }
  ts_ago(newest, sizeof newest, 8, 1);                   /* row 999 */
  seed_targets("#big", newest);
  assert_int_equal(0, fake_db_iter_opens(st.messages));

  step_us = 1000;                      /* 1 ms per clock read; 10 ms slices */
  htrim_pass_start(&p);
  slices = run_until_idle(&p);
  assert_true(slices >= 100);          /* a drain over many slices */
  assert_int_equal(1000, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, fake_db_rows(st.messages));

  assert_int_equal(1, fake_db_iter_opens(st.messages));
  assert_int_equal(1, fake_db_seek_lasts(st.messages));
  assert_int_equal(0, fake_db_seek_firsts(st.messages));
  assert_int_equal(1, emptied_calls);
  assert_int_equal(1, emptied_count);
  assert_string_equal("#big", emptied_names[0]);
  assert_false(targets_has("#big"));
}

/* A pass start reopens the walk from the first key: a row stored with a
 * time older than where the last pass (or the current one) stopped -- a
 * late CH W, a lagged relay -- goes at the next pass. */
static void test_ageout_pass_start_catches_late_row(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htrim_params pb = bf_params(3);
  char ts[32], mid[16];
  int i;
  (void)state;

  ageout_ready();
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 300), "O1", "a:bob", NULL);
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 200), "O2", "a:bob", NULL);
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100), "O3", "a:bob", NULL);
  ageout_pass(&p);
  assert_int_equal(3, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  /* After the pass: older than every key it deleted. */
  seed_plain("#u", ts_ago(ts, sizeof ts, 8, 500), "LATE", "a:bob", NULL);
  assert_int_equal(0, htrim_run_slice(&p));            /* no pass, no walk */
  assert_int_equal(1, fake_db_rows(st.by_time));
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(4, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  /* During a pass: the walk is past it; the next pass start goes back. */
  for (i = 0; i < 10; i++) {
    snprintf(mid, sizeof mid, "M%d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  step_us = 1000;                      /* 1 ms per clock read; 3 ms slices */
  htrim_pass_start(&pb);
  assert_int_equal(1, htrim_run_slice(&pb));
  assert_int_equal(7, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  seed_plain("#u", ts_ago(ts, sizeof ts, 8, 500), "LATE2", "a:bob", NULL);
  htrim_pass_start(&pb);
  assert_int_equal(1, htrim_run_slice(&pb));
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, key_exists(st.msgid, "LATE2", 5));
  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(15, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_acct_matches_cf();
}

/** Assert the most recent bounded by_time iterator opened at exactly
 * @a k (@a kl bytes; NULL = no lower bound). */
static void assert_bt_lower(const void *k, size_t kl)
{
  const void *lo;
  size_t ll;
  fake_db_last_iter_lower(st.by_time, &lo, &ll);
  if (!k) {
    assert_null(lo);
    return;
  }
  assert_non_null(lo);
  assert_int_equal(kl, ll);
  assert_memory_equal(k, lo, kl);
}

/* The bed (valgrind, 2026-11-04): a pass start that reopened the walk at
 * the first by_time key walked every tombstone the earlier passes left --
 * ~3000, 316-433 ms in one slice.  A pass start resumes where the last
 * walk stopped (rows behind it are gone), and goes back only as far as
 * the oldest row indexed behind it since -- a late store, or a backfill
 * after a retention rise. */
static void test_ageout_pass_start_resumes_past_drained_head(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], last[32], late[32], ahead[32], mid[16];
  char k[HTC_BT_KEY_MAX + 1];
  int i, kl;
  (void)state;

  ageout_ready();
  for (i = 0; i < 5; i++) {
    snprintf(mid, sizeof mid, "O%d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  ts_ago(last, sizeof last, 8, 96);                     /* O4, the last deleted */
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(NULL, 0);                             /* the first walk: from the first key */
  assert_int_equal(5, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  /* No row behind the walk: the next pass resumes past O4. */
  kl = bt_of(k, sizeof k - 1, "#t", last, "O4");
  k[kl++] = '\0';                                       /* O4's key ‖ 0x00 */
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(k, (size_t)kl);

  /* A row ahead of the walk (newer than O4, still past retention) is not
   * behind it: the pass still resumes past O4, and deletes it. */
  seed_plain("#u", ts_ago(ahead, sizeof ahead, 8, 50), "AHEAD", "a:bob", NULL);
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(k, (size_t)kl);
  assert_int_equal(6, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, fake_db_rows(st.by_time));

  /* Late stores behind the walk: the next pass starts AT the oldest. */
  seed_plain("#u", ts_ago(ts, sizeof ts, 9, 0), "LATE1", "a:bob", NULL);
  seed_plain("#u", ts_ago(late, sizeof late, 10, 0), "LATE0", "a:bob", NULL);
  seed_plain("#u", ts_ago(ts, sizeof ts, 8, 200), "LATE2", "a:bob", NULL);
  kl = bt_of(k, sizeof k, "#u", late, "LATE0");
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(k, (size_t)kl);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(9, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_acct_matches_cf();
}

/* A backfill that indexes a row behind the walk (retention went up, so a
 * row the walk had passed is inside it again, unindexed) sends the next
 * pass back to it once retention comes down again. */
static void test_ageout_backfill_row_behind_walk_is_late(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htrim_params p9 = bf_params(0);
  char ts[32], told[32];
  (void)state;

  ageout_ready();
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&p);                                      /* the walk is past 8 days */
  assert_int_equal(0, fake_db_rows(st.by_time));

  /* Retention 9: an older binary's row at 8.5 days is inside it, and the
   * backfill (re-run, as after a downgrade window) indexes it. */
  p9.retention_days = 9;
  htrim_check_index_gap(UINT64_MAX, 0);
  assert_int_equal(0, htrim_backfill_done());
  seed_legacy_row("#l", ts_ago(told, sizeof told, 8, 43200), "L1", "Bob", 0, "", "", 0);
  run_until_idle(&p9);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, fake_db_rows(st.by_time));

  /* Back to 7: the next pass goes back for it. */
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_int_equal(2, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_acct_matches_cf();
}

/* Task 5 review M2: an aged-out REDACT row takes its redact_index row,
 * whose key the store built from htc_parse_ms(the row's own ts) and the
 * delete rebuilds from the by_time key's ms -- also for a ts that is not
 * in the canonical <sec>.<3 digits> form.  A younger REDACT row keeps
 * its own. */
static void test_ageout_redact_takes_its_index_row(void **state)
{
  struct htrim_params p = bf_params(0);
  char t1[32], t2[32], t3[32];
  (void)state;

  ageout_ready();
  snprintf(t1, sizeof t1, "%llu.5", (unsigned long long)(BF_NOW_S - 8ULL * 86400ULL));
  ts_ago(t2, sizeof t2, 8, 1);
  ts_ago(t3, sizeof t3, 1, 0);
  seed_row("#t", t1, "RD1", "a:bob", HTC_F_REDACT, "", "P1", 0, NULL);
  seed_row("#t", t2, "RD2", "a:bob", HTC_F_REDACT, "", "P2", 0, NULL);
  seed_row("#t", t3, "RD3", "a:bob", HTC_F_REDACT, "", "P3", 0, NULL);
  assert_int_equal(3, fake_db_rows(st.redact));

  ageout_pass(&p);
  assert_row_rows("#t", t1, "RD1", "a:bob", HTC_F_REDACT, "", "P1", 0);
  assert_row_rows("#t", t2, "RD2", "a:bob", HTC_F_REDACT, "", "P2", 0);
  assert_row_rows("#t", t3, "RD3", "a:bob", HTC_F_REDACT, "", "P3", 1);
  assert_int_equal(1, fake_db_rows(st.redact));
  assert_int_equal(2, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(test_stage_index_writes_both, setup, teardown),
    cmocka_unit_test_setup_teardown(test_acct_scan_loads_totals, setup, teardown),
    cmocka_unit_test_setup_teardown(test_acct_scan_concurrent_store_and_delete, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delete_row_removes_every_index, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delete_noncanonical_ts, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delete_parent_keeps_newer_child, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delete_paste_by_value, setup, teardown),
    cmocka_unit_test_setup_teardown(test_commit_failure_keeps_everything, setup, teardown),
    cmocka_unit_test_setup_teardown(test_uncounted_delete, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_removes_empty_target, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_skips_when_newest_not_deleted, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_no_targets_entry, setup, teardown),
    cmocka_unit_test_setup_teardown(test_slice_budget, setup, teardown),
    cmocka_unit_test_setup_teardown(test_run_slice_scan_then_idle, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_seeks_tail_not_head, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_failure_wants_sweep, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delete_malformed_advances, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delete_poisoned_slice, setup, teardown),
    cmocka_unit_test_setup_teardown(test_run_slice_error_recorded, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_indexes_in_retention, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_ages_out_old_uncounted, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_skips_indexed, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_resumes_after_restart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_done_skips_next_boot, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_ml_counts_blob, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_parse_failure, setup, teardown),
    cmocka_unit_test_setup_teardown(test_index_gap_reruns_backfill, setup, teardown),
    cmocka_unit_test_setup_teardown(test_index_gap_resets_unfinished_walk, setup, teardown),
    cmocka_unit_test_setup_teardown(test_index_gap_reset_failure_reported, setup, teardown),
    cmocka_unit_test_setup_teardown(test_meta_read_error_means_not_done, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_logs_first_unindexable_keys, setup, teardown),
    cmocka_unit_test_setup_teardown(test_run_slice_rotation, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_below_cutoff_only, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_keeps_cutoff_ms, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_budget, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_failed_commit_is_whole_rows, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_single_target_one_emptiness_check, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_pass_start_catches_late_row, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_redact_takes_its_index_row, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_pass_start_resumes_past_drained_head, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_backfill_row_behind_walk_is_late, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
