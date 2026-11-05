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

/** A slow cleanup: the clock jumps this far inside the next emptied
 * callback (inside the commit's measured span), once. */
static uint64_t emptied_jump_us;

/** Every name the emptied callback was given, over the whole test. */
#define MAX_EMPTIED_ALL 128
static int  emptied_total;
static char emptied_all[MAX_EMPTIED_ALL][HTC_TARGET_MAX];

static void on_emptied(const char **targets, int count)
{
  int i;
  fake_us += emptied_jump_us;
  emptied_jump_us = 0;
  emptied_calls++;
  emptied_count = count;
  for (i = 0; i < count && i < MAX_EMPTIED; i++)
    snprintf(emptied_names[i], sizeof emptied_names[i], "%s", targets[i]);
  for (i = 0; i < count; i++, emptied_total++)
    if (emptied_total < MAX_EMPTIED_ALL)
      snprintf(emptied_all[emptied_total], sizeof emptied_all[0], "%s", targets[i]);
}

/** How many times the emptied callback named @a target so far. */
static int emptied_times(const char *target)
{
  int i, n = 0;
  for (i = 0; i < emptied_total && i < MAX_EMPTIED_ALL; i++)
    n += strcmp(emptied_all[i], target) == 0;
  return n;
}

/** The coverage callback (a commit moved or cleared the floor). */
static int coverage_calls;
static void on_coverage(void)
{
  coverage_calls++;
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
  emptied_jump_us = 0;
  memset(emptied_names, 0, sizeof emptied_names);
  emptied_total = 0;
  coverage_calls = 0;
  htrim_set_coverage_cb(on_coverage);
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
 * htrim_stage_index in the same batch, commit, and htrim_note_stored.
 * @a bytes 0 charges the row-size formula's figure; anything else
 * charges exactly that (the cap tests' fixed-size rows). */
static void seed_row_sized(const char *target, const char *ts, const char *msgid,
                           const char *owner, unsigned char flags,
                           const char *reply_parent, const char *redact_parent,
                           size_t ml_len, uint32_t bytes, struct htc_rec *rec_out)
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
  rec.bytes = bytes ? bytes
                    : htc_row_bytes((size_t)mkl, 80, (flags & HTC_F_ML) ? ml_len : 0,
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

static void seed_row(const char *target, const char *ts, const char *msgid,
                     const char *owner, unsigned char flags,
                     const char *reply_parent, const char *redact_parent,
                     size_t ml_len, struct htc_rec *rec_out)
{
  seed_row_sized(target, ts, msgid, owner, flags, reply_parent, redact_parent,
                 ml_len, 0, rec_out);
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

/** Finish the boot accounting scan (so stores/deletes apply directly),
 * and the targets sweep every start runs once it has (Task 8) -- over
 * the targets keys there are when this is called. */
static void load_acct(void)
{
  struct htrim_params p = params(0);
  int i;
  for (i = 0; i < 1000 && !htrim_acct_loaded(); i++)
    assert_true(htrim_run_slice(&p) >= 0);
  assert_int_equal(1, htrim_acct_loaded());
  for (i = 0; i < 1000 && htrim_tsweep_pending(); i++)
    assert_true(htrim_run_slice(&p) >= 0);
  assert_int_equal(0, htrim_tsweep_pending());
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
  assert_int_equal(1, htrim_run_slice(&p));        /* the start's targets sweep is due */
  assert_int_equal(1, htrim_acct_loaded());
  stats = htrim_stats();
  assert_int_equal(HTRIM_PH_ACCTSCAN, stats->last_phase);
  assert_int_equal(250, stats->last_slice_us);      /* begin -> end of cleanup */
  assert_int_equal(250, stats->max_slice_us);
  assert_int_equal(HTRIM_PH_ACCTSCAN, stats->max_phase);
  for (i = 0; i < HTRIM_PATH_COUNT; i++)
    assert_int_equal(0, stats->deleted[i]);
  htrim_reset_max_slice();
  assert_int_equal(0, htrim_stats()->max_slice_us);
  assert_int_equal(HTRIM_PH_NONE, htrim_stats()->max_phase);
  assert_int_equal(0, htrim_run_slice(&p));        /* the sweep (no targets), then idle */
  assert_int_equal(HTRIM_PH_TSWEEP, htrim_stats()->last_phase);
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
  assert_non_null(strstr(htrim_last_error(), "scan slice failed"));
  assert_int_equal(1, htrim_run_slice(&p));          /* the next one recovers; */
  assert_int_equal(1, htrim_acct_loaded());          /* the targets sweep is next */

  /* Every -1 says why, the early ones too. */
  htrim_shutdown();
  assert_int_equal(-1, htrim_run_slice(&p));
  assert_non_null(strstr(htrim_last_error(), "not started"));
  assert_int_equal(0, htrim_init(&st, parse_cb, fake_clock, on_emptied));
  assert_int_equal(-1, htrim_run_slice(NULL));
  assert_non_null(strstr(htrim_last_error(), "without parameters"));
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
 * the budget reports work only when another entry exists.  The first
 * slice knows no costs: five 1 ms rows.  It learns a commit cost of
 * 0.2 ms a row and a cleanup cost of 1 ms an examined entry (the one
 * target it touched), both charged ahead from then on: four rows a
 * slice (Task 8 fix round, M5). */
static void test_ageout_budget(void **state)
{
  static const int per_slice[] = { 5, 4, 4, 4, 4, 4, 4 };
  struct htrim_params p = bf_params(5);
  char ts[32], mid[16];
  int i, done = 0;
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
  for (i = 0; i < (int)(sizeof per_slice / sizeof per_slice[0]); i++) {
    done += per_slice[i];
    assert_int_equal(1, htrim_run_slice(&p));
    assert_int_equal(HTRIM_PH_AGEOUT, htrim_stats()->last_phase);
    assert_int_equal((uint64_t)done, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
    assert_int_equal(31 - done, fake_db_rows(st.by_time));
    assert_int_equal(1, htrim_ageout_pending());
  }
  assert_int_equal(0, htrim_run_slice(&p));            /* the last row */
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

/* A pass start goes back for a row stored with a time older than where
 * the last pass (or the current one) stopped -- a late CH W, a lagged
 * relay: it goes at the next pass. */
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

  /* During a pass: the walk is past it; the next pass start makes it due,
   * oldest first, ahead of the rows still due from before. */
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
  /* LATE2 by key first, then the next due row: the costs the first slice
   * learned (commit, and a cleanup entry per touched target) leave room
   * for one row more. */
  assert_int_equal(1, htrim_run_slice(&pb));
  assert_int_equal(9, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
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
 * ~3000, 316-433 ms in one slice -- and so did every pass that found no
 * row to delete.  A walk stopped by the budget resumes past the last key
 * it deleted; a walk that reached the cutoff resumes AT the cutoff bound
 * (everything below it is gone); a pass start goes back only as far as
 * the oldest row indexed behind that point since -- a late store, or a
 * backfill after a retention rise. */
static void test_ageout_pass_start_resumes_past_drained_head(void **state)
{
  struct htrim_params p = bf_params(3);
  char ts[32], last[32], late[32], ahead[32], mid[16];
  char k[HTC_BT_KEY_MAX + 1];
  unsigned char cut[8];
  int i, kl;
  (void)state;

  ageout_ready();
  for (i = 0; i < 5; i++) {
    snprintf(mid, sizeof mid, "O%d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  ts_ago(last, sizeof last, 8, 98);                     /* O2 */
  step_us = 1000;                      /* 1 ms per clock read; 3 ms slices */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));             /* O0..O2, stopped by the budget */
  assert_bt_lower(NULL, 0);                             /* the first walk: from the first key */
  assert_int_equal(3, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  /* The next slice resumes past O2 (O2's key ‖ 0x00). */
  kl = bt_of(k, sizeof k - 1, "#t", last, "O2");
  k[kl++] = '\0';
  assert_int_equal(0, htrim_run_slice(&p));             /* O3, O4, then the cutoff */
  assert_bt_lower(k, (size_t)kl);
  assert_int_equal(5, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  /* That walk reached the cutoff: the next pass resumes at its bound, and
   * so does every pass after one that found nothing. */
  htc_be64(cut, p.now_ms - 7ULL * 86400ULL * 1000ULL);
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(cut, sizeof cut);
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(cut, sizeof cut);
  assert_int_equal(0, htrim_stats()->oldest_seen_ms);   /* a walk that read nothing */

  /* A retention rise moves the cutoff back; the resume point does not
   * follow it backwards (the keys between are gone too). */
  p.retention_days = 8;
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  p.retention_days = 7;
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(cut, sizeof cut);

  /* An hour on, a row stored then (inside retention, so ahead of the walk)
   * has aged out: the pass resumes at the old bound and deletes it. */
  seed_plain("#u", ts_ago(ahead, sizeof ahead, 7, -1800), "AHEAD", "a:bob", NULL);
  p.now_ms += 3600ULL * 1000ULL;
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(cut, sizeof cut);
  assert_int_equal(6, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, fake_db_rows(st.by_time));

  /* Late stores behind the walk: the next pass deletes them by key and
   * resumes AT its frontier -- it never walks back over the deleted run
   * (Task 8 fix round: the late rows are kept exactly). */
  seed_plain("#u", ts_ago(ts, sizeof ts, 9, 0), "LATE1", "a:bob", NULL);
  seed_plain("#u", ts_ago(late, sizeof late, 10, 0), "LATE0", "a:bob", NULL);
  seed_plain("#u", ts_ago(ts, sizeof ts, 8, 200), "LATE2", "a:bob", NULL);
  htrim_pass_start(&p);
  step_us = 0;
  assert_int_equal(0, htrim_run_slice(&p));
  htc_be64(cut, p.now_ms - 7ULL * 86400ULL * 1000ULL);  /* the frontier, an hour on */
  assert_bt_lower(cut, sizeof cut);
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

/* ------------------------------------------------------------------ */
/* The slice's whole cost (Task 7 fix round)                           */
/* ------------------------------------------------------------------ */

/* The budget covers what a slice pays after staging too, in two parts
 * (Task 8 fix round, M5): the commit, per staged row, and the cleanup,
 * per entry it examines.  A slow cleanup (a 39 ms jump inside the
 * emptied callback: 40 ms for its 2 entries, #e and #big) teaches 20 ms
 * an entry, charged ahead for #big from the first row on: the next
 * slices stage one row each, until the EWMA (1/4) has eased as the
 * cleanups cost 1 ms again.  The slow slice's breakdown is on the max. */
static void test_slice_budget_learns_commit_cost(void **state)
{
  struct htrim_params p = bf_params(10);
  char ts[32], te[32], mid[16];
  uint64_t d;
  int i;
  (void)state;

  ageout_ready();
  seed_plain("#e", ts_ago(te, sizeof te, 8, 200), "E0", "a:bob", NULL);
  seed_targets("#e", te);                 /* emptied by the first slice */
  for (i = 0; i < 30; i++) {
    snprintf(mid, sizeof mid, "B%02d", i);
    seed_plain("#big", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }

  step_us = 1000;                      /* 1 ms per clock read; 10 ms slices */
  emptied_jump_us = 39000;
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);   /* cost 0 yet */
  assert_int_equal(1, emptied_calls);
  assert_true(htrim_stats()->last_slice_us >= 50000);   /* the cleanup is in the slice */
  assert_int_equal(htrim_stats()->last_slice_us, htrim_stats()->max_slice_us);
  assert_int_equal(11000, htrim_stats()->max_walk_us);     /* 10 rows + the start read */
  assert_int_equal(1000, htrim_stats()->max_commit_us);
  assert_int_equal(40000, htrim_stats()->max_cleanup_us);
  assert_int_equal(1, htrim_stats()->max_seeks);           /* #e's tail seek */

  /* 20 ms an entry ahead for #big: one row a slice ... */
  d = htrim_stats()->deleted[HTRIM_PATH_AGEOUT];
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_AGEOUT] - d);
  d = htrim_stats()->deleted[HTRIM_PATH_AGEOUT];
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_AGEOUT] - d);

  /* ... until the cleanup cost has eased: more rows a slice again. */
  for (i = 0; i < 10; i++) {
    d = htrim_stats()->deleted[HTRIM_PATH_AGEOUT];
    assert_int_equal(1, htrim_run_slice(&p));
    if (htrim_stats()->deleted[HTRIM_PATH_AGEOUT] - d >= 2)
      break;
  }
  assert_true(i < 10);

  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(31, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
}

/* However slow the last commit, a slice stages at least one row: the
 * walk always moves. */
static void test_slice_budget_at_least_one_row(void **state)
{
  struct htrim_params p = bf_params(10);
  char ts[32], te[32], mid[16];
  uint64_t d;
  int i;
  (void)state;

  ageout_ready();
  seed_plain("#e", ts_ago(te, sizeof te, 8, 200), "E0", "a:bob", NULL);
  seed_targets("#e", te);
  for (i = 0; i < 20; i++) {
    snprintf(mid, sizeof mid, "B%02d", i);
    seed_plain("#big", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }

  step_us = 1000;
  emptied_jump_us = 10000000ULL;       /* a 10 s commit */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  for (i = 0; i < 3; i++) {
    d = htrim_stats()->deleted[HTRIM_PATH_AGEOUT];
    assert_int_equal(1, htrim_run_slice(&p));
    assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_AGEOUT] - d);
  }
}

/** @a n targets "#c00".., one past-retention row each, stamped with it:
 * each one's delete empties it, and its check needs a seek. */
static void seed_emptiable_targets(int n)
{
  char ts[32], t[16], mid[16];
  int i;
  for (i = 0; i < n; i++) {
    snprintf(t, sizeof t, "#c%02d", i);
    snprintf(mid, sizeof mid, "C%02d", i);
    seed_plain(t, ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
    seed_targets(t, ts);
  }
}

/* A budgeted slice does at most 16 emptiness seeks; the rest of its
 * touched targets carry over, oldest first, and are checked by the next
 * slices -- a cleanup-only slice when no phase has work -- each once. */
static void test_cleanup_carries_past_16_checks(void **state)
{
  struct htrim_params p = bf_params(15);
  unsigned int lasts;
  (void)state;

  ageout_ready();
  seed_emptiable_targets(40);
  assert_int_equal(40, fake_db_rows(st.targets));
  lasts = fake_db_seek_lasts(st.messages);

  htrim_pass_start(&p);                /* step_us 0: one slice takes all 40 */
  assert_int_equal(1, htrim_run_slice(&p));        /* 24 checks still due */
  assert_int_equal(HTRIM_PH_AGEOUT, htrim_stats()->last_phase);
  assert_int_equal(40, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, htrim_ageout_pending());
  assert_int_equal(lasts + 16, fake_db_seek_lasts(st.messages));
  assert_int_equal(1, emptied_calls);
  assert_int_equal(16, emptied_count);
  assert_string_equal("#c00", emptied_names[0]);
  assert_string_equal("#c15", emptied_names[15]);
  assert_int_equal(24, fake_db_rows(st.targets));

  assert_int_equal(1, htrim_run_slice(&p));        /* a cleanup-only slice */
  assert_int_equal(HTRIM_PH_CLEANUP, htrim_stats()->last_phase);
  assert_int_equal(lasts + 32, fake_db_seek_lasts(st.messages));
  assert_int_equal(2, emptied_calls);
  assert_int_equal(16, emptied_count);
  assert_string_equal("#c16", emptied_names[0]);
  assert_string_equal("#c31", emptied_names[15]);

  assert_int_equal(0, htrim_run_slice(&p));        /* the last 8: idle after */
  assert_int_equal(lasts + 40, fake_db_seek_lasts(st.messages));
  assert_int_equal(3, emptied_calls);
  assert_int_equal(8, emptied_count);
  assert_string_equal("#c32", emptied_names[0]);
  assert_string_equal("#c39", emptied_names[7]);
  assert_int_equal(0, fake_db_rows(st.targets));
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(lasts + 40, fake_db_seek_lasts(st.messages));
}

/* Carried checks go before a later slice's own: no target waits behind
 * newer ones for ever (names sorting first do not jump the queue). */
static void test_cleanup_carry_goes_first(void **state)
{
  struct htrim_params p = bf_params(40);
  char ts[32], t[16], mid[16];
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i < 40; i++) {            /* oldest: the first slice's 40 rows */
    snprintf(t, sizeof t, "#m%02d", i);
    snprintf(mid, sizeof mid, "M%02d", i);
    seed_plain(t, ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
    seed_targets(t, ts);
  }
  for (i = 0; i < 20; i++) {            /* newer, and sorting before "#m" */
    snprintf(t, sizeof t, "#a%02d", i);
    snprintf(mid, sizeof mid, "A%02d", i);
    seed_plain(t, ts_ago(ts, sizeof ts, 8, 50 - i), mid, "a:bob", NULL);
    seed_targets(t, ts);
  }

  step_us = 1000;                      /* 40 rows a slice */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(40, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_string_equal("#m00", emptied_names[0]);   /* #m16..#m39 carried */

  assert_int_equal(1, htrim_run_slice(&p));        /* the 20 "#a" rows */
  assert_int_equal(60, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(16, emptied_count);
  assert_string_equal("#m16", emptied_names[0]);
  assert_string_equal("#m31", emptied_names[15]);

  assert_int_equal(1, htrim_run_slice(&p));        /* cleanup only */
  assert_int_equal(16, emptied_count);
  assert_string_equal("#m32", emptied_names[0]);
  assert_string_equal("#a00", emptied_names[8]);

  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(12, emptied_count);
  assert_string_equal("#a08", emptied_names[0]);
  assert_int_equal(0, fake_db_rows(st.targets));
}

/* A carried target touched again is checked once, with the newer of its
 * deleted times, and reported once. */
static void test_cleanup_carry_merges_a_retouched_target(void **state)
{
  struct htrim_params p = bf_params(21);
  char t1[32], t2[32];
  unsigned int lasts;
  int i, zz = 0;
  (void)state;

  ageout_ready();
  seed_emptiable_targets(20);
  /* "#zz": a row the stamp counts (t1) and a newer one it does not (t2,
   * as a JOIN) -- each delete of them needs a seek. */
  seed_plain("#zz", ts_ago(t1, sizeof t1, 8, 50), "Z1", "a:bob", NULL);
  seed_plain("#zz", ts_ago(t2, sizeof t2, 8, 40), "Z2", "a:bob", NULL);
  seed_targets("#zz", t1);
  lasts = fake_db_seek_lasts(st.messages);

  step_us = 1000;                      /* 21 rows in the first slice: all but Z2 */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(21, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(lasts + 16, fake_db_seek_lasts(st.messages));   /* #c16..#c19, #zz carried */
  assert_int_equal(16, emptied_count);

  assert_int_equal(0, htrim_run_slice(&p));        /* Z2, and the carried five */
  assert_int_equal(22, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(lasts + 21, fake_db_seek_lasts(st.messages));
  assert_int_equal(5, emptied_count);
  for (i = 0; i < emptied_count; i++)
    zz += strcmp(emptied_names[i], "#zz") == 0;
  assert_int_equal(1, zz);
  assert_int_equal(0, fake_db_rows(st.targets));
}

/* The carry is in memory only: a restart drops it, and those targets'
 * keys stay until the targets sweep every start runs once the accounting
 * scan has loaded (Task 8 amendment) finds them empty. */
static void test_cleanup_carry_dropped_on_restart(void **state)
{
  struct htrim_params p = bf_params(15);
  (void)state;

  ageout_ready();
  seed_emptiable_targets(20);
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(16, emptied_count);
  assert_int_equal(4, fake_db_rows(st.targets));

  reboot();
  assert_int_equal(1, htrim_tsweep_pending());
  assert_int_equal(1, htrim_run_slice(&p));        /* the scan comes first */
  assert_int_equal(HTRIM_PH_ACCTSCAN, htrim_stats()->last_phase);
  assert_int_equal(1, htrim_acct_loaded());
  assert_int_equal(4, fake_db_rows(st.targets));
  run_until_idle(&p);                  /* then the sweep, once */
  assert_int_equal(HTRIM_PH_TSWEEP, htrim_stats()->last_phase);
  assert_int_equal(2, emptied_calls);
  assert_int_equal(4, emptied_count);
  assert_string_equal("#c16", emptied_names[0]);
  assert_string_equal("#c19", emptied_names[3]);
  assert_int_equal(0, fake_db_rows(st.targets));
  assert_int_equal(0, htrim_tsweep_pending());
  assert_int_equal(0, htrim_run_slice(&p));
}

/* A caller's own slice that names its phase is recorded like the
 * engine's (the burst-loss prune: last and max slice); one without a
 * phase is not. */
static void test_caller_slice_recorded_with_phase(void **state)
{
  struct htrim_slice *s;
  (void)state;

  seed_plain("#t", "100.000", "M1", "a:bob", NULL);
  seed_plain("#t", "200.000", "M2", "a:bob", NULL);

  step_us = 700;
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "100.000", "M1", 1);
  assert_int_equal(1, htrim_slice_commit(s));
  assert_int_equal(HTRIM_PH_NONE, htrim_stats()->last_phase);
  assert_int_equal(0, htrim_stats()->max_slice_us);

  s = htrim_slice_begin(0);
  assert_non_null(s);
  htrim_slice_set_phase(s, HTRIM_PH_INCARNATION);
  stage_del(s, HTRIM_PATH_INCARNATION, "#t", "200.000", "M2", 1);
  assert_int_equal(1, htrim_slice_commit(s));
  assert_int_equal(HTRIM_PH_INCARNATION, htrim_stats()->last_phase);
  assert_int_equal(700, htrim_stats()->last_slice_us);   /* unbudgeted: begin + commit */
  assert_int_equal(700, htrim_stats()->max_slice_us);
  assert_int_equal(HTRIM_PH_INCARNATION, htrim_stats()->max_phase);
  assert_string_equal("incarnation", htrim_phase_name(HTRIM_PH_INCARNATION));
  assert_string_equal("cleanup", htrim_phase_name(HTRIM_PH_CLEANUP));
}

/* ------------------------------------------------------------------ */
/* The cap (Task 8)                                                    */
/* ------------------------------------------------------------------ */

/** The cap tests' limits: cap 10000, high 85 (8500), low 75 (7500), the
 * share step on at 10% (1000); no retention (no age-out), no hints. */
static struct htrim_params ev_params(unsigned int slice_ms)
{
  struct htrim_params p = params(slice_ms);
  p.now_ms = BF_NOW_S * 1000ULL;
  p.retention_days = 0;
  p.cap_bytes = 10000;
  p.high_pct = 85;
  p.low_pct = 75;
  p.quota_on = 1;
  p.share_pct = 10;
  return p;
}

/** A row of exactly @a bytes for @a owner at @a secs (whole seconds). */
static void seed_sized(const char *target, uint64_t secs, const char *msgid,
                       const char *owner, uint32_t bytes)
{
  char ts[32];
  snprintf(ts, sizeof ts, "%llu.000", (unsigned long long)secs);
  seed_row_sized(target, ts, msgid, owner, 0, "", "", 0, bytes, NULL);
}

/** @a n rows of @a bytes for @a owner in @a target, msgids <pfx>00..,
 * at @a secs0 + i seconds. */
static void seed_run(const char *target, const char *pfx, const char *owner,
                     int n, uint64_t secs0, uint32_t bytes)
{
  char mid[24];
  int i;
  for (i = 0; i < n; i++) {
    snprintf(mid, sizeof mid, "%s%02d", pfx, i);
    seed_sized(target, secs0 + (uint64_t)i, mid, owner, bytes);
  }
}

/** Whether the row seed_sized wrote is there: its messages row and its
 * by_time row agree. */
static int row_present(const char *target, uint64_t secs, const char *msgid)
{
  char ts[32], mk[HTC_MSG_KEY_MAX], bt[HTC_BT_KEY_MAX];
  int n, btl, in_bt;
  snprintf(ts, sizeof ts, "%llu.000", (unsigned long long)secs);
  n = htc_msg_key(mk, sizeof mk, target, ts, msgid);
  btl = bt_of(bt, sizeof bt, target, ts, msgid);
  in_bt = key_exists(st.by_time, bt, (size_t)btl);
  assert_int_equal(in_bt, key_exists(st.messages, mk, (size_t)n));
  return in_bt;
}

static uint64_t owner_of(const char *owner)
{
  return htc_acct_owner(htrim_acct(), owner);
}

static uint64_t total_now(void)
{
  return htc_acct_total(htrim_acct());
}

/** The cap tests' start: the backfill finished, the accounting loaded,
 * the boot sweep done. */
static void evict_ready(void)
{
  ageout_ready();
}

/* Review Focus (plan note 4): eviction waits for the backfill -- until
 * every pre-existing row is indexed, by_time lacks the oldest rows and
 * the owner totals are partial.  Over high the whole time, nothing is
 * evicted while the backfill still walks; then the cap applies. */
static void test_evict_waits_for_backfill(void **state)
{
  struct htrim_params p = ev_params(5);
  int slices = 0;
  (void)state;

  load_acct_backfill_pending();
  seed_run("#n", "N", "-", 90, 1000, 100);
  assert_int_equal(9000, total_now());

  step_us = 1000;                      /* ~5 backfill rows a 5 ms slice */
  while (!htrim_backfill_done()) {
    assert_true(htrim_run_slice(&p) >= 0);
    assert_int_not_equal(HTRIM_PH_EVICT, htrim_stats()->last_phase);
    assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
    assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
    assert_int_equal(0, htrim_draining());
    assert_true(++slices < 1000);
  }
  assert_true(slices > 5);
  assert_int_equal(9000, total_now());

  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(7500, total_now());
  assert_int_equal(15, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
}

/* Anti-goal 1: an owner over its share loses its own oldest rows -- down
 * to its share -- and nobody else loses anything.  The dash owner holds
 * most of the store but is never share-trimmed. */
static void test_evict_owner_share_first(void **state)
{
  struct htrim_params p = ev_params(0);
  char mid[16];
  int i;
  (void)state;

  evict_ready();
  seed_run("#n", "N", "-", 52, 1000, 100);            /* the oldest rows */
  seed_run("#q", "Q", "a:quiet", 5, 1500, 100);
  seed_run("#f", "F", "a:flood", 30, 2000, 100);
  assert_int_equal(8700, total_now());

  run_until_idle(&p);
  assert_true(owner_of("a:flood") <= 1000);
  assert_true(owner_of("a:flood") > 900);
  for (i = 0; i < 30; i++) {
    snprintf(mid, sizeof mid, "F%02d", i);
    assert_int_equal(i >= 20, row_present("#f", 2000 + (uint64_t)i, mid));
  }
  assert_int_equal(500, owner_of("a:quiet"));
  assert_int_equal(5200, owner_of("-"));
  assert_int_equal(6700, total_now());
  assert_int_equal(20, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(0, htrim_coverage_floor_ms());
  assert_int_equal(-1, meta_is(HTRIM_META_FLOOR, ""));
  assert_int_equal(0, coverage_calls);
  assert_int_equal(0, htrim_draining());
  assert_acct_matches_cf();
}

/* Nobody over share: the oldest rows go, whoever owns them, until the
 * store is at the low watermark; the coverage floor follows them. */
static void test_evict_oldest_after_shares(void **state)
{
  struct htrim_params p = ev_params(0);
  char mid[16], want[32];
  int i;
  (void)state;

  evict_ready();
  for (i = 0; i < 86; i++) {
    int q = i == 2 || i == 5 || i == 8 || i == 40 || i == 60;
    snprintf(mid, sizeof mid, "R%02d", i);
    seed_sized(i & 1 ? "#a" : "#b", 1000 + (uint64_t)i, mid, q ? "a:q" : "-", 100);
  }
  assert_int_equal(500, owner_of("a:q"));
  assert_int_equal(8600, total_now());

  run_until_idle(&p);
  for (i = 0; i < 86; i++) {
    snprintf(mid, sizeof mid, "R%02d", i);
    assert_int_equal(i >= 11, row_present(i & 1 ? "#a" : "#b", 1000 + (uint64_t)i, mid));
  }
  assert_int_equal(200, owner_of("a:q"));
  assert_int_equal(7500, total_now());
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  snprintf(want, sizeof want, "%llu", (unsigned long long)htc_parse_ms("1010.000"));
  assert_int_equal(1, meta_is(HTRIM_META_FLOOR, want));
  assert_int_equal(htc_parse_ms("1010.000"), htrim_coverage_floor_ms());
  assert_int_equal(1, coverage_calls);
  assert_acct_matches_cf();
}

/* Hysteresis: a drain starts strictly above high and goes on below it,
 * slice after slice, until the store is at or below low; then a store
 * that leaves it under high starts nothing. */
static void test_evict_hysteresis(void **state)
{
  struct htrim_params p = ev_params(3);
  int i, rc, between = 0;
  (void)state;

  evict_ready();
  seed_run("#t", "H", "-", 85, 1000, 100);             /* 8500: not above high */
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(0, htrim_draining());
  assert_int_equal(85, fake_db_rows(st.by_time));

  seed_run("#t", "J", "-", 1, 2000, 100);              /* 8600 */
  step_us = 1000;                      /* ~3 rows a 3 ms slice */
  for (i = 0; i < 100; i++) {
    rc = htrim_run_slice(&p);
    assert_int_equal(HTRIM_PH_EVICT, htrim_stats()->last_phase);
    if (total_now() <= 7500)
      break;
    assert_int_equal(1, rc);
    assert_int_equal(1, htrim_draining());
    if (total_now() <= 8500)
      between = 1;
  }
  assert_true(between);
  assert_true(i >= 2);
  assert_int_equal(7500, total_now());
  assert_int_equal(0, htrim_draining());

  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(7500, total_now());
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);

  seed_run("#t", "K", "-", 10, 3000, 100);             /* 8500 again */
  run_until_idle(&p);
  assert_int_equal(8500, total_now());
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
}

/* Review Focus 4: more owners over their share than a plan can list (40
 * at a 1% share, 32 steps) never falls through to oldest-overall -- the
 * compliant a:quiet holds the oldest row of the store and keeps it after
 * every slice.  Each owner the drain picks goes down to its share, in the
 * plan's order (largest over first, ties by owner), a step started in one
 * slice finishing in the next; no new step starts once the store is at
 * the low watermark (12090 - 23 x 200 = 7490). */
static void test_evict_truncated_plan_spares_compliant_owner(void **state)
{
  struct htrim_params p = ev_params(5);
  char owner[16], mid[16];
  int o, r, i, rc = 1, k;
  (void)state;

  p.share_pct = 1;                     /* share 100 */
  evict_ready();
  seed_sized("#q", 500, "QUIET", "a:quiet", 90);
  for (o = 0; o < 40; o++) {
    snprintf(owner, sizeof owner, "a:o%02d", o);
    for (r = 0; r < 3; r++) {
      snprintf(mid, sizeof mid, "O%02d_%d", o, r);
      seed_sized("#o", 1000 + (uint64_t)(r * 100 + o), mid, owner, 100);
    }
  }
  assert_int_equal(12090, total_now());

  step_us = 1000;                      /* a few rows a 5 ms slice */
  for (i = 0; i < 1000 && rc == 1; i++) {
    rc = htrim_run_slice(&p);
    assert_true(rc >= 0);
    assert_int_equal(90, owner_of("a:quiet"));
    assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  }
  assert_int_equal(0, rc);
  assert_true(i > 5);                  /* the drain took many slices */
  assert_true(total_now() <= 7500);
  for (k = 0; k < 40; k++) {
    snprintf(owner, sizeof owner, "a:o%02d", k);
    if (owner_of(owner) != 100)
      break;
  }
  for (o = k; o < 40; o++) {
    snprintf(owner, sizeof owner, "a:o%02d", o);
    assert_int_equal(300, owner_of(owner));
  }
  assert_int_equal(23, k);
  assert_int_equal(7490, total_now());
  assert_int_equal(46, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  assert_true(row_present("#q", 500, "QUIET"));
  assert_acct_matches_cf();
}

/* A by_owner entry whose by_time row is gone is removed by the owner
 * walk on its own, its size off its owner's total -- it is not a row, so
 * the per-path counter does not count it. */
static void test_evict_orphan_owner_entry(void **state)
{
  struct htrim_params p = ev_params(0);
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16];
  unsigned char sz[4];
  struct db_writebatch *wb;
  int btl, bol, i;
  (void)state;

  seed_backfill_done();
  seed_run("#f", "F", "a:flood", 29, 2000, 100);
  seed_run("#n", "N", "-", 56, 1000, 100);
  btl = htc_bt_key(bt, sizeof bt, 1500000, "#f", "GONE");   /* older than a:flood's rows */
  bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
  assert_true(btl > 0 && bol > 0);
  htc_size_pack(sz, 100);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, sizeof sz));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  reboot();
  load_acct();                         /* the scan counts the orphan */
  assert_int_equal(3000, owner_of("a:flood"));
  assert_int_equal(8600, total_now());

  run_until_idle(&p);
  assert_false(key_exists(st.by_owner, bo, (size_t)bol));
  assert_int_equal(1000, owner_of("a:flood"));
  assert_int_equal(19, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  for (i = 0; i < 29; i++) {
    snprintf(mid, sizeof mid, "F%02d", i);
    assert_int_equal(i >= 19, row_present("#f", 2000 + (uint64_t)i, mid));
  }
  assert_acct_matches_cf();
}

/** Assert the last compaction hint on @a cf covered exactly
 * [@a lo, @a hi ‖ 0x00). */
static void assert_hint(struct db_cf *cf, const void *lo, size_t lol,
                        const void *hi, size_t hil)
{
  const void *s, *e;
  size_t sl, el;
  assert_int_equal(DB_OK, fake_db_last_suggest(cf, &s, &sl, &e, &el));
  assert_int_equal(lol, sl);
  assert_memory_equal(lo, s, lol);
  assert_int_equal(hil + 1, el);
  assert_memory_equal(hi, e, hil);
  assert_int_equal(0, ((const char *)e)[hil]);
}

/* A drain ends with one compaction hint per column family it deleted
 * from, over [first deleted key, last deleted key ‖ 0x00); the cumulative
 * trigger hints a CF once compact_min_rows keys have gone since its last
 * hint, whatever deleted them. */
static void test_drain_suggests_compaction(void **state)
{
  struct htrim_params p = ev_params(0);
  char lo[HTC_BT_KEY_MAX], hi[HTC_BT_KEY_MAX], ts[32], mid[16];
  uint64_t base = BF_NOW_S - 86400;    /* a day old: inside retention below */
  int lol, hil, i;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_run("#t", "R", "-", 86, base, 100);
  assert_int_equal(0, fake_db_suggest_calls(st.by_time));

  /* The drain ends with four hints due, issued one a slice (a flush
   * switches the memtable on this thread): the slice that ended the
   * drain issues the first, three cleanup-only slices the rest. */
  for (i = 0; i < 100 && htrim_run_slice(&p) == 1; i++)
    if (htrim_stats()->deleted[HTRIM_PATH_OLDEST] == 11)
      break;
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(1, fake_db_suggest_calls(st.messages)
                      + fake_db_suggest_calls(st.msgid)
                      + fake_db_suggest_calls(st.by_time)
                      + fake_db_suggest_calls(st.by_owner));
  assert_true(htrim_stats()->max_hint_us == 0);           /* step_us 0 */
  run_until_idle(&p);
  assert_int_equal(HTRIM_PH_CLEANUP, htrim_stats()->last_phase);
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));
  snprintf(ts, sizeof ts, "%llu.000", (unsigned long long)base);
  lol = bt_of(lo, sizeof lo, "#t", ts, "R00");
  snprintf(ts, sizeof ts, "%llu.000", (unsigned long long)(base + 10));
  hil = bt_of(hi, sizeof hi, "#t", ts, "R10");
  assert_hint(st.by_time, lo, (size_t)lol, hi, (size_t)hil);
  assert_int_equal(1, fake_db_suggest_calls(st.messages));
  assert_int_equal(1, fake_db_suggest_calls(st.msgid));
  assert_int_equal(1, fake_db_suggest_calls(st.by_owner));
  assert_int_equal(0, fake_db_suggest_calls(st.reply));   /* nothing deleted there */

  /* compact_min_rows 10: an age-out pass of 12 rows hints once more. */
  p.cap_bytes = 0;
  p.retention_days = 7;
  p.compact_min_rows = 10;
  for (i = 0; i < 12; i++) {
    snprintf(mid, sizeof mid, "A%02d", i);
    seed_plain("#old", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&p);
  assert_int_equal(12, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(2, fake_db_suggest_calls(st.by_time));
  lol = bt_of(lo, sizeof lo, "#old", ts_ago(ts, sizeof ts, 8, 100), "A00");
  hil = bt_of(hi, sizeof hi, "#old", ts_ago(ts, sizeof ts, 8, 89), "A11");
  assert_hint(st.by_time, lo, (size_t)lol, hi, (size_t)hil);
}

/* Task 7 review I3: a steady pass deletes far fewer rows than any
 * one-pass trigger, so the hint counts deletes since a CF's last hint,
 * across passes: 4 + 4 rows hint nothing, the third pass reaches 10 and
 * the hint covers all 12; four more start the count again.  Only the
 * time-ordered CFs (by_time, msgid_index, ml_content) are hinted so;
 * each hint flushes the CF's memtable first (fix round, M1 / I4). */
static void test_compaction_hint_cumulative(void **state)
{
  struct htrim_params p = bf_params(0);
  char lo[HTC_BT_KEY_MAX], hi[HTC_BT_KEY_MAX], ts[32], mid[16];
  int pass, i, lol, hil;
  (void)state;

  p.compact_min_rows = 10;
  ageout_ready();
  for (pass = 0; pass < 4; pass++) {
    for (i = 0; i < 4; i++) {
      snprintf(mid, sizeof mid, "P%d_%d", pass, i);
      seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - pass * 10 - i), mid, "a:bob", NULL);
    }
    ageout_pass(&p);
    assert_int_equal((uint64_t)(4 * (pass + 1)), htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
    assert_int_equal(pass >= 2 ? 1 : 0, fake_db_suggest_calls(st.by_time));
    assert_int_equal(fake_db_suggest_calls(st.by_time), fake_db_flush_calls(st.by_time));
    /* msgid_index loses 2 keys a row (both forms): 16 >= 10 at pass 1. */
    assert_int_equal(pass >= 3 ? 2 : pass >= 1 ? 1 : 0, fake_db_suggest_calls(st.msgid));
    /* The prefix-keyed CFs are not hinted cumulatively (M1). */
    assert_int_equal(0, fake_db_suggest_calls(st.messages));
    assert_int_equal(0, fake_db_suggest_calls(st.by_owner));
  }
  lol = bt_of(lo, sizeof lo, "#t", ts_ago(ts, sizeof ts, 8, 100), "P0_0");
  hil = bt_of(hi, sizeof hi, "#t", ts_ago(ts, sizeof ts, 8, 77), "P2_3");
  assert_hint(st.by_time, lo, (size_t)lol, hi, (size_t)hil);
}

/* The coverage floor goes once retention covers it: a pass start whose
 * cutoff is past the floor deletes its meta row and tells the coverage
 * callback; a cutoff at or before it, or no retention, keeps it. */
static void test_floor_cleared_when_aged_past(void **state)
{
  struct htrim_params p = bf_params(0);
  uint64_t f = (BF_NOW_S - 6ULL * 86400ULL) * 1000ULL;
  char fs[32];
  (void)state;

  snprintf(fs, sizeof fs, "%llu", (unsigned long long)f);
  put_meta(HTRIM_META_FLOOR, fs);
  reboot();
  load_acct();
  assert_int_equal(f, htrim_coverage_floor_ms());

  htrim_pass_start(&p);                /* cutoff 7 days ago: before the floor */
  assert_int_equal(f, htrim_coverage_floor_ms());
  assert_int_equal(1, meta_is(HTRIM_META_FLOOR, fs));
  p.retention_days = 0;
  p.now_ms += 3ULL * 86400ULL * 1000ULL;
  htrim_pass_start(&p);                /* no retention: nothing covers it */
  assert_int_equal(f, htrim_coverage_floor_ms());
  p.retention_days = 7;
  p.now_ms = f + 7ULL * 86400ULL * 1000ULL;   /* cutoff == floor: kept */
  htrim_pass_start(&p);
  assert_int_equal(f, htrim_coverage_floor_ms());
  assert_int_equal(0, coverage_calls);

  p.now_ms += 1;                       /* cutoff one ms past the floor */
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_coverage_floor_ms());
  assert_int_equal(-1, meta_is(HTRIM_META_FLOOR, fs));
  assert_int_equal(1, coverage_calls);
  reboot();
  assert_int_equal(0, htrim_coverage_floor_ms());
}

/* Cap 0 is no cap: whatever the total, eviction has no work and an
 * otherwise idle engine stays idle; a drain under way when the cap goes
 * to 0 stops. */
static void test_evict_cap_zero_idle(void **state)
{
  struct htrim_params p = ev_params(3);
  uint64_t d;
  int i;
  (void)state;

  p.cap_bytes = 0;
  evict_ready();
  seed_run("#t", "Z", "-", 90, 1000, 100);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(0, htrim_draining());
  for (i = 0; i < HTRIM_PATH_COUNT; i++)
    assert_int_equal(0, htrim_stats()->deleted[i]);

  p.cap_bytes = 10000;                 /* 9000 > 8500 */
  step_us = 1000;
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(1, htrim_draining());
  d = htrim_stats()->deleted[HTRIM_PATH_OLDEST];
  assert_true(d > 0 && d < 15);
  p.cap_bytes = 0;
  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(0, htrim_draining());
  assert_int_equal(d, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(0, htrim_run_slice(&p));
}

/* Task 4 review ruling: the cleanup's stamp shortcut is exact for
 * oldest-first age-out, not for eviction.  An owner trim deletes #t's
 * newest (stamped) row while an older row of another owner stays; then
 * oldest-overall deletes that one, which the stamp says is not the
 * newest -- #t is empty, its targets key left.  The sweep after the drain
 * removes it and reports it once; a live target keeps its key. */
static void test_tsweep_removes_target_emptied_out_of_order(void **state)
{
  struct htrim_params p = ev_params(0);
  int i;
  (void)state;

  evict_ready();
  seed_sized("#t", 100, "TOLD", "-", 100);              /* the oldest row */
  seed_sized("#t", 500, "TNEW", "a:flood", 100);        /* a:flood's oldest */
  seed_targets("#t", "500.000");
  seed_run("#f", "F", "a:flood", 19, 600, 100);
  seed_run("#n", "N", "-", 70, 1000, 100);
  seed_targets("#n", "1069.000");
  assert_int_equal(9100, total_now());

  for (i = 0; i < 100; i++) {
    assert_true(htrim_run_slice(&p) >= 0);
    if (!htrim_draining())
      break;
  }
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  assert_int_equal(6, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_false(row_present("#t", 100, "TOLD"));
  assert_false(row_present("#t", 500, "TNEW"));
  assert_true(targets_has("#t"));       /* the shortcut's leftover */
  assert_int_equal(0, emptied_times("#t"));
  assert_int_equal(1, htrim_tsweep_pending());

  run_until_idle(&p);                  /* the sweep, then one hint a slice */
  assert_false(targets_has("#t"));
  assert_int_equal(1, emptied_times("#t"));
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));
  assert_int_equal(1, fake_db_suggest_calls(st.by_owner));
  assert_true(targets_has("#n"));
  assert_int_equal(0, emptied_times("#n"));
  assert_int_equal(0, htrim_tsweep_pending());
  assert_string_equal("tsweep", htrim_phase_name(HTRIM_PH_TSWEEP));
}

/* A cleanup that could not finish arms the sweep, which then reaps the
 * target it left. */
static void test_tsweep_after_failed_cleanup(void **state)
{
  struct htrim_slice *s;
  struct htrim_params p = params(0);
  (void)state;

  load_acct();
  seed_plain("#t", "100.000", "T1", "a:bob", NULL);
  seed_plain("#t", "200.000", "T2", "a:bob", NULL);
  seed_targets("#t", "200.000");
  fake_db_fail_commit_at(env, 2);      /* the cleanup's own batch */
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "100.000", "T1", 1);
  stage_del(s, HTRIM_PATH_AGEOUT, "#t", "200.000", "T2", 1);
  assert_int_equal(2, htrim_slice_commit(s));
  assert_true(targets_has("#t"));
  assert_int_equal(1, htrim_tsweep_wanted());
  assert_int_equal(1, htrim_tsweep_pending());

  run_until_idle(&p);
  assert_false(targets_has("#t"));
  assert_int_equal(1, emptied_times("#t"));
  assert_int_equal(0, htrim_tsweep_wanted());
  assert_int_equal(0, htrim_tsweep_pending());
}

/* Task 7 re-review M1: an unbudgeted slice (the burst-loss prune, inside
 * BURST) checks its own touched targets only; the carried checks stay
 * with the engine's budgeted slices. */
static void test_cleanup_unbudgeted_slice_keeps_the_carry(void **state)
{
  struct htrim_params p = bf_params(15);
  unsigned int lasts;
  (void)state;

  ageout_ready();
  seed_emptiable_targets(56);
  htrim_pass_start(&p);                /* step_us 0: one slice takes all 56 */
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(56, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(40, fake_db_rows(st.targets));   /* 40 carried */

  seed_plain("#u0", "100.000", "U0", "a:bob", NULL);
  seed_targets("#u0", "100.000");
  seed_plain("#u1", "100.000", "U1", "a:bob", NULL);
  seed_targets("#u1", "100.000");
  lasts = fake_db_seek_lasts(st.messages);
  {
    struct htrim_slice *s = htrim_slice_begin(0);
    assert_non_null(s);
    htrim_slice_set_phase(s, HTRIM_PH_INCARNATION);
    stage_del(s, HTRIM_PATH_INCARNATION, "#u0", "100.000", "U0", 1);
    stage_del(s, HTRIM_PATH_INCARNATION, "#u1", "100.000", "U1", 1);
    assert_int_equal(2, htrim_slice_commit(s));
  }
  assert_int_equal(lasts + 2, fake_db_seek_lasts(st.messages));
  assert_int_equal(2, emptied_count);
  assert_string_equal("#u0", emptied_names[0]);
  assert_string_equal("#u1", emptied_names[1]);
  assert_int_equal(40, fake_db_rows(st.targets));   /* still carried */

  run_until_idle(&p);                  /* 16 + 16 + 8 */
  assert_int_equal(lasts + 42, fake_db_seek_lasts(st.messages));
  assert_int_equal(0, fake_db_rows(st.targets));
}

/** Assert meta row @a key holds exactly @a v (@a vl bytes). */
static void assert_meta_bytes(const char *key, const void *v, size_t vl)
{
  struct db_val got = { NULL, 0 };
  assert_int_equal(DB_OK, db_get(env, st.meta, key, strlen(key), NULL, &got));
  assert_int_equal(vl, got.len);
  assert_memory_equal(v, got.base, vl);
  db_val_free(&got);
}

/* Task 7 fix round 2 F6: the resume point is persisted with each
 * committed age-out slice, so the first walk after a restart starts there
 * -- not at the first key, whose seek walks every tombstone the earlier
 * passes left (791 ms on the bed, nothing to delete). */
static void test_ageout_resume_persisted_across_restart(void **state)
{
  struct htrim_params p = bf_params(3);
  char ts[32], last[32], mid[16];
  char k[HTC_BT_KEY_MAX + 1];
  unsigned char cut[8];
  int i, kl;
  (void)state;

  ageout_ready();
  for (i = 0; i < 5; i++) {
    snprintf(mid, sizeof mid, "O%d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  step_us = 1000;                      /* 3 rows a 3 ms slice */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(3, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  kl = bt_of(k, sizeof k - 1, "#t", ts_ago(last, sizeof last, 8, 98), "O2");
  k[kl++] = '\0';
  assert_meta_bytes(HTRIM_META_AGEOUT_RESUME, k, (size_t)kl);

  reboot();
  step_us = 0;
  load_acct();
  step_us = 1000;
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(k, (size_t)kl);
  assert_int_equal(2, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  htc_be64(cut, p.now_ms - 7ULL * 86400ULL * 1000ULL);
  assert_meta_bytes(HTRIM_META_AGEOUT_RESUME, cut, sizeof cut);

  reboot();
  step_us = 0;
  load_acct();
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(cut, sizeof cut);
  assert_int_equal(0, fake_db_rows(st.by_time));
}

/* The persisted resume point never skips a row: a row indexed behind it
 * (a late store, a backfill after a retention rise) moves it back in the
 * same batch, so a restart before the next pass -- which drops the
 * in-memory note of the late row -- still walks it. */
static void test_ageout_late_row_survives_restart(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htrim_params p9 = bf_params(0);
  char ts[32], told[32];
  char k[HTC_BT_KEY_MAX];
  int kl;
  (void)state;

  ageout_ready();
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));

  /* A late store behind the walk; then a restart. */
  seed_plain("#u", ts_ago(ts, sizeof ts, 10, 0), "LATE", "a:bob", NULL);
  kl = bt_of(k, sizeof k, "#u", ts, "LATE");
  assert_meta_bytes(HTRIM_META_AGEOUT_RESUME, k, (size_t)kl);
  reboot();
  load_acct();
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  /* A backfill row behind the walk (retention 9, as after a downgrade
   * window); then a restart before retention 7's next pass. */
  p9.retention_days = 9;
  htrim_check_index_gap(UINT64_MAX, 0);
  seed_legacy_row("#l", ts_ago(told, sizeof told, 8, 43200), "L1", "Bob", 0, "", "", 0);
  run_until_idle(&p9);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(1, fake_db_rows(st.by_time));
  reboot();
  load_acct();
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_acct_matches_cf();
}

/* An owner step that spans slices resumes past the last by_owner key it
 * deleted -- never from the owner's first key again, whose seek walks
 * every tombstone the step left so far. */
static void test_evict_owner_resumes_past_its_deleted_head(void **state)
{
  struct htrim_params p = ev_params(3);
  char pre[HTC_OWNER_MAX + 1], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX + 1], mid[16], ts[32];
  const void *lo;
  size_t ll;
  uint64_t d;
  int n, btl, bol;
  (void)state;

  evict_ready();
  seed_run("#n", "N", "-", 56, 1000, 100);
  seed_run("#f", "F", "a:flood", 30, 2000, 100);     /* 8600; a:flood over by 2000 */
  step_us = 1000;
  assert_int_equal(1, htrim_run_slice(&p));
  n = htc_bo_prefix(pre, sizeof pre, "a:flood");
  fake_db_last_iter_lower(st.by_owner, &lo, &ll);
  assert_int_equal((size_t)n, ll);
  assert_memory_equal(pre, lo, ll);                   /* a new step: the owner's first key */
  d = htrim_stats()->deleted[HTRIM_PATH_OWNER];
  assert_true(d > 0 && d < 20);

  snprintf(mid, sizeof mid, "F%02d", (int)d - 1);
  snprintf(ts, sizeof ts, "%llu.000", (unsigned long long)(2000 + d - 1));
  btl = bt_of(bt, sizeof bt, "#f", ts, mid);
  bol = htc_bo_key(bo, sizeof bo - 1, "a:flood", bt, (size_t)btl);
  bo[bol++] = '\0';
  assert_int_equal(1, htrim_run_slice(&p));
  fake_db_last_iter_lower(st.by_owner, &lo, &ll);
  assert_int_equal((size_t)bol, ll);
  assert_memory_equal(bo, lo, ll);

  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(1000, owner_of("a:flood"));
  assert_int_equal(20, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
}

/* An owner whose total says more than its by_owner entries hold (a
 * double count) is walked to the end of its range: it then holds 0, and
 * the drain ends instead of picking it again every slice. */
static void test_evict_owner_drift_ends(void **state)
{
  struct htrim_params p = ev_params(0);
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16], ts[32];
  int i, btl, bol;
  (void)state;

  evict_ready();
  seed_run("#f", "F", "a:flood", 20, 2000, 100);
  for (i = 0; i < 20; i++) {           /* every row counted twice */
    snprintf(mid, sizeof mid, "F%02d", i);
    snprintf(ts, sizeof ts, "%d.000", 2000 + i);
    btl = bt_of(bt, sizeof bt, "#f", ts, mid);
    bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
    htrim_note_stored("a:flood", bo, (size_t)bol, 100);
  }
  seed_run("#n", "N", "-", 56, 1000, 100);
  assert_int_equal(4000, owner_of("a:flood"));
  assert_int_equal(9600, total_now());

  run_until_idle(&p);
  assert_int_equal(0, owner_of("a:flood"));
  assert_int_equal(20, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  assert_int_equal(5600, total_now());
  assert_int_equal(0, htrim_draining());
  assert_acct_matches_cf();
}

/* Totals that say more than the time index holds: oldest-overall runs
 * out of rows; the totals are counted again from by_owner and the drain
 * ends -- no slice after slice of empty walks. */
static void test_evict_oldest_exhausted_recounts(void **state)
{
  struct htrim_params p = ev_params(0);
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16];
  int i, btl, bol;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_run("#t", "R", "-", 10, 1000, 100);
  for (i = 0; i < 80; i++) {           /* counts with no row behind them */
    snprintf(mid, sizeof mid, "X%02d", i);
    btl = htc_bt_key(bt, sizeof bt, 5000000 + (uint64_t)i, "#x", mid);
    bol = htc_bo_key(bo, sizeof bo, "-", bt, (size_t)btl);
    htrim_note_stored("-", bo, (size_t)bol, 100);
  }
  assert_int_equal(9000, total_now());

  run_until_idle(&p);
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(1, htrim_acct_loaded());
  assert_int_equal(0, total_now());
  assert_int_equal(0, htrim_draining());
  assert_acct_matches_cf();
}

/* A drain's oldest-overall walk starts where age-out resumes -- every
 * row below it is gone, so a seek from the first key would only walk
 * their tombstones -- or at a row indexed behind that point since (here
 * the oldest row of all, and the first to go); later slices resume past
 * the last key deleted. */
static void test_evict_oldest_starts_at_ageout_point(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(3);
  char ts[32], mid[16], late[32];
  char k[HTC_BT_KEY_MAX + 1];
  int i, kl;
  (void)state;

  ageout_ready();
  for (i = 0; i < 3; i++) {
    snprintf(mid, sizeof mid, "O%d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&pa);                    /* resumes at the 7-day cutoff now */
  assert_int_equal(0, fake_db_rows(st.by_time));

  p.quota_on = 0;
  seed_run("#n", "N", "-", 85, BF_NOW_S - 3600, 100);
  seed_sized("#l", BF_NOW_S - 9 * 86400, "LATE", "-", 100);   /* behind it */
  snprintf(late, sizeof late, "%llu.000", (unsigned long long)(BF_NOW_S - 9 * 86400));
  assert_int_equal(8600, total_now());

  step_us = 1000;
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(HTRIM_PH_EVICT, htrim_stats()->last_phase);
  kl = bt_of(k, sizeof k, "#l", late, "LATE");
  assert_bt_lower(k, (size_t)kl);
  assert_false(row_present("#l", BF_NOW_S - 9 * 86400, "LATE"));
  i = (int)htrim_stats()->deleted[HTRIM_PATH_OLDEST] - 2;      /* the last N deleted */
  assert_true(i >= 0);
  snprintf(mid, sizeof mid, "N%02d", i);
  snprintf(ts, sizeof ts, "%llu.000", (unsigned long long)(BF_NOW_S - 3600 + (uint64_t)i));
  kl = bt_of(k, sizeof k - 1, "#n", ts, mid);
  k[kl++] = '\0';
  assert_int_equal(1, htrim_run_slice(&p));
  assert_bt_lower(k, (size_t)kl);

  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(7500, total_now());
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
}

/* ------------------------------------------------------------------ */
/* Task 8 fix round 1                                                  */
/* ------------------------------------------------------------------ */

/* I1: the owner step in progress holds only while the planner's share
 * gate does.  The share percentage SET to 0, or the quota SET off, in the
 * middle of a step ends it: no further owner-path deletes, the owner
 * keeps what it has (the drain goes on oldest-overall, here over the
 * dash rows, which are the oldest). */
static void evict_step_then(int quota_on, int share_pct)
{
  struct htrim_params p = ev_params(3);
  uint64_t d, flood;
  int i;

  evict_ready();
  seed_run("#n", "N", "-", 56, 1000, 100);
  seed_run("#f", "F", "a:flood", 30, 2000, 100);      /* 8600; over by 2000 */
  step_us = 1000;
  assert_int_equal(1, htrim_run_slice(&p));
  d = htrim_stats()->deleted[HTRIM_PATH_OWNER];
  assert_true(d > 0 && d < 20);                       /* a step in progress */

  p.quota_on = quota_on;
  p.share_pct = share_pct;
  flood = owner_of("a:flood");
  for (i = 0; i < 100 && htrim_run_slice(&p) == 1; i++)
    ;
  assert_int_equal(d, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  assert_int_equal(flood, owner_of("a:flood"));
  assert_true(htrim_stats()->deleted[HTRIM_PATH_OLDEST] > 0);
  assert_true(total_now() <= 7500);
  assert_int_equal(0, htrim_draining());
}

static void test_evict_step_ends_when_share_pct_zero(void **state)
{
  (void)state;
  evict_step_then(1, 0);
}

static void test_evict_step_ends_when_quota_off(void **state)
{
  (void)state;
  evict_step_then(0, 10);
}

/* I2: a new owner step's walk starts at owner 0x00 ‖ the live floor --
 * the owner's entries below it name rows age-out already deleted, and a
 * seek from the owner's first key would walk all their tombstones. */
static void test_evict_owner_step_starts_past_aged_out_head(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(0);
  char ts[32], mid[16], k[HTC_BO_KEY_MAX + 8];
  unsigned char cut[8];
  const void *lo;
  size_t ll;
  int i, n;
  (void)state;

  ageout_ready();
  for (i = 0; i < 20; i++) {                          /* a:flood's aged-out head */
    snprintf(mid, sizeof mid, "O%02d", i);
    seed_plain("#f", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:flood", NULL);
  }
  ageout_pass(&pa);
  assert_int_equal(0, fake_db_rows(st.by_time));
  htc_be64(cut, pa.now_ms - 7ULL * 86400ULL * 1000ULL);

  seed_run("#n", "N", "-", 56, BF_NOW_S - 7200, 100);
  seed_run("#f", "F", "a:flood", 30, BF_NOW_S - 3600, 100);
  run_until_idle(&p);
  assert_int_equal(1000, owner_of("a:flood"));
  n = htc_bo_prefix(k, sizeof k, "a:flood");
  memcpy(k + n, cut, sizeof cut);
  n += (int)sizeof cut;
  fake_db_last_iter_lower(st.by_owner, &lo, &ll);
  assert_int_equal((size_t)n, ll);
  assert_memory_equal(k, lo, ll);
}

/* I3: an emptiness check steps over at most HTRIM_EMPTY_SKIP_MAX (10000)
 * tombstones.  A target a drain just emptied of 10001 rows is undecided:
 * its key stays, it is not reported, its range is flushed and hinted,
 * and a later sweep (at the next pass start) checks it again -- once the
 * tombstones are compacted away, that check finds it empty.  The boot
 * sweep meets it the same way. */
static void test_emptiness_undecided_past_skip_limit(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16], lo[8], hi[8];
  const void *s, *e;
  size_t sl, el;
  unsigned int sug;
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "B%05d", i);
    seed_plain("#big", ts_ago(ts, sizeof ts, 8, 20000 - i), mid, "a:bob", NULL);
  }
  seed_targets("#big", ts);
  ageout_pass(&p);                     /* one slice: all 10001 rows */
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_true(fake_db_tombstones(st.messages) > 10000);
  assert_true(targets_has("#big"));    /* undecided: kept, */
  assert_int_equal(0, emptied_times("#big"));         /* not reported, */
  assert_int_equal(1, fake_db_suggest_calls(st.messages));   /* hinted */
  assert_int_equal(1, fake_db_flush_calls(st.messages));
  memcpy(lo, "#big\0", 5);
  memcpy(hi, "#big\x01", 5);              /* exactly [#big\0, #big\x01) */
  assert_int_equal(DB_OK, fake_db_last_suggest(st.messages, &s, &sl, &e, &el));
  assert_int_equal(5, sl);
  assert_memory_equal(lo, s, 5);
  assert_int_equal(5, el);
  assert_memory_equal(hi, e, 5);
  assert_int_equal(0, htrim_tsweep_pending());        /* not this second: */
  run_until_idle(&p);
  assert_true(targets_has("#big"));

  /* A restart: the boot sweep meets the same run, undecided again. */
  reboot();
  load_acct();
  assert_true(targets_has("#big"));
  assert_int_equal(0, emptied_times("#big"));
  sug = fake_db_suggest_calls(st.messages);
  assert_int_equal(2, sug);

  /* Compaction drops the tombstones; the next pass start's sweep decides. */
  fake_db_drop_tombstones(st.messages);
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_tsweep_pending());
  run_until_idle(&p);
  assert_false(targets_has("#big"));
  assert_int_equal(1, emptied_times("#big"));
}

/* The age-out rewind, exactly: late rows (indexed behind the walk's
 * frontier, past a long deleted run) are deleted by key at the next pass,
 * and the walk resumes at the frontier -- the run is never crossed. */
static void test_ageout_late_rows_by_key_skip_the_run(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16];
  unsigned char cut[8];
  unsigned int opens;
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i < 300; i++) {          /* the run, deleted by the first pass */
    snprintf(mid, sizeof mid, "R%03d", i);
    seed_plain("#run", ts_ago(ts, sizeof ts, 8, 1000 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&p);
  htc_be64(cut, p.now_ms - 7ULL * 86400ULL * 1000ULL);
  assert_bt_lower(NULL, 0);
  assert_int_equal(300, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  seed_plain("#l", ts_ago(ts, sizeof ts, 10, 0), "L0", "a:bob", NULL);   /* behind */
  seed_plain("#l", ts_ago(ts, sizeof ts, 9, 0), "L1", "a:bob", NULL);    /* the run, */
  seed_plain("#m", ts_ago(ts, sizeof ts, 8, 500), "L2", "a:bob", NULL);  /* and in it */
  assert_int_equal(3, fake_db_rows(st.by_time));
  opens = fake_db_iter_opens(st.by_time);
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_int_equal(303, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(opens + 1, fake_db_iter_opens(st.by_time));   /* one walk, */
  assert_bt_lower(cut, sizeof cut);                              /* at the frontier */
  assert_meta_bytes(HTRIM_META_AGEOUT_RESUME, cut, sizeof cut);
  assert_acct_matches_cf();
}

/* Past HTRIM_LATE_MAX (64) late rows the pass falls back to rewinding
 * the walk to the oldest of them, and walks forward from there. */
static void test_ageout_late_rows_overflow_rewinds(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16], k[HTC_BT_KEY_MAX], first[32];
  int i, kl;
  (void)state;

  ageout_ready();
  seed_plain("#run", ts_ago(ts, sizeof ts, 8, 0), "R0", "a:bob", NULL);
  ageout_pass(&p);
  for (i = 0; i < 65; i++) {
    snprintf(mid, sizeof mid, "L%02d", i);
    seed_plain("#l", ts_ago(i ? ts : first, sizeof ts, 9, 100 - i), mid, "a:bob", NULL);
  }
  kl = bt_of(k, sizeof k, "#l", first, "L00");
  assert_meta_bytes(HTRIM_META_AGEOUT_RESUME, k, (size_t)kl);
  htrim_pass_start(&p);
  assert_int_equal(0, htrim_run_slice(&p));
  assert_bt_lower(k, (size_t)kl);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(66, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
}

/* M3/M4: the oldest-overall walk starts at the larger of where this drain
 * stopped and where age-out resumes -- an age-out pass in the middle of a
 * drain deleted the rows between -- and a walk that runs out of rows from
 * that bound recounts the totals at once, never walking from the first
 * key. */
static void test_evict_oldest_resumes_past_ageout(void **state)
{
  struct htrim_params p = ev_params(3);
  char mid[16], k[HTC_BT_KEY_MAX + 1], ts[32];
  unsigned char cut[8];
  uint64_t cutoff = 1006ULL * 1000ULL + 1;
  int kl;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_run("#t", "R", "-", 86, 1000, 100);            /* 8600: 11 rows to go */
  p.now_ms = cutoff + 7ULL * 86400ULL * 1000ULL;
  p.retention_days = 7;
  step_us = 1000;
  assert_int_equal(1, htrim_run_slice(&p));           /* R00..R02 */
  assert_int_equal(HTRIM_PH_EVICT, htrim_stats()->last_phase);
  assert_int_equal(3, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);

  htrim_pass_start(&p);                               /* age-out takes R03..R06 */
  step_us = 0;
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(HTRIM_PH_AGEOUT, htrim_stats()->last_phase);
  assert_int_equal(4, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);

  step_us = 1000;
  htc_be64(cut, cutoff);
  assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(HTRIM_PH_EVICT, htrim_stats()->last_phase);
  assert_bt_lower(cut, sizeof cut);                   /* not R02 ‖ 0x00 */
  snprintf(mid, sizeof mid, "R%02d", 2);
  snprintf(ts, sizeof ts, "%d.000", 1002);
  kl = bt_of(k, sizeof k - 1, "#t", ts, mid);
  (void)kl;
  step_us = 0;
  run_until_idle(&p);
  assert_int_equal(7500, total_now());
}

/* M3: an oldest-overall walk that runs out of rows from a bound (here
 * the age-out resume point: everything below is gone) recounts at once
 * -- one walk in the whole drain, never a second from the first key. */
static void test_evict_oldest_exhausted_from_bound_recounts(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(0);
  char ts[32], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16];
  unsigned int opens;
  int i, btl, bol;
  (void)state;

  p.quota_on = 0;
  ageout_ready();
  seed_plain("#old", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&pa);                    /* age-out resumes at the cutoff now */
  seed_run("#t", "R", "-", 10, BF_NOW_S - 3600, 100);
  for (i = 0; i < 80; i++) {           /* counts with no row behind them */
    snprintf(mid, sizeof mid, "X%02d", i);
    btl = htc_bt_key(bt, sizeof bt, BF_NOW_S * 1000ULL + (uint64_t)i, "#x", mid);
    bol = htc_bo_key(bo, sizeof bo, "-", bt, (size_t)btl);
    htrim_note_stored("-", bo, (size_t)bol, 100);
  }
  assert_true(total_now() >= 9000);
  opens = fake_db_iter_opens(st.by_time);
  run_until_idle(&p);
  assert_int_equal(opens + 1, fake_db_iter_opens(st.by_time));
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(1, htrim_acct_loaded());
  assert_int_equal(0, htrim_draining());
  assert_acct_matches_cf();
}

/* A due late row a slice did not reach holds the stored resume point
 * back: the due list is in memory, so a restart before the slice that
 * takes it must still walk it. */
static void test_ageout_due_rows_survive_restart(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htrim_params p1 = bf_params(1);
  char ts[32], t1[32], k[HTC_BT_KEY_MAX];
  int kl;
  (void)state;

  ageout_ready();
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&p);
  seed_plain("#l", ts_ago(t1, sizeof t1, 9, 0), "L1", "a:bob", NULL);
  seed_plain("#l", ts_ago(ts, sizeof ts, 10, 0), "L0", "a:bob", NULL);
  step_us = 1000;                      /* a 1 ms slice: L0 only */
  htrim_pass_start(&p1);
  assert_int_equal(1, htrim_run_slice(&p1));
  assert_int_equal(1, fake_db_rows(st.by_time));
  kl = bt_of(k, sizeof k, "#l", t1, "L1");
  assert_meta_bytes(HTRIM_META_AGEOUT_RESUME, k, (size_t)kl);

  reboot();
  step_us = 0;
  load_acct();
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(1, htrim_stats()->deleted[HTRIM_PATH_AGEOUT]);
}

/* A due compaction hint is issued by the engine's own slices only --
 * never inside a caller's burst-loss prune (an INCARNATION slice runs
 * inside BURST, and a hint's flush switches a memtable on this thread). */
static void test_caller_slice_issues_no_hint(void **state)
{
  struct htrim_params p = ev_params(0);
  struct htrim_slice *s;
  unsigned int before;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_run("#t", "R", "-", 86, 1000, 100);
  assert_int_equal(1, htrim_run_slice(&p));          /* the whole drain */
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(0, htrim_draining());
  seed_plain("#p", "5000.000", "P1", "a:bob", NULL);
  before = fake_db_suggest_calls(st.messages) + fake_db_suggest_calls(st.msgid)
           + fake_db_suggest_calls(st.by_time) + fake_db_suggest_calls(st.by_owner);
  assert_true(before < 4);             /* hints still due */

  s = htrim_slice_begin(0);
  assert_non_null(s);
  htrim_slice_set_phase(s, HTRIM_PH_INCARNATION);
  stage_del(s, HTRIM_PATH_INCARNATION, "#p", "5000.000", "P1", 1);
  assert_int_equal(1, htrim_slice_commit(s));
  assert_int_equal(before, fake_db_suggest_calls(st.messages) + fake_db_suggest_calls(st.msgid)
                           + fake_db_suggest_calls(st.by_time) + fake_db_suggest_calls(st.by_owner));
  run_until_idle(&p);
  assert_int_equal(4, fake_db_suggest_calls(st.messages) + fake_db_suggest_calls(st.msgid)
                      + fake_db_suggest_calls(st.by_time) + fake_db_suggest_calls(st.by_owner));
}

/* ------------------------------------------------------------------ */
/* Task 8 fix round 2                                                  */
/* ------------------------------------------------------------------ */

/* Important 1 (the re-review's probe): two rows a backfill slice indexed
 * behind the age-out frontier.  Only its smallest key was noted, so under
 * the exact late set only that row became due; the pass deleted it by key
 * and resumed at the frontier, and the other was never walked.  A slice
 * that indexes more than one row behind the frontier falls back to the
 * oldest-row rewind. */
static void test_backfill_rows_behind_walk_all_age_out(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htrim_params p9 = bf_params(0);
  char ts[32], t1[32], t2[32];
  (void)state;

  ageout_ready();
  seed_plain("#t", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));

  p9.retention_days = 9;
  htrim_check_index_gap(UINT64_MAX, 0);
  seed_legacy_row("#l", ts_ago(t1, sizeof t1, 8, 43200), "L1", "Bob", 0, "", "", 0);
  seed_legacy_row("#m", ts_ago(t2, sizeof t2, 8, 36000), "L2", "Bob", 0, "", "", 0);
  run_until_idle(&p9);
  assert_int_equal(1, htrim_backfill_done());
  assert_int_equal(2, fake_db_rows(st.by_time));

  ageout_pass(&p);
  assert_int_equal(0, fake_db_rows(st.by_time));
  assert_int_equal(0, fake_db_rows(st.messages));
  assert_acct_matches_cf();
}

/* Important 2: a non-waiting flush still blocks the calling thread when
 * RocksDB would stall writes after it (a flush of that CF in flight -- an
 * immutable memtable -- with max_write_buffer_number 2, or L0 one file
 * short of level0_slowdown_writes_trigger).  A hint on such a CF issues
 * the compaction suggestion alone, does not flush, and stays due: a later
 * slice flushes it once the CF is idle. */
static void test_hint_skips_flush_of_busy_cf(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16];
  int i;
  (void)state;

  p.compact_min_rows = 10;
  ageout_ready();
  for (i = 0; i < 12; i++) {
    snprintf(mid, sizeof mid, "A%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  fake_db_set_busy(st.by_time, 1, 0);           /* a flush in flight */
  fake_db_set_busy(st.msgid, 0, 19);            /* L0 at the trigger - 1 */
  htrim_pass_start(&p);
  assert_int_equal(1, htrim_run_slice(&p));     /* age-out; both hints due */
  assert_int_equal(0, fake_db_flush_calls(st.by_time));
  assert_int_equal(0, fake_db_flush_calls(st.msgid));
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));   /* the suggestion alone */
  assert_int_equal(1, fake_db_suggest_calls(st.msgid));
  assert_int_equal(1, htrim_run_slice(&p));     /* still due: work remains, */
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));   /* suggested once */
  assert_int_equal(0, fake_db_flush_calls(st.by_time));

  fake_db_set_busy(st.by_time, 0, 0);
  fake_db_set_busy(st.msgid, 0, 18);
  run_until_idle(&p);                           /* one flush a slice */
  assert_int_equal(1, fake_db_flush_calls(st.by_time));
  assert_int_equal(1, fake_db_flush_calls(st.msgid));
  assert_int_equal(2, fake_db_suggest_calls(st.by_time));
  assert_int_equal(0, htrim_run_slice(&p));
}

/* A CF that stays busy: its hint is dropped after a bounded wait (the
 * engine goes idle), its count kept -- once more rows go, the trigger
 * hints the whole range. */
static void test_hint_on_a_cf_busy_for_good_is_dropped(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16], lo[HTC_BT_KEY_MAX];
  const void *s, *e;
  size_t sl, el;
  int i, n, lol;
  (void)state;

  p.compact_min_rows = 10;
  ageout_ready();
  for (i = 0; i < 12; i++) {
    snprintf(mid, sizeof mid, "A%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  fake_db_set_busy(st.by_time, 1, 0);
  htrim_pass_start(&p);
  n = run_until_idle(&p);
  assert_true(n > 10 && n < 200);               /* waited, then dropped */
  assert_int_equal(0, fake_db_flush_calls(st.by_time));
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));
  /* Still busy, no new rows: the next pass does not wait on it again. */
  htrim_pass_start(&p);
  assert_true(run_until_idle(&p) <= 2);
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));

  fake_db_set_busy(st.by_time, 0, 0);
  for (i = 0; i < 10; i++) {                    /* 12 + 10: past the rearm */
    snprintf(mid, sizeof mid, "B%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 50 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&p);
  assert_int_equal(1, fake_db_flush_calls(st.by_time));
  assert_int_equal(2, fake_db_suggest_calls(st.by_time));
  assert_int_equal(DB_OK, fake_db_last_suggest(st.by_time, &s, &sl, &e, &el));
  lol = bt_of(lo, sizeof lo, "#t", ts_ago(ts, sizeof ts, 8, 100), "A00");
  assert_int_equal((size_t)lol, sl);
  assert_memory_equal(lo, s, sl);
}

/* M3: an undecided emptiness check's flush and hint go through the due
 * hints: none inside a caller's (INCARNATION) slice, the next engine
 * slice issues it. */
static void test_undecided_hint_waits_for_an_engine_slice(void **state)
{
  struct htrim_params p = bf_params(0);
  struct htrim_slice *s;
  char ts[32], mid[16], newest[32];
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "B%05d", i);
    seed_plain("#big", ts_ago(ts, sizeof ts, 1, 20000 - i), mid, "a:bob", NULL);
  }
  memcpy(newest, ts, sizeof newest);
  seed_targets("#big", newest);
  s = htrim_slice_begin(0);                     /* the burst-loss prune */
  assert_non_null(s);
  htrim_slice_set_phase(s, HTRIM_PH_INCARNATION);
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "B%05d", i);
    stage_del(s, HTRIM_PATH_INCARNATION, "#big", ts_ago(ts, sizeof ts, 1, 20000 - i), mid, 1);
  }
  assert_int_equal(10001, htrim_slice_commit(s));
  assert_true(targets_has("#big"));             /* undecided */
  assert_int_equal(0, fake_db_flush_calls(st.messages));
  assert_int_equal(0, fake_db_suggest_calls(st.messages));

  assert_int_equal(0, htrim_run_slice(&p));     /* an engine slice issues it */
  assert_int_equal(1, fake_db_flush_calls(st.messages));
  assert_int_equal(1, fake_db_suggest_calls(st.messages));
}

/* M4: an owner step that starts at the live floor and runs out of
 * entries has not seen the owner's entries below the floor: it walks
 * below its start once (fix round 3) -- the orphan the boot scan counted
 * goes, with its bytes -- and since the total is still short (it was
 * double-counted), the totals are counted again rather than zeroed. */
static void test_evict_owner_from_floor_runs_out_recounts(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(0);
  char ts[32], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16], bo_orphan[HTC_BO_KEY_MAX];
  unsigned char sz[4];
  struct db_writebatch *wb;
  int i, btl, bol, bol_orphan;
  (void)state;

  ageout_ready();
  seed_plain("#old", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&pa);                             /* the floor: the 7-day cutoff */
  /* An orphan entry of a:flood below the floor, counted by a reboot's scan. */
  btl = htc_bt_key(bt, sizeof bt, (BF_NOW_S - 9 * 86400ULL) * 1000ULL, "#f", "GONE");
  bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
  memcpy(bo_orphan, bo, (size_t)bol);
  bol_orphan = bol;
  htc_size_pack(sz, 600);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, sizeof sz));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  seed_run("#f", "F", "a:flood", 20, BF_NOW_S - 3600, 100);
  seed_run("#n", "N", "-", 66, BF_NOW_S - 7200, 100);
  reboot();
  load_acct();
  htrim_pass_start(&pa);                        /* the floor again, after the restart */
  run_until_idle(&pa);
  assert_int_equal(2600, owner_of("a:flood"));
  /* Drift: every a:flood row counted twice. */
  for (i = 0; i < 20; i++) {
    char t[32];
    snprintf(mid, sizeof mid, "F%02d", i);
    snprintf(t, sizeof t, "%llu.000", (unsigned long long)(BF_NOW_S - 3600 + (uint64_t)i));
    btl = bt_of(bt, sizeof bt, "#f", t, mid);
    bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
    htrim_note_stored("a:flood", bo, (size_t)bol, 100);
  }
  assert_int_equal(4600, owner_of("a:flood"));
  run_until_idle(&p);
  assert_int_equal(1, htrim_acct_loaded());     /* recounted: what by_owner holds */
  assert_int_equal(0, owner_of("a:flood"));     /* rows and orphan gone */
  assert_false(key_exists(st.by_owner, bo_orphan, (size_t)bol_orphan));
  assert_int_equal(0, htrim_draining());
  assert_acct_matches_cf();
}

/* M6: a hint whose flush fails keeps its count (the next trigger hints
 * the whole range), and the trigger backs off until compact_min_rows more
 * keys have gone (or 60 slices; fix round 3).  msgid_index is the first
 * CF hinted here: it loses 2 keys a row. */
static void test_hint_flush_failure_keeps_the_count(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16];
  const void *s, *e;
  size_t sl, el;
  unsigned int by_time;
  int i;
  (void)state;

  p.compact_min_rows = 30;
  ageout_ready();
  for (i = 0; i < 16; i++) {                    /* msgid 32 >= 30; by_time 16 */
    snprintf(mid, sizeof mid, "A%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  fake_db_fail_next_flush(env);
  ageout_pass(&p);                              /* msgid's hint: the flush fails */
  assert_int_equal(1, fake_db_flush_calls(st.msgid));
  assert_int_equal(0, fake_db_suggest_calls(st.msgid));
  by_time = fake_db_suggest_calls(st.by_time);
  for (i = 0; i < 2; i++) {
    snprintf(mid, sizeof mid, "B%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 50 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&p);                              /* 36: backing off, no retry yet */
  assert_int_equal(1, fake_db_flush_calls(st.msgid));
  assert_int_equal(0, fake_db_suggest_calls(st.msgid));
  for (i = 0; i < 13; i++) {                    /* 36 + 26 = 62: compact_min_rows more */
    snprintf(mid, sizeof mid, "C%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 40 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&p);                              /* hinted, from A00 */
  assert_int_equal(1, fake_db_suggest_calls(st.msgid));
  assert_int_equal(DB_OK, fake_db_last_suggest(st.msgid, &s, &sl, &e, &el));
  assert_int_equal(3, sl);
  assert_memory_equal("A00", s, 3);
  assert_int_equal(by_time + 1, fake_db_suggest_calls(st.by_time));   /* 31 >= 30 */
}

/* M6: a drain that starts while the last one's drain-end hints are still
 * due (one a slice) keeps them -- the prefix-keyed CF's hint then covers
 * both drains, from the first one's first deleted key. */
static void test_drain_start_keeps_a_due_hint(void **state)
{
  struct htrim_params p = ev_params(0);
  char lo[HTC_BO_KEY_MAX], bt[HTC_BT_KEY_MAX], ts[32];
  const void *s, *e;
  size_t sl, el;
  int lol, btl;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_run("#t", "R", "-", 86, 1000, 100);
  assert_int_equal(1, htrim_run_slice(&p));     /* drain 1, and its first hint */
  assert_int_equal(11, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(0, fake_db_suggest_calls(st.by_owner));      /* still due */
  seed_run("#u", "S", "-", 20, 2000, 100);       /* 9500: over high again */
  run_until_idle(&p);
  assert_true(htrim_stats()->deleted[HTRIM_PATH_OLDEST] > 11);  /* drain 2 ran */
  assert_true(fake_db_suggest_calls(st.by_owner) >= 1);
  snprintf(ts, sizeof ts, "%d.000", 1000);
  btl = bt_of(bt, sizeof bt, "#t", ts, "R00");
  lol = htc_bo_key(lo, sizeof lo, "-", bt, (size_t)btl);
  /* by_owner's hint, still due when drain 2 began, kept drain 1's
   * deletes: one hint, issued after drain 2, from drain 1's first key. */
  assert_int_equal(1, fake_db_suggest_calls(st.by_owner));
  assert_int_equal(DB_OK, fake_db_last_suggest(st.by_owner, &s, &sl, &e, &el));
  (void)e;
  (void)el;
  assert_int_equal((size_t)lol, sl);
  assert_memory_equal(lo, s, sl);
}

/* ------------------------------------------------------------------ */
/* Task 8 fix round 3                                                  */
/* ------------------------------------------------------------------ */

/* The re-review's probe: an owner whose orphaned by_owner bytes below the
 * live floor exceed its share.  Its step from the floor ran out, the
 * totals were recounted, and the next drain picked it again -- 1000
 * recounts in 2000 slices, the cap never enforced.  The step now walks
 * below its start once and removes the orphan with its bytes. */
static void test_evict_orphan_below_floor_over_share(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(0);
  char ts[32], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  unsigned char sz[4];
  struct db_writebatch *wb;
  int i, btl, bol, recounts = 0, prev = 1, rc = 1;
  (void)state;

  ageout_ready();
  seed_plain("#old", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&pa);
  btl = htc_bt_key(bt, sizeof bt, (BF_NOW_S - 9 * 86400ULL) * 1000ULL, "#f", "GONE");
  bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
  htc_size_pack(sz, 1200);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, sizeof sz));
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  seed_run("#f", "F", "a:flood", 20, BF_NOW_S - 3600, 100);
  seed_run("#n", "N", "-", 75, BF_NOW_S - 7200, 100);
  reboot();
  load_acct();
  htrim_pass_start(&pa);
  run_until_idle(&pa);
  assert_int_equal(3200, owner_of("a:flood"));
  assert_int_equal(10700, total_now());

  for (i = 0; i < 2000 && rc == 1; i++) {
    rc = htrim_run_slice(&p);
    if (prev && !htrim_acct_loaded())
      recounts++;
    prev = htrim_acct_loaded();
  }
  assert_int_equal(0, rc);
  assert_int_equal(0, recounts);
  assert_false(key_exists(st.by_owner, bo, (size_t)bol));
  assert_int_equal(0, owner_of("a:flood"));
  assert_int_equal(7500, total_now());
  assert_int_equal(0, htrim_draining());
  assert_acct_matches_cf();
}

/* The walk below the start, stopped by the budget, resumes there in the
 * next slice (its iterator opens past the last orphan it removed) and
 * finishes the step: share 1% (100), a:flood 10 rows + 12 orphans below
 * the floor (2200) -- trim 2100: the 10 rows, then 11 orphans. */
static void test_evict_below_floor_walk_resumes(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(3);
  char ts[32], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16];
  unsigned char sz[4];
  struct db_writebatch *wb;
  uint64_t floor_ms = (BF_NOW_S - 7ULL * 86400ULL) * 1000ULL;
  int i, btl, bol, rc = 1, resumed_below = 0;
  (void)state;

  p.share_pct = 1;
  ageout_ready();
  seed_plain("#old", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&pa);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  htc_size_pack(sz, 100);
  for (i = 0; i < 12; i++) {
    snprintf(mid, sizeof mid, "G%02d", i);
    btl = htc_bt_key(bt, sizeof bt, (BF_NOW_S - 9 * 86400ULL + (uint64_t)i) * 1000ULL, "#f", mid);
    bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, sizeof sz));
  }
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  seed_run("#f", "F", "a:flood", 10, BF_NOW_S - 3600, 100);
  seed_run("#n", "N", "-", 66, BF_NOW_S - 7200, 100);
  reboot();
  load_acct();
  htrim_pass_start(&pa);
  run_until_idle(&pa);
  assert_int_equal(2200, owner_of("a:flood"));  /* 8800 > 8500 */

  step_us = 1000;                               /* a few entries a 3 ms slice */
  for (i = 0; i < 1000 && rc == 1; i++) {
    const void *lo;
    size_t ll;
    rc = htrim_run_slice(&p);
    fake_db_last_iter_lower(st.by_owner, &lo, &ll);
    if (lo && ll > 8 + 8 && memcmp(lo, "a:flood\0", 8) == 0) {
      const unsigned char *b8 = (const unsigned char *)lo + 8;
      uint64_t ms = 0;
      int j;
      for (j = 0; j < 8; j++)
        ms = (ms << 8) | b8[j];
      if (ms < floor_ms) {                      /* past an orphan it removed, */
        const void *up;
        size_t ul;
        unsigned char start[16];
        memcpy(start, "a:flood\0", 8);
        htc_be64(start + 8, floor_ms);
        fake_db_last_iter_upper(st.by_owner, &up, &ul);
        assert_int_equal(16, ul);               /* and still below the start */
        assert_memory_equal(start, up, 16);
        resumed_below = 1;
      }
    }
  }
  assert_int_equal(0, rc);
  assert_true(resumed_below);
  assert_int_equal(100, owner_of("a:flood"));   /* one orphan left: at its share */
  assert_int_equal(66, fake_db_rows(st.by_time));
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_OWNER]);
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(1, htrim_acct_loaded());
  assert_acct_matches_cf();
}

/* The re-review's M6 probe: a prefix-keyed CF's drain-end hint that fails
 * is no longer due -- the next drain's start must still keep its count
 * (these CFs have no other trigger): drain 2's hint starts at R00. */
static void test_failed_prefix_hint_survives_the_next_drain(void **state)
{
  struct htrim_params p = ev_params(0);
  char lo[HTC_BO_KEY_MAX], bt[HTC_BT_KEY_MAX], ts[32];
  const void *s, *e;
  size_t sl, el;
  int lol, btl, n = 0;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_run("#t", "R", "-", 86, 1000, 100);
  while (fake_db_flush_calls(st.by_owner) == 0 && n < 50) {   /* every flush fails */
    fake_db_fail_next_flush(env);
    htrim_run_slice(&p);
    n++;
  }
  assert_int_equal(1, fake_db_flush_calls(st.by_owner));
  assert_int_equal(0, fake_db_suggest_calls(st.by_owner));
  seed_run("#u", "S", "-", 20, 2000, 100);       /* 9500: over high again */
  run_until_idle(&p);
  assert_int_equal(1, fake_db_suggest_calls(st.by_owner));
  snprintf(ts, sizeof ts, "%d.000", 1000);
  btl = bt_of(bt, sizeof bt, "#t", ts, "R00");
  lol = htc_bo_key(lo, sizeof lo, "-", bt, (size_t)btl);
  assert_int_equal(DB_OK, fake_db_last_suggest(st.by_owner, &s, &sl, &e, &el));
  assert_int_equal((size_t)lol, sl);
  assert_memory_equal(lo, s, sl);
}

/** Two targets of one row each, both emptied in one unbudgeted slice
 * with more than 10000 tombstones in the way ahead of them: a filler run
 * in each target's range keeps the check from deciding. */
static void seed_undecided_pair(const char *a, const char *b)
{
  char ts[32], mid[16];
  struct htrim_slice *s;
  int i, t;
  const char *names[2];

  names[0] = a;
  names[1] = b;
  for (t = 0; t < 2; t++) {
    for (i = 0; i <= 10000; i++) {
      snprintf(mid, sizeof mid, "%c%05d", 'a' + t, i);
      seed_plain(names[t], ts_ago(ts, sizeof ts, 1, 30000 - i), mid, "a:bob", NULL);
    }
    seed_targets(names[t], ts);
  }
  s = htrim_slice_begin(0);
  assert_non_null(s);
  for (t = 0; t < 2; t++)
    for (i = 0; i <= 10000; i++) {
      snprintf(mid, sizeof mid, "%c%05d", 'a' + t, i);
      stage_del(s, HTRIM_PATH_AGEOUT, names[t], ts_ago(ts, sizeof ts, 1, 30000 - i), mid, 1);
    }
  assert_int_equal(20002, htrim_slice_commit(s));
}

/* (a) Undecided targets are hinted each over its own range -- never one
 * range across unrelated targets (most of the CF) -- and (c) one messages
 * flush serves both messages slots when both are due. */
static void test_undecided_targets_hinted_apart(void **state)
{
  struct htrim_params p = ev_params(0);
  const void *s, *e;
  size_t sl, el;
  (void)state;

  p.quota_on = 0;
  evict_ready();
  seed_undecided_pair("#aa", "#zz");
  assert_true(targets_has("#aa"));
  assert_true(targets_has("#zz"));
  assert_int_equal(0, fake_db_suggest_calls(st.messages));     /* a caller's slice */

  /* A drain due at the same time: its messages hint and the undecided
   * ranges share one flush. */
  seed_run("#t", "R", "-", 86, BF_NOW_S - 600, 100);
  assert_int_equal(1, htrim_run_slice(&p));     /* the drain, and the messages hint */
  assert_int_equal(HTRIM_PH_EVICT, htrim_stats()->last_phase);
  assert_int_equal(0, htrim_draining());
  assert_int_equal(1, fake_db_flush_calls(st.messages));
  assert_int_equal(3, fake_db_suggest_calls(st.messages));     /* drain + 2 targets */
  assert_int_equal(DB_OK, fake_db_last_suggest(st.messages, &s, &sl, &e, &el));
  assert_int_equal(4, sl);                      /* the last: a target's own range */
  assert_int_equal(4, el);
  assert_true((memcmp(s, "#zz\0", 4) == 0 && memcmp(e, "#zz\x01", 4) == 0)
              || (memcmp(s, "#aa\0", 4) == 0 && memcmp(e, "#aa\x01", 4) == 0));
  /* The sweep the drain armed meets both still undecided: one more hint
   * later, both ranges apart again. */
  run_until_idle(&p);
  assert_int_equal(2, fake_db_flush_calls(st.messages));
  assert_int_equal(5, fake_db_suggest_calls(st.messages));
}

/* (b) A time-ordered CF whose flush keeps failing: one WARNING for the
 * streak, and the retries back off (not one a slice); the first success
 * ends the streak. */
static void test_failing_hint_backs_off(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16], *log;
  FILE *tmp;
  unsigned int flushes;
  long len;
  int i, pass;
  (void)state;

  p.compact_min_rows = 10;
  ageout_ready();
  stderr_capture(&tmp);
  for (pass = 0; pass < 5; pass++) {
    for (i = 0; i < 6; i++) {                   /* by_time: 6 a pass, >= 10 by pass 2 */
      snprintf(mid, sizeof mid, "P%d_%d", pass, i);
      seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - pass * 10 - i), mid, "a:bob", NULL);
    }
    htrim_pass_start(&p);
    for (i = 0; i < 20; i++) {                  /* every flush fails */
      fake_db_fail_next_flush(env);
      if (htrim_run_slice(&p) != 1)
        break;
    }
  }
  flushes = fake_db_flush_calls(st.by_time);
  db_flush_cf(env, st.reply, 0);                /* use up an armed failure */
  fflush(stderr);
  stderr_restore();
  fseek(tmp, 0, SEEK_END);
  len = ftell(tmp);
  rewind(tmp);
  log = (char *)calloc(1, (size_t)len + 1);
  assert_int_equal((size_t)len, fread(log, 1, (size_t)len, tmp));
  fclose(tmp);
  assert_true(flushes >= 1 && flushes <= 3);    /* backed off, not each pass */
  assert_int_equal(1, count_of(log, "compaction hint on by_time failed"));
  free(log);

  for (i = 0; i < 12; i++) {                    /* compact_min_rows more: a retry */
    snprintf(mid, sizeof mid, "Q%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 40 - i), mid, "a:bob", NULL);
  }
  ageout_pass(&p);
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));
}

/* (d) The undecided slot's log line counts targets, not keys. */
static void test_undecided_hint_logs_targets(void **state)
{
  struct htrim_params p = ev_params(0);
  char *log;
  FILE *tmp;
  long len;
  (void)state;

  evict_ready();
  stderr_capture(&tmp);
  seed_undecided_pair("#aa", "#zz");
  run_until_idle(&p);
  fflush(stderr);
  stderr_restore();
  fseek(tmp, 0, SEEK_END);
  len = ftell(tmp);
  rewind(tmp);
  log = (char *)calloc(1, (size_t)len + 1);
  assert_int_equal((size_t)len, fread(log, 1, (size_t)len, tmp));
  fclose(tmp);
  assert_non_null(strstr(log, "compaction hint on messages: 2 undecided target ranges"));
  free(log);
}

/* Both phases ran out short of the trim (the total drifted): the totals
 * are counted again -- never zeroed, since a row the owner stored while
 * the walk below its start was still going lies above the walk and was
 * never seen (zeroing would drop its bytes). */
static void test_evict_drift_after_both_phases_recounts(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(3);
  char ts[32], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16], t[32];
  unsigned char sz[4], start[16];
  struct db_writebatch *wb;
  uint64_t floor_ms = (BF_NOW_S - 7ULL * 86400ULL) * 1000ULL;
  int i, btl, bol, rc = 1, stored = 0;
  (void)state;

  ageout_ready();
  seed_plain("#old", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&pa);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  htc_size_pack(sz, 100);
  for (i = 0; i < 20; i++) {                    /* 20 orphans below the floor */
    snprintf(mid, sizeof mid, "G%02d", i);
    btl = htc_bt_key(bt, sizeof bt, (BF_NOW_S - 9 * 86400ULL + (uint64_t)i) * 1000ULL, "#f", mid);
    bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, sizeof sz));
  }
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  seed_run("#f", "F", "a:flood", 10, BF_NOW_S - 3600, 100);
  seed_run("#n", "N", "-", 26, BF_NOW_S - 7200, 100);
  reboot();
  load_acct();
  htrim_pass_start(&pa);
  run_until_idle(&pa);
  for (i = 0; i < 30; i++) {                    /* drift: 3000 counted twice */
    snprintf(mid, sizeof mid, "F%02d", i % 10);
    snprintf(t, sizeof t, "%llu.000", (unsigned long long)(BF_NOW_S - 3600 + (uint64_t)(i % 10)));
    btl = bt_of(bt, sizeof bt, "#f", t, mid);
    bol = htc_bo_key(bo, sizeof bo, "a:flood", bt, (size_t)btl);
    htrim_note_stored("a:flood", bo, (size_t)bol, 100);
  }
  assert_int_equal(6000, owner_of("a:flood"));  /* 8600 > 8500: trim 5000 */

  memcpy(start, "a:flood\0", 8);
  htc_be64(start + 8, floor_ms);
  step_us = 1000;                               /* a few entries a 3 ms slice */
  for (i = 0; i < 1000 && rc == 1; i++) {
    const void *up;
    size_t ul;
    rc = htrim_run_slice(&p);
    fake_db_last_iter_upper(st.by_owner, &up, &ul);
    if (!stored && rc == 1 && htrim_acct_loaded() && up && ul == 16
        && memcmp(up, start, 16) == 0) {        /* the walk below the start */
      seed_sized("#f", BF_NOW_S - 60, "NEW", "a:flood", 100);
      stored = 1;
    }
  }
  assert_int_equal(0, rc);
  assert_true(stored);
  assert_int_equal(1, htrim_acct_loaded());
  assert_int_equal(100, owner_of("a:flood"));   /* the row stored meanwhile */
  assert_true(row_present("#f", BF_NOW_S - 60, "NEW"));
  assert_acct_matches_cf();
}

/* ------------------------------------------------------------------ */
/* Task 8 round-3 minors (folded into Task 9)                          */
/* ------------------------------------------------------------------ */

/** Stop capturing stderr and return what was written (free it). */
static char *captured_log(FILE *tmp)
{
  char *log;
  long len;

  fflush(stderr);
  stderr_restore();
  fseek(tmp, 0, SEEK_END);
  len = ftell(tmp);
  rewind(tmp);
  log = (char *)calloc(1, (size_t)len + 1);
  assert_non_null(log);
  assert_int_equal((size_t)len, fread(log, 1, (size_t)len, tmp));
  fclose(tmp);
  return log;
}

/* Minor 1: a target already in the undecided set is not added again --
 * two caller slices that each leave #aa undecided add one range, hinted
 * once and counted once. */
static void test_undecided_target_not_added_twice(void **state)
{
  struct htrim_params p = params(0);
  struct htrim_slice *s;
  char ts[32], late[32], mid[16], *log;
  FILE *tmp;
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "a%05d", i);
    seed_plain("#aa", ts_ago(ts, sizeof ts, 1, 30000 - i), mid, "a:bob", NULL);
  }
  seed_targets("#aa", ts);
  s = htrim_slice_begin(0);
  assert_non_null(s);
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "a%05d", i);
    stage_del(s, HTRIM_PATH_AGEOUT, "#aa", ts_ago(ts, sizeof ts, 1, 30000 - i), mid, 1);
  }
  assert_int_equal(10001, htrim_slice_commit(s));    /* #aa undecided */
  seed_plain("#aa", ts_ago(late, sizeof late, 1, 100), "late", "a:bob", NULL);
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#aa", late, "late", 1);
  assert_int_equal(1, htrim_slice_commit(s));        /* ... and again */
  assert_true(targets_has("#aa"));
  assert_int_equal(0, fake_db_suggest_calls(st.messages));   /* caller slices */

  stderr_capture(&tmp);
  run_until_idle(&p);                  /* an engine slice issues the hint */
  log = captured_log(tmp);
  assert_int_equal(1, fake_db_suggest_calls(st.messages));
  assert_non_null(strstr(log, "compaction hint on messages: 1 undecided target range,"));
  free(log);
}

/* Minor 2: a busy CF's lone suggestion that fails is logged -- one
 * WARNING a streak, as a failed flush is -- the flush stays due, and the
 * first hint that goes through ends the streak. */
static void test_busy_hint_suggest_failure_logged(void **state)
{
  struct htrim_params p = bf_params(0);
  char ts[32], mid[16], *log;
  FILE *tmp;
  int i;
  (void)state;

  p.compact_min_rows = 10;
  ageout_ready();
  for (i = 0; i < 12; i++) {
    snprintf(mid, sizeof mid, "A%02d", i);
    seed_plain("#t", ts_ago(ts, sizeof ts, 8, 100 - i), mid, "a:bob", NULL);
  }
  fake_db_set_busy(st.by_time, 1, 0);           /* a flush in flight */
  fake_db_fail_next_suggest(st.by_time);
  stderr_capture(&tmp);
  htrim_pass_start(&p);
  for (i = 0; i < 5; i++)                       /* age-out; the hints */
    assert_int_equal(1, htrim_run_slice(&p));
  assert_int_equal(1, fake_db_suggest_calls(st.by_time));   /* alone, failed */
  assert_int_equal(0, fake_db_flush_calls(st.by_time));
  fake_db_set_busy(st.by_time, 0, 0);
  run_until_idle(&p);                           /* flushed, suggested */
  log = captured_log(tmp);
  assert_int_equal(1, fake_db_flush_calls(st.by_time));
  assert_int_equal(2, fake_db_suggest_calls(st.by_time));
  assert_int_equal(1, count_of(log, "compaction hint on by_time failed"));
  assert_int_equal(1, count_of(log, "compaction hints on by_time go through again"));
  free(log);
}

/* Minor 5: an owner step carries only its own start.  A step that starts
 * at the owner's first key (no live floor) must not keep an earlier
 * owner's start from the same slice: its walk below would run up to that
 * other owner's keys and remove every entry of the owners sorting between
 * the two alone.  Owner steps here go a:yy (resumed across slices), then
 * a:bb (which runs out above its start and walks below it, over its
 * orphans); a:mm sorts between them and is under its share: it keeps
 * every row and every byte. */
static void test_evict_owner_walks_keep_to_their_owner(void **state)
{
  struct htrim_params pa = bf_params(0);
  struct htrim_params p = ev_params(3);
  struct db_writebatch *wb;
  char ts[32], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX], mid[16];
  unsigned char sz[4];
  int i, btl, bol;
  (void)state;

  ageout_ready();
  seed_plain("#old", ts_ago(ts, sizeof ts, 8, 0), "O1", "a:bob", NULL);
  ageout_pass(&pa);                    /* a live floor: age-out's resume point */
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  htc_size_pack(sz, 100);
  for (i = 0; i < 12; i++) {           /* a:bb's orphans below the floor */
    snprintf(mid, sizeof mid, "G%02d", i);
    btl = htc_bt_key(bt, sizeof bt, (BF_NOW_S - 9 * 86400ULL + (uint64_t)i) * 1000ULL, "#b", mid);
    bol = htc_bo_key(bo, sizeof bo, "a:bb", bt, (size_t)btl);
    assert_int_equal(DB_OK, db_writebatch_put(wb, st.by_owner, bo, (size_t)bol, sz, sizeof sz));
  }
  assert_int_equal(DB_OK, db_writebatch_commit(wb, 0));
  db_writebatch_destroy(wb);
  seed_run("#y", "Y", "a:yy", 30, BF_NOW_S - 3600, 100);   /* 3000: trim 2000 */
  seed_run("#b", "B", "a:bb", 3, BF_NOW_S - 3000, 100);    /* + 1200: trim 500 */
  seed_run("#m", "M", "a:mm", 5, BF_NOW_S - 2400, 100);    /* 500: under share */
  seed_run("#n", "N", "-", 46, BF_NOW_S - 7200, 100);
  reboot();                            /* the boot scan counts the orphans */
  load_acct();
  assert_int_equal(1500, owner_of("a:bb"));
  assert_int_equal(9600, total_now());

  step_us = 1000;                      /* a few entries a 3 ms slice */
  run_until_idle(&p);
  assert_int_equal(1000, owner_of("a:yy"));
  assert_int_equal(1000, owner_of("a:bb"));
  for (i = 0; i < 3; i++) {
    snprintf(mid, sizeof mid, "B%02d", i);
    assert_false(row_present("#b", BF_NOW_S - 3000 + (uint64_t)i, mid));
  }
  assert_int_equal(500, owner_of("a:mm"));
  for (i = 0; i < 5; i++) {
    snprintf(mid, sizeof mid, "M%02d", i);
    assert_true(row_present("#m", BF_NOW_S - 2400 + (uint64_t)i, mid));
  }
  assert_acct_matches_cf();
}

/* ------------------------------------------------------------------ */
/* Emergency eviction (Task 9)                                          */
/* ------------------------------------------------------------------ */

/** Row @a i of the emergency tests: three targets in turn, the oldest in
 * the alphabetically LAST one (the old emergency path took the first
 * target's rows, whatever their age), at 1000 + i seconds. */
static const char *em_target(int i)
{
  static const char *const names[3] = { "#a", "#b", "#c" };
  return names[(i + 2) % 3];
}

static void em_seed(int n)
{
  char mid[16];
  int i;
  for (i = 0; i < n; i++) {
    snprintf(mid, sizeof mid, "E%03d", i);
    seed_sized(em_target(i), 1000 + (uint64_t)i, mid, i % 2 ? "a:bob" : "-", 100);
  }
}

static int em_present(int i)
{
  char mid[16];
  snprintf(mid, sizeof mid, "E%03d", i);
  return row_present(em_target(i), 1000 + (uint64_t)i, mid);
}

/* One budgeted slice of the oldest rows overall, through by_time -- no
 * plan, no gates: the backfill still to run and the totals not loaded
 * change nothing.  The coverage floor moves like an oldest-overall
 * walk's; the targets cleanup (and its CH A - reports) waits for the
 * next engine slice. */
static void test_emergency_one_slice(void **state)
{
  char want[32];
  int i;
  (void)state;

  em_seed(200);
  assert_int_equal(0, htrim_backfill_done());
  assert_int_equal(0, htrim_acct_loaded());
  step_us = 1000;
  assert_int_equal(5, htrim_emergency(5));
  for (i = 0; i < 200; i++)
    assert_int_equal(i >= 5, em_present(i));
  assert_int_equal(htc_parse_ms("1004.000"), htrim_coverage_floor_ms());
  snprintf(want, sizeof want, "%llu", (unsigned long long)htc_parse_ms("1004.000"));
  assert_int_equal(1, meta_is(HTRIM_META_FLOOR, want));
  assert_int_equal(0, coverage_calls);          /* never inside the store */
  assert_int_equal(5, htrim_stats()->deleted[HTRIM_PATH_EMERGENCY]);
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_OLDEST]);
  assert_int_equal(HTRIM_PH_EMERGENCY, htrim_stats()->last_phase);
  assert_int_equal(0, emptied_calls);

  /* The next engine slice tells the coverage callback, once. */
  {
    struct htrim_params p = params(5);
    assert_true(htrim_run_slice(&p) >= 0);
    assert_int_equal(1, coverage_calls);
    assert_true(htrim_run_slice(&p) >= 0);
    assert_int_equal(1, coverage_calls);
  }
}

static void test_emergency_empty_store(void **state)
{
  (void)state;
  step_us = 1000;
  assert_int_equal(0, htrim_emergency(5));
  assert_int_equal(0, htrim_coverage_floor_ms());
  assert_int_equal(-1, meta_is(HTRIM_META_FLOOR, ""));
  assert_int_equal(0, coverage_calls);
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_EMERGENCY]);
}

/* The rows go through the accounting rule like any counted delete; a
 * second emergency resumes past the first one's deletes (it never walks
 * their tombstones again). */
static void test_emergency_counts_and_resumes(void **state)
{
  char bt[HTC_BT_KEY_MAX + 1], ts[32], mid[16];
  const void *lo;
  size_t ll;
  int i, btl;
  (void)state;

  evict_ready();
  em_seed(40);
  assert_int_equal(4000, total_now());
  step_us = 1000;
  assert_int_equal(5, htrim_emergency(5));
  assert_int_equal(3500, total_now());
  assert_acct_matches_cf();

  assert_int_equal(5, htrim_emergency(5));
  snprintf(mid, sizeof mid, "E%03d", 4);
  snprintf(ts, sizeof ts, "%d.000", 1004);
  btl = bt_of(bt, sizeof bt - 1, em_target(4), ts, mid);
  bt[btl] = '\0';                                /* E004 ‖ 0x00 */
  fake_db_last_iter_lower(st.by_time, &lo, &ll);
  assert_int_equal((size_t)btl + 1, ll);
  assert_memory_equal(bt, lo, ll);
  for (i = 0; i < 40; i++)
    assert_int_equal(i >= 10, em_present(i));
  assert_int_equal(3000, total_now());
  assert_int_equal(10, htrim_stats()->deleted[HTRIM_PATH_EMERGENCY]);
  assert_acct_matches_cf();
}

/* Amendments: the emergency arms the targets sweep, like a drain's end;
 * the targets it emptied are reported by the next engine slice -- never
 * from inside the store that ran out of space. */
static void test_emergency_arms_sweep_and_defers_reports(void **state)
{
  struct htrim_params p = params(0);
  (void)state;

  evict_ready();
  seed_sized("#x", 900, "X1", "a:bob", 100);
  seed_sized("#x", 901, "X2", "a:bob", 100);
  seed_targets("#x", "901.000");
  em_seed(20);
  assert_int_equal(0, htrim_tsweep_pending());
  step_us = 1000;
  assert_int_equal(5, htrim_emergency(5));       /* X1, X2, E000..E002 */
  assert_false(row_present("#x", 901, "X2"));
  assert_int_equal(0, emptied_calls);
  assert_true(targets_has("#x"));
  assert_int_equal(1, htrim_tsweep_pending());

  step_us = 0;
  run_until_idle(&p);
  assert_false(targets_has("#x"));
  assert_int_equal(1, emptied_times("#x"));
  assert_int_equal(0, htrim_tsweep_pending());
}

/* A failed commit applies nothing: the rows, the floor, the counters and
 * the totals stay as they were. */
static void test_emergency_commit_failure_applies_nothing(void **state)
{
  int i;
  (void)state;

  evict_ready();
  em_seed(20);
  step_us = 1000;
  fake_db_fail_next_commit(env);
  assert_int_equal(-1, htrim_emergency(5));
  for (i = 0; i < 20; i++)
    assert_true(em_present(i));
  assert_int_equal(0, htrim_coverage_floor_ms());
  assert_int_equal(0, coverage_calls);
  assert_int_equal(0, htrim_stats()->deleted[HTRIM_PATH_EMERGENCY]);
  assert_int_equal(2000, total_now());
  assert_int_equal(0, htrim_tsweep_pending());
}

/* Fix round 1, I1: an undecided hint that failed is re-armed when the
 * same target is undecided again (the de-dup must not swallow it): the
 * slot has no cumulative trigger, so that is its only way back. */
static void test_undecided_hint_retried_after_failure(void **state)
{
  struct htrim_params p = params(0);
  struct htrim_slice *s;
  char ts[32], late[32], mid[16];
  int i;
  (void)state;

  ageout_ready();
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "a%05d", i);
    seed_plain("#aa", ts_ago(ts, sizeof ts, 1, 30000 - i), mid, "a:bob", NULL);
  }
  seed_targets("#aa", ts);
  s = htrim_slice_begin(0);
  assert_non_null(s);
  for (i = 0; i <= 10000; i++) {
    snprintf(mid, sizeof mid, "a%05d", i);
    stage_del(s, HTRIM_PATH_AGEOUT, "#aa", ts_ago(ts, sizeof ts, 1, 30000 - i), mid, 1);
  }
  assert_int_equal(10001, htrim_slice_commit(s));    /* #aa undecided */
  fake_db_fail_next_flush(env);
  run_until_idle(&p);                                 /* its hint: the flush fails */
  assert_int_equal(1, fake_db_flush_calls(st.messages));
  assert_int_equal(0, fake_db_suggest_calls(st.messages));

  seed_plain("#aa", ts_ago(late, sizeof late, 1, 100), "late", "a:bob", NULL);
  s = htrim_slice_begin(0);
  assert_non_null(s);
  stage_del(s, HTRIM_PATH_AGEOUT, "#aa", late, "late", 1);
  assert_int_equal(1, htrim_slice_commit(s));        /* #aa undecided again */
  run_until_idle(&p);                                 /* the hint goes again */
  assert_int_equal(2, fake_db_flush_calls(st.messages));
  assert_int_equal(1, fake_db_suggest_calls(st.messages));
  assert_true(targets_has("#aa"));
}

/* Fix round 1, M3: within 1 s of an emergency that failed or found
 * nothing, the next one is skipped (returns 0 at once, no walk): a store
 * stuck failing (a NoSpace background error) would otherwise pay a whole
 * slice on every message. */
static void test_emergency_skips_a_second_after_nothing(void **state)
{
  unsigned int opens;
  (void)state;

  evict_ready();
  step_us = 0;
  fake_us = 10000000;
  assert_int_equal(0, htrim_emergency(5));            /* nothing indexed */
  em_seed(20);
  opens = fake_db_iter_opens(st.by_time);
  fake_us += 999000;
  assert_int_equal(0, htrim_emergency(5));            /* skipped */
  assert_int_equal(opens, fake_db_iter_opens(st.by_time));
  assert_true(em_present(0));
  fake_us += 2000;                                    /* 1.001 s after it */
  step_us = 1000;
  assert_int_equal(5, htrim_emergency(5));
  assert_false(em_present(0));

  step_us = 0;                                        /* a failure, the same */
  fake_db_fail_next_commit(env);
  assert_int_equal(-1, htrim_emergency(5));
  opens = fake_db_iter_opens(st.by_time);
  fake_us += 500000;
  assert_int_equal(0, htrim_emergency(5));            /* skipped */
  assert_int_equal(opens, fake_db_iter_opens(st.by_time));
  assert_true(em_present(5));
  fake_us += 600000;
  step_us = 1000;
  assert_int_equal(5, htrim_emergency(5));
  assert_false(em_present(5));
  /* After one that deleted rows, the next is not skipped. */
  assert_int_equal(5, htrim_emergency(5));
  assert_false(em_present(10));
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
    cmocka_unit_test_setup_teardown(test_slice_budget_learns_commit_cost, setup, teardown),
    cmocka_unit_test_setup_teardown(test_slice_budget_at_least_one_row, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_carries_past_16_checks, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_carry_goes_first, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_carry_merges_a_retouched_target, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_carry_dropped_on_restart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_caller_slice_recorded_with_phase, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_waits_for_backfill, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_owner_share_first, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_oldest_after_shares, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_hysteresis, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_truncated_plan_spares_compliant_owner, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_orphan_owner_entry, setup, teardown),
    cmocka_unit_test_setup_teardown(test_drain_suggests_compaction, setup, teardown),
    cmocka_unit_test_setup_teardown(test_compaction_hint_cumulative, setup, teardown),
    cmocka_unit_test_setup_teardown(test_floor_cleared_when_aged_past, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_cap_zero_idle, setup, teardown),
    cmocka_unit_test_setup_teardown(test_tsweep_removes_target_emptied_out_of_order, setup, teardown),
    cmocka_unit_test_setup_teardown(test_tsweep_after_failed_cleanup, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cleanup_unbudgeted_slice_keeps_the_carry, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_resume_persisted_across_restart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_late_row_survives_restart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_owner_resumes_past_its_deleted_head, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_owner_drift_ends, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_oldest_exhausted_recounts, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_oldest_starts_at_ageout_point, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_step_ends_when_share_pct_zero, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_step_ends_when_quota_off, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_owner_step_starts_past_aged_out_head, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emptiness_undecided_past_skip_limit, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_late_rows_by_key_skip_the_run, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_late_rows_overflow_rewinds, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_oldest_resumes_past_ageout, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_oldest_exhausted_from_bound_recounts, setup, teardown),
    cmocka_unit_test_setup_teardown(test_ageout_due_rows_survive_restart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_caller_slice_issues_no_hint, setup, teardown),
    cmocka_unit_test_setup_teardown(test_backfill_rows_behind_walk_all_age_out, setup, teardown),
    cmocka_unit_test_setup_teardown(test_hint_skips_flush_of_busy_cf, setup, teardown),
    cmocka_unit_test_setup_teardown(test_hint_on_a_cf_busy_for_good_is_dropped, setup, teardown),
    cmocka_unit_test_setup_teardown(test_undecided_hint_waits_for_an_engine_slice, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_owner_from_floor_runs_out_recounts, setup, teardown),
    cmocka_unit_test_setup_teardown(test_hint_flush_failure_keeps_the_count, setup, teardown),
    cmocka_unit_test_setup_teardown(test_drain_start_keeps_a_due_hint, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_orphan_below_floor_over_share, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_below_floor_walk_resumes, setup, teardown),
    cmocka_unit_test_setup_teardown(test_failed_prefix_hint_survives_the_next_drain, setup, teardown),
    cmocka_unit_test_setup_teardown(test_undecided_targets_hinted_apart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_failing_hint_backs_off, setup, teardown),
    cmocka_unit_test_setup_teardown(test_undecided_hint_logs_targets, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_drift_after_both_phases_recounts, setup, teardown),
    cmocka_unit_test_setup_teardown(test_undecided_target_not_added_twice, setup, teardown),
    cmocka_unit_test_setup_teardown(test_busy_hint_suggest_failure_logged, setup, teardown),
    cmocka_unit_test_setup_teardown(test_evict_owner_walks_keep_to_their_owner, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emergency_one_slice, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emergency_empty_store, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emergency_counts_and_resumes, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emergency_arms_sweep_and_defers_reports, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emergency_commit_failure_applies_nothing, setup, teardown),
    cmocka_unit_test_setup_teardown(test_undecided_hint_retried_after_failure, setup, teardown),
    cmocka_unit_test_setup_teardown(test_emergency_skips_a_second_after_nothing, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
