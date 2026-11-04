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

static int teardown(void **state)
{
  (void)state;
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

/** Write what the store path writes for one row, then index it through
 * htrim_stage_index in the same batch, commit, and htrim_note_stored. */
static void seed_row(const char *target, const char *ts, const char *msgid,
                     const char *owner, unsigned char flags,
                     const char *reply_parent, const char *redact_parent,
                     size_t ml_len, struct htc_rec *rec_out)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  char mk[HTC_MSG_KEY_MAX], ik[HTC_MSG_KEY_MAX], rk[HTC_MSG_KEY_MAX];
  char bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  char val[81];
  struct htc_rec rec;
  size_t bolen = 0;
  int mkl, ikl, btl, n;

  assert_non_null(wb);
  mkl = htc_msg_key(mk, sizeof mk, target, ts, msgid);
  assert_true(mkl > 0);
  n = snprintf(val, sizeof val, "%s|%u|%s|%s|", owner, (unsigned)flags,
               reply_parent, redact_parent);
  assert_true(n > 0 && n < 80);
  memset(val + n, 'x', 80 - (size_t)n);
  val[80] = '\0';
  assert_int_equal(DB_OK, db_writebatch_put(wb, st.messages, mk, (size_t)mkl, val, 80));

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
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
