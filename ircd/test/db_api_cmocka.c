/*
 * db_api_cmocka.c - storage API spec: bounded iterators, range delete,
 * compaction hint.
 *
 * One spec, two backends: compiled plain, this links the in-memory
 * fake (fake_db.c/.h, no RocksDB) as db_api_fake_cmocka.  Compiled
 * with -DDB_API_REAL, it links the real RocksDB backend
 * (../db_rocksdb.o) against a mkdtemp()'d env as db_api_rocksdb_cmocka.
 * Every test (other than the REAL-only snapshot test) runs against
 * both, so the fake cannot drift from what RocksDB actually does --
 * in particular the iterator-bound-lifetime behaviour in
 * test_bounded_iter_owns_bounds (RocksDB's C readoptions otherwise
 * keep only a pointer to the caller's bound bytes).
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

#ifdef DB_API_REAL
#include <dirent.h>
#include <unistd.h>
#else
#include "fake_db.h"
#endif

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

static struct db_env  *env;
static struct db_cf   *cf;
static struct db_iter *it;

#ifdef DB_API_REAL
static char g_tmpdir[64];

/* RocksDB env directories are flat (SST/log/manifest files, no
 * subdirectories) at the sizes this suite ever reaches. */
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

static int test_setup(void **state)
{
  (void)state;
  it = NULL;
#ifdef DB_API_REAL
  {
    static const char tmpl[] = "/tmp/dbapiXXXXXX";
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
  assert_int_equal(db_cf_open(env, "test", NULL, &cf), DB_OK);
  return 0;
}

static int test_teardown(void **state)
{
  (void)state;
  if (it) {
    db_iter_close(it);
    it = NULL;
  }
#ifdef DB_API_REAL
  db_env_close(env);
  rm_rf(g_tmpdir);
#else
  fake_db_free(env);
#endif
  env = NULL;
  cf = NULL;
  return 0;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/** A string literal as (pointer, length) with embedded NULs kept. */
#define B(lit) (lit), (sizeof(lit) - 1)

/** One committed write batch per key, value "v". */
static void put(const void *k, size_t kl)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(db_writebatch_put(wb, cf, k, kl, "v", 1), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
}

static void assert_key(struct db_iter *i, const void *k, size_t kl)
{
  size_t klen = 0;
  const void *kp;
  assert_true(db_iter_valid(i));
  kp = db_iter_key(i, &klen);
  assert_non_null(kp);
  assert_int_equal((int)klen, (int)kl);
  assert_memory_equal(kp, k, kl);
}

static void be64_encode(uint64_t v, unsigned char out[8])
{
  int i;
  for (i = 0; i < 8; i++)
    out[7 - i] = (unsigned char)(v >> (8 * i));
}

static void seed_abcd(void)
{
  put(B("a"));
  put(B("b"));
  put(B("c"));
  put(B("d"));
}

static void seed_abcde(void)
{
  put(B("a"));
  put(B("b"));
  put(B("c"));
  put(B("d"));
  put(B("e"));
}

/* ------------------------------------------------------------------ */
/* db_iter_open_bounded                                                */
/* ------------------------------------------------------------------ */

static void test_bounded_iter_half_open(void **state)
{
  (void)state;
  seed_abcd();

  it = db_iter_open_bounded(env, cf, NULL, B("b"), B("d"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, B("b"));
  db_iter_next(it);
  assert_key(it, B("c"));
  db_iter_next(it);
  assert_false(db_iter_valid(it));
}

/* Review Focus 1: RocksDB's C readoptions keep only a pointer to the
 * caller's bound bytes -- a bound built in a stack buffer dangles once
 * the caller reuses it, unless db_iter_open_bounded copies it. */
static void test_bounded_iter_owns_bounds(void **state)
{
  char lo[2] = "b", hi[2] = "d";
  (void)state;
  seed_abcd();

  it = db_iter_open_bounded(env, cf, NULL, lo, 1, hi, 1);
  assert_non_null(it);
  lo[0] = 'z';
  hi[0] = 'a';

  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, B("b"));
  db_iter_next(it);
  assert_key(it, B("c"));
  db_iter_next(it);
  assert_false(db_iter_valid(it));
}

static void test_bounded_iter_seek_clamps(void **state)
{
  (void)state;
  seed_abcd();

  it = db_iter_open_bounded(env, cf, NULL, B("b"), B("d"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek(it, B("a")), DB_OK);
  assert_key(it, B("b"));
  assert_int_equal(db_iter_seek(it, B("d")), DB_NOTFOUND);
}

static void test_bounded_iter_null_bounds(void **state)
{
  (void)state;
  seed_abcd();

  it = db_iter_open_bounded(env, cf, NULL, NULL, 0, NULL, 0);
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, B("a"));
  db_iter_next(it);
  assert_key(it, B("b"));
  db_iter_next(it);
  assert_key(it, B("c"));
  db_iter_next(it);
  assert_key(it, B("d"));
  db_iter_next(it);
  assert_false(db_iter_valid(it));
}

static void test_bounded_iter_be64_upper(void **state)
{
  unsigned char k1[8], k2[8], hi[8];
  char key1[32], key2[32];
  size_t kl1, kl2;
  (void)state;

  be64_encode(1000, k1);
  be64_encode(2000, k2);
  be64_encode(1500, hi);

  memcpy(key1, k1, 8);
  memcpy(key1 + 8, "#a\0M1", 5);
  kl1 = 13;

  memcpy(key2, k2, 8);
  memcpy(key2 + 8, "#a\0M2", 5);
  kl2 = 13;

  put(key1, kl1);
  put(key2, kl2);

  it = db_iter_open_bounded(env, cf, NULL, NULL, 0, hi, 8);
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, key1, kl1);
  db_iter_next(it);
  assert_false(db_iter_valid(it));
}

/* ------------------------------------------------------------------ */
/* db_delete_range                                                     */
/* ------------------------------------------------------------------ */

static void test_delete_range_half_open(void **state)
{
  (void)state;
  seed_abcde();

  assert_int_equal(db_delete_range(env, cf, B("b"), B("d")), DB_OK);
  assert_int_equal(db_exists(env, cf, B("a"), NULL), DB_OK);
  assert_int_equal(db_exists(env, cf, B("b"), NULL), DB_NOTFOUND);
  assert_int_equal(db_exists(env, cf, B("c"), NULL), DB_NOTFOUND);
  assert_int_equal(db_exists(env, cf, B("d"), NULL), DB_OK);
  assert_int_equal(db_exists(env, cf, B("e"), NULL), DB_OK);
}

static void test_delete_range_whole_text_cf(void **state)
{
  (void)state;
  put(B("#chan\0acct"));
  put(B("&x\0y"));
  put(B("zz"));

  assert_int_equal(db_delete_range(env, cf, "", 0, "\xff\xff\xff\xff", 4), DB_OK);

  it = db_iter_open(env, cf, NULL);
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_NOTFOUND);
  assert_false(db_iter_valid(it));
}

/* ------------------------------------------------------------------ */
/* db_suggest_compact                                                  */
/* ------------------------------------------------------------------ */

static void test_suggest_compact_returns(void **state)
{
  (void)state;
  seed_abcd();

  assert_int_equal(db_suggest_compact(env, cf, NULL, 0, NULL, 0), DB_OK);
  assert_int_equal(db_suggest_compact(env, cf, B("a"), B("c")), DB_OK);

  assert_int_equal(db_exists(env, cf, B("a"), NULL), DB_OK);
  assert_int_equal(db_exists(env, cf, B("b"), NULL), DB_OK);
  assert_int_equal(db_exists(env, cf, B("c"), NULL), DB_OK);
  assert_int_equal(db_exists(env, cf, B("d"), NULL), DB_OK);
}

/* The trim engine's emptiness check seeks the LAST key of a target's
 * bounded range (a drain deletes from the head, so the tail is live and
 * the seek never walks the head's tombstones).  SeekToLast must honour
 * both bounds: RocksDB 9.10 include/rocksdb/options.h -- "If
 * iterate_upper_bound is not null, SeekToLast() will position the
 * iterator at the first key smaller than iterate_upper_bound", and
 * iterate_lower_bound "defines the smallest key at which the backward
 * iterator can return an entry". */
static void test_bounded_iter_seek_last(void **state)
{
  struct db_writebatch *wb;
  (void)state;
  seed_abcd();

  it = db_iter_open_bounded(env, cf, NULL, B("b"), B("d"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("c"));
  db_iter_prev(it);
  assert_key(it, B("b"));
  db_iter_prev(it);
  assert_false(db_iter_valid(it));
  db_iter_close(it);

  /* Keys on both sides of the range, none inside it. */
  it = db_iter_open_bounded(env, cf, NULL, B("bb"), B("c"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_NOTFOUND);
  assert_false(db_iter_valid(it));
  db_iter_close(it);

  /* A target-shaped range [t\0, t\x01) between live neighbours, whose
   * own rows were all deleted (tombstones on RocksDB). */
  put(B("#a\0x"));
  put(B("#b\0" "1"));
  put(B("#b\0" "2"));
  put(B("#c\0z"));
  it = db_iter_open_bounded(env, cf, NULL, B("#b\0"), B("#b\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("#b\0" "2"));
  db_iter_close(it);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(db_writebatch_del(wb, cf, B("#b\0" "1")), DB_OK);
  assert_int_equal(db_writebatch_del(wb, cf, B("#b\0" "2")), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
  it = db_iter_open_bounded(env, cf, NULL, B("#b\0"), B("#b\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_NOTFOUND);
  assert_false(db_iter_valid(it));
}

/* The shapes history.c's prefix-bounded lookups rely on (Task 7 fix
 * round): a msgid miss in [m\0, m\x01) is DB_NOTFOUND, never the next
 * msgid's row; a LATEST-style seek past a target's last row is
 * DB_NOTFOUND and seek_last falls back to that row; the walk back stops
 * at the target's first row, never reaching the previous target. */
static void test_bounded_iter_prefix_lookups(void **state)
{
  (void)state;
  put(B("m0\0" "#x"));
  put(B("m2\0" "#y"));
  it = db_iter_open_bounded(env, cf, NULL, B("m1\0"), B("m1\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek(it, B("m1\0")), DB_NOTFOUND);
  assert_false(db_iter_valid(it));
  db_iter_close(it);

  put(B("#a\0" "100"));
  put(B("#b\0" "100"));
  put(B("#b\0" "200"));
  put(B("#c\0" "100"));
  it = db_iter_open_bounded(env, cf, NULL, B("#b\0"), B("#b\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek(it, B("#b\0" "999")), DB_NOTFOUND);
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("#b\0" "200"));
  assert_int_equal(db_iter_prev(it), DB_OK);
  assert_key(it, B("#b\0" "100"));
  assert_int_equal(db_iter_prev(it), DB_NOTFOUND);
  assert_false(db_iter_valid(it));
  /* A seek inside the range still lands on the first row at or after it. */
  assert_int_equal(db_iter_seek(it, B("#b\0" "150")), DB_OK);
  assert_key(it, B("#b\0" "200"));
  assert_int_equal(db_iter_next(it), DB_NOTFOUND);
  db_iter_close(it);

  /* A name that is a prefix of another -- "#a" and "#ab", the PM pairs
   * "alice:bob" and "alice:bobby": [P\0, P\x01) holds P's rows only, as
   * the longer name's next byte is a name byte (> 0x01).  Both ways
   * round: the shorter name's range never reaches the longer one's rows,
   * and a range holding none of its own is empty from either end. */
  put(B("#ab\0" "050"));
  put(B("#ab\0" "300"));
  it = db_iter_open_bounded(env, cf, NULL, B("#a\0"), B("#a\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, B("#a\0" "100"));
  assert_int_equal(db_iter_next(it), DB_NOTFOUND);
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("#a\0" "100"));
  assert_int_equal(db_iter_seek(it, B("#a\0" "200")), DB_NOTFOUND);
  db_iter_close(it);
  it = db_iter_open_bounded(env, cf, NULL, B("#ab\0"), B("#ab\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, B("#ab\0" "050"));
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("#ab\0" "300"));
  assert_int_equal(db_iter_prev(it), DB_OK);
  assert_key(it, B("#ab\0" "050"));
  assert_int_equal(db_iter_prev(it), DB_NOTFOUND);
  db_iter_close(it);

  put(B("alice:bobby\0" "100"));
  it = db_iter_open_bounded(env, cf, NULL, B("alice:bob\0"), B("alice:bob\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_NOTFOUND);
  assert_int_equal(db_iter_seek_last(it), DB_NOTFOUND);
  db_iter_close(it);
  put(B("alice:bob\0" "200"));
  it = db_iter_open_bounded(env, cf, NULL, B("alice:bob\0"), B("alice:bob\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("alice:bob\0" "200"));
  assert_int_equal(db_iter_next(it), DB_NOTFOUND);
  assert_int_equal(db_iter_seek(it, B("alice:bob\0" "150")), DB_OK);
  assert_key(it, B("alice:bob\0" "200"));
  assert_int_equal(db_iter_seek(it, B("alice:bob\0" "250")), DB_NOTFOUND);
}

/* A limited iterator (Task 8 fix round, I3): a positioning call that
 * would step over more deleted entries than its cap returns
 * DB_INCOMPLETE -- neither found nor not found -- instead of walking the
 * whole run; within the cap, or past a live row, it behaves as
 * db_iter_open_bounded.  (RocksDB's count also takes the hidden versions
 * a tombstone shadows, so the caps here leave a wide margin.) */
static void test_bounded_iter_skip_limit(void **state)
{
  struct db_writebatch *wb;
  char k[16];
  int i;
  (void)state;

  put(B("#s\0x"));
  put(B("#u\0x"));
  for (i = 0; i < 200; i++) {
    snprintf(k, sizeof k, "#t%c%04d", 0, i);
    put(k, 7);
  }
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  for (i = 0; i < 200; i++) {
    snprintf(k, sizeof k, "#t%c%04d", 0, i);
    assert_int_equal(db_writebatch_del(wb, cf, k, 7), DB_OK);
  }
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);

  it = db_iter_open_bounded_limited(env, cf, NULL, B("#t\0"), B("#t\x01"), 50);
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_INCOMPLETE);
  assert_false(db_iter_valid(it));
  db_iter_close(it);
  it = db_iter_open_bounded_limited(env, cf, NULL, B("#t\0"), B("#t\x01"), 100000);
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_NOTFOUND);
  db_iter_close(it);
  it = db_iter_open_bounded(env, cf, NULL, B("#t\0"), B("#t\x01"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_NOTFOUND);
  db_iter_close(it);

  /* A live row at the tail: seek_last lands on it at once; from the head
   * the run is in the way. */
  put(B("#t\0" "9999"));
  it = db_iter_open_bounded_limited(env, cf, NULL, B("#t\0"), B("#t\x01"), 50);
  assert_non_null(it);
  assert_int_equal(db_iter_seek_last(it), DB_OK);
  assert_key(it, B("#t\0" "9999"));
  assert_int_equal(db_iter_seek_first(it), DB_INCOMPLETE);
  assert_false(db_iter_valid(it));
  db_iter_close(it);
  it = NULL;
}

/* db_flush_cf: a non-waiting flush returns at once with DB_OK. */
static void test_flush_cf_returns(void **state)
{
  (void)state;
  put(B("a"));
  assert_int_equal(db_flush_cf(env, cf, 0), DB_OK);
  assert_int_equal(db_flush_cf(env, cf, 1), DB_OK);
#ifndef DB_API_REAL
  assert_int_equal(2, fake_db_flush_calls(cf));
#endif
}

/* db_property_u64: a numeric backend property.  history.c polls
 * "rocksdb.background-errors" each trim tick; RocksDB counts background
 * errors on the default CF's stats, so the poll reads it with cf NULL.
 * A healthy env reports 0 (through any CF); a property the backend does
 * not have is DB_NOTFOUND. */
static void test_property_u64(void **state)
{
  uint64_t v;
  (void)state;
  put(B("a"));

  v = 12345;
  assert_int_equal(db_property_u64(env, NULL, "rocksdb.background-errors", &v), DB_OK);
  assert_int_equal(0, v);
  v = 12345;
  assert_int_equal(db_property_u64(env, cf, "rocksdb.background-errors", &v), DB_OK);
  assert_int_equal(0, v);
  assert_int_equal(db_property_u64(env, NULL, "rocksdb.no-such-property", &v), DB_NOTFOUND);
  assert_int_not_equal(db_property_u64(env, NULL, NULL, &v), DB_OK);
  assert_int_not_equal(db_property_u64(env, NULL, "rocksdb.background-errors", NULL), DB_OK);
}

/* ------------------------------------------------------------------ */
/* Real-backend-only: snapshot isolation through a bounded iterator    */
/* ------------------------------------------------------------------ */

#ifdef DB_API_REAL
static void test_bounded_iter_snapshot(void **state)
{
  struct db_snapshot *snap;
  (void)state;
  seed_abcd();

  snap = db_snapshot_new(env);
  assert_non_null(snap);
  put(B("bb"));   /* sorts between "b" and "c"; written after the snapshot */

  it = db_iter_open_bounded(env, cf, snap, B("b"), B("d"));
  assert_non_null(it);
  assert_int_equal(db_iter_seek_first(it), DB_OK);
  assert_key(it, B("b"));
  db_iter_next(it);
  assert_key(it, B("c"));
  db_iter_next(it);
  assert_false(db_iter_valid(it));

  db_snapshot_destroy(snap);
}

/* db_env_opts.deletion_heavy_cfs (Task 8): the deletion-triggered
 * compaction marker on a CF that already exists when the env opens, and
 * on one db_cf_open creates; its SST files (a compaction flushes the
 * memtable) are written and compacted with it, and the rows read back
 * after a reopen.  An options call: no seam shows the marker itself. */
static void test_deletion_heavy_cfs_open(void **state)
{
  static const char *const heavy[] = { "test", "heavy", NULL };
  struct db_env_opts o;
  struct db_writebatch *wb;
  struct db_cf *h;
  struct db_val v = { NULL, 0 };
  char k[16];
  int i;
  (void)state;

  memset(&o, 0, sizeof o);
  o.deletion_heavy_cfs = heavy;
  o.deletion_window = 128;
  o.deletion_trigger = 64;
  put(B("keep"));
  db_env_close(env);                          /* reopened with the option */
  assert_int_equal(db_env_open(g_tmpdir, &o, 8, &env), DB_OK);
  assert_int_equal(db_cf_open(env, "test", NULL, &cf), DB_OK);
  assert_int_equal(db_cf_open(env, "heavy", NULL, &h), DB_OK);   /* created */

  for (i = 0; i < 300; i++) {
    snprintf(k, sizeof k, "k%04d", i);
    wb = db_writebatch_new(env);
    assert_non_null(wb);
    assert_int_equal(db_writebatch_put(wb, h, k, strlen(k), "v", 1), DB_OK);
    assert_int_equal(db_writebatch_put(wb, cf, k, strlen(k), "v", 1), DB_OK);
    assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
    db_writebatch_destroy(wb);
  }
  assert_int_equal(db_env_compact(env, h), DB_OK);
  wb = db_writebatch_new(env);
  assert_non_null(wb);
  for (i = 0; i < 299; i++) {
    snprintf(k, sizeof k, "k%04d", i);
    assert_int_equal(db_writebatch_del(wb, h, k, strlen(k)), DB_OK);
    assert_int_equal(db_writebatch_del(wb, cf, k, strlen(k)), DB_OK);
  }
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
  assert_int_equal(db_env_compact(env, h), DB_OK);
  assert_int_equal(db_env_compact(env, cf), DB_OK);

  db_env_close(env);
  assert_int_equal(db_env_open(g_tmpdir, &o, 8, &env), DB_OK);
  assert_int_equal(db_cf_open(env, "test", NULL, &cf), DB_OK);
  assert_int_equal(db_cf_open(env, "heavy", NULL, &h), DB_OK);
  assert_int_equal(db_get(env, h, B("k0299"), NULL, &v), DB_OK);
  db_val_free(&v);
  assert_int_equal(db_get(env, h, B("k0000"), NULL, &v), DB_NOTFOUND);
  assert_int_equal(db_get(env, cf, B("keep"), NULL, &v), DB_OK);
  db_val_free(&v);
}
#endif

/* ------------------------------------------------------------------ */

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(test_bounded_iter_half_open, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_owns_bounds, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_seek_clamps, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_null_bounds, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_be64_upper, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_delete_range_half_open, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_delete_range_whole_text_cf, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_suggest_compact_returns, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_seek_last, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_prefix_lookups, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_bounded_iter_skip_limit, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_flush_cf_returns, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_property_u64, test_setup, test_teardown),
#ifdef DB_API_REAL
    cmocka_unit_test_setup_teardown(test_bounded_iter_snapshot, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(test_deletion_heavy_cfs_open, test_setup, test_teardown),
#endif
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
