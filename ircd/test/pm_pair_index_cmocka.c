/* pm_pair_index_cmocka.c - CMocka tests for the PM pair index (W5 Task 11)
 *
 * Links the REAL ircd/pm_pair_index.c (../pm_pair_index.o) against the
 * in-memory store (fake_db.o): the pm_pairs column family that lets
 * CHATHISTORY TARGETS find the PM pairs one identity takes part in without
 * walking every target on the server.
 *
 * Under test:
 *  - pm_pair_split: what counts as a pair key;
 *  - pm_pair_index_key: both components folded;
 *  - stage / unstage: a row under each half;
 *  - walk: either half, any case, never a prefix of another identity;
 *  - rebuild: pairs only, orphans dropped, idempotent, many batches, a
 *    malformed key skipped, a failed commit leaving only whole batches.
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "pm_pair_index.h"
#include "fake_db.h"

#define B(lit) (lit), (sizeof(lit) - 1)

static struct db_env *env;
static struct db_cf *targets;
static struct db_cf *idx;

static int setup(void **state)
{
  (void)state;
  env = fake_db_new();
  assert_int_equal(db_cf_open(env, "targets", NULL, &targets), DB_OK);
  assert_int_equal(db_cf_open(env, "pm_pairs", NULL, &idx), DB_OK);
  return 0;
}

static int teardown(void **state)
{
  (void)state;
  fake_db_free(env);
  env = NULL;
  return 0;
}

static void put(struct db_cf *cf, const char *k, size_t kl, const char *v)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  assert_non_null(wb);
  assert_int_equal(db_writebatch_put(wb, cf, k, kl, v, strlen(v)), DB_OK);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
}

static int has(struct db_cf *cf, const char *k, size_t kl)
{
  return db_exists(env, cf, k, kl, NULL) == DB_OK;
}

static void stage(const char *pair)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  assert_int_equal(pm_pair_index_stage(wb, idx, pair, strlen(pair)), 0);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
}

/* What a walk collected. */
struct walked {
  int n;
  char pairs[16][96];
};

static int collect(const char *pair, size_t plen, void *ctx)
{
  struct walked *w = (struct walked *)ctx;
  if (w->n < 16) {
    memcpy(w->pairs[w->n], pair, plen);
    w->pairs[w->n][plen] = '\0';
  }
  w->n++;
  return 0;
}

static int stop_at_first(const char *pair, size_t plen, void *ctx)
{
  (void)pair;
  (void)plen;
  (*(int *)ctx)++;
  return 1;
}

static void test_pair_split(void **state)
{
  size_t colon = 99;
  (void)state;
  assert_int_equal(pm_pair_split(B("a:b"), &colon), 0);
  assert_int_equal(colon, 1);
  assert_int_equal(pm_pair_split(B("alice:bob"), &colon), 0);
  assert_int_equal(colon, 5);
  assert_int_equal(pm_pair_split(B(":b"), NULL), -1);
  assert_int_equal(pm_pair_split(B("a:"), NULL), -1);
  assert_int_equal(pm_pair_split(B("ab"), NULL), -1);
  assert_int_equal(pm_pair_split(B("a:b:c"), NULL), -1);
  /* A channel whose name holds one ':' is not a pair. */
  assert_int_equal(pm_pair_split(B("#a:b"), NULL), -1);
  assert_int_equal(pm_pair_split(B("&a:b"), NULL), -1);
  assert_int_equal(pm_pair_split("", 0, NULL), -1);
}

static void test_key_folds_both(void **state)
{
  char key[PM_PAIR_INDEX_KEYLEN];
  int n;
  (void)state;
  n = pm_pair_index_key(key, sizeof key, B("Rubin"), B("Rubin:Zed["));
  assert_int_equal(n, (int)sizeof("rubin\0rubin:zed{") - 1);
  assert_memory_equal(key, "rubin\0rubin:zed{", (size_t)n);
  /* Does not fit: -1. */
  assert_int_equal(pm_pair_index_key(key, 8, B("Rubin"), B("Rubin:Zed[")), -1);
}

static void test_stage_both_halves(void **state)
{
  (void)state;
  stage("alice:bob");
  assert_int_equal(fake_db_rows(idx), 2);
  assert_true(has(idx, B("alice\0alice:bob")));
  assert_true(has(idx, B("bob\0alice:bob")));
}

static void test_stage_rejects_non_pair(void **state)
{
  struct db_writebatch *wb = db_writebatch_new(env);
  (void)state;
  assert_int_equal(pm_pair_index_stage(wb, idx, B("#chan")), -1);
  assert_int_equal(db_writebatch_count(wb), 0);
  db_writebatch_destroy(wb);
}

static void test_walk_either_half(void **state)
{
  struct walked w;
  (void)state;
  stage("alice:bob");
  stage("bob:carol");
  stage("dave:erin");

  memset(&w, 0, sizeof w);
  assert_int_equal(pm_pair_index_walk(env, idx, "BOB", collect, &w), 2);
  assert_int_equal(w.n, 2);
  assert_string_equal(w.pairs[0], "alice:bob");
  assert_string_equal(w.pairs[1], "bob:carol");

  /* A prefix of an identity is not that identity. */
  memset(&w, 0, sizeof w);
  assert_int_equal(pm_pair_index_walk(env, idx, "bo", collect, &w), 0);
  assert_int_equal(w.n, 0);

  memset(&w, 0, sizeof w);
  assert_int_equal(pm_pair_index_walk(env, idx, "erin", collect, &w), 1);
  assert_string_equal(w.pairs[0], "dave:erin");
}

static void test_walk_stops(void **state)
{
  int calls = 0;
  (void)state;
  stage("alice:bob");
  stage("bob:carol");
  assert_int_equal(pm_pair_index_walk(env, idx, "bob", stop_at_first, &calls), 1);
  assert_int_equal(calls, 1);
}

static void test_walk_open_failure(void **state)
{
  struct walked w;
  (void)state;
  stage("alice:bob");
  memset(&w, 0, sizeof w);
  fake_db_fail_next_iter_open(env);
  assert_int_equal(pm_pair_index_walk(env, idx, "bob", collect, &w), -1);
}

static void test_unstage_both_halves(void **state)
{
  struct db_writebatch *wb;
  (void)state;
  stage("alice:bob");
  stage("bob:carol");
  wb = db_writebatch_new(env);
  assert_int_equal(pm_pair_index_unstage(wb, idx, B("Alice:Bob")), 0);
  assert_int_equal(db_writebatch_commit(wb, 0), DB_OK);
  db_writebatch_destroy(wb);
  assert_int_equal(fake_db_rows(idx), 2);
  assert_false(has(idx, B("alice\0alice:bob")));
  assert_false(has(idx, B("bob\0alice:bob")));
  assert_true(has(idx, B("bob\0bob:carol")));
  assert_true(has(idx, B("carol\0bob:carol")));
}

static void test_rebuild_indexes_pairs_only(void **state)
{
  (void)state;
  put(targets, B("#chan"), "1790000000.000");
  put(targets, B("alice:bob"), "1790000001.000");
  put(targets, B("bob:carol"), "1790000002.000");
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 4);
  assert_true(has(idx, B("alice\0alice:bob")));
  assert_true(has(idx, B("bob\0alice:bob")));
  assert_true(has(idx, B("bob\0bob:carol")));
  assert_true(has(idx, B("carol\0bob:carol")));
}

static void test_rebuild_drops_orphans(void **state)
{
  (void)state;
  put(targets, B("alice:bob"), "1790000001.000");
  put(idx, B("x\0x:y"), "1");
  put(idx, B("y\0x:y"), "1");
  /* A row whose pair exists but under the wrong identity is an orphan too. */
  put(idx, B("zed\0alice:bob"), "1");
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 2);
  assert_false(has(idx, B("x\0x:y")));
  assert_false(has(idx, B("y\0x:y")));
  assert_false(has(idx, B("zed\0alice:bob")));
  assert_true(has(idx, B("alice\0alice:bob")));
  assert_true(has(idx, B("bob\0alice:bob")));
}

static void test_rebuild_idempotent(void **state)
{
  (void)state;
  put(targets, B("alice:bob"), "1790000001.000");
  put(targets, B("bob:carol"), "1790000002.000");
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 4);
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 4);
  /* Nothing was missing the second time: no row deleted and rewritten. */
  assert_int_equal(fake_db_tombstones(idx), 0);
}

static void test_rebuild_many_batches(void **state)
{
  int i;
  (void)state;
  for (i = 0; i < 5000; i++) {
    char k[32];
    int n = snprintf(k, sizeof k, "a%04d:b%04d", i, i);
    put(targets, k, (size_t)n, "1790000001.000");
  }
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 10000);
  assert_true(has(idx, B("a4999\0a4999:b4999")));
  assert_true(has(idx, B("b0000\0a0000:b0000")));
}

static void test_rebuild_skips_malformed(void **state)
{
  (void)state;
  put(targets, B("a:b:c"), "1790000001.000");
  put(targets, B(":b"), "1790000001.000");
  put(targets, B("#x:y"), "1790000001.000");
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 0);
}

static void test_rebuild_failed_commit(void **state)
{
  int i;
  size_t rows;
  (void)state;
  for (i = 0; i < 1500; i++) {
    char k[32];
    int n = snprintf(k, sizeof k, "a%04d:b%04d", i, i);
    put(targets, k, (size_t)n, "1790000001.000");
  }
  /* The first batch commits, the second fails. */
  fake_db_fail_commit_at(env, 2);
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), -1);
  rows = fake_db_rows(idx);
  assert_true(rows % PM_PAIR_INDEX_BATCH == 0);   /* whole batches only */
  assert_true(rows < 3000);
  /* The next open completes it. */
  assert_int_equal(pm_pair_index_rebuild(env, targets, idx), 0);
  assert_int_equal(fake_db_rows(idx), 3000);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_pair_split),
    cmocka_unit_test(test_key_folds_both),
    cmocka_unit_test_setup_teardown(test_stage_both_halves, setup, teardown),
    cmocka_unit_test_setup_teardown(test_stage_rejects_non_pair, setup, teardown),
    cmocka_unit_test_setup_teardown(test_walk_either_half, setup, teardown),
    cmocka_unit_test_setup_teardown(test_walk_stops, setup, teardown),
    cmocka_unit_test_setup_teardown(test_walk_open_failure, setup, teardown),
    cmocka_unit_test_setup_teardown(test_unstage_both_halves, setup, teardown),
    cmocka_unit_test_setup_teardown(test_rebuild_indexes_pairs_only, setup, teardown),
    cmocka_unit_test_setup_teardown(test_rebuild_drops_orphans, setup, teardown),
    cmocka_unit_test_setup_teardown(test_rebuild_idempotent, setup, teardown),
    cmocka_unit_test_setup_teardown(test_rebuild_many_batches, setup, teardown),
    cmocka_unit_test_setup_teardown(test_rebuild_skips_malformed, setup, teardown),
    cmocka_unit_test_setup_teardown(test_rebuild_failed_commit, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
