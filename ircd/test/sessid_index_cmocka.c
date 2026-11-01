/* cmocka suite for the pure session-id -> owner index
 * (include/sessid_index.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/sessid_index.h"

static void test_find_returns_every_owner_of_a_key(void **state)
{
  (void)state;
  struct SessidLink l1, l2, l3;
  int o1, o2, o3;
  void *out[8];

  memset(&l1, 0, sizeof(l1));
  memset(&l2, 0, sizeof(l2));
  memset(&l3, 0, sizeof(l3));

  sessid_index_set(&l1, &o1, "K");
  sessid_index_set(&l2, &o2, "K");
  sessid_index_set(&l3, &o3, "K");

  assert_int_equal(3, (int)sessid_index_find("K", out, 8));
  /* out[0..2] hold &o1, &o2, &o3 in some order. */
  {
    int saw1 = 0, saw2 = 0, saw3 = 0;
    size_t i;
    for (i = 0; i < 3; i++) {
      if (out[i] == &o1) saw1 = 1;
      else if (out[i] == &o2) saw2 = 1;
      else if (out[i] == &o3) saw3 = 1;
    }
    assert_int_equal(saw1, 1);
    assert_int_equal(saw2, 1);
    assert_int_equal(saw3, 1);
  }

  /* cmocka runs every test in one process with no per-test fork, and
   * the index's buckets are a static global: a link left filed when a
   * stack-allocated SessidLink goes out of scope becomes a dangling
   * pointer the NEXT test's lookup can walk into.  Every test that
   * links a local node must unlink it before returning. */
  sessid_index_unlink(&l1);
  sessid_index_unlink(&l2);
  sessid_index_unlink(&l3);
}

static void test_set_moves_owner_to_new_key(void **state)
{
  (void)state;
  struct SessidLink l1;
  int o1;
  void *out[4];

  memset(&l1, 0, sizeof(l1));

  sessid_index_set(&l1, &o1, "K1");
  assert_int_equal(1, (int)sessid_index_find("K1", out, 4));

  sessid_index_set(&l1, &o1, "K2");
  assert_int_equal(0, (int)sessid_index_find("K1", out, 4));
  assert_int_equal(1, (int)sessid_index_find("K2", out, 4));
  assert_ptr_equal(out[0], &o1);

  sessid_index_unlink(&l1);
}

static void test_unlink_removes_only_that_owner(void **state)
{
  (void)state;
  struct SessidLink l1, l2;
  int o1, o2;
  void *out[4];

  memset(&l1, 0, sizeof(l1));
  memset(&l2, 0, sizeof(l2));

  sessid_index_set(&l1, &o1, "K");
  sessid_index_set(&l2, &o2, "K");
  assert_int_equal(2, (int)sessid_index_find("K", out, 4));

  sessid_index_unlink(&l1);
  assert_int_equal(1, (int)sessid_index_find("K", out, 4));
  assert_ptr_equal(out[0], &o2);

  sessid_index_unlink(&l2);
}

static void test_empty_key_is_not_indexed(void **state)
{
  (void)state;
  struct SessidLink l1;
  int o1;

  memset(&l1, 0, sizeof(l1));

  sessid_index_set(&l1, &o1, "");
  assert_int_equal(l1.sl_linked, 0);
  assert_int_equal(0, (int)sessid_index_find("", NULL, 0));
}

static void test_keys_are_case_sensitive(void **state)
{
  (void)state;
  struct SessidLink l1;
  int o1;

  memset(&l1, 0, sizeof(l1));

  sessid_index_set(&l1, &o1, "AbC");
  assert_int_equal(0, (int)sessid_index_find("abc", NULL, 0));
  assert_int_equal(1, (int)sessid_index_find("AbC", NULL, 0));

  sessid_index_unlink(&l1);
}

static void test_find_respects_max_returns_total(void **state)
{
  (void)state;
  struct SessidLink l1, l2, l3;
  int o1, o2, o3;
  void *out[1];

  memset(&l1, 0, sizeof(l1));
  memset(&l2, 0, sizeof(l2));
  memset(&l3, 0, sizeof(l3));

  sessid_index_set(&l1, &o1, "K");
  sessid_index_set(&l2, &o2, "K");
  sessid_index_set(&l3, &o3, "K");

  out[0] = NULL;
  assert_int_equal(3, (int)sessid_index_find("K", out, 1));
  assert_non_null(out[0]);

  sessid_index_unlink(&l1);
  sessid_index_unlink(&l2);
  sessid_index_unlink(&l3);
}

static void test_relink_same_key_is_idempotent(void **state)
{
  (void)state;
  struct SessidLink l1;
  int o1;

  memset(&l1, 0, sizeof(l1));

  sessid_index_set(&l1, &o1, "K");
  sessid_index_set(&l1, &o1, "K");
  assert_int_equal(1, (int)sessid_index_find("K", NULL, 0));

  sessid_index_unlink(&l1);
}

static void test_unlink_unlinked_is_noop(void **state)
{
  (void)state;
  struct SessidLink l1;

  memset(&l1, 0, sizeof(l1));
  sessid_index_unlink(&l1);
  assert_int_equal(l1.sl_linked, 0);
}

/* Bouncer-analyst review (2026-10-24), edit 1: client_find_by_session_id
 * cannot filter to IsUser-only owners through sessid_index_find(key,
 * NULL, 0) -- that call just counts every owner under the key,
 * regardless of what kind of thing it is.  sessid_index_count_if adds a
 * predicate so the filtered count needs no owner storage (max 0). */
static int pred_marker_o1, pred_marker_o3;

static int owner_is_o1_or_o3(void *owner)
{
  return owner == &pred_marker_o1 || owner == &pred_marker_o3;
}

static void test_count_if_filters_without_storage(void **state)
{
  (void)state;
  struct SessidLink l1, l2, l3;
  int o2;

  memset(&l1, 0, sizeof(l1));
  memset(&l2, 0, sizeof(l2));
  memset(&l3, 0, sizeof(l3));

  sessid_index_set(&l1, &pred_marker_o1, "K");
  sessid_index_set(&l2, &o2, "K");
  sessid_index_set(&l3, &pred_marker_o3, "K");

  /* Unfiltered: all three are under "K". */
  assert_int_equal(3, (int)sessid_index_find("K", NULL, 0));

  /* Filtered to the predicate's two matching owners, with no array to
   * fill (the max-0, owners-NULL shape client_find_by_session_id uses
   * for sessid_in_use_locally()). */
  assert_int_equal(2, (int)sessid_index_count_if("K", owner_is_o1_or_o3));

  /* A key nothing is filed under counts zero, filtered or not. */
  assert_int_equal(0, (int)sessid_index_count_if("nope", owner_is_o1_or_o3));

  sessid_index_unlink(&l1);
  sessid_index_unlink(&l2);
  sessid_index_unlink(&l3);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_find_returns_every_owner_of_a_key),
    cmocka_unit_test(test_set_moves_owner_to_new_key),
    cmocka_unit_test(test_unlink_removes_only_that_owner),
    cmocka_unit_test(test_empty_key_is_not_indexed),
    cmocka_unit_test(test_keys_are_case_sensitive),
    cmocka_unit_test(test_find_respects_max_returns_total),
    cmocka_unit_test(test_relink_same_key_is_idempotent),
    cmocka_unit_test(test_unlink_unlinked_is_noop),
    cmocka_unit_test(test_count_if_filters_without_storage),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
