/*
 * crdt_hlc_cmocka.c - the HLC_MAX_FORWARD_MS bound on hlc_receive_bounded.
 *
 * A peer reading more than max_forward_ms ahead of our wall clock is
 * refused: the clock is not adopted from it, and advances exactly as a
 * local event at now_ms instead. max_forward_ms of 0 is unbounded.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../../include/crdt_hlc.h"

static void test_within_bound_adopts(void **state)
{
  struct HLC local = { 1000, 0, 1 };
  struct HLC remote = { 31000, 5, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, 60000, &rej);

  assert_int_equal(0, rej);
  assert_true(r.physical_ms == 31000);
  assert_int_equal(6, r.logical);
}

static void test_at_bound_adopts(void **state)
{
  struct HLC local = { 1000, 0, 1 };
  struct HLC remote = { 61000, 5, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, 60000, &rej);

  assert_int_equal(0, rej);
  assert_true(r.physical_ms == 61000);
}

static void test_beyond_bound_refuses(void **state)
{
  struct HLC local = { 1000, 0, 1 };
  struct HLC remote = { 61001, 5, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, 60000, &rej);

  assert_int_equal(1, rej);
  assert_true(r.physical_ms == 1000);
  assert_int_equal(1, r.logical);
}

static void test_beyond_bound_wall_moved(void **state)
{
  struct HLC local = { 900, 7, 1 };
  struct HLC remote = { 99999999, 5, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, 60000, &rej);

  assert_int_equal(1, rej);
  assert_true(r.physical_ms == 1000);
  assert_int_equal(0, r.logical);
}

static void test_zero_is_unbounded(void **state)
{
  struct HLC local = { 1000, 0, 1 };
  struct HLC remote = { 1000000000000ULL, 5, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, 0, &rej);

  assert_int_equal(0, rej);
  assert_true(r.physical_ms == 1000000000000ULL);
}

static void test_remote_behind_unchanged(void **state)
{
  struct HLC local = { 5000, 3, 1 };
  struct HLC remote = { 1000, 9, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, 60000, &rej);

  assert_int_equal(0, rej);
  assert_true(r.physical_ms == 5000);
  assert_int_equal(4, r.logical);
}

/* I1 fix: the bound check must not compute now_ms + max_forward_ms — that
 * sum can overflow uint64_t when max_forward_ms is very large (as happens
 * when a negative FEAT_HLC_MAX_FORWARD_MS sign-extends on the parse.c call
 * site before this fix). A huge max_forward_ms must still mean "basically
 * unbounded", not "wrap around and refuse everything". */
static void test_huge_max_still_adopts(void **state)
{
  struct HLC local = { 1000, 0, 1 };
  struct HLC remote = { 1000000000000ULL, 5, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, UINT64_MAX, &rej);

  assert_int_equal(0, rej);
  assert_true(r.physical_ms == 1000000000000ULL);
}

static void test_huge_max_remote_behind_unchanged(void **state)
{
  struct HLC local = { 5000, 3, 1 };
  struct HLC remote = { 1000, 9, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  r = hlc_receive_bounded(&local, &remote, 1000, UINT64_MAX - 500, &rej);

  assert_int_equal(0, rej);
  assert_true(r.physical_ms == 5000);
  assert_int_equal(4, r.logical);
}

/* Logical overflow carries into physical time; it never wraps to 0 at
 * the same physical_ms, which minted an older stamp and, with the msgid's
 * 12-bit counter (65536 % 4096 == 0), a duplicate msgid. */
static void test_local_overflow_carries(void **state)
{
  struct HLC local = { UINT64_C(1) << 50, UINT16_MAX, 1 };
  struct HLC old = local;
  struct HLC r;
  (void)state;

  /* The wall clock (now) is far behind physical_ms: the clock is pinned. */
  r = hlc_local_event(&local);

  assert_true(hlc_compare(&r, &old) > 0);
  assert_true(r.physical_ms == old.physical_ms + 1);
  assert_int_equal(0, r.logical);
}

static void test_receive_overflow_carries(void **state)
{
  struct HLC local = { 5000, 3, 1 };
  struct HLC remote = { 9000, UINT16_MAX, 2 };
  struct HLC same = { 9001, UINT16_MAX, 2 };
  int rej = -1;
  struct HLC r;
  (void)state;

  /* Remote ahead with a full counter: the result is after the remote. */
  r = hlc_receive_bounded(&local, &remote, 1000, 0, &rej);
  assert_int_equal(0, rej);
  assert_true(hlc_compare(&r, &remote) > 0);
  assert_true(r.physical_ms == 9001);
  assert_int_equal(0, r.logical);

  /* Same physical time, max logical saturated: still after both. */
  r = hlc_receive_bounded(&local, &same, 1000, 0, &rej);
  assert_true(r.physical_ms == 9002);
  assert_int_equal(0, r.logical);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_within_bound_adopts),
    cmocka_unit_test(test_at_bound_adopts),
    cmocka_unit_test(test_beyond_bound_refuses),
    cmocka_unit_test(test_beyond_bound_wall_moved),
    cmocka_unit_test(test_zero_is_unbounded),
    cmocka_unit_test(test_remote_behind_unchanged),
    cmocka_unit_test(test_huge_max_still_adopts),
    cmocka_unit_test(test_huge_max_remote_behind_unchanged),
    cmocka_unit_test(test_local_overflow_carries),
    cmocka_unit_test(test_receive_overflow_carries),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
