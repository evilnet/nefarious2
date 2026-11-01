/* ipcheck_refund_cmocka.c - unit tests for ircd/ipcheck_refund.c.
 * Compiled against a 1-bucket, 2-slot table (see test/Makefile.in) so a
 * full bucket is reachable with arbitrary account names. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "ipcheck_refund.h"

#define T0 1000000

static int setup(void **state)
{
  (void)state;
  ipcheck_refund_clear();
  return 0;
}

/* limit refunds pass, the next is refused */
static void test_cap(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0,     3, 600));
  assert_true(ipcheck_refund_take("alice", T0 + 1, 3, 600));
  assert_true(ipcheck_refund_take("alice", T0 + 2, 3, 600));
  assert_false(ipcheck_refund_take("alice", T0 + 3, 3, 600));
}

/* the window runs from the first counted refund; refusals do not move it */
static void test_window_from_first_refund(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0, 1, 60));
  assert_false(ipcheck_refund_take("alice", T0 + 30, 1, 60));
  assert_false(ipcheck_refund_take("alice", T0 + 59, 1, 60));
  /* boundary: exactly period after the first refund opens a new window */
  assert_true(ipcheck_refund_take("alice", T0 + 60, 1, 60));
  assert_false(ipcheck_refund_take("alice", T0 + 61, 1, 60));
}

/* accounts have independent budgets */
static void test_accounts_independent(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0, 1, 600));
  assert_false(ipcheck_refund_take("alice", T0, 1, 600));
  assert_true(ipcheck_refund_take("bob", T0, 1, 600));
}

/* one account, two spellings: one budget */
static void test_case_insensitive(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("Alice", T0, 1, 600));
  assert_false(ipcheck_refund_take("alice", T0, 1, 600));
  assert_false(ipcheck_refund_take("ALICE", T0, 1, 600));
}

/* limit or period at zero grants nothing: the feature off */
static void test_disabled(void **state)
{
  (void)state;
  assert_false(ipcheck_refund_take("alice", T0, 0, 600));
  assert_false(ipcheck_refund_take("alice", T0, 3, 0));
  assert_false(ipcheck_refund_take("", T0, 3, 600));
  assert_false(ipcheck_refund_take(NULL, T0, 3, 600));
}

/* a full bucket fails closed: a newcomer gets no refund, and the accounts
 * already in it keep their windows */
static void test_full_bucket_fails_closed(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0,      1, 600));
  assert_true(ipcheck_refund_take("bob",   T0 + 10, 1, 600));
  /* carol finds both slots holding live windows */
  assert_false(ipcheck_refund_take("carol", T0 + 30, 1, 600));
  assert_false(ipcheck_refund_take("carol", T0 + 31, 5, 600));
  /* alice and bob are still exhausted: nobody was evicted */
  assert_false(ipcheck_refund_take("alice", T0 + 40, 1, 600));
  assert_false(ipcheck_refund_take("bob",   T0 + 40, 1, 600));
  /* once a window is over its slot is free again */
  assert_true(ipcheck_refund_take("carol", T0 + 600, 1, 600));
}

/* the review's bypass: accounts that share a bucket, taken in turn inside
 * one window, never draw more than their caps together */
static void test_rotation_keeps_the_cap(void **state)
{
  static const char *const names[] = {"acct0", "acct1", "acct2", "acct3", "acct4"};
  int round, k, granted = 0;
  (void)state;
  for (round = 0; round < 100; ++round)
    for (k = 0; k < 5; ++k)
      granted += ipcheck_refund_take(names[k], T0 + round, 10, 600);
  /* two slots, a cap of 10 each */
  assert_int_equal(granted, 20);
}

/* an expired entry is reused, so a newcomer gets in once a window ends */
static void test_expired_reused_first(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0,       1, 60));
  assert_true(ipcheck_refund_take("bob",   T0 + 100, 1, 60));
  /* alice's window is over; carol takes her slot, bob keeps his */
  assert_true(ipcheck_refund_take("carol", T0 + 110, 1, 60));
  assert_false(ipcheck_refund_take("bob",   T0 + 120, 1, 60));
  assert_false(ipcheck_refund_take("carol", T0 + 120, 1, 60));
}

/* a name longer than the table keeps is still one account */
static void test_long_name(void **state)
{
  const char *name = "averyveryverylongaccountname";
  (void)state;
  assert_true(ipcheck_refund_take(name, T0, 1, 600));
  assert_false(ipcheck_refund_take(name, T0 + 1, 1, 600));
}

/* clear forgets everything */
static void test_clear(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0, 1, 600));
  assert_false(ipcheck_refund_take("alice", T0, 1, 600));
  ipcheck_refund_clear();
  assert_true(ipcheck_refund_take("alice", T0, 1, 600));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_cap, setup),
    cmocka_unit_test_setup(test_window_from_first_refund, setup),
    cmocka_unit_test_setup(test_accounts_independent, setup),
    cmocka_unit_test_setup(test_case_insensitive, setup),
    cmocka_unit_test_setup(test_disabled, setup),
    cmocka_unit_test_setup(test_full_bucket_fails_closed, setup),
    cmocka_unit_test_setup(test_rotation_keeps_the_cap, setup),
    cmocka_unit_test_setup(test_expired_reused_first, setup),
    cmocka_unit_test_setup(test_long_name, setup),
    cmocka_unit_test_setup(test_clear, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
