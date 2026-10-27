/* ipcheck_refund_cmocka.c - unit tests for ircd/ipcheck_refund.c.
 * Compiled against a 1-bucket, 2-slot table (see test/Makefile.in) so the
 * eviction paths are reachable with arbitrary account names. */
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

/* a full bucket evicts the account whose window opened earliest, which
 * then gets a fresh window; the others keep theirs */
static void test_eviction_grants_fresh_window(void **state)
{
  (void)state;
  assert_true(ipcheck_refund_take("alice", T0,      1, 600));
  assert_true(ipcheck_refund_take("bob",   T0 + 10, 1, 600));
  /* alice and bob are both exhausted */
  assert_false(ipcheck_refund_take("alice", T0 + 20, 1, 600));
  assert_false(ipcheck_refund_take("bob",   T0 + 20, 1, 600));
  /* carol needs a slot: alice (the oldest window) goes */
  assert_true(ipcheck_refund_take("carol", T0 + 30, 1, 600));
  assert_false(ipcheck_refund_take("bob",   T0 + 40, 1, 600));
  assert_true(ipcheck_refund_take("alice", T0 + 40, 1, 600));
}

/* an expired entry is reused before a live one is evicted */
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
    cmocka_unit_test_setup(test_eviction_grants_fresh_window, setup),
    cmocka_unit_test_setup(test_expired_reused_first, setup),
    cmocka_unit_test_setup(test_long_name, setup),
    cmocka_unit_test_setup(test_clear, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
