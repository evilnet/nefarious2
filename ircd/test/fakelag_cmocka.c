/*
 * fakelag_cmocka.c - the post-registration fake-lag credit.
 *
 * fakelag_charge() absorbs a charge into the credit before the lag clock
 * is charged.  The credit is one-shot: it only ever decreases.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "fakelag.h"

static void test_no_credit_charges_in_full(void **state)
{
  int credit = 0;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 2), 2);
  assert_int_equal(credit, 0);
}

static void test_credit_absorbs_whole_charge(void **state)
{
  int credit = 20;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 2), 0);
  assert_int_equal(credit, 18);
}

static void test_credit_absorbs_part_of_a_charge(void **state)
{
  int credit = 1;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 3), 2);
  assert_int_equal(credit, 0);
}

static void test_credit_is_one_shot(void **state)
{
  int credit = 20;
  int i, charged = 0;
  (void)state;
  /* Ten 2-second commands ride on the credit, the eleventh pays. */
  for (i = 0; i < 10; i++)
    charged += fakelag_charge(&credit, 2);
  assert_int_equal(charged, 0);
  assert_int_equal(credit, 0);
  assert_int_equal(fakelag_charge(&credit, 2), 2);
  assert_int_equal(credit, 0);
}

static void test_zero_or_negative_lag_charges_nothing(void **state)
{
  int credit = 5;
  (void)state;
  assert_int_equal(fakelag_charge(&credit, 0), 0);
  assert_int_equal(fakelag_charge(&credit, -1), 0);
  assert_int_equal(credit, 5);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_no_credit_charges_in_full),
    cmocka_unit_test(test_credit_absorbs_whole_charge),
    cmocka_unit_test(test_credit_absorbs_part_of_a_charge),
    cmocka_unit_test(test_credit_is_one_shot),
    cmocka_unit_test(test_zero_or_negative_lag_charges_nothing),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
