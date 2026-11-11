/*
 * iauth_respawn_cmocka.c - when an IAuth program that went away on its
 * own is started again.
 *
 * iauth_respawn_exited() is told how long the program ran and returns the
 * delay before the next start: none for the first exit after a good run,
 * otherwise 5 s doubling to a 300 s cap.  A program that has run
 * IAUTH_RESPAWN_STABLE seconds ends the streak (iauth_respawn_stable(), or
 * an exit after that long).
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "iauth_respawn.h"

static void test_crash_after_good_run_restarts_at_once(void **state)
{
  struct IAuthRespawn r = { 0, 0 };
  (void)state;
  assert_int_equal(iauth_respawn_exited(&r, 3600), 0);
  assert_int_equal(r.failures, 1);
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_FAST), 5);
}

static void test_failing_at_start_backs_off_to_the_cap(void **state)
{
  static const unsigned int want[] = { 5, 10, 20, 40, 80, 160, 300, 300, 300 };
  struct IAuthRespawn r = { 0, 0 };
  unsigned int i;
  (void)state;
  for (i = 0; i < sizeof(want) / sizeof(want[0]); i++)
    assert_int_equal(iauth_respawn_exited(&r, 0), want[i]);
  assert_int_equal(r.failures, 9);
}

static void test_first_exit_too_soon_is_not_immediate(void **state)
{
  struct IAuthRespawn r = { 0, 0 };
  (void)state;
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_FAST - 1), 5);
}

static void test_flapping_after_a_good_run_backs_off(void **state)
{
  struct IAuthRespawn r = { 0, 0 };
  (void)state;
  /* Up 30 s each time: long enough not to be a failed start, too short
   * to end the streak. */
  assert_int_equal(iauth_respawn_exited(&r, 30), 0);
  assert_int_equal(iauth_respawn_exited(&r, 30), 5);
  assert_int_equal(iauth_respawn_exited(&r, 30), 10);
  assert_int_equal(iauth_respawn_exited(&r, 30), 20);
}

static void test_a_long_run_ends_the_streak(void **state)
{
  struct IAuthRespawn r = { 0, 0 };
  unsigned int i;
  (void)state;
  for (i = 0; i < 10; i++)
    iauth_respawn_exited(&r, 0);
  assert_int_equal(r.delay, IAUTH_RESPAWN_MAX);
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_STABLE), 0);
  assert_int_equal(r.failures, 1);
  assert_int_equal(iauth_respawn_exited(&r, 0), 5);
}

static void test_stable_reports_and_resets(void **state)
{
  struct IAuthRespawn r = { 0, 0 };
  (void)state;
  assert_int_equal(iauth_respawn_stable(&r), 0);     /* nothing to report */
  iauth_respawn_exited(&r, 0);
  iauth_respawn_exited(&r, 0);
  iauth_respawn_exited(&r, 0);
  assert_int_equal(iauth_respawn_stable(&r), 3);
  assert_int_equal(r.failures, 0);
  assert_int_equal(r.delay, 0);
  /* A good run again: the next crash restarts at once. */
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_FAST), 0);
}

static void test_clock_going_back_is_a_fast_exit(void **state)
{
  struct IAuthRespawn r = { 0, 0 };
  (void)state;
  assert_int_equal(iauth_respawn_exited(&r, -10), 5);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_crash_after_good_run_restarts_at_once),
    cmocka_unit_test(test_failing_at_start_backs_off_to_the_cap),
    cmocka_unit_test(test_first_exit_too_soon_is_not_immediate),
    cmocka_unit_test(test_flapping_after_a_good_run_backs_off),
    cmocka_unit_test(test_a_long_run_ends_the_streak),
    cmocka_unit_test(test_stable_reports_and_resets),
    cmocka_unit_test(test_clock_going_back_is_a_fast_exit),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
