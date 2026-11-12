/*
 * iauth_respawn_t.c - when an IAuth program that went away on its own is
 * started again (include/iauth_respawn.h).
 *
 * iauth_respawn_exited() is told how long the program ran and returns the
 * delay before the next start: none for the first exit after a good run,
 * otherwise 5 s doubling to a 300 s cap.  A program that has run
 * IAUTH_RESPAWN_STABLE seconds ends the streak (iauth_respawn_stable(), or
 * an exit after that long).
 *
 * A failed assertion prints where and what; the program exits non-zero
 * if any did.
 */
#include <stdio.h>

#include "iauth_respawn.h"

static int checks;              /**< assertions evaluated */
static int failures;            /**< assertions that did not hold */

static void check(int ok, const char *file, int line, const char *what)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED %s:%d: %s\n", file, line, what);
  }
}

#define assert_int_equal(a, b) \
  check((long)(a) == (long)(b), __FILE__, __LINE__, #a " == " #b)

static void crash_after_good_run_restarts_at_once(void)
{
  struct IAuthRespawn r = { 0, 0 };
  assert_int_equal(iauth_respawn_exited(&r, 3600), 0);
  assert_int_equal(r.failures, 1);
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_FAST), 5);
}

static void failing_at_start_backs_off_to_the_cap(void)
{
  static const unsigned int want[] = { 5, 10, 20, 40, 80, 160, 300, 300, 300 };
  struct IAuthRespawn r = { 0, 0 };
  unsigned int i;
  for (i = 0; i < sizeof(want) / sizeof(want[0]); i++)
    assert_int_equal(iauth_respawn_exited(&r, 0), want[i]);
  assert_int_equal(r.failures, 9);
}

static void first_exit_too_soon_is_not_immediate(void)
{
  struct IAuthRespawn r = { 0, 0 };
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_FAST - 1), 5);
}

static void flapping_after_a_good_run_backs_off(void)
{
  struct IAuthRespawn r = { 0, 0 };
  /* Up 30 s each time: long enough not to be a failed start, too short
   * to end the streak. */
  assert_int_equal(iauth_respawn_exited(&r, 30), 0);
  assert_int_equal(iauth_respawn_exited(&r, 30), 5);
  assert_int_equal(iauth_respawn_exited(&r, 30), 10);
  assert_int_equal(iauth_respawn_exited(&r, 30), 20);
}

static void a_long_run_ends_the_streak(void)
{
  struct IAuthRespawn r = { 0, 0 };
  unsigned int i;
  for (i = 0; i < 10; i++)
    iauth_respawn_exited(&r, 0);
  assert_int_equal(r.delay, IAUTH_RESPAWN_MAX);
  assert_int_equal(iauth_respawn_exited(&r, IAUTH_RESPAWN_STABLE), 0);
  assert_int_equal(r.failures, 1);
  assert_int_equal(iauth_respawn_exited(&r, 0), 5);
}

static void stable_reports_and_resets(void)
{
  struct IAuthRespawn r = { 0, 0 };
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

static void clock_going_back_is_a_fast_exit(void)
{
  struct IAuthRespawn r = { 0, 0 };
  assert_int_equal(iauth_respawn_exited(&r, -10), 5);
}

int main(void)
{
  crash_after_good_run_restarts_at_once();
  failing_at_start_backs_off_to_the_cap();
  first_exit_too_soon_is_not_immediate();
  flapping_after_a_good_run_backs_off();
  a_long_run_ends_the_streak();
  stable_reports_and_resets();
  clock_going_back_is_a_fast_exit();
  printf("iauth_respawn_t: %d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
