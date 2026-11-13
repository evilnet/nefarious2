/*
 * nick_delay_cmocka.c - the NICKDELAY rule (include/nick_delay.h).
 *
 * One rule serves the primary's server (the session user's own
 * Connection) and a device's own server (the device's Connection, for a
 * primary on another server): two quick changes after a quiet spell, then
 * one per delay, and a refused attempt pushes the next one 2 s further.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "nick_delay.h"

#define DELAY 30

/* A connection fresh from make_client(): next = now - NICK_DELAY. */
static void test_two_quick_changes_then_refused(void **state)
{
  time_t now = 1000000;
  time_t next = now - DELAY;

  (void)state;
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 0);
  assert_int_equal(next, now);
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 0);
  assert_int_equal(next, now + DELAY);
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 1);
  assert_int_equal(next, now + DELAY + 2);
}

/* Each refused attempt costs 2 s more; once the time comes, one change. */
static void test_refusals_push_the_next_change(void **state)
{
  time_t now = 1000000;
  time_t next = now + DELAY;

  (void)state;
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 1);
  assert_int_equal(nick_delay_refuses(&next, now + 1, DELAY), 1);
  assert_int_equal(next, now + DELAY + 4);
  assert_int_equal(nick_delay_refuses(&next, now + DELAY + 3, DELAY), 1);
  assert_int_equal(nick_delay_refuses(&next, now + DELAY + 8, DELAY), 0);
  assert_int_equal(next, now + DELAY + 6 + DELAY);
}

/* After a long quiet spell next is pulled up to now, never left behind:
 * again exactly two changes. */
static void test_quiet_spell_allows_two_again(void **state)
{
  time_t now = 1000000;
  time_t next = now - 10 * DELAY;

  (void)state;
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 0);
  assert_int_equal(next, now);
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 0);
  assert_int_equal(nick_delay_refuses(&next, now, DELAY), 1);
}

/* NICKDELAY 0 (or a negative setting) allows everything, touches nothing. */
static void test_no_delay_allows_all(void **state)
{
  time_t next = 5;
  int i;

  (void)state;
  for (i = 0; i < 10; i++) {
    assert_int_equal(nick_delay_refuses(&next, 1000000, 0), 0);
    assert_int_equal(nick_delay_refuses(&next, 1000000, -1), 0);
  }
  assert_int_equal(next, 5);
}

/* Two connections keep two budgets: a device's own delay never moves
 * the primary's, and the other way round. */
static void test_budgets_are_per_connection(void **state)
{
  time_t now = 1000000;
  time_t primary = now - DELAY, device = now - DELAY;

  (void)state;
  assert_int_equal(nick_delay_refuses(&primary, now, DELAY), 0);
  assert_int_equal(nick_delay_refuses(&primary, now, DELAY), 0);
  assert_int_equal(nick_delay_refuses(&primary, now, DELAY), 1);
  assert_int_equal(device, now - DELAY);
  assert_int_equal(nick_delay_refuses(&device, now, DELAY), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_two_quick_changes_then_refused),
    cmocka_unit_test(test_refusals_push_the_next_change),
    cmocka_unit_test(test_quiet_spell_allows_two_again),
    cmocka_unit_test(test_no_delay_allows_all),
    cmocka_unit_test(test_budgets_are_per_connection),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
