/* webpush_attention_cmocka.c - CMocka tests for the webpush attention
 * predicate (webpush_attention.c).  The module is pure: no ircd deps.
 *
 * Pins the rule from .claude/para/projects/webpush-attention-trigger.md:
 * push only when no connection is connected, present and recently active.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/webpush_attention.h"

#define T0   1800000000LL
#define IDLE 900LL

static struct webpush_conn_state st(int held, int away, long long last)
{
  struct webpush_conn_state c;
  c.held = held; c.away = away; c.last_msg = last;
  return c;
}

static void test_empty_and_held(void **state)
{
  struct webpush_conn_state c[2];
  (void)state;
  assert_int_equal(webpush_unattended(NULL, 0, T0, IDLE), 1);
  c[0] = st(1, 0, T0);            /* held: the socket is gone, recency irrelevant */
  c[1] = st(1, 0, T0);
  assert_int_equal(webpush_unattended(c, 2, T0, IDLE), 1);
}

static void test_one_attending_blocks(void **state)
{
  struct webpush_conn_state c[3];
  (void)state;
  c[0] = st(1, 0, 0);              /* held ghost */
  c[1] = st(0, 1, T0);             /* away, though active a second ago */
  c[2] = st(0, 0, T0 - 60);        /* present, spoke a minute ago: attending */
  assert_int_equal(webpush_unattended(c, 3, T0, IDLE), 0);
  c[2].away = 1;                   /* ...until it goes away */
  assert_int_equal(webpush_unattended(c, 3, T0, IDLE), 1);
}

static void test_idle_boundary(void **state)
{
  struct webpush_conn_state c[1];
  (void)state;
  c[0] = st(0, 0, T0 - IDLE);      /* exactly at the window: idle */
  assert_int_equal(webpush_unattended(c, 1, T0, IDLE), 1);
  c[0] = st(0, 0, T0 - IDLE + 1);  /* one second inside: attending */
  assert_int_equal(webpush_unattended(c, 1, T0, IDLE), 0);
  c[0] = st(0, 0, 0);              /* never spoke: idle */
  assert_int_equal(webpush_unattended(c, 1, T0, IDLE), 1);
}

static void test_idle_rule_off(void **state)
{
  struct webpush_conn_state c[2];
  (void)state;
  /* idle <= 0: a connected, present connection attends however quiet;
   * only held or away connections can be unattended. */
  c[0] = st(0, 0, T0 - 100 * IDLE);
  assert_int_equal(webpush_unattended(c, 1, T0, 0), 0);
  c[0] = st(0, 1, T0);
  c[1] = st(1, 0, T0);
  assert_int_equal(webpush_unattended(c, 2, T0, 0), 1);
}

static void test_power_user_day(void **state)
{
  /* Home box (idle for hours), work box (typing), phone app (background). */
  struct webpush_conn_state c[3];
  (void)state;
  c[0] = st(0, 0, T0 - 5 * 3600);
  c[1] = st(0, 0, T0 - 30);
  c[2] = st(0, 0, T0 - 2 * 3600);
  assert_int_equal(webpush_unattended(c, 3, T0, IDLE), 0);   /* at the desk */
  c[1].last_msg = T0 - 20 * 60;                              /* 20 min into lunch */
  assert_int_equal(webpush_unattended(c, 3, T0, IDLE), 1);   /* push */
  c[1].last_msg = T0 - 20 * 60; c[1].away = 0;
  c[0].away = 1;                                             /* home box marks away: no change */
  assert_int_equal(webpush_unattended(c, 3, T0, IDLE), 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_empty_and_held),
    cmocka_unit_test(test_one_attending_blocks),
    cmocka_unit_test(test_idle_boundary),
    cmocka_unit_test(test_idle_rule_off),
    cmocka_unit_test(test_power_user_day),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
