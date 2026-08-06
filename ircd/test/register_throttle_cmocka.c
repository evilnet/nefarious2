/* register_throttle_cmocka.c - unit tests for ircd/register_throttle.c.
 * Compiled against a 1-bucket, 4-slot table (see test/Makefile.in) so the
 * eviction paths are reachable with arbitrary addresses. */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <netinet/in.h>

#include "res.h"
#include "register_throttle.h"

static struct irc_in_addr mk_v4(int a, int b, int c, int d)
{
  struct irc_in_addr ip;
  memset(&ip, 0, sizeof(ip));
  ip.in6_16[6] = htons((a << 8) | b);
  ip.in6_16[7] = htons((c << 8) | d);
  return ip;
}

static struct irc_in_addr mk_v6(unsigned short w0, unsigned short w1,
                                unsigned short w2, unsigned short w3,
                                unsigned short w7)
{
  struct irc_in_addr ip;
  memset(&ip, 0, sizeof(ip));
  ip.in6_16[0] = htons(w0);
  ip.in6_16[1] = htons(w1);
  ip.in6_16[2] = htons(w2);
  ip.in6_16[3] = htons(w3);
  ip.in6_16[7] = htons(w7);
  return ip;
}

#define T0 1000000

static int setup(void **state)
{
  (void)state;
  reg_throttle_clear();
  return 0;
}

/* limit attempts pass, the next refuses */
static void test_ip_limit_exhaustion(void **state)
{
  struct irc_in_addr ip = mk_v4(10, 0, 0, 1);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0,     3, 3600, 0));
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0 + 1, 3, 3600, 0));
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0 + 2, 3, 3600, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&ip, T0 + 3, 3, 3600, 0));
}

/* window elapses since last counted attempt -> fresh budget */
static void test_ip_window_reset(void **state)
{
  struct irc_in_addr ip = mk_v4(10, 0, 0, 2);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0, 1, 60, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&ip, T0 + 30, 1, 60, 0));
  /* boundary: exactly period after the last COUNTED attempt (T0) */
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0 + 60, 1, 60, 0));
}

/* refusals must not slide the window: hammering at t+30, t+45 does not
 * push recovery past T0+period */
static void test_refusals_do_not_extend_window(void **state)
{
  struct irc_in_addr ip = mk_v4(10, 0, 0, 3);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0, 1, 60, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&ip, T0 + 30, 1, 60, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&ip, T0 + 45, 1, 60, 0));
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0 + 60, 1, 60, 0));
}

/* distinct IPv4 addresses have independent budgets */
static void test_distinct_ips_independent(void **state)
{
  struct irc_in_addr a = mk_v4(10, 0, 0, 4), b = mk_v4(10, 0, 0, 5);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&a, T0, 1, 3600, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&a, T0 + 1, 1, 3600, 0));
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&b, T0 + 2, 1, 3600, 0));
}

/* IPv6: same /64 shares one budget, different /64 does not */
static void test_v6_slash64_grouping(void **state)
{
  struct irc_in_addr a = mk_v6(0x2001, 0xdb8, 1, 1, 0x0001);
  struct irc_in_addr b = mk_v6(0x2001, 0xdb8, 1, 1, 0xbeef); /* same /64 */
  struct irc_in_addr c = mk_v6(0x2001, 0xdb8, 1, 2, 0x0001); /* different /64 */
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&a, T0, 1, 3600, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&b, T0 + 1, 1, 3600, 0));
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&c, T0 + 2, 1, 3600, 0));
}

/* zero disables each limiter independently; period<=0 disables both */
static void test_zero_disables(void **state)
{
  struct irc_in_addr ip = mk_v4(10, 0, 0, 6);
  int i;
  (void)state;
  for (i = 0; i < 50; i++)
    assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0 + i, 0, 3600, 0));
  reg_throttle_clear();
  for (i = 0; i < 50; i++)
    assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip, T0 + i, 5, 0, 5));
}

/* global cap trips across distinct IPs even with per-IP disabled */
static void test_global_cap(void **state)
{
  struct irc_in_addr a = mk_v4(10, 1, 0, 1), b = mk_v4(10, 1, 0, 2),
                     c = mk_v4(10, 1, 0, 3);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK,     reg_throttle_check(&a, T0,     0, 60, 2));
  assert_int_equal(REG_THROTTLE_OK,     reg_throttle_check(&b, T0 + 1, 0, 60, 2));
  assert_int_equal(REG_THROTTLE_GLOBAL, reg_throttle_check(&c, T0 + 2, 0, 60, 2));
  /* fixed window anchored at first attempt: frees at T0+60 */
  assert_int_equal(REG_THROTTLE_OK,     reg_throttle_check(&c, T0 + 60, 0, 60, 2));
}

/* a per-IP refusal must not consume global budget */
static void test_ip_refusal_spares_global(void **state)
{
  struct irc_in_addr a = mk_v4(10, 2, 0, 1), b = mk_v4(10, 2, 0, 2);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&a, T0,     1, 3600, 2));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&a, T0 + 1, 1, 3600, 2));
  /* global still has 1 of 2 left; b consumes it, then trips */
  assert_int_equal(REG_THROTTLE_OK,     reg_throttle_check(&b, T0 + 2, 1, 3600, 2));
  /* b's per-IP budget is spent too, so use a third IP for the global trip */
  {
    struct irc_in_addr c = mk_v4(10, 2, 0, 3);
    assert_int_equal(REG_THROTTLE_GLOBAL, reg_throttle_check(&c, T0 + 3, 1, 3600, 2));
  }
}

/* with the test's 1x4 table, a 5th distinct live IP evicts the oldest */
static void test_eviction_oldest_live(void **state)
{
  struct irc_in_addr ip[5];
  int i;
  (void)state;
  for (i = 0; i < 5; i++)
    ip[i] = mk_v4(10, 3, 0, i + 1);
  for (i = 0; i < 4; i++)
    assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip[i], T0 + i, 1, 3600, 0));
  /* table full of live entries; the 5th evicts ip[0] (oldest) */
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip[4], T0 + 10, 1, 3600, 0));
  /* ip[0] got fresh budget by eviction (accepted safety trade-off) --
   * and its re-insert evicts the new oldest, ip[1] */
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip[0], T0 + 11, 1, 3600, 0));
  /* ip[3] (newest of the originals) was never evicted: still refused */
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&ip[3], T0 + 12, 1, 3600, 0));
}

/* expired entries are reused before live ones are evicted */
static void test_expired_reused_before_eviction(void **state)
{
  struct irc_in_addr ip[5];
  int i;
  (void)state;
  for (i = 0; i < 5; i++)
    ip[i] = mk_v4(10, 4, 0, i + 1);
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip[0], T0, 1, 60, 0));
  for (i = 1; i < 4; i++)  /* three live entries, well inside their window */
    assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip[i], T0 + 100, 1, 60, 0));
  /* ip[0]'s entry is expired at T0+100, so its slot is reclaimed by an
   * incoming address; with one slot still free, ip[4] fits without
   * touching any LIVE entry -- which is the property under test: */
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&ip[4], T0 + 101, 1, 60, 0));
  /* the live entries kept their state: all still refused */
  for (i = 1; i < 4; i++)
    assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&ip[i], T0 + 102, 1, 60, 0));
}

/* reg_throttle_expire frees expired entries; reg_throttle_clear frees all */
static void test_expire_and_clear(void **state)
{
  struct irc_in_addr a = mk_v4(10, 5, 0, 1), b = mk_v4(10, 5, 0, 2);
  (void)state;
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&a, T0, 1, 60, 0));
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&b, T0 + 50, 1, 60, 0));
  reg_throttle_expire(T0 + 70, 60);        /* a expired, b still live */
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&a, T0 + 71, 1, 60, 0));
  assert_int_equal(REG_THROTTLE_IP, reg_throttle_check(&b, T0 + 72, 1, 60, 0));
  reg_throttle_clear();
  assert_int_equal(REG_THROTTLE_OK, reg_throttle_check(&b, T0 + 73, 1, 60, 0));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_ip_limit_exhaustion, setup),
    cmocka_unit_test_setup(test_ip_window_reset, setup),
    cmocka_unit_test_setup(test_refusals_do_not_extend_window, setup),
    cmocka_unit_test_setup(test_distinct_ips_independent, setup),
    cmocka_unit_test_setup(test_v6_slash64_grouping, setup),
    cmocka_unit_test_setup(test_zero_disables, setup),
    cmocka_unit_test_setup(test_global_cap, setup),
    cmocka_unit_test_setup(test_ip_refusal_spares_global, setup),
    cmocka_unit_test_setup(test_eviction_oldest_live, setup),
    cmocka_unit_test_setup(test_expired_reused_before_eviction, setup),
    cmocka_unit_test_setup(test_expire_and_clear, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
