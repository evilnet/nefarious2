/* webpush_expiry_cmocka.c - CMocka tests for the stale-subscription
 * decision helpers (webpush_expiry.c).  The module is pure: no ircd deps,
 * no stubs.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>

#include "../../include/webpush_expiry.h"

#define T0 1800000000  /* fixed "now" */
#define DAY 86400LL

static void test_armed_at(void **state)
{
  (void)state;

  /* New-format record carries its arming timestamp. */
  assert_int_equal(webpush_armed_at("https://fcm|x|y|" "1800000000"), T0);

  /* Old-format records and malformed fields never sweep (armed = 0). */
  assert_int_equal(webpush_armed_at("https://fcm|x|y"), 0);
  assert_int_equal(webpush_armed_at("https://fcm|x|y|"), 0);
  assert_int_equal(webpush_armed_at("https://fcm|x|y|soon"), 0);
  assert_int_equal(webpush_armed_at("no pipes"), 0);
  assert_int_equal(webpush_armed_at(NULL), 0);

  /* A stray extra field is tolerated; the timestamp still parses. */
  assert_int_equal(webpush_armed_at("a|b|c|123|extra"), 123);

  /* A negative timestamp is garbage: treated as absent. */
  assert_int_equal(webpush_armed_at("a|b|c|-5"), 0);
}

static void test_expired(void **state)
{
  (void)state;

  /* Exactly at the window boundary: expired. */
  assert_int_equal(webpush_expired(T0 - 180 * DAY, T0, 180 * DAY), 1);

  /* One second younger: alive. */
  assert_int_equal(webpush_expired(T0 - 180 * DAY + 1, T0, 180 * DAY), 0);

  /* Timestamp-less (old-format) records are never swept. */
  assert_int_equal(webpush_expired(0, T0, 180 * DAY), 0);

  /* max_age <= 0 disables the sweep entirely. */
  assert_int_equal(webpush_expired(1, T0, 0), 0);
  assert_int_equal(webpush_expired(1, T0, -5), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_armed_at),
    cmocka_unit_test(test_expired),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
