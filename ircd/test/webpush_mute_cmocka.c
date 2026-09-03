/* webpush_mute_cmocka.c - CMocka tests for the draft/webpush mute list
 * parser (webpush_mute.c).  The module is pure: no ircd deps, no stubs.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>

#include "../../include/webpush_mute.h"

#define T0 1800000000 /* fixed "now" */

static void test_empty_and_null(void **state)
{
  (void)state;

  assert_int_equal(webpush_mute_check(NULL, "#ps", T0), 0);
  assert_int_equal(webpush_mute_check("", "#ps", T0), 0);
  assert_int_equal(webpush_mute_check("*:" "9999999999", NULL, T0), 0);
}

static void test_global_snooze(void **state)
{
  (void)state;
  char value[64];

  snprintf(value, sizeof(value), "*:%lld", (long long)T0 + 3600);
  assert_int_equal(webpush_mute_check(value, "#ps", T0), 1);
  assert_int_equal(webpush_mute_check(value, "alice", T0), 1);

  /* Expired global entry: not muted. */
  snprintf(value, sizeof(value), "*:%lld", (long long)T0 - 1);
  assert_int_equal(webpush_mute_check(value, "#ps", T0), 0);

  /* Indefinite (0) mutes forever. */
  snprintf(value, sizeof(value), "*:0");
  assert_int_equal(webpush_mute_check(value, "#ps", T0 + 86400 * 365), 1);
}

static void test_target_match(void **state)
{
  (void)state;
  char value[96];

  snprintf(value, sizeof(value), "#ps:%lld;alice:%lld",
     (long long)T0 + 3600, (long long)T0 + 7200);
  assert_int_equal(webpush_mute_check(value, "#ps", T0), 1);
  assert_int_equal(webpush_mute_check(value, "alice", T0), 1);
  assert_int_equal(webpush_mute_check(value, "#other", T0), 0);
  assert_int_equal(webpush_mute_check(value, "bob", T0), 0);

  /* Prefixes must not match: #p is not #ps. */
  snprintf(value, sizeof(value), "#ps:%lld", (long long)T0 + 3600);
  assert_int_equal(webpush_mute_check(value, "#p", T0), 0);
}

static void test_expired_and_garbage_entries_are_skipped(void **state)
{
  (void)state;
  /* Expired target entry between live ones; malformed entries skipped. */
  assert_int_equal(
    webpush_mute_check("#old:1;;nocolon;bad:x;#ps:9999999999", "#ps", T0),
    1);
  assert_int_equal(
    webpush_mute_check("#old:1;;nocolon;bad:x", "#ps", T0), 0);
}

static void test_prune_expired(void **state)
{
  (void)state;
  char out[128];
  char value[96];

  snprintf(value, sizeof(value), "#old:%lld;#ps:%lld",
     (long long)T0 - 1, (long long)T0 + 3600);
  assert_int_equal(webpush_mute_prune(value, NULL, T0, out, sizeof(out)), 1);
  assert_string_equal(out, "#ps:1800003600");

  /* Nothing expired: unchanged. */
  assert_int_equal(webpush_mute_prune("#ps:0", NULL, T0, out, sizeof(out)), 0);
  assert_string_equal(out, "#ps:0");
}

static void test_prune_drop_target(void **state)
{
  (void)state;
  char out[128];
  char value[96];

  snprintf(value, sizeof(value), "*:%lld;#ps:%lld",
     (long long)T0 + 3600, (long long)T0 + 7200);
  assert_int_equal(
    webpush_mute_prune(value, "#ps", T0, out, sizeof(out)), 1);
  assert_string_equal(out, "*:1800003600");

  /* Dropping an absent target changes nothing. */
  assert_int_equal(
    webpush_mute_prune(value, "#nope", T0, out, sizeof(out)), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_empty_and_null),
    cmocka_unit_test(test_global_snooze),
    cmocka_unit_test(test_target_match),
    cmocka_unit_test(test_expired_and_garbage_entries_are_skipped),
    cmocka_unit_test(test_prune_expired),
    cmocka_unit_test(test_prune_drop_target),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
