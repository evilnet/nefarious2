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

static int eq_ascii_ci(const char *a, size_t alen, const char *b, size_t blen)
{
  size_t i;
  if (alen != blen)
    return 0;
  for (i = 0; i < alen; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x += 32;
    if (y >= 'A' && y <= 'Z') y += 32;
    if (x != y)
      return 0;
  }
  return 1;
}

static void test_negative_until_is_indefinite(void **state)
{
  (void)state;
  /* The header promises 0 or negative = indefinite; check and prune agree. */
  assert_int_equal(webpush_mute_check("#ps:-1", "#ps", T0 + 86400 * 365), 1);
  {
    char out[64];
    assert_int_equal(webpush_mute_prune("#ps:-1", NULL, T0, out, sizeof(out)), 0);
    assert_string_equal(out, "#ps:-1");
  }
}

static void test_comparator_makes_names_case_insensitive(void **state)
{
  (void)state;
  char value[64];
  char out[64];
  snprintf(value, sizeof(value), "#Linux:%lld", (long long)T0 + 3600);
  /* Byte compare: no match across case. */
  assert_int_equal(webpush_mute_check(value, "#linux", T0), 0);
  /* With the ircd's compare: a mute typed in another case still holds. */
  assert_int_equal(webpush_mute_check_cmp(value, "#linux", T0, eq_ascii_ci), 1);
  assert_int_equal(webpush_mute_check_cmp(value, "#linu", T0, eq_ascii_ci), 0);
  assert_int_equal(webpush_mute_prune_cmp(value, "#LINUX", T0, out, sizeof(out), eq_ascii_ci), 1);
  assert_string_equal(out, "");
}

static void test_prune_refuses_to_truncate(void **state)
{
  (void)state;
  char out[12];
  /* Two live entries that do not fit: -1 and an empty out, never a
   * silently shortened list. */
  assert_int_equal(webpush_mute_prune("#ps:0;#other:0", NULL, T0, out, sizeof(out)), -1);
  assert_string_equal(out, "");
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
    cmocka_unit_test(test_negative_until_is_indefinite),
    cmocka_unit_test(test_comparator_makes_names_case_insensitive),
    cmocka_unit_test(test_prune_refuses_to_truncate),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
