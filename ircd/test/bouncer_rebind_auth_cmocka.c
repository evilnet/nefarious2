/* cmocka suite for bounce_rebind_auth (include/bouncer_rebind_auth.h).
 *
 * The rebind gate authorizes on any of three independent signals. Real
 * rebinds occur about four times per five months in production, so the
 * decision is pinned here rather than observed in the field.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_rebind_auth.h"

static void test_no_signal_refuses(void **state)
{
  (void)state;
  assert_int_equal(bounce_rebind_auth(0, 0, 0), BRA_NONE);
}

static void test_origin_alone_authorizes(void **state)
{
  (void)state;
  assert_int_equal(bounce_rebind_auth(1, 0, 0), BRA_ORIGIN);
}

static void test_sessid_alone_authorizes(void **state)
{
  (void)state;
  assert_int_equal(bounce_rebind_auth(0, 1, 0), BRA_SESSID);
}

static void test_acc_ts_alone_authorizes(void **state)
{
  (void)state;
  /* Task 2 flips this to BRA_NONE. Until then it pins current behaviour. */
  assert_int_equal(bounce_rebind_auth(0, 0, 1), BRA_ACC_TS);
}

static void test_sessid_supersedes_origin(void **state)
{
  (void)state;
  /* Redesign A.2/C.2: sessid is the canonical session identity; hs_origin is
   * historical-only metadata. Where both hold, the report must say sessid. */
  assert_int_equal(bounce_rebind_auth(1, 1, 0), BRA_SESSID);
  assert_int_equal(bounce_rebind_auth(1, 1, 1), BRA_SESSID);
}

static void test_stronger_signal_wins_over_acc_ts(void **state)
{
  (void)state;
  /* acc_ts is the weakest signal and must never be reported when a
   * stronger one is present -- otherwise the log undercounts the real
   * gates and overcounts the one we are trying to retire. */
  assert_int_equal(bounce_rebind_auth(1, 0, 1), BRA_ORIGIN);
  assert_int_equal(bounce_rebind_auth(0, 1, 1), BRA_SESSID);
}

static void test_names_are_stable(void **state)
{
  (void)state;
  /* These strings land in a log operators grep. */
  assert_string_equal(bounce_rebind_auth_name(BRA_NONE),   "none");
  assert_string_equal(bounce_rebind_auth_name(BRA_ORIGIN), "origin");
  assert_string_equal(bounce_rebind_auth_name(BRA_SESSID), "sessid");
  assert_string_equal(bounce_rebind_auth_name(BRA_ACC_TS), "account-TS");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_no_signal_refuses),
    cmocka_unit_test(test_origin_alone_authorizes),
    cmocka_unit_test(test_sessid_alone_authorizes),
    cmocka_unit_test(test_acc_ts_alone_authorizes),
    cmocka_unit_test(test_sessid_supersedes_origin),
    cmocka_unit_test(test_stronger_signal_wins_over_acc_ts),
    cmocka_unit_test(test_names_are_stable),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
