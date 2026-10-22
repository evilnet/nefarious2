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

static void test_acc_ts_alone_no_longer_authorizes(void **state)
{
  (void)state;
  /* Retired 2026-09. The account timestamp is a services-supplied value the
   * ircd otherwise only couriers, and matching on it is too coarse: two
   * unrelated non-bouncer connections sharing an account matched each other.
   * 8cf493c propagates the sessid through burst, which is what this arm was
   * standing in for. */
  assert_int_equal(bounce_rebind_auth(0, 0, 1), BRA_NONE);
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

/* The Keycloak id vetoes, never authorizes: account-level, so it says
 * nothing about WHICH session; it only proves a different user. */
static void test_kc_ids_that_differ_conflict(void **state)
{
  (void)state;
  assert_true(bounce_rebind_kc_conflict("a6p7gJ2tEdGAtADAT9QwyA",
                                        "AAAAAAAAAAAAAAAAAAAAAA"));
}

static void test_same_kc_id_does_not_conflict(void **state)
{
  (void)state;
  assert_false(bounce_rebind_kc_conflict("a6p7gJ2tEdGAtADAT9QwyA",
                                         "a6p7gJ2tEdGAtADAT9QwyA"));
}

/* A missing id never vetoes: legacy hops strip it, restored ghosts may
 * lack it. */
static void test_missing_kc_id_does_not_conflict(void **state)
{
  (void)state;
  assert_false(bounce_rebind_kc_conflict("", "a6p7gJ2tEdGAtADAT9QwyA"));
  assert_false(bounce_rebind_kc_conflict("a6p7gJ2tEdGAtADAT9QwyA", ""));
  assert_false(bounce_rebind_kc_conflict(NULL, "a6p7gJ2tEdGAtADAT9QwyA"));
  assert_false(bounce_rebind_kc_conflict("a6p7gJ2tEdGAtADAT9QwyA", NULL));
  assert_false(bounce_rebind_kc_conflict(NULL, NULL));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_no_signal_refuses),
    cmocka_unit_test(test_origin_alone_authorizes),
    cmocka_unit_test(test_sessid_alone_authorizes),
    cmocka_unit_test(test_acc_ts_alone_no_longer_authorizes),
    cmocka_unit_test(test_sessid_supersedes_origin),
    cmocka_unit_test(test_stronger_signal_wins_over_acc_ts),
    cmocka_unit_test(test_names_are_stable),
    cmocka_unit_test(test_kc_ids_that_differ_conflict),
    cmocka_unit_test(test_same_kc_id_does_not_conflict),
    cmocka_unit_test(test_missing_kc_id_does_not_conflict),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
