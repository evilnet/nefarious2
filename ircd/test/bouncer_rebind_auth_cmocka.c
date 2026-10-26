/* cmocka suite for bounce_rebind_auth (include/bouncer_rebind_auth.h).
 *
 * The rebind gate authorizes on the session id alone; the origin and
 * account-TS arms are retired.  Real rebinds occur about four times per
 * five months in production, so the decision is pinned here rather than
 * observed in the field.
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

static void test_origin_alone_no_longer_authorizes(void **state)
{
  (void)state;
  /* Retired 2026-10. The origin a session record notes goes stale: a ghost
   * rebind keeps it, a merge points it at the server merged into, a BS C
   * yield at the peer that announced the session.  A line whose session id
   * does not match ours says the incoming client is in another session, or
   * in none; matching on the origin then handed our held session to a
   * client that is not in it. */
  assert_int_equal(bounce_rebind_auth(1, 0, 0), BRA_NONE);
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
  /* acc_ts is never reported: the session id authorizes alone, and the
   * retired origin arm does not come back beside the retired acc_ts one. */
  assert_int_equal(bounce_rebind_auth(1, 0, 1), BRA_NONE);
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

/* Whether a login may join a session (user, 2026-10-23): a new Keycloak id
 * never attaches to an old session, and an old session is never tied to a
 * new id.  A session with no id joins (the transition: X3 logins, records
 * from before the id was kept); so does a login without one. */
static void test_kc_join_same_or_missing_id_joins(void **state)
{
  (void)state;
  assert_int_equal(bounce_kc_join("a6p7gJ2tEdGAtADAT9QwyA", "a6p7gJ2tEdGAtADAT9QwyA", 0), BKJ_JOIN);
  assert_int_equal(bounce_kc_join("", "a6p7gJ2tEdGAtADAT9QwyA", 0), BKJ_JOIN);
  assert_int_equal(bounce_kc_join("a6p7gJ2tEdGAtADAT9QwyA", "", 1), BKJ_JOIN);
  assert_int_equal(bounce_kc_join(NULL, NULL, 1), BKJ_JOIN);
}

/* The previous user's leftover with nothing connected anywhere ends; the
 * login then registers on its own. */
static void test_kc_join_conflict_ends_an_unused_leftover(void **state)
{
  (void)state;
  assert_int_equal(bounce_kc_join("a6p7gJ2tEdGAtADAT9QwyA", "AAAAAAAAAAAAAAAAAAAAAA", 1),
                   BKJ_END_STALE);
}

/* A session still in use (a live primary, aliases anywhere, a ghost on
 * another server) refuses the login: registering beside it collides. */
static void test_kc_join_conflict_refuses_while_in_use(void **state)
{
  (void)state;
  assert_int_equal(bounce_kc_join("a6p7gJ2tEdGAtADAT9QwyA", "AAAAAAAAAAAAAAAAAAAAAA", 0),
                   BKJ_REFUSE);
}

/* A same-nick verdict's Keycloak check: our side's id is its session's
 * when it has one, else the client's own, so a client in no session is
 * checked like a held ghost (whose own id the rebind reads). */
#define KC_A "a6p7gJ2tEdGAtADAT9QwyA"
#define KC_B "AAAAAAAAAAAAAAAAAAAAAA"
static void test_side_kc_conflict_reads_the_session_else_the_client(void **state)
{
  (void)state;
  /* In a session: the session's id. */
  assert_true(bounce_side_kc_conflict(KC_A, "", KC_B));
  assert_true(bounce_side_kc_conflict(KC_A, KC_A, KC_B));
  assert_false(bounce_side_kc_conflict(KC_A, KC_B, KC_A));
  /* In no session (or a session that knows no id): the client's own. */
  assert_true(bounce_side_kc_conflict(NULL, KC_A, KC_B));
  assert_true(bounce_side_kc_conflict("", KC_A, KC_B));
  assert_false(bounce_side_kc_conflict(NULL, KC_A, KC_A));
  /* A missing id never conflicts. */
  assert_false(bounce_side_kc_conflict(NULL, NULL, KC_B));
  assert_false(bounce_side_kc_conflict("", "", KC_B));
  assert_false(bounce_side_kc_conflict(KC_A, KC_A, ""));
  assert_false(bounce_side_kc_conflict(NULL, KC_A, NULL));
  assert_false(bounce_side_kc_conflict(NULL, NULL, NULL));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_no_signal_refuses),
    cmocka_unit_test(test_origin_alone_no_longer_authorizes),
    cmocka_unit_test(test_sessid_alone_authorizes),
    cmocka_unit_test(test_acc_ts_alone_no_longer_authorizes),
    cmocka_unit_test(test_sessid_supersedes_origin),
    cmocka_unit_test(test_stronger_signal_wins_over_acc_ts),
    cmocka_unit_test(test_names_are_stable),
    cmocka_unit_test(test_kc_ids_that_differ_conflict),
    cmocka_unit_test(test_same_kc_id_does_not_conflict),
    cmocka_unit_test(test_missing_kc_id_does_not_conflict),
    cmocka_unit_test(test_kc_join_same_or_missing_id_joins),
    cmocka_unit_test(test_kc_join_conflict_ends_an_unused_leftover),
    cmocka_unit_test(test_kc_join_conflict_refuses_while_in_use),
    cmocka_unit_test(test_side_kc_conflict_reads_the_session_else_the_client),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
