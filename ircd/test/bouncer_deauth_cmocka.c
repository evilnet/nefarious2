/* cmocka suite for the pure bouncer deauth decision points
 * (include/bouncer_deauth.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_deauth.h"

/* Every field name that appears on the BX U wire.  The receiver in
 * bounce_alias_update() is the reference list; the local-apply block in
 * bounce_emit_alias_update() had drifted two fields behind it, which is
 * the bug this table exists to prevent recurring. */
static const char *const wire_fields[] = {
  "host", "realhost", "realname", "fakehost",
  "cloakhost", "cloakip", "username", "account", "caps"
};

static void test_account_is_a_known_field(void **state)
{
  (void)state;
  /* The live-in-prod bug: the local-apply block had no "account" case, so
   * local aliases never learned an account set or clear. */
  assert_int_equal(bounce_alias_field_id("account"), BX_ALIAS_FIELD_ACCOUNT);
  assert_int_equal(bounce_alias_field_id("caps"), BX_ALIAS_FIELD_CAPS);
}

static void test_every_wire_field_maps(void **state)
{
  (void)state;
  size_t i;
  for (i = 0; i < sizeof(wire_fields) / sizeof(wire_fields[0]); i++)
    assert_int_not_equal(bounce_alias_field_id(wire_fields[i]),
                         BX_ALIAS_FIELD_UNKNOWN);
}

static void test_field_ids_are_distinct_and_complete(void **state)
{
  (void)state;
  /* Completeness guard: the wire list and the enum must stay the same
   * size, so adding an enumerator without teaching the wire (or vice
   * versa) fails here rather than silently no-op'ing at runtime. */
  size_t n = sizeof(wire_fields) / sizeof(wire_fields[0]);
  size_t i, j;
  assert_int_equal((int)n, BX_ALIAS_FIELD_COUNT - 1);  /* -1 for UNKNOWN */
  for (i = 0; i < n; i++)
    for (j = i + 1; j < n; j++)
      assert_int_not_equal(bounce_alias_field_id(wire_fields[i]),
                           bounce_alias_field_id(wire_fields[j]));
}

static void test_round_trips_to_the_wire_name(void **state)
{
  (void)state;
  size_t i;
  for (i = 0; i < sizeof(wire_fields) / sizeof(wire_fields[0]); i++) {
    enum BounceAliasField id = bounce_alias_field_id(wire_fields[i]);
    assert_string_equal(bounce_alias_field_name(id), wire_fields[i]);
  }
}

static void test_unknown_and_null_are_unknown(void **state)
{
  (void)state;
  assert_int_equal(bounce_alias_field_id(NULL), BX_ALIAS_FIELD_UNKNOWN);
  assert_int_equal(bounce_alias_field_id(""), BX_ALIAS_FIELD_UNKNOWN);
  assert_int_equal(bounce_alias_field_id("nosuchfield"), BX_ALIAS_FIELD_UNKNOWN);
  /* Field names are matched case-insensitively on the wire, as
   * bounce_alias_update() used ircd_strcmp. */
  assert_int_equal(bounce_alias_field_id("ACCOUNT"), BX_ALIAS_FIELD_ACCOUNT);
  assert_ptr_equal(bounce_alias_field_name(BX_ALIAS_FIELD_UNKNOWN), NULL);
  assert_ptr_equal(bounce_alias_field_name(BX_ALIAS_FIELD_COUNT), NULL);
}

/* A matching, local, live primary: the ordinary case. */
static struct BounceDeauthSubject subj_primary(void)
{
  struct BounceDeauthSubject s;
  memset(&s, 0, sizeof(s));
  s.is_user = 1;
  s.is_account = 1;
  s.account_matches = 1;
  s.is_local = 1;
  return s;
}

static void test_local_primary_is_cleared_or_killed(void **state)
{
  (void)state;
  struct BounceDeauthSubject s = subj_primary();
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_CLEAR_ACCOUNT);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_KILL_SOCKET);
}

static void test_remote_client_is_deauthed_never_killed(void **state)
{
  (void)state;
  /* With remote_ok (the network-wide walk of a single receiver): B-2 is
   * about the KILL: exit_client() on a remote victim emits no KILL and
   * sends a victim-sourced QUIT on every downlink, which the victim's own
   * side discards as wrong-direction -- permanent split-brain.  The
   * DEAUTH is legal for a remote client: the local replica is cleared and
   * AC U from &me reaches its home server, which runs the full receiver.
   * So a remote primary is deauthed, kill or not, and a remote held ghost
   * too (its home server tears the session down on AC U); a remote alias
   * is left to its primary. */
  struct BounceDeauthSubject s = subj_primary();
  s.is_local = 0;
  s.remote_ok = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_CLEAR_ACCOUNT);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_CLEAR_ACCOUNT);

  s = subj_primary();
  s.is_local = 0;
  s.remote_ok = 1;
  s.is_hold = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_CLEAR_ACCOUNT);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_CLEAR_ACCOUNT);

  s = subj_primary();
  s.is_local = 0;
  s.remote_ok = 1;
  s.is_alias = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);
}

/* Webhook plan 4: every server receives every event and acts on what it
 * owns, so a remote client -- primary, held ghost or alias -- is its home
 * server's job and is SKIPped here unless remote_ok says otherwise. */
static void test_remote_client_is_skipped_by_default(void **state)
{
  (void)state;
  struct BounceDeauthSubject s = subj_primary();
  s.is_local = 0;
  assert_int_equal(s.remote_ok, 0);
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);

  s = subj_primary();
  s.is_local = 0;
  s.is_hold = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);

  s = subj_primary();
  s.is_local = 0;
  s.is_alias = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);

  /* The local client of the same shape is still acted on. */
  s = subj_primary();
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_CLEAR_ACCOUNT);
}

static void test_held_ghost_destroys_the_session(void **state)
{
  (void)state;
  /* B-6: a held ghost is an IsUser client with an account, so it matched
   * the old walk.  Deauthing it clears the account out from under the
   * session's own hs_client; killing it leaves the session HOLDING with
   * the DB record intact because FLAG_KILLED is unset.  Neither is the
   * right primitive -- tear the session down explicitly. */
  struct BounceDeauthSubject s = subj_primary();
  s.is_hold = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_DESTROY_SESSION);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_DESTROY_SESSION);
}

static void test_alias_skipped_on_clear_killed_on_kill(void **state)
{
  (void)state;
  /* Aliases mirror the primary's account via bounce_apply_alias_field,
   * so a direct clear would double-apply and would leak the alias
   * numeric to legacy peers via AC U (aliases are BX C-introduced).
   * Kills still take every socket -- whole-session loss is by design
   * (invariant #6). */
  struct BounceDeauthSubject s = subj_primary();
  s.is_alias = 1;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_KILL_SOCKET);
}

static void test_non_matching_and_non_user_are_skipped(void **state)
{
  (void)state;
  struct BounceDeauthSubject s = subj_primary();
  s.account_matches = 0;
  assert_int_equal(bounce_deauth_classify(&s, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);

  s = subj_primary();
  s.is_user = 0;
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);

  s = subj_primary();
  s.is_account = 0;
  assert_int_equal(bounce_deauth_classify(&s, 1), BOUNCE_DEAUTH_SKIP);
}

static void test_null_subject_is_skipped(void **state)
{
  (void)state;
  assert_int_equal(bounce_deauth_classify(NULL, 0), BOUNCE_DEAUTH_SKIP);
  assert_int_equal(bounce_deauth_classify(NULL, 1), BOUNCE_DEAUTH_SKIP);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_account_is_a_known_field),
    cmocka_unit_test(test_every_wire_field_maps),
    cmocka_unit_test(test_field_ids_are_distinct_and_complete),
    cmocka_unit_test(test_round_trips_to_the_wire_name),
    cmocka_unit_test(test_unknown_and_null_are_unknown),
    cmocka_unit_test(test_local_primary_is_cleared_or_killed),
    cmocka_unit_test(test_remote_client_is_deauthed_never_killed),
    cmocka_unit_test(test_held_ghost_destroys_the_session),
    cmocka_unit_test(test_alias_skipped_on_clear_killed_on_kill),
    cmocka_unit_test(test_non_matching_and_non_user_are_skipped),
    cmocka_unit_test(test_null_subject_is_skipped),
    cmocka_unit_test(test_remote_client_is_skipped_by_default),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
