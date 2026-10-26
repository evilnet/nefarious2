/* cmocka suite for the pure bouncer wire decisions (include/bouncer_wire.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_wire.h"

/* bounce_legacy_link_knows(link_aware, link_gated, face_behind_link) */

static void aware_link_never_knows(void **s)
{
  (void)s;
  /* An IRCv3-aware link follows the session through BX/BS (it got the
   * BX X or BX P itself); it never needs a legacy retraction. */
  assert_false(bounce_legacy_link_knows(1, 0, 0));
}

static void gated_link_knows_nothing(void **s)
{
  (void)s;
  /* No N has gone to a gated link yet; its burst at release carries the
   * final face once. */
  assert_false(bounce_legacy_link_knows(0, 1, 0));
}

static void own_direction_excluded(void **s)
{
  (void)s;
  /* The link the face lives behind introduced it to us. */
  assert_false(bounce_legacy_link_knows(0, 0, 1));
}

static void legacy_link_may_know_whatever_is_recorded(void **s)
{
  (void)s;
  /* A legacy link that is neither gated nor the face's own direction may
   * know the face, even when the session's burst records name another
   * face toward it: a relayed N records nothing, and a record can be
   * stale.  The records are not an input. */
  assert_true(bounce_legacy_link_knows(0, 0, 0));
}

static void only_a_plain_legacy_link_knows(void **s)
{
  int aware, gated, behind;
  (void)s;
  for (aware = 0; aware < 2; aware++)
    for (gated = 0; gated < 2; gated++)
      for (behind = 0; behind < 2; behind++)
        assert_int_equal(bounce_legacy_link_knows(aware, gated, behind),
                         !aware && !gated && !behind);
}

/* bounce_demote_check(stage, facts) */

/* Facts for a demote that can run, as the caller reads them before the
 * demote: our live primary, its own session, a new primary of the same
 * account homed on an IRCv3-aware server. */
static struct bounce_demote_facts plan_ok(void)
{
  struct bounce_demote_facts f;
  memset(&f, 0, sizeof f);
  f.face_account_user = 1;
  f.session_found = 1;
  f.session_account = 1;
  f.session_slot = BOUNCE_SLOT_FACE;
  f.new_home_known = 1;
  f.new_home_aware = 1;
  f.new_account = 1;
  return f;
}

/* The same demote between its two steps: the face is the alias the
 * demote made and the slot waits for the new primary. */
static struct bounce_demote_facts finish_ok(void)
{
  struct bounce_demote_facts f = plan_ok();
  f.face_alias = 1;
  f.session_slot = BOUNCE_SLOT_EMPTY;
  return f;
}

static void demote_runs_when_every_guard_holds(void **s)
{
  struct bounce_demote_facts plan = plan_ok(), fin = finish_ok();
  (void)s;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &plan), BOUNCE_DEMOTE_OK);
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &fin), BOUNCE_DEMOTE_OK);
}

static void no_facts_is_refused(void **s)
{
  (void)s;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, NULL), BOUNCE_DEMOTE_NO_NEW_HOME);
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, NULL), BOUNCE_DEMOTE_NO_NEW_HOME);
}

static void reconcile_skips_a_candidate_homed_on_legacy(void **s)
{
  /* The post-burst reconcile asks about each co-session candidate: a
   * live remote client of the account whose home is a legacy server
   * (its session id was stamped by whichever fork server relayed it).
   * The face is our live primary, the candidate is known and carries the
   * account. */
  struct bounce_demote_facts f = plan_ok();
  (void)s;
  f.new_home_aware = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_LEGACY_HOME);
}

static void demote_refuses_a_legacy_home(void **s)
{
  /* The demote itself (and the same-nick merge deciding before it) asks
   * about the new primary's HOME server, never the link it came in on:
   * a legacy home is refused at both steps. */
  struct bounce_demote_facts plan = plan_ok(), fin = finish_ok();
  (void)s;
  plan.new_home_aware = 0;
  fin.new_home_aware = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &plan), BOUNCE_DEMOTE_LEGACY_HOME);
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &fin), BOUNCE_DEMOTE_LEGACY_HOME);
}

static void demote_guards_on_the_face(void **s)
{
  struct bounce_demote_facts f;
  (void)s;

  f = plan_ok(); f.face_account_user = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_NOT_ACCOUNT_USER);
  f = plan_ok(); f.face_alias = 1;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_FACE_ALIAS);
  f = plan_ok(); f.face_held = 1;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_FACE_HELD);
  /* A dying primary is left to its own exit, which holds the session; an
   * alias exit would broadcast BX X and end it everywhere. */
  f = plan_ok(); f.face_dying = 1;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_FACE_DYING);
}

static void demote_guards_on_the_session(void **s)
{
  struct bounce_demote_facts f;
  (void)s;

  f = plan_ok(); f.session_found = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_NO_SESSION);
  /* The face must be the session's primary, not merely in the session. */
  f = plan_ok(); f.session_slot = BOUNCE_SLOT_OTHER;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_SESSION_SLOT);
  f = plan_ok(); f.session_slot = BOUNCE_SLOT_EMPTY;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_SESSION_SLOT);
  f = plan_ok(); f.new_home_known = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_NO_NEW_HOME);
}

/* Each finish guard refuses at FINISH, and the same fact already refuses
 * at PLAN, so a merge that decided "yes" never meets it half done. */
static void finish_guard(void (*apply)(struct bounce_demote_facts *),
                         enum bounce_demote_bar want)
{
  struct bounce_demote_facts plan = plan_ok(), fin = finish_ok();
  apply(&plan);
  apply(&fin);
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &fin), want);
  assert_int_not_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &plan), BOUNCE_DEMOTE_OK);
}

static void no_new_primary(struct bounce_demote_facts *f) { f->new_home_known = 0; }
static void face_without_account(struct bounce_demote_facts *f) { f->face_account_user = 0; }
static void new_primary_other_account(struct bounce_demote_facts *f) { f->new_account = 0; }
static void no_session(struct bounce_demote_facts *f) { f->session_found = 0; }
static void session_other_account(struct bounce_demote_facts *f) { f->session_account = 0; }

static void finish_needs_the_new_primary(void **s)
{
  (void)s;
  finish_guard(no_new_primary, BOUNCE_DEMOTE_NO_NEW_HOME);
}

static void finish_needs_the_face_logged_in(void **s)
{
  (void)s;
  finish_guard(face_without_account, BOUNCE_DEMOTE_NOT_ACCOUNT_USER);
}

static void finish_needs_the_new_primary_on_the_account(void **s)
{
  /* No account on the new primary, or another one, reads the same. */
  (void)s;
  finish_guard(new_primary_other_account, BOUNCE_DEMOTE_NEW_ACCOUNT);
}

static void finish_needs_the_session(void **s)
{
  (void)s;
  finish_guard(no_session, BOUNCE_DEMOTE_NO_SESSION);
}

static void finish_needs_the_session_on_the_account(void **s)
{
  (void)s;
  finish_guard(session_other_account, BOUNCE_DEMOTE_SESSION_ACCOUNT);
}

static void finish_needs_the_slot_empty(void **s)
{
  /* Between the two steps the slot is empty; a client there (the face
   * itself, or another) means the demote did not run on this session. */
  struct bounce_demote_facts f = finish_ok();
  (void)s;
  f.session_slot = BOUNCE_SLOT_OTHER;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &f), BOUNCE_DEMOTE_SESSION_SLOT);
  f.session_slot = BOUNCE_SLOT_FACE;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &f), BOUNCE_DEMOTE_SESSION_SLOT);
}

static void finish_needs_the_demoted_alias(void **s)
{
  struct bounce_demote_facts f = finish_ok();
  (void)s;
  f.face_alias = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &f), BOUNCE_DEMOTE_FACE_ALIAS);
}

static void session_of_another_keycloak_user(struct bounce_demote_facts *f) { f->kc_id_conflict = 1; }

static void finish_refuses_another_keycloak_user(void **s)
{
  (void)s;
  finish_guard(session_of_another_keycloak_user, BOUNCE_DEMOTE_KC_CONFLICT);
}

static void another_keycloak_user_is_refused_first(void **s)
{
  /* Sessions of different Keycloak users are never merged.  The bar is
   * the Keycloak one whatever else fails, so the same-nick merge vetoes
   * exactly when the ids differ, as it did before it asked the
   * predicate. */
  struct bounce_demote_facts f = plan_ok();
  (void)s;
  f.kc_id_conflict = 1;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_KC_CONFLICT);
  f.face_dying = 1;
  f.new_home_aware = 0;
  f.session_slot = BOUNCE_SLOT_OTHER;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_KC_CONFLICT);
  f.new_home_known = 0;
  assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f), BOUNCE_DEMOTE_KC_CONFLICT);
}

static void a_plan_yes_carries_through_the_finish(void **s)
{
  /* For every combination of the facts the demote itself does not
   * change, PLAN "yes" means the finish after the demote ("the face is
   * now an alias, the slot is empty") says yes too.  This is what lets
   * the same-nick merge withhold an N and swap the legacy face before
   * the demote runs. */
  unsigned int bits;
  (void)s;
  for (bits = 0; bits < (1u << 10); bits++) {
    struct bounce_demote_facts plan, fin;
    memset(&plan, 0, sizeof plan);
    plan.face_account_user = !!(bits & 1);
    plan.face_alias        = !!(bits & 2);
    plan.face_held         = !!(bits & 4);
    plan.face_dying        = !!(bits & 8);
    plan.session_found     = !!(bits & 16);
    plan.session_account   = !!(bits & 32);
    plan.new_home_known    = !!(bits & 64);
    plan.new_home_aware    = !!(bits & 128);
    plan.new_account       = !!(bits & 256);
    plan.kc_id_conflict    = !!(bits & 512);
    plan.session_slot      = BOUNCE_SLOT_FACE;
    if (bounce_demote_check(BOUNCE_DEMOTE_PLAN, &plan) != BOUNCE_DEMOTE_OK)
      continue;
    fin = plan;
    fin.face_alias = 1;
    fin.session_slot = BOUNCE_SLOT_EMPTY;
    assert_int_equal(bounce_demote_check(BOUNCE_DEMOTE_FINISH, &fin), BOUNCE_DEMOTE_OK);
  }
}

static void every_bar_has_a_name(void **s)
{
  int b;
  (void)s;
  assert_string_equal(bounce_demote_bar_name(BOUNCE_DEMOTE_OK), "ok");
  assert_string_equal(bounce_demote_bar_name(BOUNCE_DEMOTE_LEGACY_HOME), "legacy home");
  assert_string_equal(bounce_demote_bar_name(BOUNCE_DEMOTE_KC_CONFLICT), "Keycloak ids differ");
  for (b = BOUNCE_DEMOTE_OK; b <= BOUNCE_DEMOTE_KC_CONFLICT; b++)
    assert_string_not_equal(bounce_demote_bar_name((enum bounce_demote_bar)b), "?");
  assert_string_equal(bounce_demote_bar_name((enum bounce_demote_bar)99), "?");
}

/* bounce_merge_choose(we_lose, bar) */

static void merge_winner_refuses_whatever_its_own_demote_could_do(void **s)
{
  /* The winner never demotes, so its own eligibility is no input: it
   * refuses the N and the peer demotes -- except for another Keycloak
   * user, below. */
  int b;
  (void)s;
  for (b = BOUNCE_DEMOTE_OK; b <= BOUNCE_DEMOTE_KC_CONFLICT; b++) {
    if (b == BOUNCE_DEMOTE_KC_CONFLICT)
      continue;
    assert_int_equal(bounce_merge_choose(0, (enum bounce_demote_bar)b), BOUNCE_MERGE_REFUSE);
  }
}

static void merge_loser_swaps_only_when_its_demote_can_run(void **s)
{
  /* Every bar that stops the demote sends the loser to the classic
   * collision rules: its primary stays live under the nick, so the N is
   * never installed beside it and the legacy face is never swapped. */
  int b;
  (void)s;
  assert_int_equal(bounce_merge_choose(1, BOUNCE_DEMOTE_OK), BOUNCE_MERGE_SWAP);
  for (b = BOUNCE_DEMOTE_OK + 1; b <= BOUNCE_DEMOTE_KC_CONFLICT; b++)
    assert_int_equal(bounce_merge_choose(1, (enum bounce_demote_bar)b), BOUNCE_MERGE_CLASSIC);
}

static void merge_of_another_keycloak_user_is_classic_on_both_sides(void **s)
{
  /* Different Keycloak users are never merged: both sides read the same
   * two ids, so both fall to the classic rules, winner and loser alike. */
  (void)s;
  assert_int_equal(bounce_merge_choose(0, BOUNCE_DEMOTE_KC_CONFLICT), BOUNCE_MERGE_CLASSIC);
  assert_int_equal(bounce_merge_choose(1, BOUNCE_DEMOTE_KC_CONFLICT), BOUNCE_MERGE_CLASSIC);
}

static void merge_loser_with_a_dying_primary_is_classic(void **s)
{
  /* The ineligible case the bed cannot stage (a socket dying between its
   * read error and its exit): classic, never a swap. */
  struct bounce_demote_facts f = plan_ok();
  (void)s;
  f.face_dying = 1;
  assert_int_equal(bounce_merge_choose(1, bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f)),
                   BOUNCE_MERGE_CLASSIC);
  f = plan_ok();
  assert_int_equal(bounce_merge_choose(1, bounce_demote_check(BOUNCE_DEMOTE_PLAN, &f)),
                   BOUNCE_MERGE_SWAP);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(aware_link_never_knows),
    cmocka_unit_test(gated_link_knows_nothing),
    cmocka_unit_test(own_direction_excluded),
    cmocka_unit_test(legacy_link_may_know_whatever_is_recorded),
    cmocka_unit_test(only_a_plain_legacy_link_knows),
    cmocka_unit_test(demote_runs_when_every_guard_holds),
    cmocka_unit_test(no_facts_is_refused),
    cmocka_unit_test(reconcile_skips_a_candidate_homed_on_legacy),
    cmocka_unit_test(demote_refuses_a_legacy_home),
    cmocka_unit_test(demote_guards_on_the_face),
    cmocka_unit_test(demote_guards_on_the_session),
    cmocka_unit_test(finish_needs_the_new_primary),
    cmocka_unit_test(finish_needs_the_face_logged_in),
    cmocka_unit_test(finish_needs_the_new_primary_on_the_account),
    cmocka_unit_test(finish_needs_the_session),
    cmocka_unit_test(finish_needs_the_session_on_the_account),
    cmocka_unit_test(finish_needs_the_slot_empty),
    cmocka_unit_test(finish_needs_the_demoted_alias),
    cmocka_unit_test(finish_refuses_another_keycloak_user),
    cmocka_unit_test(another_keycloak_user_is_refused_first),
    cmocka_unit_test(a_plan_yes_carries_through_the_finish),
    cmocka_unit_test(every_bar_has_a_name),
    cmocka_unit_test(merge_winner_refuses_whatever_its_own_demote_could_do),
    cmocka_unit_test(merge_loser_swaps_only_when_its_demote_can_run),
    cmocka_unit_test(merge_of_another_keycloak_user_is_classic_on_both_sides),
    cmocka_unit_test(merge_loser_with_a_dying_primary_is_classic),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
