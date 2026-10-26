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

/* bounce_hold_stamp(held, primary): the ,H mark a home server puts on its
 * own client's N.  held = bounce_nick_side_held(), primary = the client is
 * its session's hs_client: the facts the receiving side's verdict reads. */

static void hold_stamp_covers_every_input(void **s)
{
  (void)s;
  assert_int_equal(bounce_hold_stamp(0, 0), BOUNCE_HOLD_MARK_OUTSIDER);
  assert_int_equal(bounce_hold_stamp(0, 1), BOUNCE_HOLD_MARK_PRIMARY);
  assert_int_equal(bounce_hold_stamp(1, 0), BOUNCE_HOLD_MARK_HELD);
  /* A held ghost is its session's hs_client: held wins. */
  assert_int_equal(bounce_hold_stamp(1, 1), BOUNCE_HOLD_MARK_HELD);
  /* Any nonzero value is "yes". */
  assert_int_equal(bounce_hold_stamp(7, 0), BOUNCE_HOLD_MARK_HELD);
  assert_int_equal(bounce_hold_stamp(0, -1), BOUNCE_HOLD_MARK_PRIMARY);
}

static void hold_mark_letters_are_the_wire_letters(void **s)
{
  (void)s;
  /* The bytes on the wire: ,Hh ,Hp ,Hn. */
  assert_int_equal(BOUNCE_HOLD_MARK_HELD, 'h');
  assert_int_equal(BOUNCE_HOLD_MARK_PRIMARY, 'p');
  assert_int_equal(BOUNCE_HOLD_MARK_OUTSIDER, 'n');
}

static void hold_mark_valid_only_for_the_three_letters(void **s)
{
  int c;
  (void)s;
  for (c = -128; c < 128; c++) {
    int want = (c == 'h' || c == 'p' || c == 'n');
    assert_int_equal(bounce_hold_mark_valid((char)c), want);
  }
  /* Every stamp is a valid mark. */
  assert_true(bounce_hold_mark_valid(bounce_hold_stamp(0, 0)));
  assert_true(bounce_hold_mark_valid(bounce_hold_stamp(0, 1)));
  assert_true(bounce_hold_mark_valid(bounce_hold_stamp(1, 0)));
  assert_true(bounce_hold_mark_valid(bounce_hold_stamp(1, 1)));
}

/* bounce_hold_marks_trusted_path(): the trust rule the server's walk
 * from a client's home toward us feeds. */

static void trust_path_direct_link(void **s)
{
  (void)s;
  /* home = our direct link: one hop. */
  assert_int_equal(bounce_hold_marks_trusted_path(1, 1, 1, 1, 1), 1);
  /* It must announce H, and so must our SERVER line to it. */
  assert_int_equal(bounce_hold_marks_trusted_path(1, 0, 1, 1, 1), 0);
  assert_int_equal(bounce_hold_marks_trusted_path(1, 1, 1, 0, 1), 0);
  /* We send marks only while the tags are on. */
  assert_int_equal(bounce_hold_marks_trusted_path(1, 1, 1, 1, 0), 0);
  /* A walk that never reached our link (home is us, or the chain is
   * broken) trusts nothing. */
  assert_int_equal(bounce_hold_marks_trusted_path(1, 1, 0, 1, 1), 0);
  assert_int_equal(bounce_hold_marks_trusted_path(0, 0, 1, 1, 1), 0);
}

static void trust_path_multi_hop(void **s)
{
  (void)s;
  /* home - hub - our link: every hop announces H. */
  assert_int_equal(bounce_hold_marks_trusted_path(3, 3, 1, 1, 1), 1);
  /* One hop without H (an older server relays no mark) is enough to
   * leave the client's state unknown. */
  assert_int_equal(bounce_hold_marks_trusted_path(3, 2, 1, 1, 1), 0);
  assert_int_equal(bounce_hold_marks_trusted_path(3, 0, 1, 1, 1), 0);
  assert_int_equal(bounce_hold_marks_trusted_path(3, 3, 1, 0, 1), 0);
  assert_int_equal(bounce_hold_marks_trusted_path(3, 3, 1, 1, 0), 0);
}

/* Over a direct link the two ends trust each other's marks or neither
 * does, as long as each still has the tags as it had them when it sent
 * its SERVER line: X announced H iff its tags were on, and the far end
 * reads X's H from that line.  A runtime switch of the tags breaks it
 * (registered). */
static void trust_path_direct_link_is_mutual(void **s)
{
  int x_tags, y_tags, x_now, y_now;
  (void)s;
  for (x_tags = 0; x_tags < 2; x_tags++)
  for (y_tags = 0; y_tags < 2; y_tags++)
  for (x_now = 0; x_now < 2; x_now++)
  for (y_now = 0; y_now < 2; y_now++) {
    /* X's view of Y's marks: Y announced H (y_tags), X announced H
     * (x_tags), X's tags now. */
    int x_trusts = bounce_hold_marks_trusted_path(1, y_tags, 1, x_tags, x_now);
    int y_trusts = bounce_hold_marks_trusted_path(1, x_tags, 1, y_tags, y_now);
    if (x_now == x_tags && y_now == y_tags)
      assert_int_equal(x_trusts, y_trusts);
  }
  /* The residual: X switched its tags off after linking. */
  assert_int_equal(bounce_hold_marks_trusted_path(1, 1, 1, 1, 0), 0);
  assert_int_equal(bounce_hold_marks_trusted_path(1, 1, 1, 1, 1), 1);
}

/* bounce_alias_filing(): where a BX C's alias is filed. */

static void alias_filing_prefers_the_named_id(void **s)
{
  int p, a, u;
  (void)s;
  for (p = 0; p < 2; p++)
  for (a = 0; a < 2; a++)
  for (u = 0; u < 2; u++)
    assert_int_equal(bounce_alias_filing(1, p, a, u), BOUNCE_FILE_EXACT);
}

static void alias_filing_then_the_primarys_session(void **s)
{
  int a, u;
  (void)s;
  /* The primary the BX C names is the hs_client of a session here:
   * that session, whatever the account fallback or the mark say. */
  for (a = 0; a < 2; a++)
  for (u = 0; u < 2; u++)
    assert_int_equal(bounce_alias_filing(0, 1, a, u), BOUNCE_FILE_PRIMARY);
}

static void alias_filing_account_only_for_a_mirrored_id(void **s)
{
  (void)s;
  /* A BX C sent before its server took our id: the account's session. */
  assert_int_equal(bounce_alias_filing(0, 0, 1, 0), BOUNCE_FILE_ACCOUNT);
  /* An id BS C kept apart (or skipped as the loser): never ours. */
  assert_int_equal(bounce_alias_filing(0, 0, 1, 1), BOUNCE_FILE_NONE);
  /* Nothing to file into. */
  assert_int_equal(bounce_alias_filing(0, 0, 0, 0), BOUNCE_FILE_NONE);
  assert_int_equal(bounce_alias_filing(0, 0, 0, 1), BOUNCE_FILE_NONE);
}

/* bounce_promote_session(): which record a BX P updates. */

static void promote_session_prefers_the_named_id(void **s)
{
  int p, a, r;
  (void)s;
  for (p = 0; p < 2; p++)
  for (a = 0; a < 2; a++)
  for (r = 0; r < 2; r++)
    assert_int_equal(bounce_promote_session(1, p, a, r), BOUNCE_PROMOTE_EXACT);
}

static void promote_session_by_the_old_primary_needs_both_keys(void **s)
{
  (void)s;
  /* The old primary's one session, listing the new primary as its alias:
   * a record of the same session under another id. */
  assert_int_equal(bounce_promote_session(0, 1, 0, 1), BOUNCE_PROMOTE_PRIMARY);
  /* The new primary on no roster here: a face swap, not our record's
   * promote. */
  assert_int_equal(bounce_promote_session(0, 1, 0, 0), BOUNCE_PROMOTE_NONE);
  /* Two sessions claim the old primary: no one record to update. */
  assert_int_equal(bounce_promote_session(0, 1, 1, 1), BOUNCE_PROMOTE_NONE);
  assert_int_equal(bounce_promote_session(0, 1, 1, 0), BOUNCE_PROMOTE_NONE);
  /* No session has the old primary. */
  assert_int_equal(bounce_promote_session(0, 0, 0, 1), BOUNCE_PROMOTE_NONE);
  assert_int_equal(bounce_promote_session(0, 0, 0, 0), BOUNCE_PROMOTE_NONE);
}

/* bounce_server_at_or_behind(): a server tree, walked toward its root. */

struct fake_server {
  const struct fake_server *up;
};

static const void *fake_up(const void *srv)
{
  return srv ? ((const struct fake_server *)srv)->up : NULL;
}

/* me -- leaf -- leaf3            (leaf3 is behind the leaf)
 *    \- slot -- x3
 * me is its own uplink, as &me is. */
static struct fake_server me_srv, leaf_srv, leaf3_srv, slot_srv, x3_srv;

static void fake_tree(void)
{
  me_srv.up = &me_srv;
  leaf_srv.up = &me_srv;
  leaf3_srv.up = &leaf_srv;
  slot_srv.up = &me_srv;
  x3_srv.up = &slot_srv;
}

static void behind_the_departing_server_or_it(void **s)
{
  (void)s;
  fake_tree();
  assert_true(bounce_server_at_or_behind(&leaf_srv, &leaf_srv, fake_up));
  assert_true(bounce_server_at_or_behind(&leaf3_srv, &leaf_srv, fake_up));
  assert_true(bounce_server_at_or_behind(&x3_srv, &slot_srv, fake_up));
}

static void not_behind_it(void **s)
{
  (void)s;
  fake_tree();
  /* Our own server, a sibling link and a server behind the sibling stay. */
  assert_false(bounce_server_at_or_behind(&me_srv, &leaf_srv, fake_up));
  assert_false(bounce_server_at_or_behind(&slot_srv, &leaf_srv, fake_up));
  assert_false(bounce_server_at_or_behind(&x3_srv, &leaf_srv, fake_up));
  /* The departing server's uplink is not behind it. */
  assert_false(bounce_server_at_or_behind(&leaf_srv, &leaf3_srv, fake_up));
}

static void behind_walk_null_and_broken_trees(void **s)
{
  static struct fake_server loop_a, loop_b, orphan;
  (void)s;
  fake_tree();
  assert_false(bounce_server_at_or_behind(NULL, &leaf_srv, fake_up));
  assert_false(bounce_server_at_or_behind(&leaf_srv, NULL, fake_up));
  assert_false(bounce_server_at_or_behind(&leaf_srv, &leaf_srv, NULL));
  /* A server with no uplink ends the walk. */
  orphan.up = NULL;
  assert_false(bounce_server_at_or_behind(&orphan, &leaf_srv, fake_up));
  /* A cycle that never reaches the departing server ends too. */
  loop_a.up = &loop_b;
  loop_b.up = &loop_a;
  assert_false(bounce_server_at_or_behind(&loop_a, &leaf_srv, fake_up));
}

/* bounce_squit_prepares(has_primary, primary_local, primary_behind,
 *                       origin_behind) */

static void squit_readies_a_session_whose_primary_left(void **s)
{
  int o;
  (void)s;
  /* Whatever the record says of its origin. */
  for (o = 0; o < 2; o++)
    assert_true(bounce_squit_prepares(1, 0, 1, o));
}

static void squit_leaves_a_session_whose_primary_stays(void **s)
{
  int b, o;
  (void)s;
  for (o = 0; o < 2; o++) {
    /* A primary of another server that stays linked. */
    assert_false(bounce_squit_prepares(1, 0, 0, o));
    /* Our own primary, live or held, whatever the origin says. */
    for (b = 0; b < 2; b++)
      assert_false(bounce_squit_prepares(1, 1, b, o));
  }
}

static void squit_goes_by_the_origin_without_a_primary(void **s)
{
  int l, b;
  (void)s;
  for (l = 0; l < 2; l++)
    for (b = 0; b < 2; b++) {
      assert_true(bounce_squit_prepares(0, l, b, 1));
      assert_false(bounce_squit_prepares(0, l, b, 0));
    }
}

/* bounce_hold_expiry_action(has_primary, primary_ours_held, alias_count) */

static void hold_expiry_ends_only_our_held_ghost(void **s)
{
  (void)s;
  assert_int_equal(bounce_hold_expiry_action(1, 1, 0), BOUNCE_HOLD_END);
  assert_int_equal(bounce_hold_expiry_action(1, 1, 2), BOUNCE_HOLD_PROMOTE);
}

static void hold_expiry_never_acts_on_another_holders_primary(void **s)
{
  int n;
  (void)s;
  /* A client of another server, or a live one: no BS X, no promote. */
  for (n = 0; n < 3; n++)
    assert_int_equal(bounce_hold_expiry_action(1, 0, n), BOUNCE_HOLD_KEEP);
}

static void hold_expiry_without_a_primary(void **s)
{
  (void)s;
  assert_int_equal(bounce_hold_expiry_action(0, 0, 1), BOUNCE_HOLD_PROMOTE);
  assert_int_equal(bounce_hold_expiry_action(0, 0, 0), BOUNCE_HOLD_DROP);
}

/* bounce_same_session_yields(ours_holding, ours_live, theirs_active,
 *                            their_primary, kc_conflict) */

static void held_copy_yields_to_a_visible_live_copy(void **s)
{
  (void)s;
  assert_true(bounce_same_session_yields(1, 0, 1, 1, 0));
}

static void held_copy_keeps_otherwise(void **s)
{
  int h, l, a, p, k;
  (void)s;
  for (h = 0; h < 2; h++)
  for (l = 0; l < 2; l++)
  for (a = 0; a < 2; a++)
  for (p = 0; p < 2; p++)
  for (k = 0; k < 2; k++) {
    if (h && !l && a && p && !k)
      continue;
    assert_false(bounce_same_session_yields(h, l, a, p, k));
  }
}

/* bounce_bsx_keeps(has_primary, primary_ours, primary_killed) */

static void bsx_keeps_a_record_we_hold(void **s)
{
  (void)s;
  /* Our live primary, or our held ghost: we hold the session. */
  assert_true(bounce_bsx_keeps(1, 1, 0));
}

static void bsx_ends_a_record_held_elsewhere(void **s)
{
  int k;
  (void)s;
  for (k = 0; k < 2; k++) {
    /* A primary of another server, or none at all. */
    assert_false(bounce_bsx_keeps(1, 0, k));
    assert_false(bounce_bsx_keeps(0, 0, k));
    assert_false(bounce_bsx_keeps(0, 1, k));
  }
  /* Ours, but killed: its exit ends the session anyway. */
  assert_false(bounce_bsx_keeps(1, 1, 1));
}

/* bounce_bsa_action(resolved, cand_alias, cand_on_roster, cand_ours,
 *                   slot_ours) */

static void bsa_installs_the_senders_primary(void **s)
{
  (void)s;
  /* A user of the sender, in no roster, while the slot is not ours. */
  assert_int_equal(bounce_bsa_action(1, 0, 0, 0, 0), BOUNCE_BSA_INSTALL);
}

static void bsa_never_installs_an_alias_or_a_roster_member(void **s)
{
  int r, o, sl;
  (void)s;
  for (r = 0; r < 2; r++)
    for (o = 0; o < 2; o++)
      for (sl = 0; sl < 2; sl++) {
        /* A per-alias line of a burst names an alias replica. */
        assert_int_equal(bounce_bsa_action(1, 1, r, o, sl), BOUNCE_BSA_IGNORE);
        /* A client our record lists as an alias. */
        assert_int_equal(bounce_bsa_action(1, 0, 1, o, sl), BOUNCE_BSA_IGNORE);
      }
}

static void bsa_never_replaces_our_primary_or_held_ghost(void **s)
{
  (void)s;
  /* Our live primary or our held ghost holds the slot: neither a client
   * the line resolves to nor one it does not changes it, and the kept
   * numeric stays too. */
  assert_int_equal(bounce_bsa_action(1, 0, 0, 0, 1), BOUNCE_BSA_IGNORE);
  assert_int_equal(bounce_bsa_action(0, 0, 0, 0, 1), BOUNCE_BSA_IGNORE);
}

static void bsa_never_installs_a_client_of_ours(void **s)
{
  int sl;
  (void)s;
  for (sl = 0; sl < 2; sl++)
    assert_int_equal(bounce_bsa_action(1, 0, 0, 1, sl), BOUNCE_BSA_IGNORE);
}

static void bsa_keeps_the_numeric_of_a_client_not_known_here(void **s)
{
  (void)s;
  assert_int_equal(bounce_bsa_action(0, 0, 0, 0, 0), BOUNCE_BSA_NUMERIC);
}

static void bsa_every_input(void **s)
{
  int r, a, ro, o, sl;
  (void)s;
  for (r = 0; r < 2; r++)
  for (a = 0; a < 2; a++)
  for (ro = 0; ro < 2; ro++)
  for (o = 0; o < 2; o++)
  for (sl = 0; sl < 2; sl++) {
    enum bounce_bsa_action act;
    /* The candidate's facts mean nothing when it did not resolve. */
    if (!r && (a || ro || o))
      continue;
    act = bounce_bsa_action(r, a, ro, o, sl);
    if (sl || a || ro || o)
      assert_int_equal(act, BOUNCE_BSA_IGNORE);
    else
      assert_int_equal(act, r ? BOUNCE_BSA_INSTALL : BOUNCE_BSA_NUMERIC);
  }
}

/* bounce_bsa_yields(in_burst, slot_ours_held, cand_member, ours_holding,
 *                   kc_conflict) */

static void bsa_attach_elsewhere_makes_our_held_copy_yield(void **s)
{
  (void)s;
  assert_true(bounce_bsa_yields(0, 1, 1, 1, 0));
}

static void bsa_yield_needs_every_fact(void **s)
{
  int b, h, m, o, k;
  (void)s;
  for (b = 0; b < 2; b++)
  for (h = 0; h < 2; h++)
  for (m = 0; m < 2; m++)
  for (o = 0; o < 2; o++)
  for (k = 0; k < 2; k++) {
    if (!b && h && m && o && !k)
      continue;
    /* A burst line (the peer's copy, announced), a slot that is not our
     * held ghost, a client that is not a visible member, a record not
     * held here, another Keycloak user: no yield. */
    assert_false(bounce_bsa_yields(b, h, m, o, k));
  }
}

/* bounce_bsd_action(kc_conflict, slot_ours) */

static void bsd_applies_to_a_slot_not_ours(void **s)
{
  (void)s;
  assert_int_equal(bounce_bsd_action(0, 0), BOUNCE_BSD_APPLY);
}

static void bsd_never_rewrites_a_slot_of_ours(void **s)
{
  (void)s;
  assert_int_equal(bounce_bsd_action(0, 1), BOUNCE_BSD_NOTE);
}

static void bsd_of_another_keycloak_user_only_passes_on(void **s)
{
  int sl;
  (void)s;
  for (sl = 0; sl < 2; sl++)
    assert_int_equal(bounce_bsd_action(1, sl), BOUNCE_BSD_FORWARD);
}

/* bounce_bsd_reannounces(action, slot_live): our primary is announced
 * again only over our own live primary. */
static void bsd_reannounces_only_over_a_live_slot(void **s)
{
  (void)s;
  assert_int_equal(bounce_bsd_reannounces(BOUNCE_BSD_NOTE, 1), 1);
  /* Our held ghost holds the slot: neither copy is live. */
  assert_int_equal(bounce_bsd_reannounces(BOUNCE_BSD_NOTE, 0), 0);
  /* The record followed the sender, or the line was another user's. */
  assert_int_equal(bounce_bsd_reannounces(BOUNCE_BSD_APPLY, 0), 0);
  assert_int_equal(bounce_bsd_reannounces(BOUNCE_BSD_APPLY, 1), 0);
  assert_int_equal(bounce_bsd_reannounces(BOUNCE_BSD_FORWARD, 0), 0);
  assert_int_equal(bounce_bsd_reannounces(BOUNCE_BSD_FORWARD, 1), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(behind_the_departing_server_or_it),
    cmocka_unit_test(not_behind_it),
    cmocka_unit_test(behind_walk_null_and_broken_trees),
    cmocka_unit_test(squit_readies_a_session_whose_primary_left),
    cmocka_unit_test(squit_leaves_a_session_whose_primary_stays),
    cmocka_unit_test(squit_goes_by_the_origin_without_a_primary),
    cmocka_unit_test(hold_expiry_ends_only_our_held_ghost),
    cmocka_unit_test(hold_expiry_never_acts_on_another_holders_primary),
    cmocka_unit_test(hold_expiry_without_a_primary),
    cmocka_unit_test(held_copy_yields_to_a_visible_live_copy),
    cmocka_unit_test(held_copy_keeps_otherwise),
    cmocka_unit_test(bsx_keeps_a_record_we_hold),
    cmocka_unit_test(bsx_ends_a_record_held_elsewhere),
    cmocka_unit_test(bsa_installs_the_senders_primary),
    cmocka_unit_test(bsa_never_installs_an_alias_or_a_roster_member),
    cmocka_unit_test(bsa_never_replaces_our_primary_or_held_ghost),
    cmocka_unit_test(bsa_never_installs_a_client_of_ours),
    cmocka_unit_test(bsa_keeps_the_numeric_of_a_client_not_known_here),
    cmocka_unit_test(bsa_every_input),
    cmocka_unit_test(bsa_attach_elsewhere_makes_our_held_copy_yield),
    cmocka_unit_test(bsa_yield_needs_every_fact),
    cmocka_unit_test(bsd_applies_to_a_slot_not_ours),
    cmocka_unit_test(bsd_never_rewrites_a_slot_of_ours),
    cmocka_unit_test(bsd_of_another_keycloak_user_only_passes_on),
    cmocka_unit_test(bsd_reannounces_only_over_a_live_slot),
    cmocka_unit_test(hold_stamp_covers_every_input),
    cmocka_unit_test(hold_mark_letters_are_the_wire_letters),
    cmocka_unit_test(hold_mark_valid_only_for_the_three_letters),
    cmocka_unit_test(trust_path_direct_link),
    cmocka_unit_test(trust_path_multi_hop),
    cmocka_unit_test(trust_path_direct_link_is_mutual),
    cmocka_unit_test(alias_filing_prefers_the_named_id),
    cmocka_unit_test(alias_filing_then_the_primarys_session),
    cmocka_unit_test(alias_filing_account_only_for_a_mirrored_id),
    cmocka_unit_test(promote_session_prefers_the_named_id),
    cmocka_unit_test(promote_session_by_the_old_primary_needs_both_keys),
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
