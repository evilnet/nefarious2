/* cmocka suite for bounce_converge_peer_wins and bounce_nick_verdict
 * (include/bouncer_converge.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_converge.h"

#define OLDER "AaCcFXwvcGOUX/PyoTpM1Q"   /* lexicographically lower = older UUID v7 */
#define NEWER "AaCrYZ3QcGOHqRsexudEHQ"

static void test_active_beats_holding_whatever_the_age(void **state)
{
  (void)state;
  /* The field case: our record is an older, clientless HOLDING replica;
   * the peer announces the live session.  The peer must win. */
  assert_int_equal(bounce_converge_peer_wins(1, OLDER, 0, NEWER), 1);
  /* Mirror image on the other server: we hold the live one. */
  assert_int_equal(bounce_converge_peer_wins(0, NEWER, 1, OLDER), 0);
  /* Age in the other direction changes nothing. */
  assert_int_equal(bounce_converge_peer_wins(1, NEWER, 0, OLDER), 1);
  assert_int_equal(bounce_converge_peer_wins(0, OLDER, 1, NEWER), 0);
}

static void test_same_state_older_id_wins(void **state)
{
  (void)state;
  assert_int_equal(bounce_converge_peer_wins(0, NEWER, 0, OLDER), 1);
  assert_int_equal(bounce_converge_peer_wins(0, OLDER, 0, NEWER), 0);
  assert_int_equal(bounce_converge_peer_wins(1, NEWER, 1, OLDER), 1);
  assert_int_equal(bounce_converge_peer_wins(1, OLDER, 1, NEWER), 0);
}

static void test_identical_id_keeps_ours(void **state)
{
  (void)state;
  assert_int_equal(bounce_converge_peer_wins(0, OLDER, 0, OLDER), 0);
  assert_int_equal(bounce_converge_peer_wins(1, OLDER, 1, OLDER), 0);
}

static void test_both_sides_agree(void **state)
{
  (void)state;
  /* Determinism: for every pairing exactly one side wins. */
  static const char *ids[2] = { OLDER, NEWER };
  int ls, ps, li, pi;
  for (ls = 0; ls < 2; ls++)
    for (ps = 0; ps < 2; ps++)
      for (li = 0; li < 2; li++)
        for (pi = 0; pi < 2; pi++) {
          int a = bounce_converge_peer_wins(ls, ids[li], ps, ids[pi]);
          int b = bounce_converge_peer_wins(ps, ids[pi], ls, ids[li]);
          if (li == pi && ls == ps)
            assert_int_equal(a + b, 0);   /* same record: nobody yields */
          else
            assert_int_equal(a + b, 1);   /* exactly one side yields */
        }
}

static void test_null_ids_do_not_crash(void **state)
{
  (void)state;
  assert_int_equal(bounce_converge_peer_wins(1, NULL, 0, NULL), 1);
  assert_int_equal(bounce_converge_peer_wins(0, NULL, 0, NULL), 0);
}

/* ---- bounce_nick_verdict: a same-nick meeting of one account ---- */

#define NA "ACAAA"   /* the lower full numeric */
#define NB "BjAAA"
#define MINTED "AaCzzzzzcGOHqRsexudEHQ"   /* a login's own id, no session's */

/* A side whose hold state is known: a held ghost or a live client. */
static struct bounce_nick_side known(int held, time_t lastnick,
                                     const char *sessid, const char *numeric)
{
  struct bounce_nick_side s;
  memset(&s, 0, sizeof s);
  s.held = held;
  s.state_known = 1;
  s.lastnick = lastnick;
  s.sessid = sessid;
  s.numeric = numeric;
  return s;
}

/* An incoming side whose hold state nobody announced. */
static struct bounce_nick_side unknown(time_t lastnick, const char *sessid,
                                       const char *numeric)
{
  struct bounce_nick_side s = known(0, lastnick, sessid, numeric);
  s.state_known = 0;
  return s;
}

/* An incoming live login known to be in no session. */
static struct bounce_nick_side outsider(time_t lastnick, const char *numeric)
{
  struct bounce_nick_side s = known(0, lastnick, MINTED, numeric);
  s.non_member = 1;
  return s;
}

static enum bounce_nick_verdict V(struct bounce_nick_side local,
                                  struct bounce_nick_side incoming,
                                  int local_is_session_primary, int link_gated)
{
  return bounce_nick_verdict(&local, &incoming, local_is_session_primary, 0,
                             link_gated);
}

static void test_held_vs_known_live_retires_whatever_the_age(void **state)
{
  int primary;
  (void)state;
  for (primary = 0; primary < 2; primary++) {
    assert_int_equal(V(known(1, 100, OLDER, NA), known(0, 50, NEWER, NB),
                       primary, 0), BNV_RETIRE_LOCAL);
    assert_int_equal(V(known(1, 50, OLDER, NA), known(0, 100, NEWER, NB),
                       primary, 0), BNV_RETIRE_LOCAL);
    /* Nor does the session ids' age, or the numerics' order. */
    assert_int_equal(V(known(1, 50, NEWER, NB), known(0, 100, OLDER, NA),
                       primary, 0), BNV_RETIRE_LOCAL);
  }
}

static void test_held_vs_known_live_same_session_drops_the_ghost(void **state)
{
  (void)state;
  /* The live one is in our session: ending the session would end it
   * too, so only our ghost goes. */
  assert_int_equal(V(known(1, 100, OLDER, NA), known(0, 50, OLDER, NB), 1, 0),
                   BNV_DROP_LOCAL_GHOST);
  assert_int_equal(V(known(1, 50, OLDER, NB), known(0, 100, OLDER, NA), 1, 0),
                   BNV_DROP_LOCAL_GHOST);
}

static void test_live_vs_known_held_keeps(void **state)
{
  (void)state;
  assert_int_equal(V(known(0, 100, NEWER, NB), known(1, 50, OLDER, NA), 1, 0),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(0, 50, OLDER, NA), known(1, 100, NEWER, NB), 1, 0),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(0, 50, OLDER, NA), known(1, 100, OLDER, NB), 1, 0),
                   BNV_KEEP_LOCAL);
  /* Ours not in a session: the open case, see the D-LH tests below. */
}

static void test_held_vs_held_older_sessid_keeps(void **state)
{
  (void)state;
  assert_int_equal(V(known(1, 100, OLDER, NB), known(1, 50, NEWER, NA), 1, 0),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(1, 50, NEWER, NA), known(1, 100, OLDER, NB), 1, 0),
                   BNV_RETIRE_LOCAL);
}

static void test_held_vs_held_same_sessid_lower_numeric_keeps(void **state)
{
  (void)state;
  assert_int_equal(V(known(1, 100, OLDER, NA), known(1, 50, OLDER, NB), 1, 0),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(1, 50, OLDER, NB), known(1, 100, OLDER, NA), 1, 0),
                   BNV_DROP_LOCAL_GHOST);
}

static void test_live_vs_live_is_d2(void **state)
{
  int k;
  (void)state;
  /* The same answers whether the incoming one is known live or its
   * state is unknown (today's wire). */
  for (k = 0; k < 2; k++) {
    struct bounce_nick_side old_in = k ? known(0, 100, NEWER, NB)
                                       : unknown(100, NEWER, NB);
    struct bounce_nick_side new_in = k ? known(0, 200, NEWER, NB)
                                       : unknown(200, NEWER, NB);
    struct bounce_nick_side tie_b = k ? known(0, 100, NEWER, NB)
                                      : unknown(100, NEWER, NB);
    struct bounce_nick_side tie_a = k ? known(0, 100, NEWER, NA)
                                      : unknown(100, NEWER, NA);
    assert_int_equal(V(known(0, 100, OLDER, NA), new_in, 1, 0), BNV_KEEP_LOCAL);
    assert_int_equal(V(known(0, 200, OLDER, NA), old_in, 1, 0),
                     BNV_DEMOTE_LOCAL);
    assert_int_equal(V(known(0, 100, OLDER, NA), tie_b, 1, 0), BNV_KEEP_LOCAL);
    assert_int_equal(V(known(0, 100, OLDER, NB), tie_a, 1, 0),
                     BNV_DEMOTE_LOCAL);
    /* Not its session's primary: no merge. */
    assert_int_equal(V(known(0, 100, OLDER, NA), new_in, 0, 0), BNV_CLASSIC);
    assert_int_equal(V(known(0, 200, OLDER, NA), old_in, 0, 0), BNV_CLASSIC);
  }
}

static void test_unknown_incoming(void **state)
{
  (void)state;
  /* Ours held: classic unless the link has not had our burst yet. */
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 1),
                   BNV_RETIRE_LOCAL);
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, OLDER, NB), 1, 1),
                   BNV_DROP_LOCAL_GHOST);
  /* The post-burst reconcile's call: never gated. */
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, OLDER, NB), 1, 0),
                   BNV_CLASSIC);
  /* Ours a live session primary: as live against live, gated or not. */
  assert_int_equal(V(known(0, 100, OLDER, NA), unknown(200, NEWER, NB), 1, 1),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(0, 200, OLDER, NA), unknown(100, NEWER, NB), 1, 1),
                   BNV_DEMOTE_LOCAL);
  assert_int_equal(V(known(0, 100, OLDER, NB), unknown(100, NEWER, NA), 1, 0),
                   BNV_DEMOTE_LOCAL);
}

static void test_live_non_member_vs_live_member_is_classic(void **state)
{
  (void)state;
  /* A login in no session is never merged into: from its side (ours not
   * a session primary) and from the member's side (it is known to be in
   * no session), whatever the ages. */
  assert_int_equal(V(known(0, 200, OLDER, NA), outsider(100, NB), 1, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(0, 100, OLDER, NA), outsider(200, NB), 1, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(0, 100, MINTED, NB), known(0, 200, OLDER, NA), 0, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(0, 200, MINTED, NB), known(0, 100, OLDER, NA), 0, 0),
                   BNV_CLASSIC);
  /* Its state needs no announcing: a login in no session is live. */
  {
    struct bounce_nick_side o = outsider(100, NB);
    o.state_known = 0;
    assert_int_equal(V(known(0, 200, OLDER, NA), o, 1, 0), BNV_CLASSIC);
  }
}

/* A live login in no session meets a held ghost of its account holding
 * its nick.  Open decision: (a) the live login wins and the held session
 * ends, or (b) classic collision (the older nick wins).  Until it is
 * made, the verdict keeps today's outcome, (b). */
static void test_dlh_live_non_member_vs_held_is_classic_until_decided(void **state)
{
  (void)state;
  /* From the held ghost's side. */
  assert_int_equal(V(known(1, 100, OLDER, NA), outsider(50, NB), 1, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(1, 50, OLDER, NA), outsider(100, NB), 1, 1),
                   BNV_CLASSIC);
  {
    struct bounce_nick_side o = outsider(100, NB);
    o.state_known = 0;
    assert_int_equal(V(known(1, 50, OLDER, NA), o, 1, 1), BNV_CLASSIC);
  }
  /* From the live login's side. */
  assert_int_equal(V(known(0, 100, MINTED, NB), known(1, 50, OLDER, NA), 0, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(0, 50, MINTED, NB), known(1, 100, OLDER, NA), 0, 1),
                   BNV_CLASSIC);
}

static void test_dlh_option_a_live_wins_PENDING(void **state)
{
  (void)state;
  print_message("PENDING: a live login in no session against a held ghost "
                "of its account is an open decision; these are option (a)'s "
                "answers (the live login wins, the held session ends). "
                "Enable when (a) is decided; delete if (b) is.\n");
  skip();
  assert_int_equal(V(known(1, 100, OLDER, NA), outsider(50, NB), 1, 0),
                   BNV_RETIRE_LOCAL);
  assert_int_equal(V(known(1, 50, OLDER, NA), outsider(100, NB), 1, 0),
                   BNV_RETIRE_LOCAL);
  assert_int_equal(V(known(0, 100, MINTED, NB), known(1, 50, OLDER, NA), 0, 0),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(0, 50, MINTED, NB), known(1, 100, OLDER, NA), 0, 0),
                   BNV_KEEP_LOCAL);
}

static void test_kc_conflict_is_classic(void **state)
{
  static const char *ids[3] = { OLDER, NEWER, MINTED };
  static const char *nums[2] = { NA, NB };
  static const time_t ts[2] = { 100, 200 };
  int lh, ik, ih, nm, li, ii, ln, in, lt, it, primary, gated;
  (void)state;
  for (lh = 0; lh < 2; lh++)
  for (ik = 0; ik < 2; ik++)
  for (ih = 0; ih < 2; ih++)
  for (nm = 0; nm < 2; nm++)
  for (li = 0; li < 3; li++)
  for (ii = 0; ii < 3; ii++)
  for (ln = 0; ln < 2; ln++)
  for (in = 0; in < 2; in++)
  for (lt = 0; lt < 2; lt++)
  for (it = 0; it < 2; it++)
  for (primary = 0; primary < 2; primary++)
  for (gated = 0; gated < 2; gated++) {
    struct bounce_nick_side l = known(lh, ts[lt], ids[li], nums[ln]);
    struct bounce_nick_side i = known(ih, ts[it], ids[ii], nums[in]);
    i.state_known = ik;
    i.non_member = nm;
    assert_int_equal(bounce_nick_verdict(&l, &i, primary, 1, gated),
                     BNV_CLASSIC);
  }
}

/* A side in the antisymmetry sweep.  member: in a session (a held ghost
 * always is); as ours it is local_is_session_primary, as the incoming
 * one it is !non_member. */
struct nick_spec {
  int held;
  int member;
  time_t lastnick;
  const char *sessid;
  const char *numeric;
};

static enum bounce_nick_verdict v_spec(const struct nick_spec *a,
                                       const struct nick_spec *b)
{
  struct bounce_nick_side l = known(a->held, a->lastnick, a->sessid, a->numeric);
  struct bounce_nick_side i = known(b->held, b->lastnick, b->sessid, b->numeric);
  i.non_member = !b->member;
  return bounce_nick_verdict(&l, &i, a->member, 0, 0);
}

static int yields(enum bounce_nick_verdict v)
{
  return v == BNV_RETIRE_LOCAL || v == BNV_DROP_LOCAL_GHOST
         || v == BNV_DEMOTE_LOCAL;
}

static void test_antisymmetric(void **state)
{
  /* The first four are the base set; the rest add a same-session held
   * pair, an equal-age live pair and logins in no session. */
  static const struct nick_spec sides[] = {
    { 1, 1, 100, OLDER, "ACAAA" },
    { 1, 1, 100, NEWER, "BjAAA" },
    { 0, 1, 100, OLDER, "ACAAB" },
    { 0, 1, 200, NEWER, "BjAAB" },
    { 1, 1, 300, OLDER, "BjAAC" },
    { 0, 1, 100, NEWER, "BjAAD" },
    { 0, 0,  50, MINTED, "ACAAE" },
    { 0, 0, 300, MINTED, "BjAAF" },
  };
  const int n = (int)(sizeof sides / sizeof sides[0]);
  int a, b, decided = 0;
  (void)state;
  for (a = 0; a < n; a++)
    for (b = 0; b < n; b++) {
      enum bounce_nick_verdict ab, ba;
      if (a == b)
        continue;
      ab = v_spec(&sides[a], &sides[b]);
      ba = v_spec(&sides[b], &sides[a]);
      /* One keeps exactly when the other yields... */
      assert_int_equal(ab == BNV_KEEP_LOCAL, yields(ba));
      /* ...and both fall back to the classic rules together. */
      assert_int_equal(ab == BNV_CLASSIC, ba == BNV_CLASSIC);
      /* A session ends only for another session's client. */
      if (ab == BNV_RETIRE_LOCAL)
        assert_int_not_equal(strcmp(sides[a].sessid, sides[b].sessid), 0);
      if (ab == BNV_DROP_LOCAL_GHOST)
        assert_int_equal(strcmp(sides[a].sessid, sides[b].sessid), 0);
      if (ab != BNV_CLASSIC)
        decided++;
    }
  /* Every pair of the base set is decided, not left to the classic rules. */
  for (a = 0; a < 4; a++)
    for (b = 0; b < 4; b++)
      if (a != b)
        assert_int_not_equal(v_spec(&sides[a], &sides[b]), BNV_CLASSIC);
  assert_true(decided > 0);
}

static void test_matches_bs_c_convergence(void **state)
{
  /* Wherever a held ghost is involved, the side that keeps is the side
   * whose session BS C's convergence keeps (session ids distinct). */
  static const char *ids[2] = { OLDER, NEWER };
  int lh, ih, li;
  (void)state;
  for (lh = 0; lh < 2; lh++)
    for (ih = 0; ih < 2; ih++)
      for (li = 0; li < 2; li++) {
        const char *lid = ids[li], *iid = ids[!li];
        enum bounce_nick_verdict v;
        if (!lh && !ih)
          continue;   /* live against live: nick age, as D.2 always was */
        v = V(known(lh, 100, lid, NA), known(ih, 100, iid, NB), 1, 0);
        assert_int_equal(v == BNV_KEEP_LOCAL,
                         !bounce_converge_peer_wins(lh, lid, ih, iid));
        assert_int_equal(v == BNV_RETIRE_LOCAL,
                         bounce_converge_peer_wins(lh, lid, ih, iid));
      }
}

static void test_verdict_null_inputs_do_not_crash(void **state)
{
  struct bounce_nick_side l = known(1, 100, NULL, NULL);
  struct bounce_nick_side i = known(1, 100, NULL, NULL);
  (void)state;
  assert_int_equal(bounce_nick_verdict(NULL, &i, 1, 0, 0), BNV_CLASSIC);
  assert_int_equal(bounce_nick_verdict(&l, NULL, 1, 0, 0), BNV_CLASSIC);
  /* NULL strings read as "": the same session, the same numeric. */
  assert_int_equal(bounce_nick_verdict(&l, &i, 1, 0, 0), BNV_KEEP_LOCAL);
  l.held = 0;
  i.held = 0;
  assert_int_equal(bounce_nick_verdict(&l, &i, 1, 0, 0), BNV_KEEP_LOCAL);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_active_beats_holding_whatever_the_age),
    cmocka_unit_test(test_same_state_older_id_wins),
    cmocka_unit_test(test_identical_id_keeps_ours),
    cmocka_unit_test(test_both_sides_agree),
    cmocka_unit_test(test_null_ids_do_not_crash),
    cmocka_unit_test(test_held_vs_known_live_retires_whatever_the_age),
    cmocka_unit_test(test_held_vs_known_live_same_session_drops_the_ghost),
    cmocka_unit_test(test_live_vs_known_held_keeps),
    cmocka_unit_test(test_held_vs_held_older_sessid_keeps),
    cmocka_unit_test(test_held_vs_held_same_sessid_lower_numeric_keeps),
    cmocka_unit_test(test_live_vs_live_is_d2),
    cmocka_unit_test(test_unknown_incoming),
    cmocka_unit_test(test_live_non_member_vs_live_member_is_classic),
    cmocka_unit_test(test_dlh_live_non_member_vs_held_is_classic_until_decided),
    cmocka_unit_test(test_dlh_option_a_live_wins_PENDING),
    cmocka_unit_test(test_kc_conflict_is_classic),
    cmocka_unit_test(test_antisymmetric),
    cmocka_unit_test(test_matches_bs_c_convergence),
    cmocka_unit_test(test_verdict_null_inputs_do_not_crash),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
