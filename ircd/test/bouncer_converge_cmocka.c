/* cmocka suite for bounce_converge_peer_wins and bounce_nick_verdict
 * (include/bouncer_converge.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_converge.h"
#include "../../include/bouncer_wire.h"

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

/* ---- BS C: a peer announces another session of the account ---- */

/* Today's rule, for a session with nothing live: a live session beats a
 * holding one (ours retired when held here, dropped when a replica);
 * between equal states the older id wins and the loser takes it. */
static void test_session_converge_as_today(void **state)
{
  static const char *ids[2] = { OLDER, NEWER };
  int lh, holder, ph, li;
  (void)state;
  for (lh = 0; lh < 2; lh++)
  for (holder = 0; holder < 2; holder++)
  for (ph = 0; ph < 2; ph++)
  for (li = 0; li < 2; li++) {
    const char *ours = ids[li], *theirs = ids[!li];
    enum bounce_session_outcome want;
    if (lh && !ph)
      want = holder ? BSO_RETIRE : BSO_DROP_REPLICA;
    else if (!lh && ph)
      want = BSO_KEEP;
    else
      want = bounce_converge_peer_wins(lh, ours, ph, theirs) ? BSO_RENAME
                                                             : BSO_KEEP;
    assert_int_equal(bounce_session_converge(lh, holder, 0, ours, ph, theirs),
                     want);
  }
}

/* A holding session of ours with a live connection (a live alias of a
 * held ghost) is never retired for a peer's live session: retiring it
 * would exit that device.  It is kept apart instead: ours keeps its id
 * and the peer's copy is not mirrored, as the peer, reading our
 * "holding", keeps its own and skips ours. */
static void test_session_converge_never_retires_a_live_session(void **state)
{
  static const char *ids[2] = { OLDER, NEWER };
  int lh, ph, li;
  (void)state;
  assert_int_equal(bounce_session_converge(1, 1, 1, OLDER, 0, NEWER), BSO_KEEP);
  assert_int_equal(bounce_session_converge(1, 1, 1, NEWER, 0, OLDER), BSO_KEEP);
  for (lh = 0; lh < 2; lh++)
  for (ph = 0; ph < 2; ph++)
  for (li = 0; li < 2; li++)
    assert_int_not_equal(bounce_session_converge(lh, 1, 1, ids[li], ph,
                                                 ids[!li]), BSO_RETIRE);
  /* A replica's connections are not here: dropping our record of it
   * exits nothing, as today. */
  assert_int_equal(bounce_session_converge(1, 0, 1, OLDER, 0, NEWER),
                   BSO_DROP_REPLICA);
  /* Otherwise the guard changes nothing: an active session of ours is
   * read as before, live or not. */
  for (ph = 0; ph < 2; ph++)
  for (li = 0; li < 2; li++)
    assert_int_equal(bounce_session_converge(0, 1, 1, ids[li], ph, ids[!li]),
                     bounce_session_converge(0, 1, 0, ids[li], ph, ids[!li]));
}

/* The id a server keeps for the account after the meeting: its own when
 * it keeps, the peer's otherwise (it takes it, or mirrors the peer's
 * session after ending its own). */
static const char *session_id_after(enum bounce_session_outcome o,
                                    const char *own, const char *peer)
{
  return o == BSO_KEEP ? own : peer;
}

/* Both servers compute from the announced states, so they agree in
 * every pairing: one keeps its id and the other takes it (or ends and
 * mirrors it) -- except a holding session with a live connection against
 * a live one, where both keep their own and neither mirrors the other
 * (the peer reads our "holding" and skips ours; we keep ours). */
static void test_session_converge_both_ends_agree(void **state)
{
  static const char *ids[2] = { OLDER, NEWER };
  int ah, al, bh, bl, ai;
  (void)state;
  for (ah = 0; ah < 2; ah++)
  for (al = 0; al < 2; al++)
  for (bh = 0; bh < 2; bh++)
  for (bl = 0; bl < 2; bl++)
  for (ai = 0; ai < 2; ai++) {
    const char *a_id = ids[ai], *b_id = ids[!ai];
    enum bounce_session_outcome a = bounce_session_converge(ah, 1, al, a_id,
                                                            bh, b_id);
    enum bounce_session_outcome b = bounce_session_converge(bh, 1, bl, b_id,
                                                            ah, a_id);
    if ((ah && al && !bh) || (bh && bl && !ah)) {
      /* Kept apart: each keeps its own, neither mirrors the other. */
      assert_int_equal(a, BSO_KEEP);
      assert_int_equal(b, BSO_KEEP);
      continue;
    }
    assert_string_equal(session_id_after(a, a_id, b_id),
                        session_id_after(b, b_id, a_id));
    /* Exactly one side changes: the other keeps. */
    assert_int_equal(a == BSO_KEEP, b != BSO_KEEP);
  }
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

/* The same with the open case answered the other way: the live login
 * wins (the switch off). */
static enum bounce_nick_verdict V_a(struct bounce_nick_side local,
                                    struct bounce_nick_side incoming,
                                    int local_is_session_primary, int link_gated)
{
  return bounce_nick_verdict_ex(&local, &incoming, local_is_session_primary, 0,
                                link_gated, 1);
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
  /* Ours held: classic.  While the link has not had our burst yet the
   * unknown client may be a login in no session: the open case, classic
   * until decided. */
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 0),
                   BNV_CLASSIC);
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 1),
                   BNV_CLASSIC);
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, OLDER, NB), 1, 1),
                   BNV_CLASSIC);
  /* The other answer: ours ends when gated, by the session ids. */
  assert_int_equal(V_a(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 1),
                   BNV_RETIRE_LOCAL);
  assert_int_equal(V_a(known(1, 100, OLDER, NA), unknown(50, OLDER, NB), 1, 1),
                   BNV_DROP_LOCAL_GHOST);
  assert_int_equal(V_a(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 0),
                   BNV_CLASSIC);
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
                "Enable when (a) is decided; delete if (b) is.  Its "
                "gated-unknown equal-id case is a further open "
                "sub-decision (see below).\n");
  skip();
  assert_int_equal(V(known(1, 100, OLDER, NA), outsider(50, NB), 1, 0),
                   BNV_RETIRE_LOCAL);
  assert_int_equal(V(known(1, 50, OLDER, NA), outsider(100, NB), 1, 0),
                   BNV_RETIRE_LOCAL);
  assert_int_equal(V(known(0, 100, MINTED, NB), known(1, 50, OLDER, NA), 0, 0),
                   BNV_KEEP_LOCAL);
  assert_int_equal(V(known(0, 50, MINTED, NB), known(1, 100, OLDER, NA), 0, 0),
                   BNV_KEEP_LOCAL);
  /* A login in no session carrying our id (a stale one): retired. */
  {
    struct bounce_nick_side o = outsider(50, NB);
    o.sessid = OLDER;
    assert_int_equal(V(known(1, 100, OLDER, NA), o, 1, 0), BNV_RETIRE_LOCAL);
  }
  /* An unknown client while our burst to its link is gated. */
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, NEWER, NB), 1, 1),
                   BNV_RETIRE_LOCAL);
  /* OPEN sub-decision of the same question, not settled by deciding (a):
   * an unknown client carrying our session id may be a member of our
   * session (DROP is right, RETIRE would end its session) or a login in
   * no session with a stale id (RETIRE is right, DROP would hand it our
   * session).  Without a mark neither answer is safe for both; this
   * asserts what the rules below the switch give today (DROP). */
  assert_int_equal(V(known(1, 100, OLDER, NA), unknown(50, OLDER, NB), 1, 1),
                   BNV_DROP_LOCAL_GHOST);
}

/* The switch is one: with it either way, the verdict differs only in
 * the open case, and there the classic answer is the switch's. */
static int open_case(const struct bounce_nick_side *l,
                     const struct bounce_nick_side *i, int primary, int gated)
{
  int in_held = !i->non_member && i->state_known && i->held;
  int in_unknown = !i->non_member && !i->state_known;
  return (l->held && (i->non_member || (in_unknown && gated)))
         || (!l->held && !primary && in_held);
}

static void test_dlh_is_one_switch(void **state)
{
  static const char *ids[3] = { OLDER, NEWER, MINTED };
  static const char *nums[2] = { NA, NB };
  int lh, ik, ih, nm, li, ii, ln, in, primary, gated, open = 0;
  (void)state;
  for (lh = 0; lh < 2; lh++)
  for (ik = 0; ik < 2; ik++)
  for (ih = 0; ih < 2; ih++)
  for (nm = 0; nm < 2; nm++)
  for (li = 0; li < 3; li++)
  for (ii = 0; ii < 3; ii++)
  for (ln = 0; ln < 2; ln++)
  for (in = 0; in < 2; in++)
  for (primary = 0; primary < 2; primary++)
  for (gated = 0; gated < 2; gated++) {
    struct bounce_nick_side l = known(lh, 100, ids[li], nums[ln]);
    struct bounce_nick_side i = known(ih, 200, ids[ii], nums[in]);
    enum bounce_nick_verdict b, a;
    i.state_known = ik;
    i.non_member = nm;
    b = bounce_nick_verdict_ex(&l, &i, primary, 0, gated, 0);
    a = bounce_nick_verdict_ex(&l, &i, primary, 0, gated, 1);
    /* Production answers with the switch as BOUNCE_LIVE_LOGIN_WINS. */
    assert_int_equal(bounce_nick_verdict(&l, &i, primary, 0, gated),
                     BOUNCE_LIVE_LOGIN_WINS ? a : b);
    if (open_case(&l, &i, primary, gated)) {
      assert_int_equal(b, BNV_CLASSIC);
      open++;
    } else
      assert_int_equal(a, b);
  }
  assert_true(open > 0);
}

/* A login known to be in no session is never in our session, whatever
 * session id it carries: the verdict never drops our ghost for it (that
 * would rebind the session onto it) and never demotes into it. */
static void test_known_non_member_never_drops(void **state)
{
  static const char *ids[3] = { OLDER, NEWER, MINTED };
  static const char *nums[2] = { NA, NB };
  int lh, ik, ih, li, ii, ln, in, primary, gated, sw;
  (void)state;
  for (sw = 0; sw < 2; sw++)
  for (lh = 0; lh < 2; lh++)
  for (ik = 0; ik < 2; ik++)
  for (ih = 0; ih < 2; ih++)
  for (li = 0; li < 3; li++)
  for (ii = 0; ii < 3; ii++)
  for (ln = 0; ln < 2; ln++)
  for (in = 0; in < 2; in++)
  for (primary = 0; primary < 2; primary++)
  for (gated = 0; gated < 2; gated++) {
    struct bounce_nick_side l = known(lh, 100, ids[li], nums[ln]);
    struct bounce_nick_side i = known(ih, 200, ids[ii], nums[in]);
    enum bounce_nick_verdict v;
    i.state_known = ik;
    i.non_member = 1;
    v = bounce_nick_verdict_ex(&l, &i, primary, 0, gated, sw);
    assert_int_not_equal(v, BNV_DROP_LOCAL_GHOST);
    assert_int_not_equal(v, BNV_DEMOTE_LOCAL);
    /* Our held ghost against it: classic with the switch on, else ended
     * as a session of its own. */
    if (lh)
      assert_int_equal(v, sw ? BNV_RETIRE_LOCAL : BNV_CLASSIC);
  }
}

/* The Keycloak check for a client of ours in no session: classic both
 * ways today whatever it says, and with the other answer it matches the
 * held side's check, so the two sides still agree. */
static void test_kc_conflict_of_a_sessionless_local(void **state)
{
  int ik, ih, nm, gated, kc;
  (void)state;
  /* Today: a live client of ours that is no session's primary meets
   * classic, whatever the incoming side is and whatever the ids say. */
  for (ik = 0; ik < 2; ik++)
  for (ih = 0; ih < 2; ih++)
  for (nm = 0; nm < 2; nm++)
  for (gated = 0; gated < 2; gated++)
  for (kc = 0; kc < 2; kc++) {
    struct bounce_nick_side l = known(0, 100, MINTED, NA);
    struct bounce_nick_side i = known(ih, 200, OLDER, NB);
    i.state_known = ik;
    i.non_member = nm;
    assert_int_equal(bounce_nick_verdict(&l, &i, 0, kc, gated), BNV_CLASSIC);
  }
  /* The other answer: our login against a known held ghost keeps, and
   * the ghost's server retires it; another Keycloak user is classic on
   * both sides. */
  {
    struct bounce_nick_side ours = known(0, 100, MINTED, NA);
    struct bounce_nick_side ghost = known(1, 50, OLDER, NB);
    struct bounce_nick_side ghost_ours = known(1, 50, OLDER, NB);
    struct bounce_nick_side login_theirs = outsider(100, NA);
    assert_int_equal(bounce_nick_verdict_ex(&ours, &ghost, 0, 0, 0, 1),
                     BNV_KEEP_LOCAL);
    assert_int_equal(bounce_nick_verdict_ex(&ghost_ours, &login_theirs, 1, 0, 0, 1),
                     BNV_RETIRE_LOCAL);
    assert_int_equal(bounce_nick_verdict_ex(&ours, &ghost, 0, 1, 0, 1),
                     BNV_CLASSIC);
    assert_int_equal(bounce_nick_verdict_ex(&ghost_ours, &login_theirs, 1, 1, 0, 1),
                     BNV_CLASSIC);
  }
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

/* ---- the hold mark on the wire: one side's stamp, the other's input ---- */

static void test_mark_fills_the_incoming_side(void **state)
{
  static const char marks[] = { 'h', 'p', 'n', '\0', 'x', 'H' };
  int t, m;
  (void)state;
  for (t = 0; t < 2; t++)
    for (m = 0; m < (int)sizeof marks; m++) {
      struct bounce_nick_side s = known(1, 123, OLDER, NB);
      int valid = marks[m] == 'h' || marks[m] == 'p' || marks[m] == 'n';
      s.non_member = 1;   /* overwritten either way */
      bounce_nick_side_from_mark(&s, t, marks[m]);
      /* Known only when every server on the path announces flag H AND
       * the N carries a mark. */
      assert_int_equal(s.state_known, t && valid);
      assert_int_equal(s.held, t && marks[m] == 'h');
      assert_int_equal(s.non_member, t && marks[m] == 'n');
      /* The rest of the side is the N's own, untouched. */
      assert_int_equal(s.lastnick, 123);
      assert_string_equal(s.sessid, OLDER);
      assert_string_equal(s.numeric, NB);
    }
  /* NULL does not crash. */
  bounce_nick_side_from_mark(NULL, 1, 'h');
}

/* A client as its home server sees it: a held ghost (its session's
 * hs_client, no live alias), a live session primary, or a live login
 * that is not its session's primary (in no session). */
enum kind { K_HELD, K_PRIMARY, K_OUTSIDER };

struct wire_side {
  enum kind kind;
  time_t lastnick;
  const char *sessid;
  const char *numeric;
};

static const char *kind_name(enum kind k)
{
  return k == K_HELD ? "held" : k == K_PRIMARY ? "primary" : "outsider";
}

/* What the home server feeds its own verdict about this client. */
static struct bounce_nick_side as_ours(const struct wire_side *w, int *primary)
{
  struct bounce_nick_side s = known(w->kind == K_HELD, w->lastnick, w->sessid,
                                    w->numeric);
  /* bsess && bsess->hs_client == client: a held ghost is its session's
   * hs_client too. */
  *primary = w->kind != K_OUTSIDER;
  return s;
}

/* What the other server makes of this client's N: the home server's
 * stamp, read through the trust of the path. */
static struct bounce_nick_side as_theirs(const struct wire_side *w, int trusted)
{
  struct bounce_nick_side s;
  char mark = bounce_hold_stamp(w->kind == K_HELD, w->kind != K_OUTSIDER);
  memset(&s, 0, sizeof s);
  s.lastnick = w->lastnick;
  s.sessid = w->sessid;
  s.numeric = w->numeric;
  bounce_nick_side_from_mark(&s, trusted, mark);
  return s;
}

static enum bounce_nick_verdict composed_g(const struct wire_side *ours,
                                           const struct wire_side *theirs,
                                           int trusted, int dlh_a, int gated)
{
  int primary;
  struct bounce_nick_side l = as_ours(ours, &primary);
  struct bounce_nick_side i = as_theirs(theirs, trusted);
  /* dlh_a: the open case answered the other way (the live login wins),
   * through the same function. */
  return bounce_nick_verdict_ex(&l, &i, primary, 0, gated, dlh_a);
}

static enum bounce_nick_verdict composed(const struct wire_side *ours,
                                         const struct wire_side *theirs,
                                         int trusted, int dlh_a)
{
  return composed_g(ours, theirs, trusted, dlh_a, 0);
}

static const char *vname(enum bounce_nick_verdict v)
{
  switch (v) {
  case BNV_CLASSIC:          return "CLASSIC";
  case BNV_KEEP_LOCAL:       return "KEEP";
  case BNV_RETIRE_LOCAL:     return "RETIRE";
  case BNV_DROP_LOCAL_GHOST: return "DROP";
  case BNV_DEMOTE_LOCAL:     return "DEMOTE";
  }
  return "?";
}

/* Every side of {held, primary, outsider} x {session A, B} x {numeric
 * NA, NB} x {nick ts 100, 200}; returns how many. */
static int all_sides(struct wire_side *out)
{
  static const char *ids[2] = { OLDER, NEWER };
  static const char *nums[2] = { NA, NB };
  static const time_t ts[2] = { 100, 200 };
  int k, s, n, t, c = 0;
  for (k = 0; k < 3; k++)
    for (s = 0; s < 2; s++)
      for (n = 0; n < 2; n++)
        for (t = 0; t < 2; t++) {
          out[c].kind = (enum kind)k;
          out[c].sessid = ids[s];
          out[c].numeric = nums[n];
          out[c].lastnick = ts[t];
          c++;
        }
  return c;
}

/* Each side stamps its own client; each verdict reads the other's stamp.
 * For every pair of clients two servers can hold (distinct numerics: a
 * numeric names its home server), one side keeps exactly when the other
 * yields, and both fall back to the classic rules together. */
static int composed_asymmetries(int dlh_a, int report)
{
  struct wire_side sides[24];
  int n = all_sides(sides), a, b, bad = 0;
  for (a = 0; a < n; a++)
    for (b = 0; b < n; b++) {
      enum bounce_nick_verdict ab, ba;
      if (!strcmp(sides[a].numeric, sides[b].numeric))
        continue;
      ab = composed(&sides[a], &sides[b], 1, dlh_a);
      ba = composed(&sides[b], &sides[a], 1, dlh_a);
      if ((ab == BNV_KEEP_LOCAL) != yields(ba)
          || (ab == BNV_CLASSIC) != (ba == BNV_CLASSIC)) {
        bad++;
        if (report)
          print_message("asymmetric (D-LH %s): %s %s %s ts%ld -> %s, "
                        "%s %s %s ts%ld -> %s\n", dlh_a ? "a" : "b",
                        kind_name(sides[a].kind), sides[a].sessid,
                        sides[a].numeric, (long)sides[a].lastnick, vname(ab),
                        kind_name(sides[b].kind), sides[b].sessid,
                        sides[b].numeric, (long)sides[b].lastnick, vname(ba));
      }
    }
  return bad;
}

static void test_composed_stamps_are_antisymmetric_dlh_b(void **state)
{
  (void)state;
  /* Today's D-LH setting: a login in no session against a held ghost is
   * classic. */
  assert_int_equal(composed_asymmetries(0, 1), 0);
}

static void test_composed_stamps_are_antisymmetric_dlh_a(void **state)
{
  (void)state;
  /* The other D-LH outcome: the live login wins. */
  assert_int_equal(composed_asymmetries(1, 1), 0);
}

static void test_composed_session_ends_only_for_another_session(void **state)
{
  struct wire_side sides[24];
  int n = all_sides(sides), a, b, d;
  (void)state;
  for (d = 0; d < 2; d++)
    for (a = 0; a < n; a++)
      for (b = 0; b < n; b++) {
        enum bounce_nick_verdict v;
        if (!strcmp(sides[a].numeric, sides[b].numeric))
          continue;
        v = composed(&sides[a], &sides[b], 1, d);
        /* A whole session ends only for another session's client -- or
         * for a login in no session, whose id is never a session's. */
        if (v == BNV_RETIRE_LOCAL && sides[b].kind != K_OUTSIDER)
          assert_int_not_equal(strcmp(sides[a].sessid, sides[b].sessid), 0);
        /* Only the ghost goes when the client is in our session; never
         * for a login in no session, whatever id it carries. */
        if (v == BNV_DROP_LOCAL_GHOST) {
          assert_int_equal(strcmp(sides[a].sessid, sides[b].sessid), 0);
          assert_int_not_equal(sides[b].kind, K_OUTSIDER);
        }
        /* Only our held ghost ever ends; only a live session primary of
         * ours is ever demoted. */
        if (v == BNV_RETIRE_LOCAL || v == BNV_DROP_LOCAL_GHOST)
          assert_int_equal(sides[a].kind, K_HELD);
        if (v == BNV_DEMOTE_LOCAL)
          assert_int_equal(sides[a].kind, K_PRIMARY);
        /* A login in no session is never merged into, nor demoted. */
        if (sides[a].kind == K_OUTSIDER || sides[b].kind == K_OUTSIDER)
          assert_int_not_equal(v, BNV_DEMOTE_LOCAL);
      }
}

static void test_composed_dlh_b_outsider_meets_held_classic(void **state)
{
  struct wire_side held = { K_HELD, 100, OLDER, NA };
  struct wire_side out_same = { K_OUTSIDER, 200, OLDER, NB };  /* a stale equal id */
  struct wire_side out_other = { K_OUTSIDER, 50, NEWER, NB };
  (void)state;
  assert_int_equal(composed(&held, &out_same, 1, 0), BNV_CLASSIC);
  assert_int_equal(composed(&out_same, &held, 1, 0), BNV_CLASSIC);
  assert_int_equal(composed(&held, &out_other, 1, 0), BNV_CLASSIC);
  assert_int_equal(composed(&out_other, &held, 1, 0), BNV_CLASSIC);
}

static void test_composed_dlh_a_outsider_with_an_equal_id_never_drops(void **state)
{
  struct wire_side held = { K_HELD, 100, OLDER, NA };
  struct wire_side out_same = { K_OUTSIDER, 200, OLDER, NB };  /* a stale equal id */
  struct wire_side out_other = { K_OUTSIDER, 50, NEWER, NB };
  (void)state;
  /* With the live login winning, a held ghost against a login in no
   * session ends as a session of its own (retired), never by the silent
   * rebind a member of our session gets, whatever id the login carries;
   * the login's server keeps it. */
  assert_int_equal(composed(&held, &out_same, 1, 1), BNV_RETIRE_LOCAL);
  assert_int_equal(composed(&out_same, &held, 1, 1), BNV_KEEP_LOCAL);
  assert_int_equal(composed(&held, &out_other, 1, 1), BNV_RETIRE_LOCAL);
  assert_int_equal(composed(&out_other, &held, 1, 1), BNV_KEEP_LOCAL);
}

/* Mixed versions: an N without a trusted mark reads as unknown.  Clients
 * a (session OLDER, numeric NA, nick ts 100) and b (NEWER, NB, ts 200).
 * Over a direct link two servers trust each other's marks or neither
 * does (bounce_hold_marks_trusted_path; multi-hop and runtime-toggle
 * residuals are registered), so in practice both sides read the other as
 * unknown (both_unknown); the one-sided columns show what a one-sided
 * trust would do.  A row is asymmetric when one side keeps and the other
 * does not yield, or only one side runs the classic rules.  The gated
 * columns are a's verdict while a's burst to b's link is still gated
 * (b has not had a's N yet, so there is no b verdict to pair it with),
 * with the open case as today (classic) and answered the other way. */
struct mixed_row {
  enum kind a, b;
  /* Both unknown: a's verdict on b, b's verdict on a. */
  enum bounce_nick_verdict both_ab, both_ba;
  int both_symmetric;
  /* a reads b as unknown, b reads a's mark. */
  enum bounce_nick_verdict one_ab, one_ba;
  int one_symmetric;
  /* a reads b as unknown while a's link to b is gated: today / the live
   * login winning. */
  enum bounce_nick_verdict gated_ab, gated_a_ab;
};

static void test_mixed_version_table(void **state)
{
  static const struct mixed_row rows[] = {
    /* held vs held: classic both ways; one-sided, b's held ghost (the
     * newer session) retires while a runs the classic rules.  Gated: the
     * unknown client may be a login in no session, so classic today. */
    { K_HELD, K_HELD, BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_RETIRE_LOCAL, 0,
      BNV_CLASSIC, BNV_RETIRE_LOCAL },
    /* held vs live primary: the held side runs the classic rules, the
     * primary merges by nick age -- today's 0.3a failure (the newer
     * live primary demotes into the held ghost; the hub's classic
     * rules kill it). */
    { K_HELD, K_PRIMARY, BNV_CLASSIC, BNV_DEMOTE_LOCAL, 0,
      BNV_CLASSIC, BNV_KEEP_LOCAL, 0,
      BNV_CLASSIC, BNV_RETIRE_LOCAL },
    { K_HELD, K_OUTSIDER, BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_RETIRE_LOCAL },
    { K_PRIMARY, K_HELD, BNV_KEEP_LOCAL, BNV_CLASSIC, 0,
      BNV_KEEP_LOCAL, BNV_RETIRE_LOCAL, 1,
      BNV_KEEP_LOCAL, BNV_KEEP_LOCAL },
    { K_PRIMARY, K_PRIMARY, BNV_KEEP_LOCAL, BNV_DEMOTE_LOCAL, 1,
      BNV_KEEP_LOCAL, BNV_DEMOTE_LOCAL, 1,
      BNV_KEEP_LOCAL, BNV_KEEP_LOCAL },
    /* live primary vs a login in no session: the primary would merge
     * into it by nick age while the login runs the classic rules (the
     * D.2-into-a-non-member row). */
    { K_PRIMARY, K_OUTSIDER, BNV_KEEP_LOCAL, BNV_CLASSIC, 0,
      BNV_KEEP_LOCAL, BNV_CLASSIC, 0,
      BNV_KEEP_LOCAL, BNV_KEEP_LOCAL },
    { K_OUTSIDER, K_HELD, BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_CLASSIC },
    { K_OUTSIDER, K_PRIMARY, BNV_CLASSIC, BNV_DEMOTE_LOCAL, 0,
      BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_CLASSIC },
    { K_OUTSIDER, K_OUTSIDER, BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_CLASSIC, 1,
      BNV_CLASSIC, BNV_CLASSIC },
  };
  int r;
  (void)state;
  for (r = 0; r < (int)(sizeof rows / sizeof rows[0]); r++) {
    struct wire_side a = { rows[r].a, 100, OLDER, NA };
    struct wire_side b = { rows[r].b, 200, NEWER, NB };
    enum bounce_nick_verdict ab, ba;
    int sym;

    ab = composed(&a, &b, 0, 0);
    ba = composed(&b, &a, 0, 0);
    sym = (ab == BNV_KEEP_LOCAL) == yields(ba)
          && (ab == BNV_CLASSIC) == (ba == BNV_CLASSIC);
    print_message("mixed both-unknown %s vs %s: %s / %s%s\n",
                  kind_name(rows[r].a), kind_name(rows[r].b), vname(ab),
                  vname(ba), sym ? "" : "  ASYMMETRIC");
    assert_int_equal(ab, rows[r].both_ab);
    assert_int_equal(ba, rows[r].both_ba);
    assert_int_equal(sym, rows[r].both_symmetric);

    ab = composed(&a, &b, 0, 0);
    ba = composed(&b, &a, 1, 0);
    sym = (ab == BNV_KEEP_LOCAL) == yields(ba)
          && (ab == BNV_CLASSIC) == (ba == BNV_CLASSIC);
    print_message("mixed one-sided %s vs %s: %s / %s%s\n",
                  kind_name(rows[r].a), kind_name(rows[r].b), vname(ab),
                  vname(ba), sym ? "" : "  ASYMMETRIC");
    assert_int_equal(ab, rows[r].one_ab);
    assert_int_equal(ba, rows[r].one_ba);
    assert_int_equal(sym, rows[r].one_symmetric);

    ab = composed_g(&a, &b, 0, 0, 1);
    ba = composed_g(&a, &b, 0, 1, 1);
    print_message("mixed gated %s vs %s: %s, live login winning %s\n",
                  kind_name(rows[r].a), kind_name(rows[r].b), vname(ab),
                  vname(ba));
    assert_int_equal(ab, rows[r].gated_ab);
    assert_int_equal(ba, rows[r].gated_a_ab);
  }
}

/* ---- our side from our own stamp, and the action a verdict maps to ---- */

static void test_stamp_reads_back_as_the_peer_reads_it(void **state)
{
  int held, prim;
  (void)state;
  /* The snapshot we decide from is the mark the peer read: for every
   * stamp, our side's held fact equals the peer's, and our primary fact
   * is "member" exactly when the peer reads no outsider. */
  for (held = 0; held < 2; held++)
    for (prim = 0; prim < 2; prim++) {
      char stamp = bounce_hold_stamp(held, prim);
      struct bounce_nick_side ours, peer;
      int primary = -1;
      memset(&ours, 0, sizeof ours);
      memset(&peer, 0, sizeof peer);
      assert_int_equal(bounce_nick_side_from_stamp(&ours, &primary, stamp), 1);
      bounce_nick_side_from_mark(&peer, 1, stamp);
      assert_int_equal(ours.state_known, 1);
      assert_int_equal(ours.non_member, 0);
      assert_int_equal(ours.held, peer.held);
      assert_int_equal(ours.held, held);
      assert_int_equal(primary, !peer.non_member);
      assert_int_equal(primary, held || prim);
    }
  /* No valid stamp: nothing is written, the caller reads its client now. */
  {
    struct bounce_nick_side ours;
    int primary = 7;
    memset(&ours, 0, sizeof ours);
    ours.held = 1;
    assert_int_equal(bounce_nick_side_from_stamp(&ours, &primary, 0), 0);
    assert_int_equal(bounce_nick_side_from_stamp(&ours, &primary, 'x'), 0);
    assert_int_equal(ours.held, 1);
    assert_int_equal(primary, 7);
    assert_int_equal(bounce_nick_side_from_stamp(NULL, NULL, 'h'), 0);
  }
}

/* Our client now: a held ghost that is its session's primary, no alias. */
static struct bounce_nick_now now_held(void)
{
  struct bounce_nick_now n;
  memset(&n, 0, sizeof n);
  n.held_ghost = 1;
  n.has_session = 1;
  n.is_primary = 1;
  n.yield_ok = 1;
  n.demote_bar = BOUNCE_DEMOTE_FACE_HELD;
  return n;
}

/* A live session primary whose demote can run. */
static struct bounce_nick_now now_live(void)
{
  struct bounce_nick_now n;
  memset(&n, 0, sizeof n);
  n.has_session = 1;
  n.is_primary = 1;
  n.yield_ok = 1;
  n.demote_bar = BOUNCE_DEMOTE_OK;
  return n;
}

static enum bounce_nick_action A(enum bounce_nick_verdict v,
                                 struct bounce_nick_side incoming,
                                 struct bounce_nick_now now)
{
  return bounce_nick_action(v, &incoming, &now);
}

static void test_action_classic_and_keep(void **state)
{
  struct bounce_nick_now live = now_live(), held = now_held(), kc = now_live();
  (void)state;
  kc.demote_bar = BOUNCE_DEMOTE_KC_CONFLICT;
  assert_int_equal(A(BNV_CLASSIC, known(0, 1, OLDER, NB), live), BNA_CLASSIC);
  assert_int_equal(A(BNV_CLASSIC, known(1, 1, OLDER, NB), held), BNA_CLASSIC);
  assert_int_equal(A(BNV_KEEP_LOCAL, known(1, 1, OLDER, NB), live), BNA_REFUSE);
  assert_int_equal(A(BNV_KEEP_LOCAL, known(1, 1, OLDER, NB), held), BNA_REFUSE);
  assert_int_equal(A(BNV_KEEP_LOCAL, known(0, 1, OLDER, NB), held), BNA_REFUSE);
  /* A live primary keeps through the merge's own choice: a Keycloak-id
   * conflict is classic on both sides. */
  assert_int_equal(A(BNV_KEEP_LOCAL, known(0, 1, OLDER, NB), kc), BNA_CLASSIC);
}

static void test_action_retire_by_what_ours_is_now(void **state)
{
  struct bounce_nick_now n;
  (void)state;
  n = now_held();
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(0, 1, NEWER, NB), n), BNA_RETIRE);
  /* A ghost no session names: it just exits. */
  n.has_session = 0;
  n.is_primary = 0;
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(0, 1, NEWER, NB), n), BNA_RETIRE);
  /* A session that only lists it on its roster is not its to end. */
  n = now_held();
  n.is_primary = 0;
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(0, 1, NEWER, NB), n), BNA_CLASSIC);
  /* Its session has a live alias now: never ended; it yields to a live
   * session primary instead, else classic. */
  n = now_held();
  n.live_alias = 1;
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(0, 1, NEWER, NB), n), BNA_YIELD);
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(1, 1, NEWER, NB), n), BNA_CLASSIC);
  assert_int_equal(A(BNV_RETIRE_LOCAL, outsider(1, NB), n), BNA_CLASSIC);
  n.yield_ok = 0;
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(0, 1, NEWER, NB), n), BNA_CLASSIC);
  /* Not a held ghost now (cannot happen within a burst): classic. */
  assert_int_equal(A(BNV_RETIRE_LOCAL, known(0, 1, NEWER, NB), now_live()), BNA_CLASSIC);
}

static void test_action_drop_by_incoming_state(void **state)
{
  struct bounce_nick_now n = now_held();
  (void)state;
  /* Our session's own ghost: by the incoming client's state. */
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, known(1, 1, OLDER, NA), n), BNA_REBIND_HELD);
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, known(0, 1, OLDER, NA), n), BNA_REBIND_LIVE);
  /* No drop for an unknown state or a login in no session. */
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, unknown(1, OLDER, NA), n), BNA_CLASSIC);
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, outsider(1, NA), n), BNA_CLASSIC);
  /* Never a rebind without the session: a ghost no session names just
   * exits (the yield the peer's keep expects); one the session only
   * lists on its roster is not its to give. */
  n.has_session = 0;
  n.is_primary = 0;
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, known(1, 1, OLDER, NA), n), BNA_RETIRE);
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, known(0, 1, OLDER, NA), n), BNA_RETIRE);
  n = now_held();
  n.is_primary = 0;
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, known(0, 1, OLDER, NA), n), BNA_CLASSIC);
  /* Not a held ghost now: classic. */
  assert_int_equal(A(BNV_DROP_LOCAL_GHOST, known(0, 1, OLDER, NA), now_live()), BNA_CLASSIC);
}

static void test_action_never_demotes_a_held_ghost(void **state)
{
  struct bounce_nick_now n = now_held();
  (void)state;
  /* A held ghost whose session still has a live alias reads as live: the
   * verdict can demote it; it yields instead. */
  n.live_alias = 1;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, known(0, 1, NEWER, NB), n), BNA_YIELD);
  /* Stamped live, held since (its socket died): yields too. */
  n.live_alias = 0;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, known(0, 1, NEWER, NB), n), BNA_YIELD);
  /* Not into an unknown incoming state; not when it may not yield; not
   * when it is not its session's primary. */
  assert_int_equal(A(BNV_DEMOTE_LOCAL, unknown(1, NEWER, NB), n), BNA_CLASSIC);
  n.yield_ok = 0;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, known(0, 1, NEWER, NB), n), BNA_CLASSIC);
  n = now_held();
  n.is_primary = 0;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, known(0, 1, NEWER, NB), n), BNA_CLASSIC);
}

static void test_action_live_primary_demote_is_the_merge(void **state)
{
  struct bounce_nick_now n = now_live();
  (void)state;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, known(0, 1, NEWER, NB), n), BNA_SWAP);
  assert_int_equal(A(BNV_DEMOTE_LOCAL, unknown(1, NEWER, NB), n), BNA_SWAP);
  n.demote_bar = BOUNCE_DEMOTE_FACE_DYING;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, known(0, 1, NEWER, NB), n), BNA_CLASSIC);
  n.demote_bar = BOUNCE_DEMOTE_LEGACY_HOME;
  assert_int_equal(A(BNV_DEMOTE_LOCAL, unknown(1, NEWER, NB), n), BNA_CLASSIC);
}

static int action_yields(enum bounce_nick_action a)
{
  return a == BNA_RETIRE || a == BNA_REBIND_LIVE || a == BNA_REBIND_HELD
         || a == BNA_SWAP || a == BNA_YIELD;
}

static void test_action_never_ends_a_live_device(void **state)
{
  static const enum bounce_nick_verdict vs[] = {
    BNV_CLASSIC, BNV_KEEP_LOCAL, BNV_RETIRE_LOCAL, BNV_DROP_LOCAL_GHOST,
    BNV_DEMOTE_LOCAL
  };
  struct bounce_nick_side ins[5];
  unsigned int v, i, bits;
  (void)state;
  ins[0] = known(1, 1, OLDER, NB);
  ins[1] = known(0, 1, OLDER, NB);
  ins[2] = unknown(1, OLDER, NB);
  ins[3] = outsider(1, NB);
  ins[4] = known(0, 1, NEWER, NB);
  for (v = 0; v < sizeof vs / sizeof vs[0]; v++)
    for (i = 0; i < 5; i++)
      for (bits = 0; bits < 32; bits++) {
        struct bounce_nick_now n;
        enum bounce_nick_action a;
        memset(&n, 0, sizeof n);
        n.held_ghost  = !!(bits & 1);
        n.has_session = !!(bits & 2);
        n.is_primary  = n.has_session && (bits & 4);
        n.live_alias  = n.has_session && (bits & 8);
        n.yield_ok    = !!(bits & 16);
        n.demote_bar  = n.held_ghost ? BOUNCE_DEMOTE_FACE_HELD : BOUNCE_DEMOTE_OK;
        a = bounce_nick_action(vs[v], &ins[i], &n);
        /* Ending a session with a live device exits that device. */
        if (n.live_alias)
          assert_int_not_equal(a, BNA_RETIRE);
        /* A client with no socket is never demoted. */
        if (n.held_ghost)
          assert_int_not_equal(a, BNA_SWAP);
        /* A live client is never retired, rebound or yielded. */
        if (!n.held_ghost)
          assert_true(a == BNA_CLASSIC || a == BNA_REFUSE || a == BNA_SWAP);
        /* Rebinds and yields act on our session: never without one. */
        if (a == BNA_REBIND_LIVE || a == BNA_REBIND_HELD || a == BNA_YIELD)
          assert_true(n.has_session && n.is_primary);
        /* Rebinds are drops: same session, a known incoming state. */
        if (a == BNA_REBIND_LIVE || a == BNA_REBIND_HELD) {
          assert_int_equal(vs[v], BNV_DROP_LOCAL_GHOST);
          assert_true(ins[i].state_known && !ins[i].non_member);
        }
        /* Only keep refuses. */
        assert_int_equal(a == BNA_REFUSE, vs[v] == BNV_KEEP_LOCAL && a != BNA_CLASSIC);
        /* A yield follows only a yielding verdict. */
        if (action_yields(a))
          assert_true(vs[v] == BNV_RETIRE_LOCAL || vs[v] == BNV_DROP_LOCAL_GHOST
                      || vs[v] == BNV_DEMOTE_LOCAL);
      }
}

/* A client as its home server holds it now, and the stamp its N carried. */
enum now_kind {
  N_HELD,             /* a held ghost, its session's primary, no alias */
  N_ORPHAN,           /* a held ghost no session names */
  N_LIVE,             /* a live session primary */
  N_HELD_LIVE_ALIAS,  /* a held ghost whose session has a live alias (p) */
  N_STAMPED_LIVE,     /* stamped live, its socket died since (held now) */
  N_OUTSIDER          /* a live login in no session */
};

struct now_side {
  enum now_kind kind;
  time_t lastnick;
  const char *sessid;
  const char *numeric;
};

static const char *now_kind_name(enum now_kind k)
{
  static const char *names[] = { "held", "orphan", "live", "held+alias",
                                 "stamped-live", "outsider" };
  return names[k];
}

static char now_stamp(enum now_kind k)
{
  switch (k) {
  case N_HELD: case N_ORPHAN: return BOUNCE_HOLD_MARK_HELD;
  case N_OUTSIDER:            return BOUNCE_HOLD_MARK_OUTSIDER;
  default:                    return BOUNCE_HOLD_MARK_PRIMARY;
  }
}

static struct bounce_nick_now now_of(enum now_kind k)
{
  struct bounce_nick_now n;
  memset(&n, 0, sizeof n);
  switch (k) {
  case N_HELD:            n = now_held(); break;
  case N_ORPHAN:          n = now_held(); n.has_session = 0; n.is_primary = 0; break;
  case N_LIVE:            n = now_live(); break;
  case N_HELD_LIVE_ALIAS: n = now_held(); n.live_alias = 1; break;
  case N_STAMPED_LIVE:    n = now_held(); break;
  case N_OUTSIDER:        n.demote_bar = BOUNCE_DEMOTE_NO_SESSION; break;
  }
  return n;
}

/* One server's action on the other's N: our side from our own stamp, the
 * incoming side from theirs, the verdict, then the action on what our
 * client is now. */
static enum bounce_nick_action composed_action(const struct now_side *ours,
                                               const struct now_side *theirs,
                                               int dlh_a)
{
  struct bounce_nick_side l, i;
  struct bounce_nick_now n = now_of(ours->kind);
  int primary = 0;
  memset(&l, 0, sizeof l);
  l.lastnick = ours->lastnick;
  l.sessid = ours->sessid;
  l.numeric = ours->numeric;
  bounce_nick_side_from_stamp(&l, &primary, now_stamp(ours->kind));
  memset(&i, 0, sizeof i);
  i.lastnick = theirs->lastnick;
  i.sessid = theirs->sessid;
  i.numeric = theirs->numeric;
  bounce_nick_side_from_mark(&i, 1, now_stamp(theirs->kind));
  return bounce_nick_action(bounce_nick_verdict_ex(&l, &i, primary, 0, 0, dlh_a),
                            &i, &n);
}

static int composed_action_asymmetries(int dlh_a)
{
  static const char *ids[2] = { OLDER, NEWER };
  static const char *nums[2] = { NA, NB };
  static const time_t ts[2] = { 100, 200 };
  struct now_side sides[6 * 8];
  int k, s, n, t, c = 0, a, b, bad = 0;
  for (k = 0; k < 6; k++)
    for (s = 0; s < 2; s++)
      for (n = 0; n < 2; n++)
        for (t = 0; t < 2; t++) {
          sides[c].kind = (enum now_kind)k;
          sides[c].sessid = ids[s];
          sides[c].numeric = nums[n];
          sides[c].lastnick = ts[t];
          c++;
        }
  for (a = 0; a < c; a++)
    for (b = 0; b < c; b++) {
      enum bounce_nick_action ab, ba;
      if (!strcmp(sides[a].numeric, sides[b].numeric))
        continue;
      ab = composed_action(&sides[a], &sides[b], dlh_a);
      ba = composed_action(&sides[b], &sides[a], dlh_a);
      if ((ab == BNA_REFUSE) != action_yields(ba)
          || (ab == BNA_CLASSIC) != (ba == BNA_CLASSIC)) {
        bad++;
        print_message("asymmetric action (D-LH %s): %s %s %s ts%ld -> %s, "
                      "%s %s %s ts%ld -> %s\n", dlh_a ? "a" : "b",
                      now_kind_name(sides[a].kind), sides[a].sessid,
                      sides[a].numeric, (long)sides[a].lastnick,
                      bounce_nick_action_name(ab),
                      now_kind_name(sides[b].kind), sides[b].sessid,
                      sides[b].numeric, (long)sides[b].lastnick,
                      bounce_nick_action_name(ba));
      }
    }
  return bad;
}

static void test_composed_actions_complement_dlh_b(void **state)
{
  (void)state;
  /* For every pair of clients two servers can hold, including a held
   * ghost with a live alias, one stamped live that is held now and an
   * orphan ghost: one side refuses exactly when the other yields, and
   * both are classic together. */
  assert_int_equal(composed_action_asymmetries(0), 0);
}

static void test_composed_actions_complement_dlh_a(void **state)
{
  (void)state;
  assert_int_equal(composed_action_asymmetries(1), 0);
}

static void test_names(void **state)
{
  (void)state;
  assert_string_equal(bounce_nick_verdict_name(BNV_CLASSIC), "classic");
  assert_string_equal(bounce_nick_verdict_name(BNV_KEEP_LOCAL), "keep");
  assert_string_equal(bounce_nick_verdict_name(BNV_RETIRE_LOCAL), "retire");
  assert_string_equal(bounce_nick_verdict_name(BNV_DROP_LOCAL_GHOST), "drop");
  assert_string_equal(bounce_nick_verdict_name(BNV_DEMOTE_LOCAL), "demote");
  assert_string_equal(bounce_nick_action_name(BNA_CLASSIC), "classic");
  assert_string_equal(bounce_nick_action_name(BNA_REFUSE), "refuse");
  assert_string_equal(bounce_nick_action_name(BNA_RETIRE), "retire");
  assert_string_equal(bounce_nick_action_name(BNA_REBIND_LIVE), "rebind as live");
  assert_string_equal(bounce_nick_action_name(BNA_REBIND_HELD), "rebind as held");
  assert_string_equal(bounce_nick_action_name(BNA_SWAP), "swap");
  assert_string_equal(bounce_nick_action_name(BNA_YIELD), "yield");
}

static void test_action_null_inputs(void **state)
{
  struct bounce_nick_side in = known(0, 1, OLDER, NB);
  struct bounce_nick_now n = now_held();
  (void)state;
  assert_int_equal(bounce_nick_action(BNV_RETIRE_LOCAL, NULL, &n), BNA_CLASSIC);
  assert_int_equal(bounce_nick_action(BNV_RETIRE_LOCAL, &in, NULL), BNA_CLASSIC);
}

/* ---- A peer's BS C: which record it is compared with ---------------- */

static void test_bsc_compare_order(void **state)
{
  int same, fol, held;
  (void)state;
  for (same = 0; same < 2; same++)
    for (fol = 0; fol < 2; fol++)
      for (held = 0; held < 2; held++) {
        enum bounce_bsc_compare want =
          same ? BOUNCE_BSC_SAME_ID
          : fol ? BOUNCE_BSC_FOLLOWED
          : held ? BOUNCE_BSC_HELD_HERE : BOUNCE_BSC_FIRST;
        assert_int_equal(bounce_bsc_compare_with(same, fol, held), want);
      }
}

/* ---- A record that follows the announced session's primary ---------- */

static void test_follow_takes_the_peer_id_when_not_announced(void **state)
{
  int oh, ph;
  (void)state;
  /* The peer never saw our id: ours takes the peer's, whatever the ages. */
  for (oh = 0; oh < 2; oh++)
    for (ph = 0; ph < 2; ph++) {
      assert_int_equal(bounce_follow_keeps_id(0, oh, OLDER, ph, NEWER), 0);
      assert_int_equal(bounce_follow_keeps_id(0, oh, NEWER, ph, OLDER), 0);
    }
}

static void test_follow_keeps_ours_only_when_the_peer_renames(void **state)
{
  (void)state;
  /* Equal states: the older id stays on both ends. */
  assert_int_equal(bounce_follow_keeps_id(1, 0, OLDER, 0, NEWER), 1);
  assert_int_equal(bounce_follow_keeps_id(1, 0, NEWER, 0, OLDER), 0);
  assert_int_equal(bounce_follow_keeps_id(1, 1, OLDER, 1, NEWER), 1);
  assert_int_equal(bounce_follow_keeps_id(1, 1, NEWER, 1, OLDER), 0);
  /* Our held copy announced, the peer's live: the peer keeps (its live
   * session beats a holding one), ours takes its id -- the yield case. */
  assert_int_equal(bounce_follow_keeps_id(1, 1, OLDER, 0, NEWER), 0);
  /* We announced live and the peer holding with a live device (the merge
   * into a held ghost that has a live alias): the peer keeps its session
   * apart, under its id; ours takes it. */
  assert_int_equal(bounce_follow_keeps_id(1, 0, OLDER, 1, NEWER), 0);
  assert_int_equal(bounce_follow_keeps_id(1, 0, NEWER, 1, OLDER), 0);
}

/* Both ends end with one id: ours by bounce_follow_keeps_id(), the peer's
 * by its own BS C rule on our announcement (its record live). */
static void test_follow_and_the_peer_agree(void **state)
{
  const char *ids[2] = { OLDER, NEWER };
  int oh, ph, o;
  (void)state;
  for (oh = 0; oh < 2; oh++)
    for (ph = 0; ph < 2; ph++)
      for (o = 0; o < 2; o++) {
        const char *ours = ids[o], *theirs = ids[1 - o];
        const char *ours_end =
          bounce_follow_keeps_id(1, oh, ours, ph, theirs) ? ours : theirs;
        const char *peer_end =
          bounce_session_converge(ph, 1, 1, theirs, oh, ours) == BSO_RENAME
            ? ours : theirs;
        assert_string_equal(ours_end, peer_end);
      }
}

/* ---- A peer's BS C outside a burst ---------------------------------- */

static void test_bsc_fresh_apart_only_outside_a_burst_both_live(void **state)
{
  int ib, lh, ph;
  (void)state;
  for (ib = 0; ib < 2; ib++)
    for (lh = 0; lh < 2; lh++)
      for (ph = 0; ph < 2; ph++)
        assert_int_equal(bounce_bsc_fresh_apart(ib, lh, ph), !ib && !lh && !ph);
}

/* ---- A BS X for an id we kept apart --------------------------------- */

static void test_bsx_reannounce_needs_every_fact(void **state)
{
  int a, h, m;
  (void)state;
  for (a = 0; a < 2; a++)
    for (h = 0; h < 2; h++)
      for (m = 0; m < 2; m++)
        assert_int_equal(bounce_bsx_reannounces(a, h, m), a && h && m);
}

/* ---- The yield's id ------------------------------------------------- */

static void test_yield_id_rules(void **state)
{
  int ib, oe, kc;
  (void)state;
  /* The same id: nothing changes, whatever else holds. */
  for (ib = 0; ib < 2; ib++)
    for (oe = 0; oe < 2; oe++)
      for (kc = 0; kc < 2; kc++)
        assert_int_equal(bounce_yield_id(1, ib, oe, kc), BOUNCE_YIELD_KEEP_ID);
  /* A record of the incoming id is here: ours joins it, never a record
   * of another Keycloak user. */
  for (ib = 0; ib < 2; ib++) {
    assert_int_equal(bounce_yield_id(0, ib, 1, 0), BOUNCE_YIELD_MERGE);
    assert_int_equal(bounce_yield_id(0, ib, 1, 1), BOUNCE_YIELD_KEEP_ID);
  }
  /* In a burst the incoming session's BS C decides; outside one ours
   * takes the incoming id now. */
  assert_int_equal(bounce_yield_id(0, 1, 0, 0), BOUNCE_YIELD_KEEP_ID);
  assert_int_equal(bounce_yield_id(0, 1, 0, 1), BOUNCE_YIELD_KEEP_ID);
  assert_int_equal(bounce_yield_id(0, 0, 0, 0), BOUNCE_YIELD_TAKE_ID);
  assert_int_equal(bounce_yield_id(0, 0, 0, 1), BOUNCE_YIELD_TAKE_ID);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_active_beats_holding_whatever_the_age),
    cmocka_unit_test(test_same_state_older_id_wins),
    cmocka_unit_test(test_identical_id_keeps_ours),
    cmocka_unit_test(test_both_sides_agree),
    cmocka_unit_test(test_null_ids_do_not_crash),
    cmocka_unit_test(test_session_converge_as_today),
    cmocka_unit_test(test_session_converge_never_retires_a_live_session),
    cmocka_unit_test(test_session_converge_both_ends_agree),
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
    cmocka_unit_test(test_dlh_is_one_switch),
    cmocka_unit_test(test_known_non_member_never_drops),
    cmocka_unit_test(test_kc_conflict_of_a_sessionless_local),
    cmocka_unit_test(test_kc_conflict_is_classic),
    cmocka_unit_test(test_antisymmetric),
    cmocka_unit_test(test_matches_bs_c_convergence),
    cmocka_unit_test(test_verdict_null_inputs_do_not_crash),
    cmocka_unit_test(test_mark_fills_the_incoming_side),
    cmocka_unit_test(test_composed_stamps_are_antisymmetric_dlh_b),
    cmocka_unit_test(test_composed_stamps_are_antisymmetric_dlh_a),
    cmocka_unit_test(test_composed_session_ends_only_for_another_session),
    cmocka_unit_test(test_composed_dlh_b_outsider_meets_held_classic),
    cmocka_unit_test(test_composed_dlh_a_outsider_with_an_equal_id_never_drops),
    cmocka_unit_test(test_mixed_version_table),
    cmocka_unit_test(test_stamp_reads_back_as_the_peer_reads_it),
    cmocka_unit_test(test_action_classic_and_keep),
    cmocka_unit_test(test_action_retire_by_what_ours_is_now),
    cmocka_unit_test(test_action_drop_by_incoming_state),
    cmocka_unit_test(test_action_never_demotes_a_held_ghost),
    cmocka_unit_test(test_action_live_primary_demote_is_the_merge),
    cmocka_unit_test(test_action_never_ends_a_live_device),
    cmocka_unit_test(test_composed_actions_complement_dlh_b),
    cmocka_unit_test(test_composed_actions_complement_dlh_a),
    cmocka_unit_test(test_names),
    cmocka_unit_test(test_action_null_inputs),
    cmocka_unit_test(test_bsc_compare_order),
    cmocka_unit_test(test_follow_takes_the_peer_id_when_not_announced),
    cmocka_unit_test(test_follow_keeps_ours_only_when_the_peer_renames),
    cmocka_unit_test(test_follow_and_the_peer_agree),
    cmocka_unit_test(test_bsc_fresh_apart_only_outside_a_burst_both_live),
    cmocka_unit_test(test_bsx_reannounce_needs_every_fact),
    cmocka_unit_test(test_yield_id_rules),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
