/*
 * IRC - Internet Relay Chat, ircd/bouncer_converge.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_converge.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_converge.h"
#include "bouncer_wire.h"

#include <string.h>

int bounce_converge_peer_wins(int local_holding, const char *local_sessid,
                              int peer_holding, const char *peer_sessid)
{
  if (!local_sessid)
    local_sessid = "";
  if (!peer_sessid)
    peer_sessid = "";

  /* State first: a live session outranks a held or clientless one. */
  if (!local_holding && peer_holding)
    return 0;
  if (local_holding && !peer_holding)
    return 1;

  /* Same state: the lower session id (strcmp of the base64 form, the same
   * answer on both ends) wins; identical ids are the same session, ours
   * stays. */
  return strcmp(peer_sessid, local_sessid) < 0;
}

enum bounce_session_outcome
bounce_session_converge(int local_holding, int local_holder, int local_live,
                        const char *local_sessid, int peer_holding,
                        const char *peer_sessid)
{
  /* A live session beats a holding one: ours ends.  A replica of
   * another server's session is only our record of it: dropping it exits
   * nothing.  A session held here that still has a live connection is
   * not ended -- that would exit the device -- and not merged either:
   * kept apart, as the peer keeps its own and skips ours. */
  if (local_holding && !peer_holding) {
    if (!local_holder)
      return BSO_DROP_REPLICA;
    return local_live ? BSO_KEEP : BSO_RETIRE;
  }
  if (!local_holding && peer_holding)
    return BSO_KEEP;
  return bounce_converge_peer_wins(local_holding, local_sessid, peer_holding,
                                   peer_sessid) ? BSO_RENAME : BSO_KEEP;
}

static const char *or_empty(const char *s)
{
  return s ? s : "";
}

/* Our held side ends: its whole session when the incoming client is in
 * another one, only the ghost when it is in ours (ending the session
 * would end the incoming client's own). */
static enum bounce_nick_verdict local_ends(const struct bounce_nick_side *local,
                                           const struct bounce_nick_side *incoming)
{
  return strcmp(or_empty(local->sessid), or_empty(incoming->sessid))
         ? BNV_RETIRE_LOCAL : BNV_DROP_LOCAL_GHOST;
}

enum bounce_nick_verdict bounce_nick_verdict(const struct bounce_nick_side *local,
                                             const struct bounce_nick_side *incoming,
                                             int local_is_session_primary,
                                             int kc_conflict, int link_gated)
{
  return bounce_nick_verdict_ex(local, incoming, local_is_session_primary,
                                kc_conflict, link_gated,
                                BOUNCE_LIVE_LOGIN_WINS);
}

enum bounce_nick_verdict bounce_nick_verdict_ex(const struct bounce_nick_side *local,
                                                const struct bounce_nick_side *incoming,
                                                int local_is_session_primary,
                                                int kc_conflict, int link_gated,
                                                int live_login_wins)
{
  int in_live, in_held, in_unknown, c;

  if (!local || !incoming)
    return BNV_CLASSIC;
  /* Sessions of different Keycloak users are never merged. */
  if (kc_conflict)
    return BNV_CLASSIC;

  /* A login in no session is live: a held ghost always has one. */
  in_live = incoming->non_member
            || (incoming->state_known && !incoming->held);
  in_held = !incoming->non_member && incoming->state_known && incoming->held;
  in_unknown = !in_live && !in_held;

  /* A live login in no session meets a held ghost, either way round --
   * and our held ghost meets a client nobody announced while our burst
   * to its link is gated, which may be such a login too.  Whether the
   * live login should win (the held session ending) is not decided;
   * until it is, the classic rules decide, as they always have.  This is
   * the only place that answers it: without it, the rules below let the
   * live login win in all three. */
  if (!live_login_wins
      && ((local->held && (incoming->non_member || (in_unknown && link_gated)))
          || (!local->held && !local_is_session_primary && in_held)))
    return BNV_CLASSIC;

  if (local->held) {
    /* A login in no session is never in our session, whatever id it
     * carries (its own, or a stale one: a client that turned its hold
     * off with -b keeps the id of the session that ended): ending only
     * the ghost would hand our session to it. */
    if (incoming->non_member)
      return BNV_RETIRE_LOCAL;
    if (in_live)
      return local_ends(local, incoming);
    if (!in_held)
      /* State unknown.  A peer we have not burst to never saw our ghost;
       * any other one may have, and decides by the classic rules. */
      return link_gated ? local_ends(local, incoming) : BNV_CLASSIC;
    /* Two held ghosts: the lower session id keeps; one session held on both
     * sides keeps the lower numeric's ghost. */
    c = strcmp(or_empty(local->sessid), or_empty(incoming->sessid));
    if (!c)
      c = strcmp(or_empty(local->numeric), or_empty(incoming->numeric));
    return c <= 0 ? BNV_KEEP_LOCAL : local_ends(local, incoming);
  }

  /* Ours is live: it beats a held ghost. */
  if (in_held)
    return BNV_KEEP_LOCAL;
  /* Two live clients merge only as two session primaries. */
  if (!local_is_session_primary || incoming->non_member)
    return BNV_CLASSIC;
  /* The established connection stays primary: the older nick timestamp,
   * then the lower numeric, which both ends compare the same way. */
  if (local->lastnick != incoming->lastnick)
    return local->lastnick < incoming->lastnick ? BNV_KEEP_LOCAL
                                                : BNV_DEMOTE_LOCAL;
  return strcmp(or_empty(local->numeric), or_empty(incoming->numeric)) <= 0
         ? BNV_KEEP_LOCAL : BNV_DEMOTE_LOCAL;
}

void bounce_nick_side_from_mark(struct bounce_nick_side *side, int trusted,
                                char mark)
{
  if (!side)
    return;
  /* Unknown unless the mark is trusted and present. */
  side->state_known = trusted && bounce_hold_mark_valid(mark);
  side->held = side->state_known && mark == BOUNCE_HOLD_MARK_HELD;
  side->non_member = side->state_known && mark == BOUNCE_HOLD_MARK_OUTSIDER;
}

int bounce_nick_side_from_stamp(struct bounce_nick_side *side, int *primary,
                                char stamp)
{
  if (!side || !bounce_hold_mark_valid(stamp))
    return 0;
  side->state_known = 1;
  side->non_member = 0;
  side->held = stamp == BOUNCE_HOLD_MARK_HELD;
  /* A held ghost holds its session's primary slot as well. */
  if (primary)
    *primary = stamp != BOUNCE_HOLD_MARK_OUTSIDER;
  return 1;
}

/* The incoming client is a live member of a session (its primary): what
 * a held ghost's live connections can follow. */
static int incoming_live_member(const struct bounce_nick_side *in)
{
  return in->state_known && !in->held && !in->non_member;
}

/* Our held ghost yields to the incoming live primary, its session's live
 * connections following, when it may. */
static enum bounce_nick_action held_yields(const struct bounce_nick_side *in,
                                           const struct bounce_nick_now *now)
{
  return now->has_session && now->is_primary && now->yield_ok
         && incoming_live_member(in) ? BNA_YIELD : BNA_CLASSIC;
}

enum bounce_nick_action
bounce_nick_action(enum bounce_nick_verdict verdict,
                   const struct bounce_nick_side *incoming,
                   const struct bounce_nick_now *now)
{
  if (!incoming || !now)
    return BNA_CLASSIC;

  switch (verdict) {
  case BNV_CLASSIC:
    return BNA_CLASSIC;

  case BNV_KEEP_LOCAL:
    if (!now->held_ghost)
      return bounce_merge_choose(0, now->demote_bar) == BOUNCE_MERGE_REFUSE
             ? BNA_REFUSE : BNA_CLASSIC;
    return BNA_REFUSE;

  case BNV_RETIRE_LOCAL:
    /* The verdict read a held ghost; a live client is not retired. */
    if (!now->held_ghost)
      return BNA_CLASSIC;
    /* Only the session's own ghost ends the session.  A ghost no session
     * names just exits. */
    if (now->has_session && !now->is_primary)
      return BNA_CLASSIC;
    /* Ending a session with a live alias would exit that device. */
    if (now->live_alias)
      return held_yields(incoming, now);
    return BNA_RETIRE;

  case BNV_DROP_LOCAL_GHOST:
    if (!now->held_ghost)
      return BNA_CLASSIC;
    /* Only a client whose state is known, and never a login in no
     * session, takes our ghost's place. */
    if (!incoming->state_known || incoming->non_member)
      return BNA_CLASSIC;
    /* Never a rebind without the session: a ghost no session names
     * leaves, as a retire of it does; one the session only lists on its
     * roster is not its to give. */
    if (!now->has_session)
      return BNA_RETIRE;
    if (!now->is_primary)
      return BNA_CLASSIC;
    return incoming->held ? BNA_REBIND_HELD : BNA_REBIND_LIVE;

  case BNV_DEMOTE_LOCAL:
    /* A held ghost has no socket to keep as an alias: it yields. */
    if (now->held_ghost)
      return held_yields(incoming, now);
    return bounce_merge_choose(1, now->demote_bar) == BOUNCE_MERGE_SWAP
           ? BNA_SWAP : BNA_CLASSIC;
  }
  return BNA_CLASSIC;
}

const char *bounce_nick_verdict_name(enum bounce_nick_verdict v)
{
  switch (v) {
  case BNV_CLASSIC:          return "classic";
  case BNV_KEEP_LOCAL:       return "keep";
  case BNV_RETIRE_LOCAL:     return "retire";
  case BNV_DROP_LOCAL_GHOST: return "drop";
  case BNV_DEMOTE_LOCAL:     return "demote";
  }
  return "?";
}

const char *bounce_nick_action_name(enum bounce_nick_action a)
{
  switch (a) {
  case BNA_CLASSIC:     return "classic";
  case BNA_REFUSE:      return "refuse";
  case BNA_RETIRE:      return "retire";
  case BNA_REBIND_LIVE: return "rebind as live";
  case BNA_REBIND_HELD: return "rebind as held";
  case BNA_SWAP:        return "swap";
  case BNA_YIELD:       return "yield";
  }
  return "?";
}

enum bounce_bsc_compare bounce_bsc_compare_with(int same_id, int followed,
                                                int held_here)
{
  if (same_id)
    return BOUNCE_BSC_SAME_ID;
  if (followed)
    return BOUNCE_BSC_FOLLOWED;
  return held_here ? BOUNCE_BSC_HELD_HERE : BOUNCE_BSC_FIRST;
}

int bounce_follow_keeps_id(int announced, int ours_holding, const char *our_id,
                           int peer_holding, const char *peer_id)
{
  /* The peer has not seen our id: it keeps its own. */
  if (!announced)
    return 0;
  /* What the peer does with our announcement: its record is the one
   * whose primary we follow, live or with a live device. */
  return bounce_session_converge(peer_holding, 1, 1, peer_id, ours_holding,
                                 our_id) == BSO_RENAME;
}

int bounce_bsc_fresh_apart(int in_burst, int local_holding, int peer_holding)
{
  /* Two live copies met outside a burst: no rename, no reconcile until
   * the next link burst. */
  return !in_burst && !local_holding && !peer_holding;
}

int bounce_bsx_reannounces(int was_apart, int ours_held_here, int link_hold_mark)
{
  return was_apart && ours_held_here && link_hold_mark;
}

enum bounce_yield_id bounce_yield_id(int same_id, int in_burst,
                                     int other_exists, int other_kc_conflict)
{
  if (same_id)
    return BOUNCE_YIELD_KEEP_ID;
  if (other_exists)
    return other_kc_conflict ? BOUNCE_YIELD_KEEP_ID : BOUNCE_YIELD_MERGE;
  return in_burst ? BOUNCE_YIELD_KEEP_ID : BOUNCE_YIELD_TAKE_ID;
}
