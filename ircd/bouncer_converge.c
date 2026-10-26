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

  /* Same state: the older session id (lexicographically lower UUID v7)
   * wins; identical ids are the same session, ours stays. */
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
    /* Two held ghosts: the older session keeps; one session held on both
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
