/*
 * IRC - Internet Relay Chat, ircd/bouncer_wire.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_wire.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_wire.h"

int bounce_legacy_link_knows(int link_aware, int link_gated,
                             int face_behind_link)
{
  /* An aware link follows the session itself; a gated one has been sent
   * nothing yet; the face's own direction introduced it to us. */
  if (link_aware || link_gated || face_behind_link)
    return 0;
  return 1;
}

enum bounce_demote_bar bounce_demote_check(enum bounce_demote_stage stage,
                                           const struct bounce_demote_facts *f)
{
  if (!f)
    return BOUNCE_DEMOTE_NO_NEW_HOME;
  /* Different Keycloak users are never merged, whatever else holds. */
  if (f->kc_id_conflict)
    return BOUNCE_DEMOTE_KC_CONFLICT;
  if (!f->new_home_known)
    return BOUNCE_DEMOTE_NO_NEW_HOME;
  /* A legacy home has no sessions and never hears BX C. */
  if (!f->new_home_aware)
    return BOUNCE_DEMOTE_LEGACY_HOME;
  if (!f->face_account_user)
    return BOUNCE_DEMOTE_NOT_ACCOUNT_USER;
  /* Before the demote the face is a live primary; after it, the alias
   * the demote made. */
  if (stage == BOUNCE_DEMOTE_FINISH ? !f->face_alias : f->face_alias)
    return BOUNCE_DEMOTE_FACE_ALIAS;
  if (f->face_held)
    return BOUNCE_DEMOTE_FACE_HELD;
  /* Its own exit holds the session; an alias exit would end it. */
  if (f->face_dying)
    return BOUNCE_DEMOTE_FACE_DYING;
  if (!f->session_found)
    return BOUNCE_DEMOTE_NO_SESSION;
  if (f->session_slot != (stage == BOUNCE_DEMOTE_FINISH ? BOUNCE_SLOT_EMPTY
                                                       : BOUNCE_SLOT_FACE))
    return BOUNCE_DEMOTE_SESSION_SLOT;
  /* The finish's account rules, asked at both steps. */
  if (!f->new_account)
    return BOUNCE_DEMOTE_NEW_ACCOUNT;
  if (!f->session_account)
    return BOUNCE_DEMOTE_SESSION_ACCOUNT;
  return BOUNCE_DEMOTE_OK;
}

const char *bounce_demote_bar_name(enum bounce_demote_bar bar)
{
  switch (bar) {
  case BOUNCE_DEMOTE_OK:               return "ok";
  case BOUNCE_DEMOTE_NO_NEW_HOME:      return "no new primary";
  case BOUNCE_DEMOTE_LEGACY_HOME:      return "legacy home";
  case BOUNCE_DEMOTE_NOT_ACCOUNT_USER: return "not a logged-in user";
  case BOUNCE_DEMOTE_FACE_ALIAS:       return "alias state";
  case BOUNCE_DEMOTE_FACE_HELD:        return "held ghost";
  case BOUNCE_DEMOTE_FACE_DYING:       return "exiting";
  case BOUNCE_DEMOTE_NO_SESSION:       return "no session";
  case BOUNCE_DEMOTE_SESSION_SLOT:     return "not the session's primary";
  case BOUNCE_DEMOTE_NEW_ACCOUNT:      return "new primary's account differs";
  case BOUNCE_DEMOTE_SESSION_ACCOUNT:  return "session's account differs";
  case BOUNCE_DEMOTE_KC_CONFLICT:      return "Keycloak ids differ";
  }
  return "?";
}

enum bounce_merge_choice bounce_merge_choose(int we_lose,
                                             enum bounce_demote_bar bar)
{
  /* Both sides read the same two ids: neither merges. */
  if (bar == BOUNCE_DEMOTE_KC_CONFLICT)
    return BOUNCE_MERGE_CLASSIC;
  if (!we_lose)
    return BOUNCE_MERGE_REFUSE;
  return bar == BOUNCE_DEMOTE_OK ? BOUNCE_MERGE_SWAP : BOUNCE_MERGE_CLASSIC;
}

char bounce_hold_stamp(int held, int primary)
{
  if (held)
    return BOUNCE_HOLD_MARK_HELD;
  return primary ? BOUNCE_HOLD_MARK_PRIMARY : BOUNCE_HOLD_MARK_OUTSIDER;
}

int bounce_hold_mark_valid(char mark)
{
  return mark == BOUNCE_HOLD_MARK_HELD || mark == BOUNCE_HOLD_MARK_PRIMARY
         || mark == BOUNCE_HOLD_MARK_OUTSIDER;
}

int bounce_hold_marks_trusted_path(int hops, int hops_with_h, int reached_us,
                                   int sent_h, int tags_on)
{
  /* We send marks only while the tags are on; a peer judges ours by the
   * H our SERVER line announced, so we trust its marks only when it can
   * trust ours; and every server between its home and us must relay
   * them. */
  if (!tags_on || !reached_us || !sent_h || hops <= 0)
    return 0;
  return hops_with_h == hops;
}

enum bounce_alias_filing bounce_alias_filing(int exact, int by_primary,
                                             int by_account, int unmirrored)
{
  if (exact)
    return BOUNCE_FILE_EXACT;
  if (by_primary)
    return BOUNCE_FILE_PRIMARY;
  /* The account's session stands in for an id only while that id may
   * still become ours by a rename -- never for one BS C kept out. */
  return by_account && !unmirrored ? BOUNCE_FILE_ACCOUNT : BOUNCE_FILE_NONE;
}

enum bounce_bxc_known bounce_bxc_known_alias(int behind_link, int same_primary,
                                             int filed_as_named, int same_nick,
                                             int same_sessid)
{
  /* Only the alias's own server speaks for it, over its own link. */
  if (!behind_link)
    return BOUNCE_BXC_KNOWN_IGNORE;
  if (same_primary && filed_as_named && same_nick && same_sessid)
    return BOUNCE_BXC_KNOWN_KEEP;
  return BOUNCE_BXC_KNOWN_REFILE;
}

enum bounce_promote_session
bounce_promote_session(int exact, int by_old_primary, int ambiguous,
                       int new_on_roster)
{
  if (exact)
    return BOUNCE_PROMOTE_EXACT;
  /* Both keys: the old primary's one session, and the new primary on its
   * roster.  Narrower than an alias's filing: a promote changes who the
   * session's primary is. */
  if (by_old_primary && !ambiguous && new_on_roster)
    return BOUNCE_PROMOTE_PRIMARY;
  return BOUNCE_PROMOTE_NONE;
}

int bounce_server_at_or_behind(const void *srv, const void *departing,
                               const void *(*up)(const void *))
{
  int hops;

  if (!srv || !departing || !up)
    return 0;
  for (hops = 0; srv && hops < BOUNCE_MAX_SERVER_DEPTH; hops++) {
    const void *next;

    if (srv == departing)
      return 1;
    next = up(srv);
    if (next == srv)
      return 0;     /* the root: our own server */
    srv = next;
  }
  return 0;
}

int bounce_squit_prepares(int has_primary, int primary_local,
                          int primary_behind, int origin_behind)
{
  /* Where the primary is, when there is one; the recorded origin only
   * for a session that has none. */
  if (has_primary)
    return !primary_local && primary_behind;
  return origin_behind;
}

enum bounce_hold_expiry bounce_hold_expiry_action(int has_primary,
                                                  int primary_ours_held,
                                                  int alias_count)
{
  if (has_primary && !primary_ours_held)
    return BOUNCE_HOLD_KEEP;
  if (alias_count > 0)
    return BOUNCE_HOLD_PROMOTE;
  return has_primary ? BOUNCE_HOLD_END : BOUNCE_HOLD_DROP;
}

int bounce_alias_is_own(int has_slot, int primary_set, int primary_is_slot,
                        int primary_is_user)
{
  /* Another copy's device: it follows a user who is not our primary. */
  return !(has_slot && primary_set && !primary_is_slot && primary_is_user);
}

int bounce_same_session_yields(int ours_holding, int ours_live,
                               int theirs_active, int their_primary,
                               int kc_conflict)
{
  return ours_holding && !ours_live && theirs_active && their_primary
         && !kc_conflict;
}

int bounce_bsx_keeps(int has_primary, int primary_ours, int primary_killed)
{
  return has_primary && primary_ours && !primary_killed;
}

enum bounce_bsa_action bounce_bsa_action(int resolved, int cand_alias,
                                         int cand_on_roster, int cand_ours,
                                         int slot_ours)
{
  /* A connection the line names for its own sake (an alias's activity),
   * or one the sender cannot speak for. */
  if (resolved && (cand_alias || cand_on_roster || cand_ours))
    return BOUNCE_BSA_IGNORE;
  /* Our own client holds the slot: we decide what it is. */
  if (slot_ours)
    return BOUNCE_BSA_IGNORE;
  return resolved ? BOUNCE_BSA_INSTALL : BOUNCE_BSA_NUMERIC;
}

int bounce_bsa_yields(int in_burst, int slot_ours_held, int cand_member,
                      int ours_holding, int kc_conflict)
{
  /* The live copy wins, as at BS C: our held ghost holds the slot, the
   * peer's member attached outside its burst. */
  return !in_burst && slot_ours_held && cand_member
         && bounce_same_session_yields(ours_holding, 0, 1, 1, kc_conflict);
}

enum bounce_bsd_action bounce_bsd_action(int kc_conflict, int slot_ours)
{
  if (kc_conflict)
    return BOUNCE_BSD_FORWARD;
  return slot_ours ? BOUNCE_BSD_NOTE : BOUNCE_BSD_APPLY;
}

int bounce_bsd_reannounces(enum bounce_bsd_action action, int slot_live,
                           int link_hold_mark)
{
  /* The sender's copy went held while ours is live: the live copy wins,
   * and a held copy yields to a BS A sent outside a burst. */
  return action == BOUNCE_BSD_NOTE && slot_live && link_hold_mark;
}

enum bounce_bxp_session_action
bounce_bxp_session_action(int slot_ours, int slot_held, int old_is_slot,
                          int new_is_slot, int ours_holding, int kc_conflict)
{
  /* A slot that is not ours follows the sender, and a swap of our own
   * face renumbers it. */
  if (!slot_ours || old_is_slot)
    return BOUNCE_BXP_APPLY;
  /* The line names our own client as the face: the record holds it
   * already (a held ghost stays held; a yield would exit it). */
  if (new_is_slot)
    return BOUNCE_BXP_KEEP;
  /* Another server's copy: our held ghost yields to its live one, as at
   * BS A; our live primary stays. */
  if (slot_held && bounce_same_session_yields(ours_holding, 0, 1, 1, kc_conflict))
    return BOUNCE_BXP_YIELD;
  return BOUNCE_BXP_KEEP;
}

enum bounce_disconnect
bounce_disconnect_action(const struct bounce_disconnect_facts *f)
{
  /* The hold's own guards stand for a promote too. */
  if (!f || f->killed || !f->logged_in || !f->bouncer_on || !f->local_user
      || !f->active_primary)
    return BOUNCE_DISCONNECT_EXIT;
  /* A live device takes over, whatever the preference: here at once,
   * elsewhere at the next tick. */
  if (f->own_aliases > 0)
    return !f->local_tried ? BOUNCE_DISCONNECT_PROMOTE_LOCAL
         : f->wants_hold ? BOUNCE_DISCONNECT_HOLD_PROMOTE
         : BOUNCE_DISCONNECT_BRIEF_PROMOTE;
  /* Nothing to promote: the preference decides. */
  return f->wants_hold ? BOUNCE_DISCONNECT_HOLD : BOUNCE_DISCONNECT_EXIT;
}


enum bounce_orphan_action
bounce_orphan_alias_action(int local, int has_primary, int filed,
                           int primary_live, int kc_conflict)
{
  /* Another server's alias is that server's; one that follows a primary
   * is no orphan. */
  if (!local || has_primary)
    return BOUNCE_ORPHAN_KEEP;
  if (filed && primary_live && !kc_conflict)
    return BOUNCE_ORPHAN_REPOINT;
  return BOUNCE_ORPHAN_EXIT;
}

int bounce_bsx_ends_device(int sender_holds, int own, int follows_sender,
                           int same_id, int kc_conflict)
{
  return sender_holds && own && follows_sender && same_id && !kc_conflict;
}

int bounce_session_end_exits(enum bounce_session_end how, int own)
{
  /* A KILL ends the whole session; a retire, only our own copy. */
  return how == BOUNCE_END_KILL || own;
}

int bounce_forced_exit_punitive(enum bounce_forced_exit why)
{
  return why == BOUNCE_FORCED_BAN || why == BOUNCE_FORCED_SERVICES;
}

enum bounce_forced_action
bounce_forced_exit_action(enum bounce_forced_exit why, int is_alias,
                          int session_primary, int primary_ours)
{
  if (!bounce_forced_exit_punitive(why))
    /* A fault: a primary goes through the disconnect rule; a device's
     * exit is its own. */
    return is_alias ? BOUNCE_FORCED_PLAIN : BOUNCE_FORCED_DISCONNECT;
  if (is_alias)
    /* A primary on another server is that server's to exit. */
    return primary_ours ? BOUNCE_FORCED_END_BY_PRIMARY : BOUNCE_FORCED_PLAIN;
  return session_primary ? BOUNCE_FORCED_END_SESSION : BOUNCE_FORCED_PLAIN;
}

enum bounce_crossed_action bounce_crossed_bxx_action(int handed_to_it,
                                                     int own_devices)
{
  if (!handed_to_it)
    return BOUNCE_CROSSED_LEAVE;
  return own_devices > 0 ? BOUNCE_CROSSED_PROMOTE : BOUNCE_CROSSED_END;
}

enum bounce_bxp_unknown bounce_bxp_unknown_action(int old_known, int new_known,
                                                  int old_from_line,
                                                  int new_filed)
{
  if (old_known && !new_known && old_from_line)
    return BOUNCE_BXP_RETIRE_OLD;
  if (!old_known && new_known && new_filed)
    return BOUNCE_BXP_PROMOTE_NEW;
  return BOUNCE_BXP_FORWARD;
}
