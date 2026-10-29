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
                          int session_primary, int primary_ours,
                          int primary_remote)
{
  if (!bounce_forced_exit_punitive(why))
    /* A fault: a primary goes through the disconnect rule; a device's
     * exit is its own. */
    return is_alias ? BOUNCE_FORCED_PLAIN : BOUNCE_FORCED_DISCONNECT;
  if (is_alias) {
    if (primary_ours)
      return BOUNCE_FORCED_END_BY_PRIMARY;
    /* A primary on another server is that server's to exit: the end goes
     * there. */
    return primary_remote ? BOUNCE_FORCED_END_BY_HOLDER : BOUNCE_FORCED_PLAIN;
  }
  return session_primary ? BOUNCE_FORCED_END_SESSION : BOUNCE_FORCED_PLAIN;
}

char bounce_member_end_letter(enum bounce_member_end how)
{
  switch (how) {
  case BOUNCE_MEMBER_END_HOLD_OFF:
    return 'O';
  case BOUNCE_MEMBER_END_DETACH:
    return 'T';
  case BOUNCE_MEMBER_END_RESET:
    return 'R';
  case BOUNCE_MEMBER_END_DISCONNECT:
    break;
  }
  return 'D';
}

int bounce_member_end_parse(const char *letter)
{
  if (!letter || !letter[0] || letter[1])
    return -1;
  switch (letter[0]) {
  case 'D':
    return BOUNCE_MEMBER_END_DISCONNECT;
  case 'O':
    return BOUNCE_MEMBER_END_HOLD_OFF;
  case 'T':
    return BOUNCE_MEMBER_END_DETACH;
  case 'R':
    return BOUNCE_MEMBER_END_RESET;
  }
  return -1;
}

unsigned int bounce_end_side_effects(enum bounce_member_end how)
{
  switch (how) {
  case BOUNCE_MEMBER_END_HOLD_OFF:
    return BOUNCE_END_FX_HOLD_OFF;
  case BOUNCE_MEMBER_END_DETACH:
    return BOUNCE_END_FX_HOLD_OFF | BOUNCE_END_FX_WEBPUSH_FORGET;
  case BOUNCE_MEMBER_END_DISCONNECT:
  case BOUNCE_MEMBER_END_RESET:
    break;
  }
  return 0;
}

int bounce_end_asker_applies(enum bounce_end_route route)
{
  return route != BOUNCE_ROUTE_CARRY;
}

int bounce_member_end_resolve_admits(int alias, int on_roster, int ours,
                                     int held_ghost)
{
  return !alias && !on_roster && (!ours || held_ghost);
}

int bounce_end_refused(enum bounce_member_end how, int enforced)
{
  return how == BOUNCE_MEMBER_END_DETACH && enforced;
}

int bounce_end_takes_device(int filed, int same_id, int kc_conflict)
{
  return (filed || same_id) && !kc_conflict;
}

enum bounce_end_route bounce_end_route(int has_primary, int primary_ours,
                                       int route_reads_carry)
{
  /* We hold it, or nobody does. */
  if (!has_primary || primary_ours)
    return BOUNCE_ROUTE_HERE;
  return route_reads_carry ? BOUNCE_ROUTE_CARRY : BOUNCE_ROUTE_OWN_COPY;
}

enum bounce_bse_action bounce_bse_action(int known_kind, int found,
                                         int has_primary, int primary_ours,
                                         int toward_sender,
                                         int route_reads_carry)
{
  if (!known_kind || !found)
    return BOUNCE_BSE_DROP;
  if (!has_primary || primary_ours)
    return BOUNCE_BSE_END;
  /* Never back toward the sender (two records each naming the other's
   * client), never toward a server that would drop it. */
  return !toward_sender && route_reads_carry ? BOUNCE_BSE_FORWARD
                                             : BOUNCE_BSE_DROP;
}

enum bounce_end_primary bounce_end_primary(enum bounce_member_end how,
                                           int primary_ours, int held,
                                           int handled)
{
  if (!primary_ours)
    return BOUNCE_END_PRIMARY_REMOTE;
  /* A held ghost leaves even when it is the handled connection: it has no
   * connection to carry on with. */
  if (held)
    return BOUNCE_END_PRIMARY_EXITS;
  if (handled)
    return BOUNCE_END_PRIMARY_ASKED;
  if (how == BOUNCE_MEMBER_END_RESET)
    return BOUNCE_END_PRIMARY_EXITS;
  return BOUNCE_END_PRIMARY_STAYS;
}

int bounce_bsx_keep_reannounces(int kept, int link_hold_mark)
{
  return kept && link_hold_mark;
}

enum bounce_crossed_action bounce_crossed_bxx_action(int handed_to_it,
                                                     int active,
                                                     int own_devices)
{
  if (!handed_to_it || !active)
    return BOUNCE_CROSSED_LEAVE;
  return own_devices > 0 ? BOUNCE_CROSSED_PROMOTE : BOUNCE_CROSSED_END;
}

enum bounce_bxp_unknown bounce_bxp_unknown_action(int old_known, int new_known,
                                                  int old_is_lines_primary,
                                                  int new_numeric_ok,
                                                  int old_is_crossed_face)
{
  if (old_known && !new_known && old_is_lines_primary && new_numeric_ok)
    return BOUNCE_BXP_HOLD_OLD;
  if (!old_known && old_is_crossed_face) {
    if (new_known)
      return BOUNCE_BXP_FOLLOW_CROSSED;
    if (new_numeric_ok)
      return BOUNCE_BXP_RENUMBER_CROSSED;
  }
  return BOUNCE_BXP_FORWARD;
}

enum bounce_crossed_note bounce_crossed_note_state(int noted, int slot_is_kept)
{
  if (!noted)
    return BOUNCE_NOTE_NONE;
  return slot_is_kept ? BOUNCE_NOTE_KEPT : BOUNCE_NOTE_STALE;
}

enum bounce_crossed_backstop
bounce_crossed_backstop_action(int noted, int slot_is_kept, long age,
                               long wait_max)
{
  switch (bounce_crossed_note_state(noted, slot_is_kept)) {
  case BOUNCE_NOTE_NONE:
    return BOUNCE_BACKSTOP_NONE;
  case BOUNCE_NOTE_STALE:
    return BOUNCE_BACKSTOP_DROP;
  case BOUNCE_NOTE_KEPT:
    break;
  }
  return age < wait_max ? BOUNCE_BACKSTOP_WAIT : BOUNCE_BACKSTOP_END;
}

int bounce_crossed_replace_retracts(int noted, int new_is_kept)
{
  return noted && !new_is_kept;
}

enum bounce_repoint_take bounce_repoint_take(int alias, int is_new,
                                             int follows_old, int follows_none,
                                             int on_roster, int same_id,
                                             int same_account, int kc_conflict,
                                             int ours)
{
  /* Never the new primary, which follows nobody from now on, and never a
   * client of another account or Keycloak user, however it was found. */
  if (!alias || is_new || !same_account || kc_conflict)
    return BOUNCE_REPOINT_SKIP;
  /* A device of the outgoing client: one that follows it, filed anywhere,
   * or one filed in the record -- by numeric and by id -- that follows
   * nobody. */
  if (!(follows_old || (follows_none && on_roster && same_id)))
    return BOUNCE_REPOINT_SKIP;
  return ours ? BOUNCE_REPOINT_OWN : BOUNCE_REPOINT_REMOTE;
}

enum bounce_swap_member
bounce_swap_membership(const struct bounce_swap_facts *f)
{
  /* Only a swap's legacy links hold the survivor where the face was. */
  if (!f || !f->swap)
    return BOUNCE_SWAP_SKIP;
  /* A membership the face held as the session's primary, in a channel a
   * client of another server can be in, that the survivor is not in. */
  if (f->face_alias || f->zombie || f->local_channel || f->survivor_member)
    return BOUNCE_SWAP_SKIP;
  /* The channel's admission modes, as m_join reads them. */
  if ((f->ssl_only && f->plaintext)
      || (f->oper_only && !f->survivor_oper)
      || (f->admin_only && !f->survivor_admin))
    return BOUNCE_SWAP_KICK;
  return BOUNCE_SWAP_TAKE;
}


/* ---------------------------------------------------------------- */
/* W3 12c-2b: the chooser and the hold-on planner                    */
/* ---------------------------------------------------------------- */

int bounce_choose_best_held(const struct bounce_choose_row *rows, int n,
                            unsigned long skip)
{
  int i, best = -1;

  if (!rows)
    return -1;
  if (n > BOUNCE_CHOOSE_MAX_ROWS)
    n = BOUNCE_CHOOSE_MAX_ROWS;
  for (i = 0; i < n; i++) {
    if (!rows[i].held || (skip & (1UL << i)))
      continue;
    if (best < 0) {
      best = i;
      continue;
    }
    /* Ours first: a local ghost avoids a cross-server transfer. */
    if (rows[i].primary_ours && !rows[best].primary_ours) {
      best = i;
      continue;
    }
    /* Then the most recent disconnect (bounce_find_best_held()'s test,
     * which reads no locality here). */
    if (rows[i].disconnect_time > rows[best].disconnect_time)
      best = i;
  }
  return best;
}

/** A held replica nothing reachable holds: no holder here, no primary,
 * no ghost numeric, no devices. */
static int choose_garbage(const struct bounce_choose_row *r)
{
  return !r->local_holder && !r->primary && !r->ghost_numeric && !r->devices;
}

/** The live-session check: the first session left in list order. */
static void choose_live(const struct bounce_choose_row *rows, int n,
                        unsigned long gone, int tls_refused,
                        enum bounce_choose_kind *kind, int *index)
{
  const struct bounce_choose_row *r;
  int i;

  *index = -1;
  for (i = 0; i < n && (gone & (1UL << i)); i++)
    ;
  if (i >= n) {
    *kind = BOUNCE_CHOOSE_NONE;
    return;
  }
  r = &rows[i];
  if (r->held) {
    *kind = BOUNCE_CHOOSE_UNREACHABLE;
    return;
  }
  *index = i;
  if (!r->primary_ours && r->primary_server && r->primary && !r->full)
    *kind = BOUNCE_CHOOSE_ACTIVE_REMOTE;
  else if (!r->primary)
    *kind = BOUNCE_CHOOSE_ORPHAN;
  else if (r->full)
    *kind = BOUNCE_CHOOSE_FULL;
  else if (tls_refused)
    *kind = BOUNCE_CHOOSE_TLS;
  else
    *kind = BOUNCE_CHOOSE_ACTIVE_ALIAS;
}

void bounce_choose(const struct bounce_choose_row *rows, int n,
                   int tls_refused, struct bounce_choice *out)
{
  unsigned long gone;
  int i;

  out->kind = BOUNCE_CHOOSE_NONE;
  out->index = -1;
  out->end_stale = 0;
  out->discard = 0;
  out->held_full = 0;
  out->active_kind = BOUNCE_CHOOSE_NONE;
  out->active_index = -1;
  if (!rows || n <= 0)
    return;
  if (n > BOUNCE_CHOOSE_MAX_ROWS)
    n = BOUNCE_CHOOSE_MAX_ROWS;

  /* 1. The Keycloak gate over every session, in order (#16). */
  for (i = 0; i < n; i++) {
    if (rows[i].kc == BKJ_END_STALE)
      out->end_stale |= 1UL << i;
    else if (rows[i].kc == BKJ_REFUSE) {
      out->kind = BOUNCE_CHOOSE_KC_REFUSE;
      out->index = i;
      return;
    }
  }
  gone = out->end_stale;

  /* 2. The best held session; garbage is dropped and the next taken. */
  for (;;) {
    const struct bounce_choose_row *r;
    int best = bounce_choose_best_held(rows, n, gone);

    if (best < 0)
      break;
    r = &rows[best];
    if (r->primary_ours) {
      out->kind = BOUNCE_CHOOSE_HELD_LOCAL;
      out->index = best;
      break;
    }
    if (r->primary_server && r->primary && !r->full) {
      out->kind = BOUNCE_CHOOSE_HELD_REMOTE;
      out->index = best;
      break;
    }
    if (choose_garbage(r)) {
      out->discard |= 1UL << best;
      gone |= 1UL << best;
      continue;
    }
    /* Passed over: the live-session check decides. */
    out->held_full = r->primary && r->full;
    break;
  }

  /* 3. The live-session check (also what a failed revive falls back to). */
  choose_live(rows, n, gone, tls_refused, &out->active_kind,
              &out->active_index);
  if (out->index < 0) {
    out->kind = out->active_kind;
    out->index = out->active_index;
  }
}

enum bounce_resume_route bounce_resume_route(const struct bounce_choice *c)
{
  if (!c)
    return BOUNCE_ROUTE_PLAIN;
  switch (c->kind) {
  case BOUNCE_CHOOSE_NONE:          return BOUNCE_ROUTE_CREATE;
  case BOUNCE_CHOOSE_KC_REFUSE:     return BOUNCE_ROUTE_REJECT_KC;
  case BOUNCE_CHOOSE_HELD_LOCAL:    return BOUNCE_ROUTE_REVIVE;
  case BOUNCE_CHOOSE_HELD_REMOTE:   return BOUNCE_ROUTE_ALIAS_REMOTE;
  case BOUNCE_CHOOSE_ACTIVE_REMOTE: return BOUNCE_ROUTE_ALIAS_REMOTE;
  case BOUNCE_CHOOSE_ACTIVE_ALIAS:  return BOUNCE_ROUTE_ALIAS_LOCAL;
  case BOUNCE_CHOOSE_ORPHAN:        return BOUNCE_ROUTE_RECLAIM;
  case BOUNCE_CHOOSE_FULL:
  case BOUNCE_CHOOSE_TLS:           return BOUNCE_ROUTE_REJECT_DUPLICATE;
  case BOUNCE_CHOOSE_UNREACHABLE:   break;
  }
  return BOUNCE_ROUTE_PLAIN;
}

enum bounce_hold_on_plan
bounce_hold_on_plan(const struct bounce_hold_on_facts *f)
{
  if (!f)
    return BOUNCE_HOLD_DEFER;
  if (f->member)
    return BOUNCE_HOLD_NOOP;
  /* R14(g): no hold or membership transition while a link is mid-burst. */
  if (f->burst)
    return BOUNCE_HOLD_DEFER;
  switch (f->choice.kind) {
  case BOUNCE_CHOOSE_KC_REFUSE:
    return BOUNCE_HOLD_REFUSE_KC;
  case BOUNCE_CHOOSE_NONE:
    return f->choice.end_stale ? BOUNCE_HOLD_END_STALE_CREATE : BOUNCE_HOLD_CREATE;
  case BOUNCE_CHOOSE_FULL:
    return BOUNCE_HOLD_REFUSE_FULL;
  case BOUNCE_CHOOSE_TLS:
    return BOUNCE_HOLD_REFUSE_TLS;
  case BOUNCE_CHOOSE_ORPHAN:
    return BOUNCE_HOLD_DEFER;
  case BOUNCE_CHOOSE_UNREACHABLE:
    return f->choice.held_full ? BOUNCE_HOLD_REFUSE_FULL : BOUNCE_HOLD_DEFER;
  case BOUNCE_CHOOSE_HELD_LOCAL:
  case BOUNCE_CHOOSE_HELD_REMOTE:
  case BOUNCE_CHOOSE_ACTIVE_REMOTE:
  case BOUNCE_CHOOSE_ACTIVE_ALIAS:
    break;
  }
  /* A session to join: its primary must be one a device can follow. */
  if (!f->primary_user || f->primary_dying || !f->primary_home_aware)
    return BOUNCE_HOLD_DEFER;
  if (f->full)
    return BOUNCE_HOLD_REFUSE_FULL;
  if (f->tls_refused)
    return BOUNCE_HOLD_REFUSE_TLS;
  return f->choice.kind == BOUNCE_CHOOSE_HELD_LOCAL ? BOUNCE_HOLD_JOIN_PROMOTE
                                                    : BOUNCE_HOLD_JOIN;
}

int bounce_hold_on_refused(enum bounce_hold_on_plan plan)
{
  return plan == BOUNCE_HOLD_REFUSE_KC || plan == BOUNCE_HOLD_REFUSE_FULL
         || plan == BOUNCE_HOLD_REFUSE_TLS || plan == BOUNCE_HOLD_DEFER;
}

int bounce_hold_on_acts(enum bounce_hold_on_plan plan)
{
  return plan == BOUNCE_HOLD_JOIN || plan == BOUNCE_HOLD_JOIN_PROMOTE
         || plan == BOUNCE_HOLD_CREATE || plan == BOUNCE_HOLD_END_STALE_CREATE;
}

const char *bounce_hold_on_plan_name(enum bounce_hold_on_plan plan)
{
  switch (plan) {
  case BOUNCE_HOLD_NOOP:             return "noop";
  case BOUNCE_HOLD_JOIN:             return "join";
  case BOUNCE_HOLD_JOIN_PROMOTE:     return "join+promote";
  case BOUNCE_HOLD_CREATE:           return "create";
  case BOUNCE_HOLD_END_STALE_CREATE: return "end-stale+create";
  case BOUNCE_HOLD_REFUSE_KC:        return "refuse-keycloak";
  case BOUNCE_HOLD_REFUSE_FULL:      return "refuse-full";
  case BOUNCE_HOLD_REFUSE_TLS:       return "refuse-tls";
  case BOUNCE_HOLD_DEFER:            return "defer";
  }
  return "unknown";
}

enum bounce_hold_tail bounce_hold_tail_step(enum bounce_hold_tail now,
                                            int on, int acts, int refused)
{
  if (on) {
    /* A refused +b is not set: what was pending stands. */
    if (refused)
      return now;
    return acts ? BOUNCE_HOLD_TAIL_ON : BOUNCE_HOLD_TAIL_NONE;
  }
  return acts ? BOUNCE_HOLD_TAIL_END : BOUNCE_HOLD_TAIL_NONE;
}

int bounce_hold_on_tells(int asker_device, int target_ours, int target_user,
                         int stands)
{
  return asker_device && !target_ours && target_user && stands;
}
