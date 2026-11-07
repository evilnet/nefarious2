/*
 * IRC - Internet Relay Chat, ircd/m_away.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: m_away.c 1271 2004-12-11 05:14:07Z klmitch $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "bouncer_session.h"
#include "capab.h"
#include "client.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

/*
 * user_set_away - set user away state
 * returns 1 if client is away or changed away message, 0 if
 * client is removing away status.
 * NOTE: this function may modify user and message, so they
 * must be mutable.
 */
int user_set_away(struct User* user, char* message)
{
  char* away;
  assert(0 != user);

  away = user->away;

  if (EmptyString(message)) {
    /*
     * Marking as not away
     */
    if (away) {
      MyFree(away);
      user->away = 0;
    }
  }
  else {
    /*
     * Marking as away
     */
    unsigned int len = strlen(message);

    if (len > AWAYLEN) {
      message[AWAYLEN] = '\0';
      len = AWAYLEN;
    }
    if (away)
      MyFree(away);
    away = (char*) MyMalloc(len + 1);
    assert(0 != away);

    user->away = away;
    strcpy(away, message);
  }
  return (user->away != 0);
}

/** The away text to show @a viewer for a stored away @a away: the star
 *  itself to a draft/pre-away client, FEAT_AWAY_STAR_MSG to any other.
 *  "An away message of * should be treated as though the connection did
 *  not exist at all": a pre-away client recognises the star and prints
 *  nothing; a legacy client needs words. */
const char *away_text_for(struct Client *viewer, const char *away)
{
  const char *word;

  if (!away || away[0] != '*' || away[1] != '\0')
    return away;
  if (viewer && MyConnect(viewer) && CapActive(viewer, CAP_DRAFT_PREAWAY))
    return away;
  word = feature_str(FEAT_AWAY_STAR_MSG);
  return (word && *word) ? word : away;
}

/** Broadcast an away-state change to other servers: the wire body for
 *  CMD_AWAY toward the rest of the mesh, for local changes and relays
 *  alike -- except a legacy sender's literal "*", which ms_away relays
 *  verbatim itself (see below).
 *  @a away NULL or "" means present; the literal "*" means the
 *  pre-away star (draft/pre-away, "hidden" rather than invisible);
 *  anything else is a normal away message.
 *
 *  An IRCv3-aware peer keeps the star verbatim -- same as a local
 *  draft/pre-away client, it does its own per-viewer substitution
 *  further on.  A legacy peer has no such layer, so it is given
 *  FEAT_AWAY_STAR_MSG straight from this hop: the same word a local
 *  non-pre-away client is shown via away_text_for().  L stores and
 *  displays away text as-is, so the substitution has to happen here,
 *  at the fork edge, not downstream.
 *
 *  The _v3 send goes first: it is the one that actually consumes any
 *  S2S tags armed on this call (msgid/time) via the opt-in flag, and
 *  the legacy send must never carry them -- sendcmdto_legacy_serv_butone()
 *  builds an untagged line unconditionally.  Both sendcmdto_serv_butone_v3()
 *  and sendcmdto_legacy_serv_butone() keep sendcmdto_serv_butone()'s
 *  alias->primary egress rewrite (bouncer-architecture invariant #10), so
 *  @a from may safely be a local alias.
 *
 *  Callers must never arm s2s_alias_source before calling this: only
 *  the first underlying send consumes it, so a second send in the star
 *  branch would fall back to the automatic IsBouncerAlias(from) check
 *  instead -- fine only because AWAY never arms one.  Keep it that way.
 *
 *  This is purely the fork-origin substitution: a caller relaying an
 *  AWAY that arrived with a literal "*" from a non-IRCv3-aware link
 *  must NOT route it through here -- that star is the sender's own
 *  legacy away-message text, not the pre-away token, and must cross
 *  every further hop unchanged.  ms_away tells the two apart by the
 *  link the AWAY arrived on, not by the sender's own server.  That is
 *  right on the graph prod runs (fork servers contiguous, legacy peers
 *  only at its edge): a legacy user's star that reaches a second fork
 *  server through the first arrives on an aware link and is taken for
 *  the pre-away token, which would show that server's own legacy peers
 *  the configured word -- and no fork server behind another one has a
 *  legacy peer there. */
void away_send_to_servers(struct Client *from, struct Client *one,
                          const char *away)
{
  if (EmptyString(away)) {
    sendcmdto_serv_butone(from, CMD_AWAY, one, "");
    return;
  }
  if (away[0] == '*' && away[1] == '\0') {
    sendcmdto_serv_butone_v3(from, CMD_AWAY, one, ":*");
    sendcmdto_legacy_serv_butone(from, CMD_AWAY, one, ":%s",
                                 away_text_for(NULL, "*"));
    return;
  }
  sendcmdto_serv_butone(from, CMD_AWAY, one, ":%s", away);
}

static int away_is_star(const char *text)
{
  return text && text[0] == '*' && text[1] == '\0';
}

/** away-notify to every local member of @a sptr's channels except @a one,
 *  the star going as a star to draft/pre-away clients and as
 *  FEAT_AWAY_STAR_MSG to the rest.  @a text NULL or "" is "back". */
void away_notify_common(struct Client *sptr, struct Client *one,
                        const char *text)
{
  if (!away_is_star(text)) {
    sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, one,
                                           CAP_AWAYNOTIFY, CAP_NONE, ":%s",
                                           text ? text : "");
    return;
  }
  sendcmdto_set_extra_withcap(CAP_DRAFT_PREAWAY);
  sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, one,
                                         CAP_AWAYNOTIFY, CAP_NONE, ":*");
  sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, one,
                                         CAP_AWAYNOTIFY, CAP_DRAFT_PREAWAY,
                                         ":%s", away_text_for(NULL, text));
}

/** The same for one channel (a JOIN announcing an existing away). */
void away_notify_channel(struct Client *sptr, struct Channel *chptr,
                         const char *text)
{
  if (!away_is_star(text)) {
    sendcmdto_channel_capab_butserv_butone(sptr, CMD_AWAY, chptr, NULL,
                                           SKIP_CHGHOST, CAP_AWAYNOTIFY,
                                           CAP_NONE, ":%s", text ? text : "");
    return;
  }
  sendcmdto_set_extra_withcap(CAP_DRAFT_PREAWAY);
  sendcmdto_channel_capab_butserv_butone(sptr, CMD_AWAY, chptr, NULL,
                                         SKIP_CHGHOST, CAP_AWAYNOTIFY,
                                         CAP_NONE, ":*");
  sendcmdto_channel_capab_butserv_butone(sptr, CMD_AWAY, chptr, NULL,
                                         SKIP_CHGHOST, CAP_AWAYNOTIFY,
                                         CAP_DRAFT_PREAWAY, ":%s",
                                         away_text_for(NULL, text));
}


/*
 * FEAT_AWAY_THROTTLE: Minimum seconds between AWAY changes (0 = disabled).
 * Prevents scripts that reset away message every few seconds from
 * generating excessive network traffic.  Applied in away_apply() for a
 * client's own AWAY only.
 */
/** Apply an away state to a local user as the AWAY command would:
 * per-connection own state; for a session member its report to the other
 * servers (bounce_note_away_state) and, where the session's primary is,
 * the session's aggregation, broadcast and away-notify (W3 Task 16: one
 * writer per session); else the network broadcast and away-notify.
 * @param[in] cptr Connection the change came in on (== sptr).
 * @param[in] sptr User whose state changes.
 * @param[in] away_message New message; empty or NULL = present; "*" =
 *   away-star (draft/pre-away).
 * @param[in] interactive Non-zero for a client's own AWAY: the throttle
 *   applies and RPL_NOWAWAY/RPL_UNAWAY are sent.  Zero when registration
 *   applies a pre-registration AWAY (draft/pre-away), which got no
 *   numerics then and gets none now.
 * @return Zero.
 */
int away_apply(struct Client *cptr, struct Client *sptr, char *away_message,
               int interactive)
{
  int was_away = cli_user(sptr)->away != 0;
  int is_away;
  int is_away_star = 0;
  int throttle;
  struct BouncerSession *bsess = NULL;
  char away_msgid[64] = "";
  uint64_t away_time_ms = 0;

  assert(0 != cptr);
  assert(cptr == sptr);

  /* A connection that belongs to a bouncer session sets its OWN away
   * state, and the session's effective state -- what the network sees
   * -- is aggregated over every connection of the session below.  Not
   * optional: the pre-away star, its per-viewer substitution, the
   * per-connection replication (BX U aw=) and webpush attention all
   * assume it.  Until 2026-09-18 this hung on a FEAT_PRESENCE_AGGREGATION
   * flag that defaulted off, and a session member falling through to
   * the plain path below broadcast a per-connection away from its own
   * numeric: its siblings saw their own nick go away while WHOIS, which
   * resolves to the primary, said present.
   *
   * A user can be IsAccount() with sessions persisted on their account
   * from other connections; if this connection is not part of one there
   * is nothing to aggregate across, so it takes the plain path. */
  if (IsAccount(sptr) && bounce_enabled_for(sptr)
      && bounce_has_sessions(cli_account(sptr))) {
    /* Alias /away -- look up the session via the alias's primary so
     * aggregation considers this alias's con_pre_away.
     * bounce_get_session keys on hs_client which is the primary. */
    struct Client *anchor =
        (IsBouncerAlias(sptr) && cli_alias_primary(sptr))
            ? cli_alias_primary(sptr) : sptr;
    bsess = bounce_get_session(anchor);
  }

  /* Check AWAY throttle - silently drop if too soon after last change.
   * Not in the session path: its effective-state change detection
   * already suppresses redundant broadcasts. */
  throttle = feature_int(FEAT_AWAY_THROTTLE);
  if (interactive && throttle > 0 && !bsess) {
    if (CurrentTime < cli_nextaway(cptr)) {
      /* Too soon - silently ignore (no error to avoid spam) */
      return 0;
    }
    /* Update next allowed time */
    cli_nextaway(cptr) = CurrentTime + throttle;
  }

  /* Check for AWAY * (hidden connection) before processing */
  if (away_message && away_message[0] == '*' && away_message[1] == '\0') {
    is_away_star = 1;
    /* Kept as the star; non-pre-away clients see FEAT_AWAY_STAR_MSG at
     * emission (away_text_for / away_notify_common). */
  }

  /* The event: one msgid and one time (the HLC's, read right after the
   * msgid is minted, so the two agree).  Registration and a revive applying
   * a pre-registration AWAY (draft/pre-away) show the event mu_away()
   * stamped when the client said it.  The session orders its members by
   * this time (W3 Task 16 fix round 2: the newest explicit event wins), and
   * the report and the session's AWAY carry it. */
  if (!interactive && con_pre_away_ms(cli_connect(sptr))) {
    ircd_strncpy(away_msgid, con_pre_away_msgid(cli_connect(sptr)),
                 sizeof(away_msgid));
    away_time_ms = con_pre_away_ms(cli_connect(sptr));
  } else {
    if (feature_bool(FEAT_MSGID))
      generate_msgid(away_msgid, sizeof(away_msgid));
    away_time_ms = history_event_time_ms(NULL);
  }

  /* Update the connection's OWN away state, on every path: a session
   * aggregates from it and the replicas read it (BX U aw=), and a
   * connection that joins a session later brings it along.  Stored in
   * con_pre_away/con_pre_away_msg so it survives effective-state
   * updates to cli_user->away. */
  if (is_away_star) {
    con_pre_away(cli_connect(sptr)) = 2;
    con_pre_away_msg(cli_connect(sptr))[0] = '\0';
  } else if (!EmptyString(away_message)) {
    con_pre_away(cli_connect(sptr)) = 1;
    ircd_strncpy(con_pre_away_msg(cli_connect(sptr)), away_message, AWAYLEN + 1);
  } else {
    con_pre_away(cli_connect(sptr)) = 0;
    con_pre_away_msg(cli_connect(sptr))[0] = '\0';
  }
  con_pre_away_ms(cli_connect(sptr)) = away_time_ms;
  ircd_strncpy(con_pre_away_msgid(cli_connect(sptr)), away_msgid,
               sizeof(con_pre_away_msgid(cli_connect(sptr))));

  if (bsess) {
    if (interactive)
      send_reply(sptr, EmptyString(away_message) ? RPL_UNAWAY : RPL_NOWAWAY);
    /* Other servers judge attention (webpush) and the server of the
     * primary aggregates from each connection's OWN state and text, with
     * this event's msgid and time; the session's state, which a present
     * sibling hides, is not it. */
    bounce_note_away_state(sptr);
    /* The session's state over every member's own (W3 Task 16): decided
     * only where the primary is, the newest explicit event's text winning
     * -- this one, a re-sent AWAY included; on a change every local member
     * shows it, AWAY goes from the primary to every link and the channels
     * are told -- this connection had its 305/306.  Anywhere else that is
     * all: the AWAY the primary's server sends, if the session changes,
     * comes back here (ms_away). */
    bounce_session_away_event(bsess, sptr);
    return 0;
  }

  /* Non-aggregated path — used when there is no bouncer session for
   * this connection (including account users whose current connection
   * isn't attached to a session). */
  is_away = user_set_away(cli_user(sptr), away_message);
  {
    if (away_msgid[0])
      sendcmdto_set_client_msgid(away_msgid);

    if (is_away)
    {
      if (!was_away) {
        if (away_msgid[0])
          sendcmdto_set_s2s_tags(away_time_ms, away_msgid);
          sendcmdto_want_s2s_tags(1);
        away_send_to_servers(sptr, cptr, away_message);
      }
      if (interactive)
        send_reply(sptr, RPL_NOWAWAY);
      away_notify_common(sptr, sptr, away_message);
    }
    else {
      if (away_msgid[0])
        sendcmdto_set_s2s_tags(away_time_ms, away_msgid);
        sendcmdto_want_s2s_tags(1);
      away_send_to_servers(sptr, cptr, NULL);
      if (interactive)
        send_reply(sptr, RPL_UNAWAY);
      sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, sptr, CAP_AWAYNOTIFY, CAP_NONE, "");
    }

    sendcmdto_set_client_msgid(NULL);
  }
  return 0;
}

/*
 * m_away - generic message handler
 * - Added 14 Dec 1988 by jto.
 *
 * parv[0] = sender prefix
 * parv[1] = away message
 */
int m_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);

  return away_apply(cptr, sptr, parv[1], 1);
}

/*
 * ms_away - server message handler
 * - Added 14 Dec 1988 by jto.
 *
 * parv[0] = sender prefix
 * parv[1] = away message
 */
int ms_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* away_message = parv[1];
  int is_away;
  int is_away_star = 0;
  int unchanged = 0;

  assert(0 != cptr);
  assert(0 != sptr);
  /*
   * servers can't set away
   */
  if (IsServer(sptr))
    return protocol_violation(sptr,"Server trying to set itself away");

  /* Check for AWAY * (hidden connection) from P10 */
  if (away_message && away_message[0] == '*' && away_message[1] == '\0') {
    is_away_star = 1;
    /* Kept as the star; non-pre-away clients see FEAT_AWAY_STAR_MSG at
     * emission (away_text_for / away_notify_common). */
  }

  /* An AWAY from another server's device: an older server reports its
   * device's own state this way.  Where the session's primary is ours we
   * decide (W3 Task 16): it is that device's own state and text, and the
   * session is aggregated again -- the AWAY that goes out, if any, is
   * ours, from the primary.  Elsewhere (a hop on the way to the primary's
   * server) it lands on the primary as before, so WHOIS and the PRIVMSG
   * auto-reply here answer as the user. */
  if (IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
    if (MyConnect(cli_alias_primary(sptr))) {
      /* Ours to decide, never applied to our primary and relayed: that was
       * the stuck shape (fix round 1, M-1).  A device no record of ours
       * lists (a full roster; sessions kept apart sharing an id) is kept
       * as its own state and nothing more. */
      if (!bounce_member_away_report(sptr, away_message, cli_s2s_msgid(cptr),
                                     cli_s2s_time_ms(cptr)))
        log_write(LS_USER, L_INFO, 0, "AWAY: %s sends an AWAY from %s%s, a "
                  "device of our %s that no session of ours lists: kept as the "
                  "device's own state, not applied",
                  cli_name(cli_user(sptr)->server),
                  cli_yxx(cli_user(sptr)->server), cli_yxx(sptr),
                  cli_name(cli_alias_primary(sptr)));
      return 0;
    }
    sptr = cli_alias_primary(sptr);
  }

  /* A session primary's AWAY saying what this server shows already is a
   * no-op past the record and the mirror below: no away-notify, no relay
   * (W3 Task 16 fix round 2, P3).  The primary's server restates its
   * decision to every link after a relink (at its away barrier's PONG,
   * fix round 4); this server shows every face as its legacy links do,
   * so unchanged here is unchanged downstream.  A user outside a session
   * keeps the stock behaviour. */
  {
    struct BouncerSession *ps = bounce_get_session(sptr);

    if (ps && ps->hs_client == sptr) {
      char line[AWAYLEN + 1];
      const char *shown = cli_user(sptr)->away;

      ircd_strncpy(line, away_message ? away_message : "", sizeof(line));
      unchanged = line[0] ? (shown && 0 == strcmp(shown, line)) : !shown;
    }
  }

  is_away = user_set_away(cli_user(sptr), away_message);
  /* A session primary's AWAY is its server's decision for the session:
   * the session's state here (the presence metadata, and what we compare
   * against should we come to decide). */
  bounce_effective_away_heard(sptr, away_message, cli_s2s_time_ms(cptr));

  /* Mirror the away state onto local aliases of this primary so their
   * WHOIS/connections see the same state.  Remote aliases learn via
   * the AWAY relay we forward below. */
  if (IsAccount(sptr) && IsUser(sptr)) {
    struct AccountSessions *as_sib =
        bounce_find_by_account(cli_user(sptr)->account);
    if (as_sib) {
      struct BouncerSession *sib_sess;
      for (sib_sess = as_sib->as_sessions; sib_sess;
           sib_sess = sib_sess->hs_anext) {
        int sib_i;
        for (sib_i = 0; sib_i < sib_sess->hs_alias_count; sib_i++) {
          struct Client *sib_alias =
              findNUser(sib_sess->hs_aliases[sib_i].ba_numeric);
          if (sib_alias && IsBouncerAlias(sib_alias)
              && cli_alias_primary(sib_alias) == sptr
              && MyConnect(sib_alias)) {
            user_set_away(cli_user(sib_alias), away_message);
          }
        }
      }
    }
  }

  if (unchanged)
    return 0;

  /* Reuse incoming S2S msgid or generate new for away-notify */
  {
    char away_msgid[64] = "";
    uint64_t away_time_ms = 0;
    if (feature_bool(FEAT_MSGID)) {
      if (cli_s2s_msgid(cptr)[0]) {
        ircd_strncpy(away_msgid, cli_s2s_msgid(cptr), sizeof(away_msgid));
        away_time_ms = cli_s2s_time_ms(cptr);
      } else
        generate_msgid(away_msgid, sizeof(away_msgid));
      /* The event's one time: the tag's, else the minted msgid's (the
       * HLC's), never a clock read per send. */
      if (!away_time_ms)
        away_time_ms = history_event_time_ms(NULL);
    }

    /* Set S2S tags for downstream server relay */
    if (away_msgid[0])
      sendcmdto_set_s2s_tags(away_time_ms, away_msgid);
      sendcmdto_want_s2s_tags(1);

    if (is_away) {
      if (is_away_star && !IsIRCv3Aware(cptr))
        /* This hop is a legacy (non-aware) link, which has no concept
         * of the pre-away star -- a legacy sender's AWAY "*" is just
         * their literal away-message text, not the hidden-connection
         * token.  Relay it verbatim to every downstream peer instead
         * of running it through away_send_to_servers()'s
         * substitution, which would turn what the sender actually
         * typed into FEAT_AWAY_STAR_MSG for our own legacy peers
         * further downstream -- a transformation only valid for a
         * genuine fork-origin pre-away star. */
        sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s", away_message);
      else
        away_send_to_servers(sptr, cptr, away_message);
    } else
      away_send_to_servers(sptr, cptr, NULL);

    /* Notify local channel members with away-notify (was missing for S2S) */
    if (away_msgid[0])
      sendcmdto_set_client_msgid(away_msgid);

    /* butone=NULL: notify every local channel member of sptr.
     * Excluding sptr makes sense for the user's own /away echo on the
     * server where they typed it (handled in m_away), but never here:
     * if sptr is remote on this server, exclusion is a no-op; if sptr
     * is local (bouncer aggregation case where leaf sent :primary AWAY
     * but the actual trigger was an alias on leaf), primary's IRC client
     * needs to learn the new state — it didn't initiate this. */
    if (is_away)
      away_notify_common(sptr, NULL, away_message);
    else
      sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, NULL,
                                             CAP_AWAYNOTIFY, CAP_NONE, "");

    sendcmdto_set_client_msgid(NULL);
  }
  return 0;
}

/*
 * mu_away - unregistered client message handler (IRCv3 draft/pre-away)
 *
 * Stores away state for application after registration completes.
 * Requires draft/pre-away capability to be negotiated.
 *
 * parv[0] = sender prefix
 * parv[1] = away message (optional, "*" means away without message/hidden)
 */
int mu_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Connection *con;
  char* away_message = (parc > 1) ? parv[1] : NULL;

  assert(0 != cptr);
  assert(cptr == sptr);

  /* Require draft/pre-away capability */
  if (!HasCap(sptr, CAP_DRAFT_PREAWAY))
    return 0;  /* Silently ignore if capability not negotiated */

  con = cli_connect(sptr);

  /* The event's msgid and time, shown when registration (or a revive, or
   * the alias fast path's report) applies it: the session orders its
   * members by when they said it (W3 Task 16 fix round 2). */
  con_pre_away_msgid(con)[0] = '\0';
  if (feature_bool(FEAT_MSGID))
    generate_msgid(con_pre_away_msgid(con), sizeof(con_pre_away_msgid(con)));
  con_pre_away_ms(con) = history_event_time_ms(NULL);

  if (EmptyString(away_message)) {
    /* AWAY with no params = present (clear pre-away) */
    con_pre_away(con) = 0;
    con_pre_away_msg(con)[0] = '\0';
  } else if (away_message[0] == '*' && away_message[1] == '\0') {
    /* AWAY * = away-star (hidden connection, doesn't count as present);
     * kept as the star, substituted per viewer at emission */
    con_pre_away(con) = 2;
    ircd_strncpy(con_pre_away_msg(con), "*", AWAYLEN + 1);
  } else {
    /* AWAY :message = normal away */
    con_pre_away(con) = 1;
    ircd_strncpy(con_pre_away_msg(con), away_message, AWAYLEN + 1);
  }

  return 0;
}

