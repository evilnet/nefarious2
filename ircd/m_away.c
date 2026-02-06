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

/*
 * user_set_away - set user away state
 * returns 1 if client is away or changed away message, 0 if 
 * client is removing away status.
 * NOTE: this function may modify user and message, so they
 * must be mutable.
 */
static int user_set_away(struct User* user, char* message)
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


/*
 * m_away - generic message handler
 * - Added 14 Dec 1988 by jto.
 *
 * parv[0] = sender prefix
 * parv[1] = away message
 *
 * FEAT_AWAY_THROTTLE: Minimum seconds between AWAY changes (0 = disabled).
 * Prevents scripts that reset away message every few seconds from
 * generating excessive network traffic.
 */
int m_away(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* away_message = parv[1];
  int was_away = cli_user(sptr)->away != 0;
  int is_away;
  int is_away_star = 0;
  int throttle;

  assert(0 != cptr);
  assert(cptr == sptr);

  /* Check AWAY throttle - silently drop if too soon after last change.
   * Skip throttle in the presence aggregation path: multiple connections
   * (primary + shadows) share cli_nextaway, so a shadow's AWAY would be
   * incorrectly throttled by the primary's.  The aggregation path's
   * effective-state change detection already suppresses redundant broadcasts. */
  throttle = feature_int(FEAT_AWAY_THROTTLE);
  if (throttle > 0 && !current_shadow &&
      !(feature_bool(FEAT_PRESENCE_AGGREGATION) && bounce_enabled())) {
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
    /* Use configured fallback message for away-star */
    if (feature_str(FEAT_AWAY_STAR_MSG)) {
      away_message = (char *)feature_str(FEAT_AWAY_STAR_MSG);
    }
  }

  /* Presence aggregation path — only when bouncer is active for this account.
   * Uses the bouncer session's connection list (primary + shadows) as the
   * authoritative aggregation path.
   *
   * IMPORTANT: Do NOT call user_set_away() before this check.  Shadow commands
   * are dispatched through the primary Client (parse_client(primary, ...)), so
   * user_set_away would corrupt the primary's away state with the shadow's.
   * Instead, update per-connection state independently, compute the effective
   * state, then set cli_user->away from the effective result.
   */
  if (feature_bool(FEAT_PRESENCE_AGGREGATION) && IsAccount(sptr)
      && bounce_enabled() && bounce_has_sessions(cli_account(sptr))) {
    struct BouncerSession *bsess = bounce_get_session(sptr);
    int new_effective = 0;
    char new_msg[AWAYLEN + 1];
    int is_away = !EmptyString(away_message);

    /* Update per-connection away state */
    if (current_shadow) {
      /* Shadow sent AWAY — update shadow state only, do NOT touch primary */
      if (is_away_star) {
        current_shadow->sh_away_state = 2;
        current_shadow->sh_away_msg[0] = '\0';
      } else if (is_away) {
        current_shadow->sh_away_state = 1;
        ircd_strncpy(current_shadow->sh_away_msg, away_message, AWAYLEN + 1);
      } else {
        current_shadow->sh_away_state = 0;
        current_shadow->sh_away_msg[0] = '\0';
      }
      current_shadow->sh_since = CurrentTime;
    } else {
      /* Primary sent AWAY — update primary's per-connection state.
       * Store both the state and the message in con_pre_away/con_pre_away_msg
       * so they survive effective-state updates to cli_user->away. */
      if (is_away_star) {
        con_pre_away(cli_connect(sptr)) = 2;
        con_pre_away_msg(cli_connect(sptr))[0] = '\0';
      } else if (is_away) {
        con_pre_away(cli_connect(sptr)) = 1;
        ircd_strncpy(con_pre_away_msg(cli_connect(sptr)), away_message, AWAYLEN + 1);
      } else {
        con_pre_away(cli_connect(sptr)) = 0;
        con_pre_away_msg(cli_connect(sptr))[0] = '\0';
      }
    }

    /* Send the appropriate reply to the user */
    if (is_away || is_away_star) {
      send_reply(sptr, RPL_NOWAWAY);
    } else {
      send_reply(sptr, RPL_UNAWAY);
    }

    /* Compute effective state across all connections */
    if (bsess) {
      int prev_effective = bsess->hs_effective_away;
      bounce_compute_effective_away(bsess, &new_effective, new_msg);

      /* Update cli_user(primary)->away to reflect the effective state.
       * This ensures WHOIS, PRIVMSG auto-reply, and other lookups
       * see the aggregated state, not a single connection's state. */
      if (new_effective == 0) {
        user_set_away(cli_user(sptr), NULL);
      } else if (new_effective == 1) {
        user_set_away(cli_user(sptr), new_msg[0] ? new_msg : (char *)away_message);
      } else {
        /* All AWAY * — set away with star message for WHOIS consistency */
        user_set_away(cli_user(sptr),
                      feature_str(FEAT_AWAY_STAR_MSG)
                        ? (char *)feature_str(FEAT_AWAY_STAR_MSG)
                        : (char *)"*");
      }

      /* Only broadcast if effective state changed */
      if (new_effective != prev_effective) {
        if (new_effective == 0) {
          /* Became present — broadcast unaway */
          sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, "");
          sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, sptr,
                                                 CAP_AWAYNOTIFY, CAP_NONE, "");
        } else if (new_effective == 1) {
          /* Became away — broadcast with effective message */
          sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s",
                               new_msg[0] ? new_msg : away_message);
          sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, sptr,
                                                 CAP_AWAYNOTIFY, CAP_NONE,
                                                 ":%s",
                                                 new_msg[0] ? new_msg : away_message);
        } else {
          /* All connections AWAY * — user is effectively away.
           * Broadcast with the AWAY_STAR_MSG fallback.  "Hidden" means
           * these connections don't count as present for aggregation,
           * NOT that the user becomes invisible to the network. */
          const char *star_msg = feature_str(FEAT_AWAY_STAR_MSG);
          if (!star_msg) star_msg = "*";
          sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s", star_msg);
          sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, sptr,
                                                 CAP_AWAYNOTIFY, CAP_NONE,
                                                 ":%s", star_msg);
        }
        bsess->hs_effective_away = new_effective;
        ircd_strncpy(bsess->hs_effective_away_msg, new_msg, AWAYLEN + 1);
      }
      /* If effective state unchanged: suppress broadcast */
    }
    return 0;
  }

  /* Original non-aggregated path */
  is_away = user_set_away(cli_user(sptr), away_message);
  if (is_away)
  {
    if (!was_away)
      sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s", away_message);
    send_reply(sptr, RPL_NOWAWAY);
    sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, sptr, CAP_AWAYNOTIFY, CAP_NONE,
                                           ":%s", away_message);
  }
  else {
    sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, "");
    send_reply(sptr, RPL_UNAWAY);
    sendcmdto_common_channels_capab_butone(sptr, CMD_AWAY, sptr, CAP_AWAYNOTIFY, CAP_NONE, "");
  }
  return 0;
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
    /* Use configured fallback message for away-star */
    if (feature_str(FEAT_AWAY_STAR_MSG)) {
      away_message = (char *)feature_str(FEAT_AWAY_STAR_MSG);
    }
  }

  is_away = user_set_away(cli_user(sptr), away_message);

  if (is_away)
    sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, ":%s", away_message);
  else
    sendcmdto_serv_butone(sptr, CMD_AWAY, cptr, "");
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

  if (EmptyString(away_message)) {
    /* AWAY with no params = present (clear pre-away) */
    con_pre_away(con) = 0;
    con_pre_away_msg(con)[0] = '\0';
  } else if (away_message[0] == '*' && away_message[1] == '\0') {
    /* AWAY * = away-star (hidden connection, doesn't count as present) */
    con_pre_away(con) = 2;
    /* Use configured away-star message as fallback */
    if (feature_str(FEAT_AWAY_STAR_MSG)) {
      ircd_strncpy(con_pre_away_msg(con), feature_str(FEAT_AWAY_STAR_MSG), AWAYLEN + 1);
    } else {
      con_pre_away_msg(con)[0] = '\0';
    }
  } else {
    /* AWAY :message = normal away */
    con_pre_away(con) = 1;
    ircd_strncpy(con_pre_away_msg(con), away_message, AWAYLEN + 1);
  }

  return 0;
}

