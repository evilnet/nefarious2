/*
 * IRC - Internet Relay Chat, ircd/m_redact.c
 * Copyright (C) 2024 Nefarious Development Team
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
 */
/** @file
 * @brief Handler for REDACT command (IRCv3 draft/message-redaction).
 *
 * Specification: https://ircv3.net/specs/extensions/message-redaction
 *
 * REDACT <target> <msgid> [:<reason>]
 *
 * Allows users to delete previously sent messages. Authorization:
 * - Users can redact their own messages (time-limited)
 * - Channel operators can redact any message in their channels
 * - IRC operators can redact any message network-wide
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>


/** Propagate REDACT to channel members with the capability.
 * @param[in] sptr Source client.
 * @param[in] chptr Channel.
 * @param[in] target Target name (channel).
 * @param[in] msgid Message ID.
 * @param[in] reason Reason (may be NULL).
 */
static void propagate_redact_to_channel(struct Client *sptr, struct Channel *chptr,
                                         const char *target, const char *msgid,
                                         const char *reason)
{
  struct Membership *member;

  for (member = chptr->members; member; member = member->next_member) {
    struct Client *acptr = member->user;

    /* Only send to local clients with message-redaction capability */
    if (!MyUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_DRAFT_REDACT))
      continue;

    /* Echo to sender only if they have echo-message capability (like PRIVMSG) */
    if (acptr == sptr && !CapActive(acptr, CAP_ECHOMSG))
      continue;

    if (reason && *reason) {
      sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s :%s", target, msgid, reason);
    } else {
      sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s", target, msgid);
    }
  }
}

/** m_redact - Handle REDACT command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = target (channel or nick)
 * parv[2] = message ID
 * parv[3] = reason (optional)
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return CPTR_KILLED if client was squit, else 0.
 */
int m_redact(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *msgid;
  const char *reason = NULL;
  struct Channel *chptr = NULL;
  struct Membership *member = NULL;
  struct HistoryMessage *msg = NULL;
  time_t msg_time;
  time_t window;
  int is_chanop = 0;
  int is_oper = 0;
  int can_redact = 0;
  int rc;

  /* Check if feature is enabled */
  if (!feature_bool(FEAT_CAP_draft_message_redaction)) {
    send_fail(sptr, "REDACT", "DISABLED", NULL,
              "Message redaction is not enabled on this server");
    return 0;
  }

  /* Need at least target and msgid */
  if (parc < 3) {
    return need_more_params(sptr, "REDACT");
  }

  target = parv[1];
  msgid = parv[2];
  if (parc > 3 && parv[3])
    reason = parv[3];

  /* Validate target is a channel */
  if (!IsChannelName(target)) {
    /* For now, only channel redaction is supported */
    send_fail(sptr, "REDACT", "INVALID_TARGET", target,
              "Cannot redact from this target");
    return 0;
  }

  /* Find the channel */
  chptr = FindChannel(target);
  if (!chptr) {
    send_fail(sptr, "REDACT", "INVALID_TARGET", target,
              "No such channel");
    return 0;
  }

  /* Must be authenticated to use REDACT.
   * Self-redaction requires account match; chanop redaction requires
   * identifiable users. When X3 is integrated into the IRCd, chanop
   * redaction can additionally check the ChanServ access list. */
  if (!cli_user(sptr) || !cli_user(sptr)->account[0]) {
    send_fail(sptr, "REDACT", "ACCOUNT_REQUIRED", NULL,
              "You must be logged in to use REDACT");
    return 0;
  }

  /* Check if user is in channel */
  member = find_member_link(chptr, sptr);
  if (!member) {
    send_fail(sptr, "REDACT", "INVALID_TARGET", target,
              "You are not in that channel");
    return 0;
  }

  /* Determine authorization level */
  is_oper = IsOper(sptr);
  is_chanop = IsChanOp(member);

  /* If chathistory is available, validate ownership and check time window */
  if (history_is_available()) {
    rc = history_lookup_message(target, msgid, &msg);
    if (rc == 1) {
      /* Not found in history */
      send_fail(sptr, "REDACT", "UNKNOWN_MSGID", msgid,
                "Message not found");
      return 0;
    } else if (rc < 0) {
      /* Database error - allow redaction anyway (trust client) */
      can_redact = 1;
    } else {
      /* Found the message - get actual timestamp for window check */
      msg_time = (time_t)strtoul(msg->timestamp, NULL, 10);

      if (is_oper) {
        /* Opers: oper-specific window (0 = unlimited), can redact anything */
        window = (time_t)feature_int(FEAT_REDACT_OPER_WINDOW);
        if (window > 0 && (CurrentTime - msg_time) > window) {
          history_free_messages(msg);
          send_fail(sptr, "REDACT", "REDACT_WINDOW_EXPIRED", msgid,
                    "Redaction window has expired");
          return 0;
        }
        can_redact = 1;
      } else if (msg->account[0] && cli_user(sptr)
                 && cli_user(sptr)->account[0]
                 && ircd_strcmp(msg->account, cli_user(sptr)->account) == 0) {
        /* Authenticated owner: account match, no time window */
        can_redact = 1;
      } else {
        /* Everyone else: regular time window applies */
        window = (time_t)feature_int(FEAT_REDACT_WINDOW);
        if (window > 0 && (CurrentTime - msg_time) > window) {
          history_free_messages(msg);
          send_fail(sptr, "REDACT", "REDACT_WINDOW_EXPIRED", msgid,
                    "Redaction window has expired");
          return 0;
        }

        /* Chanops can redact others' messages */
        if (!can_redact && is_chanop && feature_bool(FEAT_REDACT_CHANOP_OTHERS)) {
          can_redact = 1;
        }
      }

      if (!can_redact) {
        history_free_messages(msg);
        send_fail(sptr, "REDACT", "REDACT_FORBIDDEN", msgid,
                  "You are not authorized to redact this message");
        return 0;
      }

      /* Delete from history database */
      history_delete_message(target, msgid);
      history_free_messages(msg);
    }
  } else {
    /* No local history — try federated lookup via CH Q X.
     * Storage servers will return the message metadata so we can
     * validate authorization before propagating the REDACT. */
    if (start_redact_fed_query(sptr, chptr, target, msgid, reason,
                               is_chanop, is_oper) == 0) {
      /* Federation query started — completion callback handles the rest */
      return 0;
    }
    /* Federation not available or failed to start */
    send_fail(sptr, "REDACT", "UNKNOWN_MSGID", msgid,
              "Message history is not available on this server");
    return 0;
  }

  /* Propagate to channel members with capability */
  propagate_redact_to_channel(sptr, chptr, target, msgid, reason);

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_REDACT, cptr, "%s %s :%s",
                        target, msgid, reason ? reason : "");

  return 0;
}

/** ms_redact - Handle REDACT command from server.
 *
 * parv[0] = sender prefix (numeric)
 * parv[1] = target (channel or nick)
 * parv[2] = message ID
 * parv[3] = reason (optional)
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return CPTR_KILLED if client was squit, else 0.
 */
int ms_redact(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *target;
  const char *msgid;
  const char *reason = NULL;
  struct Channel *chptr = NULL;

  /* Need at least target and msgid */
  if (parc < 3)
    return 0;

  target = parv[1];
  msgid = parv[2];
  if (parc > 3 && parv[3])
    reason = parv[3];

  /* For channels, propagate to members and other servers */
  if (IsChannelName(target)) {
    chptr = FindChannel(target);
    if (chptr) {
      /* Delete from local history if available */
      if (history_is_available()) {
        history_delete_message(target, msgid);
      }

      /* Propagate to channel members with capability */
      propagate_redact_to_channel(sptr, chptr, target, msgid, reason);
    }
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_REDACT, cptr, "%s %s :%s",
                        target, msgid, reason ? reason : "");

  return 0;
}
