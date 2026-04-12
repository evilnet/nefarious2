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
#include "handlers.h"
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
#include <sys/time.h>
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

    /* Sender echo: only send back to sender if they have echo-message */
    if (acptr == sptr) {
      if (!CapOwnHas(sptr, CAP_ECHOMSG))
        continue;
    }

    /* Set stc_withcap so send_buffer routes per-connection */
    cap_route_ctx.stc_active = 1;
    cap_route_ctx.stc_withcap = CAP_DRAFT_REDACT;
    cap_route_ctx.stc_skipcap = CAP_NONE;

    if (reason && *reason) {
      sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s :%s", target, msgid, reason);
    } else {
      sendcmdto_one(sptr, CMD_REDACT, acptr, "%s %s", target, msgid);
    }

    cap_route_ctx.stc_active = 0;
    cap_route_ctx.stc_withcap = CAP_NONE;
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

  if (!cli_user(sptr)) {
    send_fail(sptr, "REDACT", "REDACT_FORBIDDEN", NULL,
              "You must be fully registered to use REDACT");
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
    /* Build combined context for FAIL responses: "target msgid" */
    char fail_ctx[BUFSIZE];
    ircd_snprintf(0, fail_ctx, sizeof(fail_ctx), "%s %s", target, msgid);

    rc = history_lookup_message(target, msgid, &msg);
    if (rc == 1) {
      /* Not found in history */
      send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fail_ctx,
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
          send_fail(sptr, "REDACT", "REDACT_WINDOW_EXPIRED", fail_ctx,
                    "Redaction window has expired");
          return 0;
        }
        can_redact = 1;
      } else if (msg->account[0] && cli_user(sptr)
                 && cli_user(sptr)->account[0]
                 && ircd_strcmp(msg->account, cli_user(sptr)->account) == 0) {
        /* Authenticated owner: account match, no time window */
        can_redact = 1;
      } else if (!msg->account[0] && !cli_user(sptr)->account[0]) {
        /* Unauthenticated sender mask fallback: both message and user must
         * be unauthenticated, and nick!user@host must match exactly.
         * This only works within the same session (nick changes break it). */
        char current_mask[HISTORY_SENDER_LEN];
        ircd_snprintf(0, current_mask, sizeof(current_mask), "%s!%s@%s",
                      cli_name(sptr), cli_user(sptr)->username,
                      cli_user(sptr)->host);
        if (ircd_strcmp(current_mask, msg->sender) == 0)
          can_redact = 1;
      }
      if (!can_redact) {
        /* Everyone else: regular time window applies */
        window = (time_t)feature_int(FEAT_REDACT_WINDOW);
        if (window > 0 && (CurrentTime - msg_time) > window) {
          history_free_messages(msg);
          send_fail(sptr, "REDACT", "REDACT_WINDOW_EXPIRED", fail_ctx,
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
        send_fail(sptr, "REDACT", "REDACT_FORBIDDEN", fail_ctx,
                  "You are not authorized to redact this message");
        return 0;
      }

      /* Redact message: strip content but keep entry for context */
      history_redact_message(target, msgid);
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
    {
      char fail_ctx[BUFSIZE];
      ircd_snprintf(0, fail_ctx, sizeof(fail_ctx), "%s %s", target, msgid);
      send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fail_ctx,
                "Message history is not available on this server");
    }
    return 0;
  }

  /* Generate a single msgid for the REDACT event — used for history storage,
   * live channel broadcast, and S2S relay. */
  {
    char redact_msgid[HISTORY_MSGID_LEN];
    struct timeval tv;
    uint64_t time_ms;

    generate_msgid(redact_msgid, sizeof(redact_msgid));
    gettimeofday(&tv, NULL);
    time_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    /* Store REDACT event in history */
    if (history_is_available()) {
      char timestamp[32];
      char sender[HISTORY_SENDER_LEN];
      char redact_content[512];

      ircd_snprintf(0, timestamp, sizeof(timestamp), "%lu.%03lu",
                    (unsigned long)tv.tv_sec,
                    (unsigned long)(tv.tv_usec / 1000));
      ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                    cli_name(sptr), cli_user(sptr)->username,
                    cli_user(sptr)->host);

      if (reason && reason[0])
        ircd_snprintf(0, redact_content, sizeof(redact_content),
                      "%s :%s", msgid, reason);
      else
        ircd_snprintf(0, redact_content, sizeof(redact_content),
                      "%s", msgid);

      history_store_message(redact_msgid, timestamp, target, sender,
                            cli_user(sptr)->account[0] ? cli_user(sptr)->account : "",
                            HISTORY_REDACT, redact_content, NULL);

      /* Write-forward to STORE servers if we're non-STORE */
      if (chptr)
        forward_history_write(chptr, sptr, redact_msgid, timestamp,
                              HISTORY_REDACT, redact_content);
    }

    /* Set msgid for live channel broadcast */
    if (feature_bool(FEAT_MSGID))
      sendcmdto_set_client_msgid(redact_msgid);

    /* Propagate to channel members with capability */
    propagate_redact_to_channel(sptr, chptr, target, msgid, reason);

    /* Set S2S tags for server relay */
    sendcmdto_set_s2s_tags(time_ms, redact_msgid);
    sendcmdto_want_s2s_tags(1);

    /* Propagate to other servers */
    sendcmdto_serv_butone(sptr, CMD_REDACT, cptr, "%s %s :%s",
                          target, msgid, reason ? reason : "");
  }

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
      /* Redact message: strip content but keep entry for context */
      if (history_is_available()) {
        history_redact_message(target, msgid);
      }

      /* Use incoming S2S msgid for the REDACT event, or generate new */
      {
        char redact_msgid[HISTORY_MSGID_LEN];
        struct timeval tv;
        uint64_t time_ms;

        if (cli_s2s_msgid(cptr)[0])
          ircd_strncpy(redact_msgid, cli_s2s_msgid(cptr), sizeof(redact_msgid));
        else
          generate_msgid(redact_msgid, sizeof(redact_msgid));

        if (cli_s2s_time_ms(cptr))
          time_ms = cli_s2s_time_ms(cptr);
        else {
          gettimeofday(&tv, NULL);
          time_ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
        }

        /* Store REDACT event in history */
        if (history_is_available()) {
          char timestamp[32];
          char sender[HISTORY_SENDER_LEN];
          char redact_content[512];

          ircd_snprintf(0, timestamp, sizeof(timestamp), "%llu.%03llu",
                        (unsigned long long)(time_ms / 1000),
                        (unsigned long long)(time_ms % 1000));

          if (cli_user(sptr))
            ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                          cli_name(sptr), cli_user(sptr)->username,
                          cli_user(sptr)->host);
          else
            ircd_strncpy(sender, cli_name(sptr), sizeof(sender));

          if (reason && reason[0])
            ircd_snprintf(0, redact_content, sizeof(redact_content),
                          "%s :%s", msgid, reason);
          else
            ircd_snprintf(0, redact_content, sizeof(redact_content),
                          "%s", msgid);

          history_store_message(redact_msgid, timestamp, target, sender,
                                (cli_user(sptr) && cli_user(sptr)->account[0])
                                  ? cli_user(sptr)->account : "",
                                HISTORY_REDACT, redact_content, NULL);
        }

        /* Set msgid for live channel broadcast */
        if (feature_bool(FEAT_MSGID))
          sendcmdto_set_client_msgid(redact_msgid);

        /* Propagate to channel members with capability */
        propagate_redact_to_channel(sptr, chptr, target, msgid, reason);

        /* Set S2S tags for server relay */
        sendcmdto_set_s2s_tags(time_ms, redact_msgid);
        sendcmdto_want_s2s_tags(1);
      }
    }
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_REDACT, cptr, "%s %s :%s",
                        target, msgid, reason ? reason : "");

  return 0;
}
