/*
 * IRC - Internet Relay Chat, ircd/m_chathistory.c
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
 * @brief Handler for CHATHISTORY command (IRCv3 draft/chathistory).
 *
 * Specification: https://ircv3.net/specs/extensions/chathistory
 *
 * CHATHISTORY subcommands:
 *   LATEST <target> <reference|*> <limit>
 *   BEFORE <target> <reference> <limit>
 *   AFTER <target> <reference> <limit>
 *   AROUND <target> <reference> <limit>
 *   BETWEEN <target> <reference> <reference> <limit>
 *   TARGETS <timestamp> <timestamp> <limit>
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
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

/** Maximum batch ID length */
#define BATCH_ID_LEN 16

/** Message type names for formatting */
static const char *msg_type_cmd[] = {
  "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
  "KICK", "MODE", "TOPIC", "TAGMSG"
};

/** Parse a message reference (timestamp= or msgid=).
 * @param[in] ref Reference string.
 * @param[out] ref_type Type of reference.
 * @param[out] value Extracted value (without prefix).
 * @return 0 on success, -1 on error.
 */
static int parse_reference(const char *ref, enum HistoryRefType *ref_type, const char **value)
{
  if (!ref || !*ref)
    return -1;

  if (*ref == '*') {
    *ref_type = HISTORY_REF_NONE;
    *value = ref;
    return 0;
  }

  if (strncmp(ref, "timestamp=", 10) == 0) {
    *ref_type = HISTORY_REF_TIMESTAMP;
    *value = ref + 10;
    return 0;
  }

  if (strncmp(ref, "msgid=", 6) == 0) {
    *ref_type = HISTORY_REF_MSGID;
    *value = ref + 6;
    return 0;
  }

  return -1;
}

/** Generate a unique batch ID for chathistory response.
 * @param[out] buf Buffer for batch ID.
 * @param[in] buflen Size of buffer.
 * @param[in] sptr Client receiving the batch.
 */
static void generate_batch_id(char *buf, size_t buflen, struct Client *sptr)
{
  static unsigned long batch_counter = 0;
  ircd_snprintf(0, buf, buflen, "hist%lu%s", ++batch_counter, cli_yxx(sptr));
}

/** Send history messages as a batch response.
 * @param[in] sptr Client to send to.
 * @param[in] target Target name for batch.
 * @param[in] messages List of messages to send.
 * @param[in] count Number of messages.
 */
static void send_history_batch(struct Client *sptr, const char *target,
                                struct HistoryMessage *messages, int count)
{
  struct HistoryMessage *msg;
  char batchid[BATCH_ID_LEN];
  const char *cmd;

  if (count == 0)
    messages = NULL;

  /* Generate batch ID */
  generate_batch_id(batchid, sizeof(batchid), sptr);

  /* Start batch */
  if (CapActive(sptr, CAP_BATCH)) {
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s chathistory %s",
                  batchid, target);
  }

  /* Send each message */
  for (msg = messages; msg; msg = msg->next) {
    cmd = (msg->type <= HISTORY_TAGMSG) ? msg_type_cmd[msg->type] : "PRIVMSG";

    if (CapActive(sptr, CAP_BATCH)) {
      /* With batch */
      if (msg->account[0]) {
        sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s;account=%s :%s %s %s :%s",
                      batchid, msg->timestamp, msg->msgid, msg->account,
                      msg->sender, cmd, target, msg->content);
      } else {
        sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s %s %s :%s",
                      batchid, msg->timestamp, msg->msgid,
                      msg->sender, cmd, target, msg->content);
      }
    } else {
      /* Without batch (shouldn't happen if client has chathistory, but fallback) */
      if (msg->account[0]) {
        sendrawto_one(sptr, "@time=%s;msgid=%s;account=%s :%s %s %s :%s",
                      msg->timestamp, msg->msgid, msg->account,
                      msg->sender, cmd, target, msg->content);
      } else {
        sendrawto_one(sptr, "@time=%s;msgid=%s :%s %s %s :%s",
                      msg->timestamp, msg->msgid,
                      msg->sender, cmd, target, msg->content);
      }
    }
  }

  /* End batch */
  if (CapActive(sptr, CAP_BATCH)) {
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
  }
}

/** Check if client can access history for a target.
 * @param[in] sptr Client requesting history.
 * @param[in] target Target name.
 * @return 0 if allowed, -1 if not.
 */
static int check_history_access(struct Client *sptr, const char *target)
{
  struct Channel *chptr;
  struct Membership *member;

  if (IsChannelName(target)) {
    chptr = FindChannel(target);
    if (!chptr)
      return -1;

    /* Check if user is on channel */
    member = find_member_link(chptr, sptr);
    if (!member) {
      /* User not on channel - could check for invite, etc. */
      return -1;
    }
    return 0;
  } else {
    /* Private message history - target should be nick:nick format */
    /* For now, just check that user is one of the nicks */
    const char *colon = strchr(target, ':');
    if (!colon)
      return -1;

    /* Extract nicks and verify sender is one of them */
    char nick1[NICKLEN + 1], nick2[NICKLEN + 1];
    size_t len1 = colon - target;
    if (len1 > NICKLEN)
      return -1;

    memcpy(nick1, target, len1);
    nick1[len1] = '\0';
    ircd_strncpy(nick2, colon + 1, NICKLEN);

    if (ircd_strcmp(cli_name(sptr), nick1) != 0 &&
        ircd_strcmp(cli_name(sptr), nick2) != 0)
      return -1;

    return 0;
  }
}

/** Handle CHATHISTORY LATEST subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] target Target channel or nick.
 * @param[in] ref_str Reference string.
 * @param[in] limit_str Limit string.
 * @return 0 on success.
 */
static int chathistory_latest(struct Client *sptr, const char *target,
                               const char *ref_str, const char *limit_str)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;

  /* Parse reference */
  if (parse_reference(ref_str, &ref_type, &ref_value) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "LATEST",
              "Invalid message reference");
    return 0;
  }

  /* Parse and validate limit */
  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  /* Check access */
  if (check_history_access(sptr, target) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  /* Query history */
  count = history_query_latest(target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  /* Send response */
  send_history_batch(sptr, target, messages, count);

  /* Free messages */
  history_free_messages(messages);

  return 0;
}

/** Handle CHATHISTORY BEFORE subcommand. */
static int chathistory_before(struct Client *sptr, const char *target,
                               const char *ref_str, const char *limit_str)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;

  if (parse_reference(ref_str, &ref_type, &ref_value) != 0 ||
      ref_type == HISTORY_REF_NONE) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BEFORE",
              "Invalid message reference");
    return 0;
  }

  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  if (check_history_access(sptr, target) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_before(target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  send_history_batch(sptr, target, messages, count);
  history_free_messages(messages);

  return 0;
}

/** Handle CHATHISTORY AFTER subcommand. */
static int chathistory_after(struct Client *sptr, const char *target,
                              const char *ref_str, const char *limit_str)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;

  if (parse_reference(ref_str, &ref_type, &ref_value) != 0 ||
      ref_type == HISTORY_REF_NONE) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "AFTER",
              "Invalid message reference");
    return 0;
  }

  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  if (check_history_access(sptr, target) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_after(target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  send_history_batch(sptr, target, messages, count);
  history_free_messages(messages);

  return 0;
}

/** Handle CHATHISTORY AROUND subcommand. */
static int chathistory_around(struct Client *sptr, const char *target,
                               const char *ref_str, const char *limit_str)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;

  if (parse_reference(ref_str, &ref_type, &ref_value) != 0 ||
      ref_type == HISTORY_REF_NONE) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "AROUND",
              "Invalid message reference");
    return 0;
  }

  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  if (check_history_access(sptr, target) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_around(target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  send_history_batch(sptr, target, messages, count);
  history_free_messages(messages);

  return 0;
}

/** Handle CHATHISTORY BETWEEN subcommand. */
static int chathistory_between(struct Client *sptr, const char *target,
                                const char *ref1_str, const char *ref2_str,
                                const char *limit_str)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type1, ref_type2;
  const char *ref_value1, *ref_value2;
  int limit, count, max_limit;

  if (parse_reference(ref1_str, &ref_type1, &ref_value1) != 0 ||
      ref_type1 == HISTORY_REF_NONE) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BETWEEN",
              "Invalid first message reference");
    return 0;
  }

  if (parse_reference(ref2_str, &ref_type2, &ref_value2) != 0 ||
      ref_type2 == HISTORY_REF_NONE) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BETWEEN",
              "Invalid second message reference");
    return 0;
  }

  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  if (check_history_access(sptr, target) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_between(target, ref_type1, ref_value1,
                                 ref_type2, ref_value2, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  send_history_batch(sptr, target, messages, count);
  history_free_messages(messages);

  return 0;
}

/** Handle CHATHISTORY TARGETS subcommand. */
static int chathistory_targets(struct Client *sptr, const char *ref1_str,
                                const char *ref2_str, const char *limit_str)
{
  struct HistoryTarget *targets = NULL;
  struct HistoryTarget *tgt;
  enum HistoryRefType ref_type1, ref_type2;
  const char *ts1, *ts2;
  char batchid[BATCH_ID_LEN];
  int limit, count, max_limit;

  /* TARGETS uses timestamp references only */
  if (parse_reference(ref1_str, &ref_type1, &ts1) != 0 ||
      ref_type1 != HISTORY_REF_TIMESTAMP) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "TARGETS",
              "TARGETS requires timestamp references");
    return 0;
  }

  if (parse_reference(ref2_str, &ref_type2, &ts2) != 0 ||
      ref_type2 != HISTORY_REF_TIMESTAMP) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "TARGETS",
              "TARGETS requires timestamp references");
    return 0;
  }

  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  count = history_query_targets(ts1, ts2, limit, &targets);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", "*",
              "Failed to retrieve targets");
    return 0;
  }

  /* Send targets in a batch */
  generate_batch_id(batchid, sizeof(batchid), sptr);

  if (CapActive(sptr, CAP_BATCH)) {
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s draft/chathistory-targets",
                  batchid);
  }

  for (tgt = targets; tgt; tgt = tgt->next) {
    /* Check access for each target before including */
    if (check_history_access(sptr, tgt->target) == 0) {
      if (CapActive(sptr, CAP_BATCH)) {
        sendrawto_one(sptr, "@batch=%s :%s!%s@%s CHATHISTORY TARGETS %s %s",
                      batchid, cli_name(&me), "chathistory", cli_name(&me),
                      tgt->target, tgt->last_timestamp);
      } else {
        sendrawto_one(sptr, ":%s!%s@%s CHATHISTORY TARGETS %s %s",
                      cli_name(&me), "chathistory", cli_name(&me),
                      tgt->target, tgt->last_timestamp);
      }
    }
  }

  if (CapActive(sptr, CAP_BATCH)) {
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
  }

  history_free_targets(targets);

  return 0;
}

/** Handle CHATHISTORY command from a local client.
 * @param[in] cptr Connection that sent the command.
 * @param[in] sptr Client that sent the command.
 * @param[in] parc Number of parameters.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
int m_chathistory(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  assert(cptr == sptr);

  /* Check if chathistory is enabled */
  if (!feature_bool(FEAT_CAP_draft_chathistory)) {
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "CHATHISTORY");
  }

  /* Require the client to have negotiated draft/chathistory capability */
  if (!CapActive(sptr, CAP_DRAFT_CHATHISTORY)) {
    send_fail(sptr, "CHATHISTORY", "NEED_REGISTRATION", NULL,
              "You must negotiate draft/chathistory capability first");
    return 0;
  }

  /* Check if history backend is available */
  if (!history_is_available()) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", NULL,
              "History service unavailable");
    return 0;
  }

  if (parc < 2) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", NULL,
              "Missing subcommand");
    return 0;
  }

  subcmd = parv[1];

  if (ircd_strcmp(subcmd, "LATEST") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "LATEST",
                "Usage: CHATHISTORY LATEST <target> <reference|*> <limit>");
      return 0;
    }
    return chathistory_latest(sptr, parv[2], parv[3], parv[4]);
  }
  else if (ircd_strcmp(subcmd, "BEFORE") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BEFORE",
                "Usage: CHATHISTORY BEFORE <target> <reference> <limit>");
      return 0;
    }
    return chathistory_before(sptr, parv[2], parv[3], parv[4]);
  }
  else if (ircd_strcmp(subcmd, "AFTER") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "AFTER",
                "Usage: CHATHISTORY AFTER <target> <reference> <limit>");
      return 0;
    }
    return chathistory_after(sptr, parv[2], parv[3], parv[4]);
  }
  else if (ircd_strcmp(subcmd, "AROUND") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "AROUND",
                "Usage: CHATHISTORY AROUND <target> <reference> <limit>");
      return 0;
    }
    return chathistory_around(sptr, parv[2], parv[3], parv[4]);
  }
  else if (ircd_strcmp(subcmd, "BETWEEN") == 0) {
    if (parc < 6) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BETWEEN",
                "Usage: CHATHISTORY BETWEEN <target> <ref1> <ref2> <limit>");
      return 0;
    }
    return chathistory_between(sptr, parv[2], parv[3], parv[4], parv[5]);
  }
  else if (ircd_strcmp(subcmd, "TARGETS") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "TARGETS",
                "Usage: CHATHISTORY TARGETS <timestamp1> <timestamp2> <limit>");
      return 0;
    }
    return chathistory_targets(sptr, parv[2], parv[3], parv[4]);
  }
  else {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", subcmd,
              "Unknown subcommand");
    return 0;
  }
}
