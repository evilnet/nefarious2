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
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
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

/** Convert client subcmd to efficient S2S single-char format.
 * L=LATEST, B=BEFORE, A=AFTER, R=AROUND, W=BETWEEN, T=TARGETS
 */
static char subcmd_to_s2s(const char *subcmd)
{
  if (ircd_strcmp(subcmd, "LATEST") == 0)  return 'L';
  if (ircd_strcmp(subcmd, "BEFORE") == 0)  return 'B';
  if (ircd_strcmp(subcmd, "AFTER") == 0)   return 'A';
  if (ircd_strcmp(subcmd, "AROUND") == 0)  return 'R';
  if (ircd_strcmp(subcmd, "BETWEEN") == 0) return 'W';
  if (ircd_strcmp(subcmd, "TARGETS") == 0) return 'T';
  return '?';
}

/** Convert S2S single-char subcmd to full name for history queries. */
static const char *s2s_to_subcmd(char c)
{
  switch (c) {
    case 'L': return "LATEST";
    case 'B': return "BEFORE";
    case 'A': return "AFTER";
    case 'R': return "AROUND";
    case 'W': return "BETWEEN";
    case 'T': return "TARGETS";
    default:  return NULL;
  }
}

/** Convert client reference to efficient S2S format.
 * Input:  "timestamp=1234.567" or "msgid=abc" or "*"
 * Output: "T1234.567" or "Mabc" or "*"
 * @param[in] ref Client reference string.
 * @param[out] buf Buffer for S2S format.
 * @param[in] buflen Buffer size.
 * @return Pointer to buf, or NULL on error.
 */
static char *ref_to_s2s(const char *ref, char *buf, size_t buflen)
{
  if (!ref || !buf || buflen < 2)
    return NULL;

  if (*ref == '*') {
    buf[0] = '*';
    buf[1] = '\0';
    return buf;
  }

  if (strncmp(ref, "timestamp=", 10) == 0) {
    ircd_snprintf(0, buf, buflen, "T%s", ref + 10);
    return buf;
  }

  if (strncmp(ref, "msgid=", 6) == 0) {
    ircd_snprintf(0, buf, buflen, "M%s", ref + 6);
    return buf;
  }

  return NULL;
}

/** Parse S2S reference format.
 * Input:  "T1234.567" or "Mabc" or "*"
 * @param[in] ref S2S reference string.
 * @param[out] ref_type Type of reference.
 * @param[out] value Pointer to value (after prefix char).
 * @return 0 on success, -1 on error.
 */
static int parse_s2s_reference(const char *ref, enum HistoryRefType *ref_type, const char **value)
{
  if (!ref || !*ref)
    return -1;

  if (*ref == '*') {
    *ref_type = HISTORY_REF_NONE;
    *value = ref;
    return 0;
  }

  if (*ref == 'T') {
    *ref_type = HISTORY_REF_TIMESTAMP;
    *value = ref + 1;
    return 0;
  }

  if (*ref == 'M') {
    *ref_type = HISTORY_REF_MSGID;
    *value = ref + 1;
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

/** Check if message type should be sent to client.
 * Without draft/event-playback, only PRIVMSG and NOTICE are sent.
 * @param[in] sptr Client to check.
 * @param[in] type Message type.
 * @return 1 if should send, 0 if should skip.
 */
static int should_send_message_type(struct Client *sptr, enum HistoryMessageType type)
{
  /* PRIVMSG and NOTICE are always sent */
  if (type == HISTORY_PRIVMSG || type == HISTORY_NOTICE)
    return 1;

  /* Other events require draft/event-playback capability */
  return CapActive(sptr, CAP_DRAFT_EVENTPLAYBACK);
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
  char iso_time[32];
  const char *cmd;
  const char *time_str;

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
    /* Filter events based on event-playback capability */
    if (!should_send_message_type(sptr, msg->type))
      continue;

    cmd = (msg->type <= HISTORY_TAGMSG) ? msg_type_cmd[msg->type] : "PRIVMSG";

    /* Convert Unix timestamp to ISO 8601 for @time= tag (IRCv3 requires ISO) */
    if (history_unix_to_iso(msg->timestamp, iso_time, sizeof(iso_time)) == 0)
      time_str = iso_time;
    else
      time_str = msg->timestamp;  /* Fallback if conversion fails */

    if (CapActive(sptr, CAP_BATCH)) {
      /* With batch */
      if (msg->account[0]) {
        sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s;account=%s :%s %s %s :%s",
                      batchid, time_str, msg->msgid, msg->account,
                      msg->sender, cmd, target, msg->content);
      } else {
        sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s %s %s :%s",
                      batchid, time_str, msg->msgid,
                      msg->sender, cmd, target, msg->content);
      }
    } else {
      /* Without batch (shouldn't happen if client has chathistory, but fallback) */
      if (msg->account[0]) {
        sendrawto_one(sptr, "@time=%s;msgid=%s;account=%s :%s %s %s :%s",
                      time_str, msg->msgid, msg->account,
                      msg->sender, cmd, target, msg->content);
      } else {
        sendrawto_one(sptr, "@time=%s;msgid=%s :%s %s %s :%s",
                      time_str, msg->msgid,
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

/* Forward declaration for federation query */
static struct FedRequest *start_fed_query(struct Client *sptr, const char *target,
                                           const char *subcmd, const char *ref,
                                           int limit,
                                           struct HistoryMessage *local_msgs,
                                           int local_count);

/** Check if we should trigger federation query.
 * Returns 1 if we should federate, 0 otherwise.
 */
static int should_federate(const char *target, int local_count, int limit)
{
  /* Only federate for channels, not PMs */
  if (!IsChannelName(target))
    return 0;

  /* Check if federation is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION))
    return 0;

  /* If we got fewer messages than requested, try federation */
  if (local_count < limit)
    return 1;

  return 0;
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

  /* Query local history */
  count = history_query_latest(target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  if (should_federate(target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, target, "LATEST",
                                              ref_str, limit, messages, count);
    if (req) {
      /* Federation started - response will be sent when complete */
      /* Note: messages ownership transferred to req */
      return 0;
    }
    /* Federation failed to start, fall through to local-only response */
  }

  /* Send local-only response */
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

  /* Check if we should try federation */
  if (should_federate(target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, target, "BEFORE",
                                              ref_str, limit, messages, count);
    if (req)
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

  /* Check if we should try federation */
  if (should_federate(target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, target, "AFTER",
                                              ref_str, limit, messages, count);
    if (req)
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

  /* Check if we should try federation */
  if (should_federate(target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, target, "AROUND",
                                              ref_str, limit, messages, count);
    if (req)
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
  char iso_time[32];
  const char *time_str;
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
      /* Convert Unix timestamp to ISO 8601 for client display */
      if (history_unix_to_iso(tgt->last_timestamp, iso_time, sizeof(iso_time)) == 0)
        time_str = iso_time;
      else
        time_str = tgt->last_timestamp;  /* Fallback if conversion fails */

      if (CapActive(sptr, CAP_BATCH)) {
        sendrawto_one(sptr, "@batch=%s :%s!%s@%s CHATHISTORY TARGETS %s timestamp=%s",
                      batchid, cli_name(&me), "chathistory", cli_name(&me),
                      tgt->target, time_str);
      } else {
        sendrawto_one(sptr, ":%s!%s@%s CHATHISTORY TARGETS %s timestamp=%s",
                      cli_name(&me), "chathistory", cli_name(&me),
                      tgt->target, time_str);
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

/*
 * S2S Chathistory Federation
 *
 * Protocol:
 *   [SERVER] CH Q <target> <subcmd> <ref> <limit> <reqid>   - Query
 *   [SERVER] CH R <reqid> <msgid> <ts> <type> <sender> <account> :<content>  - Response
 *   [SERVER] CH E <reqid> <count>   - End response
 */

/** Maximum pending federation requests */
#define MAX_FED_REQUESTS 64

/** Maximum messages collected per request */
#define MAX_FED_MESSAGES 500

/** Structure for a pending federation request */
struct FedRequest {
  char reqid[32];                     /**< Request ID */
  char target[CHANNELLEN + 1];        /**< Target channel */
  char client_yxx[6];                 /**< Client numeric (YXX) for safe lookup */
  struct HistoryMessage *local_msgs;  /**< Local LMDB results */
  struct HistoryMessage *fed_msgs;    /**< Federated results */
  int local_count;                    /**< Number of local messages */
  int fed_count;                      /**< Number of federated messages */
  int servers_pending;                /**< Servers we're waiting for */
  time_t start_time;                  /**< When request started */
  int limit;                          /**< Original limit requested */
  struct Timer timer;                 /**< Timeout timer (embedded) */
  int timer_active;                   /**< Whether timer is active */
};

/** Global array of pending federation requests */
static struct FedRequest *fed_requests[MAX_FED_REQUESTS];

/** Counter for generating unique request IDs */
static unsigned long fed_reqid_counter = 0;

/** Find a federation request by ID */
static struct FedRequest *find_fed_request(const char *reqid)
{
  int i;
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (fed_requests[i] && strcmp(fed_requests[i]->reqid, reqid) == 0)
      return fed_requests[i];
  }
  return NULL;
}

/** Free a federation request */
static void free_fed_request(struct FedRequest *req)
{
  int i;

  if (!req)
    return;

  /* Free message lists */
  if (req->local_msgs)
    history_free_messages(req->local_msgs);
  if (req->fed_msgs)
    history_free_messages(req->fed_msgs);

  /* Remove timer if active */
  if (req->timer_active)
    timer_del(&req->timer);

  /* Remove from array */
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (fed_requests[i] == req) {
      fed_requests[i] = NULL;
      break;
    }
  }

  MyFree(req);
}

/** Add a message to the federated results list */
static void add_fed_message(struct FedRequest *req, const char *msgid,
                            const char *timestamp, int type,
                            const char *sender, const char *account,
                            const char *content)
{
  struct HistoryMessage *msg, *tail;

  if (!req || req->fed_count >= MAX_FED_MESSAGES)
    return;

  msg = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
  ircd_strncpy(msg->msgid, msgid, sizeof(msg->msgid) - 1);
  ircd_strncpy(msg->timestamp, timestamp, sizeof(msg->timestamp) - 1);
  ircd_strncpy(msg->target, req->target, sizeof(msg->target) - 1);
  ircd_strncpy(msg->sender, sender, sizeof(msg->sender) - 1);
  if (account && strcmp(account, "*") != 0)
    ircd_strncpy(msg->account, account, sizeof(msg->account) - 1);
  msg->type = type;
  if (content)
    ircd_strncpy(msg->content, content, sizeof(msg->content) - 1);
  msg->next = NULL;

  /* Append to list */
  if (!req->fed_msgs) {
    req->fed_msgs = msg;
  } else {
    for (tail = req->fed_msgs; tail->next; tail = tail->next)
      ;
    tail->next = msg;
  }
  req->fed_count++;
}

/** Check if message already exists in a list (by msgid) */
static int message_exists(struct HistoryMessage *list, const char *msgid)
{
  struct HistoryMessage *m;
  for (m = list; m; m = m->next) {
    if (strcmp(m->msgid, msgid) == 0)
      return 1;
  }
  return 0;
}

/** Merge and deduplicate two message lists, sort by timestamp */
static struct HistoryMessage *merge_messages(struct HistoryMessage *list1,
                                              struct HistoryMessage *list2,
                                              int limit)
{
  struct HistoryMessage *result = NULL, *tail = NULL;
  struct HistoryMessage *m, *next, *best;
  struct HistoryMessage *p1 = list1, *p2 = list2;
  int count = 0;

  /* Simple merge: collect all unique messages, sort by timestamp */
  /* First, add all from list1 */
  for (m = list1; m && count < limit; m = m->next) {
    struct HistoryMessage *copy = (struct HistoryMessage *)MyCalloc(1, sizeof(*copy));
    memcpy(copy, m, sizeof(*copy));
    copy->next = NULL;
    if (!result) {
      result = tail = copy;
    } else {
      tail->next = copy;
      tail = copy;
    }
    count++;
  }

  /* Add unique messages from list2 */
  for (m = list2; m && count < limit; m = m->next) {
    if (!message_exists(result, m->msgid)) {
      struct HistoryMessage *copy = (struct HistoryMessage *)MyCalloc(1, sizeof(*copy));
      memcpy(copy, m, sizeof(*copy));
      copy->next = NULL;
      if (!result) {
        result = tail = copy;
      } else {
        tail->next = copy;
        tail = copy;
      }
      count++;
    }
  }

  /* Simple bubble sort by timestamp (descending for LATEST) */
  /* For small lists this is fine; for large lists we'd want better sorting */
  if (result && result->next) {
    int swapped;
    do {
      swapped = 0;
      struct HistoryMessage **pp = &result;
      while (*pp && (*pp)->next) {
        struct HistoryMessage *a = *pp;
        struct HistoryMessage *b = a->next;
        /* Sort descending by timestamp (newest first) */
        if (strcmp(a->timestamp, b->timestamp) < 0) {
          a->next = b->next;
          b->next = a;
          *pp = b;
          swapped = 1;
        }
        pp = &((*pp)->next);
      }
    } while (swapped);
  }

  return result;
}

/** Complete a federation request and send results to client */
static void complete_fed_request(struct FedRequest *req)
{
  struct HistoryMessage *merged;
  struct Client *client;
  int total;

  if (!req)
    return;

  /* Look up the client by numeric - they may have disconnected */
  client = findNUser(req->client_yxx);
  if (!client) {
    /* Client disconnected, just clean up */
    free_fed_request(req);
    return;
  }

  /* Merge local and federated results */
  merged = merge_messages(req->local_msgs, req->fed_msgs, req->limit);

  /* Count total */
  total = 0;
  for (struct HistoryMessage *m = merged; m; m = m->next)
    total++;

  /* Send to client */
  send_history_batch(client, req->target, merged, total);

  /* Free merged list */
  history_free_messages(merged);

  /* Clean up request */
  free_fed_request(req);
}

/** Timer callback for federation timeout */
static void fed_timeout_callback(struct Event *ev)
{
  struct FedRequest *req;

  if (ev_type(ev) != ET_EXPIRE)
    return;

  req = (struct FedRequest *)t_data(ev_timer(ev));
  if (!req)
    return;

  req->timer_active = 0;  /* Timer has expired */

  /* Complete with whatever we have */
  complete_fed_request(req);
}

/** Count connected servers */
static int count_servers(void)
{
  int count = 0;
  struct DLink *lp;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next)
    count++;

  return count;
}

/** Send a federation query to all servers
 * @param[in] sptr Client requesting history
 * @param[in] target Channel name
 * @param[in] subcmd Subcommand (LATEST, BEFORE, etc.)
 * @param[in] ref Reference string
 * @param[in] limit Maximum messages
 * @param[in] local_msgs Already-retrieved local messages
 * @param[in] local_count Number of local messages
 * @return Request ID or NULL on failure
 */
static struct FedRequest *start_fed_query(struct Client *sptr, const char *target,
                                           const char *subcmd, const char *ref,
                                           int limit,
                                           struct HistoryMessage *local_msgs,
                                           int local_count)
{
  struct FedRequest *req;
  char reqid[32];
  char s2s_ref[64];
  char s2s_subcmd;
  int i, server_count;
  struct DLink *lp;

  /* Check if federation is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION))
    return NULL;

  /* Count connected servers */
  server_count = count_servers();
  if (server_count == 0)
    return NULL;  /* No servers to query */

  /* Convert to efficient S2S format */
  s2s_subcmd = subcmd_to_s2s(subcmd);
  if (s2s_subcmd == '?')
    return NULL;  /* Unknown subcmd */

  if (!ref_to_s2s(ref, s2s_ref, sizeof(s2s_ref)))
    return NULL;  /* Invalid reference */

  /* Find empty slot */
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (!fed_requests[i])
      break;
  }
  if (i >= MAX_FED_REQUESTS)
    return NULL;  /* No room */

  /* Generate request ID */
  ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu",
                cli_yxx(&me), ++fed_reqid_counter);

  /* Create request */
  req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
  ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
  ircd_strncpy(req->target, target, sizeof(req->target) - 1);
  /* Store full client numeric (server + client) for safe lookup later
   * findNUser expects the full numeric like "BjAAU" not just the client part "AAU" */
  ircd_snprintf(0, req->client_yxx, sizeof(req->client_yxx), "%s%s",
                cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
  req->local_msgs = local_msgs;
  req->local_count = local_count;
  req->fed_msgs = NULL;
  req->fed_count = 0;
  req->servers_pending = server_count;
  req->start_time = CurrentTime;
  req->limit = limit;

  fed_requests[i] = req;

  /* Set timeout timer */
  timer_add(timer_init(&req->timer), fed_timeout_callback,
            (void *)req, TT_RELATIVE,
            feature_int(FEAT_CHATHISTORY_TIMEOUT));
  req->timer_active = 1;

  /* Send query to all servers using efficient S2S format:
   * CH Q <target> <subcmd:1char> <ref:T/M prefix> <limit> <reqid>
   */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *server = lp->value.cptr;
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q %s %c %s %d %s",
                  target, s2s_subcmd, s2s_ref, limit, reqid);
  }

  return req;
}

/*
 * ms_chathistory - server message handler for S2S chathistory federation
 *
 * P10 Format (optimized for efficiency):
 *   [SERVER] CH Q <target> <subcmd:1char> <ref:T/M/*> <limit> <reqid>   - Query
 *   [SERVER] CH R <reqid> <msgid> <ts> <type> <sender> <account> :<content>  - Response
 *   [SERVER] CH E <reqid> <count>   - End response
 *
 * Subcmd codes: L=LATEST, B=BEFORE, A=AFTER, R=AROUND, W=BETWEEN, T=TARGETS
 * Ref format: T<timestamp>, M<msgid>, or * for none
 *
 * parv[0] = sender prefix
 * parv[1] = subcommand (Q, R, or E)
 * parv[2+] = parameters based on subcommand
 */
int ms_chathistory(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *subcmd;
  struct Client *origin;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Sender must be a server */
  if (!IsServer(sptr))
    return 0;

  if (parc < 2)
    return 0;

  subcmd = parv[1];

  if (strcmp(subcmd, "Q") == 0) {
    /* Query: Q <target> <subcmd:1char> <ref:T/M/*> <limit> <reqid> */
    char *target, *query_subcmd_str, *ref, *reqid;
    char query_subcmd_char;
    const char *query_subcmd_full;
    int limit, count;
    struct HistoryMessage *messages = NULL;
    struct HistoryMessage *msg;
    enum HistoryRefType ref_type;
    const char *ref_value;

    if (parc < 7)
      return 0;

    target = parv[2];
    query_subcmd_str = parv[3];
    ref = parv[4];
    limit = atoi(parv[5]);
    reqid = parv[6];

    /* Propagate query to other servers (except source) - keep efficient format */
    sendcmdto_serv_butone(sptr, CMD_CHATHISTORY, cptr, "Q %s %s %s %d %s",
                          target, query_subcmd_str, ref, limit, reqid);

    /* Only process for channels (not PMs) */
    if (!IsChannelName(target)) {
      /* Send empty response for PMs */
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
      return 0;
    }

    /* Check if we have history backend */
    if (!history_is_available()) {
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
      return 0;
    }

    /* Parse S2S reference format (T..., M..., *) */
    if (parse_s2s_reference(ref, &ref_type, &ref_value) != 0) {
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
      return 0;
    }

    /* Parse single-char subcmd */
    query_subcmd_char = query_subcmd_str[0];
    query_subcmd_full = s2s_to_subcmd(query_subcmd_char);

    /* Query local LMDB based on subcommand */
    if (query_subcmd_char == 'L') {
      count = history_query_latest(target, ref_type, ref_value, limit, &messages);
    } else if (query_subcmd_char == 'B') {
      count = history_query_before(target, ref_type, ref_value, limit, &messages);
    } else if (query_subcmd_char == 'A') {
      count = history_query_after(target, ref_type, ref_value, limit, &messages);
    } else if (query_subcmd_char == 'R') {
      count = history_query_around(target, ref_type, ref_value, limit, &messages);
    } else {
      /* Unsupported subcommand for federation */
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
      return 0;
    }

    if (count <= 0) {
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
      return 0;
    }

    /* Send response messages */
    for (msg = messages; msg; msg = msg->next) {
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "R %s %s %s %d %s %s :%s",
                    reqid, msg->msgid, msg->timestamp, msg->type,
                    msg->sender, msg->account[0] ? msg->account : "*",
                    msg->content);
    }

    /* Send end marker */
    sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d", reqid, count);

    history_free_messages(messages);
  }
  else if (strcmp(subcmd, "R") == 0) {
    /* Response: R <reqid> <msgid> <ts> <type> <sender> <account> :<content> */
    char *reqid, *msgid, *timestamp, *sender, *account, *content;
    int type;
    struct FedRequest *req;

    if (parc < 8)
      return 0;

    reqid = parv[2];
    msgid = parv[3];
    timestamp = parv[4];
    type = atoi(parv[5]);
    sender = parv[6];
    account = parv[7];
    content = (parc > 8) ? parv[8] : "";

    /* Find the request */
    req = find_fed_request(reqid);
    if (!req)
      return 0;  /* Request not found or already completed */

    /* Add message to federated results */
    add_fed_message(req, msgid, timestamp, type, sender, account, content);
  }
  else if (strcmp(subcmd, "E") == 0) {
    /* End: E <reqid> <count> */
    char *reqid;
    int count;
    struct FedRequest *req;

    if (parc < 4)
      return 0;

    reqid = parv[2];
    count = atoi(parv[3]);

    /* Find the request */
    req = find_fed_request(reqid);
    if (!req)
      return 0;

    /* Decrement pending count */
    req->servers_pending--;

    /* If all servers have responded, complete the request */
    if (req->servers_pending <= 0) {
      complete_fed_request(req);
    }
  }

  return 0;
}
