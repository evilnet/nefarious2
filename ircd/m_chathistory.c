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
#include <openssl/evp.h>

/** Maximum batch ID length */
#define BATCH_ID_LEN 16

/** Max bytes per base64 chunk (after encoding).
 * P10 line limit is 512 bytes. After headers (~100 bytes), we have ~400 safe.
 * Raw data: 300 bytes -> 400 base64 chars.
 */
#define CH_CHUNK_RAW_SIZE 300
#define CH_CHUNK_B64_SIZE 400

/** Check if content needs base64 encoding (contains newline or is too long).
 * @param[in] content Content string to check.
 * @return 1 if encoding needed, 0 otherwise.
 */
static int ch_needs_encoding(const char *content)
{
  if (!content)
    return 0;
  /* Encode if contains newline (would corrupt P10 stream) */
  if (strchr(content, '\n') != NULL)
    return 1;
  /* Encode if too long for single P10 message (after headers ~100 bytes) */
  if (strlen(content) > 400)
    return 1;
  return 0;
}

/** Base64 encode a string using OpenSSL.
 * @param[in] input Input data.
 * @param[in] inlen Input length.
 * @param[out] output Output buffer (must be at least (inlen*4/3)+5 bytes).
 * @return Length of encoded string.
 */
static int ch_base64_encode(const char *input, size_t inlen, char *output)
{
  int outlen;
  EVP_EncodeBlock((unsigned char *)output, (const unsigned char *)input, inlen);
  outlen = ((inlen + 2) / 3) * 4;
  output[outlen] = '\0';
  return outlen;
}

/** Send a chathistory response with base64 chunking if needed.
 * Protocol:
 *   CH R <reqid> <msgid> <ts> <type> <sender> <account> :<content>  - normal
 *   CH B <reqid> <msgid> <ts> <type> <sender> <account> + :<b64>    - start/more
 *   CH B <reqid> <msgid> + :<b64>                                    - continue
 *   CH B <reqid> <msgid> :<b64>                                      - final
 * @param[in] sptr Target server.
 * @param[in] reqid Request ID.
 * @param[in] msg History message.
 */
static void send_ch_response(struct Client *sptr, const char *reqid,
                             struct HistoryMessage *msg)
{
  const char *account = msg->account[0] ? msg->account : "*";

  /* Check if content needs base64 encoding */
  if (!ch_needs_encoding(msg->content)) {
    /* Simple case: send as-is */
    sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "R %s %s %s %d %s %s :%s",
                  reqid, msg->msgid, msg->timestamp, msg->type,
                  msg->sender, account, msg->content);
    return;
  }

  /* Base64 encode the content */
  size_t content_len = strlen(msg->content);
  size_t b64_len = ((content_len + 2) / 3) * 4 + 1;
  char *b64 = MyMalloc(b64_len);
  if (!b64) {
    /* Fallback: send truncated without encoding */
    sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "R %s %s %s %d %s %s :%s",
                  reqid, msg->msgid, msg->timestamp, msg->type,
                  msg->sender, account, "[content too large]");
    return;
  }

  ch_base64_encode(msg->content, content_len, b64);
  size_t b64_total = strlen(b64);

  /* If it fits in one message, send complete B message (no + marker) */
  if (b64_total <= CH_CHUNK_B64_SIZE) {
    sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "B %s %s %s %d %s %s :%s",
                  reqid, msg->msgid, msg->timestamp, msg->type,
                  msg->sender, account, b64);
    MyFree(b64);
    return;
  }

  /* Multi-chunk: send with chunking */
  size_t offset = 0;
  int first = 1;

  while (offset < b64_total) {
    size_t remaining = b64_total - offset;
    size_t chunk_size = (remaining > CH_CHUNK_B64_SIZE) ? CH_CHUNK_B64_SIZE : remaining;
    int more = (offset + chunk_size < b64_total);
    char chunk[CH_CHUNK_B64_SIZE + 1];

    memcpy(chunk, b64 + offset, chunk_size);
    chunk[chunk_size] = '\0';

    if (first) {
      /* First chunk: include all metadata, + marker if more coming */
      if (more) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "B %s %s %s %d %s %s + :%s",
                      reqid, msg->msgid, msg->timestamp, msg->type,
                      msg->sender, account, chunk);
      } else {
        /* Single chunk that just barely needed encoding */
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "B %s %s %s %d %s %s :%s",
                      reqid, msg->msgid, msg->timestamp, msg->type,
                      msg->sender, account, chunk);
      }
      first = 0;
    } else {
      /* Continuation chunk: just reqid, msgid, and marker */
      if (more) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "B %s %s + :%s",
                      reqid, msg->msgid, chunk);
      } else {
        /* Final chunk: no + marker */
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "B %s %s :%s",
                      reqid, msg->msgid, chunk);
      }
    }

    offset += chunk_size;
  }

  MyFree(b64);
}

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
 * Output: "1234.567" or "AB-1234-5" or "*"
 * No prefix needed - timestamps start with digit, msgids don't.
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
    ircd_strncpy(buf, ref + 10, buflen - 1);
    buf[buflen - 1] = '\0';
    return buf;
  }

  if (strncmp(ref, "msgid=", 6) == 0) {
    ircd_strncpy(buf, ref + 6, buflen - 1);
    buf[buflen - 1] = '\0';
    return buf;
  }

  return NULL;
}

/** Parse S2S reference format.
 * Input:  "1234.567" (timestamp) or "AB-1234-5" (msgid) or "*" (none)
 * Timestamps always start with a digit, msgids never do (they start with server numeric).
 * @param[in] ref S2S reference string.
 * @param[out] ref_type Type of reference.
 * @param[out] value Pointer to value.
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

  /* Handle IRC client format prefixes (X3 sends these) */
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

  /* Timestamps start with a digit, msgids start with server numeric (letter) */
  if (IsDigit(*ref)) {
    *ref_type = HISTORY_REF_TIMESTAMP;
    *value = ref;
    return 0;
  }

  /* Anything else is a msgid */
  *ref_type = HISTORY_REF_MSGID;
  *value = ref;
  return 0;
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

/** Send a single history message, handling multiline content.
 * If content contains newlines and client supports multiline, send as nested batch.
 * Otherwise truncate to first line.
 *
 * @param[in] sptr Client to send to.
 * @param[in] msg Message to send.
 * @param[in] target Target name.
 * @param[in] outer_batchid Outer chathistory batch ID (or NULL if no batch).
 * @param[in] time_str ISO timestamp string.
 * @param[in] cmd Command name (PRIVMSG, NOTICE, etc.).
 */
static void send_history_message(struct Client *sptr, struct HistoryMessage *msg,
                                  const char *target, const char *outer_batchid,
                                  const char *time_str, const char *cmd)
{
  char *newline;
  char first_line[512];
  char *content = msg->content;

  /* Check if content contains newlines (stored multiline) */
  newline = strchr(content, '\n');

  if (newline && CapActive(sptr, CAP_DRAFT_MULTILINE) && CapActive(sptr, CAP_BATCH)) {
    /* Re-batch as draft/multiline nested inside chathistory batch */
    static unsigned long ml_counter = 0;
    char ml_batchid[BATCH_ID_LEN];
    char *line_start = content;
    char *line_end;
    int first = 1;

    /* Generate unique multiline batch ID */
    ircd_snprintf(0, ml_batchid, sizeof(ml_batchid), "ml%lu%s", ++ml_counter, cli_yxx(sptr));

    /* Start nested multiline batch (inside outer chathistory batch) */
    if (outer_batchid) {
      sendrawto_one(sptr, "@batch=%s :testnet.fractalrealities.net BATCH +%s draft/multiline %s",
                    outer_batchid, ml_batchid, target);
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s draft/multiline %s",
                    ml_batchid, target);
    }

    /* Send each line with the same msgid (per multiline spec) */
    while (line_start && *line_start) {
      line_end = strchr(line_start, '\n');
      if (line_end) {
        /* Copy line without newline */
        size_t len = line_end - line_start;
        if (len >= sizeof(first_line))
          len = sizeof(first_line) - 1;
        memcpy(first_line, line_start, len);
        first_line[len] = '\0';
        line_start = line_end + 1;
      } else {
        /* Last line (no trailing newline) */
        ircd_strncpy(first_line, line_start, sizeof(first_line) - 1);
        line_start = NULL;
      }

      /* Send line as part of multiline batch */
      if (first) {
        /* First line gets time and msgid */
        if (msg->account[0]) {
          sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s;account=%s :%s %s %s :%s",
                        ml_batchid, time_str, msg->msgid, msg->account,
                        msg->sender, cmd, target, first_line);
        } else {
          sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s %s %s :%s",
                        ml_batchid, time_str, msg->msgid,
                        msg->sender, cmd, target, first_line);
        }
        first = 0;
      } else {
        /* Subsequent lines - same msgid, batch tag only */
        if (msg->account[0]) {
          sendrawto_one(sptr, "@batch=%s;msgid=%s;account=%s :%s %s %s :%s",
                        ml_batchid, msg->msgid, msg->account,
                        msg->sender, cmd, target, first_line);
        } else {
          sendrawto_one(sptr, "@batch=%s;msgid=%s :%s %s %s :%s",
                        ml_batchid, msg->msgid,
                        msg->sender, cmd, target, first_line);
        }
      }
    }

    /* End nested multiline batch */
    if (outer_batchid) {
      sendrawto_one(sptr, "@batch=%s :testnet.fractalrealities.net BATCH -%s",
                    outer_batchid, ml_batchid);
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", ml_batchid);
    }
  } else if (newline && outer_batchid) {
    /* Tier 2: Client has chathistory batch but not multiline capability.
     * Send each line as separate PRIVMSG within the chathistory batch.
     * This allows full content retrieval even without multiline support.
     * All lines share the same msgid so clients know they're related.
     */
    char *line_start = content;
    char *line_end;
    int first = 1;

    while (line_start && *line_start) {
      line_end = strchr(line_start, '\n');
      if (line_end) {
        size_t len = line_end - line_start;
        if (len >= sizeof(first_line))
          len = sizeof(first_line) - 1;
        memcpy(first_line, line_start, len);
        first_line[len] = '\0';
        line_start = line_end + 1;
      } else {
        ircd_strncpy(first_line, line_start, sizeof(first_line) - 1);
        line_start = NULL;
      }

      /* Send each line as separate message in batch */
      if (first) {
        /* First line gets time and msgid */
        if (msg->account[0]) {
          sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s;account=%s :%s %s %s :%s",
                        outer_batchid, time_str, msg->msgid, msg->account,
                        msg->sender, cmd, target, first_line);
        } else {
          sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s %s %s :%s",
                        outer_batchid, time_str, msg->msgid,
                        msg->sender, cmd, target, first_line);
        }
        first = 0;
      } else {
        /* Subsequent lines - same msgid indicates they're part of same logical message */
        if (msg->account[0]) {
          sendrawto_one(sptr, "@batch=%s;msgid=%s;account=%s :%s %s %s :%s",
                        outer_batchid, msg->msgid, msg->account,
                        msg->sender, cmd, target, first_line);
        } else {
          sendrawto_one(sptr, "@batch=%s;msgid=%s :%s %s %s :%s",
                        outer_batchid, msg->msgid,
                        msg->sender, cmd, target, first_line);
        }
      }
    }
  } else {
    /* Tier 3: No chathistory batch or no newlines - send single message */
    /* If there are newlines but no batch, truncate to first line */
    if (newline) {
      size_t len = newline - content;
      if (len >= sizeof(first_line))
        len = sizeof(first_line) - 1;
      memcpy(first_line, content, len);
      first_line[len] = '\0';
      content = first_line;
    }

    if (outer_batchid) {
      /* With batch (but no newlines) */
      if (msg->account[0]) {
        sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s;account=%s :%s %s %s :%s",
                      outer_batchid, time_str, msg->msgid, msg->account,
                      msg->sender, cmd, target, content);
      } else {
        sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s %s %s :%s",
                      outer_batchid, time_str, msg->msgid,
                      msg->sender, cmd, target, content);
      }
    } else {
      /* Without batch */
      if (msg->account[0]) {
        sendrawto_one(sptr, "@time=%s;msgid=%s;account=%s :%s %s %s :%s",
                      time_str, msg->msgid, msg->account,
                      msg->sender, cmd, target, content);
      } else {
        sendrawto_one(sptr, "@time=%s;msgid=%s :%s %s %s :%s",
                      time_str, msg->msgid,
                      msg->sender, cmd, target, content);
      }
    }
  }
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

    /* Send message, handling multiline content if present */
    send_history_message(sptr, msg, target,
                         CapActive(sptr, CAP_BATCH) ? batchid : NULL,
                         time_str, cmd);
  }

  /* End batch */
  if (CapActive(sptr, CAP_BATCH)) {
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
  }
}

/** Normalize a PM target to the canonical nick1:nick2 format.
 * Clients can query with just a nickname (per IRCv3 spec), but internally
 * PM history is stored with target key "lowerNick:higherNick" (sorted).
 *
 * @param[in] sptr Client requesting history (their nick is the other party).
 * @param[in] target Target name (plain nick or already nick:nick format).
 * @param[out] normalized Buffer to store normalized target (at least NICKLEN*2+2).
 * @param[in] buflen Size of normalized buffer.
 * @return 0 on success, -1 on error (invalid nick, user not found, etc.)
 */
static int normalize_pm_target(struct Client *sptr, const char *target,
                                char *normalized, size_t buflen)
{
  const char *nick1, *nick2;
  const char *colon = strchr(target, ':');

  if (colon) {
    /* Already in nick:nick format - just validate and optionally copy */
    char n1[NICKLEN + 1], n2[NICKLEN + 1];
    size_t len1 = colon - target;
    if (len1 > NICKLEN || len1 == 0)
      return -1;

    memcpy(n1, target, len1);
    n1[len1] = '\0';
    ircd_strncpy(n2, colon + 1, NICKLEN);
    if (!n2[0])
      return -1;

    /* Verify sender is one of the nicks */
    if (ircd_strcmp(cli_name(sptr), n1) != 0 &&
        ircd_strcmp(cli_name(sptr), n2) != 0)
      return -1;

    /* Write normalized target if buffer provided */
    if (normalized && buflen > 0) {
      /* Ensure consistent sorting (lowerNick:higherNick) */
      if (ircd_strcmp(n1, n2) < 0) {
        nick1 = n1;
        nick2 = n2;
      } else {
        nick1 = n2;
        nick2 = n1;
      }
      ircd_snprintf(0, normalized, buflen, "%s:%s", nick1, nick2);
    }
  } else {
    /* Plain nickname - construct nick1:nick2 from sender + target */
    struct Client *target_client = FindUser(target);
    if (!target_client) {
      /* Target user not found - could be offline. For now, still allow
       * the query (history might exist from when they were online). */
    }

    /* Write normalized target if buffer provided */
    if (normalized && buflen > 0) {
      /* Sort nicks for consistent key format */
      if (ircd_strcmp(cli_name(sptr), target) < 0) {
        nick1 = cli_name(sptr);
        nick2 = target;
      } else {
        nick1 = target;
        nick2 = cli_name(sptr);
      }
      ircd_snprintf(0, normalized, buflen, "%s:%s", nick1, nick2);
    }
  }

  return 0;
}

/** Check if client can access history for a target.
 * @param[in] sptr Client requesting history.
 * @param[in] target Target name (channel, plain nick, or nick:nick format).
 * @param[out] normalized_target If non-NULL and target is a PM, receives
 *             the normalized nick1:nick2 format for LMDB lookup.
 * @param[in] normalized_len Size of normalized_target buffer.
 * @return 0 if allowed, -1 if not.
 */
static int check_history_access(struct Client *sptr, const char *target,
                                 char *normalized_target, size_t normalized_len)
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
    /* For channels, normalized target is same as input */
    if (normalized_target && normalized_len > 0)
      ircd_strncpy(normalized_target, target, normalized_len - 1);
    return 0;
  } else {
    /* Private message history */
    if (normalize_pm_target(sptr, target, normalized_target, normalized_len) != 0)
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
  char lookup_target[NICKLEN * 2 + 2];  /* Normalized target for LMDB lookup */

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

  /* Check access and normalize target (for PMs, converts nick to nick:nick format) */
  if (check_history_access(sptr, target, lookup_target, sizeof(lookup_target)) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  /* Query local history using normalized target */
  count = history_query_latest(lookup_target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  if (should_federate(lookup_target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, "LATEST",
                                              ref_str, limit, messages, count);
    if (req) {
      /* Federation started - response will be sent when complete */
      /* Note: messages ownership transferred to req */
      return 0;
    }
    /* Federation failed to start, fall through to local-only response */
  }

  /* Send local-only response using normalized target */
  send_history_batch(sptr, lookup_target, messages, count);

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
  char lookup_target[NICKLEN * 2 + 2];

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

  if (check_history_access(sptr, target, lookup_target, sizeof(lookup_target)) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_before(lookup_target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  if (should_federate(lookup_target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, "BEFORE",
                                              ref_str, limit, messages, count);
    if (req)
      return 0;
  }

  send_history_batch(sptr, lookup_target, messages, count);
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
  char lookup_target[NICKLEN * 2 + 2];

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

  if (check_history_access(sptr, target, lookup_target, sizeof(lookup_target)) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_after(lookup_target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  if (should_federate(lookup_target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, "AFTER",
                                              ref_str, limit, messages, count);
    if (req)
      return 0;
  }

  send_history_batch(sptr, lookup_target, messages, count);
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
  char lookup_target[NICKLEN * 2 + 2];

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

  if (check_history_access(sptr, target, lookup_target, sizeof(lookup_target)) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_around(lookup_target, ref_type, ref_value, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  if (should_federate(lookup_target, count, limit)) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, "AROUND",
                                              ref_str, limit, messages, count);
    if (req)
      return 0;
  }

  send_history_batch(sptr, lookup_target, messages, count);
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
  char lookup_target[NICKLEN * 2 + 2];

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

  if (check_history_access(sptr, target, lookup_target, sizeof(lookup_target)) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", target,
              "No access to target");
    return 0;
  }

  count = history_query_between(lookup_target, ref_type1, ref_value1,
                                 ref_type2, ref_value2, limit, &messages);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", target,
              "Failed to retrieve history");
    return 0;
  }

  send_history_batch(sptr, lookup_target, messages, count);
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
    /* Check access for each target before including.
     * Note: targets from LMDB are already in internal format (nick1:nick2 for PMs),
     * so we pass NULL for normalized_target since we don't need normalization. */
    if (check_history_access(sptr, tgt->target, NULL, 0) == 0) {
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
  int response_sent;                  /**< Whether response was already sent */
};

/** Global array of pending federation requests */
static struct FedRequest *fed_requests[MAX_FED_REQUESTS];

/** Counter for generating unique request IDs */
static unsigned long fed_reqid_counter = 0;

/** Maximum number of pending base64 chunks */
#define MAX_PENDING_CHUNKS 64

/** Structure for tracking base64 chunked messages */
struct ChunkEntry {
  char key[128];           /**< reqid:msgid */
  char reqid[32];
  char msgid[64];
  char timestamp[32];
  int type;
  char sender[64];
  char account[64];
  char *b64_data;          /**< Accumulated base64 */
  size_t b64_len;
  size_t b64_alloc;
};

/** Global array of pending chunks */
static struct ChunkEntry *pending_chunks[MAX_PENDING_CHUNKS];

/** Find a chunk entry by key */
static struct ChunkEntry *find_chunk(const char *key)
{
  int i;
  for (i = 0; i < MAX_PENDING_CHUNKS; i++) {
    if (pending_chunks[i] && strcmp(pending_chunks[i]->key, key) == 0)
      return pending_chunks[i];
  }
  return NULL;
}

/** Free a chunk entry */
static void free_chunk(struct ChunkEntry *chunk)
{
  int i;
  if (!chunk)
    return;
  if (chunk->b64_data)
    MyFree(chunk->b64_data);
  for (i = 0; i < MAX_PENDING_CHUNKS; i++) {
    if (pending_chunks[i] == chunk) {
      pending_chunks[i] = NULL;
      break;
    }
  }
  MyFree(chunk);
}

/** Create a new chunk entry */
static struct ChunkEntry *create_chunk(const char *reqid, const char *msgid,
                                       const char *timestamp, int type,
                                       const char *sender, const char *account)
{
  struct ChunkEntry *chunk;
  int i;

  for (i = 0; i < MAX_PENDING_CHUNKS; i++) {
    if (!pending_chunks[i])
      break;
  }
  if (i >= MAX_PENDING_CHUNKS)
    return NULL;

  chunk = (struct ChunkEntry *)MyCalloc(1, sizeof(struct ChunkEntry));
  ircd_snprintf(0, chunk->key, sizeof(chunk->key), "%s:%s", reqid, msgid);
  ircd_strncpy(chunk->reqid, reqid, sizeof(chunk->reqid) - 1);
  ircd_strncpy(chunk->msgid, msgid, sizeof(chunk->msgid) - 1);
  ircd_strncpy(chunk->timestamp, timestamp, sizeof(chunk->timestamp) - 1);
  chunk->type = type;
  ircd_strncpy(chunk->sender, sender, sizeof(chunk->sender) - 1);
  ircd_strncpy(chunk->account, account, sizeof(chunk->account) - 1);
  chunk->b64_alloc = 1024;
  chunk->b64_data = MyMalloc(chunk->b64_alloc);
  chunk->b64_data[0] = '\0';
  chunk->b64_len = 0;

  pending_chunks[i] = chunk;
  return chunk;
}

/** Append base64 data to chunk */
static void append_chunk_data(struct ChunkEntry *chunk, const char *b64)
{
  size_t add_len = strlen(b64);
  if (chunk->b64_len + add_len + 1 > chunk->b64_alloc) {
    chunk->b64_alloc = (chunk->b64_len + add_len + 1) * 2;
    chunk->b64_data = MyRealloc(chunk->b64_data, chunk->b64_alloc);
  }
  memcpy(chunk->b64_data + chunk->b64_len, b64, add_len + 1);
  chunk->b64_len += add_len;
}

/** Base64 decode using OpenSSL.
 * @param[in] input Base64 encoded string.
 * @param[in] inlen Input length.
 * @param[out] output Decoded output (caller frees).
 * @param[out] outlen Decoded length.
 * @return 1 on success, 0 on failure.
 */
static int ch_base64_decode(const char *input, size_t inlen, char **output, size_t *outlen)
{
  size_t alloc_len = (inlen * 3) / 4 + 4;
  char *decoded = MyMalloc(alloc_len);
  int decoded_len;

  decoded_len = EVP_DecodeBlock((unsigned char *)decoded,
                                 (const unsigned char *)input, inlen);
  if (decoded_len < 0) {
    MyFree(decoded);
    return 0;
  }

  /* EVP_DecodeBlock includes padding - adjust for actual length */
  while (inlen > 0 && input[inlen - 1] == '=') {
    decoded_len--;
    inlen--;
  }

  decoded[decoded_len] = '\0';
  *output = decoded;
  *outlen = decoded_len;
  return 1;
}

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

/** Send federation results to client (does NOT free the request)
 * Call this to send results, then let timer destroy event free the request.
 */
static void send_fed_response(struct FedRequest *req)
{
  struct HistoryMessage *merged;
  struct Client *client;
  int total;

  if (!req || req->response_sent)
    return;

  req->response_sent = 1;  /* Mark as sent to prevent double-send */

  /* Look up the client by numeric - they may have disconnected */
  client = findNUser(req->client_yxx);
  if (!client) {
    /* Client disconnected, nothing to send */
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
}

/** Complete a federation request - sends response and triggers cleanup.
 * For timeout path: timer_run will call ET_DESTROY after we return.
 * For early completion: we call timer_del which triggers ET_DESTROY.
 */
static void complete_fed_request(struct FedRequest *req)
{
  if (!req)
    return;

  /* Send response to client */
  send_fed_response(req);

  /* If timer is still active (early completion), delete it.
   * timer_del will trigger ET_DESTROY callback which frees the request.
   * If timer already expired (timeout path), timer_run will send ET_DESTROY.
   */
  if (req->timer_active) {
    req->timer_active = 0;
    timer_del(&req->timer);
    /* Note: timer_del triggers ET_DESTROY, which calls free_fed_request */
  }
  /* If !timer_active, we're in the timeout callback and timer_run will
   * send ET_DESTROY after we return, so don't free here */
}

/** Timer callback for federation timeout.
 * Handles both ET_EXPIRE (timeout) and ET_DESTROY (cleanup).
 */
static void fed_timeout_callback(struct Event *ev)
{
  struct FedRequest *req;

  req = (struct FedRequest *)t_data(ev_timer(ev));
  if (!req)
    return;

  switch (ev_type(ev)) {
  case ET_EXPIRE:
    /* Timer expired - complete with whatever we have.
     * Don't free here - timer_run will send ET_DESTROY after we return.
     */
    req->timer_active = 0;
    complete_fed_request(req);
    break;

  case ET_DESTROY:
    /* Timer is being destroyed - safe to free the request now.
     * This is called by timer_run after ET_EXPIRE, or by timer_del.
     */
    free_fed_request(req);
    break;

  default:
    break;
  }
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

    /* Send response messages.
     * Uses base64 chunked encoding for content with newlines or long content.
     * - CH R: normal response (content as-is)
     * - CH B: base64 encoded response (with chunking if needed)
     */
    for (msg = messages; msg; msg = msg->next) {
      send_ch_response(sptr, reqid, msg);
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
  else if (strcmp(subcmd, "B") == 0) {
    /* Base64 Response: B <reqid> <msgid> <ts> <type> <sender> <account> [+] :<b64>
     * Or continuation:  B <reqid> <msgid> [+] :<b64>
     * + marker means more chunks coming. No + means final.
     */
    char *reqid, *msgid;
    const char *b64_data;
    struct FedRequest *req;
    struct ChunkEntry *chunk;
    char chunk_key[128];
    int has_more = 0;
    int is_continuation = 0;

    if (parc < 4)
      return 0;

    reqid = parv[2];
    msgid = parv[3];

    /* Find the request */
    req = find_fed_request(reqid);
    if (!req)
      return 0;

    /* Determine message format based on parc:
     * parc=5: continuation "B <reqid> <msgid> :<b64>" (final)
     * parc=6: continuation "B <reqid> <msgid> + :<b64>" (more)
     * parc=9: full "B <reqid> <msgid> <ts> <type> <sender> <account> :<b64>" (complete)
     * parc=10: full "B <reqid> <msgid> <ts> <type> <sender> <account> + :<b64>" (first)
     */
    if (parc <= 6) {
      is_continuation = 1;
      if (parc == 6 && strcmp(parv[4], "+") == 0) {
        has_more = 1;
        b64_data = parv[5];
      } else {
        has_more = 0;
        b64_data = parv[4];
      }
    } else {
      is_continuation = 0;
      if (parc == 10 && strcmp(parv[8], "+") == 0) {
        has_more = 1;
        b64_data = parv[9];
      } else {
        has_more = 0;
        b64_data = (parc > 8) ? parv[8] : "";
      }
    }

    /* Create chunk key */
    ircd_snprintf(0, chunk_key, sizeof(chunk_key), "%s:%s", reqid, msgid);

    if (is_continuation) {
      chunk = find_chunk(chunk_key);
      if (!chunk)
        return 0;  /* Continuation without start */
    } else {
      chunk = create_chunk(reqid, msgid, parv[4], atoi(parv[5]), parv[6], parv[7]);
      if (!chunk)
        return 0;  /* No slots available */
    }

    /* Append base64 data */
    append_chunk_data(chunk, b64_data);

    if (!has_more) {
      /* Final chunk - decode and add to results */
      char *decoded;
      size_t decoded_len;

      if (ch_base64_decode(chunk->b64_data, chunk->b64_len, &decoded, &decoded_len)) {
        add_fed_message(req, chunk->msgid, chunk->timestamp, chunk->type,
                        chunk->sender, chunk->account, decoded);
        MyFree(decoded);
      }
      free_chunk(chunk);
    }
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
