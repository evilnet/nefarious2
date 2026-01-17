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
#include "ircd_compress.h"
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
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/* Forward declarations for functions used before definition */
static int is_ulined_server(struct Client *server);
int has_chathistory_advertisement(struct Client *server);
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

/** Check if content needs base64 encoding.
 * Note: New multiline content uses \x1F separators, but we must still check for
 * \n to handle legacy data that was stored with newline separators.
 * @param[in] content Content string to check.
 * @return 1 if encoding needed, 0 otherwise.
 */
static int ch_needs_encoding(const char *content)
{
  if (!content)
    return 0;
  /* Encode if contains newline (legacy data or would corrupt P10 stream) */
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
 *   CH Z <reqid> <msgid> <ts> <type> <sender> <account> :<b64_compressed> - compressed passthrough
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

  /* If we have raw compressed data, send with Z flag for bandwidth savings.
   * Only use Z if the base64-encoded result fits in a single P10 message.
   * Otherwise fall through to normal B chunking with decompressed content.
   */
  if (msg->raw_content && msg->raw_content_len > 0) {
    size_t b64_len = ((msg->raw_content_len + 2) / 3) * 4 + 1;
    if (b64_len <= CH_CHUNK_B64_SIZE) {
      char *b64 = MyMalloc(b64_len);
      if (b64) {
        ch_base64_encode((const char *)msg->raw_content, msg->raw_content_len, b64);
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "Z %s %s %s %d %s %s :%s",
                      reqid, msg->msgid, msg->timestamp, msg->type,
                      msg->sender, account, b64);
        MyFree(b64);
        return;
      }
    }
    /* Fall through to uncompressed if too large or malloc failed */
  }

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

/** Validate a timestamp value.
 * Valid formats:
 *   - Unix timestamp: digits with optional decimal (e.g., "1234567890.123")
 *   - ISO 8601: "YYYY-MM-DDTHH:MM:SS.sssZ" or similar
 * @param[in] ts Timestamp string to validate.
 * @return 1 if valid, 0 if invalid.
 */
static int validate_timestamp(const char *ts)
{
  const char *p;

  if (!ts || !*ts)
    return 0;

  /* Check for Unix timestamp format: digits with optional decimal point */
  if (IsDigit(*ts)) {
    int has_decimal = 0;
    for (p = ts; *p; p++) {
      if (*p == '.') {
        if (has_decimal)
          return 0;  /* Multiple decimals */
        has_decimal = 1;
      } else if (*p == 'T' || *p == '-' || *p == ':' || *p == 'Z') {
        /* This looks like ISO 8601 format - validate below */
        break;
      } else if (!IsDigit(*p)) {
        return 0;  /* Invalid character */
      }
    }
    if (!*p)
      return 1;  /* Valid Unix timestamp */
  }

  /* Check for ISO 8601 format: YYYY-MM-DDTHH:MM:SS[.sss]Z
   * Relaxed validation - just check basic structure */
  if (strlen(ts) >= 19) {  /* Minimum: YYYY-MM-DDTHH:MM:SS */
    /* Check YYYY-MM-DD pattern at start */
    if (IsDigit(ts[0]) && IsDigit(ts[1]) && IsDigit(ts[2]) && IsDigit(ts[3]) &&
        ts[4] == '-' &&
        IsDigit(ts[5]) && IsDigit(ts[6]) &&
        ts[7] == '-' &&
        IsDigit(ts[8]) && IsDigit(ts[9]) &&
        ts[10] == 'T') {
      return 1;  /* Valid ISO 8601 */
    }
  }

  return 0;  /* Invalid format */
}

/** Validate a timestamp value in strict ISO 8601 format only.
 * Per IRCv3 chathistory spec, clients should send ISO 8601 timestamps.
 * Valid format: "YYYY-MM-DDTHH:MM:SS[.sss]Z"
 * @param[in] ts Timestamp string to validate.
 * @return 1 if valid ISO 8601, 0 if invalid.
 */
static int validate_iso_timestamp(const char *ts)
{
  if (!ts || !*ts)
    return 0;

  /* Check for ISO 8601 format: YYYY-MM-DDTHH:MM:SS[.sss]Z
   * Relaxed validation - just check basic structure */
  if (strlen(ts) >= 19) {  /* Minimum: YYYY-MM-DDTHH:MM:SS */
    /* Check YYYY-MM-DD pattern at start */
    if (IsDigit(ts[0]) && IsDigit(ts[1]) && IsDigit(ts[2]) && IsDigit(ts[3]) &&
        ts[4] == '-' &&
        IsDigit(ts[5]) && IsDigit(ts[6]) &&
        ts[7] == '-' &&
        IsDigit(ts[8]) && IsDigit(ts[9]) &&
        ts[10] == 'T') {
      return 1;  /* Valid ISO 8601 */
    }
  }

  return 0;  /* Not ISO 8601 format */
}

/** Validate a client-facing timestamp value.
 * Respects FEAT_CHATHISTORY_STRICT_TIMESTAMPS:
 *   - If TRUE: only accepts ISO 8601 format (per IRCv3 spec)
 *   - If FALSE: accepts both ISO 8601 and Unix timestamps (permissive)
 * @param[in] ts Timestamp string to validate.
 * @return 1 if valid, 0 if invalid.
 */
static int validate_client_timestamp(const char *ts)
{
  if (feature_bool(FEAT_CHATHISTORY_STRICT_TIMESTAMPS))
    return validate_iso_timestamp(ts);
  return validate_timestamp(ts);
}

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
    const char *ts = ref + 10;
    /* Validate the timestamp value per IRCv3 spec.
     * Uses validate_client_timestamp which respects STRICT_TIMESTAMPS config. */
    if (!validate_client_timestamp(ts))
      return -1;
    *ref_type = HISTORY_REF_TIMESTAMP;
    *value = ts;
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
 * If content contains \x1F separators and client supports multiline,
 * send as nested batch. Otherwise truncate to first line.
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
  char *separator;
  char first_line[512];
  char *content = msg->content;

  /* Check if content contains Unit Separator (multiline) */
  separator = strchr(content, '\x1F');

  if (separator && CapActive(sptr, CAP_DRAFT_MULTILINE) && CapActive(sptr, CAP_BATCH)) {
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
      line_end = strchr(line_start, '\x1F');
      if (line_end) {
        /* Copy line without separator */
        size_t len = line_end - line_start;
        if (len >= sizeof(first_line))
          len = sizeof(first_line) - 1;
        memcpy(first_line, line_start, len);
        first_line[len] = '\0';
        line_start = line_end + 1;
      } else {
        /* Last line (no trailing separator) */
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
  } else if (separator && outer_batchid) {
    /* Tier 2: Client has chathistory batch but not multiline capability.
     * Send each line as separate PRIVMSG within the chathistory batch.
     * This allows full content retrieval even without multiline support.
     * All lines share the same msgid so clients know they're related.
     */
    char *line_start = content;
    char *line_end;
    int first = 1;

    while (line_start && *line_start) {
      line_end = strchr(line_start, '\x1F');
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
    /* Tier 3: No chathistory batch or no separators - send single message */
    /* If there are separators but no batch, truncate to first line */
    if (separator) {
      size_t len = separator - content;
      if (len >= sizeof(first_line))
        len = sizeof(first_line) - 1;
      memcpy(first_line, content, len);
      first_line[len] = '\0';
      content = first_line;
    }

    if (outer_batchid) {
      /* With batch (but no separators) */
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

  /* Federate if we got fewer messages than requested.
   * Note: count_servers() already skips U-lined services (X3 etc.) since
   * they don't store chat history. If only services are connected,
   * start_fed_query() returns NULL and we return local results immediately.
   *
   * TODO: This still has a "kick the can" problem for multi-server:
   * - If local_count == 0 and remote servers exist, we federate
   * - But if remote servers also have no history, we wait for timeout
   * - The spec says return empty batch immediately, but we can't know
   *   if remote servers have history without asking them
   * - Possible future optimization: async channel presence tracking
   */
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
 *   [SERVER] CH Z <reqid> <msgid> <ts> <type> <sender> <account> :<b64_zstd> - Compressed response
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

/*
 * ============================================================================
 * Chathistory Write Forwarding (CH W / CH WB)
 * ============================================================================
 *
 * Non-STORE servers forward channel messages to STORE servers via CH W/WB.
 * CH W is for plain text (≤400 bytes, no newlines).
 * CH WB is for base64 encoded content (multiline, >400 bytes).
 *
 * Protocol:
 *   CH W <target> <msgid> <ts> <sender> <account> <type> :<content>
 *   CH WB <target> <msgid> <ts> <sender> <account> <type> [+] :<b64>
 *   CH WB <target> <msgid> [+] :<b64>  (continuation)
 */

/** Maximum number of pending write chunks */
#define MAX_PENDING_WRITE_CHUNKS 64

/** Structure for tracking CH WB chunked writes */
struct WriteChunkEntry {
  char key[CHANNELLEN + HISTORY_MSGID_LEN + 2];  /**< target:msgid */
  char target[CHANNELLEN + 1];
  char msgid[HISTORY_MSGID_LEN];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int type;
  char sender[HISTORY_SENDER_LEN];
  char account[ACCOUNTLEN + 1];
  char *b64_data;          /**< Accumulated base64 */
  size_t b64_len;
  size_t b64_alloc;
};

/** Global array of pending write chunks */
static struct WriteChunkEntry *pending_write_chunks[MAX_PENDING_WRITE_CHUNKS];

/** Find a write chunk by key */
static struct WriteChunkEntry *find_write_chunk(const char *key)
{
  int i;
  for (i = 0; i < MAX_PENDING_WRITE_CHUNKS; i++) {
    if (pending_write_chunks[i] && strcmp(pending_write_chunks[i]->key, key) == 0)
      return pending_write_chunks[i];
  }
  return NULL;
}

/** Free a write chunk entry */
static void free_write_chunk(struct WriteChunkEntry *chunk)
{
  int i;
  if (!chunk)
    return;
  if (chunk->b64_data)
    MyFree(chunk->b64_data);
  for (i = 0; i < MAX_PENDING_WRITE_CHUNKS; i++) {
    if (pending_write_chunks[i] == chunk) {
      pending_write_chunks[i] = NULL;
      break;
    }
  }
  MyFree(chunk);
}

/** Create a new write chunk entry */
static struct WriteChunkEntry *create_write_chunk(const char *target, const char *msgid,
                                                   const char *timestamp, int type,
                                                   const char *sender, const char *account)
{
  struct WriteChunkEntry *chunk;
  int i;

  for (i = 0; i < MAX_PENDING_WRITE_CHUNKS; i++) {
    if (!pending_write_chunks[i])
      break;
  }
  if (i >= MAX_PENDING_WRITE_CHUNKS)
    return NULL;

  chunk = (struct WriteChunkEntry *)MyCalloc(1, sizeof(struct WriteChunkEntry));
  ircd_snprintf(0, chunk->key, sizeof(chunk->key), "%s:%s", target, msgid);
  ircd_strncpy(chunk->target, target, sizeof(chunk->target) - 1);
  ircd_strncpy(chunk->msgid, msgid, sizeof(chunk->msgid) - 1);
  ircd_strncpy(chunk->timestamp, timestamp, sizeof(chunk->timestamp) - 1);
  chunk->type = type;
  ircd_strncpy(chunk->sender, sender, sizeof(chunk->sender) - 1);
  ircd_strncpy(chunk->account, account, sizeof(chunk->account) - 1);
  chunk->b64_alloc = 1024;
  chunk->b64_data = MyMalloc(chunk->b64_alloc);
  chunk->b64_data[0] = '\0';
  chunk->b64_len = 0;

  pending_write_chunks[i] = chunk;
  return chunk;
}

/** Append base64 data to write chunk */
static void append_write_chunk_data(struct WriteChunkEntry *chunk, const char *b64)
{
  size_t add_len = strlen(b64);
  if (chunk->b64_len + add_len + 1 > chunk->b64_alloc) {
    chunk->b64_alloc = (chunk->b64_len + add_len + 1) * 2;
    chunk->b64_data = MyRealloc(chunk->b64_data, chunk->b64_alloc);
  }
  memcpy(chunk->b64_data + chunk->b64_len, b64, add_len + 1);
  chunk->b64_len += add_len;
}

/** Process a completed write forward (store if appropriate).
 * @param[in] target Channel name.
 * @param[in] msgid Message ID.
 * @param[in] timestamp Unix timestamp.
 * @param[in] sender Full sender mask.
 * @param[in] account Sender's account or "*".
 * @param[in] type_char Type character (P, N, T).
 * @param[in] content Message content.
 */
static void process_write_forward(const char *target, const char *msgid,
                                  const char *timestamp, const char *sender,
                                  const char *account, char type_char,
                                  const char *content)
{
  struct Channel *chptr;
  enum HistoryMessageType type;
  int has_local_users;

  /* Only process channels */
  if (!IsChannelName(target))
    return;

  /* Check if we're a storage server */
  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;

  /* Deduplication: check if we already have this msgid */
  if (history_has_msgid(msgid) == 1) {
    Debug((DEBUG_DEBUG, "CH W: Duplicate msgid %s for %s, ignoring", msgid, target));
    return;
  }

  /* Convert type char to enum */
  switch (type_char) {
    case 'P': type = HISTORY_PRIVMSG; break;
    case 'N': type = HISTORY_NOTICE; break;
    case 'T': type = HISTORY_TAGMSG; break;
    default:
      Debug((DEBUG_DEBUG, "CH W: Unknown type '%c' for %s", type_char, target));
      return;
  }

  /* Find channel */
  chptr = FindChannel(target);

  /* Decide whether to store:
   * - Registered channels (+r): Always store (if STORE_REGISTERED enabled)
   * - Channel with local users: Store (natural interest)
   * - Channel doesn't exist or no local users: Check if forwarding is trusted
   *
   * For CH W, the sending server already decided the message was worth
   * forwarding. If the channel doesn't exist locally, we still store it
   * since we're the designated STORE server for this message.
   */
  if (chptr) {
    /* Check for local member interest (not just any members) */
    struct Membership *member;
    has_local_users = 0;
    for (member = chptr->members; member; member = member->next_member) {
      if (MyConnect(member->user)) {
        has_local_users = 1;
        break;
      }
    }

    if (feature_bool(FEAT_CHATHISTORY_STORE_REGISTERED) &&
        (chptr->mode.mode & MODE_REGISTERED)) {
      /* Registered channel - always store */
      Debug((DEBUG_DEBUG, "CH W: Storing registered channel message for %s", target));
    } else if (has_local_users) {
      /* Has local users - store */
      Debug((DEBUG_DEBUG, "CH W: Storing message for %s (has local users)", target));
    } else {
      /* Unregistered without local users - but we received CH W, so store anyway.
       * The forwarding server made the decision that this should be stored here.
       * This handles edge cases like:
       * - Registered channel where ChanServ JOIN hasn't propagated yet
       * - Transient channels during netjoin
       */
      Debug((DEBUG_DEBUG, "CH W: Storing forwarded message for %s (trusting sender)", target));
    }
  } else {
    /* Channel doesn't exist locally but we received CH W.
     * Store anyway - the forwarding server believed this was worth storing.
     * This enables storage for channels where we have no local presence.
     */
    Debug((DEBUG_DEBUG, "CH W: Channel %s doesn't exist locally, storing anyway (CH W trust)", target));
  }

  /* Check if this is a new channel for Layer 1 advertisement */
  int is_new_channel = (history_has_channel(target) == 0);

  /* Store the message */
  if (history_store_message(msgid, timestamp, target, sender,
                            (account[0] == '*') ? NULL : account,
                            type, content) == 0) {
    /* Layer 1: Broadcast CH A + if this is the first message in the channel */
    if (is_new_channel) {
      broadcast_channel_advertisement(target);
    }
  }
}

/** Check if content needs encoding (same logic as ch_needs_encoding) */
static int write_needs_encoding(const char *content)
{
  if (!content)
    return 0;
  if (strchr(content, '\n') != NULL)
    return 1;
  if (strlen(content) > 400)
    return 1;
  return 0;
}

/** Send CH W or CH WB to a target server.
 * Handles chunking for large/multiline content.
 * @param[in] server Target storage server.
 * @param[in] target Channel name.
 * @param[in] msgid Message ID.
 * @param[in] timestamp Unix timestamp.
 * @param[in] sender Full sender mask.
 * @param[in] account Sender's account or "*".
 * @param[in] type_char Type character (P, N, T).
 * @param[in] content Message content.
 */
static void send_ch_write(struct Client *server, const char *target,
                          const char *msgid, const char *timestamp,
                          const char *sender, const char *account,
                          char type_char, const char *content)
{
  /* Check if content needs base64 encoding */
  if (!write_needs_encoding(content)) {
    /* Simple case: send as CH W */
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "W %s %s %s %s %s %c :%s",
                  target, msgid, timestamp, sender, account, type_char, content);
    return;
  }

  /* Base64 encode the content */
  size_t content_len = strlen(content);
  size_t b64_len = ((content_len + 2) / 3) * 4 + 1;
  char *b64 = MyMalloc(b64_len);
  if (!b64) {
    /* Fallback: truncate and send as plain */
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "W %s %s %s %s %s %c :[content too large]",
                  target, msgid, timestamp, sender, account, type_char);
    return;
  }

  ch_base64_encode(content, content_len, b64);
  size_t b64_total = strlen(b64);

  /* If it fits in one message, send complete WB message (no + marker) */
  if (b64_total <= CH_CHUNK_B64_SIZE) {
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "WB %s %s %s %s %s %c :%s",
                  target, msgid, timestamp, sender, account, type_char, b64);
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
        sendcmdto_one(&me, CMD_CHATHISTORY, server, "WB %s %s %s %s %s %c + :%s",
                      target, msgid, timestamp, sender, account, type_char, chunk);
      } else {
        sendcmdto_one(&me, CMD_CHATHISTORY, server, "WB %s %s %s %s %s %c :%s",
                      target, msgid, timestamp, sender, account, type_char, chunk);
      }
      first = 0;
    } else {
      /* Continuation chunk: just target, msgid, and marker */
      if (more) {
        sendcmdto_one(&me, CMD_CHATHISTORY, server, "WB %s %s + :%s",
                      target, msgid, chunk);
      } else {
        /* Final chunk: no + marker */
        sendcmdto_one(&me, CMD_CHATHISTORY, server, "WB %s %s :%s",
                      target, msgid, chunk);
      }
    }

    offset += chunk_size;
  }

  MyFree(b64);
}

/** Forward a channel message to the nearest storage server.
 * Called by non-STORE servers when FEAT_CHATHISTORY_WRITE_FORWARD is enabled.
 * @param[in] chptr Channel.
 * @param[in] sptr Sender client.
 * @param[in] msgid Message ID.
 * @param[in] timestamp Unix timestamp.
 * @param[in] type Message type (HISTORY_PRIVMSG, HISTORY_NOTICE, HISTORY_TAGMSG).
 * @param[in] content Message content.
 */
void forward_history_write(struct Channel *chptr, struct Client *sptr,
                           const char *msgid, const char *timestamp,
                           enum HistoryMessageType type, const char *content)
{
  struct DLink *lp;
  struct Client *nearest_storage = NULL;
  char sender[HISTORY_SENDER_LEN];
  const char *account;
  char type_char;

  /* Only forward if write forwarding is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_WRITE_FORWARD))
    return;

  /* Don't forward if we're a storage server (we handle it locally) */
  if (feature_bool(FEAT_CHATHISTORY_STORE))
    return;

  /* Build sender string: nick!user@host */
  if (cli_user(sptr))
    ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                  cli_name(sptr),
                  cli_user(sptr)->username,
                  cli_user(sptr)->host);
  else
    ircd_strncpy(sender, cli_name(sptr), sizeof(sender) - 1);

  /* Get account name if logged in, or "*" */
  account = (cli_user(sptr) && cli_user(sptr)->account[0])
            ? cli_user(sptr)->account : "*";

  /* Convert type to char */
  switch (type) {
    case HISTORY_PRIVMSG: type_char = 'P'; break;
    case HISTORY_NOTICE: type_char = 'N'; break;
    case HISTORY_TAGMSG: type_char = 'T'; break;
    default: type_char = 'P'; break;
  }

  /* Find nearest server with storage advertisement */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *server = lp->value.cptr;

    /* Skip U-lined servers (services) */
    if (is_ulined_server(server))
      continue;

    /* Must have storage advertisement */
    if (!has_chathistory_advertisement(server))
      continue;

    /* For now, just use the first one we find
     * TODO: Could optimize to find nearest by hop count
     */
    nearest_storage = server;
    break;
  }

  if (!nearest_storage) {
    Debug((DEBUG_DEBUG, "forward_history_write: No storage server found for %s",
           chptr->chname));
    return;
  }

  Debug((DEBUG_DEBUG, "forward_history_write: Forwarding %s to %s via CH W",
         chptr->chname, cli_name(nearest_storage)));

  send_ch_write(nearest_storage, chptr->chname, msgid, timestamp,
                sender, account, type_char, content);
}

/*
 * ============================================================================
 * Chathistory Federation Advertisement (CH A)
 * ============================================================================
 *
 * Servers advertise their chathistory storage capabilities to enable
 * intelligent federation routing. This avoids querying servers that
 * don't store history or don't have relevant channels.
 *
 * Protocol:
 *   CH A S <retention_days>  - Storage capability (sent at BURST)
 *   CH A R <retention_days>  - Retention update (on REHASH)
 *   CH A F :<channel> ...    - Full channel sync
 *   CH A + :<channel>        - Add channel
 *   CH A - :<channel>        - Remove channel (optional)
 */

/** Maximum servers we track advertisements for (matches NN_MAX_SERVER) */
#define MAX_AD_SERVERS 4096

/** Maximum channels to track per server in advertisement */
#define MAX_AD_CHANNELS 8192

/** Structure for chathistory storage advertisement from a server */
struct ChathistoryAd {
  int has_advertisement;           /**< Received any CH A? */
  int retention_days;              /**< Retention policy (0 = unlimited) */
  int is_storage_server;           /**< Does this server store history? */
  time_t last_update;              /**< When we last received an update */
  /* Layer 1: Channel presence tracking */
  int has_channel_ads;             /**< Received CH A F? */
  int channel_count;               /**< Number of channels in set */
  char **channels;                 /**< Array of channel names (lowercase) */
};

/** Global array of server advertisements, indexed by server numeric */
static struct ChathistoryAd *server_ads[MAX_AD_SERVERS];

/** Get server numeric index for array lookup.
 * @param[in] server Server client.
 * @return Numeric index (0-4095) or -1 if invalid.
 */
static int server_ad_index(struct Client *server)
{
  if (!server || !IsServer(server))
    return -1;
  /* Server numeric is 2 chars base64, giving 0-4095 range */
  return base64toint(cli_yxx(server));
}

/** Find or create advertisement entry for a server.
 * @param[in] server Server client.
 * @return Pointer to ChathistoryAd or NULL on failure.
 */
static struct ChathistoryAd *get_server_ad(struct Client *server)
{
  int idx = server_ad_index(server);
  if (idx < 0)
    return NULL;

  if (!server_ads[idx]) {
    server_ads[idx] = (struct ChathistoryAd *)MyCalloc(1, sizeof(struct ChathistoryAd));
  }
  return server_ads[idx];
}

/** Check if a server has advertised storage capability.
 * @param[in] server Server client.
 * @return 1 if server stores history, 0 otherwise.
 */
int has_chathistory_advertisement(struct Client *server)
{
  int idx = server_ad_index(server);
  if (idx < 0)
    return 0;
  if (!server_ads[idx])
    return 0;
  return server_ads[idx]->has_advertisement && server_ads[idx]->is_storage_server;
}

/** Get retention days for a server.
 * @param[in] server Server client.
 * @return Retention days (0 = unlimited), or -1 if no advertisement.
 */
int server_retention_days(struct Client *server)
{
  int idx = server_ad_index(server);
  if (idx < 0)
    return -1;
  if (!server_ads[idx] || !server_ads[idx]->has_advertisement)
    return -1;
  return server_ads[idx]->retention_days;
}

/** Clear advertisement entry for a server (on SQUIT).
 * @param[in] server Server client.
 */
void clear_server_ad(struct Client *server)
{
  int idx = server_ad_index(server);
  int i;
  if (idx < 0)
    return;
  if (server_ads[idx]) {
    /* Free channel array if present */
    if (server_ads[idx]->channels) {
      for (i = 0; i < server_ads[idx]->channel_count; i++) {
        if (server_ads[idx]->channels[i])
          MyFree(server_ads[idx]->channels[i]);
      }
      MyFree(server_ads[idx]->channels);
    }
    MyFree(server_ads[idx]);
    server_ads[idx] = NULL;
  }
}

/** Check if a server has channel-level advertisements (Layer 1).
 * @param[in] server Server client.
 * @return 1 if server has channel ads, 0 otherwise.
 */
static int has_channel_advertisement(struct Client *server)
{
  int idx = server_ad_index(server);
  if (idx < 0)
    return 0;
  if (!server_ads[idx])
    return 0;
  return server_ads[idx]->has_channel_ads;
}

/** Check if a server advertises a specific channel.
 * @param[in] server Server client.
 * @param[in] channel Channel name to check.
 * @return 1 if server advertises the channel, 0 otherwise.
 */
static int server_advertises_channel(struct Client *server, const char *channel)
{
  struct ChathistoryAd *ad;
  int idx = server_ad_index(server);
  char lowerchan[CHANNELLEN + 1];
  int i;

  if (idx < 0 || !server_ads[idx])
    return 0;

  ad = server_ads[idx];
  if (!ad->has_channel_ads || !ad->channels)
    return 0;

  /* Lowercase the channel name for comparison */
  ircd_strncpy(lowerchan, channel, CHANNELLEN);
  lowerchan[CHANNELLEN] = '\0';
  for (i = 0; lowerchan[i]; i++)
    lowerchan[i] = ToLower(lowerchan[i]);

  /* Linear search - could use hash table for very large sets */
  for (i = 0; i < ad->channel_count; i++) {
    if (ad->channels[i] && strcmp(ad->channels[i], lowerchan) == 0)
      return 1;
  }

  return 0;
}

/** Add a channel to a server's advertisement set.
 * @param[in] server Server client.
 * @param[in] channel Channel name to add.
 * @return 1 if added (new), 0 if already present or error.
 */
static int add_server_channel_ad(struct Client *server, const char *channel)
{
  struct ChathistoryAd *ad;
  char lowerchan[CHANNELLEN + 1];
  int i;

  ad = get_server_ad(server);
  if (!ad)
    return 0;

  /* Lowercase the channel name */
  ircd_strncpy(lowerchan, channel, CHANNELLEN);
  lowerchan[CHANNELLEN] = '\0';
  for (i = 0; lowerchan[i]; i++)
    lowerchan[i] = ToLower(lowerchan[i]);

  /* Allocate channels array if needed */
  if (!ad->channels) {
    ad->channels = (char **)MyCalloc(MAX_AD_CHANNELS, sizeof(char *));
    if (!ad->channels)
      return 0;
    ad->channel_count = 0;
  }

  /* Check if already present */
  for (i = 0; i < ad->channel_count; i++) {
    if (ad->channels[i] && strcmp(ad->channels[i], lowerchan) == 0)
      return 0;  /* Already present */
  }

  /* Add if room */
  if (ad->channel_count >= MAX_AD_CHANNELS)
    return 0;

  ad->channels[ad->channel_count] = (char *)MyMalloc(strlen(lowerchan) + 1);
  if (!ad->channels[ad->channel_count])
    return 0;

  strcpy(ad->channels[ad->channel_count], lowerchan);
  ad->channel_count++;

  return 1;
}

/** Remove a channel from a server's advertisement set.
 * @param[in] server Server client.
 * @param[in] channel Channel name to remove.
 * @return 1 if removed, 0 if not found.
 */
static int remove_server_channel_ad(struct Client *server, const char *channel)
{
  struct ChathistoryAd *ad;
  char lowerchan[CHANNELLEN + 1];
  int i;

  ad = get_server_ad(server);
  if (!ad || !ad->channels)
    return 0;

  /* Lowercase the channel name */
  ircd_strncpy(lowerchan, channel, CHANNELLEN);
  lowerchan[CHANNELLEN] = '\0';
  for (i = 0; lowerchan[i]; i++)
    lowerchan[i] = ToLower(lowerchan[i]);

  /* Find and remove */
  for (i = 0; i < ad->channel_count; i++) {
    if (ad->channels[i] && strcmp(ad->channels[i], lowerchan) == 0) {
      MyFree(ad->channels[i]);
      /* Shift remaining entries down */
      for (; i < ad->channel_count - 1; i++) {
        ad->channels[i] = ad->channels[i + 1];
      }
      ad->channels[ad->channel_count - 1] = NULL;
      ad->channel_count--;
      return 1;
    }
  }

  return 0;
}

/** Clear all channel advertisements for a server (before CH A F).
 * @param[in] server Server client.
 */
static void clear_server_channel_ads(struct Client *server)
{
  struct ChathistoryAd *ad;
  int i;

  ad = get_server_ad(server);
  if (!ad)
    return;

  if (ad->channels) {
    for (i = 0; i < ad->channel_count; i++) {
      if (ad->channels[i])
        MyFree(ad->channels[i]);
      ad->channels[i] = NULL;
    }
    ad->channel_count = 0;
  }
  ad->has_channel_ads = 0;
}

/** Convert numeric index back to base64 string (helper for stats).
 * @param[in] n Numeric value.
 * @return Pointer to static string.
 */
static const char *int_to_base64_str(unsigned int n)
{
  static char buf[8];
  /* For server numerics (2 chars in base64), limited to 64*64 = 4096 */
  if (n < 64) {
    inttobase64(buf, n, 1);
  } else {
    inttobase64(buf, n, 2);
  }
  return buf;
}

/** Report chathistory advertisement state for STATS A.
 * Shows which servers have advertised chathistory storage capability.
 * @param[in] to Client requesting stats.
 * @param[in] sd Stats descriptor.
 * @param[in] param Extra parameter (unused).
 */
void chathistory_report_ads(struct Client *to, const struct StatDesc *sd, char *param)
{
  int i;
  int storage_count = 0;
  int total_count = 0;

  (void)sd;
  (void)param;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "A :Chathistory Federation Advertisements");

  /* Iterate through all server slots */
  for (i = 0; i < MAX_AD_SERVERS; i++) {
    struct Client *server;
    struct ChathistoryAd *ad = server_ads[i];
    char timebuf[32] = "never";

    if (!ad)
      continue;

    total_count++;

    /* Try to find the server by numeric index */
    server = FindNServer(int_to_base64_str(i));
    if (!server)
      continue;  /* Server entry exists but server not connected */

    if (ad->last_update > 0) {
      struct tm tm;
      gmtime_r(&ad->last_update, &tm);
      strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);
    }

    if (ad->is_storage_server) {
      storage_count++;
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "A :  %s: STORE retention=%d days (updated %s)",
                 cli_name(server),
                 ad->retention_days,
                 timebuf);
    } else if (ad->has_advertisement) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "A :  %s: advertisement present but not storage",
                 cli_name(server));
    }
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "A :Summary: %d storage server(s) of %d advertised",
             storage_count, total_count);

  /* Show our own status */
  if (feature_bool(FEAT_CHATHISTORY_STORE)) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "A :Local: STORE enabled, retention=%d days",
               feature_int(FEAT_CHATHISTORY_RETENTION));
  } else {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "A :Local: STORE disabled (relay only)");
  }
}

/*
 * ============================================================================
 * Channel Advertisement Sending (Layer 1)
 * ============================================================================
 */

/** Maximum size for CH A F channel list (leave room for command overhead) */
#define CH_A_F_MAX_SIZE 400

/** Context for channel advertisement enumeration callback */
struct ChannelAdCtx {
  struct Client *target;      /**< Target server or NULL for broadcast */
  char buffer[CH_A_F_MAX_SIZE + 1];
  int buffer_len;
  int total_sent;
};

/** Callback for building and sending CH A F messages.
 * Accumulates channels until buffer is full, then sends.
 */
static int channel_ad_callback(const char *channel, void *data)
{
  struct ChannelAdCtx *ctx = (struct ChannelAdCtx *)data;
  int chan_len = strlen(channel);

  /* Check if adding this channel would overflow buffer */
  if (ctx->buffer_len + chan_len + 1 > CH_A_F_MAX_SIZE) {
    /* Send current buffer */
    if (ctx->buffer_len > 0) {
      if (ctx->target) {
        sendcmdto_one(&me, CMD_CHATHISTORY, ctx->target, "A F :%s", ctx->buffer);
      } else {
        sendcmdto_serv_butone(&me, CMD_CHATHISTORY, NULL, "A F :%s", ctx->buffer);
      }
    }
    /* Reset buffer */
    ctx->buffer[0] = '\0';
    ctx->buffer_len = 0;
  }

  /* Add channel to buffer */
  if (ctx->buffer_len > 0) {
    ctx->buffer[ctx->buffer_len++] = ' ';
  }
  strcpy(ctx->buffer + ctx->buffer_len, channel);
  ctx->buffer_len += chan_len;
  ctx->total_sent++;

  return 0;  /* Continue enumeration */
}

/** Send channel advertisements to a specific server.
 * Called after END_OF_BURST_ACK to advertise our local history channels.
 * @param[in] server Server to send advertisements to.
 * @return Number of channels advertised, or -1 on error.
 */
int send_channel_advertisements(struct Client *server)
{
  struct ChannelAdCtx ctx;
  int count;

  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return 0;  /* Only storage servers advertise channels */

  ctx.target = server;
  ctx.buffer[0] = '\0';
  ctx.buffer_len = 0;
  ctx.total_sent = 0;

  count = history_enumerate_channels(channel_ad_callback, &ctx);
  if (count < 0)
    return -1;

  /* Send any remaining buffered channels */
  if (ctx.buffer_len > 0) {
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "A F :%s", ctx.buffer);
  }

  Debug((DEBUG_DEBUG, "CH A F: Sent %d channel advertisements to %s",
         ctx.total_sent, cli_name(server)));

  return ctx.total_sent;
}

/** Broadcast a new channel advertisement to all peer servers.
 * Called when first message is stored for a new channel.
 * @param[in] channel Channel name to advertise.
 */
void broadcast_channel_advertisement(const char *channel)
{
  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;  /* Only storage servers advertise channels */

  if (!channel || (channel[0] != '#' && channel[0] != '&'))
    return;  /* Only advertise channels, not DMs */

  Debug((DEBUG_DEBUG, "CH A +: Broadcasting new channel %s", channel));

  sendcmdto_serv_butone(&me, CMD_CHATHISTORY, NULL, "A + :%s", channel);
}

/** Broadcast a channel removal to all peer servers.
 * Called when a channel's last message is evicted/purged.
 * This is the callback function registered with history.c.
 * @param[in] channel Channel name that was emptied.
 */
static void broadcast_channel_removal(const char *channel)
{
  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;  /* Only storage servers advertise channels */

  if (!channel || (channel[0] != '#' && channel[0] != '&'))
    return;  /* Only advertise channels, not DMs */

  Debug((DEBUG_DEBUG, "CH A -: Broadcasting channel removal %s", channel));

  sendcmdto_serv_butone(&me, CMD_CHATHISTORY, NULL, "A - :%s", channel);
}

/** Initialize chathistory callbacks.
 * Registers the channel removal callback with the history subsystem.
 * Called after history_init() succeeds.
 */
void chathistory_init_callbacks(void)
{
  history_set_channel_removed_callback(broadcast_channel_removal);
  Debug((DEBUG_DEBUG, "chathistory: registered channel removal callback"));
}

/** Check if a server's retention window covers a given timestamp.
 * Used for federation query routing - skip servers whose retention
 * doesn't cover the query timeframe.
 * @param[in] server Server client.
 * @param[in] query_time Timestamp to check (0 = current time / LATEST query).
 * @return 1 if server's retention covers the timestamp, 0 otherwise.
 */
int server_retention_covers(struct Client *server, time_t query_time)
{
  int retention;

  /* No advertisement = unknown, include by default for backward compatibility */
  if (!has_chathistory_advertisement(server))
    return 0;

  retention = server_retention_days(server);

  /* Unlimited retention (0) covers everything */
  if (retention == 0 || retention == -1)
    return 1;

  /* No query time specified (e.g., LATEST query) = always covered */
  if (query_time == 0)
    return 1;

  /* Check if query timestamp falls within retention window */
  {
    time_t oldest_covered = CurrentTime - (retention * 86400);
    return (query_time >= oldest_covered);
  }
}

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

/** Check if a server is U-lined (services).
 * U-lined servers don't store chat history, so we skip them in federation.
 */
static int is_ulined_server(struct Client *server)
{
  return find_conf_byhost(cli_confs(server), cli_name(server), CONF_UWORLD) != NULL;
}

/** Count connected non-U-lined servers (real IRC servers only).
 * U-lined servers (services like X3) don't store chat history.
 * @deprecated Use count_storage_servers() for federation queries.
 */
static int count_servers(void)
{
  int count = 0;
  struct DLink *lp;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *server = lp->value.cptr;
    if (!is_ulined_server(server))
      count++;
  }

  return count;
}

/** Count servers that have advertised chathistory storage capability.
 * Only servers that sent CH A S are counted - these actually store history.
 * Optionally filters by retention window and channel advertisements.
 * @param[in] target Target channel/nick for Layer 1 filtering.
 * @param[in] query_time Timestamp for retention filtering (0 = no filter).
 * @return Number of storage-capable servers.
 */
static int count_storage_servers(const char *target, time_t query_time)
{
  int count = 0;
  struct DLink *lp;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *server = lp->value.cptr;

    /* Skip U-lined servers (services) */
    if (is_ulined_server(server))
      continue;

    /* Skip servers without storage advertisement */
    if (!has_chathistory_advertisement(server))
      continue;

    /* Skip servers whose retention doesn't cover query time */
    if (query_time != 0 && !server_retention_covers(server, query_time))
      continue;

    /* Layer 1: If server has channel-level ads, check if it has this target */
    if (target && has_channel_advertisement(server) &&
        !server_advertises_channel(server, target))
      continue;

    count++;
  }

  return count;
}

/** Send a federation query to storage servers
 * @param[in] sptr Client requesting history
 * @param[in] target Channel name
 * @param[in] subcmd Subcommand (LATEST, BEFORE, etc.)
 * @param[in] ref Reference string
 * @param[in] limit Maximum messages
 * @param[in] local_msgs Already-retrieved local messages
 * @param[in] local_count Number of local messages
 * @return Request ID or NULL on failure
 *
 * Phase 3: Advertisement-Based Routing
 * Only queries servers that have advertised chathistory storage (CH A S)
 * and whose retention window covers the query timeframe.
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
  time_t query_time = 0;
  enum HistoryRefType ref_type;
  const char *ref_value;

  /* Check if federation is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION))
    return NULL;

  /* Convert to efficient S2S format */
  s2s_subcmd = subcmd_to_s2s(subcmd);
  if (s2s_subcmd == '?')
    return NULL;  /* Unknown subcmd */

  if (!ref_to_s2s(ref, s2s_ref, sizeof(s2s_ref)))
    return NULL;  /* Invalid reference */

  /* Extract timestamp from reference for retention filtering.
   * For timestamp references, we can skip servers whose retention doesn't
   * cover the query time. For msgid or * references, we query all storage servers.
   */
  if (parse_reference(ref, &ref_type, &ref_value) == 0) {
    if (ref_type == HISTORY_REF_TIMESTAMP && ref_value) {
      query_time = (time_t)strtoul(ref_value, NULL, 10);
    }
    /* For HISTORY_REF_MSGID or HISTORY_REF_NONE, query_time stays 0 (no filter) */
  }

  /* Count storage-capable servers that cover the query timeframe.
   * Only servers that have sent CH A S are counted.
   * Layer 1: Also filters by channel advertisements if present.
   */
  server_count = count_storage_servers(target, query_time);
  if (server_count == 0)
    return NULL;  /* No storage servers to query */

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

  /* Send query to storage servers using efficient S2S format:
   * CH Q <target> <subcmd:1char> <ref:T/M prefix> <limit> <reqid>
   *
   * Only query servers that:
   * 1. Are not U-lined (services)
   * 2. Have advertised chathistory storage (CH A S)
   * 3. Have retention that covers the query timeframe
   * 4. (Layer 1) If server has channel-level ads, target must be advertised
   */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *server = lp->value.cptr;

    /* Skip U-lined servers (services don't store history) */
    if (is_ulined_server(server))
      continue;

    /* Skip servers without storage advertisement */
    if (!has_chathistory_advertisement(server))
      continue;

    /* Skip servers whose retention doesn't cover query time */
    if (query_time != 0 && !server_retention_covers(server, query_time))
      continue;

    /* Layer 1: If server has channel-level ads, check if it has this target */
    if (has_channel_advertisement(server) && !server_advertises_channel(server, target))
      continue;

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
 *   [SERVER] CH Z <reqid> <msgid> <ts> <type> <sender> <account> :<b64_zstd> - Compressed response
 *   [SERVER] CH E <reqid> <count>   - End response
 *
 * Subcmd codes: L=LATEST, B=BEFORE, A=AFTER, R=AROUND, W=BETWEEN, T=TARGETS
 * Ref format: T<timestamp>, M<msgid>, or * for none
 *
 * parv[0] = sender prefix
 * parv[1] = subcommand (Q, R, Z, or E)
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

    /* Phase 3: Propagate query to storage servers only.
     * Filter by advertisement (CH A S) and retention window.
     */
    {
      struct DLink *lp;
      time_t query_time = 0;

      /* Extract timestamp from S2S reference for retention filtering.
       * S2S format: T<timestamp>, M<msgid>, or * for none.
       */
      if (ref[0] == 'T' && ref[1] != '\0') {
        query_time = (time_t)strtoul(ref + 1, NULL, 10);
      }
      /* For M<msgid> or *, query_time stays 0 (no retention filter) */

      for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
        struct Client *server = lp->value.cptr;

        /* Skip source server */
        if (server == cptr)
          continue;

        /* Skip U-lined servers (services don't store history) */
        if (is_ulined_server(server))
          continue;

        /* Skip servers without storage advertisement */
        if (!has_chathistory_advertisement(server))
          continue;

        /* Skip servers whose retention doesn't cover query time */
        if (query_time != 0 && !server_retention_covers(server, query_time))
          continue;

        sendcmdto_one(sptr, CMD_CHATHISTORY, server, "Q %s %s %s %d %s",
                      target, query_subcmd_str, ref, limit, reqid);
      }
    }

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
     * Uses base64 chunked encoding for long content (>400 bytes).
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
  else if (strcmp(subcmd, "Z") == 0) {
    /* Compressed Response: Z <reqid> <msgid> <ts> <type> <sender> <account> :<b64_compressed>
     * Content is base64-encoded zstd-compressed data for bandwidth savings.
     */
    char *reqid, *msgid, *timestamp, *sender, *account, *b64_content;
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
    b64_content = (parc > 8) ? parv[8] : "";

    /* Find the request */
    req = find_fed_request(reqid);
    if (!req)
      return 0;

#ifdef USE_ZSTD
    /* Decode base64 then decompress */
    {
      char *decoded;
      size_t decoded_len;

      if (ch_base64_decode(b64_content, strlen(b64_content), &decoded, &decoded_len)) {
        char decompressed[HISTORY_CONTENT_LEN];
        size_t decompressed_len;

        if (decompress_data((unsigned char *)decoded, decoded_len,
                            (unsigned char *)decompressed, sizeof(decompressed) - 1,
                            &decompressed_len) >= 0) {
          decompressed[decompressed_len] = '\0';
          add_fed_message(req, msgid, timestamp, type, sender, account, decompressed);
        }
        MyFree(decoded);
      }
    }
#else
    /* No zstd support - can't decompress, skip this message */
    Debug((DEBUG_DEBUG, "CH Z: Received compressed response but USE_ZSTD not enabled"));
#endif
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
  else if (strcmp(subcmd, "A") == 0) {
    /* Advertisement: A <subtype> [params...]
     * Subtypes:
     *   S <retention_days>  - Storage capability
     *   R <retention_days>  - Retention update
     *   F :<channel> ...    - Full channel sync (future)
     *   + :<channel>        - Add channel (future)
     *   - :<channel>        - Remove channel (future)
     */
    char *subtype;
    struct ChathistoryAd *ad;

    if (parc < 3)
      return 0;

    subtype = parv[2];
    ad = get_server_ad(sptr);
    if (!ad)
      return 0;

    if (subtype[0] == 'S') {
      /* Storage capability: S <retention_days> */
      int retention;

      if (parc < 4)
        return 0;

      retention = atoi(parv[3]);
      ad->has_advertisement = 1;
      ad->is_storage_server = 1;
      ad->retention_days = retention;
      ad->last_update = CurrentTime;

      Debug((DEBUG_DEBUG, "CH A S: Server %s advertises storage with %d day retention",
             cli_name(sptr), retention));

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone(sptr, CMD_CHATHISTORY, cptr, "A S %d", retention);
    }
    else if (subtype[0] == 'R') {
      /* Retention update: R <retention_days> */
      int retention;

      if (parc < 4)
        return 0;

      retention = atoi(parv[3]);
      ad->retention_days = retention;
      ad->last_update = CurrentTime;

      Debug((DEBUG_DEBUG, "CH A R: Server %s updated retention to %d days",
             cli_name(sptr), retention));

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone(sptr, CMD_CHATHISTORY, cptr, "A R %d", retention);
    }
    else if (subtype[0] == 'F') {
      /* Full channel sync: F :<channel> <channel> ... (Layer 1) */
      char *chanlist;
      char *chan;
      char *saveptr = NULL;
      int added = 0;

      if (parc < 4)
        return 0;

      chanlist = parv[3];

      /* Clear existing channel ads before full sync */
      clear_server_channel_ads(sptr);

      /* Parse space-separated channel list */
      chan = strtok_r(chanlist, " ", &saveptr);
      while (chan) {
        if (chan[0] == '#' || chan[0] == '&') {
          add_server_channel_ad(sptr, chan);
          added++;
        }
        chan = strtok_r(NULL, " ", &saveptr);
      }

      ad->has_channel_ads = 1;
      ad->last_update = CurrentTime;

      Debug((DEBUG_DEBUG, "CH A F: Server %s advertises %d channels",
             cli_name(sptr), added));

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone(sptr, CMD_CHATHISTORY, cptr, "A F :%s", parv[parc - 1]);
    }
    else if (subtype[0] == '+') {
      /* Add channel: + :<channel> (Layer 1) */
      if (parc < 4)
        return 0;

      if (add_server_channel_ad(sptr, parv[3])) {
        Debug((DEBUG_DEBUG, "CH A +: Server %s added channel %s",
               cli_name(sptr), parv[3]));
      }
      ad->last_update = CurrentTime;

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone(sptr, CMD_CHATHISTORY, cptr, "A + :%s", parv[3]);
    }
    else if (subtype[0] == '-') {
      /* Remove channel: - :<channel> (Layer 1) */
      if (parc < 4)
        return 0;

      if (remove_server_channel_ad(sptr, parv[3])) {
        Debug((DEBUG_DEBUG, "CH A -: Server %s removed channel %s",
               cli_name(sptr), parv[3]));
      }
      ad->last_update = CurrentTime;

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone(sptr, CMD_CHATHISTORY, cptr, "A - :%s", parv[3]);
    }
    /* Unknown subtypes are silently ignored for forward compatibility */
  }
  else if (strcmp(subcmd, "W") == 0) {
    /* Write Forward (plain text): W <target> <msgid> <ts> <sender> <account> <type> :<content> */
    char *target, *msgid, *timestamp, *sender, *account, *type_str, *content;

    if (parc < 9)
      return 0;

    target = parv[2];
    msgid = parv[3];
    timestamp = parv[4];
    sender = parv[5];
    account = parv[6];
    type_str = parv[7];
    content = parv[8];

    Debug((DEBUG_DEBUG, "CH W: Received write forward for %s msgid=%s from %s",
           target, msgid, cli_name(sptr)));

    process_write_forward(target, msgid, timestamp, sender, account,
                          type_str[0], content);
  }
  else if (strcmp(subcmd, "WB") == 0) {
    /* Write Forward (base64): WB <target> <msgid> <ts> <sender> <account> <type> [+] :<b64>
     * Or continuation:        WB <target> <msgid> [+] :<b64>
     * + marker means more chunks coming. No + means final.
     */
    char *target, *msgid;
    const char *b64_data;
    struct WriteChunkEntry *chunk;
    char chunk_key[CHANNELLEN + HISTORY_MSGID_LEN + 2];
    int has_more = 0;
    int is_continuation = 0;

    if (parc < 4)
      return 0;

    target = parv[2];
    msgid = parv[3];

    /* Determine message format based on parc:
     * parc=5: continuation "WB <target> <msgid> :<b64>" (final)
     * parc=6: continuation "WB <target> <msgid> + :<b64>" (more)
     * parc=9: full "WB <target> <msgid> <ts> <sender> <account> <type> :<b64>" (complete)
     * parc=10: full "WB <target> <msgid> <ts> <sender> <account> <type> + :<b64>" (first)
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
    ircd_snprintf(0, chunk_key, sizeof(chunk_key), "%s:%s", target, msgid);

    if (is_continuation) {
      chunk = find_write_chunk(chunk_key);
      if (!chunk) {
        Debug((DEBUG_DEBUG, "CH WB: Continuation without start for %s", chunk_key));
        return 0;
      }
    } else {
      /* Parse type character */
      char type_char = parv[7][0];
      int type_int = 0;
      switch (type_char) {
        case 'P': type_int = HISTORY_PRIVMSG; break;
        case 'N': type_int = HISTORY_NOTICE; break;
        case 'T': type_int = HISTORY_TAGMSG; break;
      }
      chunk = create_write_chunk(target, msgid, parv[4], type_int, parv[5], parv[6]);
      if (!chunk) {
        Debug((DEBUG_DEBUG, "CH WB: No slots available for %s", chunk_key));
        return 0;
      }
    }

    /* Append base64 data */
    append_write_chunk_data(chunk, b64_data);

    if (!has_more) {
      /* Final chunk - decode and process */
      char *decoded;
      size_t decoded_len;
      char type_char;

      /* Convert type enum back to char for process_write_forward */
      switch (chunk->type) {
        case HISTORY_PRIVMSG: type_char = 'P'; break;
        case HISTORY_NOTICE: type_char = 'N'; break;
        case HISTORY_TAGMSG: type_char = 'T'; break;
        default: type_char = 'P'; break;
      }

      if (ch_base64_decode(chunk->b64_data, chunk->b64_len, &decoded, &decoded_len)) {
        Debug((DEBUG_DEBUG, "CH WB: Decoded %zu bytes for %s", decoded_len, target));
        process_write_forward(chunk->target, chunk->msgid, chunk->timestamp,
                              chunk->sender, chunk->account, type_char, decoded);
        MyFree(decoded);
      } else {
        Debug((DEBUG_DEBUG, "CH WB: Base64 decode failed for %s", target));
      }
      free_write_chunk(chunk);
    }
  }

  return 0;
}
