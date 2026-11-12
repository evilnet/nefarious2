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
#include "chathistory_ephemeral.h"
#include "chathistory_merge.h"
#include "chathistory_presence.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "history_trim_codec.h"
#include "redact_index.h"   /* redaction catch-up query (design B) */
/* m_redact.c (handlers.h cannot be included here -- forward_history_write prototype nit) */
extern int redact_apply_row(struct Client *src, struct Channel *chptr, const char *msgid,
                            const char *redact_msgid, uint64_t time_ms, const char *reason,
                            const char *sender_str, const char *account_str, int show_always);
extern int redact_row_judge(const char *target, const char *msgid);
extern void redact_announce_local(struct Client *src, struct Channel *chptr,
                                  const char *msgid, const char *redact_msgid,
                                  uint64_t time_ms, const char *reason);
extern void redact_echo_requester(struct Client *sptr, const char *target,
                                  const char *msgid, const char *reason);
static void redact_catchup_kick(unsigned int store_num);   /* design B trigger (defined with the catch-up) */
static void rdx_retry_reset(int idx);    /* the catch-up retry (W5 Push F, I-3), with it */
static void rdx_retry_cancel(int idx);
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "metadata.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "replay.h"
#include "s_user.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "bouncer_session.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/* Forward declarations for functions used before definition */
static int is_ulined_server(struct Client *server);
int has_chathistory_advertisement(struct Client *server);
void broadcast_channel_advertisement(const char *channel);
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <openssl/evp.h>
#ifdef USE_ZSTD
#include <zstd.h>
#endif

/** Maximum batch ID length */
#define BATCH_ID_LEN 16

/* Chunk budgets are MEASURED per row against the 510-byte P10 line in
 * send_ch_response (read path) and send_ch_write (write-forward); the
 * old fixed 300/400 constants assumed a ~100-byte header and overflowed
 * on a long target/msgid/hostmask (audit 2026-09-06 #11, re-review R2). */

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
 * The R line and the first B line carry the row's client-only tags in the
 * compact tag region, @A<row time><row msgid>,C<tags> (W5 Task 2), toward
 * a peer that takes S2S tags (sendcmdto_one_ctags); the receiver keeps
 * them with the row.  The tags go verbatim, the server's own PM markers
 * (+evilnet.github.io/ssid= / rsid= / sid=) included: the requester's PM
 * naming reads them (replay.c), and strip_internal_tags removes them
 * before any client sees the row.  A continuation B line has no tags,
 * and Z needs none: its payload is the stored record, tags inside.
 * The tag region does not count against the line's body (msgq_vmake), so
 * the measured budgets below stand.
 * @param[in] sptr Target server.
 * @param[in] reqid Request ID.
 * @param[in] msg History message.
 */
static void send_ch_response(struct Client *sptr, const char *reqid,
                             struct HistoryMessage *msg)
{
  const char *account = msg->account[0] ? msg->account : "*";
  const char *content = msg->dyn_content ? msg->dyn_content : msg->content;
  int wire_type = msg->dyn_content ? HISTORY_MULTILINE : msg->type;
  uint64_t row_ms = history_parse_ms(msg->timestamp);
  char tbuf[8];
  size_t full, cont;

  ircd_snprintf(0, tbuf, sizeof(tbuf), "%d", wire_type);
  /* Content budget for one P10 line = 510 (BUFSIZE-2) minus this row's
   * header.  Measured per row so a long prod hostmask (sender) or
   * account no longer overflows the line and gets silently truncated
   * by msgq (audit 2026-09-06 #11).  The first/R/Z line carries the
   * full metadata; continuation B lines carry only reqid+msgid. */
  {
    size_t base = strlen(reqid) + strlen(msg->msgid) + strlen(msg->timestamp)
                + strlen(tbuf) + strlen(msg->sender) + strlen(account);
    size_t over = 3 /*:XX*/ + 4 /* CH B */ + 7 /* single spaces */ + 2 /* " :" */ + base;
    size_t cover = 3 + 4 + strlen(reqid) + 1 + strlen(msg->msgid) + 2 /* " +" */ + 2 /* " :" */;
    full = (over + 4 < 510) ? (size_t)(510 - over - 4) : 8;    /* -4 safety */
    full &= ~((size_t)3);                                      /* mult of 4 for b64 */
    cont = (cover + 4 < 510) ? (size_t)(510 - cover - 4) : 8;
    cont &= ~((size_t)3);
  }

  /* Compressed passthrough (Z) only when the whole b64 fits one line. */
  if (!msg->dyn_content && msg->raw_content && msg->raw_content_len > 0) {
    size_t b64_len = ((msg->raw_content_len + 2) / 3) * 4 + 1;
    if (b64_len - 1 <= full) {
      char *b64 = MyMalloc(b64_len);
      if (b64) {
        ch_base64_encode((const char *)msg->raw_content, msg->raw_content_len, b64);
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "Z %s %s %s %d %s %s :%s",
                      reqid, msg->msgid, msg->timestamp, wire_type,
                      msg->sender, account, b64);
        MyFree(b64);
        return;
      }
    }
  }

  /* Plain R only when the raw content has no newline AND fits one line. */
  if (!ch_needs_encoding(content) && strlen(content) <= full) {
    sendcmdto_one_ctags(&me, CMD_CHATHISTORY, sptr, row_ms, msg->msgid, msg->client_tags,
                        "R %s %s %s %d %s %s :%s",
                        reqid, msg->msgid, msg->timestamp, wire_type,
                        msg->sender, account, content);
    return;
  }

  /* Base64 + chunk to fit each line. */
  {
    size_t content_len = strlen(content);
    size_t b64_len = ((content_len + 2) / 3) * 4 + 1;
    char *b64 = MyMalloc(b64_len);
    size_t b64_total, offset = 0;
    int first = 1;
    if (!b64) {
      sendcmdto_one_ctags(&me, CMD_CHATHISTORY, sptr, row_ms, msg->msgid, msg->client_tags,
                          "R %s %s %s %d %s %s :%s",
                          reqid, msg->msgid, msg->timestamp, wire_type,
                          msg->sender, account, "[content too large]");
      return;
    }
    ch_base64_encode(content, content_len, b64);
    b64_total = strlen(b64);

    if (b64_total <= full) {
      sendcmdto_one_ctags(&me, CMD_CHATHISTORY, sptr, row_ms, msg->msgid, msg->client_tags,
                          "B %s %s %s %d %s %s :%s",
                          reqid, msg->msgid, msg->timestamp, wire_type,
                          msg->sender, account, b64);
      MyFree(b64);
      return;
    }

    while (offset < b64_total) {
      size_t budget = first ? full : cont;
      size_t remaining = b64_total - offset;
      size_t chunk_size = remaining > budget ? budget : remaining;
      int more = (offset + chunk_size < b64_total);
      char chunk[520];
      if (chunk_size > sizeof(chunk) - 1)
        chunk_size = sizeof(chunk) - 1;
      memcpy(chunk, b64 + offset, chunk_size);
      chunk[chunk_size] = '\0';
      if (first) {
        sendcmdto_one_ctags(&me, CMD_CHATHISTORY, sptr, row_ms, msg->msgid, msg->client_tags,
                            more ? "B %s %s %s %d %s %s + :%s" : "B %s %s %s %d %s %s :%s",
                            reqid, msg->msgid, msg->timestamp, wire_type,
                            msg->sender, account, chunk);
        first = 0;
      } else {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr,
                      more ? "B %s %s + :%s" : "B %s %s :%s",
                      reqid, msg->msgid, chunk);
      }
      offset += chunk_size;
    }
    MyFree(b64);
  }
}

/** Send a responder's rows to the requester @a to under @a reqid, in list
 * order.  A context child (history_attach_context: a reaction or a REDACT
 * of the row before it) is preceded by a CH C declaration naming its parent
 * -- the last non-context row sent -- so the requester splices it after
 * that parent, uncounted; older requesters ignore CH C and see the child as
 * an ordinary row.  The child's client-only tags (reactions live entirely
 * in them) ride the declaration: the R row's trailing param is the content,
 * which is empty for a TAGMSG.
 * @param[in] to Requester (the server the reply goes to).
 * @param[in] reqid Request ID.
 * @param[in] rows Rows, context children spliced in after their parents.
 * @param[in] parents 1: send every row.  0 (the children request, CH Q K;
 *   W5 Task 14): a non-context row is a stub that only names the parent of
 *   the children after it -- declare and send the children, never the stub.
 */
static void send_ch_rows(struct Client *to, const char *reqid, struct HistoryMessage *rows,
                         int parents)
{
  const char *last_parent = NULL;
  struct HistoryMessage *msg;

  for (msg = rows; msg; msg = msg->next) {
    if (msg->is_context && last_parent) {
      if (msg->client_tags[0]) {
        /* Measure the line like the R/B rows: client_tags is 512
         * wide and the header ~170, so msgq would cut a long tag
         * set mid-tag and the receiver stored the fragment
         * verbatim (re-review R13).  Drop whole tags from the
         * end at ';' boundaries until it fits. */
        char ctags[512];
        size_t over = 3 + 4 /* CH C */ + 4 /* spaces */ + 2 /* " :" */
                    + strlen(reqid) + strlen(last_parent) + strlen(msg->msgid);
        size_t room = (over + 4 < 510) ? (size_t)(510 - over - 4) : 0;
        ircd_strncpy(ctags, msg->client_tags, sizeof(ctags) - 1);
        ctags[sizeof(ctags) - 1] = '\0';
        while (strlen(ctags) > room) {
          char *semi = strrchr(ctags, ';');
          if (!semi) { ctags[0] = '\0'; break; }
          *semi = '\0';
        }
        if (ctags[0])
          sendcmdto_one(&me, CMD_CHATHISTORY, to, "C %s %s %s :%s",
                        reqid, last_parent, msg->msgid, ctags);
        else
          sendcmdto_one(&me, CMD_CHATHISTORY, to, "C %s %s %s",
                        reqid, last_parent, msg->msgid);
      } else
        sendcmdto_one(&me, CMD_CHATHISTORY, to, "C %s %s %s",
                      reqid, last_parent, msg->msgid);
    }
    else if (!msg->is_context) {
      last_parent = msg->msgid;
      if (!parents)
        continue;   /* a stub: it names the parent, it is not a row */
    }
    else if (!parents)
      continue;     /* a child with no parent before it: nothing to name */
    send_ch_response(to, reqid, msg);
  }
}

/** Message type names for formatting.
 * Non-static: shared with replay.c for async history delivery.
 */
const char *msg_type_cmd[] = {
  "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
  "KICK", "MODE", "TOPIC", "TAGMSG", "PRIVMSG", /* GAP rendered as PRIVMSG */
  "NICK", "REDACT",
  "PRIVMSG" /* MULTILINE rendered as PRIVMSG */
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
  if (ircd_strcmp(subcmd, "EXACT") == 0)   return 'X';
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
    case 'X': return "EXACT";
    case 'S': return "SEARCH";
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
void generate_batch_id(char *buf, size_t buflen, struct Client *sptr)
{
  static unsigned long batch_counter = 0;
  /* batch spec: a reference is ASCII letters, digits and/or hyphen.  The
   * process-unique counter alone satisfies uniqueness; the client numeric
   * it used to carry is base64 over [A-Za-z0-9[]] and put an illegal '['
   * or ']' in every batch id of ~3%% of clients (audit 2026-09-06 #27). */
  (void)sptr;
  ircd_snprintf(0, buf, buflen, "hist%lu", ++batch_counter);
}

/** "<subcommand> <target>" -- the spec's context for FAIL CHATHISTORY
 * INVALID_TARGET / MESSAGE_ERROR (the subcommand was missing; a parser
 * indexing the params positionally read the target as the subcommand;
 * audit 2026-09-06 #25). */
static const char *ch_fail_ctx(const char *subcmd, const char *target)
{
  static char buf[CHANNELLEN + 32];
  ircd_snprintf(0, buf, sizeof(buf), "%s %s", subcmd, (target && *target) ? target : "*");
  return buf;
}

/** A msgid selector the store cannot place on @a lookup_target (#73,
 * #214): not a row of that target and not an id of the form this server
 * family mints, so it carries no time either (a legacy id held elsewhere
 * or nowhere, garbage).  One answer for every subcommand -- LATEST too
 * (it used to answer as if the reference were "*") and either BETWEEN
 * bound: FAIL CHATHISTORY MESSAGE_ERROR <sub> <target> <msgid> :Unknown
 * message id, so the client falls back to a timestamp.  A well-formed id
 * the target does not hold is a time (history_msgid_ref_timestamp).
 * Called after the access check, on the target's store key: whether an
 * id resolves must not be learnt about a target the requester cannot
 * read.  Returns 1 when it sent the FAIL. */
static int fail_unknown_msgid(struct Client *sptr, const char *subcmd,
                              const char *target, const char *lookup_target,
                              enum HistoryRefType ref_type,
                              const char *ref_value)
{
  char ts[HISTORY_TIMESTAMP_LEN];
  static char ctx[CHANNELLEN + HISTORY_MSGID_LEN + 40];
  if (ref_type != HISTORY_REF_MSGID || !ref_value)
    return 0;
  if (history_msgid_ref_timestamp(lookup_target, ref_value, ts) >= 0)
    return 0;
  ircd_snprintf(0, ctx, sizeof(ctx), "%s %s %s", subcmd,
                (target && *target) ? target : "*", ref_value);
  send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ctx, "Unknown message id");
  return 1;
}

/** Check if message type should be sent to client.
 * Without draft/event-playback, only PRIVMSG and NOTICE are sent.
 * @param[in] sptr Client to check.
 * @param[in] type Message type.
 * @return 1 if should send, 0 if should skip.
 */
int should_send_message_type(struct Client *sptr, enum HistoryMessageType type)
{
  /* PRIVMSG, NOTICE, GAP markers, and TAGMSG are always sent.
   * TAGMSG is included without event-playback per chathistory ratification
   * discussion — reactions are message-like content, not events.
   * Only stored TAGMSGs pass this check (typing-only are filtered earlier). */
  if (type == HISTORY_PRIVMSG || type == HISTORY_NOTICE ||
      type == HISTORY_GAP || type == HISTORY_MULTILINE)
    return 1;

  /* TAGMSG is message-like content and does not need event-playback --
   * but message-tags says a server MUST NOT deliver TAGMSG to a client
   * that has not negotiated it (audit 2026-09-06 #17). */
  if (type == HISTORY_TAGMSG)
    return CapRecipientHas(sptr, CAP_MSGTAGS);

  /* REDACT requires message-redaction cap but NOT event-playback.
   * Per spec: "draft/event-playback is not required in order to include
   * REDACT messages in chathistory responses." */
  if (type == HISTORY_REDACT)
    return CapRecipientHas(sptr, CAP_DRAFT_REDACT);

  /* Other events (JOIN, PART, QUIT, KICK, MODE, NICK) require event-playback.
   * The CONNECTION's own caps decide (CapRecipientHas), like every tag
   * emission does -- CapActive is the bouncer session's UNION, which let a
   * sibling's event-playback deliver JOIN/PART rows to a connection that
   * never negotiated it (audit 2026-09-06). */
  return CapRecipientHas(sptr, CAP_DRAFT_EVENTPLAYBACK);
}

/** A stored TAGMSG whose client tags are ALL +typing (legacy rows from
 * before typing-only TAGMSGs stopped being stored).  Such a row is never
 * emitted, so it must not consume a page slot either. */
static int history_row_is_typing_only(const struct HistoryMessage *msg)
{
  const char *tags, *tp;

  if (msg->type != HISTORY_TAGMSG)
    return 0;
  tags = msg->client_tags[0] ? msg->client_tags
       : (msg->dyn_content ? msg->dyn_content : msg->content);
  if (!tags[0])
    return 1;
  for (tp = tags; tp && *tp; ) {
    const char *sep = strchr(tp, ';');
    size_t tlen = sep ? (size_t)(sep - tp) : strlen(tp);
    if (tlen < 7 || strncmp(tp, "+typing", 7) != 0 ||
        (tlen > 7 && tp[7] != '='))
      return 0;
    tp = sep ? sep + 1 : NULL;
  }
  return 1;
}

static int typing_only_veto(const struct HistoryMessage *msg, void *ctx)
{
  (void)ctx;
  return history_row_is_typing_only(msg);
}

/** Bit mask of the row types should_send_message_type() lets @a sptr
 * receive, for filtering INSIDE the walk (see HistoryRowFilter.type_mask).
 * Returns 0 (= no filtering) when every type passes. */
static unsigned int requester_type_mask(struct Client *sptr)
{
  unsigned int mask = 0, all = 0;
  int type;

  for (type = 0; type < HISTORY_TYPE_COUNT; type++) {
    all |= 1u << type;
    if (should_send_message_type(sptr, (enum HistoryMessageType)type))
      mask |= 1u << type;
  }
  return mask == all ? 0 : mask;
}

/** The row filter for a local requester's walk: the presence hook when
 * strict presence opened one (@a pf), else the caller's @a bare filter,
 * either way carrying the requester's type mask.  Never NULL. */
static struct HistoryRowFilter *query_row_filter(struct Client *sptr,
                                                 struct PresenceQueryFilter *pf,
                                                 struct HistoryRowFilter *bare)
{
  struct HistoryRowFilter *hook = presence_query_filter_hook(pf);

  if (!hook) {
    memset(bare, 0, sizeof(*bare));
    hook = bare;
  }
  hook->type_mask = requester_type_mask(sptr);
  hook->veto = typing_only_veto;
  hook->veto_ctx = NULL;
  return hook;
}

/** Copy @a in to @a out without the server's own reserved vendor tags
 * (`+evilnet.github.io/sid=`, `ssid=`, `rsid=`, `chathistory-gap`, and
 * the legacy `+afternet.org/sid=`).  Thin wrapper over the pure
 * ircd_strip_reserved_vendor_tags() (ircd_string.c) -- the same
 * filter ircd_relay.c's store_private_history() uses as defence in
 * depth on the way IN, built on ircd_reserved_vendor_tag(), the
 * single source of truth for this list, shared with parse.c's
 * capture-time reservation gate, so a future server-written tag only
 * needs adding there.  The PM markers exist for the ephemeral
 * participant check in check_history_access and for naming a
 * conversation after the right session (replay.c), and carry session
 * ids that are nobody else's business; `chathistory-gap` never
 * actually reaches stored client_tags (it's sent live, never stored),
 * so stripping it here is a no-op kept for the same reason reusing
 * the whole `+afternet.org/` namespace is: one list, not two to keep
 * in sync.
 * @return @a out (empty when nothing else was there). */
static const char *strip_internal_tags(const char *in, char *out, size_t outsz)
{
  return ircd_strip_reserved_vendor_tags(in, out, outsz);
}

/** Client line budget for the message body: 512 bytes for everything
 * after the tags (":<sender> <cmd> <target> :" + body + CRLF), the
 * tag section being separately bounded by message-tags. */
static size_t history_line_budget(const char *sender, const char *cmd,
                                  const char *target)
{
  size_t head = 1 + strlen(sender) + 1 + strlen(cmd) + 1 + strlen(target) + 2;
  return head + 2 < 510 ? 510 - head - 2 : 1;
}

/** Longest prefix of @a line (@a len bytes) that fits @a budget,
 * preferring the last space (kept in the part) and never splitting a
 * UTF-8 sequence. */
static size_t history_split_point(const char *line, size_t len, size_t budget)
{
  size_t i;
  if (len <= budget)
    return len;
  for (i = budget; i > 0; i--)
    if (line[i - 1] == ' ')
      return i;
  i = budget;
  while (i > 0 && (line[i] & 0xC0) == 0x80)
    i--;
  return i > 0 ? i : budget;
}

/** Emit one logical line as as many wire lines as the budget needs:
 * the first with @a pfx_first, the rest with @a pfx_cont.  The budget is
 * measured on the part after the tags. */
static void send_split_line(struct Client *sptr, const char *pfx_first,
                            const char *pfx_cont, const char *line, size_t len)
{
  const char *pfx = pfx_first;
  while (1) {
    const char *body = (pfx[0] == '@') ? strchr(pfx, ' ') : pfx;
    size_t head = body ? strlen(body + (pfx[0] == '@' ? 1 : 0)) : strlen(pfx);
    size_t budget = head + 2 < 510 ? 510 - head - 2 : 1;
    size_t n = history_split_point(line, len, budget);
    sendrawto_one(sptr, "%s%.*s", pfx, (int)n, line);
    if (n >= len)
      return;
    line += n;
    len -= n;
    pfx = pfx_cont;
  }
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
void send_history_message(struct Client *sptr, struct HistoryMessage *msg,
                           const char *target, const char *outer_batchid,
                                  const char *time_str, const char *cmd)
{
  char *separator;
  char *content = msg->dyn_content ? msg->dyn_content : msg->content;
  const char *ctx_tag = msg->is_context ? ";draft/chathistory-context" : "";

  /* Build tag prefix once, gating each tag behind its capability.
   * Format: "batch=X;time=T;msgid=M;account=A;ctx" or subset thereof.
   * This avoids duplicating cap checks across every sendrawto_one call. */
  char tags[512];
  int tpos = 0;
  int has_time = (time_str && *time_str && CapRecipientHas(sptr, CAP_SERVERTIME));
  int has_msgid = (msg->msgid[0] && CapRecipientHas(sptr, CAP_MSGTAGS));
  int has_account = (msg->account[0] && CapRecipientHas(sptr, CAP_ACCOUNTTAG));

  if (outer_batchid) {
    tpos += ircd_snprintf(0, tags + tpos, sizeof(tags) - tpos, "batch=%s", outer_batchid);
  }
  if (has_time) {
    if (tpos) tags[tpos++] = ';';
    tpos += ircd_snprintf(0, tags + tpos, sizeof(tags) - tpos, "time=%s", time_str);
  }
  if (has_msgid) {
    if (tpos) tags[tpos++] = ';';
    tpos += ircd_snprintf(0, tags + tpos, sizeof(tags) - tpos, "msgid=%s", msg->msgid);
  }
  if (has_account) {
    if (tpos) tags[tpos++] = ';';
    tpos += ircd_snprintf(0, tags + tpos, sizeof(tags) - tpos, "account=%s", msg->account);
  }
  if (ctx_tag[0]) {
    /* ctx_tag starts with ';' already */
    tpos += ircd_snprintf(0, tags + tpos, sizeof(tags) - tpos, "%s", ctx_tag);
  }
  tags[tpos] = '\0';

  /* QUIT and NICK messages don't take a channel target in IRC protocol.
   * Format: :sender QUIT :reason  /  :oldnick!u@h NICK :newnick
   * Both are always single-line so handle them early and return. */
  if (msg->type == HISTORY_QUIT || msg->type == HISTORY_NICK) {
    if (tpos)
      sendrawto_one(sptr, "@%s :%s %s :%s", tags, msg->sender, cmd, content);
    else
      sendrawto_one(sptr, ":%s %s :%s", msg->sender, cmd, content);
    return;
  }

  /* JOIN content is empty — don't emit a trailing ":" with nothing after it.
   * Correct IRC: "JOIN #channel" (no trailing parameter). */
  if (msg->type == HISTORY_JOIN) {
    if (tpos)
      sendrawto_one(sptr, "@%s :%s %s %s", tags, msg->sender, cmd, target);
    else
      sendrawto_one(sptr, ":%s %s %s", msg->sender, cmd, target);
    return;
  }

  /* PART with empty reason — don't emit trailing ":".
   * PART with reason uses trailing normally via generic path. */
  if (msg->type == HISTORY_PART && (!content[0])) {
    if (tpos)
      sendrawto_one(sptr, "@%s :%s %s %s", tags, msg->sender, cmd, target);
    else
      sendrawto_one(sptr, ":%s %s %s", msg->sender, cmd, target);
    return;
  }

  /* MODE content is stored as "-o nick" or "+o nick" (mode string + params).
   * Correct IRC: "MODE #chan -o nick" — params must be space-separated. */
  if (msg->type == HISTORY_MODE) {
    if (tpos)
      sendrawto_one(sptr, "@%s :%s %s %s %s", tags, msg->sender, cmd, target, content);
    else
      sendrawto_one(sptr, ":%s %s %s %s", msg->sender, cmd, target, content);
    return;
  }

  /* KICK content is stored as "nick :reason" — emit raw after target.
   * Correct IRC: "KICK #channel nick :reason" */
  if (msg->type == HISTORY_KICK) {
    if (tpos)
      sendrawto_one(sptr, "@%s :%s %s %s %s", tags, msg->sender, cmd, target, content);
    else
      sendrawto_one(sptr, ":%s %s %s %s", msg->sender, cmd, target, content);
    return;
  }

  /* REDACT content is stored as "target_msgid :reason" or just "target_msgid".
   * IRC format: REDACT #channel target_msgid [:reason] */
  if (msg->type == HISTORY_REDACT) {
    if (tpos)
      sendrawto_one(sptr, "@%s :%s %s %s %s", tags, msg->sender, cmd, target, content);
    else
      sendrawto_one(sptr, ":%s %s %s %s", msg->sender, cmd, target, content);
    return;
  }

  /* TAGMSG: client tags go in the @ prefix, not as a trailing parameter.
   * TAGMSG has no message body.
   * New format: client_tags field has the tags, content is empty.
   * Legacy format: content has the tags, client_tags is empty.
   * Format: @batch=X;time=T;msgid=M;+draft/react=val :sender TAGMSG #channel */
  if (msg->type == HISTORY_TAGMSG) {
    char ctags_buf[516];
    const char *ctags = strip_internal_tags(msg->client_tags[0] ? msg->client_tags : content,
                                            ctags_buf, sizeof(ctags_buf));
    if (tpos && *ctags)
      sendrawto_one(sptr, "@%s;%s :%s %s %s", tags, ctags, msg->sender, cmd, target);
    else if (tpos)
      sendrawto_one(sptr, "@%s :%s %s %s", tags, msg->sender, cmd, target);
    else if (*ctags)
      sendrawto_one(sptr, "@%s :%s %s %s", ctags, msg->sender, cmd, target);
    else
      sendrawto_one(sptr, ":%s %s %s", msg->sender, cmd, target);
    return;
  }

  /* Build client tags suffix for PRIVMSG/NOTICE replay.
   * Format: ";+reply=abc123" (leading semicolon for tag list concatenation).
   * Only emit for PRIVMSG/NOTICE when recipient has message-tags cap.
   * Note: ctx_tag and account are already in `tags` prefix above. */
  {
    char ctags_str[516] = "";

    if (msg->client_tags[0] &&
        (msg->type == HISTORY_PRIVMSG || msg->type == HISTORY_NOTICE ||
         msg->type == HISTORY_MULTILINE) &&
        CapRecipientHas(sptr, CAP_MSGTAGS)) {
      char kept[516];
      strip_internal_tags(msg->client_tags, kept, sizeof(kept));
      if (kept[0])
        ircd_snprintf(0, ctags_str, sizeof(ctags_str), ";%s", kept);
    }

  /* Unit Separators are honored only on genuine multiline records
   * (type-marked, or legacy-sentinel-resolved => dyn_content set).
   * A \x1F a client embedded in a plain message renders literally. */
  separator = (msg->type == HISTORY_MULTILINE || msg->dyn_content)
                ? strchr(content, '\x1F') : NULL;

  /* Wire prefixes.  Every logical line goes through send_split_line,
   * which re-splits a line longer than the client line budget at word
   * boundaries (audit #26: concat parts are joined at store time and
   * the split points are lost; a joined line over the limit was sent
   * whole, over the limit).  Continuation parts carry
   * draft/multiline-concat for a multiline client, and are plain
   * consecutive messages for the fallback tiers. */
  {
    char pfx_first[1100], pfx_cont[1100];
    int ml_client = CapRecipientHas(sptr, CAP_DRAFT_MULTILINE)
                    && CapRecipientHas(sptr, CAP_BATCH);
    size_t body_budget = history_line_budget(msg->sender, cmd, target);
    int first_over = strlen(content) > body_budget
                     && (!separator || (size_t)(separator - content) > body_budget);

  if ((separator || first_over) && ml_client) {
    /* Re-batch as draft/multiline nested inside chathistory batch */
    static unsigned long ml_counter = 0;
    char ml_batchid[BATCH_ID_LEN];
    char *line_start = content;
    char *line_end;

    /* Generate unique multiline batch ID */
    ircd_snprintf(0, ml_batchid, sizeof(ml_batchid), "ml%lu", ++ml_counter);   /* see generate_batch_id */

    /* Start nested multiline batch (inside outer chathistory batch).
     * Per multiline spec, server tags (time, msgid, account) and client tags
     * go on the BATCH + opener. The `tags` prefix already has these. */
    if (tpos) {
      if (ctags_str[0])
        sendrawto_one(sptr, "@%s%s :%s BATCH +%s draft/multiline %s",
                      tags, ctags_str, cli_name(&me), ml_batchid, target);
      else
        sendrawto_one(sptr, "@%s :%s BATCH +%s draft/multiline %s",
                      tags, cli_name(&me), ml_batchid, target);
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s draft/multiline %s",
                    ml_batchid, target);
    }

    /* Per multiline spec, inner lines only get @batch= tag.
     * Server tags (time, msgid, account) go on the BATCH opener. */
    ircd_snprintf(0, pfx_first, sizeof(pfx_first), "@batch=%s :%s %s %s :",
                  ml_batchid, msg->sender, cmd, target);
    ircd_snprintf(0, pfx_cont, sizeof(pfx_cont),
                  "@batch=%s;draft/multiline-concat :%s %s %s :",
                  ml_batchid, msg->sender, cmd, target);
    while (line_start && *line_start) {
      size_t len;
      line_end = strchr(line_start, '\x1F');
      len = line_end ? (size_t)(line_end - line_start) : strlen(line_start);
      send_split_line(sptr, pfx_first, pfx_cont, line_start, len);
      line_start = line_end ? line_end + 1 : NULL;
    }

    /* End nested multiline batch */
    if (outer_batchid) {
      sendrawto_one(sptr, "@batch=%s :%s BATCH -%s",
                    outer_batchid, cli_name(&me), ml_batchid);
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", ml_batchid);
    }
  } else if (separator && outer_batchid) {
    /* Tier 2: Client has chathistory batch but not multiline capability.
     * Send each line as separate PRIVMSG within the chathistory batch.
     * All lines share the same msgid so clients know they're related. */
    char *line_start = content;
    char *line_end;
    int first = 1;
    char rest[sizeof(tags)];

    /* Subsequent lines: the batch/time tags but NOT the msgid.  The
     * live fallback (send_multiline_fallback) puts the msgid on the
     * first line only; repeating it here made msgid-deduping clients
     * keep one line of every multiline in history and broke the
     * one-msgid-per-event rule (audit 2026-09-06 #14). */
    rest[0] = '\0';
    if (tpos) {
      const char *m = strstr(tags, "msgid=");
      if (m) {
        const char *e = strchr(m, ';');
        size_t pre = (size_t)(m - tags);
        /* drop "msgid=...;" or a trailing ";msgid=..." */
        if (e) {
          memcpy(rest, tags, pre);
          ircd_strncpy(rest + pre, e + 1, sizeof(rest) - pre - 1);
        } else {
          if (pre > 0 && tags[pre - 1] == ';')
            pre--;
          memcpy(rest, tags, pre);
          rest[pre] = '\0';
        }
      } else
        ircd_strncpy(rest, tags, sizeof(rest) - 1);
    }
    if (rest[0])
      ircd_snprintf(0, pfx_cont, sizeof(pfx_cont), "@%s :%s %s %s :",
                    rest, msg->sender, cmd, target);
    else
      ircd_snprintf(0, pfx_cont, sizeof(pfx_cont), ":%s %s %s :",
                    msg->sender, cmd, target);
    if (tpos)
      ircd_snprintf(0, pfx_first, sizeof(pfx_first), "@%s%s :%s %s %s :",
                    tags, ctags_str, msg->sender, cmd, target);
    else
      ircd_snprintf(0, pfx_first, sizeof(pfx_first), ":%s %s %s :",
                    msg->sender, cmd, target);

    while (line_start && *line_start) {
      size_t len;
      line_end = strchr(line_start, '\x1F');
      len = line_end ? (size_t)(line_end - line_start) : strlen(line_start);
      if (len > 0) {   /* multiline: MUST NOT send blank lines to a non-multiline client */
        /* First line gets all tags + client tags; its continuation parts
         * and every later line get the msgid-less tags. */
        send_split_line(sptr, first ? pfx_first : pfx_cont, pfx_cont, line_start, len);
        first = 0;
      }
      line_start = line_end ? line_end + 1 : NULL;
    }
  } else {
    /* Tier 3: No chathistory batch or no separators - the first logical
     * line only, re-split if it is over the wire. */
    size_t len = separator ? (size_t)(separator - content) : strlen(content);

    if (tpos)
      ircd_snprintf(0, pfx_first, sizeof(pfx_first), "@%s%s :%s %s %s :",
                    tags, ctags_str, msg->sender, cmd, target);
    else
      ircd_snprintf(0, pfx_first, sizeof(pfx_first), ":%s %s %s :",
                    msg->sender, cmd, target);
    ircd_snprintf(0, pfx_cont, sizeof(pfx_cont), ":%s %s %s :",
                  msg->sender, cmd, target);
    send_split_line(sptr, pfx_first, pfx_cont, content, len);
  }
  } /* end prefix scope */
  } /* end ctags_str scope */
}

/** Check if user has ops override privilege for a channel.
 * @param[in] sptr Client to check.
 * @param[in] chptr Channel to check (NULL for non-channel targets).
 * @return 1 if user has override, 0 otherwise.
 */
static int has_ops_override(struct Client *sptr, struct Channel *chptr)
{
  struct Membership *member;

  /* Check if ops override feature is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_OPS_OVERRIDE))
    return 0;

  /* IRCops always have override */
  if (IsOper(sptr) || IsAnOper(sptr))
    return 1;

  /* Check if user is channel op */
  if (chptr) {
    member = find_member_link(chptr, sptr);
    if (member && IsChanOp(member))
      return 1;
  }

  return 0;
}

/** Send a gap marker as a PRIVMSG with the +evilnet.github.io/chathistory-gap tag.
 * For channels, the source is the server (sender identity hidden).
 * For PMs, the source is the original sender.
 * @param[in] sptr Client to send to.
 * @param[in] target Target name.
 * @param[in] batchid Batch ID (or NULL if no batch).
 * @param[in] time_str ISO timestamp string.
 * @param[in] msgid Message ID.
 * @param[in] sender Original sender hostmask.
 * @param[in] count Number of collapsed gap markers.
 */
void send_gap_marker(struct Client *sptr, const char *target,
                      const char *batchid, const char *time_str,
                      const char *msgid, const char *sender,
                             int count)
{
  char content[128];
  int is_channel = IsChannelPrefix(*target);
  const char *source;

  if (count > 1)
    ircd_snprintf(0, content, sizeof(content), "[%d messages not stored]", count);
  else
    ircd_strncpy(content, "[message not stored]", sizeof(content) - 1);

  /* Channel gaps: from server (hide sender). PM gaps: from original sender. */
  source = is_channel ? cli_name(&me) : sender;

  /* Build tags with capability checks */
  {
    char gtags[256];
    int gpos = 0;
    if (batchid)
      gpos += ircd_snprintf(0, gtags + gpos, sizeof(gtags) - gpos, "batch=%s", batchid);
    if (time_str && *time_str && CapRecipientHas(sptr, CAP_SERVERTIME)) {
      if (gpos) gtags[gpos++] = ';';
      gpos += ircd_snprintf(0, gtags + gpos, sizeof(gtags) - gpos, "time=%s", time_str);
    }
    if (msgid && *msgid && CapRecipientHas(sptr, CAP_MSGTAGS)) {
      if (gpos) gtags[gpos++] = ';';
      gpos += ircd_snprintf(0, gtags + gpos, sizeof(gtags) - gpos, "msgid=%s", msgid);
    }
    /* Our extension, so our namespace (formerly +draft/chathistory-gap),
     * and a client-only tag only to a client that negotiated message-tags
     * (audit 2026-09-06 #29 / #17). */
    if (CapRecipientHas(sptr, CAP_MSGTAGS)) {
      if (gpos) gtags[gpos++] = ';';
      gpos += ircd_snprintf(0, gtags + gpos, sizeof(gtags) - gpos,
                            "+evilnet.github.io/chathistory-gap");
    }
    gtags[gpos] = '\0';

    if (gpos)
      sendrawto_one(sptr, "@%s :%s PRIVMSG %s :%s", gtags, source, target, content);
    else
      sendrawto_one(sptr, ":%s PRIVMSG %s :%s", source, target, content);
  }
}

/** Send history messages as a batch response.
 * @param[in] sptr Client to send to.
 * @param[in] target Target name for batch.
 * @param[in] messages List of messages to send.
 * @param[in] count Number of messages.
 * @param[in] ops_override If non-zero, user requested :full override.
 * @param[in] label Label string for labeled-response (NULL for auto-replay).
 */
static void send_history_batch(struct Client *sptr, const char *target,
                                struct HistoryMessage *messages, int count,
                                int ops_override, const char *label,
                                int complete)
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

  /* Start batch — include @label on BATCH +start if labeled-response
   * applies, and @draft/chathistory-end when the result is COMPLETE
   * (same completeness signal as the local auto-replay legs: absence
   * means the leg may have been truncated at the server cap). */
  if (CapRecipientHas(sptr, CAP_BATCH)) {
    const char *end_tag = complete ? "draft/chathistory-end;" : "";

    if (label && label[0] && feature_bool(FEAT_CAP_labeled_response) &&
        CapRecipientHas(sptr, CAP_LABELEDRESP)) {
      sendrawto_one(sptr, "@%slabel=%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                    end_tag, label, cli_name(&me), batchid, target);
      cli_label_responded(sptr) = 1;
    } else if (complete) {
      sendrawto_one(sptr, "@draft/chathistory-end :%s " MSG_BATCH_CMD " +%s chathistory %s",
                    cli_name(&me), batchid, target);
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s chathistory %s",
                    batchid, target);
    }
  }

  /* Send each message */
  for (msg = messages; msg; msg = msg->next) {
    /* Filter events based on event-playback capability */
    if (!should_send_message_type(sptr, msg->type))
      continue;

    /* Skip typing-only TAGMSGs (legacy data stored before typing filter fix).
     * Check if ALL tags are +typing — if any non-typing tag exists, keep it. */
    if (msg->type == HISTORY_TAGMSG) {
      const char *tags = msg->client_tags[0] ? msg->client_tags
                       : (msg->dyn_content ? msg->dyn_content : msg->content);
      int dominated_by_typing = 1;
      const char *tp = tags;
      if (!tags[0]) { dominated_by_typing = 1; }
      else while (tp && *tp) {
        const char *sep = strchr(tp, ';');
        size_t tlen = sep ? (size_t)(sep - tp) : strlen(tp);
        if (tlen < 7 || strncmp(tp, "+typing", 7) != 0 ||
            (tlen > 7 && tp[7] != '=')) {
          dominated_by_typing = 0;
          break;
        }
        tp = sep ? sep + 1 : NULL;
      }
      if (dominated_by_typing)
        continue;
    }

    /* Convert Unix timestamp to ISO 8601 for @time= tag (IRCv3 requires ISO) */
    if (history_unix_to_iso(msg->timestamp, iso_time, sizeof(iso_time)) == 0)
      time_str = iso_time;
    else
      time_str = msg->timestamp;  /* Fallback if conversion fails */

    /* Handle gap markers: collapse consecutive gaps from the same sender */
    if (msg->type == HISTORY_GAP) {
      int gap_count = 1;
      struct HistoryMessage *gap_start = msg;

      /* Count consecutive gaps from the same sender */
      while (msg->next && msg->next->type == HISTORY_GAP &&
             ircd_strcmp(msg->sender, msg->next->sender) == 0) {
        msg = msg->next;
        gap_count++;
      }

      /* Send collapsed gap marker using timestamp/msgid from first gap */
      send_gap_marker(sptr, target,
                       CapRecipientHas(sptr, CAP_BATCH) ? batchid : NULL,
                       time_str, gap_start->msgid, gap_start->sender,
                       gap_count);
      continue;
    }

    cmd = (msg->type <= HISTORY_MULTILINE) ? msg_type_cmd[msg->type] : "PRIVMSG";

    /* Send message, handling multiline content if present */
    send_history_message(sptr, msg, target,
                         CapRecipientHas(sptr, CAP_BATCH) ? batchid : NULL,
                         time_str, cmd);

    /* SendQ safety for federation paths (main path uses async replay) */
    if (!sendq_replay_ok(sptr))
      break;
  }

  /* End batch */
  if (CapRecipientHas(sptr, CAP_BATCH)) {
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
  }
}

/* Forward declaration — definition further down, after the per-subcommand
 * helpers it co-locates with.  Used here by chathistory_page_since. */
static int presence_filter_and_replay(struct Client *sptr,
                                       const char *target,
                                       struct HistoryMessage **head,
                                       int count, int ops_override,
                                       const char *label, int complete,
                                       const char *requested,
                                       const struct hm_idset *extra);
static int open_query_presence(struct Client *sptr, const char *lookup_target,
                               int ops_override,
                               struct PresenceQueryFilter **pf_out);
static int query_page_complete(struct HistoryRowFilter *hook, int count,
                               int limit);
static int redact_filter_messages(const char *target,
                                  struct HistoryMessage **head, int count,
                                  const struct hm_idset *extra);

/** Build one page of history since @a since_timestamp for @a sptr on
 * @a target the way the on-demand handlers do.  See history.h.  This is
 * the ONLY page builder the bouncer reattach replay may use (wave 1). */
int chathistory_page_since(struct Client *sptr, const char *target, int limit,
                           const char *since_timestamp, const char *since_msgid,
                           struct HistoryMessage **out, int *complete)
{
  struct HistoryMessage *messages = NULL;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  int count;

  *out = NULL;
  *complete = 1;
  if (!history_is_available())
    return -1;

  /* LATEST with a floor rather than AFTER: when more rows than the limit
   * exist, the page is the NEWEST ones.  Presence hook, type mask and
   * typing veto all run inside the walk, so `count < limit` means the
   * walk was exhausted. */
  if (open_query_presence(sptr, target, 0, &pf) < 0)
    return 0;   /* fail closed: nothing visible to replay */
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_latest_after(target, limit, since_timestamp,
                                     since_msgid, &messages, hook);
  *complete = query_page_complete(hook, count, limit);
  presence_query_filter_close(pf);
  if (count < 0)
    return -1;

  if (count > 0 && messages) {
    /* Same reply-side sequence as presence_filter_and_replay. */
    history_attach_context(target, messages);
    count = redact_filter_messages(target, &messages, count, NULL);
    count = presence_filter_messages(sptr, target, &messages, count, 0);
  }
  if (count <= 0 || !messages) {
    if (messages)
      history_free_messages(messages);
    return 0;
  }
  *out = messages;
  return count;
}

/** Normalize a PM target to the canonical nick1:nick2 format.
 * Clients can query with just a nickname (per IRCv3 spec), but internally
 * PM history is stored with target key "lowerNick:higherNick" (sorted).
 *
 * @param[in] sptr Client requesting history (their nick is the other party).
 * @param[in] target Target name (plain nick or already nick:nick format).
 * @param[out] normalized Buffer to store normalized target (minimum
 *             NICKLEN*2+2; callers now pass the shared CHANNELLEN+1-sized
 *             lookup buffer, which dominates).
 * @param[in] buflen Size of normalized buffer.
 * @return 0 on success, -1 on error (invalid nick, user not found, etc.)
 */
static int normalize_pm_target(struct Client *sptr, const char *target,
                                char *normalized, size_t buflen)
{
  const char *nick1, *nick2;
  const char *colon = strchr(target, ':');

  if (colon) {
    char n1[NICKLEN + 1], n2[NICKLEN + 1];
    size_t len1 = colon - target;
    int self_is_n1, self_is_n2;
    if (len1 > NICKLEN || len1 == 0)
      return -1;
    memcpy(n1, target, len1);
    n1[len1] = '\0';
    ircd_strncpy(n2, colon + 1, NICKLEN + 1);
    if (!n2[0])
      return -1;

    self_is_n1 = history_pm_identity_matches(sptr, n1, strlen(n1));
    self_is_n2 = history_pm_identity_matches(sptr, n2, strlen(n2));
    if (!self_is_n1 && !self_is_n2)
      return -1;

    if (normalized && buflen > 0) {
      char self_id[S2S_SESSID_BUFSIZE], other_id[S2S_SESSID_BUFSIZE];
      const char *other_typed = self_is_n1 ? n2 : n1;
      struct Client *oc = FindUser(other_typed);
      const char *a, *b;
      history_pm_identity(sptr, self_id, sizeof(self_id));
      if (oc) history_pm_identity(oc, other_id, sizeof(other_id));
      else    ircd_strncpy(other_id, other_typed, sizeof(other_id));
      if (ircd_strcmp(self_id, other_id) < 0) { a = self_id; b = other_id; }
      else                                    { a = other_id; b = self_id; }
      ircd_snprintf(0, normalized, buflen, "%s:%s", a, b);
    }
  } else {
    struct Client *target_client = FindUser(target);
    if (normalized && buflen > 0) {
      char self_id[S2S_SESSID_BUFSIZE], other_id[S2S_SESSID_BUFSIZE];
      const char *a, *b;
      history_pm_identity(sptr, self_id, sizeof(self_id));
      if (target_client) history_pm_identity(target_client, other_id, sizeof(other_id));
      else               ircd_strncpy(other_id, target, sizeof(other_id));
      if (ircd_strcmp(self_id, other_id) < 0) { a = self_id; b = other_id; }
      else                                    { a = other_id; b = self_id; }
      ircd_snprintf(0, normalized, buflen, "%s:%s", a, b);

      /* Not a live user: the name may be the nick a departed
       * unauthenticated correspondent last used -- what TARGETS lists
       * them as -- whose half of the key is their session id.  When
       * nothing is stored under the direct pair, find the pair by that
       * nick with the derivation TARGETS used to name it. */
      /* Also when the nick IS held right now but by an identity with no
       * rows under this pair: TARGETS named the conversation after the
       * stored rows' nick, so a reused nick must still reach them
       * (audit 2026-09-06 #19). */
      if (history_has_channel(normalized) == 0) {
        char pair[PM_PAIRKEY_BUFSIZE];
        if (replay_pm_pair_for_nick(sptr, target, pair, sizeof(pair)))
          ircd_strncpy(normalized, pair, buflen);
      }
    }
  }

  return 0;
}

/** Check if client can access history for a target.
 * @param[in] sptr Client requesting history.
 * @param[in] target Target name (channel, plain nick, or nick:nick format).
 * @param[out] normalized_target If non-NULL, receives the LMDB lookup key:
 *             the raw channel name if target is a channel, or the
 *             normalized nick1:nick2 format if target is a PM.
 * @param[in] normalized_len Size of normalized_target buffer; must be at
 *            least CHANNELLEN + 1 to hold a channel name without truncation
 *            (this also covers the smaller NICKLEN*2+2 PM case).
 * @return 0 if allowed, -1 if not.
 */
static int check_history_access(struct Client *sptr, const char *target,
                                 char *normalized_target, size_t normalized_len)
{
  struct Channel *chptr;

  if (IsChannelName(target)) {
    /* A future undersized caller would silently truncate channel names
     * sharing a long prefix, cross-leaking history between channels
     * (F-CH2).  Fail loudly in debug builds instead. */
    assert(normalized_len == 0 || normalized_len >= CHANNELLEN + 1);

    chptr = FindChannel(target);
    if (!chptr)
      return -1;

    /* Check if channel has +H (public history) - bypass all access checks */
    if (chptr->mode.exmode & EXMODE_PUBLICHISTORY) {
      if (normalized_target && normalized_len > 0)
        ircd_strncpy(normalized_target, chptr->chname, normalized_len);
      return 0;  /* Public history - allow access */
    }

    /* Must be a current member of the channel.
     * When CHATHISTORY_REQUIRE_AUTH is set, also require authentication
     * (Afternet policy).  When unset, current members can access history
     * without auth — they can already see messages in real-time. */
    if (!IsAccount(sptr) && feature_bool(FEAT_CHATHISTORY_REQUIRE_AUTH))
      return -1;
    if (!find_member_link(chptr, sptr))
      return -1;

    /* Channels: the store keys rows under the CANONICAL spelling
     * (chptr->chname -- every store site passes it) and build_key never
     * folds case, so the lookup key must be the canonical name too, not
     * the client's spelling.  "#linux" against a channel created as
     * "#Linux" used to scan an empty prefix and return an empty batch
     * (field report 2026-09-02).  Presence keys fold case themselves. */
    if (normalized_target && normalized_len > 0)
      ircd_strncpy(normalized_target, chptr->chname, normalized_len);
    return 0;
  } else {
    /* Private message history.  Two participant-check paths:
     *
     *   - Authed sptr: account-based.  normalize_pm_target verifies the
     *     sender's nick matches one half of the canonical pair-key.
     *
     *   - Ephemeral sptr (no account): session_id-based.  The stored
     *     PM record's client_tags carry a server-injected
     *     `+evilnet.github.io/sid=<sessid>` tag for the ephemeral
     *     participant (see ircd_relay.c store_private_history).  Auth
     *     requires that the caller's cli_session_id matches that tag
     *     in at least one record under the canonical pair-key.
     *
     *     Why sessid and not nick: nicks aren't owned for ephemerals,
     *     so a nick-only check would let "Mallory takes Alice's nick"
     *     read Alice's PM history.  Binding to session_id ensures only
     *     the same connection that participated can query — and the
     *     UUID v7 minting in bouncer_session.c's generate_sessid
     *     defends against collision.
     *
     *     Consequence: ephemerals see only PM history from their
     *     current session.  Disconnect = lose access.  By design — if
     *     persistent identity is needed, register an account. */
    if (IsAccount(sptr)) {
      if (normalize_pm_target(sptr, target, normalized_target, normalized_len) != 0)
        return -1;
      return 0;
    }
    if (cli_session_id(sptr)[0]) {
      char canonical[PM_PAIRKEY_BUFSIZE];
      if (normalize_pm_target(sptr, target, canonical, sizeof(canonical)) != 0)
        return -1;
      /* Two sources for ephemerals:
       *   - LMDB records bearing our sessid tag (Phase 5a — applies
       *     when the counterparty was authed at message time)
       *   - The in-memory ring (Phase C — applies for
       *     ephemeral↔ephemeral conversations, which never reach LMDB)
       * If either source has data, the sender clearly participated. */
      if (!history_pm_target_has_sessid(canonical, cli_session_id(sptr))
          && !chathistory_ephemeral_has_target(sptr, canonical))
        return -1;
      if (normalized_target && normalized_len > 0)
        ircd_strncpy(normalized_target, canonical, normalized_len);
      return 0;
    }
    /* Neither account nor session_id — shouldn't happen post-Phase A
     * (every Client gets a session_id at make_client) but fail safe. */
    return -1;
  }
}

/* Forward declarations for federation */
/** Set by start_fed_query when federation was wanted but no request slot
 * was free: the local page must then NOT claim completeness (audit #22). */
static int fed_start_capacity_miss = 0;
/** Set by start_fed_query (and start_fed_targets_query) when federation was
 * wanted but CHATHISTORY_FEDERATION is off here while a storage peer that
 * could be asked is linked (W5 Push F, I-1): the peer may hold what this
 * page lacks and is not asked, so, as for a missing slot, the page is not
 * complete.  Not a slot miss (STATS does not count it). */
static int fed_start_unasked = 0;
/** start_fed_query found a storage peer to ask and did not ask it: no free
 * request slot, or federation off here (callers: the page is partial unless
 * only its rows' context was wanted). */
#define fed_start_missed() (fed_start_capacity_miss || fed_start_unasked)
static struct FedRequest *start_fed_query(struct Client *sptr, const char *target,
                                           const char *requested,
                                           const char *subcmd, const char *ref,
                                           int limit,
                                           struct HistoryMessage *local_msgs,
                                           int local_count, int ops_override,
                                           const char *ref2, int local_complete);
static struct FedRequest *start_fed_query_ex(struct Client *sptr, const char *target,
                                              const char *requested,
                                              const char *subcmd, const char *ref,
                                              int limit,
                                              struct HistoryMessage *local_msgs,
                                              int local_count, int ops_override,
                                              const char *ref2, int local_complete,
                                              int own_label);
static void fed_request_set_why(struct FedRequest *req, int why, int partial);
static int count_storage_servers(const char *target, time_t query_time);
static int is_ulined_server(struct Client *server);
static void fed_timeout_callback(struct Event *ev);

/* Forward declarations for auto-replay federation */
struct AutoReplayContext;
static void autoreplay_next_channel(struct AutoReplayContext *ctx);
static void complete_autoreplay_channel(struct FedRequest *req);

/* Server advertisement tracking — defined here (before first use in
 * start_fed_targets_query), full struct definition is below. */
#define MAX_AD_SERVERS 4096
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
  /** Its CH A S came before the end of the burst that carries its state to
   * us (its own EB, or the EB of any server on the path to it): its absence
   * stays open, and its REDACT catch-up waits, until that EB
   * (chathistory_server_eob).  Goes with the entry (clear_server_ad). */
  unsigned char eob_pending;
  /** The feature letters of its last CH A S, as it sent them (ch_ad_letters:
   * [A-Za-z], at most CH_AD_LETTERS_MAX, known to this build or not), and
   * the CH_AD_* bits this build reads from them (K = it answers CH Q K, the
   * children request; W5 Task 14).  Both replaced on every CH A S, never
   * OR'd: a relinked server that dropped one starts without it.  The
   * letters go on verbatim with every relay and re-flood of the ad, so a
   * hop never strips a feature it does not know or has turned off itself
   * (fix round 1). */
  char letters[CH_AD_LETTERS_MAX + 1];
  unsigned int features;
};

/** " <letters>" for a CH A S relay or re-flood of @a ad, or "" when it
 * carried none (CH A S <days> [<features>]). */
static const char *ad_feature_suffix(const struct ChathistoryAd *ad, char *buf, size_t bufsz)
{
  if (!ad->letters[0])
    return "";
  ircd_snprintf(0, buf, bufsz, " %s", ad->letters);
  return buf;
}

/** Global array of server advertisements, indexed by server numeric */
static struct ChathistoryAd *server_ads[MAX_AD_SERVERS];

/* Storage-server ABSENCE intervals (2026-09-08, chathistory-partial).
 * Stores only diverge across a netsplit: while a storage server is away it
 * is not consulted and, before this table, forgotten.  Each server that
 * ever advertised storage keeps its last few absence intervals
 * [SQUIT, relink) (end 0 = still away).  A query whose span overlaps an
 * interval fans out even when the local page is full (the other side's
 * rows are otherwise hidden), and one that overlaps an OPEN interval is
 * answered partial.
 *
 * An absence is the ONLY record of what the other side said during the
 * split: the receive windows stay open across it (W5 Task 9), so a
 * forgotten absence lets a page over that split be answered locally and
 * complete.  So none is forgotten while a row of its time can still be
 * asked about: a full table folds its oldest interval into the next-oldest
 * (one interval from the older split's start to the newer one's end:
 * it can only make more pages fan out), and an interval ages out only once
 * its whole end second is at or below this store's floor as it is now
 * (history_live_floor_ms(); never with unlimited retention and no eviction
 * floor).  Push D review I-1.  Not the received floor's high-water mark
 * (history_local_floor_ms(), R40): the mark can sit above what was really
 * deleted (retention lowered and raised before age-out caught up, a clock
 * step), and an absence aged out early lets a full PM page over that split
 * -- PM pages never consult the windows -- be answered locally and
 * complete; one kept longer only adds fan-out (R41). */
#define MAX_ABSENCES 4
struct StorageAbsence {
  time_t start;
  time_t end;      /**< 0 while the server is away */
};
static struct StorageAbsence *absences[MAX_AD_SERVERS];

static void absence_open(int idx)
{
  struct StorageAbsence *a;
  int i, j;
  if (idx < 0 || idx >= MAX_AD_SERVERS)
    return;
  if (!absences[idx])
    absences[idx] = (struct StorageAbsence *)MyCalloc(MAX_ABSENCES, sizeof(struct StorageAbsence));
  a = absences[idx];
  for (i = 0; i < MAX_ABSENCES; i++)
    if (a[i].start && a[i].end == 0)
      return;   /* already open */
  /* Every slot is closed here.  Close the holes an aged-out slot left
   * (newest first), then, when the table is full, fold the oldest interval
   * into the next-oldest instead of dropping it. */
  for (i = j = 0; i < MAX_ABSENCES; i++)
    if (a[i].start)
      a[j++] = a[i];
  for (; j < MAX_ABSENCES; j++)
    a[j].start = a[j].end = 0;
  if (a[MAX_ABSENCES - 1].start && a[MAX_ABSENCES - 2].start
      && a[MAX_ABSENCES - 1].start < a[MAX_ABSENCES - 2].start)
    a[MAX_ABSENCES - 2].start = a[MAX_ABSENCES - 1].start;
  /* Shift the oldest out, newest at [0]. */
  memmove(&a[1], &a[0], sizeof(a[0]) * (MAX_ABSENCES - 1));
  a[0].start = CurrentTime;
  a[0].end = 0;
}

static void absence_close(int idx)
{
  struct StorageAbsence *a;
  int i;
  if (idx < 0 || idx >= MAX_AD_SERVERS || !absences[idx])
    return;
  a = absences[idx];
  for (i = 0; i < MAX_ABSENCES; i++)
    if (a[i].start && a[i].end == 0)
      a[i].end = CurrentTime;
}

/** Does [lo, hi] (unix seconds; 0 = unbounded on that side) overlap any
 * known storage-server absence?  Sets *open_hit when an overlapping
 * absence is still open (that server is away right now).  An interval
 * whose whole end second is at or below this store's floor as it is now
 * (history_live_floor_ms(), never the high-water mark: see the table's
 * comment) is dropped as it is met: no row of its time is left to ask
 * about here. */
static int absence_overlap(time_t lo, time_t hi, int *open_hit)
{
  int idx, i, any = 0;
  uint64_t floor_ms = history_live_floor_ms();
  time_t horizon = (time_t)(floor_ms / 1000ULL);

  if (lo == 0)
    lo = horizon;
  if (hi == 0)
    hi = CurrentTime;
  *open_hit = 0;
  for (idx = 0; idx < MAX_AD_SERVERS; idx++) {
    struct StorageAbsence *a = absences[idx];
    if (!a)
      continue;
    for (i = 0; i < MAX_ABSENCES; i++) {
      if (!a[i].start)
        continue;
      /* Its end is a whole second, inclusive (as the overlap test below
       * reads it): it ages out only once that second's last ms is at or
       * below the floor. */
      if (a[i].end && floor_ms
          && (uint64_t)a[i].end * 1000ULL + 999ULL <= floor_ms) {
        a[i].start = a[i].end = 0;   /* aged out */
        continue;
      }
      if (a[i].start <= hi && (a[i].end == 0 || a[i].end >= lo)) {
        any = 1;
        if (a[i].end == 0)
          *open_hit = 1;
      }
    }
  }
  return any;
}

/** Is a storage peer away right now (W5 Push F, I-1)?  An absence in the
 * table that is still open, or -- after this server restarted, before the
 * first storage peer's burst has ended -- the on-disk mark that it has had
 * one (history_recv_peer_missing): the table lives in memory, so a restart
 * forgets every absence, and the receive windows have not opened. */
static int storage_peers_linked(void);   /* below, with the ads */

static int store_away_now(void)
{
  int open_hit = 0;

  if (absence_overlap(0, 0, &open_hit) && open_hit)
    return 1;
  return history_recv_peer_missing();
}

/** Unix seconds of a client reference on @a target's store key (0 =
 * unresolvable). */
static time_t ref_unix_secs(const char *target, enum HistoryRefType t, const char *v)
{
  char buf[HISTORY_TIMESTAMP_LEN];
  if (!v || !*v)
    return 0;
  if (t == HISTORY_REF_MSGID) {
    if (history_msgid_ref_timestamp(target, v, buf) < 0)
      return 0;
    return (time_t)strtoul(buf, NULL, 10);
  }
  if (t == HISTORY_REF_TIMESTAMP) {
    if (history_iso_to_unix(v, buf, sizeof(buf)) == 0)
      return (time_t)strtoul(buf, NULL, 10);
    return (time_t)strtoul(v, NULL, 10);
  }
  return 0;
}

/** Which subcommand a page answers (claim_span: where it fills from). */
enum fed_page {
  FP_LATEST,     /**< newest first, back from now (r1: an optional "after" anchor) */
  FP_BEFORE,     /**< newest first, back from r1 */
  FP_AFTER,      /**< oldest first, on from r1 */
  FP_AROUND,     /**< half back from r1, the rest on from it */
  FP_BETWEEN     /**< from r1 toward r2 */
};

/** The span a page claims to answer completely, in unix seconds (0 = open:
 * no lower bound / up to now).  A page fills from its starting bound toward
 * the other one, so it claims everything from that start to where it
 * stopped: its last row when it filled up (count >= limit), the far bound
 * when the walk ran out:
 *   LATEST [r1]  back from now:    [full ? oldest : r1, now]
 *   BEFORE r1    back from r1:     [full ? oldest : open, r1]
 *   AFTER r1     on from r1:       [r1, full ? newest : now]
 *   BETWEEN      ascending:        [r1, full ? newest : r2]
 *                descending:       [full ? oldest : r2, r1]
 *   AROUND r1    back half full (at least limit/2 rows before r1) ? oldest
 *                : open, and the forward half full (count >= limit) ?
 *                newest : now.
 * A bound this server cannot resolve (0) is open, which claims more.
 * (The span used to be a full page's own first..last rows: a full LATEST
 * page whose newest row predates a stretch this server never received
 * claimed nothing newer was said -- W5 Task 9.  Rows before a reference in
 * the reference's own second are not counted for AROUND, which can only
 * open its lower end.) */
static void claim_span(enum fed_page page, struct HistoryMessage *rows,
                       int count, int limit, time_t r1, time_t r2, int desc,
                       time_t *lo, time_t *hi)
{
  struct HistoryMessage *m;
  time_t oldest = 0, newest = 0;
  int full = count >= limit && rows, before = 0;

  for (m = rows; m; m = m->next) {
    time_t t = (time_t)strtoul(m->timestamp, NULL, 10);
    if (!oldest || t < oldest)
      oldest = t;
    if (t > newest)
      newest = t;
    if (r1 && t < r1)
      before++;
  }
  switch (page) {
  case FP_LATEST:
    *lo = full ? oldest : r1;
    *hi = 0;
    break;
  case FP_BEFORE:
    *lo = full ? oldest : 0;
    *hi = r1;
    break;
  case FP_AFTER:
    *lo = r1;
    *hi = full ? newest : 0;
    break;
  case FP_BETWEEN:
    if (desc) {
      *lo = full ? oldest : r2;
      *hi = r1;
    } else {
      *lo = r1;
      *hi = full ? newest : r2;
    }
    break;
  case FP_AROUND:
  default:
    *lo = (rows && before >= limit / 2) ? oldest : 0;
    *hi = full ? newest : 0;
    break;
  }
}

/** Why a page federates (federation_wanted; the STATS counters). */
enum fed_reason {
  FED_WHY_NONE = 0,
  FED_WHY_UNRECEIVED,   /**< a channel span this server did not receive */
  FED_WHY_SHORT,        /**< a PM page that ran out (count < limit) */
  FED_WHY_ABSENCE,      /**< the span overlaps a storage peer's absence */
  FED_WHY_CONTEXT,      /**< the page's own span passed, but its rows' context
                             range [oldest row, now] did not */
  FED_WHY_COUNT
};

/** Federation started per reason, and wanted with no request slot free,
 * since this server started (STATS chathistory "Federation:"). */
static unsigned long fed_started_why[FED_WHY_COUNT];
static unsigned long fed_slot_misses;
/** Pages federated for their context only whose peers held a row inside
 * the page's own (received) span that this store lacks: a sign that a
 * receive window claimed what this server did not receive
 * (context_only_peer_rows; not counted when the peers' walks were wider). */
static unsigned long fed_window_misses;
/** The children request (CH Q K, W5 Task 14), since this server started:
 * stores asked and the lines sent them; children kept, and dropped (past
 * the request's cap, no parent, not a TAGMSG/REDACT); stores whose
 * last-line E never came before the request's timeout. */
static unsigned long fed_children_asked, fed_children_lines;
static unsigned long fed_children_rows, fed_children_dropped, fed_children_unanswered;

/** Count a start_fed_query outcome for a page that wanted it for @a why. */
static void fed_count(const struct FedRequest *req, int why)
{
  if (req)
    fed_started_why[why]++;
  else if (fed_start_capacity_miss)
    fed_slot_misses++;
}

void chathistory_fed_report(struct Client *to)
{
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Federation: started %lu (unreceived %lu, short %lu, "
             "absence %lu, context %lu), slot misses %lu, window misses %lu",
             fed_started_why[FED_WHY_UNRECEIVED] + fed_started_why[FED_WHY_SHORT]
             + fed_started_why[FED_WHY_ABSENCE] + fed_started_why[FED_WHY_CONTEXT],
             fed_started_why[FED_WHY_UNRECEIVED], fed_started_why[FED_WHY_SHORT],
             fed_started_why[FED_WHY_ABSENCE], fed_started_why[FED_WHY_CONTEXT],
             fed_slot_misses, fed_window_misses);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Federation children: asked %lu (lines %lu), rows %lu, "
             "dropped %lu, unanswered %lu",
             fed_children_asked, fed_children_lines, fed_children_rows,
             fed_children_dropped, fed_children_unanswered);
}

int chathistory_retention_advertised(void);   /* below; handlers.h */

/** The part of a channel page's claimed span [@a lo, @a hi] (unix seconds,
 * 0 = open; claim_span) that anyone can be asked about, in epoch ms,
 * widened to whole seconds:
 *   lo' = max(lo, the channel's creation, now - the widest retention a
 *             reachable store keeps, when that is limited),
 *   hi' = hi, else now -- never past now.
 * Both the receive windows and the absence table are asked about this span
 * (fix round 1, R31): before the channel existed, or past every store's
 * retention, nothing was said that a peer could hold. */
static void channel_span_clamp(const char *chname, time_t lo, time_t hi,
                               uint64_t *lo_ms, uint64_t *hi_ms)
{
  struct Channel *chptr = FindChannel(chname);
  uint64_t now = history_recv_now_ms();
  int widest = chathistory_retention_advertised();

  *lo_ms = (uint64_t)lo * 1000ULL;
  *hi_ms = hi ? (uint64_t)hi * 1000ULL + 999ULL : now;
  if (*hi_ms > now)
    *hi_ms = now;
  if (chptr && chptr->creationtime > 0
      && (uint64_t)chptr->creationtime * 1000ULL > *lo_ms)
    *lo_ms = (uint64_t)chptr->creationtime * 1000ULL;
  if (widest > 0) {
    /* The same clock as history_local_floor_ms()'s retention horizon, so a
     * store that keeps exactly the widest retention is not below its own
     * floor here. */
    uint64_t span = (uint64_t)widest * 1000ULL;
    uint64_t base = (uint64_t)CurrentTime * 1000ULL;
    uint64_t horizon = base > span ? base - span : 0;
    if (horizon > *lo_ms)
      *lo_ms = horizon;
  }
}

/** One channel range's check: is [@a lo, @a hi] (claimed, unix seconds,
 * 0 = open), clamped (channel_span_clamp), received here and clear of
 * every storage peer's absence?  An overlapping absence that is still open
 * sets *@a partial; so does a range this server never received while a
 * storage peer is away right now, wherever its absence started
 * (store_away_now: that peer may hold the range and cannot be asked; W5
 * Push F, I-1 -- before, such a page found nobody to ask and was answered
 * complete).  Callers checking a page's context range ignore *@a partial
 * (a context gap is never partial: user decision 2026-11-08 15:08).
 * @return FED_WHY_UNRECEIVED, FED_WHY_ABSENCE or FED_WHY_NONE. */
static int channel_range_check(const char *chname, time_t lo, time_t hi,
                               int *partial)
{
  uint64_t lo_ms, hi_ms;
  int open_hit = 0, absent;

  channel_span_clamp(chname, lo, hi, &lo_ms, &hi_ms);
  /* An inverted span (the page lies wholly before the channel's creation:
   * a registered channel's earlier incarnation) is never received; its
   * absence check keeps the span as claimed. */
  if (lo_ms <= hi_ms)
    absent = absence_overlap((time_t)(lo_ms / 1000ULL), (time_t)(hi_ms / 1000ULL),
                             &open_hit);
  else
    absent = absence_overlap(lo, hi, &open_hit);
  if (absent && open_hit)
    *partial = 1;
  if (!history_recv_covers(chname, lo_ms, hi_ms)) {
    if (store_away_now())
      *partial = 1;
    return FED_WHY_UNRECEIVED;
  }
  return absent ? FED_WHY_ABSENCE : FED_WHY_NONE;
}

/** Should this page fan out to the storage peers (W5 Task 9)?
 *   - a channel: when the span the page claims (claim_span), clamped
 *     (channel_span_clamp), is not one this server received
 *     (history_recv_covers), or overlaps a storage peer's absence -- a full
 *     page included, a short one over a received span not (it is
 *     complete).  A page that holds rows carries their context too
 *     (history_attach_context: reactions, REDACTs -- whatever their own
 *     time; REDACT context hides its parent from every requester), and a
 *     child can be born any time after its parent: such a page also needs
 *     [its claimed start, now] received and clear of absences, or it fans
 *     out (FED_WHY_CONTEXT; user decision 2026-11-08, option B) -- for its
 *     rows' context only (send_fed_response keeps the local rows).  An
 *     empty page has no parents: its own span decides;
 *   - a PM target: when the page is short, or the claimed span overlaps an
 *     absence.
 * An absence that is still open (that store is away now) and overlaps the
 * page's OWN span sets *@a partial; one that meets only the context range
 * does not (user decision 2026-11-08 15:08).  So does a storage peer away
 * now (store_away_now) when the page's own rows are the ones a peer may
 * complete -- a channel page whose own span was not received here, a PM
 * page that ran short -- wherever that peer's absence started (W5 Push F,
 * I-1).  Never for the context range: a page federated for its context
 * only is never partial (R38).
 * @return the reason (enum fed_reason), FED_WHY_NONE for no. */
static int federation_wanted(const char *target, enum fed_page page,
                             int count, int limit, struct HistoryMessage *rows,
                             enum HistoryRefType t1, const char *v1,
                             enum HistoryRefType t2, const char *v2,
                             int *partial)
{
  time_t r1 = ref_unix_secs(target, t1, v1), r2 = ref_unix_secs(target, t2, v2), lo, hi;
  int desc = 0, open_hit = 0, absent, why;

  if (page == FP_BETWEEN) {
    desc = history_between_descending(target, t1, v1, t2, v2);
    if (desc < 0)
      desc = r1 > r2;
  }
  claim_span(page, rows, count, limit, r1, r2, desc, &lo, &hi);
  if (!IsChannelName(target)) {
    absent = absence_overlap(lo, hi, &open_hit);
    if (absent && open_hit)
      *partial = 1;
    if (count < limit) {
      if (store_away_now())
        *partial = 1;   /* the peer that may complete it is away (I-1) */
      return FED_WHY_SHORT;
    }
    return absent ? FED_WHY_ABSENCE : FED_WHY_NONE;
  }
  why = channel_range_check(target, lo, hi, partial);
  /* The context range: from where the page's claim starts (at or before
   * its oldest row) up to now.  Only needed when the claim stops short of
   * now.  A gap there federates but never makes the page partial: its rows
   * are complete, only a reaction or REDACT may be missing (user decision
   * 2026-11-08 15:08), so an open absence there is not reported. */
  if (why == FED_WHY_NONE && count > 0 && rows && hi != 0) {
    int context_partial = 0;
    if (channel_range_check(target, lo, 0, &context_partial) != FED_WHY_NONE)
      why = FED_WHY_CONTEXT;
  }
  return why;
}

/** Single convergence point for chathistory result delivery.
 *
 * Combines the user-requested @a ops_override (parsed `:full`) with the
 * caller's real privilege via has_ops_override() — a non-op who passes
 * `:full` gets the filtered result like everyone else.  Then runs the
 * strict-presence filter (no-op unless FEAT_CHATHISTORY_STRICT_PRESENCE
 * is enabled, the target is a non-+H channel, and the override was
 * denied).  Finally hands the (possibly shortened) list to the replay
 * engine.
 *
 * Used by every local subcommand path (LATEST/BEFORE/AFTER/AROUND/
 * BETWEEN) and by the federation merge step — single funnel for
 * filter + ops semantics.
 *
 * @param head  Address of the message-list head; presence filter may
 *              unlink entries.  Ownership of the (possibly-shortened)
 *              list transfers to the replay engine on return.
 * @return     The post-filter message count.
 */
/** The most LEGACY children (indexed by an older build, untyped) a context
 * reaction's redaction lookup fetches (F-2; W5 Task 15 fix round 1).  A
 * child indexed by this build carries its link type and is never fetched
 * or counted (history_redact_lookup), so only old entries can reach this,
 * and no one can add those: past this many, with no REDACT among them, the
 * lookup answers unknown and the reaction is hidden (fail closed). */
#define CTX_REDACT_CHILDREN_MAX 32

/** F-2's lookups for one page, through hm_redact_filter: the store key,
 * one snapshot opened at the first lookup, and the lookups that came back
 * unknown. */
struct CtxRedactCheck {
  const char *target;
  struct HistoryRedactLookup *h;
  int opened;
  int unread;
};

/** Is the context row @a m redacted in this server's store (W5 Task 15,
 * F-2)?  REDACTs reach every store, a tombstone where the message is not
 * held (Push B), so the answer here is authoritative.  One walk of @a m's
 * own children per context row, in the page's one snapshot: each typed
 * child read off the index, at most CTX_REDACT_CHILDREN_MAX legacy ones
 * fetched.  -1 -- unreadable, too many legacy children, or no store
 * at all (a storeless server cannot know: every context reaction it was
 * sent is hidden, the binding fail-closed ruling) -- hides the row. */
static int ctx_redacted_here(const struct HistoryMessage *m, void *arg)
{
  struct CtxRedactCheck *c = (struct CtxRedactCheck *)arg;
  int r;

  if (!c->opened) {
    c->opened = 1;
    c->h = history_redact_lookup_open();
  }
  r = history_redact_lookup(c->h, c->target, m->msgid, CTX_REDACT_CHILDREN_MAX);
  if (r < 0)
    c->unread++;
  return r;
}

/** The reply-side redaction filter of every history page
 * (hm_redact_filter; W5 Task 15): drop the PRIVMSG/NOTICE/TAGMSG/MULTILINE
 * entries a REDACT entry of @a *head names, however many (F-6), or that
 * @a extra names (the targets of REDACTs a federated request dropped for
 * budget; NULL for none), a row one of whose children could not be read,
 * the reactions of a message dropped that way (F-7), and every context
 * entry this server's store knows redacted, or cannot read, or cannot ask
 * (no store) (F-2).  REDACT entries stay (the audit/visibility artifact the
 * client relies on, and the tombstone policy).  @a target is the store key
 * the page was read under.
 * @return the post-filter count (@a count when nothing was dropped). */
static int redact_filter_messages(const char *target,
                                  struct HistoryMessage **head, int count,
                                  const struct hm_idset *extra)
{
  struct CtxRedactCheck c;

  memset(&c, 0, sizeof(c));
  c.target = target;
  count = hm_redact_filter(head, count, extra, ctx_redacted_here, &c);
  if (c.h)
    history_redact_lookup_close(c.h);
  if (c.unread) {
    if (!history_is_available())
      Debug((DEBUG_DEBUG, "chathistory %s: no store to look up %d context "
             "row(s) in: not shown", target, c.unread));
    else
      log_write(LS_SYSTEM, L_WARNING, 0,
                "chathistory %s: %d context row(s) not shown, their redaction "
                "could not be read", target, c.unread);
  }
  return count;
}

static int presence_filter_and_replay(struct Client *sptr,
                                       const char *target,
                                       struct HistoryMessage **head,
                                       int count, int ops_override,
                                       const char *label, int complete,
                                       const char *requested,
                                       const struct hm_idset *extra)
{
  /* `complete` is REPLAY_COMPLETE | REPLAY_PARTIAL flags (plain 0/1
   * from older callers still means complete/not). */
  int real_override = 0;
  if (ops_override) {
    struct Channel *chptr =
        (target && IsChannelName(target)) ? FindChannel(target) : NULL;
    real_override = has_ops_override(sptr, chptr);
  }
  /* Drop redacted originals before presence + replay so redacted
   * content never reaches the wire for normal queries.  Audit access
   * (a later capability) would skip this filter. */
  count = redact_filter_messages(target, head, count, extra);
  count = presence_filter_messages(sptr, target, head, count, real_override);
  replay_start_batch(sptr, target, *head, count, real_override, label,
                     complete, requested);
  return count;
}

/** Presence-aware paging: arm the query-time presence filter for @a sptr
 * on @a lookup_target (see chathistory-presence-paging.md).  The user's
 * ":full" request only counts when has_ops_override() confirms it.
 * Returns 0 to proceed (*pf_out may be NULL = unfiltered walk) or -1
 * when the request must fail CLOSED -- the caller answers an empty,
 * complete page. */
static int open_query_presence(struct Client *sptr, const char *lookup_target,
                               int ops_override,
                               struct PresenceQueryFilter **pf_out)
{
  int rc = 0;
  int real_override = 0;

  if (ops_override) {
    struct Channel *chptr = (lookup_target && IsChannelName(lookup_target))
        ? FindChannel(lookup_target) : NULL;
    real_override = has_ops_override(sptr, chptr);
  }
  *pf_out = presence_query_filter_open(sptr, lookup_target, real_override, &rc);
  return (rc < 0) ? -1 : 0;
}

/** Completeness of a page produced by a (possibly filtered) walk: fewer
 * visible rows than the limit means the walk was exhausted -- unless
 * the raw-scan cap cut it short. */
static int query_page_complete(struct HistoryRowFilter *hook, int count,
                               int limit)
{
  if (hook && hook->truncated)
    return 0;
  return count < limit;
}

/** Is @a lookup_target a conversation held only in @a sptr's ephemeral
 * ring -- a DM between two parties without an account, never stored
 * (ircd_relay.c store_private_history), keyed by two session ids that no
 * stored pair ever is?  check_history_access admitted the requester by
 * its ring. */
static int ring_only_pair(struct Client *sptr, const char *lookup_target)
{
  return !IsChannelName(lookup_target) && !IsAccount(sptr)
      && cli_session_id(sptr)[0]
      && chathistory_ephemeral_has_target(sptr, lookup_target);
}

/** A selector's place among @a rows (the pair's ring entries): the row
 * with that msgid, else the time a decodable id carries, else unknown
 * (-1) -- the rule the store resolves selectors by; a timestamp is its
 * whole millisecond; "*" is no selector (1). */
static int ring_pos(const struct HistoryMessage *rows, enum HistoryRefType t,
                    const char *v, struct hm_pos *p)
{
  const struct HistoryMessage *m;

  p->msgid = NULL;
  p->ms = 0;
  if (t == HISTORY_REF_NONE || !v)
    return 1;
  if (t == HISTORY_REF_TIMESTAMP)
    return hm_targets_ref_ms(v, &p->ms) == 0 ? 0 : -1;
  for (m = rows; m; m = m->next)
    if (strcmp(m->msgid, v) == 0) {
      p->ms = history_parse_ms(m->timestamp);
      p->msgid = v;
      return 0;
    }
  p->ms = msgid_decode_time_ms(v);
  p->msgid = v;
  return p->ms ? 0 : -1;
}

/** Answer a subcommand for a conversation held only in @a sptr's ring
 * (ring_only_pair; issue 215 review B1).  The ring used to be read only
 * by LATEST, oldest entries first up to the limit, its selector ignored
 * and the end tag set whenever fewer than the limit came back; every
 * other subcommand walked the store, found nothing, and claimed the end.
 * Now every subcommand pages the ring by the store's rules
 * (hm_page_select): the requester's type mask and typing veto first
 * (uncounted, as inside a walk), selectors placed as the store places
 * them, the end tag only when nothing is left beyond the page.  The ring
 * is this server's alone: no federation. */
static int ring_answer(struct Client *sptr, const char *subcmd,
                       enum hm_page_op op, const char *target,
                       const char *lookup_target,
                       enum HistoryRefType t1, const char *v1,
                       enum HistoryRefType t2, const char *v2, int limit)
{
  struct HistoryMessage *rows = NULL, *page, **pp, *m;
  struct hm_pos p1, p2;
  unsigned int mask = requester_type_mask(sptr);
  int r1, r2, count = 0, complete = 1;

  chathistory_ephemeral_rows(sptr, lookup_target, &rows);
  r1 = ring_pos(rows, t1, v1, &p1);
  r2 = ring_pos(rows, t2, v2, &p2);
  if (r1 < 0 || r2 < 0) {
    static char ctx[CHANNELLEN + HISTORY_MSGID_LEN + 40];
    ircd_snprintf(0, ctx, sizeof(ctx), "%s %s %s", subcmd, target,
                  r1 < 0 ? v1 : v2);
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ctx, "Unknown message id");
    history_free_messages(rows);
    return 0;
  }
  for (pp = &rows; (m = *pp); ) {
    if ((mask && !(mask & (1u << m->type))) || history_row_is_typing_only(m)) {
      *pp = m->next;
      m->next = NULL;
      history_free_messages(m);
    } else
      pp = &m->next;
  }
  page = hm_page_select(rows, op, r1 == 0 ? &p1 : NULL, r2 == 0 ? &p2 : NULL,
                        limit, &count, &complete);
  presence_filter_and_replay(sptr, lookup_target, &page, count, 0,
                             cli_label(sptr), complete ? REPLAY_COMPLETE : 0,
                             target, NULL);
  return 0;
}

/** Handle CHATHISTORY LATEST subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] target Target channel or nick.
 * @param[in] ref_str Reference string.
 * @param[in] limit_str Limit string.
 * @param[in] ops_override If non-zero, user requested :full override.
 * @return 0 on success.
 */
static int chathistory_latest(struct Client *sptr, const char *target,
                               const char *ref_str, const char *limit_str,
                               int ops_override)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;
  int fed_why = FED_WHY_NONE, partial = 0;
  int complete = 1;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  char lookup_target[CHANNELLEN + 1];  /* must fit a channel name (CHANNELLEN) or a
                                       * PM identity pair-key (PM_PAIRKEY_BUFSIZE); CHANNELLEN+1 dominates */

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
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", ch_fail_ctx("LATEST", target),
              "No access to target");
    return 0;
  }
  if (fail_unknown_msgid(sptr, "LATEST", target, lookup_target, ref_type, ref_value))
    return 0;
  if (ring_only_pair(sptr, lookup_target))
    return ring_answer(sptr, "LATEST", HM_PAGE_LATEST, target, lookup_target,
                       ref_type, ref_value, HISTORY_REF_NONE, NULL, limit);

  /* Query local history using normalized target.  Presence-aware
   * paging: the walk skips rows outside the caller's presence without
   * counting them, so `count < limit` means the walk was exhausted. */
  if (open_query_presence(sptr, lookup_target, ops_override, &pf) < 0) {
    presence_filter_and_replay(sptr, lookup_target, &messages, 0,
                               ops_override, cli_label(sptr), 1, target, NULL);
    return 0;
  }
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_latest(lookup_target, ref_type, ref_value, limit,
                               &messages, hook);
  complete = query_page_complete(hook, count, limit);
  presence_query_filter_close(pf);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ch_fail_ctx("LATEST", target),
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  /* A channel page fans out when the span it claims was not received
   * here (the receive windows, W5 Task 9), a PM page when it is short;
   * either when the span overlaps a known store's absence, and then it is
   * partial while that store is still away (chathistory-partial,
   * 2026-09-08). */
  fed_why = federation_wanted(lookup_target, FP_LATEST, count, limit, messages,
                              ref_type, ref_value, HISTORY_REF_NONE, NULL, &partial);
  if (fed_why) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, target, "LATEST",
                                              ref_str, limit, messages, count,
                                              ops_override, NULL, complete);
    fed_count(req, fed_why);
    /* Federation wanted and a peer not asked (no slot, or federation off
     * here: fed_start_missed): withhold the end tag -- unless only the
     * rows' context was wanted (their own span is complete here). */
    if (!req && fed_start_missed() && fed_why != FED_WHY_CONTEXT) {
      complete = 0;
      partial = 1;
    }
    if (req)
      fed_request_set_why(req, fed_why, partial);
    if (req) {
      /* Federation started - response will be sent when complete */
      /* Note: messages ownership transferred to req */
      return 0;
    }
    /* Federation failed to start, fall through to local-only response */
  }

  /* Attach context messages (reactions, redacts) to their parents */
  history_attach_context(lookup_target, messages);
  /* Async replay — ownership of messages transfers to ReplayState */
  /* Completeness = QUERY EXHAUSTION: judged on the raw row count
   * BEFORE reply-side filters (redact originals, cap-gated REDACT
   * events, strict presence all legitimately shrink the emitted
   * page), and threaded down to the batch opener -- the replay layer
   * used to stamp every single-shot page final regardless. */
  count = presence_filter_and_replay(sptr, lookup_target, &messages, count,
                                     ops_override, cli_label(sptr),
                                     (complete ? REPLAY_COMPLETE : 0)
                                     | (partial ? REPLAY_PARTIAL : 0), target, NULL);

  return 0;
}

/** Handle CHATHISTORY BEFORE subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] target Target channel or nick.
 * @param[in] ref_str Reference string.
 * @param[in] limit_str Limit string.
 * @param[in] ops_override If non-zero, user requested :full override.
 * @return 0 on success.
 */
static int chathistory_before(struct Client *sptr, const char *target,
                               const char *ref_str, const char *limit_str,
                               int ops_override)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;
  int fed_why = FED_WHY_NONE, partial = 0;
  int complete = 1;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  char lookup_target[CHANNELLEN + 1];  /* must fit a channel name (CHANNELLEN) or a
                                       * PM identity pair-key (PM_PAIRKEY_BUFSIZE); CHANNELLEN+1 dominates */

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
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", ch_fail_ctx("BEFORE", target),
              "No access to target");
    return 0;
  }
  if (fail_unknown_msgid(sptr, "BEFORE", target, lookup_target, ref_type, ref_value))
    return 0;
  if (ring_only_pair(sptr, lookup_target))
    return ring_answer(sptr, "BEFORE", HM_PAGE_BEFORE, target, lookup_target,
                       ref_type, ref_value, HISTORY_REF_NONE, NULL, limit);

  if (open_query_presence(sptr, lookup_target, ops_override, &pf) < 0) {
    presence_filter_and_replay(sptr, lookup_target, &messages, 0,
                               ops_override, cli_label(sptr), 1, target, NULL);
    return 0;
  }
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_before(lookup_target, ref_type, ref_value, limit,
                               &messages, hook);
  complete = query_page_complete(hook, count, limit);
  presence_query_filter_close(pf);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ch_fail_ctx("BEFORE", target),
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  /* A channel page fans out when the span it claims was not received
   * here (the receive windows, W5 Task 9), a PM page when it is short;
   * either when the span overlaps a known store's absence, and then it is
   * partial while that store is still away (chathistory-partial,
   * 2026-09-08). */
  fed_why = federation_wanted(lookup_target, FP_BEFORE, count, limit, messages,
                              ref_type, ref_value, HISTORY_REF_NONE, NULL, &partial);
  if (fed_why) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, target, "BEFORE",
                                              ref_str, limit, messages, count,
                                              ops_override, NULL, complete);
    fed_count(req, fed_why);
    /* Federation wanted and a peer not asked (no slot, or federation off
     * here: fed_start_missed): withhold the end tag -- unless only the
     * rows' context was wanted (their own span is complete here). */
    if (!req && fed_start_missed() && fed_why != FED_WHY_CONTEXT) {
      complete = 0;
      partial = 1;
    }
    if (req)
      fed_request_set_why(req, fed_why, partial);
    if (req)
      return 0;
  }

  /* Attach context messages (reactions, redacts) to their parents */
  history_attach_context(lookup_target, messages);
  /* Async replay — ownership of messages transfers to ReplayState */
  /* Completeness = QUERY EXHAUSTION: judged on the raw row count
   * BEFORE reply-side filters (redact originals, cap-gated REDACT
   * events, strict presence all legitimately shrink the emitted
   * page), and threaded down to the batch opener -- the replay layer
   * used to stamp every single-shot page final regardless. */
  count = presence_filter_and_replay(sptr, lookup_target, &messages, count,
                                     ops_override, cli_label(sptr),
                                     (complete ? REPLAY_COMPLETE : 0)
                                     | (partial ? REPLAY_PARTIAL : 0), target, NULL);

  return 0;
}

/** Handle CHATHISTORY AFTER subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] target Target channel or nick.
 * @param[in] ref_str Reference string.
 * @param[in] limit_str Limit string.
 * @param[in] ops_override If non-zero, user requested :full override.
 * @return 0 on success.
 */
static int chathistory_after(struct Client *sptr, const char *target,
                              const char *ref_str, const char *limit_str,
                              int ops_override)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;
  int fed_why = FED_WHY_NONE, partial = 0;
  int complete = 1;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  char lookup_target[CHANNELLEN + 1];  /* must fit a channel name (CHANNELLEN) or a
                                       * PM identity pair-key (PM_PAIRKEY_BUFSIZE); CHANNELLEN+1 dominates */

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
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", ch_fail_ctx("AFTER", target),
              "No access to target");
    return 0;
  }
  if (fail_unknown_msgid(sptr, "AFTER", target, lookup_target, ref_type, ref_value))
    return 0;
  if (ring_only_pair(sptr, lookup_target))
    return ring_answer(sptr, "AFTER", HM_PAGE_AFTER, target, lookup_target,
                       ref_type, ref_value, HISTORY_REF_NONE, NULL, limit);

  if (open_query_presence(sptr, lookup_target, ops_override, &pf) < 0) {
    presence_filter_and_replay(sptr, lookup_target, &messages, 0,
                               ops_override, cli_label(sptr), 1, target, NULL);
    return 0;
  }
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_after(lookup_target, ref_type, ref_value, limit,
                              &messages, hook);
  complete = query_page_complete(hook, count, limit);
  presence_query_filter_close(pf);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ch_fail_ctx("AFTER", target),
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  /* A channel page fans out when the span it claims was not received
   * here (the receive windows, W5 Task 9), a PM page when it is short;
   * either when the span overlaps a known store's absence, and then it is
   * partial while that store is still away (chathistory-partial,
   * 2026-09-08). */
  fed_why = federation_wanted(lookup_target, FP_AFTER, count, limit, messages,
                              ref_type, ref_value, HISTORY_REF_NONE, NULL, &partial);
  if (fed_why) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, target, "AFTER",
                                              ref_str, limit, messages, count,
                                              ops_override, NULL, complete);
    fed_count(req, fed_why);
    /* Federation wanted and a peer not asked (no slot, or federation off
     * here: fed_start_missed): withhold the end tag -- unless only the
     * rows' context was wanted (their own span is complete here). */
    if (!req && fed_start_missed() && fed_why != FED_WHY_CONTEXT) {
      complete = 0;
      partial = 1;
    }
    if (req)
      fed_request_set_why(req, fed_why, partial);
    if (req)
      return 0;
  }

  /* Attach context messages (reactions, redacts) to their parents */
  history_attach_context(lookup_target, messages);
  /* Async replay — ownership of messages transfers to ReplayState */
  /* Completeness = QUERY EXHAUSTION: judged on the raw row count
   * BEFORE reply-side filters (redact originals, cap-gated REDACT
   * events, strict presence all legitimately shrink the emitted
   * page), and threaded down to the batch opener -- the replay layer
   * used to stamp every single-shot page final regardless. */
  count = presence_filter_and_replay(sptr, lookup_target, &messages, count,
                                     ops_override, cli_label(sptr),
                                     (complete ? REPLAY_COMPLETE : 0)
                                     | (partial ? REPLAY_PARTIAL : 0), target, NULL);

  return 0;
}

/** Handle CHATHISTORY AROUND subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] target Target channel or nick.
 * @param[in] ref_str Reference string.
 * @param[in] limit_str Limit string.
 * @param[in] ops_override If non-zero, user requested :full override.
 * @return 0 on success.
 */
static int chathistory_around(struct Client *sptr, const char *target,
                               const char *ref_str, const char *limit_str,
                               int ops_override)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type;
  const char *ref_value;
  int limit, count, max_limit;
  int fed_why = FED_WHY_NONE, partial = 0;
  int complete = 1;
  int around_exhausted = 0;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  char lookup_target[CHANNELLEN + 1];  /* must fit a channel name (CHANNELLEN) or a
                                       * PM identity pair-key (PM_PAIRKEY_BUFSIZE); CHANNELLEN+1 dominates */

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
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", ch_fail_ctx("AROUND", target),
              "No access to target");
    return 0;
  }
  if (fail_unknown_msgid(sptr, "AROUND", target, lookup_target, ref_type, ref_value))
    return 0;
  if (ring_only_pair(sptr, lookup_target))
    return ring_answer(sptr, "AROUND", HM_PAGE_AROUND, target, lookup_target,
                       ref_type, ref_value, HISTORY_REF_NONE, NULL, limit);

  if (open_query_presence(sptr, lookup_target, ops_override, &pf) < 0) {
    presence_filter_and_replay(sptr, lookup_target, &messages, 0,
                               ops_override, cli_label(sptr), 1, target, NULL);
    return 0;
  }
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_around(lookup_target, ref_type, ref_value, limit,
                               &messages, hook, &around_exhausted);
  /* The last page only when nothing lies past EITHER end (#214): a short
   * page is not enough -- a back half that filled up may have more
   * before it however few rows came after. */
  complete = around_exhausted && !hook->truncated;
  presence_query_filter_close(pf);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ch_fail_ctx("AROUND", target),
              "Failed to retrieve history");
    return 0;
  }

  /* Check if we should try federation */
  /* A channel page fans out when the span it claims was not received
   * here (the receive windows, W5 Task 9), a PM page when it is short;
   * either when the span overlaps a known store's absence, and then it is
   * partial while that store is still away (chathistory-partial,
   * 2026-09-08). */
  fed_why = federation_wanted(lookup_target, FP_AROUND, count, limit, messages,
                              ref_type, ref_value, HISTORY_REF_NONE, NULL, &partial);
  if (fed_why) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, target, "AROUND",
                                              ref_str, limit, messages, count,
                                              ops_override, NULL, complete);
    fed_count(req, fed_why);
    /* Federation wanted and a peer not asked (no slot, or federation off
     * here: fed_start_missed): withhold the end tag -- unless only the
     * rows' context was wanted (their own span is complete here). */
    if (!req && fed_start_missed() && fed_why != FED_WHY_CONTEXT) {
      complete = 0;
      partial = 1;
    }
    if (req)
      fed_request_set_why(req, fed_why, partial);
    if (req)
      return 0;
  }

  /* Attach context messages (reactions, redacts) to their parents */
  history_attach_context(lookup_target, messages);
  /* Async replay — ownership of messages transfers to ReplayState */
  /* Completeness = QUERY EXHAUSTION: judged on the raw row count
   * BEFORE reply-side filters (redact originals, cap-gated REDACT
   * events, strict presence all legitimately shrink the emitted
   * page), and threaded down to the batch opener -- the replay layer
   * used to stamp every single-shot page final regardless. */
  count = presence_filter_and_replay(sptr, lookup_target, &messages, count,
                                     ops_override, cli_label(sptr),
                                     (complete ? REPLAY_COMPLETE : 0)
                                     | (partial ? REPLAY_PARTIAL : 0), target, NULL);

  return 0;
}

/** Handle CHATHISTORY BETWEEN subcommand.
 * @param[in] sptr Client sending the command.
 * @param[in] target Target channel or nick.
 * @param[in] ref1_str First reference string.
 * @param[in] ref2_str Second reference string.
 * @param[in] limit_str Limit string.
 * @param[in] ops_override If non-zero, user requested :full override.
 * @return 0 on success.
 */
static int chathistory_between(struct Client *sptr, const char *target,
                                const char *ref1_str, const char *ref2_str,
                                const char *limit_str, int ops_override)
{
  struct HistoryMessage *messages = NULL;
  enum HistoryRefType ref_type1, ref_type2;
  const char *ref_value1, *ref_value2;
  int limit, count, max_limit;
  int fed_why = FED_WHY_NONE, partial = 0;
  int complete = 1;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  char lookup_target[CHANNELLEN + 1];  /* must fit a channel name (CHANNELLEN) or a
                                       * PM identity pair-key (PM_PAIRKEY_BUFSIZE); CHANNELLEN+1 dominates */

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
    send_fail(sptr, "CHATHISTORY", "INVALID_TARGET", ch_fail_ctx("BETWEEN", target),
              "No access to target");
    return 0;
  }
  if (fail_unknown_msgid(sptr, "BETWEEN", target, lookup_target, ref_type1, ref_value1)
      || fail_unknown_msgid(sptr, "BETWEEN", target, lookup_target, ref_type2, ref_value2))
    return 0;
  if (ring_only_pair(sptr, lookup_target))
    return ring_answer(sptr, "BETWEEN", HM_PAGE_BETWEEN, target, lookup_target,
                       ref_type1, ref_value1, ref_type2, ref_value2, limit);

  if (open_query_presence(sptr, lookup_target, ops_override, &pf) < 0) {
    presence_filter_and_replay(sptr, lookup_target, &messages, 0,
                               ops_override, cli_label(sptr), 1, target, NULL);
    return 0;
  }
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_between(lookup_target, ref_type1, ref_value1,
                                 ref_type2, ref_value2, limit, &messages,
                                 hook);
  complete = query_page_complete(hook, count, limit);
  presence_query_filter_close(pf);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ch_fail_ctx("BETWEEN", target),
              "Failed to retrieve history");
    return 0;
  }

  /* Federation (oversight fix): BETWEEN was the one subcommand that
   * never federated -- the CH Q wire had a single ref slot; W now
   * carries an optional trailing second ref. */
  /* A channel page fans out when the span it claims was not received
   * here (the receive windows, W5 Task 9), a PM page when it is short;
   * either when the span overlaps a known store's absence, and then it is
   * partial while that store is still away (chathistory-partial,
   * 2026-09-08). */
  fed_why = federation_wanted(lookup_target, FP_BETWEEN, count, limit, messages,
                              ref_type1, ref_value1, ref_type2, ref_value2, &partial);
  if (fed_why) {
    struct FedRequest *req = start_fed_query(sptr, lookup_target, target, "BETWEEN",
                                              ref1_str, limit, messages, count,
                                              ops_override, ref2_str, complete);
    fed_count(req, fed_why);
    /* Federation wanted and a peer not asked (no slot, or federation off
     * here: fed_start_missed): withhold the end tag -- unless only the
     * rows' context was wanted (their own span is complete here). */
    if (!req && fed_start_missed() && fed_why != FED_WHY_CONTEXT) {
      complete = 0;
      partial = 1;
    }
    if (req)
      fed_request_set_why(req, fed_why, partial);
    if (req)
      return 0;  /* messages ownership transferred to req */
  }

  /* Attach context messages (reactions, redacts) to their parents */
  history_attach_context(lookup_target, messages);
  /* Async replay — ownership of messages transfers to ReplayState */
  /* Completeness = QUERY EXHAUSTION: judged on the raw row count
   * BEFORE reply-side filters (redact originals, cap-gated REDACT
   * events, strict presence all legitimately shrink the emitted
   * page), and threaded down to the batch opener -- the replay layer
   * used to stamp every single-shot page final regardless. */
  count = presence_filter_and_replay(sptr, lookup_target, &messages, count,
                                     ops_override, cli_label(sptr),
                                     (complete ? REPLAY_COMPLETE : 0)
                                     | (partial ? REPLAY_PARTIAL : 0), target, NULL);

  return 0;
}

/*
 * S2S Chathistory Federation — Struct & Globals
 * (Moved early for TARGETS federation support)
 */

/** Maximum pending federation requests */
#define MAX_FED_REQUESTS 64

/** Maximum messages collected per request */
#define MAX_FED_MESSAGES 500
/** The page leg's context children a request keeps (W5 Task 15, F-4):
 * their own bound, apart from MAX_FED_MESSAGES, so a reaction-heavy reply
 * can neither cut the page nor push a row out, and a peer cannot flood
 * memory with them.  The excess is dropped: a lost child costs context,
 * never a row, and is never partial (user decision 2026-11-08 15:08). */
#define MAX_FED_CONTEXT 500

/** The children request (CH Q K, W5 Task 14): the most context children a
 * request takes (the requester's bound, and the <cap> it puts on the wire;
 * a responder sends at most min(<cap>, this) per line). */
#define FED_CHILDREN_MAX 500
/** The most msgids one CH Q K line is read for (a 510-byte line holds no
 * more than this many one-character tokens). */
#define FED_K_IDS_MAX 256

/** Structure for a pending federation request */
/** Parent linkage for a children-leg context child (CH C <reqid>K); the
 * page leg's live in its hm_page_leg (HM_DECL_MAX, remove-on-match). */
struct FedCtxPair {
  char child[HISTORY_MSGID_LEN];
  char parent[HISTORY_MSGID_LEN];
  char tags[512];   /**< Child's client-only tags (CH R never carries them) */
};
/** The children leg's CH C declarations in flight (W5 Task 14).  Each one
 * is removed when its row arrives (add_fed_child), and a responder sends a
 * declaration right before its row, so this bounds what interleaves across
 * responders.  A full table costs nothing: the row names its parent itself
 * (hm_context_parent). */
#define FED_K_DECL_MAX 16

struct FedRequest {
  char reqid[32];                     /**< Request ID */
  char target[CHANNELLEN + 1];        /**< Target channel */
  char requested[CHANNELLEN + 1];     /**< Target as the client typed it (batch name) */
  char client_yxx[6];                 /**< Client numeric (YXX) for safe lookup */
  struct HistoryMessage *local_msgs;  /**< Local LMDB results */
  /** The peers' replies on the page leg (chathistory_merge.h): their rows
   * (leg.rows against MAX_FED_MESSAGES) and context children (leg.ctx
   * against MAX_FED_CONTEXT), the CH C declarations in flight, and the
   * targets of REDACTs dropped for budget (W5 Task 15).  Every request
   * type keeps its replies here. */
  struct hm_page_leg leg;
  int partial;                        /**< a known store is away over the span */
  int cut;                            /**< a responder was lost: timeout/SQUIT or
                                       *   the aggregate cap dropped rows (partial);
                                       *   NOT a responder's own full page (that is
                                       *   fed_truncated = "more exists") */
  int local_count;                    /**< Number of local messages */
  int servers_pending;                /**< Servers we're waiting for */
  time_t start_time;                  /**< When request started */
  int limit;                          /**< Original limit requested */
  int ops_override;                   /**< Whether client requested :full override */
  struct Timer timer;                 /**< Timeout timer (embedded) */
  int timer_active;                   /**< Whether timer is active */
  int response_sent;                  /**< Whether response was already sent */
  int fed_truncated;                  /**< Any storage server flagged its result truncated (CH E ... T) */
  int local_incomplete;               /**< The origin's own walk did not exhaust (scan cap / short) */
  int keep_oldest;                    /**< Merge trim direction: 1 keep oldest (AFTER/asc BETWEEN), 0 keep newest */
  int context_only;                   /**< Federated only for the rows' context
                                       *   (FED_WHY_CONTEXT): the local rows are the
                                       *   page, the peers add context to them */
  int around;                         /**< An AROUND page whose reference resolved:
                                       *   the merge is centred on it (hm_trim_around) */
  uint64_t around_ms;                 /**< That reference's time (epoch ms) */
  char around_msgid[HISTORY_MSGID_LEN]; /**< ... and row, for a msgid reference (else empty) */
  int peer_walk_wider;                /**< The responders' walks are not filtered as
                                       *   this page's was: strict presence, and a
                                       *   requester with no account (a responder
                                       *   filters only by account presence) */
  unsigned char e_seen[MAX_AD_SERVERS / 8]; /**< responders whose CH E arrived (dup guard) */
  /* The children request (CH Q K, W5 Task 14): its own reply leg, under
   * <reqid>K (find_fed_request_leg).  Its replies never touch fed_count,
   * fed_truncated, cut, partial or ctx_pairs: a context gap is never
   * partial (user decision 2026-11-08 15:08). */
  int k_pending;                      /**< K-capable stores whose last-line E has not come */
  unsigned char k_e_seen[MAX_AD_SERVERS / 8]; /**< children leg CH E dup guard */
  struct HistoryMessage *k_msgs;      /**< the children (is_context, ctx_parent set) */
  int k_count;
  struct FedCtxPair k_decl[FED_K_DECL_MAX]; /**< children leg CH C, removed on match */
  int k_decl_count;
  char (*k_ids)[HISTORY_MSGID_LEN];   /**< the msgids asked about, sorted (fed_k_listed) */
  int k_id_count;
  void (*completion_cb)(struct FedRequest *); /**< Custom completion (NULL = send_fed_response) */
  void *cb_data;                      /**< Custom data for completion callback */
  void (*cleanup_cb)(void *cb_data);  /**< Custom cleanup for cb_data (NULL = MyFree) */
  char label[64];                     /**< Saved label for labeled-response on async completion */
};

/** Record why a subcommand page federates (federation_wanted's reason) and
 * whether a store away over its own span makes it partial. */
static void fed_request_set_why(struct FedRequest *req, int why, int partial)
{
  req->partial = partial;
  req->context_only = (why == FED_WHY_CONTEXT);
}

/** Global array of pending federation requests */
static struct FedRequest *fed_requests[MAX_FED_REQUESTS];

/** Counter for generating unique request IDs */
static unsigned long fed_reqid_counter = 0;

/* ---------------------------------------------------------------- */
/* CHATHISTORY TARGETS (W5 Task 11)                                  */
/*                                                                  */
/* TARGETS lists the REQUESTER'S OWN targets -- its channels and its */
/* PM pairs (the pair index) -- read one by one, never a walk over   */
/* every target the server holds.  It has BETWEEN's semantics        */
/* (chathistory.md :111, :119): both bounds exclusive, the limit      */
/* counted from the first argument, the argument order the direction */
/* (forwards from an older first bound, backwards from a newer one); */
/* rows ascending (:126), ties by folded name (:128); a group of     */
/* equal stamps never split at the page edge (hm_targets_page).      */
/* Times compare as integer ms, never as "sec.mmm" strings.          */
/*                                                                  */
/* A target's "latest" is network-wide: the maximum over the stores  */
/* that answered.  Each server sends the requester's targets whose   */
/* stamp is above the window's lower bound -- in-window rows, and    */
/* veto rows at or past its upper bound, which can only disqualify a */
/* target another store holds in the window -- and the requester     */
/* merges them, keeps the window, and pages.                         */
/* ---------------------------------------------------------------- */

/** The most CH T lines one responder sends for a request (in-window rows
 * first, nearest the first selector; veto rows last: hm_targets_responder).
 * Past it the answer ends "E <reqid> <n> T". */
#define CH_T_MAX_ROWS 500

static int server_ad_index(struct Client *server);   /* below */

/** Context for federated TARGETS query, stored in FedRequest.cb_data. */
struct TargetsFedContext {
  struct HistoryTarget *local_targets;   /**< The requester's own (targets_collect) */
  struct HistoryTarget *fed_targets;     /**< The peers' CH T rows */
  uint64_t first_ms;                     /**< The client's first bound */
  uint64_t second_ms;                    /**< ... and its second */
  struct hm_targets_resp *resp;          /**< One per responder heard from */
  int nresp, resp_max;
};

/* Forward declarations for TARGETS federation */
static void complete_targets_fed(struct FedRequest *req);
static void cleanup_targets_context(void *data);

/** Is @a name one of @a rq's own targets, one it may be shown?  A channel
 * it is a member of (an unjoined +H channel is not its target: decided
 * 2026-10-25) that check_history_access lets it read; a PM pair whose one
 * half is its identity (account, else session id). */
static int targets_own(struct Client *rq, const char *name)
{
  if (IsChannelName(name)) {
    struct Channel *ch = FindChannel(name);
    if (!ch || !find_member_link(ch, rq))
      return 0;
    return check_history_access(rq, ch->chname, NULL, 0) == 0;
  } else {
    const char *colon = strchr(name, ':');
    if (!colon || colon == name || !colon[1] || strchr(colon + 1, ':'))
      return 0;
    return history_pm_identity_matches(rq, name, (size_t)(colon - name))
        || history_pm_identity_matches(rq, colon + 1, strlen(colon + 1));
  }
}

/** Prepend a copy of (@a name, @a ts) to @a *list. */
static void targets_push(struct HistoryTarget **list, const char *name, const char *ts)
{
  struct HistoryTarget *t = (struct HistoryTarget *)MyCalloc(1, sizeof(*t));
  ircd_strncpy(t->target, name, sizeof(t->target));
  ircd_strncpy(t->last_timestamp, ts, sizeof(t->last_timestamp));
  t->next = *list;
  *list = t;
}

/** @a rq's own targets this store holds a stamp for above @a lo_ms
 * (exclusive; veto rows included): each channel it is a member of that
 * targets_own accepts (one point read in the targets index), and with
 * CHATHISTORY_PRIVATE its PM pairs (the pair index) and, for a local
 * requester without an account, the conversations its ephemeral ring
 * holds (#215: two parties without an account are never stored, only
 * ringed, so the pair index never had them and TARGETS never listed one
 * that LATEST returned).  Uncapped: bounded by the requester's own
 * memberships and conversations.  Works for a remote @a rq too (a
 * responder): membership and identity are network-wide; a ring is held
 * by its client's own server alone, which lists it.
 * @return The count, or -1 on a storage error (*out NULL). */
static int targets_collect(struct Client *rq, uint64_t lo_ms, struct HistoryTarget **out)
{
  struct HistoryTarget *list = NULL;
  struct Membership *m;
  int n = 0;

  *out = NULL;
  if (!cli_user(rq))
    return 0;
  for (m = cli_user(rq)->channel; m; m = m->next_channel) {
    char ts[HISTORY_TIMESTAMP_LEN];
    int rc;
    if (!m->channel || check_history_access(rq, m->channel->chname, NULL, 0) != 0)
      continue;
    rc = history_target_latest(m->channel->chname, ts, sizeof(ts));
    if (rc < 0) {
      history_free_targets(list);
      return -1;
    }
    if (rc > 0 || history_parse_ms(ts) <= lo_ms)
      continue;
    targets_push(&list, m->channel->chname, ts);
    n++;
  }
  if (feature_bool(FEAT_CHATHISTORY_PRIVATE)) {
    char identity[S2S_SESSID_BUFSIZE];
    struct HistoryTarget *pm = NULL, *t;
    int rc;
    history_pm_identity(rq, identity, sizeof(identity));
    rc = history_identity_pm_targets(identity, lo_ms, 0, /*include_newer=*/1,
                                     /*max=*/0, &pm, NULL, NULL);
    if (rc < 0) {
      history_free_targets(list);
      return -1;
    }
    for (t = pm; t && t->next; t = t->next)
      ;
    if (t) {
      t->next = list;
      list = pm;
    }
    n += rc;
    if (MyConnect(rq) && !IsAccount(rq)) {
      struct HistoryTarget *ring = NULL;
      int rn = chathistory_ephemeral_targets(rq, lo_ms, &ring);
      for (t = ring; t && t->next; t = t->next)
        ;
      if (t) {
        t->next = list;
        list = ring;
      }
      n += rn;
    }
  }
  *out = list;
  return n;
}

/** Should a TARGETS page ask the storage peers (W5 Task 11)?  It should
 * whenever a peer could hold a stamp for one of the requester's targets
 * that this store lacks:
 *   - with CHATHISTORY_PRIVATE, always: a PM pair is held only where one of
 *     its parties had a connection, so any store may hold one;
 *   - a channel the requester is a member of, unless this store received it
 *     (history_recv_covers) and no storage peer was away (the absence
 *     table) from its own latest stamp here -- or, with none, from the
 *     channel's creation (channel_span_clamp) -- up to now.  One whose
 *     stamp here is already at or past the window's upper bound is out of
 *     the window whatever a peer says (the latest only rises).
 * A storage peer that is away right now (store_away_now: an open absence,
 * or, since this server restarted, one it has had that is not back yet)
 * leaves a known hole: *@a partial is set (user decision 2026-11-08: no
 * end tag, and evilnet.github.io/chathistory-partial), even when no peer
 * is left to ask -- this replaces "no storage peers, so complete".  So is a
 * page from
 * a store whose PM pair index rebuild failed at this start
 * (history_pm_index_whole).
 * @return 1 to federate, 0 not. */
/** qsort / bsearch order of a HistoryTarget pointer array by name (the
 * IRC case mapping, as channel names compare). */
static int targets_by_name(const void *a, const void *b)
{
  const struct HistoryTarget *const *x = (const struct HistoryTarget *const *)a;
  const struct HistoryTarget *const *y = (const struct HistoryTarget *const *)b;
  return ircd_strcmp((*x)->target, (*y)->target);
}

static int targets_federation_wanted(struct Client *sptr, struct HistoryTarget *local,
                                     uint64_t lo_ms, uint64_t hi_ms, int *partial)
{
  struct Membership *m;
  struct HistoryTarget **byname = NULL, *t;
  int want = 0, n = 0;

  (void)lo_ms;
  if (!cli_user(sptr))
    return 0;
  if (feature_bool(FEAT_CHATHISTORY_PRIVATE)) {
    /* An open absence always meets [lo, now]; so does a storage peer this
     * server has had and that is not back since it restarted (W5 Push F,
     * I-1: store_away_now). */
    if (store_away_now())
      *partial = 1;
    /* A pair index whose rebuild failed at this start may lack pairs: the
     * page may lack PM conversations this store holds. */
    if (!history_pm_index_whole())
      *partial = 1;
    /* Decided: it federates, and the channels below could only set partial
     * for a store away now, which the test above already did (final review
     * m-1: their checks were dead work on every TARGETS with PM history,
     * prod's setting). */
    return 1;
  }
  /* The requester's own channel stamps, looked up by name: one sort, not a
   * walk of the list per membership (m-1). */
  for (t = local; t; t = t->next)
    n++;
  if (n > 0) {
    int i = 0;
    byname = (struct HistoryTarget **)MyMalloc((size_t)n * sizeof(*byname));
    for (t = local; t; t = t->next)
      byname[i++] = t;
    qsort(byname, (size_t)n, sizeof(*byname), targets_by_name);
  }
  for (m = cli_user(sptr)->channel; m; m = m->next_channel) {
    struct Channel *ch = m->channel;
    struct HistoryTarget key, *kp = &key, **hit = NULL;
    time_t from = 0;

    if (!ch || check_history_access(sptr, ch->chname, NULL, 0) != 0)
      continue;
    if (byname) {
      ircd_strncpy(key.target, ch->chname, sizeof(key.target));
      hit = (struct HistoryTarget **)bsearch(&kp, byname, (size_t)n, sizeof(*byname),
                                             targets_by_name);
    }
    if (hit) {
      uint64_t ms = history_parse_ms((*hit)->last_timestamp);
      if (ms >= hi_ms)
        continue;
      from = (time_t)(ms / 1000ULL);
    }
    if (channel_range_check(ch->chname, from, 0, partial) != FED_WHY_NONE)
      want = 1;
  }
  if (byname)
    MyFree(byname);
  return want;
}

/** hm_targets_page's eligibility test: what the requester may be shown,
 * judged on the merged (network-wide) stamp -- its own target
 * (targets_own); for a channel under strict presence without +H, one it
 * was present in at that last activity; for a PM pair, one with somebody
 * to name it after (replay_pm_display_nick: never a session id, never a
 * service bot), and for a conversation held only in the requester's
 * ephemeral ring, only under a name that CHATHISTORY reaches it by --
 * the same access check and key derivation LATEST uses (#215).  An
 * unauthenticated party is weaker identity than an account: a nick can
 * pass to someone else, and the ring is keyed by session ids, so the
 * listing follows LATEST rather than any name the ring remembers. */
static int targets_eligible(const struct HistoryTarget *t, void *ctx)
{
  struct Client *sptr = (struct Client *)ctx;

  if (!targets_own(sptr, t->target))
    return 0;
  if (IsChannelName(t->target)) {
    if (feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE)) {
      struct Channel *pchan = FindChannel(t->target);
      if (!(pchan && (pchan->mode.exmode & EXMODE_PUBLICHISTORY))) {
        int p_is_session = 0;
        const char *p_anchor = presence_anchor_for(sptr, &p_is_session);
        /* The index holds only the last activity's millisecond; read it
         * as the end of that millisecond so activity in the join's own
         * millisecond counts as witnessed. */
        int64_t act = PRESENCE_TIME_FROM_MS_LATE((int64_t)history_parse_ms(t->last_timestamp));
        if (!p_anchor || act == 0
            || !presence_was_present(p_anchor, p_is_session, t->target, act))
          return 0;
      }
    }
    return 1;
  } else {
    char name[CHANNELLEN + 1];
    if (!replay_pm_display_nick(sptr, t->target, name, sizeof(name)))
      return 0;
    if (chathistory_ephemeral_has_target(sptr, t->target)) {
      /* The ring pair is listed as `name` only when LATEST <name> reads
       * exactly it: not when another conversation answers to that name
       * (normalize_pm_target's stored-pair fallback) or access is refused. */
      char lookup[CHANNELLEN + 1];
      if (check_history_access(sptr, name, lookup, sizeof(lookup)) != 0
          || ircd_strcmp(lookup, t->target) != 0)
        return 0;
    }
    return 1;
  }
}

/** Send a TARGETS page (@a page: ascending, every row eligible).
 * @a end sets draft/chathistory-end ("the next page will return an empty
 * batch", :136); @a partial sets evilnet.github.io/chathistory-partial (a
 * storage peer's answer is known to be missing) and always withholds the
 * end tag, as on chathistory batches. */
static void send_targets_batch(struct Client *sptr, struct HistoryTarget *page,
                               const char *label, int end, int partial)
{
  char batchid[BATCH_ID_LEN];
  char iso_time[32];
  struct HistoryTarget *tgt;
  int batch = CapRecipientHas(sptr, CAP_BATCH);

  if (partial)
    end = 0;
  generate_batch_id(batchid, sizeof(batchid), sptr);
  if (batch) {
    char tagbuf[256];
    int tl = 0;
    int want_label = label && label[0] && feature_bool(FEAT_CAP_labeled_response)
                     && CapRecipientHas(sptr, CAP_LABELEDRESP);
    tagbuf[0] = '\0';
    if (end)
      tl += ircd_snprintf(0, tagbuf + tl, sizeof(tagbuf) - tl, "draft/chathistory-end");
    if (partial)
      tl += ircd_snprintf(0, tagbuf + tl, sizeof(tagbuf) - tl,
                          "%sevilnet.github.io/chathistory-partial", tl ? ";" : "");
    if (want_label)
      tl += ircd_snprintf(0, tagbuf + tl, sizeof(tagbuf) - tl, "%slabel=%s",
                          tl ? ";" : "", label);
    if (tagbuf[0])
      sendrawto_one(sptr, "@%s :%s " MSG_BATCH_CMD " +%s draft/chathistory-targets",
                    tagbuf, cli_name(&me), batchid);
    else
      sendrawto_one(sptr, ":%s " MSG_BATCH_CMD " +%s draft/chathistory-targets",
                    cli_name(&me), batchid);
    if (want_label)
      cli_label_responded(sptr) = 1;
  }

  for (tgt = page; tgt; tgt = tgt->next) {
    const char *row_target = tgt->target;
    const char *time_str;
    char other_buf[CHANNELLEN + 1];

    if (history_unix_to_iso(tgt->last_timestamp, iso_time, sizeof(iso_time)) == 0)
      time_str = iso_time;
    else
      time_str = tgt->last_timestamp;

    /* Spec conformance (#565 clarified format): response rows carry a
     * BARE ISO timestamp -- the "timestamp=" prefix belongs to request
     * syntax only.  PM rows: the store key is the identity pair "a:b";
     * the spec's <nickname> is the OTHER participant. */
    if (IsChannelName(tgt->target)) {
      /* The index keys folded names (db_casefold.h); show a live
       * channel under its current spelling. */
      struct Channel *live = FindChannel(tgt->target);
      if (live)
        row_target = live->chname;
    } else {
      /* PM pair key: name the row after the other party from the newest
       * stored rows (replay_pm_display_nick): the nick the other party's
       * newest row carries -- that same session's current nick while it
       * is connected -- else the nick the requester addressed, else the
       * other party's account.  Never another live client's nick: an
       * account's connections are not interchangeable.  The raw half of
       * the key is an identity -- for an account-less party a session id
       * -- and must never reach a client as a "target" (PoxChat opened
       * "Dialog with AaBj..." on prod, 2026-09-02).  targets_eligible
       * already kept only pairs that can be named. */
      if (!replay_pm_display_nick(sptr, tgt->target, other_buf, sizeof(other_buf)))
        continue;
      row_target = other_buf;
    }
    if (batch)
      sendrawto_one(sptr, "@batch=%s :%s!%s@%s CHATHISTORY TARGETS %s %s",
                    batchid, cli_name(&me), "chathistory", cli_name(&me),
                    row_target, time_str);
    else
      sendrawto_one(sptr, ":%s!%s@%s CHATHISTORY TARGETS %s %s",
                    cli_name(&me), "chathistory", cli_name(&me),
                    row_target, time_str);
  }

  if (batch)
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
}

/** Page and send a TARGETS answer from @a list (consumed: the requester's
 * own targets, merged with its peers' when it federated).
 * @param[in] whole Every store that could be asked answered in full (no
 *   responder cut its rows, none was lost, no request slot was missing).
 * @param[in] partial A store's answer is known to be missing.
 * @param[in] resp What each responder sent (NULL when local): a cut one's
 *   answer may leave a hole the page reaches into (hm_targets_cut_partial). */
static void targets_answer(struct Client *sptr, struct HistoryTarget *list,
                           uint64_t first_ms, uint64_t second_ms, int limit,
                           const char *label, int whole, int partial,
                           const struct hm_targets_resp *resp, int nresp)
{
  int more = 0;

  hm_targets_page(&list, first_ms, second_ms, limit, targets_eligible, sptr, &more);
  if (resp && hm_targets_cut_partial(resp, nresp, first_ms, second_ms, list, more))
    partial = 1;
  /* The end tag (I8): nothing eligible beyond the page in its direction,
   * and the network's answer whole. */
  send_targets_batch(sptr, list, label, whole && !partial && !more, partial);
  history_free_targets(list);
}

/** The responder entry for @a si (added when new; NULL past the table). */
static struct hm_targets_resp *targets_resp(struct TargetsFedContext *ctx, int si)
{
  int i;
  for (i = 0; i < ctx->nresp; i++)
    if (ctx->resp[i].si == si)
      return &ctx->resp[i];
  if (ctx->nresp >= ctx->resp_max)
    return NULL;
  memset(&ctx->resp[ctx->nresp], 0, sizeof(ctx->resp[0]));
  ctx->resp[ctx->nresp].si = si;
  return &ctx->resp[ctx->nresp++];
}

/** Accumulate a CH T response into the federated targets list. */
static void add_fed_target(struct FedRequest *req, struct Client *from,
                           const char *target, const char *last_timestamp)
{
  struct TargetsFedContext *ctx;
  struct hm_targets_resp *r;

  if (!req || !req->cb_data || req->completion_cb != complete_targets_fed)
    return;
  ctx = (struct TargetsFedContext *)req->cb_data;
  targets_push(&ctx->fed_targets, target, last_timestamp);

  /* Where this responder's answer has reached (it sends in-window rows
   * nearest the first selector first, veto rows last). */
  r = targets_resp(ctx, server_ad_index(from));
  if (r)
    hm_targets_resp_row(r, ctx->first_ms, ctx->second_ms,
                        history_parse_ms(last_timestamp));
}

/** A TARGETS responder's E carried T: it cut its answer at CH_T_MAX_ROWS. */
static void targets_note_cut(struct FedRequest *req, struct Client *from)
{
  struct hm_targets_resp *r;
  if (!req || !req->cb_data || req->completion_cb != complete_targets_fed)
    return;
  r = targets_resp((struct TargetsFedContext *)req->cb_data, server_ad_index(from));
  if (r)
    r->cut = 1;
}

/** Initiate a federated TARGETS query to storage servers.  Takes
 * ownership of @a local_targets when it returns a request. */
static struct FedRequest *start_fed_targets_query(
  struct Client *sptr,
  const char *ts1, const char *ts2,
  uint64_t first_ms, uint64_t second_ms,
  int limit,
  struct HistoryTarget *local_targets,
  int partial)
{
  struct FedRequest *req;
  struct TargetsFedContext *ctx;
  char reqid[32];
  char s2s_ref[128];
  char idtok[ACCOUNTLEN + S2S_SESSID_BUFSIZE + 2];
  int i, server_count;

  fed_start_capacity_miss = 0;
  fed_start_unasked = 0;
  server_count = count_storage_servers(NULL, 0);
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION)) {
    fed_start_unasked = server_count > 0;   /* a peer not asked (I-1) */
    return NULL;
  }
  if (server_count == 0)
    return NULL;

  /* Find empty slot */
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (!fed_requests[i])
      break;
  }
  if (i >= MAX_FED_REQUESTS) {
    fed_start_capacity_miss = 1;   /* caller: the local page is partial */
    return NULL;
  }

  /* S2S dual-timestamp ref: the client's two bounds, in its order (the
   * responder pages from the first: hm_targets_responder). */
  ircd_snprintf(0, s2s_ref, sizeof(s2s_ref), "%s,%s", ts1, ts2);

  /* The requester's identity, so a responder never takes a reused or
   * swapped numeric (BX P) for it: A<account>, else S<session id>
   * (targets_requester). */
  if (IsAccount(sptr) && cli_user(sptr) && cli_user(sptr)->account[0])
    ircd_snprintf(0, idtok, sizeof(idtok), "A%s", cli_user(sptr)->account);
  else
    ircd_snprintf(0, idtok, sizeof(idtok), "S%s", cli_session_id(sptr));

  /* Generate request ID */
  ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu",
                cli_yxx(&me), ++fed_reqid_counter);

  /* Create context for targets accumulation */
  ctx = (struct TargetsFedContext *)MyCalloc(1, sizeof(struct TargetsFedContext));
  ctx->local_targets = local_targets;
  ctx->first_ms = first_ms;
  ctx->second_ms = second_ms;
  ctx->resp_max = server_count;
  ctx->resp = (struct hm_targets_resp *)MyCalloc((size_t)server_count, sizeof(*ctx->resp));

  /* Create request */
  req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
  ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
  req->target[0] = '*';
  req->target[1] = '\0';
  ircd_snprintf(0, req->client_yxx, sizeof(req->client_yxx), "%s%s",
                cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
  req->servers_pending = server_count;
  req->start_time = CurrentTime;
  req->limit = limit;
  req->partial = partial;
  req->completion_cb = complete_targets_fed;
  req->cb_data = ctx;
  req->cleanup_cb = cleanup_targets_context;

  /* Save label for async response delivery */
  req->label[0] = '\0';
  if (cli_label(sptr)[0]) {
    ircd_strncpy(req->label, cli_label(sptr), sizeof(req->label));
    cli_label_responded(sptr) = 1;  /* Suppress generic ACK */
  }

  fed_requests[i] = req;

  /* Set timeout timer */
  timer_add(timer_init(&req->timer), fed_timeout_callback,
            (void *)req, TT_RELATIVE,
            feature_int(FEAT_CHATHISTORY_TIMEOUT));
  req->timer_active = 1;

  /* Send targeted queries to all storage servers in the network */
  {
    int si;
    for (si = 0; si < MAX_AD_SERVERS; si++) {
      struct ChathistoryAd *ad = server_ads[si];
      struct Client *server;
      char dest_yxx[4];

      if (!ad || !ad->has_advertisement || !ad->is_storage_server)
        continue;

      inttobase64(dest_yxx, si, 2);
      server = FindNServer(dest_yxx);
      if (!server || server == &me)
        continue;

      if (is_ulined_server(server))
        continue;

      /* "*" keeps ref2's slot; P<yxx> names the requester, "0" holds the
       * type mask's slot (a responder parses parv[10] as a hex mask for
       * every subcommand: 0 = all), and the identity token follows
       * (parv[11]; a middle hop re-emits it, older responders ignore it). */
      sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q * T %s %d %s %s * P%s 0 %s",
                    s2s_ref, limit, reqid, dest_yxx, req->client_yxx, idtok);
    }
  }

  return req;
}

/** Federation completion callback for TARGETS. */
static void complete_targets_fed(struct FedRequest *req)
{
  struct TargetsFedContext *ctx;
  struct HistoryTarget *merged;
  struct Client *client;

  if (!req || req->response_sent || !req->cb_data)
    return;

  req->response_sent = 1;

  client = findNUser(req->client_yxx);
  if (!client)
    return;  /* Client disconnected */

  ctx = (struct TargetsFedContext *)req->cb_data;

  /* One row per target at its network-wide latest, then the page.  A
   * responder lost (timeout, SQUIT) or one that could not answer (U)
   * leaves a known hole: partial, no end tag (user decision 2026-11-08).
   * One that cut its rows (T) leaves the answer not whole: no end tag; and
   * where it cut before its veto rows, a hole the page may reach into
   * (hm_targets_cut_partial). */
  merged = hm_targets_merge(ctx->local_targets, ctx->fed_targets);
  ctx->local_targets = NULL;
  ctx->fed_targets = NULL;
  targets_answer(client, merged, ctx->first_ms, ctx->second_ms, req->limit,
                 req->label, !req->fed_truncated && !req->cut,
                 req->partial || req->cut, ctx->resp, ctx->nresp);
}

/** Custom cleanup for TargetsFedContext — frees inner target lists. */
static void cleanup_targets_context(void *data)
{
  struct TargetsFedContext *ctx = (struct TargetsFedContext *)data;
  if (!ctx)
    return;
  if (ctx->local_targets)
    history_free_targets(ctx->local_targets);
  if (ctx->fed_targets)
    history_free_targets(ctx->fed_targets);
  if (ctx->resp)
    MyFree(ctx->resp);
  MyFree(ctx);
}

/** The requester a CH Q * T names: P<yxx> (or F<yxx>) is its numeric and
 * @a idtok, when the origin sent one, its identity -- A<account> or
 * S<session id> (start_fed_targets_query).  The numeric's client when it
 * carries that identity; else, for a session id, the one non-alias user
 * carrying it (the numeric was reused, or BX P swapped it in place); else
 * nobody.  An origin that sends no token (an older build) gets the numeric
 * alone, as before.
 * @return The requester, or NULL (answered E <reqid> 0 U). */
static struct Client *targets_requester(const char *ptok, const char *idtok)
{
  struct Client *rq = NULL;

  if (ptok && (ptok[0] == 'P' || ptok[0] == 'F') && ptok[1])
    rq = findNUser(ptok + 1);
  if (rq && (!IsUser(rq) || !cli_user(rq)))
    rq = NULL;
  if (!idtok || !idtok[0])
    return rq;
  if (idtok[0] == 'A' && idtok[1]) {
    if (rq && IsAccount(rq) && cli_user(rq)->account[0]
        && ircd_strcmp(cli_user(rq)->account, idtok + 1) == 0)
      return rq;
    return NULL;
  }
  if (idtok[0] == 'S' && idtok[1]) {
    struct Client *found[BOUNCER_MAX_ALIASES + 4], *one = NULL;
    size_t n, i;
    if (rq && !IsAccount(rq) && strcmp(cli_session_id(rq), idtok + 1) == 0)
      return rq;
    n = client_find_by_session_id(idtok + 1, found, sizeof(found) / sizeof(found[0]));
    if (n > sizeof(found) / sizeof(found[0]))
      n = sizeof(found) / sizeof(found[0]);
    for (i = 0; i < n; i++) {
      if (!found[i] || IsBouncerAlias(found[i]) || IsAccount(found[i]) || !cli_user(found[i]))
        continue;
      if (one)
        return NULL;   /* not one: cannot tell */
      one = found[i];
    }
    return one;
  }
  return NULL;
}

/** Handle CHATHISTORY TARGETS subcommand. */
static int chathistory_targets(struct Client *sptr, const char *ref1_str,
                                const char *ref2_str, const char *limit_str)
{
  struct HistoryTarget *targets = NULL;
  enum HistoryRefType ref_type1, ref_type2;
  const char *ts1, *ts2;
  uint64_t first_ms, second_ms, lo, hi;
  int limit, count, max_limit;
  int partial = 0, whole = 1;

  /* TARGETS uses timestamp references only */
  if (parse_reference(ref1_str, &ref_type1, &ts1) != 0 ||
      ref_type1 != HISTORY_REF_TIMESTAMP ||
      parse_reference(ref2_str, &ref_type2, &ts2) != 0 ||
      ref_type2 != HISTORY_REF_TIMESTAMP) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "TARGETS",
              "TARGETS requires timestamp references");
    return 0;
  }
  /* Integer ms, whatever the width of the seconds (I1). */
  if (hm_targets_ref_ms(ts1, &first_ms) != 0 || hm_targets_ref_ms(ts2, &second_ms) != 0) {
    send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "TARGETS",
              "Invalid timestamp");
    return 0;
  }

  limit = atoi(limit_str);
  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0)
    limit = max_limit;
  if (limit > max_limit)
    limit = max_limit;

  lo = first_ms < second_ms ? first_ms : second_ms;
  hi = first_ms < second_ms ? second_ms : first_ms;
  if (lo == hi) {
    /* Both bounds exclusive: an empty window, and so is every page from it. */
    send_targets_batch(sptr, NULL, cli_label(sptr), 1, 0);
    return 0;
  }

  count = targets_collect(sptr, lo, &targets);
  if (count < 0) {
    send_fail(sptr, "CHATHISTORY", "MESSAGE_ERROR", ch_fail_ctx("TARGETS", "*"),
              "Failed to retrieve targets");
    return 0;
  }

  if (targets_federation_wanted(sptr, targets, lo, hi, &partial)) {
    struct FedRequest *req = start_fed_targets_query(sptr, ts1, ts2, first_ms, second_ms,
                                                     limit, targets, partial);
    if (req)
      return 0;  /* Deferred: complete_targets_fed answers */
    /* No request slot, or federation off here while a storage peer is
     * linked: the peers' answers are missing (partial, as the row handlers
     * do; re-review 2026-09-07 R19; W5 Push F, I-1).  No peer to ask: the
     * local answer is all there is -- partial when one is away
     * (targets_federation_wanted). */
    if (fed_start_missed()) {
      if (fed_start_capacity_miss)
        fed_slot_misses++;
      whole = 0;
      partial = 1;
    }
  }

  targets_answer(sptr, targets, first_ms, second_ms, limit, cli_label(sptr),
                 whole, partial, NULL, 0);
  return 0;
}

/** Check if a parameter is the :full override flag.
 * @param[in] param Parameter to check.
 * @return 1 if it's the :full flag, 0 otherwise.
 */
static int is_full_override(const char *param)
{
  if (!param)
    return 0;
  /* IRC parser strips leading : from trailing param, so we check for "full" */
  return (ircd_strcmp(param, "full") == 0);
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
  int ops_override = 0;

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
                "Usage: CHATHISTORY LATEST <target> <reference|*> <limit> [:full]");
      return 0;
    }
    ops_override = (parc > 5 && is_full_override(parv[5]));
    return chathistory_latest(sptr, parv[2], parv[3], parv[4], ops_override);
  }
  else if (ircd_strcmp(subcmd, "BEFORE") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BEFORE",
                "Usage: CHATHISTORY BEFORE <target> <reference> <limit> [:full]");
      return 0;
    }
    ops_override = (parc > 5 && is_full_override(parv[5]));
    return chathistory_before(sptr, parv[2], parv[3], parv[4], ops_override);
  }
  else if (ircd_strcmp(subcmd, "AFTER") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "AFTER",
                "Usage: CHATHISTORY AFTER <target> <reference> <limit> [:full]");
      return 0;
    }
    ops_override = (parc > 5 && is_full_override(parv[5]));
    return chathistory_after(sptr, parv[2], parv[3], parv[4], ops_override);
  }
  else if (ircd_strcmp(subcmd, "AROUND") == 0) {
    if (parc < 5) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "AROUND",
                "Usage: CHATHISTORY AROUND <target> <reference> <limit> [:full]");
      return 0;
    }
    ops_override = (parc > 5 && is_full_override(parv[5]));
    return chathistory_around(sptr, parv[2], parv[3], parv[4], ops_override);
  }
  else if (ircd_strcmp(subcmd, "BETWEEN") == 0) {
    if (parc < 6) {
      send_fail(sptr, "CHATHISTORY", "INVALID_PARAMS", "BETWEEN",
                "Usage: CHATHISTORY BETWEEN <target> <ref1> <ref2> <limit> [:full]");
      return 0;
    }
    ops_override = (parc > 6 && is_full_override(parv[6]));
    return chathistory_between(sptr, parv[2], parv[3], parv[4], parv[5], ops_override);
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

/** Maximum number of pending base64 chunks */
#define MAX_PENDING_CHUNKS 64

/** Structure for tracking base64 chunked messages */
struct ChunkEntry {
  char key[128];           /**< reqid:msgid */
  char reqid[32];
  char msgid[64];
  char timestamp[32];
  int type;
  char sender[HISTORY_SENDER_LEN];   /* was 64: a long hostmask survived the
                                      * measured wire chunking and was then cut
                                      * on reassembly (re-review R14) */
  char account[ACCOUNTLEN + 1];
  char client_tags[512];   /**< the first line's ,C tags (W5 Task 2), kept
                            * for the final chunk; as wide as the row's */
  char *b64_data;          /**< Accumulated base64 */
  size_t b64_len;
  size_t b64_alloc;
  struct Client *link;     /**< origin link, for per-link cleanup */
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
  struct Client *link;     /**< origin link, for per-link cleanup */
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
  /* Cap reassembly at the largest a single legitimate message can be, base64-
   * expanded (+slack).  A peer streaming unbounded continuation lines would
   * otherwise grow this without limit until MyRealloc's exit(2) crashes the
   * daemon. */
  int cfg_max = feature_int(FEAT_MULTILINE_MAX_BYTES);
  size_t max_content = (cfg_max > 0) ? (size_t)cfg_max : 0;
  size_t ceiling;
  if (max_content < HISTORY_CONTENT_LEN)
    max_content = HISTORY_CONTENT_LEN;
  ceiling = max_content + max_content / 3 + 512;   /* base64 4/3 expansion + slack */
  if (chunk->b64_len + add_len + 1 > ceiling) {
    /* Malformed/abusive: refuse to grow further.  This function is void and
     * its two callers (CH B / CH WB continuation handlers) already call it
     * fire-and-forget with no return-value check; the !has_more finalize
     * path they both fall through to already handles a corrupt/incomplete
     * b64 blob safely (ch_base64_decode's own failure check) and always
     * frees the chunk regardless.  So matching the existing convention here
     * means simply declining to append further growth. */
    return;
  }
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
 * @param[in] origin Name of the server that sent the CH W / CH WB.
 */
static void process_write_forward(const char *target, const char *msgid,
                                  const char *timestamp, const char *sender,
                                  const char *account, char type_char,
                                  char *content, const char *origin)
{
  struct Channel *chptr;
  enum HistoryMessageType type;
  int has_local_users;
  char *client_tags = NULL;
  char owner[HTC_OWNER_MAX];

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
    case 'J': type = HISTORY_JOIN; break;
    case 'L': type = HISTORY_PART; break;
    case 'Q': type = HISTORY_QUIT; break;
    case 'I': type = HISTORY_KICK; break;
    case 'M': type = HISTORY_MODE; break;
    case 'O': type = HISTORY_TOPIC; break;
    case 'T': type = HISTORY_TAGMSG; break;
    case 'K': type = HISTORY_NICK; break;
    case 'R': type = HISTORY_REDACT; break;
    default:
      Debug((DEBUG_DEBUG, "CH W: Unknown type '%c' for %s", type_char, target));
      return;
  }

  /* Split + unescape the federation payload (history_forward_encode on
   * the sender): a raw leading \x06 is the composer's tag bracket,
   * never client bytes.  Everything below sees clean content. */
  content = history_forward_split(content, &client_tags);

  /* Find channel */
  chptr = FindChannel(target);

  /* Check if channel has +P (no storage) mode */
  if (chptr && (chptr->mode.exmode & EXMODE_NOSTORAGE))
    return;

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

  /* REDACT: stored once -- beside its message, or as a tombstone for a
   * message this store does not hold (the rule every REDACT that reaches
   * this store from elsewhere follows; redact_apply_row, rdx_row_decide).
   * A repeat under a new REDACT msgid stores no second row (the msgid
   * dedup above catches only the same one).  The +P check above comes
   * first: a +P channel stores nothing new. */
  if (type == HISTORY_REDACT) {
    char target_msgid[HISTORY_MSGID_LEN];
    const char *space;
    size_t len;
    int d;

    if (!content)
      return;
    space = strchr(content, ' ');
    len = space ? (size_t)(space - content) : strlen(content);
    if (len >= sizeof(target_msgid))
      len = sizeof(target_msgid) - 1;
    memcpy(target_msgid, content, len);
    target_msgid[len] = '\0';
    d = redact_row_judge(target, target_msgid);
    if (d == RDX_ROW_SKIP_APPLIED || d == RDX_ROW_RETRY) {
      Debug((DEBUG_DEBUG, "CH W: REDACT %s of %s in %s from %s not stored (%s)",
             msgid, target_msgid, target, origin,
             d == RDX_ROW_SKIP_APPLIED ? "already redacted" : "store not read"));
      if (d == RDX_ROW_RETRY)
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "CH W: REDACT %s %s from %s: the store could not be read; no REDACT row stored",
                  target, target_msgid, origin);
      return;
    }
    if (d == RDX_ROW_APPLY)
      history_redact_message(target, target_msgid);
  }

  /* Check if this is a new channel for Layer 1 advertisement */
  int is_new_channel = (history_has_channel(target) == 0);

  /* The row's trim owner: the account the forwarder named, else the
   * forwarding server (the sender's own IP and server are not on the
   * wire).  An account too long for an owner key falls back the same
   * way. */
  if (htc_owner_key(owner, sizeof(owner), account, NULL, origin) < 0
      && htc_owner_key(owner, sizeof(owner), NULL, NULL, origin) < 0)
    ircd_strncpy(owner, HTC_OWNER_NONE, sizeof(owner));

  /* Store the message.  original_target is NULL on the federation
   * write-forward path — the federated source doesn't (yet) carry that
   * field, so replay's direction-reconstruction fallback handles PMs
   * stored via this path. */
  if (history_store_message(msgid, timestamp, target, NULL, sender,
                            (account[0] == '*') ? NULL : account,
                            type, content, client_tags, owner) == 0) {
    /* Layer 1: Broadcast CH A + if this is the first message in the channel */
    if (is_new_channel) {
      broadcast_channel_advertisement(target);
    }
  }
}

/** Send one CH W/WB line to @a server, untouched by the S2S tag state.
 * A write-forward goes out ahead of its message's own relay
 * (forward_channel_history, ircd_relay.c; m_tagmsg.c), while the relay's
 * msgid/time/sessid/alias overrides are already armed, and sendcmdto_one
 * consumes or clears every one of them: the relay would lose its tags.
 * The CH W payload names its msgid and time itself, so the line needs no
 * tags.  Ungated like sendcmdto_one: a burst-gated store still gets it.
 * @param[in] server Target storage server.
 * @param[in] pattern Format for the CH arguments (after "CH ").
 */
static void ch_write_line(struct Client *server, const char *pattern, ...)
{
  struct VarData vd;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  sendrawto_one(cli_from(server), "%:#C %s %v", &me, TOK_CHATHISTORY, &vd);
  va_end(vd.vd_args);
}

/** Send CH W or CH WB to a target server.
 * Handles chunking for large/multiline content.
 *
 * Content budget per P10 line = 510 (BUFSIZE-2) minus THIS row's header,
 * measured, never a fixed 400: the W/WB header alone (target, msgid,
 * timestamp, sender mask, account, type) can reach ~430 bytes, and
 * msgq silently truncates anything over 510, so a fixed budget cut W
 * content and corrupted WB base64 exactly the way the read path's R/Z/B
 * did before send_ch_response was measured (re-review 2026-09-07 R2).
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
  size_t full, cont;
  size_t content_len, b64_len, b64_total, offset;
  char *b64;
  int first;

  if (!content)
    content = "";

  {
    /* ":XX CH W <target> <msgid> <ts> <sender> <account> <c> :<content>" */
    size_t base = strlen(target) + strlen(msgid) + strlen(timestamp)
                + strlen(sender) + strlen(account) + 1 /* type */;
    size_t over = 3 /*:XX*/ + 4 /* CH W */ + 8 /* single spaces */ + 2 /* " :" */ + base;
    /* ":XX CH WB <target> <msgid> + :<chunk>" */
    size_t cover = 3 + 5 /* CH WB */ + 1 + strlen(target) + 1 + strlen(msgid)
                 + 2 /* " +" */ + 2 /* " :" */;
    full = (over + 4 < 510) ? (size_t)(510 - over - 4) : 8;    /* -4 safety */
    full &= ~((size_t)3);                                      /* mult of 4 for b64 */
    cont = (cover + 4 < 510) ? (size_t)(510 - cover - 4) : 8;
    cont &= ~((size_t)3);
  }

  /* Plain W only when the content has no newline AND fits one line. */
  if (strchr(content, '\n') == NULL && strlen(content) <= full) {
    ch_write_line(server, "W %s %s %s %s %s %c :%s",
                  target, msgid, timestamp, sender, account, type_char, content);
    return;
  }

  /* Base64 encode the content */
  content_len = strlen(content);
  b64_len = ((content_len + 2) / 3) * 4 + 1;
  b64 = MyMalloc(b64_len);
  if (!b64) {
    ch_write_line(server, "W %s %s %s %s %s %c :[content too large]",
                  target, msgid, timestamp, sender, account, type_char);
    return;
  }

  ch_base64_encode(content, content_len, b64);
  b64_total = strlen(b64);

  /* If it fits in one message, send complete WB message (no + marker) */
  if (b64_total <= full) {
    ch_write_line(server, "WB %s %s %s %s %s %c :%s",
                  target, msgid, timestamp, sender, account, type_char, b64);
    MyFree(b64);
    return;
  }

  /* Multi-chunk: the first line carries the full header (budget `full`),
   * continuations only target+msgid (budget `cont`). */
  offset = 0;
  first = 1;
  while (offset < b64_total) {
    size_t remaining = b64_total - offset;
    size_t budget = first ? full : cont;
    size_t chunk_size = (remaining > budget) ? budget : remaining;
    int more = (offset + chunk_size < b64_total);
    char chunk[520];

    if (chunk_size > sizeof(chunk) - 1)
      chunk_size = sizeof(chunk) - 1;
    memcpy(chunk, b64 + offset, chunk_size);
    chunk[chunk_size] = '\0';

    if (first) {
      if (more)
        ch_write_line(server, "WB %s %s %s %s %s %c + :%s",
                      target, msgid, timestamp, sender, account, type_char, chunk);
      else
        ch_write_line(server, "WB %s %s %s %s %s %c :%s",
                      target, msgid, timestamp, sender, account, type_char, chunk);
      first = 0;
    } else if (more) {
      ch_write_line(server, "WB %s %s + :%s",
                    target, msgid, chunk);
    } else {
      ch_write_line(server, "WB %s %s :%s",
                    target, msgid, chunk);
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
    case HISTORY_NOTICE:  type_char = 'N'; break;
    case HISTORY_JOIN:    type_char = 'J'; break;
    case HISTORY_PART:    type_char = 'L'; break;
    case HISTORY_QUIT:    type_char = 'Q'; break;
    case HISTORY_KICK:    type_char = 'I'; break;
    case HISTORY_MODE:    type_char = 'M'; break;
    case HISTORY_TOPIC:   type_char = 'O'; break;
    case HISTORY_TAGMSG:  type_char = 'T'; break;
    case HISTORY_NICK:    type_char = 'K'; break;
    case HISTORY_REDACT:  type_char = 'R'; break;
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
 *   CH A + :<channel> ...    - Add channel(s)
 *   CH A - :<channel> ...    - Remove channel(s)
 */

/* MAX_AD_SERVERS, MAX_AD_CHANNELS, struct ChathistoryAd, and server_ads[]
 * are defined above (near federation forward declarations) for visibility
 * in start_fed_targets_query() and count_storage_servers(). */

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

/** The retention a client of this server can count on: the widest over
 * the stores it can reach right now -- this server when it stores, and
 * every linked server advertising storage (CH A S / R; the entry goes
 * with the link).  Seconds; 0 when some reachable store keeps history
 * for good; -1 when no store is reachable.  Retention is decided per
 * server, so the network-wide answer changes with the topology: it
 * drops the moment a wider store leaves (it may never be back) and rises
 * when one links or widens.  A client must therefore treat the horizon
 * as current, never final (2026-09-20). */
int chathistory_retention_advertised(void)
{
  int widest = -1;
  unsigned int i;

  if (feature_bool(FEAT_CHATHISTORY_STORE)) {
    int days = feature_int(FEAT_CHATHISTORY_RETENTION);
    if (days <= 0)
      return 0;
    widest = days;
  }
  for (i = 0; i < MAX_AD_SERVERS; i++) {
    const struct ChathistoryAd *ad = server_ads[i];
    if (!ad || !ad->has_advertisement || !ad->is_storage_server)
      continue;
    if (ad->retention_days <= 0)
      return 0;
    if (ad->retention_days > widest)
      widest = ad->retention_days;
  }
  return widest < 0 ? -1 : widest * 86400;
}

/** Keep ISUPPORT evilnet/CHATHISTORYRETENTION at the value above and,
 * when it changed and @a announce is set, push a fresh 005 to the
 * clients that negotiated draft/extended-isupport.  Called from the
 * 005 build, the feature notifiers, and every store advertisement
 * change: a CH A S (a store linked), a CH A R (one changed its
 * retention), and the SQUIT that clears a store's entry. */
void chathistory_update_retention_isupport(int announce)
{
  static int last = -2;
  int now = chathistory_retention_advertised();

  if (now == last)
    return;
  last = now;
  if (now < 0)
    del_isupport("evilnet/CHATHISTORYRETENTION");
  else
    add_isupport_i("evilnet/CHATHISTORYRETENTION", now);
  if (announce)
    send_isupport_update();
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
  if (server_ads[idx] && server_ads[idx]->has_advertisement
      && server_ads[idx]->is_storage_server)
    absence_open(idx);   /* a known store is going away: remember it */
  rdx_retry_cancel(idx);   /* its catch-up waits for its next advertisement */
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
  chathistory_update_retention_isupport(1);   /* a store may have left: no grace */
  history_recv_peers_linked(storage_peers_linked());
}

/** Re-flood every known storage advertisement to a newly linked peer,
 * on behalf of each ad's owner.  Only the owner self-advertises (CH A S
 * at END_OF_BURST_ACK), so a server already behind a hub was never made
 * known to a peer that links later -- its ad stays NULL there and it is
 * never federated to, an asymmetric look-alike of the SOLO condition
 * (audit 2026-09-06 #21).  Skips servers reached VIA the new peer (they
 * are on its side and it already knows them). */
void chathistory_reflood_ads(struct Client *newpeer)
{
  int si;
  if (!newpeer || !IsServer(newpeer))
    return;
  for (si = 0; si < MAX_AD_SERVERS; si++) {
    struct ChathistoryAd *ad = server_ads[si];
    struct Client *owner;
    char yxx[4];
    char letters[CH_AD_LETTERS_MAX + 2];
    if (!ad || !ad->has_advertisement || !ad->is_storage_server)
      continue;
    inttobase64(yxx, si, 2);
    owner = FindNServer(yxx);
    if (!owner || owner == &me || owner == newpeer)
      continue;
    /* Only a REAL P10 server may be a message source here.  On the
     * crdt-mesh branch a tree-departed server is kept as a
     * STAT_MESH_SERVER stub (cli_user == NULL, dead-sink link); its ad
     * can linger, and a stub as a %C source SIGSEGVs (crdt-mesh skill
     * invariant #2).  Pure-CRDT nodes never advertise over P10 and are
     * outside the CH wire entirely.  IsServer is exact STAT_SERVER. */
    if (!IsServer(owner))
      continue;
    if (cli_from(owner) == newpeer)
      continue;   /* reached via the new peer -- it already has this ad */
    sendcmdto_one(owner, CMD_CHATHISTORY, newpeer, "A S %d%s", ad->retention_days,
                  ad_feature_suffix(ad, letters, sizeof(letters)));
  }
}

/** Is the burst that carries @a server's state to us still open?  Its own
 * (a store still bursting, its EB not seen yet) or that of any server on
 * the path to it: a server that gated its burst toward its new uplink holds
 * the burst tail (the users and channels of every server behind it) and its
 * EB, and drops the serv_butone lines meanwhile, the REDACTs of a store
 * behind it among them (52ac2d63).  That junction need not be our direct
 * link: in A-B-C-D, with D already linked to C and C relinking to B, A sees
 * C bursting while D and B are not, and D's CH A S still reaches A (C's
 * reflood goes to B ungated, B relays it).  So walk the uplinks to us, as
 * m_server's net-junction check does; for a direct store this is
 * IsBurst(server). */
static int ad_burst_pending(struct Client *server)
{
  struct Client *s;
  for (s = server; s && !IsMe(s) && cli_serv(s); s = cli_serv(s)->up)
    if (IsBurst(s))
      return 1;
  return 0;
}

/** A store advertised and the burst that carries its state here has ended:
 * it is back for real.  The one closer: the CH A S handler calls it for a
 * store that advertises after that burst (an ungated relink: its EB comes
 * first), chathistory_server_eob for one that advertised before it. */
/** The storage peers linked here whose burst has ended (W5 Push F, I-1:
 * the receive windows' storage-peer mark, history_recv_peers_linked). */
static int storage_peers_linked(void)
{
  int si, n = 0;
  char yxx[4];

  for (si = 0; si < MAX_AD_SERVERS; si++) {
    struct ChathistoryAd *ad = server_ads[si];
    struct Client *server;

    if (!ad || !ad->has_advertisement || !ad->is_storage_server || ad->eob_pending)
      continue;
    server = FindNServer(inttobase64(yxx, si, 2));
    if (server && server != &me && IsServer(server) && !is_ulined_server(server))
      n++;
  }
  return n;
}

static void ad_store_back(int idx)
{
  absence_close(idx);   /* back: close its absence */
  rdx_retry_reset(idx);   /* the kick below is the attempt (I-3) */
  redact_catchup_kick((unsigned int)idx);   /* what did we miss while it was away? */
  /* The first one after boot: this server receives the network's traffic
   * from now on, so its receive windows open (W5 Task 9; later calls do
   * nothing). */
  history_recv_link_up();
  /* A storage peer is linked: remembered on disk, so a restart before it
   * is back answers pages over spans never received here partial (W5 Push
   * F, I-1). */
  history_recv_peers_linked(storage_peers_linked());
}

/** A server's END_OF_BURST arrived (ms_end_of_burst, after ClearBurst; for
 * every server, relayed EBs included): every store whose CH A S came while
 * its burst was still open, and whose burst has now ended -- its own EB and
 * that of every server on the path to it seen -- is back (ad_store_back),
 * and its flag is cleared (W5 Task 12).  The EB that ends a pending store's
 * burst is its own or that of a server on its path, so one EB can settle
 * several stores; checking every pending ad covers them all.
 * @param[in] server The server whose EB this is. */
void chathistory_server_eob(struct Client *server)
{
  int si;
  if (!server || !IsServer(server))
    return;
  for (si = 0; si < MAX_AD_SERVERS; si++) {
    struct ChathistoryAd *ad = server_ads[si];
    struct Client *owner;
    char yxx[4];
    if (!ad || !ad->eob_pending)
      continue;
    inttobase64(yxx, si, 2);
    owner = FindNServer(yxx);
    if (!owner || owner == &me || !IsServer(owner) || ad_burst_pending(owner))
      continue;
    ad->eob_pending = 0;
    Debug((DEBUG_DEBUG, "CH A S: %s's burst ended (EB of %s): absence closed, REDACT catch-up kicked",
           cli_name(owner), cli_name(server)));
    ad_store_back(si);
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
  ircd_strncpy(lowerchan, channel, CHANNELLEN + 1);
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
  ircd_strncpy(lowerchan, channel, CHANNELLEN + 1);
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
  ircd_strncpy(lowerchan, channel, CHANNELLEN + 1);
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
                 "A :  %s: STORE retention=%d days (updated %s)%s%s",
                 cli_name(server),
                 ad->retention_days,
                 timebuf,
                 ad->letters[0] ? " features=" : "", ad->letters);
    } else if (ad->has_advertisement) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "A :  %s: advertisement present but not storage",
                 cli_name(server));
    }
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "A :Summary: %d storage server(s) of %d advertised",
             storage_count, total_count);

  /* Show our own status: the configured retention, and the coverage
   * CH A S / R advertise (less once oldest-overall eviction left a
   * floor inside retention). */
  if (feature_bool(FEAT_CHATHISTORY_STORE)) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "A :Local: STORE enabled, retention=%d days, advertising %d days",
               feature_int(FEAT_CHATHISTORY_RETENTION), history_coverage_days());
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
        sendcmdto_serv_butone_v3(&me, CMD_CHATHISTORY, NULL, "A F :%s", ctx->buffer);
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

  sendcmdto_serv_butone_v3(&me, CMD_CHATHISTORY, NULL, "A + :%s", channel);
}

/** Maximum size for CH A +/- channel list (leave room for command overhead) */
#define CH_A_PM_MAX_SIZE 400

/** Broadcast channel removals to all peer servers.
 * Called when channels' last messages are evicted/purged.
 * This is the callback function registered with history.c.
 * Batches multiple channels into single messages for efficiency.
 * @param[in] channels Array of channel names that were emptied.
 * @param[in] count Number of channels in array.
 */
static void broadcast_channel_removal(const char **channels, int count)
{
  char buffer[CH_A_PM_MAX_SIZE + 1];
  int buffer_len = 0;
  int i;

  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;  /* Only storage servers advertise channels */

  if (!channels || count <= 0)
    return;

  for (i = 0; i < count; i++) {
    const char *channel = channels[i];
    int chan_len;

    if (!channel || (channel[0] != '#' && channel[0] != '&'))
      continue;  /* Skip non-channels (DMs) */

    chan_len = strlen(channel);

    /* Check if adding this channel would overflow buffer */
    if (buffer_len + chan_len + 1 > CH_A_PM_MAX_SIZE) {
      /* Send current buffer */
      if (buffer_len > 0) {
        sendcmdto_serv_butone_v3(&me, CMD_CHATHISTORY, NULL, "A - :%s", buffer);
        Debug((DEBUG_DEBUG, "CH A -: Sent batch removal"));
      }
      buffer_len = 0;
    }

    /* Add channel to buffer (space-separated) */
    if (buffer_len > 0) {
      buffer[buffer_len++] = ' ';
    }
    strcpy(buffer + buffer_len, channel);
    buffer_len += chan_len;
  }

  /* Send remaining buffered channels */
  if (buffer_len > 0) {
    sendcmdto_serv_butone_v3(&me, CMD_CHATHISTORY, NULL, "A - :%s", buffer);
    Debug((DEBUG_DEBUG, "CH A -: Broadcasting %d channel removals", count));
  }
}

/** The coverage (days) last told to peers by CH A R, or seeded at start
 * with what every link's CH A S will carry; -1 = not known yet. */
static int coverage_advertised = -1;

/** history_coverage_days() may have changed (the trim engine moved or
 * cleared the coverage floor, a trim pass started, CHATHISTORY_RETENTION
 * changed): tell every IRCv3 peer the new value with CH A R -- only when
 * it differs from the last one told.  The engine calls this after every
 * committed oldest-overall slice, about once a second during a drain, and
 * at every pass start; the value changes far more rarely.  Links that
 * come up later hear the value of the moment in their CH A S
 * (ms_end_of_burst).  Main thread, never inside a store: it sends. */
void chathistory_coverage_changed(void)
{
  int now;

  if (!feature_bool(FEAT_CHATHISTORY_STORE))
    return;                                     /* we advertise no storage */
  now = history_coverage_days();
  if (now == coverage_advertised)
    return;
  coverage_advertised = now;
  if (!cli_serv(&me))
    return;                                     /* before make_server: no links */
  sendcmdto_serv_butone_v3(&me, CMD_CHATHISTORY, NULL, "A R %d", now);
  log_write(LS_SYSTEM, L_INFO, 0,
            "chathistory: advertising %d days of coverage (retention %d)",
            now, feature_int(FEAT_CHATHISTORY_RETENTION));
}

/** Initialize chathistory callbacks.
 * Registers the channel removal and coverage callbacks with the history
 * subsystem.  Called after history_init() succeeds (main thread).
 */
void chathistory_init_callbacks(void)
{
  history_set_channel_removed_callback(broadcast_channel_removal);
  /* The coverage peers will hear at their link's CH A S: a change from
   * it is what CH A R reports.  (history_init has read the floor.) */
  coverage_advertised = history_coverage_days();
  history_set_coverage_callback(chathistory_coverage_changed);
  Debug((DEBUG_DEBUG, "chathistory: registered channel removal and coverage callbacks"));
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

/** Free all pending read/write federation chunks that arrived from a dying
 *  link.  Without this, partial chunk reassembly leaks when a peer squits
 *  mid-stream (the continuation/end pieces never arrive).  Mirrors the
 *  per-link cleanup that multiline (s2s_multiline_cleanup_link) already does. */
void chathistory_fed_cleanup_link(struct Client *link)
{
  int i;
  if (!link)
    return;
  for (i = 0; i < MAX_PENDING_CHUNKS; i++)
    if (pending_chunks[i] && pending_chunks[i]->link == link)
      free_chunk(pending_chunks[i]);
  for (i = 0; i < MAX_PENDING_WRITE_CHUNKS; i++)
    if (pending_write_chunks[i] && pending_write_chunks[i]->link == link)
      free_write_chunk(pending_write_chunks[i]);
}

/** Create a new chunk entry.  @a client_tags are the first line's ,C
 * tags (may be NULL or empty): only that line carries them. */
static struct ChunkEntry *create_chunk(const char *reqid, const char *msgid,
                                       const char *timestamp, int type,
                                       const char *sender, const char *account,
                                       const char *client_tags)
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
  if (client_tags)
    ircd_strncpy(chunk->client_tags, client_tags, sizeof(chunk->client_tags));
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
  /* Cap reassembly at the largest a single legitimate message can be, base64-
   * expanded (+slack).  A peer streaming unbounded continuation lines would
   * otherwise grow this without limit until MyRealloc's exit(2) crashes the
   * daemon. */
  int cfg_max = feature_int(FEAT_MULTILINE_MAX_BYTES);
  size_t max_content = (cfg_max > 0) ? (size_t)cfg_max : 0;
  size_t ceiling;
  if (max_content < HISTORY_CONTENT_LEN)
    max_content = HISTORY_CONTENT_LEN;
  ceiling = max_content + max_content / 3 + 512;   /* base64 4/3 expansion + slack */
  if (chunk->b64_len + add_len + 1 > ceiling) {
    /* Malformed/abusive: refuse to grow further.  This function is void and
     * its two callers (CH B / CH WB continuation handlers) already call it
     * fire-and-forget with no return-value check; the !has_more finalize
     * path they both fall through to already handles a corrupt/incomplete
     * b64 blob safely (ch_base64_decode's own failure check) and always
     * frees the chunk regardless.  So matching the existing convention here
     * means simply declining to append further growth. */
    return;
  }
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
/* ---- redaction catch-up (requester side; design B) ------------------- */

struct RdxScanEmit { struct Client *to; const char *reqid; int n; };

static void rdx_scan_emit_cb(uint64_t time_ms, const char *redact_msgid,
                             const struct rdx_val *v, void *ctx)
{
  struct RdxScanEmit *sc = (struct RdxScanEmit *)ctx;
  sendcmdto_one(&me, CMD_CHATHISTORY, sc->to, "D %s %llu %s %s %s %s %s :%s", sc->reqid,
               (unsigned long long)time_ms, redact_msgid, v->target,
               v->parent_msgid, v->sender, v->account[0] ? v->account : "*",
               v->reason);
  sc->n++;
}

struct RdxCatchup {
  char     store_yxx[3];
  int      round;
  uint64_t start_ms;      /* when this round was issued */
  uint64_t last_ms;       /* newest row time seen (for a truncated continuation) */
};

static struct FedRequest *find_fed_request(const char *reqid);
static void free_fed_request(struct FedRequest *req);
static struct FedRequest *start_redact_catchup(const char *store_yxx, uint64_t since_ms,
                                               int round, int *slot_miss);
static void rdx_retry_arm(int idx, int soon, const char *why);

/* A CH D row -> a REDACT HistoryMessage on the request (target carried). */
static void add_fed_redact(struct FedRequest *req, const struct rdx_reply *rr)
{
  struct HistoryMessage *msg, *tail;
  struct RdxCatchup *rc = (struct RdxCatchup *)req->cb_data;
  if (req->leg.rows >= MAX_FED_MESSAGES) {
    req->fed_truncated = 1;
    return;
  }
  msg = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
  ircd_strncpy(msg->msgid, rr->redact_msgid, sizeof(msg->msgid) - 1);
  history_format_ms(msg->timestamp, sizeof(msg->timestamp), rr->time_ms);
  ircd_strncpy(msg->target, rr->v.target, sizeof(msg->target) - 1);
  ircd_strncpy(msg->sender, rr->v.sender, sizeof(msg->sender) - 1);
  ircd_strncpy(msg->account, rr->v.account, sizeof(msg->account) - 1);
  msg->type = HISTORY_REDACT;
  if (rr->v.reason[0])
    ircd_snprintf(0, msg->content, sizeof(msg->content), "%s :%s", rr->v.parent_msgid, rr->v.reason);
  else
    ircd_strncpy(msg->content, rr->v.parent_msgid, sizeof(msg->content) - 1);
  msg->next = NULL;
  if (!req->leg.msgs)
    req->leg.msgs = msg;
  else {
    for (tail = req->leg.msgs; tail->next; tail = tail->next) ;
    tail->next = msg;
  }
  req->leg.rows++;
  if (rc && rr->time_ms > rc->last_ms)
    rc->last_ms = rr->time_ms;
}

/* A catch-up continues a truncated reply for at most this many rounds. */
#define RDX_CATCHUP_ROUNDS 8

/* Completion: judge every row against this store, then move the watermark.
 * - A row is stored and shown to the channel's local members when this
 *   store holds its message and has not applied it (redact_apply_row,
 *   rdx_row_decide).  An orphan (a message this store does not hold: it
 *   never reached it, or the trim evicted it) is stored as a tombstone
 *   (redact_apply_row says why; none in a +P channel, logged "+P skipped")
 *   and shown to no client: no member here saw its message.  A redaction
 *   applied or tombstoned already, live or by an
 *   earlier round, is neither stored nor shown: every round re-reads from
 *   the watermark less a slack.
 * - A row the store could not read cuts the round (RETRY).
 * - A row for a channel that does not exist here (empty network-wide since)
 *   is skipped and counted, as before.
 * - The watermark (rdx_watermark_decide): a cut (a timeout, a CH E U, a row
 *   not read) keeps it.  A truncated reply continues from its newest row for
 *   up to RDX_CATCHUP_ROUNDS rounds; after the last, the watermark stops at
 *   that row, never past rows it did not fetch, and the next catch-up asks
 *   for the rest.  A complete one sets it to when the round was asked.
 * - While the store stays linked, a round that keeps the watermark, a
 *   continue that cannot start, and a last round that left more are asked
 *   again (rdx_retry_decide: backed off from 30 s to 10 min; the last-round
 *   case at 30 s), never only at the store's next relink: SEARCH (local),
 *   the context redaction lookup (F-2) and the catch-up replay all trust
 *   this store to hold every REDACT (W5 Push F, I-3).  A complete round
 *   resets the backoff. */
static void complete_redact_catchup(struct FedRequest *req)
{
  struct RdxCatchup *rc = (struct RdxCatchup *)req->cb_data;
  struct HistoryMessage *m;
  int applied = 0, repeats = 0, tombstones = 0, pskipped = 0, unread = 0, gone = 0;
  uint64_t wm = 0;
  enum rdx_wm wd;
  char gonebuf[48] = "";
  char pbuf[32] = "";
  char why[96];

  for (m = req->leg.msgs; m; m = m->next) {
    char parent[HISTORY_MSGID_LEN];
    struct Channel *chptr;
    const char *sp = strchr(m->content, ' ');
    const char *reason = NULL;
    size_t pl = sp ? (size_t)(sp - m->content) : strlen(m->content);
    if (pl == 0 || pl >= sizeof parent)
      continue;
    memcpy(parent, m->content, pl);
    parent[pl] = '\0';
    if (sp) {
      reason = sp + 1;
      if (*reason == ':') reason++;
      if (!*reason) reason = NULL;
    }
    if (!IsChannelName(m->target) || !(chptr = FindChannel(m->target))) {
      gone++;
      continue;
    }
    switch (redact_apply_row(&me, chptr, parent, m->msgid, history_parse_ms(m->timestamp),
                             reason, m->sender, m->account, 0)) {
    case RDX_ROW_APPLY:        applied++; break;
    case RDX_ROW_SKIP_APPLIED: repeats++; break;
    case RDX_ROW_SKIP_ORPHAN:  /* a tombstone, but none in +P (redact_apply_row) */
      if (chptr->mode.exmode & EXMODE_NOSTORAGE)
        pskipped++;
      else
        tombstones++;
      break;
    case RDX_ROW_RETRY:        unread++; req->cut = 1; break;
    }
  }
  if (!rc)
    return;

  wd = rdx_watermark_decide(req->cut, req->fed_truncated, rc->round, RDX_CATCHUP_ROUNDS,
                            rc->last_ms, rc->start_ms, &wm);
  if (wd != RDX_WM_KEEP)
    history_redact_watermark_set(wm);

  if (wd == RDX_WM_KEEP && unread)
    ircd_snprintf(0, why, sizeof why, "%d row(s) unread, watermark kept", unread);
  else if (wd == RDX_WM_KEEP && req->cut)
    ircd_snprintf(0, why, sizeof why, "cut, watermark kept");
  else if (wd == RDX_WM_KEEP)
    ircd_snprintf(0, why, sizeof why, "truncated with no row, watermark kept");
  else if (wd == RDX_WM_SET_CONTINUE)
    ircd_snprintf(0, why, sizeof why, "more -> round %d", rc->round + 1);
  else if (req->fed_truncated)
    ircd_snprintf(0, why, sizeof why, "more after %d rounds, watermark at the newest row %llu",
                  rc->round, (unsigned long long)wm);
  else
    ircd_snprintf(0, why, sizeof why, "watermark %llu", (unsigned long long)wm);
  if (gone)
    ircd_snprintf(0, gonebuf, sizeof gonebuf, ", %d for a channel not here", gone);
  if (pskipped)
    ircd_snprintf(0, pbuf, sizeof pbuf, ", %d +P skipped", pskipped);
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "REDACT catch-up from %s (round %d): applied %d, skipped %d applied, %d tombstone%s%s; %s",
            rc->store_yxx, rc->round, applied, repeats, tombstones, pbuf, gonebuf, why);

  {
    int idx = base64toint(rc->store_yxx);

    if (wd == RDX_WM_SET_CONTINUE) {
      int miss = 0;
      if (!start_redact_catchup(rc->store_yxx, rc->last_ms, rc->round + 1, &miss))
        rdx_retry_arm(idx, 0, miss ? "its next round found no free request slot"
                                   : "its next round could not start");
    } else {
      switch (rdx_retry_decide(wd, req->fed_truncated)) {
      case RDX_RETRY_BACKOFF:
        rdx_retry_arm(idx, 0, why);
        break;
      case RDX_RETRY_SOON:
        rdx_retry_arm(idx, 1, why);
        break;
      case RDX_RETRY_NONE:
      default:
        rdx_retry_reset(idx);
        break;
      }
    }
  }
}

static struct FedRequest *start_redact_catchup(const char *store_yxx, uint64_t since_ms,
                                               int round, int *slot_miss)
{
  struct FedRequest *req;
  struct RdxCatchup *rc;
  struct Client *server;
  char reqid[32];
  int i;
  if (slot_miss)
    *slot_miss = 0;
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION) || !history_is_available())
    return NULL;
  server = FindNServer(store_yxx);
  if (!server || server == &me)
    return NULL;
  for (i = 0; i < MAX_FED_REQUESTS; i++)
    if (!fed_requests[i])
      break;
  if (i >= MAX_FED_REQUESTS) {
    /* It used to return here silently (W5 Push F, I-3): the caller now
     * asks again while the store stays linked (rdx_retry_arm). */
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "REDACT catch-up from %s (round %d): no free request slot",
              store_yxx, round);
    if (slot_miss)
      *slot_miss = 1;
    return NULL;
  }
  ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu", cli_yxx(&me), ++fed_reqid_counter);
  req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
  rc = (struct RdxCatchup *)MyCalloc(1, sizeof(struct RdxCatchup));
  ircd_strncpy(rc->store_yxx, store_yxx, sizeof rc->store_yxx);
  rc->round = round;
  rc->start_ms = (uint64_t)CurrentTime * 1000ULL;
  ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
  ircd_strncpy(req->target, "*", sizeof(req->target) - 1);
  ircd_strncpy(req->client_yxx, cli_yxx(&me), sizeof(req->client_yxx));
  req->servers_pending = 1;
  req->start_time = CurrentTime;
  req->limit = 200;
  req->completion_cb = complete_redact_catchup;
  req->cb_data = rc;
  fed_requests[i] = req;
  timer_add(timer_init(&req->timer), fed_timeout_callback, (void *)req, TT_RELATIVE,
            feature_int(FEAT_CHATHISTORY_TIMEOUT));
  req->timer_active = 1;
  sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q * D %llu %d %s %s",
                (unsigned long long)since_ms, req->limit, reqid, store_yxx);
  Debug((DEBUG_DEBUG, "REDACT catch-up: asked %s since %llu (round %d)",
         store_yxx, (unsigned long long)since_ms, round));
  return req;
}

/* Trigger: a store just (re)advertised itself -- first sight after our
 * boot, or back after a split -- or its retry came round (rdx_retry_cb).
 * Ask it for what we may have missed since our watermark (60 s slack; 0 =
 * everything, bounded per round).  No free request slot: asked again
 * while it stays linked. */
static void redact_catchup_kick(unsigned int store_num)
{
  char yxx[4];
  uint64_t wm;
  int miss = 0;
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION) || !history_is_available())
    return;
  wm = history_redact_watermark_get();
  if (!start_redact_catchup(inttobase64(yxx, (int)store_num, 2),
                            wm > 60000 ? wm - 60000 : 0, 1, &miss) && miss)
    rdx_retry_arm((int)store_num, 0, "no free request slot");
}

/* ---- the per-store catch-up retry (W5 Push F, I-3) ------------------ */
/* A catch-up that failed -- a slot miss at the kick, a round that kept the */
/* watermark (a timeout, a CH E U, a row not read), a continue that could  */
/* not start -- or stopped at RDX_CATCHUP_ROUNDS with more left used to    */
/* wait for that store's next (re)advertisement, possibly weeks; SEARCH    */
/* (local), F-2's authoritative lookup and the catch-up replay showed the  */
/* redacted message meanwhile.  Now it is asked again while the store     */
/* stays linked: one timer per store, backed off (rdx_retry_next_delay),  */
/* reset by a complete round, dropped when the store leaves                */
/* (clear_server_ad) or advertises again (ad_store_back kicks at once).    */
/* No request slot is reserved for the catch-up: the retry covers a miss.  */

struct RdxRetry {
  struct Timer timer;
  int idx;                 /**< the store's server_ads index */
  int delay;               /**< the interval last armed, seconds (0: none yet) */
  unsigned char armed;     /**< the timer is queued */
  unsigned char in_cb;     /**< inside its expiry (timer_run holds the timer) */
  unsigned char gone;      /**< the store left: freed at its ET_DESTROY */
};
static struct RdxRetry *rdx_retry[MAX_AD_SERVERS];

/** Store @a idx, when it is linked here, advertises storage and its burst
 * has ended; else NULL. */
static struct Client *rdx_store_up(int idx)
{
  struct ChathistoryAd *ad;
  struct Client *server;
  char yxx[4];

  if (idx < 0 || idx >= MAX_AD_SERVERS)
    return NULL;
  ad = server_ads[idx];
  if (!ad || !ad->has_advertisement || !ad->is_storage_server || ad->eob_pending)
    return NULL;
  server = FindNServer(inttobase64(yxx, idx, 2));
  if (!server || server == &me || !IsServer(server))
    return NULL;
  return server;
}

static void rdx_retry_cb(struct Event *ev)
{
  struct RdxRetry *rr = (struct RdxRetry *)t_data(ev_timer(ev));

  if (!rr)
    return;
  switch (ev_type(ev)) {
  case ET_EXPIRE: {
    struct Client *server;

    rr->armed = 0;
    if (rr->gone || !(server = rdx_store_up(rr->idx)))
      break;   /* gone, or not back yet: its next advertisement kicks */
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "REDACT catch-up from %s: asking again (after %d s)",
              cli_name(server), rr->delay);
    rr->in_cb = 1;
    redact_catchup_kick((unsigned int)rr->idx);
    rr->in_cb = 0;
    break;
  }
  case ET_DESTROY:
    if (rr->gone)
      MyFree(rr);
    break;
  default:
    break;
  }
}

/** Ask store @a idx again later, while it stays linked: at the first
 * interval when @a soon (its last round moved on and left more), else at
 * the next backed-off one.  One retry at a time per store; nothing when it
 * is not linked (its next advertisement kicks).  @a why is logged. */
static void rdx_retry_arm(int idx, int soon, const char *why)
{
  struct RdxRetry *rr;
  struct Client *server = rdx_store_up(idx);

  if (!server)
    return;
  if (!(rr = rdx_retry[idx])) {
    rr = (struct RdxRetry *)MyCalloc(1, sizeof(*rr));
    rr->idx = idx;
    rdx_retry[idx] = rr;
  }
  if (rr->armed)
    return;
  rr->delay = soon ? RDX_RETRY_FIRST_S : rdx_retry_next_delay(rr->delay);
  /* Inside its own expiry timer_run still holds the timer: re-add it
   * without timer_init (GEN_READD re-queues it after the callback). */
  if (rr->in_cb)
    timer_add(&rr->timer, rdx_retry_cb, (void *)rr, TT_RELATIVE, rr->delay);
  else
    timer_add(timer_init(&rr->timer), rdx_retry_cb, (void *)rr, TT_RELATIVE, rr->delay);
  rr->armed = 1;
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "REDACT catch-up from %s: %s; asking again in %d s while it stays linked",
            cli_name(server), why, rr->delay);
}

/** Store @a idx's catch-up completed, or it advertised again (a fresh
 * catch-up starts): the next failure starts at the first interval, and a
 * queued retry is dropped. */
static void rdx_retry_reset(int idx)
{
  struct RdxRetry *rr = (idx >= 0 && idx < MAX_AD_SERVERS) ? rdx_retry[idx] : NULL;

  if (!rr)
    return;
  rr->delay = 0;
  if (rr->armed) {
    rr->armed = 0;
    timer_del(&rr->timer);   /* ET_DESTROY: kept (not gone) */
  }
}

/** Store @a idx left (clear_server_ad): its retry goes with it. */
static void rdx_retry_cancel(int idx)
{
  struct RdxRetry *rr;

  if (idx < 0 || idx >= MAX_AD_SERVERS || !(rr = rdx_retry[idx]))
    return;
  rdx_retry[idx] = NULL;
  rr->gone = 1;
  if (rr->armed) {
    rr->armed = 0;
    timer_del(&rr->timer);   /* ET_DESTROY frees it -- now, or after its expiry */
  } else if (!rr->in_cb)
    MyFree(rr);
  /* else inside its expiry: timer_run's ET_DESTROY frees it */
}

static struct FedRequest *find_fed_request(const char *reqid)
{
  int i;
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (fed_requests[i] && strcmp(fed_requests[i]->reqid, reqid) == 0)
      return fed_requests[i];
  }
  return NULL;
}

/** The request a reply's reqid belongs to, and its leg: the page leg's
 * reqid exactly, else the children leg's, <reqid>K (W5 Task 14; a minted
 * reqid ends in a digit, so the two never collide).
 * @param[out] k_leg 1 for the children leg, else 0. */
static struct FedRequest *find_fed_request_leg(const char *reqid, int *k_leg)
{
  struct FedRequest *req;
  size_t len;
  int i;

  *k_leg = 0;
  if (!reqid)
    return NULL;
  if ((req = find_fed_request(reqid)))
    return req;
  len = strlen(reqid);
  if (len < 2 || reqid[len - 1] != 'K')
    return NULL;
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    req = fed_requests[i];
    if (req && strlen(req->reqid) == len - 1 && strncmp(req->reqid, reqid, len - 1) == 0) {
      *k_leg = 1;
      return req;
    }
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
  hm_leg_free(&req->leg);
  if (req->k_msgs)
    history_free_messages(req->k_msgs);
  if (req->k_ids)
    MyFree(req->k_ids);
  /* Its CH B entries still in reassembly (a row cut off by the timeout or
   * the request's end): the table is global and has no expiry, so a slot
   * left behind would make later pages lose rows (W5 Task 15 fix round 2). */
  for (i = 0; i < MAX_PENDING_CHUNKS; i++)
    if (pending_chunks[i] && hm_chunk_of_request(pending_chunks[i]->key, req->reqid))
      free_chunk(pending_chunks[i]);

  /* Free custom callback data */
  if (req->cb_data) {
    if (req->cleanup_cb)
      req->cleanup_cb(req->cb_data);
    else
      MyFree(req->cb_data);
    req->cb_data = NULL;
  }

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

/** Add a message to the federated results list.  @a client_tags are the
 * row's client-only tags as its responder sent them (the ,C segment of a
 * CH R or first CH B line, or the record a CH Z carries); NULL or empty
 * for none (an older responder sends none).  A CH C declaration's tags
 * fill in only when the row brought none of its own.
 *
 * hm_leg_add decides what it is (W5 Task 15): a context child when a CH C
 * declared it (the declaration taken out of the table), or -- on a page,
 * once a declaration was lost to a full table (F-3's fallback) -- when its
 * own parent is a row of the page; else a row.  A context child counts
 * against MAX_FED_CONTEXT, never MAX_FED_MESSAGES, and past it is dropped
 * without cutting the page (F-4).  A row past MAX_FED_MESSAGES is dropped
 * and cuts the page.  A REDACT dropped either way leaves its target in
 * req->leg.side, so the page still hides it. */
static void add_fed_message(struct FedRequest *req, const char *msgid,
                            const char *timestamp, int type,
                            const char *sender, const char *account,
                            const char *content, const char *client_tags)
{
  struct HistoryMessage *msg;

  if (!req)
    return;

  msg = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
  ircd_strncpy(msg->msgid, msgid, sizeof(msg->msgid));
  ircd_strncpy(msg->timestamp, timestamp, sizeof(msg->timestamp));
  ircd_strncpy(msg->target, req->target, sizeof(msg->target));
  ircd_strncpy(msg->sender, sender, sizeof(msg->sender));
  if (account && strcmp(account, "*") != 0)
    ircd_strncpy(msg->account, account, sizeof(msg->account));
  msg->type = type;
  if (content)
    ircd_strncpy(msg->content, content, sizeof(msg->content));
  if (client_tags)
    ircd_strncpy(msg->client_tags, client_tags, sizeof(msg->client_tags));

  switch (hm_leg_add(&req->leg, msg, req->local_msgs,
                     MAX_FED_MESSAGES, MAX_FED_CONTEXT)) {
  case HM_DROP_ROW:
    req->fed_truncated = 1;   /* rows beyond the cap are dropped: say so */
    req->cut = 1;             /* ... and dropped rows can be anywhere: partial */
    break;
  case HM_DROP_CONTEXT:
    /* Context only: never partial, never a row lost. */
    Debug((DEBUG_DEBUG, "chathistory %s: request %s keeps %d context children; "
           "%s dropped", req->target, req->reqid, MAX_FED_CONTEXT, msgid));
    break;
  default:
    break;
  }
}

/** qsort/bsearch order of the children request's msgid list. */
static int fed_k_id_cmp(const void *a, const void *b)
{
  return strcmp((const char *)a, (const char *)b);
}

/** Was @a msgid one of the rows this request asked the children of (CH Q K,
 * W5 Task 14)?  A store answers only for the msgids it was sent, so a child
 * of any other parent is not this page's (fix round 1). */
static int fed_k_listed(const struct FedRequest *req, const char *msgid)
{
  char key[HISTORY_MSGID_LEN];

  if (!req->k_ids || req->k_id_count <= 0 || !msgid || !msgid[0])
    return 0;
  ircd_strncpy(key, msgid, sizeof(key));
  return bsearch(key, req->k_ids, (size_t)req->k_id_count, sizeof(req->k_ids[0]),
                 fed_k_id_cmp) != NULL;
}

/** Add a row of the children leg (CH Q K, W5 Task 14) to req->k_msgs as a
 * context child.  Its parent is its CH C declaration's (removed from the
 * table on match), else the row's own (hm_context_parent: a TAGMSG's
 * +reply / +draft/reply, a REDACT's first content word); the
 * declaration's tags fill in when the row brought none.  Dropped (and
 * counted) past FED_CHILDREN_MAX children (a REDACT's target is kept in
 * req->leg.side all the same), with no parent, with a parent the request
 * did not ask about (fed_k_listed), after the answer went out, or unless
 * it is a TAGMSG or a REDACT.  Never touches the page leg's rows,
 * fed_truncated or cut: a child lost costs a page context, never a row. */
static void add_fed_child(struct FedRequest *req, const char *msgid,
                          const char *timestamp, int type,
                          const char *sender, const char *account,
                          const char *content, const char *client_tags)
{
  struct HistoryMessage *msg, **tp;
  char parent[HISTORY_MSGID_LEN] = "";
  char dtags[sizeof(req->k_decl[0].tags)] = "";
  int i;

  for (i = 0; i < req->k_decl_count; i++) {
    if (strcmp(req->k_decl[i].child, msgid) == 0) {
      ircd_strncpy(parent, req->k_decl[i].parent, sizeof(parent));
      ircd_strncpy(dtags, req->k_decl[i].tags, sizeof(dtags));
      req->k_decl[i] = req->k_decl[--req->k_decl_count];
      break;
    }
  }
  if (req->response_sent || req->k_count >= FED_CHILDREN_MAX
      || (type != HISTORY_TAGMSG && type != HISTORY_REDACT)) {
    /* A REDACT past the cap still hides its target (W5 Task 15 fix round
     * 1): it is kept in the request's side set. */
    if (!req->response_sent && req->k_count >= FED_CHILDREN_MAX)
      hm_idset_note_redact(&req->leg.side, type, content);
    fed_children_dropped++;
    return;
  }
  msg = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
  ircd_strncpy(msg->msgid, msgid, sizeof(msg->msgid));
  ircd_strncpy(msg->timestamp, timestamp, sizeof(msg->timestamp));
  ircd_strncpy(msg->target, req->target, sizeof(msg->target));
  ircd_strncpy(msg->sender, sender, sizeof(msg->sender));
  if (account && strcmp(account, "*") != 0)
    ircd_strncpy(msg->account, account, sizeof(msg->account));
  msg->type = type;
  if (content)
    ircd_strncpy(msg->content, content, sizeof(msg->content));
  if (client_tags && client_tags[0])
    ircd_strncpy(msg->client_tags, client_tags, sizeof(msg->client_tags));
  else if (dtags[0])
    ircd_strncpy(msg->client_tags, dtags, sizeof(msg->client_tags));
  if ((!parent[0] && !hm_context_parent(msg, parent, sizeof(parent)))
      || !fed_k_listed(req, parent)) {
    history_free_messages(msg);
    fed_children_dropped++;
    return;
  }
  msg->is_context = 1;
  ircd_strncpy(msg->ctx_parent, parent, sizeof(msg->ctx_parent));
  for (tp = &req->k_msgs; *tp; tp = &(*tp)->next)
    ;
  *tp = msg;
  req->k_count++;
  fed_children_rows++;
}

/** Unlink federated context children (marked via CH C) from a
 * request's page leg.  They must not participate in the ordinary
 * merge -- context children are spliced after their parent, uncounted
 * (#526), not sorted/limited as rows (hm_leg_extract_context). */
static struct HistoryMessage *extract_fed_context(struct FedRequest *req)
{
  return hm_leg_extract_context(&req->leg);
}

/** Keep the target of every REDACT the peers sent -- rows, page-leg
 * context, children -- in the request's side set, before the merge (W5
 * Task 15 fix round 2, I-B): the merge's limit (an AFTER page keeps the
 * oldest rows, an AROUND page is cut on its reference) can cut a peer's
 * REDACT row while the older row it names stays on the page.  Within the
 * side set's bound; past it the page fails closed (fed_close_page). */
static void fed_seed_side(struct FedRequest *req, const struct HistoryMessage *fed_ctx)
{
  hm_idset_note_list(&req->leg.side, req->leg.msgs);
  hm_idset_note_list(&req->leg.side, fed_ctx);
  hm_idset_note_list(&req->leg.side, req->k_msgs);
}

/** A REDACT this request could not keep -- its side set full, or lost
 * before it was read with no declaration to name its target
 * (fed_row_lost) -- may name any row of the page, a local one included (a
 * children-leg REDACT always names one; a peer row's local copy is the one
 * the merge keeps; a context-only page is all local rows): every row of
 * the finished page a REDACT could name is withheld (hm_leg_close_page;
 * W5 Task 15 fix rounds 1 and 2).  Never partial: as every other
 * fail-closed hide (an unreadable child, a lookup that cannot tell). */
static void fed_close_page(struct FedRequest *req, struct HistoryMessage **page)
{
  int n = hm_leg_close_page(&req->leg, page);

  if (req->leg.side.lost)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "chathistory %s: request %s lost a REDACT it could not keep; "
              "%d row(s) of the page withheld (fail closed)",
              req->target, req->reqid, n);
}

/** Take a declaration out of the children leg's table (W5 Task 15 fix
 * round 2): @a msgid's, its parent copied to @a parent.
 * @return 1 when it was declared, else 0. */
static int fed_k_forget_decl(struct FedRequest *req, const char *msgid,
                             char *parent, size_t plen)
{
  int i;

  for (i = 0; i < req->k_decl_count; i++) {
    if (strcmp(req->k_decl[i].child, msgid) == 0) {
      ircd_strncpy(parent, req->k_decl[i].parent, plen);
      req->k_decl[i] = req->k_decl[--req->k_decl_count];
      return 1;
    }
  }
  return 0;
}

/** A peer's row this request could not take before reading its content
 * (W5 Task 15 fix rounds 1 and 2): a CH B whose first line found no
 * reassembly slot (MAX_PENDING_CHUNKS), a CH B or CH Z that would not
 * decode, a CH Z with no zstd here.  @a type is the type its line carried.
 * A REDACT row can come this way: its content is "<msgid> :<reason>", and
 * a long or encoded reason makes send_ch_response use CH B, a compressed
 * record CH Z.
 *   - A declared REDACT (CH C, on either leg) still names its target: its
 *     declaration's parent goes into the side set, and the page hides it.
 *   - An undeclared REDACT names a target this request cannot know: the
 *     page fails closed (req->leg.side.lost; fed_close_page).
 *   - A row lost from the page leg that its CH C did not declare context
 *     is a row lost: the page is cut (partial).  Lost context -- declared,
 *     or on the children leg -- is never partial. */
static void fed_row_lost(struct FedRequest *req, int k_leg, const char *msgid,
                         int type)
{
  char parent[HISTORY_MSGID_LEN] = "";
  int declared;

  if (k_leg)
    declared = fed_k_forget_decl(req, msgid, parent, sizeof(parent));
  else
    declared = hm_leg_forget_decl(&req->leg, msgid, parent, sizeof(parent));
  if (type == HISTORY_REDACT) {
    if (declared && parent[0])
      hm_idset_add(&req->leg.side, parent);
    else
      req->leg.side.lost = 1;
  }
  if (!k_leg && !declared)
    req->cut = 1;
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "chathistory %s: request %s lost a peer's row %s (type %d) before "
            "reading it%s", req->target, req->reqid, msgid, type,
            type != HISTORY_REDACT ? ""
            : req->leg.side.lost ? ": the page fails closed"
            : ": its declared target is still hidden");
}

/** The rows the peers sent as rows of their own pages, for a page
 * federated for its context only (FED_WHY_CONTEXT; their declared context
 * is already out, extract_fed_context).  @a rows is the local page.
 *   - A duplicate of a local row is not added; the local row takes its
 *     client-only tags when it has none (hm_merge's rule: a local row
 *     stored before relays kept them, W5 Task 2).
 *   - A reaction or REDACT of a local row moves out of req->leg.msgs onto
 *     the end of @a ctx_list, marked as that row's context child: a peer
 *     whose page reaches past ours (it lacks some of our rows) holds such
 *     a child as a row, not behind a CH C.
 *   - Any other row is not on the page.  One strictly between the oldest
 *     and the newest local row should not exist -- the page's own span
 *     was received here -- so the page is counted (STATS "window
 *     misses") and logged: a sign that a receive window claimed what this
 *     server did not receive.  Not when the peers' walks were wider than
 *     this page's (req->peer_walk_wider: strict presence, a requester with
 *     no account), nor is it proof: a peer's presence records, replicated
 *     by observation, can differ from this server's.
 * The rows left in req->leg.msgs are freed with the request.
 * @return The extended context list (hm_splice_context takes it). */
static struct HistoryMessage *context_only_peer_rows(struct FedRequest *req,
                                                     struct HistoryMessage *rows,
                                                     struct HistoryMessage *ctx_list)
{
  struct HistoryMessage **pp = &req->leg.msgs, *tail = ctx_list, *r;
  struct HistoryMessage *first_miss = NULL;
  uint64_t oldest = 0, newest = 0;
  int misses = 0;

  while (tail && tail->next)
    tail = tail->next;
  for (r = rows; r; r = r->next) {
    uint64_t t = history_parse_ms(r->timestamp);
    if (!oldest || t < oldest)
      oldest = t;
    if (t > newest)
      newest = t;
  }
  while (*pp) {
    struct HistoryMessage *m = *pp;
    char parent[HISTORY_MSGID_LEN];
    uint64_t t;

    if ((r = hm_find_dup(rows, m))) {
      if (!r->client_tags[0] && m->client_tags[0])
        ircd_strncpy(r->client_tags, m->client_tags, sizeof(r->client_tags));
      pp = &m->next;
      continue;
    }
    if (hm_context_parent(m, parent, sizeof(parent))) {
      for (r = rows; r; r = r->next)
        if (!r->is_context && strcmp(r->msgid, parent) == 0)
          break;
      if (r) {
        *pp = m->next;
        m->next = NULL;
        m->is_context = 1;
        ircd_strncpy(m->ctx_parent, parent, sizeof(m->ctx_parent));
        if (tail)
          tail->next = m;
        else
          ctx_list = m;
        tail = m;
        req->leg.rows--;
        continue;
      }
    }
    t = history_parse_ms(m->timestamp);
    if (oldest < t && t < newest) {
      if (!misses++)
        first_miss = m;
    }
    pp = &m->next;
  }
  if (misses && !req->peer_walk_wider) {
    fed_window_misses++;
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "chathistory: %s: a page fanned out for its context only got "
              "%d row(s) inside its own span that this store lacks (first "
              "%s at %s): a receive window may have claimed what was not "
              "received",
              req->target, misses, first_miss->msgid, first_miss->timestamp);
  }
  return ctx_list;
}

/** Send federation results to client (does NOT free the request)
 * Call this to send results, then let timer destroy event free the request.
 */
static void send_fed_response(struct FedRequest *req)
{
  struct HistoryMessage *merged;
  struct Client *client;
  int total, flags;

  if (!req || req->response_sent)
    return;

  req->response_sent = 1;  /* Mark as sent to prevent double-send */

  /* Look up the client by numeric - they may have disconnected */
  client = findNUser(req->client_yxx);
  if (!client) {
    /* Client disconnected, nothing to send */
    return;
  }

  /* Merge local and federated results.  Context children declared by
   * remote responders (CH C) are pulled aside first -- they splice
   * after their parents below instead of competing as rows. */
  {
    struct HistoryMessage *fed_ctx = extract_fed_context(req);

    /* Every REDACT the peers sent keeps its target past the merge's cut
     * (I-B). */
    fed_seed_side(req, fed_ctx);

    if (req->context_only) {
      /* Federated for the rows' context only: the page's own span was
       * received here and no absence overlaps it, so the local rows are
       * complete for it and ARE the page -- a peer's wider page (an AROUND
       * centred where it lacks our rows, an AFTER that runs on past them)
       * must not move or trim it.  The peers add context to those rows: the
       * children they declared (CH C) and any row of theirs that is a
       * child of ours; a duplicate of ours lends it its client-only tags
       * (context_only_peer_rows).  The local list goes to the replay engine
       * whole; it leaves the request so free_fed_request does not free it
       * too. */
      merged = req->local_msgs;
      req->local_msgs = NULL;
      fed_ctx = context_only_peer_rows(req, merged, fed_ctx);
    } else {
      /* Once a CH C was lost to a full table (and only then), a peer row
       * with no declaration whose own parent is a row of the page is
       * context, not a row (W5 Task 15, F-3's fallback): one whose parent
       * arrived after it, from another responder (add_fed_message took the
       * rest).  A child whose parent the merge drops is freed by the
       * splice. */
      hm_leg_derive(&req->leg, req->local_msgs, &fed_ctx);
      if (req->around) {
        /* Merged uncut, then centred on the reference (hm_trim_around frees
         * the rows it cuts, which are the merge's own copies). */
        merged = hm_trim_around(hm_merge(req->local_msgs, req->leg.msgs, INT_MAX, 0),
                                req->limit, req->around_ms, req->around_msgid);
      } else
        merged = hm_merge(req->local_msgs, req->leg.msgs, req->limit, req->keep_oldest);
    }

    /* The children leg's (CH Q K, W5 Task 14) go after the page leg's
     * context: the children of local rows a peer holds and this store
     * lacks.  They are never counted (total is counted before them) and
     * spliced like the rest, so a child already on the page -- attached
     * locally, brought by the page leg, or a row of the merge -- appears
     * once (hm_splice_context's hm_find_dup), and one whose parent the
     * merge dropped is freed. */
    if (req->k_msgs) {
      struct HistoryMessage **tp = &fed_ctx;
      while (*tp)
        tp = &(*tp)->next;
      *tp = req->k_msgs;
      req->k_msgs = NULL;
      req->k_count = 0;
    }

    /* Count total */
    total = 0;
    for (struct HistoryMessage *m = merged; m; m = m->next)
      total++;

    /* Attach context messages (reactions, redacts) to their parents;
     * then splice the remote-only children (dedup against the local
     * attach by msgid). */
    history_attach_context(req->target, merged);
    hm_splice_context(merged, fed_ctx);
    /* A REDACT lost with its target unknown: the page fails closed. */
    fed_close_page(req, &merged);
  }
  /* Async replay — ownership of merged list transfers to ReplayState.
   * Completeness judged on the PRE-filter merged total (see the
   * query_count note in the subcommand handlers). */
  /* Partial = a responder was cut (timeout/SQUIT/aggregate cap) or a
   * known store was away over the span (chathistory-partial).  A page
   * federated for its context only is as complete as its local walk: a
   * lost responder or a store away costs it context, never a row, and that
   * is not partial (user decision 2026-11-08 15:08). */
  if (req->context_only)
    flags = req->local_incomplete ? 0 : REPLAY_COMPLETE;
  else
    flags = ((total < req->limit && !req->fed_truncated
              && !req->local_incomplete) ? REPLAY_COMPLETE : 0)
            | ((req->cut || req->partial) ? REPLAY_PARTIAL : 0);
  total = presence_filter_and_replay(client, req->target, &merged, total,
                                     req->ops_override, req->label, flags,
                                     req->requested, &req->leg.side);
}

/** Complete a federation request - sends response and triggers cleanup.
 * For timeout path: timer_run will call ET_DESTROY after we return.
 * For early completion: we call timer_del which triggers ET_DESTROY.
 */
static void complete_fed_request(struct FedRequest *req)
{
  if (!req)
    return;

  /* Use custom completion if set, otherwise default to send_fed_response */
  if (req->completion_cb)
    req->completion_cb(req);
  else
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
    /* Timer expired - complete with whatever we have.  Any responder
     * that never answered means the page is INCOMPLETE: mark it so the
     * merged completeness withholds @draft/chathistory-end instead of
     * telling an end-tag client there is no more history (audit
     * 2026-09-06 #10; also covers a peer that SQUIT mid-query).
     * Don't free here - timer_run will send ET_DESTROY after we return. */
    req->timer_active = 0;
    if (req->servers_pending > 0) {
      req->fed_truncated = 1;
      req->cut = 1;   /* a responder never answered: partial */
    }
    /* A children-leg store that never answered (W5 Task 14) costs the page
     * context only: counted, never partial. */
    if (req->k_pending > 0)
      fed_children_unanswered += (unsigned long)req->k_pending;
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
  int i;
  char buf[4];

  /* Iterate all known storage servers in the network (not just direct links).
   * server_ads[] is populated via CH A S propagation and tracks all servers. */
  for (i = 0; i < MAX_AD_SERVERS; i++) {
    struct ChathistoryAd *ad = server_ads[i];
    struct Client *server;

    if (!ad || !ad->has_advertisement || !ad->is_storage_server)
      continue;

    /* Resolve numeric index to server struct */
    server = FindNServer(inttobase64(buf, i, 2));
    if (!server || server == &me)
      continue;

    /* Skip U-lined servers (services) */
    if (is_ulined_server(server))
      continue;

    /* Skip servers whose retention doesn't cover query time */
    if (query_time != 0 && !server_retention_covers(server, query_time))
      continue;

    /* Layer 1 channel-list filter is intentionally NOT applied here:
     * CH A F is emitted once at burst-time and not refreshed when new
     * channels are created.  Filtering by it would render every
     * post-burst channel unreachable via federation — the test
     * channel "client1 creates #X on primary, client2 queries from
     * leaf" always fails because #X didn't exist when primary sent
     * its CH A F.  The plan for a properly-refreshed channel
     * presence filter is the bloom-filter design at
     * .claude/plans/federation-dedup-s2s-msgid.md (deferred).  Until
     * that lands, we federate to every storage-capable peer and let
     * the remote return an empty batch if it has nothing for the
     * channel — a small extra cost vs. silently breaking federation
     * for new channels. */
    (void)target;  /* parameter retained for future bloom-filter path */

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
/** Resolve a client reference (ISO timestamp, msgid, or *) on @a target's
 * store key to a Unix "sec.mmm" string for BETWEEN direction comparison;
 * empty on failure. */
static void fed_ref_to_unix(const char *target, const char *ref, char *out, size_t n)
{
  enum HistoryRefType t;
  const char *v;
  out[0] = '\0';
  if (!ref || parse_reference(ref, &t, &v) != 0)
    return;
  if (t == HISTORY_REF_TIMESTAMP) {
    if (history_iso_to_unix(v, out, n) != 0)
      ircd_strncpy(out, v, n - 1), out[n-1] = '\0';
  } else if (t == HISTORY_REF_MSGID) {
    if (history_msgid_ref_timestamp(target, v, out) < 0)
      out[0] = '\0';
  }
  /* HISTORY_REF_NONE ("*"): leave empty -> no direction preference. */
}

/** hm_children_wanted's test for a channel page's row (W5 Task 14): was
 * [@a ms, now], widened to whole seconds, received here and clear of every
 * storage peer's absence?  The page's own context check (federation_wanted),
 * applied per row; @a ctx is the channel name. */
static int fed_ctx_received(uint64_t ms, void *ctx)
{
  int partial = 0;
  return channel_range_check((const char *)ctx, (time_t)(ms / 1000ULL), 0,
                             &partial) == FED_WHY_NONE;
}

/** Is @a si's ad a store a children request may go to: it advertised
 * storage with K, and it is a linked, non-U-lined server other than us
 * (every skip the page loop applies, except retention: a child's time is
 * not its parent's, so a short-retention store can hold a recent reaction
 * to an old row; W5 Task 14). */
static struct Client *children_store(int si)
{
  struct ChathistoryAd *ad = server_ads[si];
  struct Client *server;
  char yxx[4];

  if (!ad || !ad->has_advertisement || !ad->is_storage_server
      || !(ad->features & CH_AD_CHILDREN))
    return NULL;
  server = FindNServer(inttobase64(yxx, si, 2));
  if (!server || server == &me || is_ulined_server(server))
    return NULL;
  return server;
}

/** Send one store the children request (CH Q K, W5 Task 14): @a ids packed
 * into lines of at most @a room bytes of list, '+' on every line but the
 * last ('*').  Every id fits a line (start_fed_query dropped any that
 * could not).
 * @return the lines sent. */
static int send_children_request(struct Client *server, const char *dest_yxx,
                                 const char *target, const char *kreqid,
                                 char token, const char *client_yxx,
                                 unsigned int mask, const char *const *ids,
                                 int n, size_t room)
{
  char list[BUFSIZE];
  int from = 0, lines = 0;

  while (from < n) {
    int got = hm_pack_ids(ids, n, from, room, list, sizeof(list));
    if (got <= 0)
      break;   /* not reached: every id fits */
    from += got;
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q %s K %c %d %s %s * %c%s %x :%s",
                  target, from < n ? '+' : '*', FED_CHILDREN_MAX, kreqid, dest_yxx,
                  token, client_yxx, mask, list);
    lines++;
  }
  return lines;
}

/** start_fed_query, and the bouncer catch-up's channel leg (W5 Push F, I-2)
 * with @a own_label 0: a leg started while the client's command is still
 * being processed (an alias attach at registration) must not take that
 * command's label nor suppress its acknowledgement -- its rows go to the
 * catch-up's batches, never to a labeled response. */
static struct FedRequest *start_fed_query_ex(struct Client *sptr, const char *target,
                                              const char *requested,
                                              const char *subcmd, const char *ref,
                                              int limit,
                                              struct HistoryMessage *local_msgs,
                                              int local_count, int ops_override,
                                              const char *ref2, int local_complete,
                                              int own_label)
{
  struct FedRequest *req;

  fed_start_capacity_miss = 0;
  fed_start_unasked = 0;
  char reqid[32];
  char s2s_ref[64];
  char s2s_ref2[64];
  char s2s_subcmd;
  int i, server_count;
  const char **kids = NULL;   /* the children request's msgids (W5 Task 14) */
  int k_n = 0, k_stores = 0, pages_sent = 0, label_responded;
  time_t query_time = 0;
  enum HistoryRefType ref_type;
  const char *ref_value;

  /* Check if federation is enabled.  Off while a storage peer is linked:
   * that peer may hold what the page lacks and is not asked -- the page is
   * not complete (fed_start_unasked; W5 Push F, I-1). */
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION)) {
    fed_start_unasked = count_storage_servers(target, 0) > 0;
    return NULL;
  }

  /* Convert to efficient S2S format */
  s2s_subcmd = subcmd_to_s2s(subcmd);
  if (s2s_subcmd == '?')
    return NULL;  /* Unknown subcmd */

  if (!ref_to_s2s(ref, s2s_ref, sizeof(s2s_ref)))
    return NULL;  /* Invalid reference */

  /* Optional second reference (BETWEEN/W): empty when absent. */
  s2s_ref2[0] = '\0';
  if (ref2 && ref2[0]) {
    if (!ref_to_s2s(ref2, s2s_ref2, sizeof(s2s_ref2)))
      return NULL;  /* Invalid second reference */
  }

  /* Extract timestamp from reference for retention filtering.
   * For timestamp references, we can skip servers whose retention doesn't
   * cover the query time. For msgid or * references, we query all storage servers.
   */
  if (parse_reference(ref, &ref_type, &ref_value) == 0) {
    if (ref_type == HISTORY_REF_TIMESTAMP && ref_value) {
      /* Clients send ISO 8601; strtoul on "2026-..." yielded 2026
       * (epoch 1970!), so server_retention_covers() rejected every
       * storage server and federation SILENTLY never fired for any
       * ISO-timestamp reference (LATEST's "*" masked this for years).
       * Convert first; fall back to raw for unix.ms refs. */
      char unix_buf[HISTORY_TIMESTAMP_LEN];
      if (history_iso_to_unix(ref_value, unix_buf, sizeof(unix_buf)) == 0)
        query_time = (time_t)strtoul(unix_buf, NULL, 10);
      else
        query_time = (time_t)strtoul(ref_value, NULL, 10);
    }
    /* For HISTORY_REF_MSGID or HISTORY_REF_NONE, query_time stays 0 (no filter) */
  }

  /* Count storage-capable servers that cover the query timeframe.
   * Only servers that have sent CH A S are counted.
   * Layer 1: Also filters by channel advertisements if present.
   */
  server_count = count_storage_servers(target, query_time);

  /* The children request (W5 Task 14): the page's own rows whose children
   * a peer may hold and this store lacks -- those whose context range
   * [row, now] was not received here (hm_children_wanted, newest first,
   * the first rejection taking every older row).  A store that never held
   * such a row still answers for it: its reply index is keyed by the
   * parent's msgid.  Asked of every K-capable store, whatever the page's
   * retention filter, so a request starts for it alone when no store
   * covers the page.  Channel pages only. */
  if (local_count > 0 && local_msgs && IsChannelName(target)
      && feature_bool(FEAT_CHATHISTORY_FED_CHILDREN)) {
    int si, rows = 0;
    struct HistoryMessage *m;

    for (si = 0; si < MAX_AD_SERVERS; si++)
      if (children_store(si))
        k_stores++;
    for (m = local_msgs; m; m = m->next)
      rows++;
    if (k_stores > 0 && rows > 0) {
      kids = (const char **)MyMalloc((size_t)rows * sizeof(*kids));
      k_n = hm_children_wanted(local_msgs, fed_ctx_received, (void *)target,
                               kids, rows);
    }
  }
  if (server_count == 0 && k_n == 0) {
    if (kids)
      MyFree(kids);
    return NULL;  /* No storage servers to query */
  }

  /* Find empty slot */
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (!fed_requests[i])
      break;
  }
  if (i >= MAX_FED_REQUESTS) {
    /* callers: the page is not complete -- unless only children were to be
     * asked (no store covers the page): a context gap is never partial */
    fed_start_capacity_miss = server_count > 0;
    if (kids)
      MyFree(kids);
    return NULL;  /* No room */
  }

  /* Generate request ID */
  ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu",
                cli_yxx(&me), ++fed_reqid_counter);

  /* Create request */
  req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
  ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
  ircd_strncpy(req->target, target, sizeof(req->target) - 1);
  ircd_strncpy(req->requested, requested ? requested : "", sizeof(req->requested) - 1);
  /* Store full client numeric (server + client) for safe lookup later
   * findNUser expects the full numeric like "BjAAU" not just the client part "AAU" */
  ircd_snprintf(0, req->client_yxx, sizeof(req->client_yxx), "%s%s",
                cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
  req->local_msgs = local_msgs;
  req->local_count = local_count;
  req->leg.derive = 1;   /* a page: F-3's fallback may apply */
  req->servers_pending = server_count;
  req->start_time = CurrentTime;
  req->limit = limit;
  req->ops_override = ops_override;
  req->local_incomplete = !local_complete;
  /* Merge trim direction: AFTER and an ascending BETWEEN keep the
   * OLDEST limit; everything else keeps the newest (audit #9). */
  if (s2s_subcmd == 'A') {
    req->keep_oldest = 1;
  } else if (s2s_subcmd == 'W' && ref2 && ref2[0]) {
    /* Ask the walk which way it went, on the same full keys it used:
     * comparing millisecond-only refs disagreed with it for same-ms
     * selectors (re-review 2026-09-07 R9).  Unresolvable (a msgid only
     * a remote store knows) falls back to the millisecond compare. */
    enum HistoryRefType t1, t2;
    const char *v1, *v2;
    int desc = -1;
    if (parse_s2s_reference(ref, &t1, &v1) == 0
        && parse_s2s_reference(ref2, &t2, &v2) == 0)
      desc = history_between_descending(target, t1, v1, t2, v2);
    if (desc >= 0) {
      req->keep_oldest = !desc;
    } else {
      char u1[HISTORY_TIMESTAMP_LEN], u2[HISTORY_TIMESTAMP_LEN];
      fed_ref_to_unix(target, ref, u1, sizeof(u1));
      fed_ref_to_unix(target, ref2, u2, sizeof(u2));
      req->keep_oldest = (u1[0] && u2[0] && strcmp(u1, u2) <= 0) ? 1 : 0;
    }
  } else {
    req->keep_oldest = 0;
  }
  /* An AROUND page is merged uncut and then centred on its reference, as a
   * local AROUND page is (hm_trim_around).  The handler already resolved a
   * msgid reference here (fail_unknown_msgid); one that does not resolve
   * now keeps the newest-limit trim. */
  if (s2s_subcmd == 'R' && parse_reference(ref, &ref_type, &ref_value) == 0
      && ref_value) {
    char ts[HISTORY_TIMESTAMP_LEN];
    if (ref_type == HISTORY_REF_MSGID
        && history_msgid_ref_timestamp(target, ref_value, ts) >= 0) {
      req->around_ms = history_parse_ms(ts);
      ircd_strncpy(req->around_msgid, ref_value, sizeof(req->around_msgid));
    } else if (ref_type == HISTORY_REF_TIMESTAMP) {
      if (history_iso_to_unix(ref_value, ts, sizeof(ts)) != 0)
        ircd_strncpy(ts, ref_value, sizeof(ts));
      req->around_ms = history_parse_ms(ts);
    }
    req->around = req->around_ms != 0;   /* 0: unparseable */
  }
  /* Strict presence filters this page's walk for any requester, but a
   * responder filters its own only by ACCOUNT presence (a session anchor
   * lives here alone): with no account the peers' pages are wider, and a
   * row of theirs this page lacks is no sign of a wrong window
   * (context_only_peer_rows). */
  req->peer_walk_wider = feature_bool(FEAT_CHATHISTORY_STRICT_PRESENCE)
                         && !(IsAccount(sptr) && cli_user(sptr)
                              && cli_user(sptr)->account[0]);

  /* Save label for async response delivery */
  req->label[0] = '\0';
  label_responded = cli_label_responded(sptr);
  if (own_label && cli_label(sptr)[0]) {
    ircd_strncpy(req->label, cli_label(sptr), sizeof(req->label));
    cli_label_responded(sptr) = 1;  /* Suppress generic ACK */
  }

  fed_requests[i] = req;

  /* Set timeout timer */
  timer_add(timer_init(&req->timer), fed_timeout_callback,
            (void *)req, TT_RELATIVE,
            feature_int(FEAT_CHATHISTORY_TIMEOUT));
  req->timer_active = 1;

  /* Send targeted queries to all storage servers in the network.
   * Uses dest_numeric for multi-hop routing — intermediates forward
   * without processing, only the destination processes the query.
   *
   * CH Q <target> <subcmd:1char> <ref:T/M prefix> <limit> <reqid> <dest_numeric>
   */
  {
    int si;
    unsigned int mask = requester_type_mask(sptr);
    char token = ops_override ? 'F' : 'P';
    char kreqid[sizeof(req->reqid) + 1] = "";
    size_t room = 0;

    /* The children request's lines: the fixed part measured once (every
     * destination is two characters), the list in what is left of the 510
     * a P10 line may carry, 4 bytes spare (send_ch_response's margin).  An
     * id that could not fit a line alone is dropped (none can: a msgid is
     * at most 63 bytes, the room at least ~245). */
    if (k_n > 0) {
      char fixed[BUFSIZE];
      int j, kept = 0;
      size_t flen;

      ircd_snprintf(0, kreqid, sizeof(kreqid), "%sK", reqid);
      ircd_snprintf(0, fixed, sizeof(fixed), "Q %s K * %d %s AA * %c%s %x",
                    target, FED_CHILDREN_MAX, kreqid, token, req->client_yxx, mask);
      flen = strlen(fixed);
      room = (6 /* "<YY> CH " */ + flen + 2 /* " :" */ + 4 < 510)
             ? 510 - 6 - flen - 2 - 4 : 0;
      for (j = 0; j < k_n; j++)
        if (strlen(kids[j]) <= room)
          kids[kept++] = kids[j];
      k_n = kept;
    }

    for (si = 0; si < MAX_AD_SERVERS; si++) {
      struct ChathistoryAd *ad = server_ads[si];
      struct Client *server;
      char dest_yxx[4];

      if (!ad || !ad->has_advertisement || !ad->is_storage_server)
        continue;

      inttobase64(dest_yxx, si, 2);
      server = FindNServer(dest_yxx);
      if (!server || server == &me)
        continue;

      if (is_ulined_server(server))
        continue;

      /* The page query, to a store whose retention covers the page. */
      if (query_time == 0 || server_retention_covers(server, query_time)) {
        /* Layer 1 channel-list filter intentionally NOT applied here —
         * see the matching rationale in count_storage_servers(): CH A F
         * is burst-time only and silently breaks federation for any
         * channel created post-burst.  Keep this loop in sync with the
         * counter; the bloom-filter design at
         * .claude/plans/federation-dedup-s2s-msgid.md will revive a
         * principled per-target filter when it lands. */
        /* Trailing requester token (presence-aware paging on the
         * responder): P<yxx> = filter to the requester's presence,
         * F<yxx> = the requester asked for ":full" (the responder applies
         * has_ops_override itself).  ref2 is "*" when absent so the token
         * keeps its slot; older responders ignore both. */
        /* Trailing type mask (hex): the row types the requester can
         * receive, so the responder skips the rest INSIDE its walk and
         * its limit+1 probe counts VISIBLE rows.  0 = all types.  Older
         * responders ignore the extra param (audit #8). */
        sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q %s %c %s %d %s %s %s %c%s %x",
                      target, s2s_subcmd, s2s_ref, limit, reqid, dest_yxx,
                      s2s_ref2[0] ? s2s_ref2 : "*",
                      token, req->client_yxx, mask);
        pages_sent++;
      }

      /* Then the children request (W5 Task 14), to every K-capable store
       * whatever the page's retention filter (children_store).  On its own
       * reply leg, <reqid>K. */
      if (k_n > 0 && children_store(si) == server) {
        fed_children_lines += send_children_request(server, dest_yxx, target, kreqid,
                                                     token, req->client_yxx, mask,
                                                     kids, k_n, room);
        req->k_pending++;
        fed_children_asked++;
      }
    }
  }

  /* The msgids asked about, kept to check each child's parent against
   * (fed_k_listed; fix round 1). */
  if (req->k_pending > 0 && k_n > 0) {
    int j;
    req->k_ids = MyMalloc((size_t)k_n * sizeof(req->k_ids[0]));
    for (j = 0; j < k_n; j++)
      ircd_strncpy(req->k_ids[j], kids[j], sizeof(req->k_ids[0]));
    qsort(req->k_ids, (size_t)k_n, sizeof(req->k_ids[0]), fed_k_id_cmp);
    req->k_id_count = k_n;
  }
  if (kids)
    MyFree(kids);

  /* Nothing went out (fix round 1: the counts above and the loop apply
   * the same skips, so this should not happen): no reply will come, and
   * waiting for the timeout would only delay the page.  Give the rows back
   * and answer locally.  A store that was counted but not asked is a page
   * that is not complete, as for a missing slot. */
  if (pages_sent == 0 && req->k_pending <= 0) {
    fed_start_capacity_miss = server_count > 0;
    req->local_msgs = NULL;   /* the caller keeps them and answers with them */
    cli_label_responded(sptr) = label_responded;
    req->timer_active = 0;
    timer_del(&req->timer);   /* ET_DESTROY frees the request */
    return NULL;
  }

  return req;
}

static struct FedRequest *start_fed_query(struct Client *sptr, const char *target,
                                           const char *requested,
                                           const char *subcmd, const char *ref,
                                           int limit,
                                           struct HistoryMessage *local_msgs,
                                           int local_count, int ops_override,
                                           const char *ref2, int local_complete)
{
  return start_fed_query_ex(sptr, target, requested, subcmd, ref, limit, local_msgs,
                            local_count, ops_override, ref2, local_complete, 1);
}

/*
 * ============================================================================
 * Federated REDACT Support
 *
 * When a REDACT names a message this server does not store -- it has no
 * store, or the row never reached it (a channel message reaches only the
 * servers with a member) -- it sends a CH Q X (exact msgid lookup)
 * federation query to the storage servers.  On completion, the callback
 * authorizes under the one rule (redact_authorize, redact_index.c) and
 * shows and relays the REDACT if permitted.
 * ============================================================================
 */

/** Context for a federated REDACT operation */
struct RedactContext {
  char msgid[HISTORY_MSGID_LEN];       /**< Message ID to redact */
  char reason[TOPICLEN + 1];           /**< Redaction reason */
  int is_chanop;                       /**< Whether requester is chanop */
  int is_oper;                         /**< Whether requester is oper */
};

/** Answer a federated REDACT (complete_redact_fed, below, wraps it in
 * the requester's labeled-response).
 * The parent is the first non-context row a storage peer returned (a
 * responder sends the row first, then its context children); it is
 * authorized under the same rule as a row found locally, and a REDACT
 * child of it (or a local REDACT row) makes the request an idempotent
 * repeat.  Otherwise the REDACT is shown to the local members under its
 * own msgid and time and relayed, and this store keeps it as a tombstone
 * (it does not hold the message): every other store keeps its row when the
 * relayed REDACT reaches it, and the requester never receives its own
 * relay (W5 Task 5, R23).
 */
static void redact_fed_answer(struct FedRequest *req, struct RedactContext *ctx,
                              struct Client *sptr)
{
  struct Channel *chptr;
  struct HistoryMessage *msg, *m;
  struct redact_auth_in ai;
  enum redact_auth verdict;
  char fctx[BUFSIZE];   /* spec: <target> <msgid> */
  char req_mask[HISTORY_SENDER_LEN];
  const char *reason;
  long window = 0;
  int already = 0;

  /* Look up the channel */
  chptr = FindChannel(req->target);
  if (!chptr) {
    send_fail(sptr, "REDACT", "INVALID_TARGET", req->target,
              "No such channel");
    return;
  }

  ircd_snprintf(0, fctx, sizeof(fctx), "%s %s", req->target, ctx->msgid);
  reason = ctx->reason[0] ? ctx->reason : NULL;

  /* The parent: the first non-context row (CH C marked the children)
   * that IS the requested message -- a row with any other msgid is not
   * it, and authorizing against it would judge the wrong message. */
  for (msg = req->leg.msgs; msg; msg = msg->next)
    if (!msg->is_context && strcmp(msg->msgid, ctx->msgid) == 0)
      break;
  if (!msg) {
    /* No store returned it.  When a store never answered (timeout, SQUIT,
     * CH E U) the row may still exist there, but the redaction spec has
     * no "unavailable" code: answer UNKNOWN_MSGID as for a row no store
     * holds (ruling R20) and say in the log the lookup was cut. */
    if (req->cut)
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "REDACT %s %s by %s: federated lookup cut (a store did not answer); "
                "answering UNKNOWN_MSGID", req->target, ctx->msgid, cli_name(sptr));
    send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fctx, "Message not found");
    return;
  }

  /* The one rule, as for a local row -- but never the unauthenticated
   * mask path: the row's sender came over the wire (header_repaired). */
  ircd_snprintf(0, req_mask, sizeof(req_mask), "%s!%s@%s",
                cli_name(sptr), cli_user(sptr)->username,
                cli_user(sptr)->host);
  memset(&ai, 0, sizeof(ai));
  ai.msg_type = msg->type;
  ai.msg_time = (long)strtoul(msg->timestamp, NULL, 10);
  ai.now = (long)CurrentTime;
  ai.msg_account = msg->account;
  ai.msg_sender = msg->sender;
  ai.req_account = cli_user(sptr)->account;
  ai.req_mask = req_mask;
  ai.header_repaired = 1;
  ai.is_oper = ctx->is_oper;
  ai.is_chanop = ctx->is_chanop;
  ai.chanop_others = feature_bool(FEAT_REDACT_CHANOP_OTHERS);
  ai.window = feature_int(FEAT_REDACT_WINDOW);
  ai.oper_window = feature_int(FEAT_REDACT_OPER_WINDOW);
  verdict = redact_authorize(&ai, &window);

  if (verdict == REDACT_AUTH_NOT_MESSAGE) {
    send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fctx, "Not a message");
    return;
  }
  if (verdict == REDACT_AUTH_EXPIRED) {
    char wctx[BUFSIZE];   /* spec: <target> <msgid> <window> */
    ircd_snprintf(0, wctx, sizeof(wctx), "%s %ld", fctx, window);
    send_fail(sptr, "REDACT", "REDACT_WINDOW_EXPIRED", wctx,
              "Redaction window has expired");
    return;
  }
  if (verdict != REDACT_AUTH_OK) {
    send_fail(sptr, "REDACT", "REDACT_FORBIDDEN", fctx,
              "You are not authorized to redact this message");
    return;
  }

  /* Already redacted: a store returned a REDACT child of the row, or this
   * server's own store holds a REDACT row for it.  A repeat is an
   * idempotent success: the requester's echo, nothing shown to the channel,
   * relayed or stored.  A returned child names the first REDACT event, and
   * the echo carries its msgid and time.  The local check is the fallback
   * for an older responder, which returns no children.  On a local miss a
   * row here is a tombstone: an earlier REDACT of this message reached this
   * store from elsewhere (a peer's, a catch-up row, a CH W write-forward)
   * while the message was not here (redact_apply_row).  It answers only
   * that one exists, so that echo carries no msgid.  An older responder's
   * repeat with no such row is shown and relayed again, and every store
   * skips the row it already holds. */
  for (m = req->leg.msgs; m; m = m->next)
    if (m->is_context && m->type == HISTORY_REDACT
        && strcmp(m->ctx_parent, ctx->msgid) == 0)
      break;
  if (m) {
    already = 1;
    if (feature_bool(FEAT_MSGID))
      sendcmdto_set_client_event(m->msgid, history_parse_ms(m->timestamp));
  } else if (history_message_is_redacted(req->target, ctx->msgid) == 1)
    already = 1;
  if (already) {
    redact_echo_requester(sptr, req->target, ctx->msgid, reason);
    sendcmdto_set_client_msgid(NULL);
    return;
  }

  /* Authorization passed: one msgid and one time for the event */
  {
    char redact_msgid[HISTORY_MSGID_LEN];
    uint64_t time_ms;
    char timestamp[32];
    char redact_content[512];

    generate_msgid(redact_msgid, sizeof(redact_msgid));
    time_ms = history_event_time_ms(NULL);   /* the msgid's own mint time (audit #16) */
    history_format_ms(timestamp, sizeof(timestamp), time_ms);
    if (reason)
      ircd_snprintf(0, redact_content, sizeof(redact_content),
                    "%s :%s", ctx->msgid, reason);
    else
      ircd_snprintf(0, redact_content, sizeof(redact_content),
                    "%s", ctx->msgid);

    /* Write-forward the REDACT event to a STORE server (non-STORE only).
     * Reason is client-supplied: sentinel-escape for the CH W payload,
     * same as m_redact.c's forward site (missed by the 0c9d97a composer
     * conversion). */
    {
      char fwd_content[sizeof(redact_content) * 2 + 1];
      history_forward_encode(fwd_content, sizeof(fwd_content), NULL,
                             redact_content);
      forward_history_write(chptr, sptr, redact_msgid, timestamp,
                            HISTORY_REDACT, fwd_content);
    }

    /* Show it to the local members under the event's msgid and time. */
    redact_announce_local(sptr, chptr, ctx->msgid, redact_msgid, time_ms, reason);

    /* Propagate to other servers (ms_redact on storage servers stores the
     * REDACT row under this same msgid and time via the S2S tags). */
    sendcmdto_set_s2s_tags(time_ms, redact_msgid);
    sendcmdto_want_s2s_tags(1);
    sendcmdto_serv_butone_v3(sptr, CMD_REDACT, sptr, "%s %s :%s",
                          req->target, ctx->msgid, reason ? reason : "");
    /* sendcmdto_set_s2s_tags armed the client event time too; clear it, as
     * complete_redact_fed did before W5, or the next bare
     * sendcmdto_set_client_msgid stamps this REDACT's time as its @time. */
    sendcmdto_set_client_msgid(NULL);

    /* This store's own row, under the same msgid and time: a tombstone, as
     * the message is not here (a local miss) -- or beside it, should it
     * have arrived during the lookup -- by the rule every store follows
     * (redact_row_judge; redact_apply_row says why a tombstone).  A REDACT
     * row that arrived during the lookup is caught by the repeat check
     * above (history_message_is_redacted, read here at completion), which
     * answered the request as a repeat and returned; so the judge sees
     * APPLY or SKIP_ORPHAN, and stores nothing on SKIP_APPLIED should it
     * see one.  Nothing in a +P channel: no message is stored there during
     * the lookup, so the row could only be a tombstone, and +P keeps none.
     * Nothing without a store. */
    if (history_is_available() && !(chptr->mode.exmode & EXMODE_NOSTORAGE)) {
      int d = redact_row_judge(chptr->chname, ctx->msgid);

      if (d == RDX_ROW_APPLY || d == RDX_ROW_SKIP_ORPHAN) {
        char sender[HISTORY_SENDER_LEN];
        char owner[HTC_OWNER_MAX];

        if (d == RDX_ROW_APPLY)
          history_redact_message(chptr->chname, ctx->msgid);
        ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                      cli_name(sptr), cli_user(sptr)->username,
                      cli_user(sptr)->host);
        history_store_message(redact_msgid, timestamp, chptr->chname, NULL,
                              sender,
                              cli_user(sptr)->account[0] ? cli_user(sptr)->account : "",
                              HISTORY_REDACT, redact_content, NULL,
                              history_owner_of(owner, sizeof(owner), sptr));
      } else if (d == RDX_ROW_RETRY)
        log_write(LS_SYSTEM, L_NOTICE, 0,
                  "REDACT %s %s by %s: the store could not be read; no REDACT row stored",
                  chptr->chname, ctx->msgid, cli_name(sptr));
    }
  }
}

/** Completion callback for federated REDACT: the requester still here,
 * answer it under its saved label. */
static void complete_redact_fed(struct FedRequest *req)
{
  struct RedactContext *ctx;
  struct Client *sptr;

  if (!req || req->response_sent)
    return;

  req->response_sent = 1;

  ctx = (struct RedactContext *)req->cb_data;
  if (!ctx)
    return;

  /* Look up the client -- may have disconnected during federation */
  sptr = findNUser(req->client_yxx);
  if (!sptr || !MyUser(sptr) || !cli_user(sptr))
    return;

  /* labeled-response: the REDACT's label was saved, and its generic ACK
   * suppressed, when the lookup started.  Answer under it -- the echo or
   * the FAIL carries it -- and ACK when the answer sent nothing labeled
   * (no echo-message); then clear it, as the end of a command would. */
  if (req->label[0]) {
    ircd_strncpy(cli_label(sptr), req->label, sizeof(cli_label(sptr)));
    cli_label_responded(sptr) = 0;
  }
  redact_fed_answer(req, ctx, sptr);
  if (req->label[0]) {
    send_labeled_ack(sptr);
    cli_label(sptr)[0] = '\0';
    cli_label_responded(sptr) = 0;
  }
}

/** Start a federated REDACT query (exact message lookup).
 * Sends CH Q X to storage servers and sets up async completion.
 * @param[in] sptr Client requesting the redaction.
 * @param[in] chptr Channel containing the message.
 * @param[in] target Channel name.
 * @param[in] msgid Message ID to look up.
 * @param[in] reason Redaction reason (may be NULL).
 * @param[in] is_chanop Whether requester is chanop.
 * @param[in] is_oper Whether requester is oper.
 * @return 0 on success (query started), -1 on failure.
 */
int start_redact_fed_query(struct Client *sptr, struct Channel *chptr,
                           const char *target, const char *msgid,
                           const char *reason, int is_chanop, int is_oper)
{
  struct FedRequest *req;
  struct RedactContext *ctx;
  char reqid[32];
  char s2s_ref[HISTORY_MSGID_LEN + 2];  /* M<msgid>\0 */
  int i, server_count;
  struct DLink *lp;

  /* Check if federation is enabled */
  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION))
    return -1;

  /* Build S2S reference: M<msgid> */
  ircd_snprintf(0, s2s_ref, sizeof(s2s_ref), "M%s", msgid);

  /* Count storage servers (no time filter for msgid lookups) */
  server_count = count_storage_servers(target, 0);
  if (server_count == 0)
    return -1;

  /* Find empty slot */
  for (i = 0; i < MAX_FED_REQUESTS; i++) {
    if (!fed_requests[i])
      break;
  }
  if (i >= MAX_FED_REQUESTS)
    return -1;

  /* Generate request ID */
  ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu",
                cli_yxx(&me), ++fed_reqid_counter);

  /* Create REDACT context */
  ctx = (struct RedactContext *)MyCalloc(1, sizeof(struct RedactContext));
  ircd_strncpy(ctx->msgid, msgid, sizeof(ctx->msgid) - 1);
  if (reason)
    ircd_strncpy(ctx->reason, reason, sizeof(ctx->reason) - 1);
  ctx->is_chanop = is_chanop;
  ctx->is_oper = is_oper;

  /* Create federation request with custom completion */
  req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
  ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
  ircd_strncpy(req->target, target, sizeof(req->target) - 1);
  ircd_snprintf(0, req->client_yxx, sizeof(req->client_yxx), "%s%s",
                cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
  req->local_msgs = NULL;
  req->local_count = 0;
  req->servers_pending = server_count;
  req->start_time = CurrentTime;
  req->limit = 1;
  req->ops_override = 0;
  req->completion_cb = complete_redact_fed;
  req->cb_data = ctx;

  /* labeled-response: complete_redact_fed answers under this label;
   * suppress the generic ACK the end of the command would send. */
  if (cli_label(sptr)[0]) {
    ircd_strncpy(req->label, cli_label(sptr), sizeof(req->label));
    cli_label_responded(sptr) = 1;
  }

  fed_requests[i] = req;

  /* Set timeout timer */
  timer_add(timer_init(&req->timer), fed_timeout_callback,
            (void *)req, TT_RELATIVE,
            feature_int(FEAT_CHATHISTORY_TIMEOUT));
  req->timer_active = 1;

  /* Send CH Q X to storage servers */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *server = lp->value.cptr;

    if (is_ulined_server(server))
      continue;
    if (!has_chathistory_advertisement(server))
      continue;

    sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q %s X %s 1 %s",
                  target, s2s_ref, reqid);
  }

  return 0;
}

/* ---------------------------------------------------------------- */
/* Auto-Replay Federation (for bouncer alias setup on non-storing servers) */
/* ---------------------------------------------------------------- */

/** Context for federated auto-replay, shared across sequential FedRequests.
 * Processes channels one at a time to avoid exhausting the fed_requests[] array.
 * Freed when all channels are processed or the client disconnects.
 */
struct AutoReplayContext {
  char client_yxx[6];              /**< Alias client numeric for safe lookup */
  struct Channel *next_chan;        /**< Next channel to process (by channel ptr) */
  struct Membership *cursor;       /**< Current position in client's channel list */
  int limit;                       /**< Per-channel message limit */
  int total_replayed;              /**< Running total of replayed messages */
  int chan_count;                   /**< Number of channels replayed */
  time_t since_time;               /**< Baseline timestamp (for read marker comparison) */
  char timestamp[HISTORY_TIMESTAMP_LEN]; /**< Formatted baseline ts */
  int incomplete;                  /**< A channel was skipped (no fed slot) */
};

/** Process the next channel in the auto-replay chain.
 * Walks the alias's channel memberships, issuing federation queries
 * sequentially.  When all channels are done, sends a summary NOTICE.
 */
static void autoreplay_next_channel(struct AutoReplayContext *ctx)
{
  struct Client *sptr;
  struct Membership *member;
  struct FedRequest *req;
  char reqid[32];
  int i, server_count;

  if (!ctx)
    return;

  /* Look up alias client — may have disconnected */
  sptr = findNUser(ctx->client_yxx);
  if (!sptr) {
    MyFree(ctx);
    return;
  }

  /* Walk channel memberships from current cursor position */
  for (member = ctx->cursor; member; member = member->next_channel) {
    struct Channel *chptr = member->channel;
    const char *channame;
    char marker_ts[32];

    if (IsZombie(member) || IsDelayedJoin(member))
      continue;

    channame = chptr->chname;

    /* NOTE: this leg used to SKIP the whole channel when the account's
     * read marker was past since_time -- same multi-device day-gap bug
     * as replay.c's marker fast-forward (see the note there). */

    /* Save cursor for next iteration (after this channel completes) */
    ctx->cursor = member->next_channel;

    /* No local leg: chathistory_auto_replay_fed runs only on a server
     * with no store (bouncer_session.c; a server with one replays through
     * replay_start_catchup and chathistory_page_since), and a store never
     * opens after boot (history_init runs once).  The local leg that stood
     * here was unreachable, and replayed without the context attach or
     * the redaction filter (W5 Task 15 fix round 1). */
    server_count = count_storage_servers(channame, 0);
    if (server_count == 0)
      continue;  /* No storage servers, skip this channel */

    /* Find empty federation slot */
    for (i = 0; i < MAX_FED_REQUESTS; i++) {
      if (!fed_requests[i])
        break;
    }
    if (i >= MAX_FED_REQUESTS) {
      /* No slot: the channel is skipped, and the client must not be
       * told its replay was complete (re-review R19). */
      ctx->incomplete = 1;
      continue;
    }

    /* Generate request ID */
    ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu",
                  cli_yxx(&me), ++fed_reqid_counter);

    /* Create federation request */
    req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
    ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
    ircd_strncpy(req->target, channame, sizeof(req->target) - 1);
    ircd_snprintf(0, req->client_yxx, sizeof(req->client_yxx), "%s%s",
                  cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
    req->local_msgs = NULL;
    req->local_count = 0;
    req->leg.derive = 1;   /* a page: F-3's fallback may apply */
    req->servers_pending = server_count;
    req->start_time = CurrentTime;
    req->limit = ctx->limit;
    req->ops_override = 0;
    req->completion_cb = complete_autoreplay_channel;
    req->cb_data = ctx;
    req->cleanup_cb = NULL;  /* We manage ctx lifetime ourselves */

    fed_requests[i] = req;

    /* Set timeout timer */
    timer_add(timer_init(&req->timer), fed_timeout_callback,
              (void *)req, TT_RELATIVE,
              feature_int(FEAT_CHATHISTORY_TIMEOUT));
    req->timer_active = 1;

    /* Send LATEST * query to all storage servers */
    {
      int si;
      for (si = 0; si < MAX_AD_SERVERS; si++) {
        struct ChathistoryAd *ad = server_ads[si];
        struct Client *server;
        char dest_yxx[4];

        if (!ad || !ad->has_advertisement || !ad->is_storage_server)
          continue;

        inttobase64(dest_yxx, si, 2);
        server = FindNServer(dest_yxx);
        if (!server || server == &me)
          continue;
        if (is_ulined_server(server))
          continue;

        /* Same wire shape as start_fed_query: LATEST after the detach
         * point (not the latest N regardless), the requester token so
         * the responder can open presence for the account, and the
         * requester's type mask so the responder's limit+1 probe counts
         * rows this connection can receive (re-review 2026-09-07 R7;
         * the bare six-param form left the responder unfiltered and a
         * JOIN/PART run longer than the limit emptied the page). */
        sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q %s L %s %d %s %s * P%s %x",
                      channame, ctx->timestamp[0] ? ctx->timestamp : "*",
                      ctx->limit, reqid, dest_yxx, ctx->client_yxx,
                      requester_type_mask(sptr));
      }
    }

    /* Federation started — return and wait for callback */
    return;
  }

  /* All channels processed — send summary and clean up */
  if (ctx->total_replayed > 0 || ctx->incomplete) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :Session replay: %d message(s) from %d channel(s)%s.",
                  sptr, ctx->total_replayed, ctx->chan_count,
                  ctx->incomplete ? " (some channels skipped: federation busy)" : "");
  }

  MyFree(ctx);
}

/** Drop the rows of @a *head at or before the ATTACH cursor @a since_ts /
 * @a since_msgid, in the store's key order (time, then msgid): a peer's
 * LATEST from the cursor's millisecond includes the cursor row and the rows
 * before it in that millisecond, which the client saw and the local walk
 * (floored at the cursor's own row) left out.  No-op without a msgid. */
static void autoreplay_drop_through_cursor(struct HistoryMessage **head,
                                           const char *since_ts,
                                           const char *since_msgid)
{
  struct HistoryMessage **pp = head;
  uint64_t cur;

  if (!since_ts || !since_msgid || !since_msgid[0])
    return;
  cur = history_parse_ms(since_ts);
  while (*pp) {
    struct HistoryMessage *m = *pp;
    uint64_t t = history_parse_ms(m->timestamp);

    if (t < cur || (t == cur && strcmp(m->msgid, since_msgid) <= 0)) {
      *pp = m->next;
      m->next = NULL;
      history_free_messages(m);
      continue;
    }
    pp = &m->next;
  }
}

/** The page of a federated auto-replay leg: the chain the storeless
 * auto-replay has run since audit #3 / re-review R7, shared since W5 Push F
 * (I-2) with a store's bouncer catch-up leg (complete_replay_leg).  The
 * peers' declared context set aside, every REDACT they sent kept in the
 * side set (I-B), F-3's fallback, the merge (the newest req->limit, as a
 * LATEST page), the children leg (CH Q K, W5 Task 14: the children of
 * local rows a peer holds; none on a storeless server), the ATTACH
 * cursor's rows dropped (autoreplay_drop_through_cursor; @a since_ts NULL
 * for none), context, the fail-closed close, the redaction filter and
 * strict presence -- as presence_filter_and_replay and
 * chathistory_page_since run them.
 * @param[out] out The page (the caller owns it), NULL when empty.
 * @param[out] merged The page's count before the reply-side filters.
 * @return Its count after them. */
static int autoreplay_page(struct FedRequest *req, struct Client *sptr,
                           const char *since_ts, const char *since_msgid,
                           struct HistoryMessage **out, int *merged)
{
  struct HistoryMessage *page, *fed_ctx;
  int total = 0;

  fed_ctx = extract_fed_context(req);
  /* As send_fed_response: every REDACT the peers sent keeps its target
   * past the merge; a lost declaration's child is context. */
  fed_seed_side(req, fed_ctx);
  hm_leg_derive(&req->leg, req->local_msgs, &fed_ctx);
  page = hm_merge(req->local_msgs, req->leg.msgs, req->limit, req->keep_oldest);
  /* The children leg's children go after the page leg's context, spliced
   * like the rest (send_fed_response). */
  if (req->k_msgs) {
    struct HistoryMessage **tp = &fed_ctx;
    while (*tp)
      tp = &(*tp)->next;
    *tp = req->k_msgs;
    req->k_msgs = NULL;
    req->k_count = 0;
  }
  autoreplay_drop_through_cursor(&page, since_ts, since_msgid);
  for (struct HistoryMessage *m = page; m; m = m->next)
    total++;
  hm_splice_context(page, fed_ctx);

  /* Same reply-side sequence as presence_filter_and_replay and
   * chathistory_page_since: context, redaction placeholders, then
   * strict presence (audit #3; re-review R7 -- this leg replayed
   * redacted originals). */
  history_attach_context(req->target, page);
  /* A REDACT lost with its target unknown: the page fails closed. */
  fed_close_page(req, &page);
  if (!page)
    total = 0;
  *merged = total;
  total = redact_filter_messages(req->target, &page, total, &req->leg.side);
  total = presence_filter_messages(sptr, req->target, &page, total, 0);
  *out = page;
  return total;
}

/** Completion callback for per-channel auto-replay federation request. */
static void complete_autoreplay_channel(struct FedRequest *req)
{
  struct AutoReplayContext *ctx;
  struct Client *sptr;

  if (!req || req->response_sent)
    return;

  req->response_sent = 1;

  ctx = (struct AutoReplayContext *)req->cb_data;
  /* Detach ctx from request so free_fed_request doesn't free it —
   * we manage ctx lifetime across the sequential chain. */
  req->cb_data = NULL;

  if (!ctx)
    return;

  sptr = findNUser(req->client_yxx);
  if (!sptr) {
    MyFree(ctx);
    return;
  }

  /* Deliver federated results to client */
  if (hm_leg_has_rows(&req->leg)) {
    struct HistoryMessage *merged = NULL;
    int total, rows;

    total = autoreplay_page(req, sptr, NULL, NULL, &merged, &rows);
    if (total > 0) {
      /* Complete only when the page was short of the limit AND no
       * responder was cut (send_fed_response's rule; a full page was
       * stamped chathistory-end here -- re-review R7).  req->cut
       * checked explicitly too: since CH E U (Task 6), a responder can
       * set cut without fed_truncated (no store / an unknown
       * subcommand / a read error), which this hand-inlined copy of
       * send_fed_response's rule had missed (fix round 1). */
      send_history_batch(sptr, req->target, merged, total, 0, NULL,
                         total < req->limit && !req->fed_truncated
                         && !req->local_incomplete && !req->cut);
      ctx->total_replayed += total;
      ctx->chan_count++;
    }

    history_free_messages(merged);
  }

  /* Continue to next channel */
  autoreplay_next_channel(ctx);
}

/* ---------------------------------------------------------------- */
/* A store's bouncer catch-up, channel leg (W5 Push F, I-2)          */
/* ---------------------------------------------------------------- */

/** What a federated catch-up leg carries to its completion. */
struct ReplayLegCtx {
  unsigned long seq;                     /**< the catch-up's leg (replay_leg_done) */
  char since_ts[32];                     /**< the floor, "sec.mmm" */
  char since_msgid[HISTORY_MSGID_LEN];   /**< the ATTACH cursor's row, else empty */
};

/** A catch-up leg's federation ended: hand its page to the catch-up
 * (replay_leg_done), which sends it in the leg's place and goes on to the
 * next channel.  Complete as a LATEST page is (send_fed_response): short
 * of the limit before the reply-side filters, nobody truncated or cut, the
 * local walk exhausted; partial when a responder was cut or a store is
 * away over the leg. */
static void complete_replay_leg(struct FedRequest *req)
{
  struct ReplayLegCtx *ctx;
  struct Client *sptr;
  struct HistoryMessage *page = NULL;
  int total, merged, flags;

  if (!req || req->response_sent)
    return;
  req->response_sent = 1;
  ctx = (struct ReplayLegCtx *)req->cb_data;   /* freed with the request */
  sptr = findNUser(req->client_yxx);
  if (!ctx || !sptr || !MyConnect(sptr) || IsDead(sptr))
    return;
  total = autoreplay_page(req, sptr, ctx->since_ts, ctx->since_msgid, &page, &merged);
  flags = ((merged < req->limit && !req->fed_truncated && !req->local_incomplete
            && !req->cut) ? REPLAY_COMPLETE : 0)
          | ((req->cut || req->partial) ? REPLAY_PARTIAL : 0);
  replay_leg_done(sptr, ctx->seq, req->target, page, total, flags);
}

int chathistory_replay_channel_leg(struct Client *sptr, const char *channame, int limit,
                                   const char *since_timestamp, const char *since_msgid,
                                   unsigned long seq, struct HistoryMessage **out,
                                   int *flags)
{
  struct HistoryMessage *messages = NULL;
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *hook;
  int count, complete, partial = 0, why;

  *out = NULL;
  *flags = 0;
  if (!history_is_available())
    return -1;

  /* The local walk chathistory_page_since makes: LATEST with a floor, the
   * presence hook, type mask and typing veto inside it. */
  if (open_query_presence(sptr, channame, 0, &pf) < 0)
    return 0;   /* fail closed: nothing visible to replay */
  hook = query_row_filter(sptr, pf, &bare);
  count = history_query_latest_after(channame, limit, since_timestamp,
                                     since_msgid, &messages, hook);
  complete = query_page_complete(hook, count, limit);
  presence_query_filter_close(pf);
  if (count < 0)
    return -1;

  /* The leg is a LATEST page from the floor: the same receive-window and
   * absence decision as an on-demand LATEST (federation_wanted), so a leg
   * whose span this store did not receive, or that crosses a storage
   * peer's absence, asks the peers, the local rows going with the request
   * as an on-demand page's do. */
  why = federation_wanted(channame, FP_LATEST, count, limit, messages,
                          HISTORY_REF_TIMESTAMP, since_timestamp, HISTORY_REF_NONE,
                          NULL, &partial);
  if (why) {
    char iso[64], ref[80];
    struct FedRequest *req = NULL;
    int missed = 1;

    if (history_unix_to_iso(since_timestamp, iso, sizeof(iso)) == 0) {
      ircd_snprintf(0, ref, sizeof(ref), "timestamp=%s", iso);
      req = start_fed_query_ex(sptr, channame, channame, "LATEST", ref, limit,
                               messages, count, 0, NULL, complete, /*own_label=*/0);
      fed_count(req, why);
      missed = fed_start_missed();
    }
    if (req) {
      struct ReplayLegCtx *ctx = (struct ReplayLegCtx *)MyCalloc(1, sizeof(*ctx));

      ctx->seq = seq;
      ircd_strncpy(ctx->since_ts, since_timestamp, sizeof(ctx->since_ts));
      if (since_msgid)
        ircd_strncpy(ctx->since_msgid, since_msgid, sizeof(ctx->since_msgid));
      fed_request_set_why(req, why, partial);
      req->completion_cb = complete_replay_leg;
      req->cb_data = ctx;   /* MyFree'd with the request */
      return REPLAY_LEG_PENDING;   /* the rows went with the request */
    }
    /* Not started.  A storage peer that may hold the rest exists and was
     * not asked (no slot, federation off here): the local rows go out
     * partial, with no end tag.  No peer to ask at all: they are all there
     * is -- partial only when one is away (federation_wanted). */
    if (missed && why != FED_WHY_CONTEXT)
      partial = 1;
  }

  if (count > 0 && messages) {
    /* Same reply-side sequence as presence_filter_and_replay. */
    history_attach_context(channame, messages);
    count = redact_filter_messages(channame, &messages, count, NULL);
    count = presence_filter_messages(sptr, channame, &messages, count, 0);
  }
  if (count <= 0 || !messages) {
    if (messages)
      history_free_messages(messages);
    return 0;
  }
  *out = messages;
  *flags = (complete && !partial ? REPLAY_COMPLETE : 0) | (partial ? REPLAY_PARTIAL : 0);
  return count;
}

/** Start federated auto-replay for a bouncer alias.
 * Iterates the alias's channel memberships, issuing CHATHISTORY LATEST *
 * federation queries to storage servers.  Results are delivered as chathistory
 * batches to the alias client.
 *
 * Follows the IRCv3 chathistory client pseudocode pattern: starts with
 * LATEST * (no lower bound) to get the most recent messages per channel.
 *
 * @param[in] sptr The alias client.
 * @param[in] since_time Baseline timestamp (for read marker optimization, may be 0).
 * @param[in] limit Per-channel message limit.
 * @return 0 on success (replay started), -1 if federation unavailable.
 */
int chathistory_auto_replay_fed(struct Client *sptr, time_t since_time, int limit)
{
  struct AutoReplayContext *ctx;

  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION))
    return -1;

  if (count_storage_servers(NULL, 0) == 0)
    return -1;

  if (!sptr || !cli_user(sptr) || !cli_user(sptr)->channel)
    return -1;

  ctx = (struct AutoReplayContext *)MyCalloc(1, sizeof(struct AutoReplayContext));
  ircd_snprintf(0, ctx->client_yxx, sizeof(ctx->client_yxx), "%s%s",
                cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
  ctx->cursor = cli_user(sptr)->channel;
  ctx->limit = limit;
  ctx->total_replayed = 0;
  ctx->chan_count = 0;
  ctx->since_time = since_time;
  if (since_time > 0)
    ircd_snprintf(0, ctx->timestamp, sizeof(ctx->timestamp), "%lu.000",
                  (unsigned long)since_time);

  autoreplay_next_channel(ctx);
  return 0;
}

/** Raw rows one SEARCH may examine, over every channel it covers. */
#define SEARCH_SCAN_MAX 50000

struct SearchMatch {
  /** The presence hook to run first, when strict presence opened one. */
  int (*presence_fn)(const struct HistoryMessage *msg, int reverse, void *ctx,
                     int64_t *skip_to);
  void *presence_ctx;
  char from[NICKLEN + 1];   /**< sender nick to match, or empty */
  const char *text;         /**< substring to match, or NULL */
  int64_t after_ms;         /**< stop below this (0 = no floor) */
  const char *target;       /**< the walk's store key (search_walk sets it) */
  int redact_unread;        /**< matches dropped: their redaction lookup failed */
};

/** Is the matched row @a msgid of @a target redacted, or not provably
 * unredacted?  A REDACT leaves its message's row as it was
 * (history_redact_message is a no-op): only the reply index links the row
 * to its REDACT child, so this walks the row's children there (the cost is
 * noted at search_row_hook).  A lookup error (-1) answers yes -- fail
 * closed: a message this server cannot prove unredacted is not shown --
 * and counts in @a *unread so the caller can say so once rather than per
 * row. */
static int search_hides(const char *target, const char *msgid, int *unread)
{
  int r = history_message_is_redacted(target, msgid);

  if (r == 0)
    return 0;
  if (r < 0)
    (*unread)++;
  return 1;
}

/** Case-insensitive substring, the ircd's case mapping. */
static const char *search_strcasestr(const char *hay, const char *needle)
{
  size_t nlen = strlen(needle);
  const char *h;

  if (nlen == 0)
    return hay;
  for (h = hay; *h; h++) {
    size_t i;
    for (i = 0; i < nlen && h[i]; i++)
      if (ToLower(h[i]) != ToLower(needle[i]))
        break;
    if (i == nlen)
      return h;
  }
  return NULL;
}

/** Walk hook: the presence decision first (it may seek), then the
 * window floor, the row type, the selectors and last the redaction. */
static int search_row_hook(const struct HistoryMessage *msg, int reverse,
                           void *ctx, int64_t *skip_to)
{
  struct SearchMatch *sm = (struct SearchMatch *)ctx;
  int64_t t = (int64_t)history_parse_ms(msg->timestamp);

  /* The walk is newest to oldest: below the floor nothing further counts. */
  if (sm->after_ms && t && t < sm->after_ms)
    return -1;

  if (sm->presence_fn) {
    int v = sm->presence_fn(msg, reverse, sm->presence_ctx, skip_to);
    if (v != 1)
      return v;
  }

  if (msg->type != HISTORY_PRIVMSG && msg->type != HISTORY_NOTICE
      && msg->type != HISTORY_MULTILINE)
    return 0;

  if (sm->from[0]) {
    size_t n = strlen(sm->from);
    if (ircd_strncmp(msg->sender, sm->from, n) != 0 || msg->sender[n] != '!')
      return 0;
  }

  if (sm->text) {
    const char *body = msg->dyn_content ? msg->dyn_content : msg->content;
    if (!body || !body[0] || !search_strcasestr(body, sm->text))
      return 0;
  }

  /* A redacted message is never a match.  A page hides it by attaching
   * its REDACT child and filtering the list; this walk never admits a
   * REDACT row, so the check is here, inside the walk: a redacted match is
   * skipped before it counts, and the answer is the next unredacted
   * matches, not fewer rows.  Last, so only a row that would otherwise be
   * returned pays for it.  Each check is the per-row cost a page pays in
   * history_attach_context -- a bounded reply-index iterator, a seek, then
   * one db_get and one deserialize per child (replies and reactions are
   * children too, not only REDACTs) -- plus a snapshot of its own, where a
   * page shares one across its rows.  Every row checked is a scanned row,
   * so the scan budget (SEARCH_SCAN_MAX) bounds how many checks a walk
   * makes -- not what one check costs. */
  if (search_hides(sm->target, msg->msgid, &sm->redact_unread))
    return 0;

  return 1;
}

/** One target's share of a search: the newest @a limit matches before
 * @a before_unix, within the shared scan budget.  Returns the row count
 * (the list is ascending) or -1 on a store error. */
/* Selectors on the S2S wire (CH Q ... S ... :<selectors>): "from=<v> text=<v>"
 * joined by spaces, values escaped like client tags (\s = space, \\ =
 * backslash) so a text with spaces survives as one parameter.  The
 * 512-byte P10 body cap bounds them: SEARCH_SEL_MAX leaves room for the
 * fixed fields. */
#define SEARCH_SEL_MAX 380

static void search_sel_escape(const char *in, char *out, size_t n)
{
  size_t o = 0;
  for (; *in && o + 2 < n; in++) {
    if (*in == ' ') { out[o++] = '\\'; out[o++] = 's'; }
    else if (*in == '\\') { out[o++] = '\\'; out[o++] = '\\'; }
    else out[o++] = *in;
  }
  out[o] = '\0';
}

static void search_sel_unescape(char *v)
{
  char *w = v;
  for (; *v; v++) {
    if (*v == '\\' && v[1] == 's') { *w++ = ' '; v++; }
    else if (*v == '\\' && v[1] == '\\') { *w++ = '\\'; v++; }
    else *w++ = *v;
  }
  *w = '\0';
}

/** The search walk shared by the local path and the S2S responder: BEFORE
 * from @a before_unix, the match hook chained behind @a base's presence
 * hook (if any), @a base's type mask and veto, @a *budget raw rows; the
 * newest @a limit unredacted matches in @a *out (the hook drops a redacted
 * one inside the walk: a list filter afterwards would find no REDACT row
 * to filter by, and could only return fewer than @a limit).
 * @a *truncated is set when the scan budget cut the window short. */
static int search_walk(const char *lookup_target, const char *before_unix,
                       int limit, struct SearchMatch *sm, int *budget,
                       const struct HistoryRowFilter *base,
                       struct HistoryMessage **out, int *truncated)
{
  struct HistoryRowFilter filter;
  int count;

  *out = NULL;
  if (*budget <= 0)
    return 0;
  memset(&filter, 0, sizeof(filter));
  sm->presence_fn = base && base->fn ? base->fn : NULL;
  sm->presence_ctx = base && base->fn ? base->ctx : NULL;
  sm->target = lookup_target;
  sm->redact_unread = 0;
  filter.fn = search_row_hook;
  filter.ctx = sm;
  filter.type_mask = base ? base->type_mask : 0;
  filter.veto = base ? base->veto : NULL;
  filter.veto_ctx = base ? base->veto_ctx : NULL;
  filter.scan_max = *budget;

  count = history_query_before(lookup_target, HISTORY_REF_TIMESTAMP,
                               before_unix, limit, out, &filter);
  *budget -= filter.scanned;
  if (truncated)
    *truncated = filter.truncated;
  /* A store whose reply index cannot be read hides every match (each one
   * still a scanned row, so the budget ends the walk): say so. */
  if (sm->redact_unread)
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SEARCH %s: %d match(es) not shown, their redaction could not be read",
              lookup_target, sm->redact_unread);
  if (count < 0)
    return -1;
  return count;
}

static int search_one_target(struct Client *sptr, const char *lookup_target,
                             const char *before_unix, int limit,
                             struct SearchMatch *sm, int *budget,
                             struct HistoryMessage **out)
{
  struct PresenceQueryFilter *pf = NULL;
  struct HistoryRowFilter bare, *phook;
  int count;

  *out = NULL;
  if (*budget <= 0)
    return 0;

  if (open_query_presence(sptr, lookup_target, 0, &pf) < 0)
    return 0;   /* fail closed: nothing visible here */
  phook = presence_query_filter_hook(pf);
  if (!phook) {
    memset(&bare, 0, sizeof(bare));
    phook = &bare;
  }
  phook->type_mask = requester_type_mask(sptr);
  phook->veto = typing_only_veto;
  phook->veto_ctx = NULL;

  count = search_walk(lookup_target, before_unix, limit, sm, budget, phook,
                      out, NULL);
  presence_query_filter_close(pf);
  if (count < 0)
    return -1;
  return presence_filter_messages(sptr, lookup_target, out, count, 0);
}

static int search_row_cmp(const void *a, const void *b)
{
  const struct HistoryMessage *ma = *(struct HistoryMessage *const *)a;
  const struct HistoryMessage *mb = *(struct HistoryMessage *const *)b;
  uint64_t ta = history_parse_ms(ma->timestamp);
  uint64_t tb = history_parse_ms(mb->timestamp);

  if (ta != tb)
    return ta < tb ? -1 : 1;
  return strcmp(ma->msgid, mb->msgid);
}

/** Send the search batch: @a head ascending, @a count rows.  Channel rows
 * go to their own channel; rows of the private conversation @a pm_other
 * (the other party's nick, or NULL) follow their direction. */
static void search_send(struct Client *sptr, struct HistoryMessage *head,
                        const char *pm_other, const char *label)
{
  char batchid[32];
  char iso_time[32];
  const char *bid = NULL;
  struct HistoryMessage *msg;

  if (CapRecipientHas(sptr, CAP_BATCH)) {
    generate_batch_id(batchid, sizeof(batchid), sptr);
    bid = batchid;
    if (label)
      sendrawto_one(sptr, "@label=%s :%s " MSG_BATCH_CMD " +%s search", label,
                    cli_name(&me), batchid);
    else
      sendrawto_one(sptr, ":%s " MSG_BATCH_CMD " +%s search", cli_name(&me), batchid);
  }

  for (msg = head; msg; msg = msg->next) {
    const char *time_str = msg->timestamp;
    const char *cmd = (msg->type == HISTORY_NOTICE) ? "NOTICE" : "PRIVMSG";
    const char *target = msg->target;

    if (history_unix_to_iso(msg->timestamp, iso_time, sizeof(iso_time)) == 0)
      time_str = iso_time;
    if (pm_other)
      target = pm_row_is_own(sptr, msg) ? pm_other : cli_name(sptr);
    send_history_message(sptr, msg, target, bid, time_str, cmd);
  }

  if (bid)
    sendrawto_one(sptr, ":%s " MSG_BATCH_CMD " -%s", cli_name(&me), batchid);
  else if (label)
    sendrawto_one(sptr, "@label=%s :%s ACK", label, cli_name(&me));
}


/* ---------------------------------------------------------------- */
/* Federated SEARCH: the CHATHISTORY federation path with letter 'S'  */
/* ---------------------------------------------------------------- */

/** Completion: merge the local and the responders' rows (dedup by msgid),
 * keep the newest limit, send the search batch.  A responder that timed
 * out or hit its scan cap is not signalled: the spec has no marker for a
 * cut scan, and the client narrows its window when a full limit comes
 * back, exactly as against a single server. */
static void complete_search_fed(struct FedRequest *req)
{
  struct Client *client;
  struct HistoryMessage *merged, *m, **all;
  int total = 0, k, keep;

  if (!req || req->response_sent)
    return;
  req->response_sent = 1;
  client = findNUser(req->client_yxx);
  if (!client)
    return;
  /* A responder filters its own redacted matches (search_row_hook); an
   * older one does not, so the responders' rows pass the same check
   * against this store before the merge.  It finds what this store knows:
   * a REDACT relayed here, or a tombstone.  One check per row (at most
   * limit per responder), each costing what a walk's check costs
   * (search_row_hook).  The local rows were checked in the walk. */
  {
    struct HistoryMessage **pp = &req->leg.msgs;
    int unread = 0;
    while (*pp) {
      struct HistoryMessage *cur = *pp;
      if (search_hides(req->target, cur->msgid, &unread)) {
        *pp = cur->next;
        cur->next = NULL;
        history_free_messages(cur);
        req->leg.rows--;
      } else
        pp = &cur->next;
    }
    if (unread)
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SEARCH %s: %d peer row(s) not shown, their redaction could not be read",
                req->target, unread);
  }
  /* No trim in the merge (its limit is a hard cap, 0 keeps nothing):
   * the union is sorted and trimmed below. */
  merged = hm_merge(req->local_msgs, req->leg.msgs, INT_MAX, 0);
  for (m = merged; m; m = m->next)
    total++;
  if (total == 0) {
    search_send(client, NULL, NULL, req->label[0] ? req->label : NULL);
    return;
  }
  /* hm_merge assumes sorted inputs; responders' rows arrive in
   * reply order, so sort the union by time and keep the newest limit. */
  all = (struct HistoryMessage **)MyMalloc(total * sizeof(*all));
  for (k = 0, m = merged; m; m = m->next)
    all[k++] = m;
  qsort(all, total, sizeof(*all), search_row_cmp);
  keep = total < req->limit ? total : req->limit;
  merged = NULL;
  for (k = total - 1; k >= 0; k--) {
    all[k]->next = NULL;
    if (k < total - keep) {
      history_free_messages(all[k]);
      continue;
    }
    all[k]->next = merged;
    merged = all[k];
  }
  MyFree(all);
  search_send(client, merged, NULL, req->label[0] ? req->label : NULL);
  history_free_messages(merged);
}

/** Fan a SEARCH out to every storage server for @a target.  Wire:
 *   CH Q <target> S T<before> <limit> <reqid> <dest> <T<after>|*> P<yxx> <mask> :<selectors>
 * Returns the request (which now owns @a local_rows) or NULL when nothing
 * was dispatched (no stores, federation off, no free slot): the caller
 * then answers locally.  Search scans, so every store is asked. */
static struct FedRequest *start_fed_search(struct Client *sptr, const char *target,
                                           const char *requested,
                                           const char *before_unix,
                                           const char *after_unix, int limit,
                                           const struct SearchMatch *sm,
                                           struct HistoryMessage *local_rows,
                                           int local_count)
{
  struct FedRequest *req;
  char reqid[32], sel[BUFSIZE], esc[BUFSIZE];
  int i, si, server_count;
  time_t query_time = after_unix && after_unix[0] ? (time_t)strtoul(after_unix, NULL, 10) : 0;

  if (!feature_bool(FEAT_CHATHISTORY_FEDERATION))
    return NULL;
  server_count = count_storage_servers(target, query_time);
  if (server_count == 0)
    return NULL;
  for (i = 0; i < MAX_FED_REQUESTS; i++)
    if (!fed_requests[i])
      break;
  if (i >= MAX_FED_REQUESTS)
    return NULL;

  sel[0] = '\0';
  if (sm->from[0]) {
    search_sel_escape(sm->from, esc, sizeof(esc));
    ircd_snprintf(0, sel, sizeof(sel), "from=%s", esc);
  }
  if (sm->text) {
    size_t l = strlen(sel);
    search_sel_escape(sm->text, esc, sizeof(esc));
    ircd_snprintf(0, sel + l, sizeof(sel) - l, "%stext=%s", l ? " " : "", esc);
  }

  ircd_snprintf(0, reqid, sizeof(reqid), "%s%lu", cli_yxx(&me), ++fed_reqid_counter);
  req = (struct FedRequest *)MyCalloc(1, sizeof(struct FedRequest));
  ircd_strncpy(req->reqid, reqid, sizeof(req->reqid) - 1);
  ircd_strncpy(req->target, target, sizeof(req->target) - 1);
  ircd_strncpy(req->requested, requested ? requested : "", sizeof(req->requested) - 1);
  ircd_snprintf(0, req->client_yxx, sizeof(req->client_yxx), "%s%s",
                cli_yxx(cli_user(sptr)->server), cli_yxx(sptr));
  req->local_msgs = local_rows;
  req->local_count = local_count;
  req->servers_pending = server_count;
  req->start_time = CurrentTime;
  req->limit = limit;
  req->keep_oldest = 0;
  req->completion_cb = complete_search_fed;
  req->label[0] = '\0';
  if (cli_label(sptr)[0]) {
    ircd_strncpy(req->label, cli_label(sptr), sizeof(req->label));
    cli_label_responded(sptr) = 1;
  }
  fed_requests[i] = req;
  timer_add(timer_init(&req->timer), fed_timeout_callback, (void *)req, TT_RELATIVE,
            feature_int(FEAT_CHATHISTORY_TIMEOUT));
  req->timer_active = 1;

  for (si = 0; si < MAX_AD_SERVERS; si++) {
    struct ChathistoryAd *ad = server_ads[si];
    struct Client *server;
    char dest_yxx[4];
    if (!ad || !ad->has_advertisement || !ad->is_storage_server)
      continue;
    inttobase64(dest_yxx, si, 2);
    server = FindNServer(dest_yxx);
    if (!server || server == &me)
      continue;
    if (is_ulined_server(server))
      continue;
    if (query_time != 0 && !server_retention_covers(server, query_time))
      continue;
    /* Same trailing shape as a page (ref2, requester token, type mask) so
     * the responder pages by the requester's presence; the selectors
     * are the trailing parameter. */
    /* References ride bare on the wire (a unix "sec.ms" is a timestamp,
     * a leading letter a msgid, "*" none -- parse_s2s_reference). */
    sendcmdto_one(&me, CMD_CHATHISTORY, server, "Q %s S %s %d %s %s %s P%s %x :%s",
                  target, before_unix, limit, reqid, dest_yxx,
                  after_unix && after_unix[0] ? after_unix : "*",
                  req->client_yxx, requester_type_mask(sptr), sel);
  }
  return req;
}

/** A responder's rows and their attached context, before it sends them
 * (W5 Task 15 fix rounds 1-3; hm_responder_skip): every context reaction
 * this store cannot show to be unredacted is not sent -- it holds the
 * reaction and so its REDACT, under the reaction in the reply index, and a
 * requester lacking that REDACT (it missed it across a split, or has no
 * store) would show the reaction.  Redacted (1) or unknown (-1: a read
 * error, or more than CTX_REDACT_CHILDREN_MAX children an older build
 * indexed untyped; typed children are never counted, so no one can force
 * -1) both skip, as on the page path.  One lookup per context reaction, in
 * one snapshot.  On the page leg (@a page_leg) a row its attach could not
 * fully read (ctx_unread) that a REDACT could name is skipped too, with
 * its context reactions -- only on a read error.  A REDACT entry is never
 * skipped: it may be all that hides the requester's own copy of its
 * target.  When its row was skipped, send_ch_rows declares it under the
 * row before (or, with no row before it, sends it bare): its content still
 * names its target, which reaches the requester's redacted set (the
 * page's REDACT set, and the side-set seed), so only its position is
 * off.  The children leg passes 0: its stub rows are never sent, and each
 * child is checked by itself.  No line changes form. */
static void skip_redacted_context(const char *target, struct HistoryMessage **head,
                                  int page_leg)
{
  struct CtxRedactCheck c;

  memset(&c, 0, sizeof(c));
  c.target = target;
  hm_responder_skip(head, page_leg, ctx_redacted_here, &c);
  if (c.h)
    history_redact_lookup_close(c.h);
}

/** Answer one line of a children request (CH Q K, W5 Task 14): the context
 * children this store holds of the msgids in @a list, whether or not it
 * holds those rows -- the reply index is keyed by the parent's msgid and
 * written when the child is stored.  Each msgid becomes a stub row and
 * history_attach_context hangs the children on it, so the rule is the
 * local attach rule exactly (a TAGMSG or a REDACT, in index order; a child
 * already in the list is skipped).  The requester's type mask (@a mask,
 * 0 = all) and the typing-only veto drop what it could not show -- never a
 * REDACT, which hides its target on the requester whatever the client sees
 * (W5 Task 15 final fixes); no presence filter here: the requester filters
 * every row it is sent, as for page context (a responder's replicated
 * presence records can differ from the origin's, and only the origin holds
 * a session anchor).  At most min(@a cap, FED_CHILDREN_MAX) children other
 * than REDACTs, every REDACT besides.  Each child goes after a CH C naming
 * its parent (send_ch_rows, parents 0: the stubs are not sent).  @a list
 * is split in place.
 * @return The children sent, REDACTs included. */
static int fed_children_answer(struct Client *to, const char *target, const char *reqid,
                               char *list, unsigned int mask, int cap)
{
  const char *ids[FED_K_IDS_MAX];
  struct HistoryMessage *stubs = NULL, *tail = NULL, *m, **pp;
  int n, i, sent = 0, kept = 0;

  if (cap <= 0 || cap > FED_CHILDREN_MAX)
    cap = FED_CHILDREN_MAX;
  n = hm_parse_ids(list, ids, FED_K_IDS_MAX);
  for (i = 0; i < n; i++) {
    m = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
    ircd_strncpy(m->msgid, ids[i], sizeof(m->msgid));
    ircd_strncpy(m->target, target, sizeof(m->target));
    if (tail)
      tail->next = m;
    else
      stubs = m;
    tail = m;
  }
  if (!stubs)
    return 0;
  history_attach_context(target, stubs);
  skip_redacted_context(target, &stubs, 0);
  /* A REDACT child is never dropped -- not for the requester's type mask
   * (a client without draft/message-redaction: the requester's own replay
   * strips the REDACT line, after its redaction filter has used it), nor
   * for the cap, which counts the other children only.  A requester that
   * lacks it (a split before catch-up) would show the message (W5 Task 15
   * final fixes, M-1). */
  for (pp = &stubs; (m = *pp); ) {
    if (m->is_context && m->type != HISTORY_REDACT
        && ((mask && !(mask & (1u << m->type)))
            || history_row_is_typing_only(m) || kept >= cap)) {
      *pp = m->next;
      m->next = NULL;
      history_free_messages(m);
      continue;
    }
    if (m->is_context) {
      sent++;
      if (m->type != HISTORY_REDACT)
        kept++;
    }
    pp = &m->next;
  }
  send_ch_rows(to, reqid, stubs, 0);
  history_free_messages(stubs);
  return sent;
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
/* Forward a federation reply (R/B/Z/T/E) that matches no local FedRequest
 * toward the origin server encoded in the reqid prefix (reqid = <yy><counter>,
 * minted by start_fed_query). Replies carry no destination field, so
 * multi-hop topologies need this hop-by-hop relay; without it a reply dies at
 * the first intermediate server and federation only works between directly
 * linked pairs. Drops (matching prior behavior) when the origin is unknown,
 * local (stale reply after timeout), or would bounce back out the arrival
 * link.  A line that arrived with client-only tags (an R or a first B
 * line's ,C, W5 Task 2) goes on with the same tag region -- the row's
 * time and msgid from the link's stash beside them -- so the origin keeps
 * the tags across a middle hop. */
static void forward_fed_reply(struct Client *sptr, struct Client *cptr,
                              int parc, char *parv[])
{
  struct Client *origin;
  char yy[3];
  char buf[BUFSIZE];
  char *out = buf;
  char *end = buf + sizeof(buf);
  int i;

  /* parv[2] = reqid for every reply subcommand; shortest frame is E (parc 4) */
  if (parc < 4 || EmptyString(parv[2]) || strlen(parv[2]) < 3)
    return;
  yy[0] = parv[2][0];
  yy[1] = parv[2][1];
  yy[2] = '\0';
  origin = FindNServer(yy);
  if (!origin || origin == &me || !IsServer(origin))
    return;
  if (cli_from(origin) == cptr)
    return;

  /* Rebuild "<sub> <p2> ... :<last>" faithfully; only the trailing param can
   * contain spaces, so param positions and parc survive the round trip. */
  for (i = 1; i < parc - 1; i++)
    out += ircd_snprintf(0, out, end - out, "%s%s", i > 1 ? " " : "", parv[i]);
  ircd_snprintf(0, out, end - out, " :%s", parv[parc - 1]);
  /* sendcmdto_one_ctags sends the plain line when the stash holds no
   * tags (every other reply), and toward a link that takes no S2S tags. */
  sendcmdto_one_ctags(sptr, CMD_CHATHISTORY, origin, cli_s2s_time_ms(cptr),
                      cli_s2s_msgid(cptr), cli_s2s_client_tags(cptr), "%s", buf);
}

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
    /* Query: Q <target> <subcmd:1char> <ref:T/M/*> <limit> <reqid> [<dest_numeric>] */
    char *target, *query_subcmd_str, *ref, *reqid;
    char *dest_numeric = NULL;
    char *ref2 = NULL;
    const char *requester = NULL;   /* P<yxx> / F<yxx>, see start_fed_query */
    unsigned int req_type_mask = 0; /* row types the requester can receive; 0 = all */
    struct PresenceQueryFilter *fed_pf = NULL;
    char query_subcmd_char;
    int between_desc = -1;   /* W: walk direction for the overflow trim */
    const char *query_subcmd_full;
    int limit, count;
    struct HistoryMessage *messages = NULL;
    enum HistoryRefType ref_type;
    const char *ref_value;

    if (parc < 7)
      return 0;

    target = parv[2];
    query_subcmd_str = parv[3];
    ref = parv[4];
    limit = atoi(parv[5]);
    reqid = parv[6];

    /* Optional destination numeric (multi-hop direct addressing) */
    if (parc >= 8 && parv[7][0] != '\0')
      dest_numeric = parv[7];

    /* Optional second reference (BETWEEN/W); "*" is the placeholder a
     * requester sends to keep the requester token's slot. */
    if (parc >= 9 && parv[8][0] != '\0' && strcmp(parv[8], "*") != 0)
      ref2 = parv[8];

    /* Optional requester token (presence-aware paging on the responder) */
    if (parc >= 10 && parv[9][0] != '\0')
      requester = parv[9];
    /* Optional trailing requester type mask (hex): the row types the
     * requester can receive.  0 / absent = all types (audit #8). */
    {
      if (parc >= 11 && parv[10][0] != '\0')
        req_type_mask = (unsigned int)strtoul(parv[10], NULL, 16);
    }

    /* Destination-addressed query: if not for us, forward and skip */
    if (dest_numeric) {
      struct Client *dest = FindNServer(dest_numeric);
      if (dest && dest != &me) {
        /* Forward to destination via P10 routing — don't process locally.
         * The trailing parameter after the type mask goes on whole: a
         * SEARCH's selectors, a children request's msgid list (CH Q K).
         * A middle hop used to re-emit the parameters only up to the mask,
         * so the far store got neither: it matched every row for a SEARCH
         * (W5 Task 14, F-1).  An older middle hop still drops it. */
        if (requester && parc >= 12 && parv[11])
          sendcmdto_one(sptr, CMD_CHATHISTORY, dest, "Q %s %s %s %d %s %s %s %s %s :%s",
                        target, query_subcmd_str, ref, limit, reqid,
                        dest_numeric, ref2 ? ref2 : "*", requester,
                        parv[10][0] ? parv[10] : "0", parv[11]);
        else if (requester)
          sendcmdto_one(sptr, CMD_CHATHISTORY, dest, "Q %s %s %s %d %s %s %s %s%s%s",
                        target, query_subcmd_str, ref, limit, reqid,
                        dest_numeric, ref2 ? ref2 : "*", requester,
                        (parc >= 11 && parv[10][0]) ? " " : "",
                        (parc >= 11 && parv[10][0]) ? parv[10] : "");
        else if (ref2)
          sendcmdto_one(sptr, CMD_CHATHISTORY, dest, "Q %s %s %s %d %s %s %s",
                        target, query_subcmd_str, ref, limit, reqid,
                        dest_numeric, ref2);
        else
          sendcmdto_one(sptr, CMD_CHATHISTORY, dest, "Q %s %s %s %d %s %s",
                        target, query_subcmd_str, ref, limit, reqid,
                        dest_numeric);
        return 0;
      }
      /* dest_numeric is us — fall through to local processing.
       * Don't propagate (query was targeted at us specifically). */
    }

    /* Legacy path (no dest_numeric): propagate to direct links as before.
     * Filter by advertisement (CH A S) and retention window.
     */
    /* Redaction catch-up: CH Q * D <since_ms> <limit> <reqid> <dest> -- not
     * a channel query: answer from the redaction index, one CH D line per
     * redaction since <since_ms>, then E.  Handled before the channel /
     * presence machinery (target is "*").  A store that was absent asks
     * this on return (design B, crdt-mesh-redact-catchup.md). */
    if (query_subcmd_str && query_subcmd_str[0] == 'D' && query_subcmd_str[1] == '\0') {
      struct RdxScanEmit sc;
      uint64_t since = (uint64_t)strtoull(ref, NULL, 10);
      int trunc = 0, lim = (limit > 0 && limit <= 500) ? limit : 200;
      sc.to = sptr;
      sc.reqid = reqid;
      sc.n = 0;
      if (!history_is_available()) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      /* A scan that could not start (no redact_index CF, the iterator
       * failed) answered nothing: say so (U), or the requester reads a
       * complete round and moves its watermark past every redaction this
       * store holds.  A row unreadable mid-scan is skipped, as before. */
      if (history_redact_index_scan(since, lim, rdx_scan_emit_cb, &sc, &trunc) < 0) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      Debug((DEBUG_DEBUG, "CH Q D: since %llu -> %d row(s) trunc %d for %s",
             (unsigned long long)since, sc.n, trunc, reqid));
      if (trunc)
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d T", reqid, sc.n);
      else
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d", reqid, sc.n);
      return 0;
    }

    /* Children request (W5 Task 14): the context children of the msgids a
     * requester's page holds, whatever this store's own page would be.
     *   CH Q <target> K <+|*> <cap> <reqid>K <dest> * <P|F><yxx> <mask> :<msgid> ...
     * '+' = more lines of this request follow, '*' = the last.  Stateless
     * per line: each is answered as it comes, and one E follows the '*'
     * line (P10 is FIFO per link and the path to us is fixed, so it is the
     * last to arrive).  Only ever sent addressed, to a store whose CH A S
     * carried K: one without a destination is ignored, never propagated.
     * A line whose list an older middle hop dropped is answered with
     * nothing. */
    if (query_subcmd_str[0] == 'K' && query_subcmd_str[1] == '\0') {
      int last = !(ref[0] == '+' && ref[1] == '\0');
      int n = 0;

      if (!dest_numeric)
        return 0;
      if (!history_is_available()) {
        if (last)
          sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      if (IsChannelName(target) && parc >= 12 && !EmptyString(parv[11]))
        n = fed_children_answer(sptr, target, reqid, parv[11], req_type_mask, limit);
      Debug((DEBUG_DEBUG, "CH Q K: %s %s -> %d child(ren)%s", target, reqid, n,
             last ? ", last line" : ""));
      if (last)
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d", reqid, n);
      return 0;
    }

    if (!dest_numeric) {
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

    /* TARGETS (W5 Task 11): the named requester's own targets this store
     * holds above the window's lower bound -- in-window rows first,
     * nearest the first selector, veto rows last (hm_targets_responder),
     * at most CH_T_MAX_ROWS, then E <reqid> <n> [T].  The requester is
     * named by P<yxx> and, from a Task 11 origin, its identity
     * (parv[11]: targets_requester); one this store cannot name, an
     * unparsable span or a read error is answered E <reqid> 0 U, never a
     * walk over every target.  A PM pair index this start could not
     * rebuild may lack pairs: the rows it has (every channel, the pairs the
     * index holds) still go, then E <reqid> <n> [T]U -- every linkable
     * origin keeps CH T rows and reads U as an unanswered store, so the
     * page keeps them and is partial (W5 Push F; it was a bare E 0 U). */
    if (query_subcmd_str[0] == 'T') {
      struct HistoryTarget *targets = NULL, *tgt;
      struct Client *rq;
      char *comma;
      uint64_t first_ms = 0, second_ms = 0;
      int n, cut = 0, ok, index_short;

      if (!history_is_available()) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }

      /* Parse dual timestamp from ref: <ts1>,<ts2>, in the client's order */
      comma = strchr(ref, ',');
      if (!comma) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      *comma = '\0';
      ok = hm_targets_ref_ms(ref, &first_ms) == 0
           && hm_targets_ref_ms(comma + 1, &second_ms) == 0;
      *comma = ',';
      if (!ok) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }

      /* A pair index this start could not rebuild may lack pairs: the
       * answer may be missing some -- U after the rows it has. */
      index_short = feature_bool(FEAT_CHATHISTORY_PRIVATE) && !history_pm_index_whole();
      rq = targets_requester(requester, (parc >= 12 && !EmptyString(parv[11])) ? parv[11] : NULL);
      if (!rq) {
        Debug((DEBUG_DEBUG, "CH Q T %s: requester %s %s not named here", reqid,
               requester ? requester : "-", (parc >= 12 && parv[11]) ? parv[11] : "-"));
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      if (targets_collect(rq, first_ms < second_ms ? first_ms : second_ms, &targets) < 0) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      n = hm_targets_responder(&targets, first_ms, second_ms, CH_T_MAX_ROWS, &cut);
      for (tgt = targets; tgt; tgt = tgt->next)
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "T %s %s %s",
                      reqid, tgt->target, tgt->last_timestamp);
      if (cut || index_short)
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d %s%s", reqid, n,
                      cut ? "T" : "", index_short ? "U" : "");
      else
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d", reqid, n);
      history_free_targets(targets);
      return 0;
    }

    /* PM (pair-key) targets are served like channels: the origin
     * server vouches for its requester (the participant check ran
     * there); this responder trusts linked servers per the P10 model. */

    /* Check if we have history backend */
    if (!history_is_available()) {
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
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

    /* A page selector this store cannot place (review A1b, issue 214):
     * not a row of the target here and not an id of the form this family
     * mints -- a legacy id the origin's target holds and this one does
     * not.  The walk would come back empty, and a bare "E <reqid> 0" reads
     * at the origin as "this store has nothing in the span", which lets
     * the page claim draft/chathistory-end with this store's rows never
     * looked for.  Answer U, "never answered the query" (the flag the
     * origin already has for no store, an unknown subcommand, a read
     * error): it withholds the end tag and marks the page partial, as for
     * any store that could not answer.  An origin from before the U flag
     * ignores the trailing parameter and reads it as before. */
    if (query_subcmd_char == 'L' || query_subcmd_char == 'B'
        || query_subcmd_char == 'A' || query_subcmd_char == 'R'
        || query_subcmd_char == 'W') {
      char ts[HISTORY_TIMESTAMP_LEN];
      enum HistoryRefType t2;
      const char *v2;
      int unplaced = ref_type == HISTORY_REF_MSGID
                     && history_msgid_ref_timestamp(target, ref_value, ts) < 0;
      if (!unplaced && query_subcmd_char == 'W' && ref2
          && parse_s2s_reference(ref2, &t2, &v2) == 0 && t2 == HISTORY_REF_MSGID)
        unplaced = history_msgid_ref_timestamp(target, v2, ts) < 0;
      if (unplaced) {
        Debug((DEBUG_DEBUG, "CH Q %s %c: a selector this store cannot place: E U",
               reqid, query_subcmd_char));
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
    }

    /* Presence-aware paging on the responder.  The requester names its
     * client (P<yxx> / F<yxx>, F = ":full" requested) so a storage
     * server walks with the requester's presence and its limit+1
     * truncation probe counts VISIBLE rows -- otherwise a remote page
     * full of rows the requester never saw is reported truncated, and
     * the origin's post-filter can only shrink it.  Only ACCOUNT
     * anchors qualify: account presence replicates by observation, a
     * session anchor lives in memory on the origin alone.  Unresolvable
     * or session-anchored requesters get the unfiltered walk (the
     * origin post-filters, as before). */
    if (requester && (requester[0] == 'P' || requester[0] == 'F')
        && requester[1] && IsChannelName(target)) {
      struct Client *rq = findNUser(requester + 1);
      if (rq && IsUser(rq) && IsAccount(rq) && cli_user(rq)
          && cli_user(rq)->account[0]) {
        if (open_query_presence(rq, target, requester[0] == 'F', &fed_pf) < 0) {
          /* Fail closed exactly as the origin would. */
          sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
          return 0;
        }
      }
    }

    /* Filter for the responder walk: the presence hook when one was
     * opened (account requester), else a bare filter -- either way it
     * carries the requester's type mask and typing veto so the limit+1
     * probe counts VISIBLE rows (audit #8). */
    struct HistoryRowFilter fed_bare;
    struct HistoryRowFilter *fed_hook = presence_query_filter_hook(fed_pf);
    int walk_truncated = 0;   /* fed_hook->truncated, read before the close */
    int around_exhausted = 1; /* R: both walks ran out (history_query_around) */
    if (!fed_hook) {
      memset(&fed_bare, 0, sizeof(fed_bare));
      fed_hook = &fed_bare;
    }
    fed_hook->type_mask = req_type_mask;
    fed_hook->veto = typing_only_veto;
    fed_hook->veto_ctx = NULL;

    /* Query local LMDB based on subcommand.  For the linear shapes
     * (L/B/A) probe limit+1: an over-limit result marks this response
     * TRUNCATED, signaled to the requester on the CH E terminator so
     * the completeness reaches the end client as the presence/absence
     * of @draft/chathistory-end.  The overflow row is trimmed so the
     * emitted set matches the plain-limit query exactly: L and B
     * collect reverse (latest-first) into a chronological list, so
     * their overflow is the HEAD (oldest); A walks forward, so its
     * overflow is the TAIL (newest).  R (around) is bidirectional --
     * no probe: flagged when either side's walk filled up (#214; it was
     * never flagged, so a responder's short AROUND page with a full back
     * half read as "nothing more" at the origin). */
    if (query_subcmd_char == 'L') {
      count = history_query_latest(target, ref_type, ref_value, limit + 1,
                                   &messages, fed_hook);
    } else if (query_subcmd_char == 'B') {
      count = history_query_before(target, ref_type, ref_value, limit + 1,
                                   &messages, fed_hook);
    } else if (query_subcmd_char == 'A') {
      count = history_query_after(target, ref_type, ref_value, limit + 1,
                                  &messages, fed_hook);
    } else if (query_subcmd_char == 'R') {
      count = history_query_around(target, ref_type, ref_value, limit,
                                   &messages, fed_hook, &around_exhausted);
    } else if (query_subcmd_char == 'W') {
      /* BETWEEN: second reference arrives as the optional trailing
       * param (after dest_numeric). */
      enum HistoryRefType ref_type2;
      const char *ref_value2;
      if (!ref2 || parse_s2s_reference(ref2, &ref_type2, &ref_value2) != 0) {
        presence_query_filter_close(fed_pf);
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
        return 0;
      }
      count = history_query_between(target, ref_type, ref_value,
                                    ref_type2, ref_value2, limit + 1, &messages,
                                    fed_hook);
      /* Which end is the overflow: descending prepends, so its overflow
       * is the HEAD; ascending appends, TAIL (re-review R8). */
      between_desc = history_between_descending(target, ref_type, ref_value,
                                                ref_type2, ref_value2);
    } else if (query_subcmd_char == 'S') {
      /* Federated SEARCH: <before> (unix sec.ms) as the reference, <after>
       * or * as ref2, the selectors as the trailing parameter (parv[11]), the
       * requester's presence already opened above.  Rows go back with
       * the page machinery; E carries T when our scan budget cut the
       * window short.  The walk drops a redacted match itself, so an
       * older requester, which does not check, never receives one. */
      struct SearchMatch ssm;
      struct HistoryMessage *rows = NULL, *r;
      int budget = SEARCH_SCAN_MAX, truncated = 0, n = 0;
      char selbuf[BUFSIZE];
      char before_buf[HISTORY_TIMESTAMP_LEN];
      memset(&ssm, 0, sizeof(ssm));
      ircd_strncpy(before_buf, ref_type == HISTORY_REF_TIMESTAMP && ref_value ? ref_value : "",
                   sizeof(before_buf) - 1);
      before_buf[sizeof(before_buf) - 1] = '\0';
      if (ref2) {
        enum HistoryRefType t2;
        const char *v2;
        if (parse_s2s_reference(ref2, &t2, &v2) == 0 && t2 == HISTORY_REF_TIMESTAMP && v2)
          ssm.after_ms = (int64_t)history_parse_ms(v2);
      }
      selbuf[0] = '\0';
      if (parc >= 12 && parv[11])
        ircd_strncpy(selbuf, parv[11], sizeof(selbuf) - 1);
      {
        char *q = selbuf, *tok;
        while ((tok = q) && *tok) {
          char *sp = strchr(tok, ' ');
          if (sp) { *sp = '\0'; q = sp + 1; } else q = tok + strlen(tok);
          if (0 == strncmp(tok, "from=", 5)) {
            ircd_strncpy(ssm.from, tok + 5, sizeof(ssm.from));
            search_sel_unescape(ssm.from);
          } else if (0 == strncmp(tok, "text=", 5)) {
            search_sel_unescape(tok + 5);
            if (tok[5])
              ssm.text = tok + 5;
          }
        }
      }
      Debug((DEBUG_DEBUG, "CH Q S: target %s before '%s' after %lld limit %d from '%s' text '%s' reftype %d",
             target, before_buf, (long long)ssm.after_ms, limit, ssm.from,
             ssm.text ? ssm.text : "", (int)ref_type));
      if (!before_buf[0]) {
        presence_query_filter_close(fed_pf);
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
        return 0;
      }
      n = search_walk(target, before_buf, limit, &ssm, &budget, fed_hook, &rows, &truncated);
      Debug((DEBUG_DEBUG, "CH Q S: %s -> %d row(s), truncated %d, budget left %d", target, n, truncated, budget));
      presence_query_filter_close(fed_pf);
      fed_pf = NULL;
      if (n < 0) {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
        return 0;
      }
      for (r = rows; r; r = r->next)
        send_ch_response(sptr, reqid, r);
      if (truncated)
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d T", reqid, n);
      else
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d", reqid, n);
      history_free_messages(rows);
      return 0;
    } else if (query_subcmd_char == 'X') {
      presence_query_filter_close(fed_pf);
      fed_pf = NULL;
      /* Exact message lookup by msgid -- used for federated REDACT.  The
       * reference is M<msgid> (start_redact_fed_query): the prefix keeps a
       * msgid whose server numeric starts with a digit from reading as a
       * timestamp.  parse_s2s_reference does not strip it -- 80859cb2 took
       * the T/M prefixes out of the page queries before X was added -- so
       * every X lookup used to look up "M<msgid>" and answer E 0: strip
       * it here.  Anything else is malformed. */
      if (ref[0] == 'M' && ref[1]) {
        struct HistoryMessage *single_msg = NULL;
        int lrc = history_lookup_message(target, ref + 1, &single_msg);
        if (lrc == 0 && single_msg) {
          /* The row first, then its context children, each after its
           * CH C: a REDACT among them tells the requester the message is
           * already redacted (a repeat is an idempotent success there).
           * An older requester reads only the first row -- the parent --
           * and ignores the rest.  E counts the row alone, as for pages. */
          history_attach_context(target, single_msg);
          send_ch_rows(sptr, reqid, single_msg, 1);
          sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 1", reqid);
          history_free_messages(single_msg);
        } else {
          /* A read error is no answer (U), not "no such row". */
          sendcmdto_one(&me, CMD_CHATHISTORY, sptr,
                        lrc < 0 ? "E %s 0 U" : "E %s 0", reqid);
          if (single_msg)
            history_free_messages(single_msg);
        }
      } else {
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0", reqid);
      }
      return 0;
    } else {
      /* Unsupported subcommand for federation */
      presence_query_filter_close(fed_pf);
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
      return 0;
    }
    /* A presence hook lives inside fed_pf: read what the walk left on it
     * before the close frees it (the flag used to be read after). */
    walk_truncated = fed_hook->truncated;
    presence_query_filter_close(fed_pf);
    fed_pf = NULL;
    fed_hook = NULL;

    if (count < 0) {
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s 0 U", reqid);
      return 0;
    }
    if (count == 0) {
      /* Nothing visible, but a walk that gave up (scan cap) or an AROUND
       * side that never looked has not run out: T, as for a full page. */
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr,
                    (walk_truncated || !around_exhausted) ? "E %s 0 T" : "E %s 0",
                    reqid);
      return 0;
    }

    /* Over-limit probe result => truncated; trim the overflow row
     * (direction-dependent end, see the query comment above). */
    {
      int truncated = 0;
      /* A filtered walk that hit its scan cap gave up, not ran out: the
       * origin must not stamp chathistory-end on it.  Every local path
       * honours hook->truncated through query_page_complete; the
       * responder did not (re-review R8). */
      if (walk_truncated)
        truncated = 1;
      if (query_subcmd_char == 'R' && !around_exhausted)
        truncated = 1;
      if ((query_subcmd_char == 'L' || query_subcmd_char == 'B'
           || query_subcmd_char == 'A' || query_subcmd_char == 'W')
          && count > limit) {
        truncated = 1;
        if (query_subcmd_char == 'A'
            || (query_subcmd_char == 'W' && between_desc == 0)) {
          struct HistoryMessage *m = messages;
          int n;
          for (n = 1; n < limit && m; n++)
            m = m->next;
          if (m && m->next) {
            history_free_messages(m->next);
            m->next = NULL;
          }
        } else {
          struct HistoryMessage *extra = messages;
          messages = messages->next;
          extra->next = NULL;
          history_free_messages(extra);
        }
        count = limit;
      }

      /* Attach context children (reactions, redacts) so remote-only
       * children of in-window parents reach the requester even when
       * their own timestamps fall outside the page (#526).  Each child
       * is preceded by a CH C declaration naming its parent; requesters
       * splice on it, older requesters ignore the unknown subcommand
       * and see the child as an ordinary row (harmless). */
      history_attach_context(target, messages);
      /* A reaction this store knows is redacted is not declared or sent
       * (W5 Task 15 fix round 1): a requester without its REDACT -- one
       * that missed it across a split, one with no store -- would show it. */
      skip_redacted_context(target, &messages, 1);

      /* Send response messages (each context child after its CH C).
       * send_ch_response picks the line form per row:
       * - CH R: normal response (content as-is)
       * - CH B: base64 encoded response (with chunking if needed)
       */
      send_ch_rows(sptr, reqid, messages, 1);

      /* Send end marker; trailing T = this result was truncated at the
       * requested limit (optional param, ignored by older parsers). */
      if (truncated)
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d T", reqid, count);
      else
        sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "E %s %d", reqid, count);
    }

    history_free_messages(messages);
  }
  else if (strcmp(subcmd, "C") == 0) {
    /* Context declaration: C <reqid> <parent_msgid> <child_msgid>.
     * Marks the (following or already-received) child row as a
     * context child of parent for splice-after-parent handling. */
    struct FedRequest *req;
    int k_leg;

    if (parc < 5)
      return 0;

    req = find_fed_request_leg(parv[2], &k_leg);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }

    if (k_leg) {
      /* The children leg (W5 Task 14): kept until its row comes, which
       * removes it (add_fed_child).  A full table leaves the row to name
       * its parent itself (hm_context_parent). */
      if (req->k_decl_count < FED_K_DECL_MAX) {
        struct FedCtxPair *pair = &req->k_decl[req->k_decl_count++];
        ircd_strncpy(pair->child, parv[4], sizeof(pair->child));
        ircd_strncpy(pair->parent, parv[3], sizeof(pair->parent));
        pair->tags[0] = '\0';
        if (parc > 5 && parv[5])
          ircd_strncpy(pair->tags, parv[5], sizeof(pair->tags));
      }
      return 0;
    }

    /* The page leg (W5 Task 15 fix round 1): kept until its row comes,
     * which takes it out (remove-on-match), so the 65th and later
     * declarations of a page are honoured; a row that came first becomes
     * the child now (hm_leg_declare).  A full table is recorded: only then
     * may an undeclared row be derived as context (F-3's fallback). */
    hm_leg_declare(&req->leg, parv[3], parv[4], (parc > 5 && parv[5]) ? parv[5] : "",
                   MAX_FED_CONTEXT);
  }
  else if (strcmp(subcmd, "R") == 0) {
    /* Response: R <reqid> <msgid> <ts> <type> <sender> <account> :<content> */
    char *reqid, *msgid, *timestamp, *sender, *account, *content;
    int type, k_leg;
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

    /* Find the request (and leg: <reqid>K is the children leg's) */
    req = find_fed_request_leg(reqid, &k_leg);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }

    /* Add message to federated results, with the client-only tags the
     * line's ,C segment brought (parse_server's per-line stash of this
     * link; empty from a responder that sends none). */
    if (k_leg)
      add_fed_child(req, msgid, timestamp, type, sender, account, content,
                    cli_s2s_client_tags(cptr));
    else
      add_fed_message(req, msgid, timestamp, type, sender, account, content,
                      cli_s2s_client_tags(cptr));
  }
  else if (strcmp(subcmd, "D") == 0) {   /* a redaction from the catch-up scan */
    struct rdx_reply rr;
    struct FedRequest *req;
    if (rdx_reply_parse(parc, parv, &rr) != 0)
      return 0;
    req = find_fed_request(rr.reqid);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }
    add_fed_redact(req, &rr);
  }
  else if (strcmp(subcmd, "Z") == 0) {
    /* Compressed Response: Z <reqid> <msgid> <ts> <type> <sender> <account> :<b64_compressed>
     * Content is base64-encoded zstd-compressed data for bandwidth savings.
     */
    char *reqid, *msgid, *timestamp, *sender, *account, *b64_content;
    int type, k_leg;
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

    /* Find the request (and leg) */
    req = find_fed_request_leg(reqid, &k_leg);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }

#ifdef USE_ZSTD
    /* Decode base64, then parse the payload as the serialized RECORD it
     * has always been: the sender ships raw_content, i.e. the stored DB
     * value 'type|sender|account|[ot][ct]content' (possibly compressed).
     * history_deserialize_record handles zstd internally and yields the
     * record's true content (sentinel-unescaped) and type.  The old
     * code passed the decompressed record blob VERBATIM as message
     * content -- header bytes rendered as message text for any
     * compressed (>threshold) record served over federation.  Wire
     * msgid/ts/sender/account stay authoritative for parity with R/B.
     * The record's client_tags are the row's: they ride the payload, so
     * Z needs no ,C segment, and they are kept like an R or B line's ,C
     * tags (W5 Task 2). */
    {
      char *decoded;
      size_t decoded_len;

      /* type: the wire copy; the record's own type is authoritative, the
       * wire's names a row lost before it was read (fed_row_lost). */
      if (ch_base64_decode(b64_content, strlen(b64_content), &decoded, &decoded_len)) {
        struct HistoryMessage rec;
        memset(&rec, 0, sizeof(rec));
        if (history_deserialize_record(decoded, decoded_len, &rec) == 0) {
          if (k_leg)
            add_fed_child(req, msgid, timestamp, rec.type, sender, account,
                          rec.content, rec.client_tags);
          else
            add_fed_message(req, msgid, timestamp, rec.type, sender, account,
                            rec.content, rec.client_tags);
        } else {
          Debug((DEBUG_DEBUG, "CH Z: undecodable record for %s, dropping", msgid));
          fed_row_lost(req, k_leg, msgid, type);
        }
        MyFree(decoded);
      } else
        fed_row_lost(req, k_leg, msgid, type);
    }
#else
    /* No zstd support - can't decompress, skip this message */
    Debug((DEBUG_DEBUG, "CH Z: Received compressed response but USE_ZSTD not enabled"));
    fed_row_lost(req, k_leg, msgid, type);
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
    int k_leg;

    /* The shortest form is the final continuation, "B <reqid> <msgid>
     * :<b64>" (parc 5).  A 4-param line has no data: the continuation
     * branch below would take the NULL parv[4] as its base64 and
     * strlen() it.  Drop it here, before the forward, so it never
     * reaches the request's origin either. */
    if (parc < 5)
      return 0;

    reqid = parv[2];
    msgid = parv[3];

    /* Find the request (and leg; the chunk key below carries the reqid as
     * sent, so the two legs' chunks never meet) */
    req = find_fed_request_leg(reqid, &k_leg);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }

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
      /* The full form is B <reqid> <msgid> <ts> <type> <sender> <account>
       * [+] <b64>: parv[7] must exist (a 7-param line is a truncated
       * full form, and parv[7] is the NULL terminator -- re-review
       * 2026-09-07 R1). */
      if (parc < 8)
        return 0;
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
      /* Only the first line carries the row's ,C tags: keep them for
       * the final chunk. */
      chunk = create_chunk(reqid, msgid, parv[4], atoi(parv[5]), parv[6], parv[7],
                           cli_s2s_client_tags(cptr));
      if (!chunk) {
        /* No slot: the row is lost before it is read.  Its continuations
         * find no chunk and are ignored. */
        fed_row_lost(req, k_leg, msgid, atoi(parv[5]));
        return 0;
      }
    }
    chunk->link = cptr;   /* track origin link for per-link cleanup */

    /* Append base64 data */
    append_chunk_data(chunk, b64_data);

    if (!has_more) {
      /* Final chunk - decode and add to results */
      char *decoded;
      size_t decoded_len;

      if (ch_base64_decode(chunk->b64_data, chunk->b64_len, &decoded, &decoded_len)) {
        if (k_leg)
          add_fed_child(req, chunk->msgid, chunk->timestamp, chunk->type,
                        chunk->sender, chunk->account, decoded, chunk->client_tags);
        else
          add_fed_message(req, chunk->msgid, chunk->timestamp, chunk->type,
                          chunk->sender, chunk->account, decoded, chunk->client_tags);
        MyFree(decoded);
      } else
        fed_row_lost(req, k_leg, chunk->msgid, chunk->type);
      free_chunk(chunk);
    }
  }
  else if (strcmp(subcmd, "T") == 0) {
    /* Target Response: T <reqid> <target> <last_timestamp> */
    char *reqid, *target, *last_timestamp;
    struct FedRequest *req;

    if (parc < 5)
      return 0;

    reqid = parv[2];
    target = parv[3];
    last_timestamp = parv[4];

    req = find_fed_request(reqid);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }

    add_fed_target(req, sptr, target, last_timestamp);
  }
  else if (strcmp(subcmd, "E") == 0) {
    /* End: E <reqid> <count> */
    char *reqid;
    int count, k_leg;
    struct FedRequest *req;

    if (parc < 4)
      return 0;

    reqid = parv[2];
    count = atoi(parv[3]);

    /* Find the request (and leg) */
    req = find_fed_request_leg(reqid, &k_leg);
    if (!req) {
      forward_fed_reply(sptr, cptr, parc, parv);
      return 0;
    }

    /* The children leg (W5 Task 14): one E per store, after its request's
     * last line.  Its flags are logged, never applied: a store that could
     * not answer (U) or cut its answer (T) costs the page context, never a
     * row, and that is not partial (user decision 2026-11-08 15:08). */
    if (k_leg) {
      unsigned int kflags = ch_e_flags((parc > 4 && parv[4]) ? parv[4] : NULL);
      int si = server_ad_index(sptr);
      if (si >= 0 && si < MAX_AD_SERVERS) {
        if (req->k_e_seen[si >> 3] & (1u << (si & 7)))
          return 0;
        req->k_e_seen[si >> 3] |= (unsigned char)(1u << (si & 7));
      }
      if (kflags)
        Debug((DEBUG_DEBUG, "CH E %s from %s: children leg %s%s", reqid, cli_name(sptr),
               (kflags & CH_E_UNANSWERED) ? "unanswered" : "",
               (kflags & CH_E_TRUNCATED) ? " truncated" : ""));
      req->k_pending--;
      if (req->servers_pending <= 0 && req->k_pending <= 0)
        complete_fed_request(req);
      return 0;
    }

    /* Optional trailing flags (letters, any order): T = that server's
     * result hit its limit; U = that server never answered the query at
     * all (no store, an unknown subcommand, or a read error) -- distinct
     * from a genuine "no rows" (bare E with no flags).  OR across
     * servers -- any truncated or unanswered contributor means the
     * aggregate cannot claim completeness. */
    {
      unsigned int eflags = ch_e_flags((parc > 4 && parv[4]) ? parv[4] : NULL);
      if (eflags & CH_E_TRUNCATED) {
        req->fed_truncated = 1;
        targets_note_cut(req, sptr);   /* a TARGETS request's cut responder */
      }
      if (eflags & CH_E_UNANSWERED)
        req->cut = 1;   /* a responder never answered: partial, never advance the watermark */
    }

    /* Decrement pending count -- once per responder: a duplicate CH E
     * from one server completed the request without the others' rows
     * (audit 2026-09-06 #14). */
    {
      int si = server_ad_index(sptr);
      if (si >= 0 && si < MAX_AD_SERVERS) {
        if (req->e_seen[si >> 3] & (1u << (si & 7)))
          return 0;
        req->e_seen[si >> 3] |= (unsigned char)(1u << (si & 7));
      }
    }
    req->servers_pending--;

    /* If all servers have responded -- on both legs: a children request
     * (W5 Task 14) may still be out -- complete the request */
    if (req->servers_pending <= 0 && req->k_pending <= 0) {
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
      /* Storage capability: S <retention_days> [<features>] -- the feature
       * letters (ch_ad_features; K = it answers CH Q K, W5 Task 14) are
       * replaced on every CH A S, never OR'd, and relayed as received
       * (ch_ad_letters).  An older server sends none and ignores ours; an
       * older middle hop drops them on relay, so a store behind it looks
       * K-less (fails safe: it is asked no K). */
      int retention;

      if (parc < 4)
        return 0;

      retention = atoi(parv[3]);
      ad->has_advertisement = 1;
      ad->is_storage_server = 1;
      ad->retention_days = retention;
      ch_ad_letters(parc >= 5 ? parv[4] : NULL, ad->letters, sizeof(ad->letters));
      ad->features = ch_ad_features(ad->letters);
      ad->last_update = CurrentTime;
      /* Back -- but not caught up until the burst that carries its state
       * here has ended.  A store sends CH A S when OUR end of burst reaches
       * it, ungated; when it (or any server on the path to it) has gated
       * its burst toward its uplink, that burst tail and EB are still held,
       * and the serv_butone lines meanwhile (REDACT, KICK, TOPIC ...) are
       * dropped.
       * Closing the absence now made pages over that window look whole,
       * and the catch-up ran before its REDACTs (W5 Task 12). */
      if (ad_burst_pending(sptr))
        ad->eob_pending = 1;   /* chathistory_server_eob closes and kicks */
      else {
        ad->eob_pending = 0;
        ad_store_back(server_ad_index(sptr));
      }

      Debug((DEBUG_DEBUG, "CH A S: Server %s advertises storage with %d day retention",
             cli_name(sptr), retention));

      /* Propagate to other servers (except source), its letters with it,
       * verbatim: known here or not, and whatever our own switch says */
      {
        char letters[CH_AD_LETTERS_MAX + 2];
        sendcmdto_serv_butone_v3(sptr, CMD_CHATHISTORY, cptr, "A S %d%s", retention,
                                 ad_feature_suffix(ad, letters, sizeof(letters)));
      }
      chathistory_update_retention_isupport(1);
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
      sendcmdto_serv_butone_v3(sptr, CMD_CHATHISTORY, cptr, "A R %d", retention);
      chathistory_update_retention_isupport(1);
    }
    else if (subtype[0] == 'F') {
      /* Full channel sync: F :<channel> <channel> ... (Layer 1) */
      char *chanlist;
      char *chan;
      char *saveptr = NULL;
      int added = 0;

      if (parc < 4)
        return 0;

      /* Tokenize a COPY: parv[3] is relayed below and strtok_r would
       * have NUL-terminated it at the first space, so every hop past
       * the first saw a one-channel list (re-review 2026-09-07 R12; the
       * + and - forms already copy). */
      char chanlist_buf[BUFSIZE];
      ircd_strncpy(chanlist_buf, parv[3], sizeof(chanlist_buf) - 1);
      chanlist_buf[sizeof(chanlist_buf) - 1] = '\0';
      chanlist = chanlist_buf;

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
      sendcmdto_serv_butone_v3(sptr, CMD_CHATHISTORY, cptr, "A F :%s", parv[parc - 1]);
    }
    else if (subtype[0] == '+') {
      /* Add channel(s): + :<channel> [channel2] ... (Layer 1) */
      char chanlist[512];
      char *chan, *saveptr;
      int added = 0;

      if (parc < 4)
        return 0;

      /* Copy to mutable buffer for tokenization */
      ircd_strncpy(chanlist, parv[3], sizeof(chanlist) - 1);
      chanlist[sizeof(chanlist) - 1] = '\0';

      /* Parse space-separated channel list */
      chan = strtok_r(chanlist, " ", &saveptr);
      while (chan) {
        if (chan[0] == '#' || chan[0] == '&') {
          if (add_server_channel_ad(sptr, chan))
            added++;
        }
        chan = strtok_r(NULL, " ", &saveptr);
      }

      if (added > 0) {
        Debug((DEBUG_DEBUG, "CH A +: Server %s added %d channels",
               cli_name(sptr), added));
      }
      ad->last_update = CurrentTime;

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone_v3(sptr, CMD_CHATHISTORY, cptr, "A + :%s", parv[3]);
    }
    else if (subtype[0] == '-') {
      /* Remove channel(s): - :<channel> [channel2] ... (Layer 1) */
      char chanlist[512];
      char *chan, *saveptr;
      int removed = 0;

      if (parc < 4)
        return 0;

      /* Copy to mutable buffer for tokenization */
      ircd_strncpy(chanlist, parv[3], sizeof(chanlist) - 1);
      chanlist[sizeof(chanlist) - 1] = '\0';

      /* Parse space-separated channel list */
      chan = strtok_r(chanlist, " ", &saveptr);
      while (chan) {
        if (chan[0] == '#' || chan[0] == '&') {
          if (remove_server_channel_ad(sptr, chan))
            removed++;
        }
        chan = strtok_r(NULL, " ", &saveptr);
      }

      if (removed > 0) {
        Debug((DEBUG_DEBUG, "CH A -: Server %s removed %d channels",
               cli_name(sptr), removed));
      }
      ad->last_update = CurrentTime;

      /* Propagate to other servers (except source) */
      sendcmdto_serv_butone_v3(sptr, CMD_CHATHISTORY, cptr, "A - :%s", parv[3]);
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
                          type_str[0], content, cli_name(sptr));
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

    /* The shortest form is the final continuation, "WB <target> <msgid>
     * :<b64>" (parc 5).  A 4-param line has no data: the continuation
     * branch below would take the NULL parv[4] as its base64 and
     * strlen() it. */
    if (parc < 5)
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
      /* The full form is B <reqid> <msgid> <ts> <type> <sender> <account>
       * [+] <b64>: parv[7] must exist (a 7-param line is a truncated
       * full form, and parv[7] is the NULL terminator -- re-review
       * 2026-09-07 R1). */
      if (parc < 8)
        return 0;
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
        case 'J': type_int = HISTORY_JOIN; break;
        case 'L': type_int = HISTORY_PART; break;
        case 'Q': type_int = HISTORY_QUIT; break;
        case 'I': type_int = HISTORY_KICK; break;
        case 'M': type_int = HISTORY_MODE; break;
        case 'O': type_int = HISTORY_TOPIC; break;
        case 'T': type_int = HISTORY_TAGMSG; break;
        case 'K': type_int = HISTORY_NICK; break;
        case 'R': type_int = HISTORY_REDACT; break;   /* re-review R15 */
      }
      chunk = create_write_chunk(target, msgid, parv[4], type_int, parv[5], parv[6]);
      if (!chunk) {
        Debug((DEBUG_DEBUG, "CH WB: No slots available for %s", chunk_key));
        return 0;
      }
    }
    chunk->link = cptr;   /* track origin link for per-link cleanup */

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
        case HISTORY_NOTICE:  type_char = 'N'; break;
        case HISTORY_JOIN:    type_char = 'J'; break;
        case HISTORY_PART:    type_char = 'L'; break;
        case HISTORY_QUIT:    type_char = 'Q'; break;
        case HISTORY_KICK:    type_char = 'I'; break;
        case HISTORY_MODE:    type_char = 'M'; break;
        case HISTORY_TOPIC:   type_char = 'O'; break;
        case HISTORY_TAGMSG:  type_char = 'T'; break;
        case HISTORY_NICK:    type_char = 'K'; break;
        case HISTORY_REDACT:  type_char = 'R'; break;
        default: type_char = 'P'; break;
      }

      if (ch_base64_decode(chunk->b64_data, chunk->b64_len, &decoded, &decoded_len)) {
        Debug((DEBUG_DEBUG, "CH WB: Decoded %zu bytes for %s", decoded_len, target));
        process_write_forward(chunk->target, chunk->msgid, chunk->timestamp,
                              chunk->sender, chunk->account, type_char, decoded,
                              cli_name(sptr));
        MyFree(decoded);
      } else {
        Debug((DEBUG_DEBUG, "CH WB: Base64 decode failed for %s", target));
      }
      free_write_chunk(chunk);
    }
  }

  return 0;
}

/* ======================================================================
 * SEARCH -- soju.im/search
 * (https://codeberg.org/emersion/soju/src/branch/master/doc/ext/search.md)
 *
 *   SEARCH in=<target> [from=<nick>] [text=<words>] [after=<ts>]
 *          [before=<ts>] [limit=<n>]
 *
 * Answered with a batch of type `search`: the matching PRIVMSG / NOTICE
 * rows in ascending time order, each with msgid and time, or an empty
 * batch.  Malformed selectors get FAIL SEARCH INVALID_PARAMS.
 *
 * Ours is a brute scan of the store: the same walk CHATHISTORY BEFORE
 * uses, from `before` (default now) back towards `after`, keeping the
 * newest `limit` matches.  `text` is a case-insensitive substring, no
 * regular expressions (the spec's ReDoS note).  The presence hook rides
 * in front of the match so a member who was not there does not find it,
 * and the reply side runs the same presence filter as a CHATHISTORY page.
 * A redacted message is never a match (search_row_hook): it is dropped
 * inside the walk, so it takes no slot of `limit`; a storage peer's rows
 * get the same check before the merge.  There is no index: search is
 * bounded by a scan budget of SEARCH_SCAN_MAX raw rows per request,
 * spent across the channels searched when `in` is absent; a client
 * wanting more asks narrower windows.  Without `in`, the channels the
 * requester is in are searched (private conversations need `in=<nick>`:
 * their keyspace is not enumerable per requester).
 * ==================================================================== */

/** Handle SEARCH (soju.im/search).  parv[1..] are `key=value` selectors;
 * the last one may carry spaces (a trailing parameter). */
int m_search(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct SearchMatch sm;
  char in[CHANNELLEN + 1] = "";
  char lookup_target[CHANNELLEN + 1];
  char before_unix[HISTORY_TIMESTAMP_LEN];
  char after_unix[HISTORY_TIMESTAMP_LEN];
  const char *pm_other = NULL;
  int limit = 0, max_limit;
  int budget = SEARCH_SCAN_MAX;
  int i;

  if (!CapActive(sptr, CAP_SOJU_SEARCH))
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "SEARCH");

  if (!history_is_available()) {
    send_fail(sptr, "SEARCH", "INTERNAL_ERROR", "*", "History storage unavailable");
    return 0;
  }

  memset(&sm, 0, sizeof(sm));
  before_unix[0] = '\0';
  after_unix[0] = '\0';

  for (i = 1; i < parc; i++) {
    char *eq = strchr(parv[i], '=');
    const char *key = parv[i];
    const char *val;

    if (!eq || eq == parv[i]) {
      send_fail(sptr, "SEARCH", "INVALID_PARAMS", parv[i], "Selectors are key=value");
      return 0;
    }
    *eq = '\0';
    val = eq + 1;

    if (ircd_strcmp(key, "in") == 0) {
      ircd_strncpy(in, val, sizeof(in));
    } else if (ircd_strcmp(key, "from") == 0) {
      ircd_strncpy(sm.from, val, sizeof(sm.from));
    } else if (ircd_strcmp(key, "text") == 0) {
      if (val[0])
        sm.text = val;
    } else if (ircd_strcmp(key, "after") == 0) {
      if (!val[0] || history_iso_to_unix(val, after_unix, sizeof(after_unix)) != 0) {
        send_fail(sptr, "SEARCH", "INVALID_PARAMS", "after", "Invalid timestamp");
        return 0;
      }
    } else if (ircd_strcmp(key, "before") == 0) {
      if (!val[0] || history_iso_to_unix(val, before_unix, sizeof(before_unix)) != 0) {
        send_fail(sptr, "SEARCH", "INVALID_PARAMS", "before", "Invalid timestamp");
        return 0;
      }
    } else if (ircd_strcmp(key, "limit") == 0) {
      limit = atoi(val);
      if (limit <= 0) {
        send_fail(sptr, "SEARCH", "INVALID_PARAMS", "limit", "Invalid limit");
        return 0;
      }
    }
    /* Unknown selectors are ignored (the spec leaves room for more). */
  }

  max_limit = feature_int(FEAT_CHATHISTORY_MAX);
  if (limit <= 0 || limit > max_limit)
    limit = max_limit;
  /* The selectors also travel S2S in one 512-byte P10 line; refuse an
   * oversize text here so local and federated behaviour agree. */
  {
    char esc[BUFSIZE];
    size_t n = 0;
    if (sm.from[0]) { search_sel_escape(sm.from, esc, sizeof(esc)); n += 5 + strlen(esc) + 1; }
    if (sm.text) { search_sel_escape(sm.text, esc, sizeof(esc)); n += 5 + strlen(esc); }
    if (n > SEARCH_SEL_MAX) {
      send_fail(sptr, "SEARCH", "INVALID_PARAMS", "text", "Selectors too long");
      return 0;
    }
  }
  if (after_unix[0])
    sm.after_ms = (int64_t)history_parse_ms(after_unix);
  if (!before_unix[0]) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    ircd_snprintf(0, before_unix, sizeof(before_unix), "%lu.%03lu",
                  (unsigned long)tv.tv_sec, (unsigned long)(tv.tv_usec / 1000));
  }

  if (in[0]) {
    struct HistoryMessage *rows = NULL;
    int count;

    if (check_history_access(sptr, in, lookup_target, sizeof(lookup_target)) != 0) {
      send_fail(sptr, "SEARCH", "INVALID_PARAMS", "in", "No access to target");
      return 0;
    }
    if (!IsChannelName(in))
      pm_other = in;

    count = search_one_target(sptr, lookup_target, before_unix, limit, &sm,
                              &budget, &rows);
    if (count < 0) {
      send_fail(sptr, "SEARCH", "INTERNAL_ERROR", "in", "Failed to search history");
      return 0;
    }
    /* Federation (2026-09-20, docs/features/search.md): a channel's rows
     * can live on other storage servers (a store that was split holds
     * rows the others lack), and a page of the same window would fan
     * out to them -- so does a search, or users could not trust it.
     * Private conversations and the no-`in` form stay local. */
    if (IsChannelName(in)) {
      struct FedRequest *req = start_fed_search(sptr, lookup_target, in,
                                                before_unix, after_unix,
                                                limit, &sm, rows, count);
      if (req)
        return 0;   /* rows are the request's now; complete_search_fed sends */
    }
    search_send(sptr, rows, pm_other, cli_label(sptr));
    history_free_messages(rows);
    return 0;
  }

  /* No `in`: every channel the requester is in, newest `limit` overall. */
  {
    struct Membership *member;
    struct HistoryMessage **all = NULL;
    struct HistoryMessage *head = NULL, **tail = &head;
    int total = 0, cap = 0, keep, k;

    for (member = cli_user(sptr)->channel; member; member = member->next_channel) {
      struct HistoryMessage *rows = NULL, *m;
      int count;

      if (IsMemberAlias(member))
        continue;   /* the primary's membership covers it */
      if (check_history_access(sptr, member->channel->chname, lookup_target,
                               sizeof(lookup_target)) != 0)
        continue;
      count = search_one_target(sptr, lookup_target, before_unix, limit, &sm,
                                &budget, &rows);
      if (count <= 0) {
        history_free_messages(rows);
        continue;
      }
      if (total + count > cap) {
        cap = (total + count) * 2;
        all = (struct HistoryMessage **)MyRealloc(all, cap * sizeof(*all));
      }
      for (m = rows; m; m = m->next)
        all[total++] = m;
    }

    if (total > 1)
      qsort(all, total, sizeof(*all), search_row_cmp);
    keep = total < limit ? total : limit;
    /* Ascending order; the newest `limit` are the tail of the sort. */
    for (k = 0; k < total; k++) {
      all[k]->next = NULL;
      if (k < total - keep) {
        history_free_messages(all[k]);
        continue;
      }
      *tail = all[k];
      tail = &all[k]->next;
    }
    MyFree(all);
    search_send(sptr, head, NULL, cli_label(sptr));
    history_free_messages(head);
  }
  return 0;
}
