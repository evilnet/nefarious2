/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
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
 */
/*
 * ms_batch - server message handler for S2S BATCH coordination
 *
 * Handles BATCH commands from other servers for coordinating
 * netjoin/netsplit batches across the network.
 *
 * P10 Format:
 *   [SERVER_NUMERIC] BT +batchid type [params]   - Start batch
 *   [SERVER_NUMERIC] BT -batchid                  - End batch
 *
 * Batch Types:
 *   netjoin  - Server reconnecting, users rejoining channels
 *   netsplit - Server disconnecting, users quitting
 *
 * IRCv3 batch specification: https://ircv3.net/specs/extensions/batch
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
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
#include "s_misc.h"
#include "s_user.h"
#include "msgq.h"
#include "class.h"
#include "bouncer_session.h"
#include "history.h"
#include "ml_content.h"
#include "paste_listener.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

/*
 * generate_paste_url - Generate a paste secret and URL for multiline fallback.
 *
 * The actual content storage happens atomically in history_store_multiline().
 * This function just generates the secret and returns the URL.
 *
 * Parameters:
 *   msgid      - base msgid for the batch
 *   secret_out - buffer to receive the generated secret
 *   secret_size - size of secret_out buffer
 *
 * Returns: paste URL string (static buffer, do not free) or NULL if unavailable
 */
static const char *generate_paste_url(const char *msgid,
                                       char *secret_out, size_t secret_size)
{
  char paste_id[PASTE_ID_MAX];

  if (!paste_listener_active())
    return NULL;

  paste_generate_secret(secret_out, secret_size);
  ircd_snprintf(0, paste_id, sizeof(paste_id), "%s-%s", msgid, secret_out);
  return paste_url(paste_id);
}

/*
 * format_batch_open_tags - Build tag prefix for multiline BATCH opener.
 *
 * Per IRCv3 multiline spec, the BATCH + opener carries server tags (time, msgid,
 * account) and client-only tags. This function builds the "@tags " prefix.
 *
 * Parameters:
 *   buf       - output buffer
 *   buflen    - size of output buffer
 *   to        - recipient client (for capability checks)
 *   from      - sender client (for account tag)
 *   timebuf   - ISO 8601 timestamp string
 *   msgid     - message ID string
 *   label     - label string (NULL or empty to skip)
 *   ctags     - client-only tags (NULL or empty to skip)
 *
 * Returns: length written, or 0 if no tags (no @ prefix needed)
 */
static int format_batch_open_tags(char *buf, size_t buflen,
                                   struct Client *to, struct Client *from,
                                   const char *timebuf, const char *msgid,
                                   const char *label, const char *ctags)
{
  int pos = 0;
  int use_tags = CapOwnHas(to, CAP_MSGTAGS);
  int has_label = (label && *label && CapOwnHas(to, CAP_LABELEDRESP));
  int has_ctags = (ctags && *ctags && use_tags);
  int has_account = (use_tags && from && IsUser(from) && IsAccount(from)
                     && CapOwnHas(to, CAP_ACCOUNTTAG));

  if (!use_tags && !has_label)
    return 0;

  buf[pos++] = '@';

  if (has_label) {
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "label=%s", label);
  }

  if (use_tags && timebuf && *timebuf) {
    if (pos > 1) buf[pos++] = ';';
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "time=%s", timebuf);
  }

  if (use_tags && msgid && *msgid) {
    if (pos > 1) buf[pos++] = ';';
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "msgid=%s", msgid);
  }

  if (has_account) {
    if (pos > 1) buf[pos++] = ';';
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "account=%s",
                         cli_user(from)->account);
  }

  if (has_ctags) {
    if (pos > 1) buf[pos++] = ';';
    pos += ircd_snprintf(0, buf + pos, buflen - pos, "%s", ctags);
  }

  buf[pos++] = ' ';
  buf[pos] = '\0';
  return pos;
}

/* Forward declarations: deliver_multiline_dm_to_one calls helpers
 * defined later in the file.  send_multiline_fallback is non-static so
 * bouncer_session.c can reuse it from the BX M (multiline echo)
 * handler — exposed via include/m_batch.h. */
extern void send_multiline_fallback(struct Client *sptr, struct Client *to,
                                     struct Client *acptr, const char *msgid,
                                     struct SLink *messages, int total_lines,
                                     int is_channel, struct Channel *chptr,
                                     const char *paste_url_str,
                                     const char *client_tags, int is_notice);
static const char *get_displayed_host(struct Client *sptr);
static void emit_bxm_to_remote_member(struct Client *member,
                                       const char *member_numeric,
                                       struct Client *sender_primary,
                                       struct Client *acptr,
                                       struct Connection *con,
                                       int is_notice,
                                       const char *batch_base_msgid,
                                       const char *batch_paste_url,
                                       int member_index);

/*
 * deliver_multiline_dm_to_one - Send a multiline DM batch to a single
 * local target, choosing between proper draft/multiline BATCH wrapping
 * and legacy fallback based on the target's negotiated capabilities.
 *
 * Used for the original recipient, recipient's aliases (forward), the
 * sender's session members (echo), and the sender themselves (echo).
 * The wire_target controls what appears in %C/the inner PRIVMSG target:
 *
 *   - Primary delivery / forward to recipient's alias: route_to == wire_target
 *     (the alias sees themselves as the target).
 *   - Echo to sender or sender's session members: route_to is the recipient
 *     of the echo, wire_target is the original DM recipient (so the alias's
 *     client routes the lines into the conversation window).
 *
 * Remote targets (!MyConnect) are not handled here; callers are responsible
 * for cross-server delivery via S2S relay or BX E.
 *
 * preserve_label: include the sender's @label tag on the BATCH opener.
 * Only the sender's own echo passes 1; everything else passes 0.
 *
 * Returns 1 if the legacy fallback path (preview + truncation NOTICE or
 * +M expansion) was taken, 0 if the proper BATCH wrapper was used or
 * the target was skipped (remote / NULL).  Callers use the return to
 * accumulate fallback_count for the sender's WARN notification.
 */
static int deliver_multiline_dm_to_one(struct Client *sptr,
                                        struct Client *route_to,
                                        struct Client *wire_target,
                                        const char *batch_base_msgid,
                                        const char *batch_timebuf,
                                        const char *batch_paste_url,
                                        int is_notice, const char *cmd_str,
                                        int preserve_label)
{
  struct Connection *con = cli_connect(sptr);
  struct SLink *lp;

  if (!route_to || !wire_target || !MyConnect(route_to))
    return 0;

  if (CapActive(route_to, CAP_DRAFT_MULTILINE) && CapActive(route_to, CAP_BATCH)) {
    /* Proper draft/multiline BATCH wrapper preserves concat semantics. */
    char batchid[16];
    const char *label = preserve_label ? con_ml_label(con) : NULL;

    ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                  NumNick(sptr), con_batch_seq(cli_connect(route_to))++);

    {
      char tagbuf[512];
      int taglen = format_batch_open_tags(tagbuf, sizeof(tagbuf), route_to, sptr,
                     batch_timebuf, batch_base_msgid,
                     (label && label[0]) ? label : NULL,
                     con_ml_client_tags(con));
      /* Per IRCv3 multiline spec, the BATCH +id opener uses the user
       * as source, not the server — clients use the wrapper's source
       * to route the batch to the correct conversation window. */
      if (taglen)
        sendrawto_one(route_to, "%s:%s!%s@%s BATCH +%s draft/multiline %s",
                      tagbuf, cli_name(sptr), cli_user(sptr)->username,
                      get_displayed_host(sptr),
                      batchid, cli_name(wire_target));
      else
        sendcmdto_one(sptr, CMD_BATCH_CMD, route_to, "+%s draft/multiline %s",
                      batchid, cli_name(wire_target));
    }

    for (lp = con_ml_messages(con); lp; lp = lp->next) {
      int concat = lp->value.cp[0];
      char *text = lp->value.cp + 1;
      if (concat) {
        sendrawto_one(route_to,
                      "@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
                      batchid, cli_name(sptr), cli_user(sptr)->username,
                      get_displayed_host(sptr), cmd_str,
                      cli_name(wire_target), text);
      } else {
        sendrawto_one(route_to,
                      "@batch=%s :%s!%s@%s %s %s :%s",
                      batchid, cli_name(sptr), cli_user(sptr)->username,
                      get_displayed_host(sptr), cmd_str,
                      cli_name(wire_target), text);
      }
    }

    sendcmdto_one(sptr, CMD_BATCH_CMD, route_to, "-%s", batchid);
    return 0;
  } else if (HasFlag(route_to, FLAG_MULTILINE_EXPAND)) {
    /* +M opt-in: expand without truncation. */
    for (lp = con_ml_messages(con); lp; lp = lp->next) {
      char *text = lp->value.cp + 1;
      if (is_notice)
        sendcmdto_one(sptr, CMD_NOTICE, route_to, "%C :%s", wire_target, text);
      else
        sendcmdto_one(sptr, CMD_PRIVATE, route_to, "%C :%s", wire_target, text);
    }
    return 1;
  } else {
    /* Legacy fallback: preview + truncation NOTICE.
     * send_multiline_fallback already takes route_to (delivery) and
     * acptr (wire %C target) separately. */
    send_multiline_fallback(sptr, route_to, wire_target, batch_base_msgid,
                             con_ml_messages(con), con_ml_msg_count(con),
                             0, NULL, batch_paste_url,
                             con_ml_client_tags(con), is_notice);
    return 1;
  }
}

/*
 * emit_bxm_to_remote_member - Send a multiline DM batch to a remote
 * bouncer-session member as a BX M (multiline alias echo) batch.
 *
 * Wire target on the inner messages is acptr (original PM target), so
 * the receiving alias's IRC client routes the conversation into the
 * correct query window.  Routing target on every BX M line is
 * member_numeric (the receiving alias).  Receiving server's BX M
 * handler (bouncer_session.c::bounce_alias_multiline_echo) buffers
 * by (link, batch_id) and on '-' end either reconstructs a
 * draft/multiline BATCH wrapper for the alias or falls back to
 * send_multiline_fallback if the alias lacks the cap.
 *
 * Caller is responsible for verifying:
 *   - !MyConnect(member)            (remote)
 *   - IsMultiline(cli_from(member)) (alias's server speaks BX M;
 *                                    in our fork, IsMultiline implies
 *                                    BX M support)
 *   - member is a session member of sender_primary's session, not the
 *     sender themselves, and not acptr
 *
 * sender_primary is used as the BX M "from" per the bouncer-session
 * convention — session messages present canonically as primary
 * regardless of which alias actually sent them.
 *
 * member_index is the loop index of the alias within its session;
 * baked into the batch_id to keep concurrent emissions to different
 * aliases from colliding on the receiver's per-link batch table.
 */
static void emit_bxm_to_remote_member(struct Client *member,
                                       const char *member_numeric,
                                       struct Client *sender_primary,
                                       struct Client *acptr,
                                       struct Connection *con,
                                       int is_notice,
                                       const char *batch_base_msgid,
                                       const char *batch_paste_url,
                                       int member_index)
{
  char bxm_batch_id[16];
  const char *ctags = con_ml_client_tags(con);
  const char *bx_tok = is_notice ? TOK_NOTICE : TOK_PRIVATE;
  struct SLink *lp;
  int first = 1;

  ircd_snprintf(0, bxm_batch_id, sizeof(bxm_batch_id), "%s%lu%d",
                cli_yxx(sender_primary), (unsigned long)CurrentTime,
                member_index);

  for (lp = con_ml_messages(con); lp; lp = lp->next) {
    int concat = lp->value.cp[0];
    const char *text = lp->value.cp + 1;
    if (*text == '\0')
      continue;
    if (first) {
      const char *msgid = (batch_base_msgid && *batch_base_msgid)
                          ? batch_base_msgid : "*";
      if (ctags && *ctags) {
        sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, member,
                      "M +%s %s %s%s %s %s %s @%s :%s",
                      bxm_batch_id, member_numeric,
                      NumNick(sender_primary), bx_tok,
                      cli_name(acptr), msgid, ctags, text);
      } else {
        sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, member,
                      "M +%s %s %s%s %s %s %s :%s",
                      bxm_batch_id, member_numeric,
                      NumNick(sender_primary), bx_tok,
                      cli_name(acptr), msgid, text);
      }
      first = 0;
    } else if (concat) {
      sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, member,
                    "M c%s %s :%s", bxm_batch_id, member_numeric, text);
    } else {
      sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, member,
                    "M %s %s :%s", bxm_batch_id, member_numeric, text);
    }
  }

  /* End of batch — paste_url empty if we don't have one. */
  sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, member,
                "M -%s %s :%s", bxm_batch_id, member_numeric,
                batch_paste_url ? batch_paste_url : "");
}

/*
 * send_multiline_fallback - Send truncated multiline with paste URL
 *
 * Sends preview lines to legacy clients, with a paste URL for the full
 * message when the paste service is available.
 *
 * Uses configurable preview budget (FEAT_MULTILINE_LEGACY_MAX_LINES):
 * - ≤max_preview lines: send all, no notice
 * - >max_preview lines: send max_preview lines + paste URL notice
 *
 * Parameters:
 *   sptr          - sender client
 *   to            - routing target (delivery recipient).  For DM echo this
 *                   is sptr; for DM delivery this equals acptr.
 *   acptr         - DM wire target (used for %C in NOTICE/PRIVMSG format).
 *                   Pass NULL for channel cases.  When `to == sptr` (DM
 *                   echo) this MUST point to the actual recipient so the
 *                   wire reads ":sptr ... acptr ..." and the sender's
 *                   client routes the line to the correct query window.
 *   msgid         - base msgid for retrieval (carried only on the first
 *                   preview line per multiline spec)
 *   messages      - linked list of message lines
 *   total_lines   - total line count
 *   is_channel    - 1 if channel, 0 if DM
 *   chptr         - channel pointer (NULL for DMs)
 *   paste_url_str - pre-computed paste URL (NULL if unavailable)
 *
 * Truncation NOTICE source: &me for channels (system signal in the
 * channel buffer), sptr for DMs (so it routes to the conversation
 * window rather than status).  Truncation gets its own freshly-generated
 * msgid; sharing the batch msgid would conflate system signal with user
 * content for history/replay.
 */
void send_multiline_fallback(struct Client *sptr, struct Client *to,
                              struct Client *acptr, const char *msgid,
                              struct SLink *messages, int total_lines,
                              int is_channel, struct Channel *chptr,
                              const char *paste_url_str,
                              const char *client_tags, int is_notice)
{
  struct SLink *lp;
  int lines_to_send;
  int send_notice;
  int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
  const char *msg_str = is_notice ? MSG_NOTICE : MSG_PRIVATE;

  /* Configurable preview budget */
  if (total_lines <= max_preview) {
    lines_to_send = total_lines;
    send_notice = 0;
  } else {
    lines_to_send = max_preview;
    send_notice = 1;
  }

  /* Send preview lines with server tags (time, msgid) for IRCv3 compliance.
   * Per multiline spec, only the FIRST fallback line carries msgid to avoid
   * duplicate history entries in receiving clients.
   * Client-only tags from BATCH open are included on each fallback line. */
  int sent = 0;
  int msgid_sent = 0;
  int use_ctags = (client_tags && *client_tags && CapActive(to, CAP_MSGTAGS));
  for (lp = messages; lp && sent < lines_to_send; lp = lp->next, sent++) {
    char *text = lp->value.cp + 1;
    if (*text == '\0')
      continue;  /* Skip blank lines in fallback per IRCv3 spec */
    const char *line_msgid = (!msgid_sent) ? msgid : NULL;
    msgid_sent = 1;
    if (use_ctags) {
      if (line_msgid)
        sendcmdto_set_client_msgid(line_msgid);
      if (is_channel)
        sendcmdto_one_client_tags(sptr, msg_str, to, client_tags,
                                  "%H :%s", chptr, text);
      else
        sendcmdto_one_client_tags(sptr, msg_str, to, client_tags,
                                  "%C :%s", acptr, text);
      if (line_msgid)
        sendcmdto_set_client_msgid(NULL);
    } else {
      if (is_notice) {
        if (is_channel)
          sendcmdto_one_tags_ext(sptr, CMD_NOTICE, to, line_msgid, "%H :%s", chptr, text);
        else
          sendcmdto_one_tags_ext(sptr, CMD_NOTICE, to, line_msgid, "%C :%s", acptr, text);
      } else {
        if (is_channel)
          sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, to, line_msgid, "%H :%s", chptr, text);
        else
          sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, to, line_msgid, "%C :%s", acptr, text);
      }
    }
  }

  if (!send_notice)
    return;

  int remaining = total_lines - sent;

  /* Truncation NOTICE: fresh msgid (system-generated, not part of user
   * content), tag-aware send so it carries msgid/time.  Source is &me
   * for channel (notice goes to channel buffer) and sptr for DM (so the
   * sender's/recipient's client routes it to the conversation window). */
  char trunc_msgid[S2S_MSGID_BUFSIZE];
  generate_msgid(trunc_msgid, sizeof(trunc_msgid));

  if (paste_url_str) {
    /* URL goes outside the bracketed count so clients that auto-linkify
     * don't grab the trailing ']' (msgids embed P10 base64 which uses
     * '[' and ']' — linkifiers can't tell URL-bracket from frame-bracket). */
    if (is_channel) {
      sendcmdto_one_tags_ext(&me, CMD_NOTICE, to, trunc_msgid,
                             "%H :[%d more lines] %s",
                             chptr, remaining, paste_url_str);
    } else {
      sendcmdto_one_tags_ext(sptr, CMD_NOTICE, to, trunc_msgid,
                             "%C :[%d more lines] %s",
                             acptr, remaining, paste_url_str);
    }
  } else {
    if (is_channel) {
      sendcmdto_one_tags_ext(&me, CMD_NOTICE, to, trunc_msgid,
                             "%H :[%d more lines]",
                             chptr, remaining);
    } else {
      sendcmdto_one_tags_ext(sptr, CMD_NOTICE, to, trunc_msgid,
                             "%C :[%d more lines]",
                             acptr, remaining);
    }
  }
}

/*
 * ms_batch - server message handler
 *
 * parv[0] = sender prefix (server numeric)
 * parv[1] = +batchid type [params] OR -batchid
 *
 * Handle BATCH from other servers (P10: BT token).
 * Format: SERVER BT +batchid netjoin server1 server2
 *         SERVER BT -batchid
 */
int ms_batch(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* batch_ref;
  char* batch_type = NULL;
  int is_start;
  struct Client* acptr;
  struct DLink* lp;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Only servers can send S2S BATCH */
  if (!IsServer(sptr))
    return protocol_violation(sptr, "Non-server trying to send S2S BATCH");

  if (parc < 2 || EmptyString(parv[1]))
    return 0;

  batch_ref = parv[1];

  /* Determine if this is batch start (+) or end (-) */
  if (batch_ref[0] == '+') {
    is_start = 1;
    batch_ref++;  /* Skip the + prefix */
    if (parc >= 3 && !EmptyString(parv[2]))
      batch_type = parv[2];
    else
      return 0;  /* Start batch requires type */
  }
  else if (batch_ref[0] == '-') {
    is_start = 0;
    batch_ref++;  /* Skip the - prefix */
  }
  else {
    return 0;  /* Invalid format */
  }

  if (EmptyString(batch_ref))
    return 0;

  /* Store batch state for this server connection */
  if (is_start) {
    ircd_strncpy(cli_s2s_batch_id(cptr), batch_ref,
                 sizeof(con_s2s_batch_id(cli_connect(cptr))) - 1);
    cli_s2s_batch_id(cptr)[sizeof(con_s2s_batch_id(cli_connect(cptr))) - 1] = '\0';
    if (batch_type) {
      ircd_strncpy(cli_s2s_batch_type(cptr), batch_type,
                   sizeof(con_s2s_batch_type(cli_connect(cptr))) - 1);
      cli_s2s_batch_type(cptr)[sizeof(con_s2s_batch_type(cli_connect(cptr))) - 1] = '\0';
    }
  }
  else {
    /* Clear batch state on end */
    cli_s2s_batch_id(cptr)[0] = '\0';
    cli_s2s_batch_type(cptr)[0] = '\0';
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone_v3(sptr, CMD_BATCH_CMD, cptr, "%s%s%s%s",
                        is_start ? "+" : "-",
                        batch_ref,
                        batch_type ? " " : "",
                        batch_type ? batch_type : "");

  /* For netjoin/netsplit batches, notify local clients with batch capability.
   * Uses send_batch_perconn to respect per-connection caps in bouncer
   * sessions — CapActive() checks the union, which would incorrectly
   * deliver BATCH to connections that never negotiated it. */
  if (batch_type && (strcmp(batch_type, "netjoin") == 0 ||
                     strcmp(batch_type, "netsplit") == 0)) {
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (!MyConnect(acptr) || !IsUser(acptr))
        continue;
      if (!CapActive(acptr, CAP_BATCH))
        continue;

      if (is_start) {
        if (parc >= 5 && !EmptyString(parv[3]) && !EmptyString(parv[4])) {
          send_batch_perconn(acptr, "+%s %s %s %s",
                             batch_ref, batch_type, parv[3], parv[4]);
        }
        else if (parc >= 4 && !EmptyString(parv[3])) {
          send_batch_perconn(acptr, "+%s %s %s",
                             batch_ref, batch_type, parv[3]);
        }
        else {
          send_batch_perconn(acptr, "+%s %s",
                             batch_ref, batch_type);
        }
      }
      else {
        send_batch_perconn(acptr, "-%s", batch_ref);
      }
    }
  }

  return 0;
}

/*
 * Helper functions for multiline batch handling
 */

/** Clear the multiline batch state for a connection */
static void
clear_multiline_batch(struct Connection *con)
{
  struct SLink *lp, *next;

  /* Free all stored messages */
  for (lp = con_ml_messages(con); lp; lp = next) {
    next = lp->next;
    if (lp->value.cp)
      MyFree(lp->value.cp);
    free_link(lp);
  }

  /* Apply accumulated lag from the batch with a configurable discount.
   * Per IRCv3 multiline spec, we should be lenient for batched messages,
   * but we can't ignore lag entirely or malicious clients could abuse
   * multiline batches to flood channels (recipients who don't support
   * multiline still receive each line as a separate PRIVMSG).
   *
   * MULTILINE_LAG_DISCOUNT controls what percentage of lag is applied for DMs:
   *   100 = full lag (no benefit to multiline, like regular messages)
   *   50  = 50% lag (default - rewards multiline while preventing abuse)
   *   0   = no lag (dangerous - allows unlimited multiline flooding)
   *
   * MULTILINE_CHANNEL_LAG_DISCOUNT is used for channel messages (typically
   * higher than DM discount since channels affect more users).
   *
   * MULTILINE_RECIPIENT_DISCOUNT: when enabled, halve the lag discount
   * percentage unconditionally for any multiline batch.  Truncation
   * fallback is bounded (capped at FEAT_MULTILINE_LEGACY_MAX_LINES) so
   * it doesn't flood; +M opt-in expansion is the recipient's choice
   * and shouldn't penalise the sender; cross-server alias mirror is
   * the sender's own bouncer setup and shouldn't penalise them either.
   * The base discount (50% DM / 75% channel) stays in place as the
   * anti-flood floor; halving rewards multiline use without worrying
   * about which path each recipient ended up on.
   */
  if (con_ml_lag_accum(con) > 0) {
    int discount;
    int discounted_lag;

    /* Use different discount for channels vs DMs */
    if (con_ml_target(con)[0] && IsChannelName(con_ml_target(con)))
      discount = feature_int(FEAT_MULTILINE_CHANNEL_LAG_DISCOUNT);
    else
      discount = feature_int(FEAT_MULTILINE_LAG_DISCOUNT);

    if (feature_bool(FEAT_MULTILINE_RECIPIENT_DISCOUNT))
      discount = discount / 2;

    /* Clamp discount to valid range */
    if (discount < 0)
      discount = 0;
    else if (discount > 100)
      discount = 100;

    discounted_lag = (con_ml_lag_accum(con) * discount) / 100;
    if (discounted_lag < 2 && discount > 0)
      discounted_lag = 2;  /* Minimum one message worth (unless fully disabled) */
    con_since(con) += discounted_lag;
  }
  con_ml_lag_accum(con) = 0;

  con_ml_batch_id(con)[0] = '\0';
  con_ml_target(con)[0] = '\0';
  con_ml_label(con)[0] = '\0';
  con_ml_client_tags(con)[0] = '\0';
  con_ml_messages(con) = NULL;
  con_ml_msg_count(con) = 0;
  con_ml_total_bytes(con) = 0;
  con_ml_batch_start(con) = 0;
  con_ml_is_notice(con) = -1;
}

/** Check for and handle client batch timeout.
 * Called periodically from check_pings().
 * @param[in] cptr Client to check.
 * @return 1 if batch was timed out, 0 otherwise.
 */
int
check_client_batch_timeout(struct Client *cptr)
{
  struct Connection *con;
  time_t timeout;

  if (!MyConnect(cptr))
    return 0;

  con = cli_connect(cptr);
  if (!con_ml_batch_id(con)[0])
    return 0; /* No active batch */

  timeout = feature_int(FEAT_CLIENT_BATCH_TIMEOUT);
  if (timeout <= 0)
    return 0; /* Timeout disabled */

  if (CurrentTime - con_ml_batch_start(con) < timeout)
    return 0; /* Not timed out yet */

  /* Batch has timed out - send FAIL and clear */
  send_fail(cptr, "BATCH", "TIMEOUT", con_ml_batch_id(con),
            "Batch timed out");
  clear_multiline_batch(con);
  return 1;
}

/** Add a message to the multiline batch.
 * @param[in] sptr Client sending the batch line.
 * @param[in] target PRIVMSG/NOTICE target from this line.
 * @param[in] text Message text (may be NULL for blank lines).
 * @param[in] concat Non-zero if draft/multiline-concat tag was present.
 * @param[in] is_notice Non-zero if this is a NOTICE (vs PRIVMSG).
 * @return 0 on success, -1 on error (batch cleared).
 */
int
multiline_add_message(struct Client *sptr, const char *target,
                      const char *text, int concat, int is_notice)
{
  struct Connection *con = cli_connect(sptr);
  struct SLink *lp;
  int len;
  char *msgcopy;

  if (!con_ml_batch_id(con)[0])
    return 0;  /* No active batch */

  /* IRCv3 multiline spec: target must match batch target */
  if (target && con_ml_target(con)[0] &&
      ircd_strcmp(target, con_ml_target(con)) != 0) {
    send_fail_ctx(sptr, "BATCH", "MULTILINE_INVALID_TARGET",
                  "Invalid multiline target",
                  "%s %s", con_ml_target(con), target);
    clear_multiline_batch(con);
    return -1;
  }

  /* IRCv3 multiline spec: batch must be all-PRIVMSG or all-NOTICE, not mixed.
   * Lock command type on first message, reject mismatches after. */
  if (con_ml_is_notice(con) < 0) {
    con_ml_is_notice(con) = is_notice ? 1 : 0;
  } else if ((con_ml_is_notice(con) != 0) != (is_notice != 0)) {
    send_fail(sptr, "BATCH", "MULTILINE_INVALID", con_ml_batch_id(con),
              "Cannot mix PRIVMSG and NOTICE in multiline batch");
    clear_multiline_batch(con);
    return -1;
  }

  len = (text && *text) ? strlen(text) : 0;

  /* IRCv3 multiline spec: concat flag on blank line is invalid */
  if (concat && len == 0) {
    send_fail(sptr, "BATCH", "MULTILINE_INVALID",
              con_ml_batch_id(con),
              "Cannot use concat tag on blank line");
    clear_multiline_batch(con);
    return -1;
  }

  /* Check limits — spec requires the numeric limit as the context parameter */
  {
    int max_lines = feature_int(FEAT_MULTILINE_MAX_LINES);
    if (con_ml_msg_count(con) >= max_lines) {
      send_fail_ctx(sptr, "BATCH", "MULTILINE_MAX_LINES",
                    "Too many lines in multiline batch", "%d", max_lines);
      clear_multiline_batch(con);
      return -1;
    }
  }

  {
    int max_bytes = feature_int(FEAT_MULTILINE_MAX_BYTES);
    if (con_ml_total_bytes(con) + len > max_bytes) {
      send_fail_ctx(sptr, "BATCH", "MULTILINE_MAX_BYTES",
                    "Multiline batch max-bytes exceeded", "%d", max_bytes);
      clear_multiline_batch(con);
      return -1;
    }
  }

  /* Store the message with concat flag encoded in high bit of first char */
  msgcopy = (char *)MyMalloc(len + 2);
  msgcopy[0] = concat ? 1 : 0;  /* Flag byte */
  strcpy(msgcopy + 1, text);

  lp = make_link();
  lp->value.cp = msgcopy;
  lp->next = NULL;

  /* Append to end of list */
  if (!con_ml_messages(con)) {
    con_ml_messages(con) = lp;
  } else {
    struct SLink *tail;
    for (tail = con_ml_messages(con); tail->next; tail = tail->next)
      ;
    tail->next = lp;
  }

  con_ml_msg_count(con)++;
  con_ml_total_bytes(con) += len;

  return 0;
}

/** Helper to get user's displayed host */
static const char *
get_displayed_host(struct Client *sptr)
{
  if (IsHiddenHost(sptr))
    return cli_user(sptr)->host;
  return cli_user(sptr)->realhost;
}

/** Helper to format ISO 8601 timestamp for server-time tag */
static void
format_time_tag(char *buf, size_t buflen)
{
  struct timeval tv;
  struct tm tm;

  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);
  snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           tv.tv_usec / 1000);
}

/** Process and deliver a completed multiline batch */
static int
process_multiline_batch(struct Client *sptr)
{
  struct Connection *con = cli_connect(sptr);
  struct Channel *chptr = NULL;
  struct Client *acptr = NULL;
  struct SLink *lp;
  struct Membership *member;
  int is_channel;
  int first;
  char batch_base_msgid[64];  /* Base msgid for entire batch */
  int fallback_count = 0;  /* Track recipients who got truncated fallback */
  int is_notice = (con_ml_is_notice(con) == 1);
  const char *cmd_str = is_notice ? "NOTICE" : "PRIVMSG";

  if (!con_ml_batch_id(con)[0])
    return 0;  /* No active batch */

  if (!con_ml_messages(con)) {
    clear_multiline_batch(con);
    return 0;  /* Empty batch */
  }

  /* IRCv3 multiline spec: reject batches consisting entirely of blank lines */
  {
    int has_content = 0;
    for (lp = con_ml_messages(con); lp; lp = lp->next) {
      char *text = lp->value.cp + 1;  /* skip concat flag byte */
      if (text[0] != '\0') { has_content = 1; break; }
    }
    if (!has_content) {
      send_fail(sptr, "BATCH", "MULTILINE_INVALID", con_ml_batch_id(con),
                "Batch consists entirely of blank lines");
      clear_multiline_batch(con);
      return 0;
    }
  }

  is_channel = IsChannelName(con_ml_target(con));

  /* Validate target */
  if (is_channel) {
    chptr = FindChannel(con_ml_target(con));
    if (!chptr) {
      send_reply(sptr, ERR_NOSUCHCHANNEL, con_ml_target(con));
      clear_multiline_batch(con);
      return 0;
    }
    /* Check if user can send to channel */
    member = find_member_link(chptr, sptr);
    if (!member && (chptr->mode.mode & MODE_NOPRIVMSGS)) {
      send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
      clear_multiline_batch(con);
      return 0;
    }
  } else {
    acptr = FindUser(con_ml_target(con));
    if (!acptr) {
      send_reply(sptr, ERR_NOSUCHNICK, con_ml_target(con));
      clear_multiline_batch(con);
      return 0;
    }
  }

  /* Generate ONE base msgid for the entire multiline batch.
   * Each line will get this base msgid with a sequence suffix: base:00, base:01, etc.
   * This ensures all lines can be retrieved together via CHATHISTORY by msgid prefix.
   */
  generate_msgid(batch_base_msgid, sizeof(batch_base_msgid));

  /* Capture time ONCE for consistent timestamps across all recipients */
  char batch_timebuf[32];
  uint64_t batch_time_ms;
  {
    struct timeval btv;
    gettimeofday(&btv, NULL);
    batch_time_ms = (uint64_t)btv.tv_sec * 1000 + btv.tv_usec / 1000;
  }
  format_time_tag(batch_timebuf, sizeof(batch_timebuf));

  /* Set global time override so all send.c tag formatters use the same
   * timestamp as the batch opener. Cleared at the end of this function. */
  sendcmdto_set_client_time(batch_timebuf);

  /* Pre-compute paste URL once for all fallback paths.
   * The paste secret is captured for later atomic storage in history_store_multiline.
   */
  char batch_paste_secret[12] = "";
  const char *batch_paste_url = NULL;
  static char batch_paste_url_buf[256];
  {
    const char *url = generate_paste_url(batch_base_msgid,
                                         batch_paste_secret, sizeof(batch_paste_secret));
    if (url) {
      ircd_strncpy(batch_paste_url_buf, url, sizeof(batch_paste_url_buf) - 1);
      batch_paste_url = batch_paste_url_buf;
    }
  }

  /* Deliver to recipients */
  if (is_channel) {
    /* For each member of the channel */
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *to = member->user;

      if (to == sptr)
        continue;  /* Skip sender (handle echo-message separately) */

      if (!MyConnect(to))
        continue;  /* Skip remote users - handled by S2S relay */

      /* With aliases, each connection is a separate Client with its own caps.
       * CapActive checks the client's own capabilities directly. */
      if (CapActive(to, CAP_DRAFT_MULTILINE) && CapActive(to, CAP_BATCH)) {
        /* Send as batch to supporting client */
        char batchid[16];
        int use_tags = CapActive(to, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        /* Per IRCv3 multiline spec, server tags (time, msgid, account) and
         * client-only tags go on the BATCH + opener, not inner messages. */
        {
          char tagbuf[512];
          int taglen = format_batch_open_tags(tagbuf, sizeof(tagbuf), to, sptr,
                         batch_timebuf, batch_base_msgid, NULL,
                         con_ml_client_tags(con));
          /* User-source BATCH opener per IRCv3 multiline spec. */
          if (taglen)
            sendrawto_one(to, "%s:%s!%s@%s BATCH +%s draft/multiline %s",
                          tagbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), batchid, chptr->chname);
          else
            sendcmdto_one(sptr, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                          batchid, chptr->chname);
        }

        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (concat) {
            sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cmd_str, chptr->chname, text);
          } else {
            sendrawto_one(to, "@batch=%s :%s!%s@%s %s %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cmd_str, chptr->chname, text);
          }
        }

        sendcmdto_one(sptr, CMD_BATCH_CMD, to, "-%s", batchid);
      } else {
        /* Fallback: send as individual messages to primary.  If
         * recipient has +M (multiline expand), send full expansion;
         * otherwise use bounded preview + truncation NOTICE.
         * fallback_count ticks for the sender's WARN message either
         * way (recipient saw a fallback experience). */
        int total_lines = con_ml_msg_count(con);

        fallback_count++;  /* Count for sender WARN notification */

        if (HasFlag(to, FLAG_MULTILINE_EXPAND)) {
          /* User opted in with +M: send all lines without truncation. */
          for (lp = con_ml_messages(con); lp; lp = lp->next) {
            char *text = lp->value.cp + 1;
            if (is_notice)
              sendcmdto_one(sptr, CMD_NOTICE, to, "%H :%s", chptr, text);
            else
              sendcmdto_one(sptr, CMD_PRIVATE, to, "%H :%s", chptr, text);
          }
        } else {
          /* Preview + paste URL fallback for legacy clients */
          send_multiline_fallback(sptr, to, NULL, batch_base_msgid,
                                   con_ml_messages(con), total_lines, 1, chptr,
                                   batch_paste_url, con_ml_client_tags(con), is_notice);
        }
      }

    }

    /* Echo to sender if they have echo-message capability.
     *
     * With aliases, each connection is a separate Client with its own channel
     * membership and capabilities. Aliases receive messages through normal
     * channel delivery above. PM echo for aliases is handled by
     * bounce_echo_pm_to_session.
     *
     * Echo protection: skip echo only when it literally won't fit in
     * the remaining sendQ space.  Since echo size equals the user's
     * own input size, this is predictable and almost always delivers.
     */
    {
      int need_echo = feature_bool(FEAT_CAP_echo_message) && CapActive(sptr, CAP_ECHOMSG);
      int skip_echo = 0;

      /* SendQ protection: skip echo only if it literally won't fit */
      if (MyConnect(sptr)) {
        unsigned int echo_bytes = con_ml_total_bytes(con);
        unsigned int current_sendq = MsgQLength(&(cli_sendQ(sptr)));
        unsigned int sendq_limit = get_sendq(sptr);
        if (current_sendq + echo_bytes > sendq_limit)
          skip_echo = 1;
      }

      if (!skip_echo && need_echo) {
        if (CapActive(sptr, CAP_DRAFT_MULTILINE) && CapActive(sptr, CAP_BATCH)) {
          /* Sender has multiline - send batch echo */
          char batchid[16];
          int use_tags = CapActive(sptr, CAP_MSGTAGS);
          int use_label = con_ml_label(con)[0] && CapActive(sptr, CAP_LABELEDRESP);

          ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                        NumNick(sptr), con_batch_seq(con)++);

          /* Per IRCv3 multiline spec, server tags (time, msgid, account) and
           * client-only tags go on the BATCH + opener. Label included for echo. */
          {
            char tagbuf[512];
            int taglen = format_batch_open_tags(tagbuf, sizeof(tagbuf), sptr, sptr,
                           batch_timebuf, batch_base_msgid,
                           con_ml_label(con), con_ml_client_tags(con));
            /* User-source BATCH opener per IRCv3 multiline spec. */
            if (taglen)
              sendrawto_one(sptr, "%s:%s!%s@%s BATCH +%s draft/multiline %s",
                            tagbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), batchid, chptr->chname);
            else
              sendcmdto_one(sptr, CMD_BATCH_CMD, sptr, "+%s draft/multiline %s",
                            batchid, chptr->chname);
          }

          for (lp = con_ml_messages(con); lp; lp = lp->next) {
            int concat = lp->value.cp[0];
            char *text = lp->value.cp + 1;

            if (concat) {
              sendrawto_one(sptr, "@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), cmd_str, chptr->chname, text);
            } else {
              sendrawto_one(sptr, "@batch=%s :%s!%s@%s %s %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), cmd_str, chptr->chname, text);
            }
          }

          sendcmdto_one(sptr, CMD_BATCH_CMD, sptr, "-%s", batchid);
        } else {
          /* Sender doesn't have multiline - preview + truncation fallback */
          send_multiline_fallback(sptr, sptr, NULL, batch_base_msgid,
                                   con_ml_messages(con), con_ml_msg_count(con),
                                   1, chptr, batch_paste_url, con_ml_client_tags(con), is_notice);
        }
      }
    }
  } else {
    /* Private message to user.
     *
     * Delivery model: the originating-server m_batch path is responsible
     * for delivering a multiline DM to every local recipient that needs
     * to see it.  That set is:
     *
     *   1. The primary recipient (acptr) if local.
     *   2. Each local alias of acptr's session — bouncer "forward".
     *   3. Each local member of sptr's session, except sptr — bouncer
     *      "echo" (so the sender's other connections see the outgoing
     *      DM in their conversation window).
     *   4. sptr itself if echo-message is negotiated.
     *
     * For each of those targets, deliver_multiline_dm_to_one() emits
     * either a proper draft/multiline BATCH wrapper (preserving concat
     * semantics) or, for capability-poor targets, the legacy preview
     * + truncation fallback.  Wire target controls what appears as the
     * inner PRIVMSG/NOTICE target — the alias's own nick for forward,
     * the original recipient's nick for echo so the sender's-side
     * clients route the lines into the conversation window.
     *
     * Remote recipients (acptr or its aliases on another server) and
     * remote sender-session members are NOT handled here — they are
     * delivered by the S2S relay block below (CMD_MULTILINE / fallback
     * PRIVMSGs) and, for aliases, by the cross-server bouncer transfer
     * (BX E) which is single-line today.  Cross-server multiline alias
     * mirroring is future work.
     */
    fallback_count += deliver_multiline_dm_to_one(sptr, acptr, acptr,
                                batch_base_msgid, batch_timebuf,
                                batch_paste_url, is_notice, cmd_str,
                                0 /* no label preservation for delivery */);

    /* Forward to acptr's session aliases.  Skip sptr itself: when sender
     * and recipient are aliases of the same session, primary delivery
     * already covers acptr, and forwarding to sptr would echo the
     * sender's own message back to itself.
     *
     * Local aliases: proper batch (or fallback) via deliver_multiline_dm_to_one.
     *
     * Remote aliases: the wire target IS the alias (forwards present the
     * alias as a normal recipient), so we can reuse the existing
     * CMD_MULTILINE S2S relay machinery for multiline-capable peers —
     * the alias's server reconstructs the BATCH for the local alias via
     * deliver_s2s_multiline_batch().  For legacy peers we fall back to
     * per-line PRIVMSG/NOTICE; the receiving legacy server has no
     * multiline state, so each line is delivered as a regular PM. */
    if (IsAccount(acptr) && !IsBouncerAlias(acptr)) {
      struct BouncerSession *acptr_sess = bounce_get_session(acptr);
      if (acptr_sess && acptr_sess->hs_alias_count > 0) {
        int i;
        for (i = 0; i < acptr_sess->hs_alias_count; i++) {
          struct Client *alias = findNUser(acptr_sess->hs_aliases[i].ba_numeric);
          if (!alias || alias == acptr || alias == sptr || !IsBouncerAlias(alias))
            continue;
          if (MyConnect(alias)) {
            fallback_count += deliver_multiline_dm_to_one(sptr, alias, alias,
                                        batch_base_msgid, batch_timebuf,
                                        batch_paste_url, is_notice, cmd_str,
                                        0);
          } else {
            struct Client *alias_server = cli_from(alias);
            if (IsServer(alias_server) && IsMultiline(alias_server)) {
              /* Multiline-capable alias server: relay the full batch
               * via CMD_MULTILINE so the remote alias sees a proper
               * draft/multiline BATCH wrapper.  Per-alias batch_id keeps
               * concurrent forwards from colliding on the receiver. */
              char fwd_batch_id[16];
              int first = 1;
              ircd_snprintf(0, fwd_batch_id, sizeof(fwd_batch_id), "%s%lu%d",
                            cli_yxx(sptr), (unsigned long)CurrentTime, i);
              for (lp = con_ml_messages(con); lp; lp = lp->next) {
                int concat = lp->value.cp[0];
                char *text = lp->value.cp + 1;
                if (first) {
                  const char *ctags = con_ml_client_tags(con);
                  sendcmdto_set_s2s_tags(batch_time_ms, batch_base_msgid);
                  if (ctags && *ctags)
                    sendcmdto_one(sptr, CMD_MULTILINE, alias_server,
                                  "+%s @%s %s :%s",
                                  fwd_batch_id, ctags, cli_name(alias), text);
                  else
                    sendcmdto_one(sptr, CMD_MULTILINE, alias_server,
                                  "+%s %s :%s",
                                  fwd_batch_id, cli_name(alias), text);
                  first = 0;
                } else if (concat) {
                  sendcmdto_one(sptr, CMD_MULTILINE, alias_server,
                                "c%s %s :%s",
                                fwd_batch_id, cli_name(alias), text);
                } else {
                  sendcmdto_one(sptr, CMD_MULTILINE, alias_server,
                                "%s %s :%s",
                                fwd_batch_id, cli_name(alias), text);
                }
              }
              sendcmdto_one(sptr, CMD_MULTILINE, alias_server, "-%s %s :%s",
                            fwd_batch_id, cli_name(alias),
                            batch_paste_url ? batch_paste_url : "");
            } else {
              /* Legacy alias server: per-line PRIVMSG/NOTICE.  Receiver
               * has no multiline state — delivers each line as a regular
               * PM to the local alias. */
              int alias_first = 1;
              for (lp = con_ml_messages(con); lp; lp = lp->next) {
                char *text = lp->value.cp + 1;
                if (*text == '\0')
                  continue;
                const char *line_msgid = alias_first ? batch_base_msgid : NULL;
                if (is_notice)
                  sendcmdto_one_tags_ext(sptr, CMD_NOTICE, alias, line_msgid,
                                         "%C :%s", alias, text);
                else
                  sendcmdto_one_tags_ext(sptr, CMD_PRIVATE, alias, line_msgid,
                                         "%C :%s", alias, text);
                alias_first = 0;
              }
            }
          }
        }
      }
    }

    /* Echo to sptr's session members (primary + other aliases),
     * skipping sptr itself and skipping any member that IS acptr (those
     * already received the message via primary delivery — echoing
     * again would duplicate).  Wire target = acptr so the alias's
     * client routes the conversation into the right window.
     *
     * Local members: proper batch via deliver_multiline_dm_to_one.
     * Remote members on multiline-capable servers: BX M batch (the
     * bouncer-aware multiline echo token, see emit_bxm_to_remote_member
     * above and bounce_alias_multiline_echo on the receive side).
     * Remote members on legacy bouncer servers: per-line BX E.  BX E/M
     * "from" is sender_primary per the bouncer-session convention —
     * session messages present canonically as primary regardless of
     * which alias actually sent them. */
    {
      struct Client *sender_primary;
      const char *bx_tok = is_notice ? TOK_NOTICE : TOK_PRIVATE;
      if (IsBouncerAlias(sptr) && cli_user(sptr)
          && cli_user(sptr)->alias_primary)
        sender_primary = cli_user(sptr)->alias_primary;
      else
        sender_primary = sptr;

      if (IsAccount(sender_primary)) {
        struct BouncerSession *sender_sess = bounce_get_session(sender_primary);
        /* Echo to primary if sender is an alias and primary != acptr
         * (avoid double-delivery on self-session DM). */
        if (sender_primary != sptr && sender_primary != acptr) {
          if (MyConnect(sender_primary)) {
            deliver_multiline_dm_to_one(sptr, sender_primary, acptr,
                                        batch_base_msgid, batch_timebuf,
                                        batch_paste_url, is_notice, cmd_str,
                                        0);
          } else if (IsMultiline(cli_from(sender_primary))) {
            char primary_nn[6];
            ircd_snprintf(0, primary_nn, sizeof(primary_nn), "%s%s",
                          NumNick(sender_primary));
            emit_bxm_to_remote_member(sender_primary, primary_nn,
                                      sender_primary, acptr, con,
                                      is_notice, batch_base_msgid,
                                      batch_paste_url,
                                      -1 /* sentinel: not in alias loop */);
          } else {
            char rcpt_nn[6];
            int first_line = 1;
            ircd_snprintf(0, rcpt_nn, sizeof(rcpt_nn), "%s%s",
                          NumNick(sender_primary));
            for (lp = con_ml_messages(con); lp; lp = lp->next) {
              char *text = lp->value.cp + 1;
              if (*text == '\0')
                continue;
              sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, sender_primary,
                  "E %s %s%s %s %s %s :%s",
                  rcpt_nn, NumNick(sender_primary), bx_tok,
                  cli_name(acptr),
                  first_line ? batch_base_msgid : "*", text);
              first_line = 0;
            }
          }
        }
        /* Echo to other aliases. */
        if (sender_sess && sender_sess->hs_alias_count > 0) {
          int i;
          for (i = 0; i < sender_sess->hs_alias_count; i++) {
            struct Client *member =
              findNUser(sender_sess->hs_aliases[i].ba_numeric);
            if (!member || member == sptr || member == acptr
                || !IsBouncerAlias(member))
              continue;
            if (MyConnect(member)) {
              deliver_multiline_dm_to_one(sptr, member, acptr,
                                          batch_base_msgid, batch_timebuf,
                                          batch_paste_url, is_notice, cmd_str,
                                          0);
            } else if (IsMultiline(cli_from(member))) {
              emit_bxm_to_remote_member(member,
                                        sender_sess->hs_aliases[i].ba_numeric,
                                        sender_primary, acptr, con,
                                        is_notice, batch_base_msgid,
                                        batch_paste_url, i);
            } else {
              int first_line = 1;
              for (lp = con_ml_messages(con); lp; lp = lp->next) {
                char *text = lp->value.cp + 1;
                if (*text == '\0')
                  continue;
                sendcmdto_one(&me, CMD_BOUNCER_TRANSFER, member,
                    "E %s %s%s %s %s %s :%s",
                    sender_sess->hs_aliases[i].ba_numeric,
                    NumNick(sender_primary), bx_tok,
                    cli_name(acptr),
                    first_line ? batch_base_msgid : "*", text);
                first_line = 0;
              }
            }
          }
        }
      }
    }

    /* Echo to sender if they have echo-message capability.  Label is
     * preserved here (and only here) so labeled-response correlates
     * with the sender's own request.  SendQ protection: drop echo only
     * if the message literally won't fit. */
    {
      int need_echo = feature_bool(FEAT_CAP_echo_message) && CapActive(sptr, CAP_ECHOMSG);
      int skip_dm_echo = 0;

      if (MyConnect(sptr)) {
        unsigned int echo_bytes = con_ml_total_bytes(con);
        unsigned int current_sendq = MsgQLength(&(cli_sendQ(sptr)));
        unsigned int sendq_limit = get_sendq(sptr);
        if (current_sendq + echo_bytes > sendq_limit)
          skip_dm_echo = 1;
      }

      if (!skip_dm_echo && need_echo) {
        deliver_multiline_dm_to_one(sptr, sptr, acptr,
                                    batch_base_msgid, batch_timebuf,
                                    batch_paste_url, is_notice, cmd_str,
                                    1 /* preserve @label on echo */);
      }
    }

    /* Capability-aware S2S relay for private messages to remote users */
    if (!MyConnect(acptr)) {
      struct Client *target_server = cli_from(acptr);
      char s2s_batch_id[16];
      ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                    cli_yxx(sptr), (unsigned long)CurrentTime);

      if (IsServer(target_server) && IsMultiline(target_server)) {
        /* Send ML tokens to capable server.
         * Set S2S tags on start token for unified msgid delivery. */
        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (first) {
            const char *ctags = con_ml_client_tags(con);
            sendcmdto_set_s2s_tags(batch_time_ms, batch_base_msgid);
            if (ctags[0])
              sendcmdto_one(sptr, CMD_MULTILINE, target_server, "+%s @%s %s :%s",
                            s2s_batch_id, ctags, cli_name(acptr), text);
            else
              sendcmdto_one(sptr, CMD_MULTILINE, target_server, "+%s %s :%s",
                            s2s_batch_id, cli_name(acptr), text);
            first = 0;
          } else if (concat) {
            sendcmdto_one(sptr, CMD_MULTILINE, target_server, "c%s %s :%s",
                          s2s_batch_id, cli_name(acptr), text);
          } else {
            sendcmdto_one(sptr, CMD_MULTILINE, target_server, "%s %s :%s",
                          s2s_batch_id, cli_name(acptr), text);
          }
        }
        sendcmdto_one(sptr, CMD_MULTILINE, target_server, "-%s %s :",
                      s2s_batch_id, cli_name(acptr));
      } else {
        /* Send fallback PRIVMSGs to legacy server.  Wire is BOUNDED
         * by max_preview + 1 NOTICE, so this does not suppress the
         * discount halving — anti-flood semantics stay intact even
         * though the legacy peer's local users see truncated content. */
        int sent = 0;
        int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
        int total_lines = con_ml_msg_count(con);
        int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;

        for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
          char *text = lp->value.cp + 1;
          if (*text == '\0')
            continue;
          if (sent == 0)
            sendcmdto_set_s2s_tags(batch_time_ms, batch_base_msgid);
          if (is_notice)
            sendcmdto_one(sptr, CMD_NOTICE, target_server, "%C :%s", acptr, text);
          else
            sendcmdto_one(sptr, CMD_PRIVATE, target_server, "%C :%s", acptr, text);
          sent++;
        }

        /* DM truncation NOTICE: source = sptr so the notice routes to
         * the conversation window in the recipient's client, not status.
         * Fresh msgid via the tag-aware send so the notice carries
         * msgid/time tags like the preview lines do. */
        if (total_lines > max_preview) {
          int remaining = total_lines - sent;
          char trunc_msgid[S2S_MSGID_BUFSIZE];
          generate_msgid(trunc_msgid, sizeof(trunc_msgid));
          if (batch_paste_url) {
            /* URL outside the bracket so linkifiers don't grab the ']'. */
            sendcmdto_one_tags_ext(sptr, CMD_NOTICE, target_server, trunc_msgid,
                "%C :[%d more lines] %s",
                acptr, remaining, batch_paste_url);
          } else {
            sendcmdto_one_tags_ext(sptr, CMD_NOTICE, target_server, trunc_msgid,
                "%C :[%d more lines - connect to a multiline-capable server to view]",
                acptr, remaining);
          }
        }
      }
    }
  }

  /* Alias source rewriting for S2S relay — match relay_channel_message pattern.
   * Use primary numeric so servers without alias support can resolve the sender.
   * CRITICAL: Must use split delivery when primary is remote — sending primary's
   * numeric toward primary's server is fake direction and gets dropped. */
  struct Client *relay_from = sptr;       /* default: alias (or non-alias sender) */
  struct Client *relay_primary = NULL;
  if (IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
    relay_primary = cli_alias_primary(sptr);
    relay_from = relay_primary;           /* primary numeric for most servers */
  }

  /* Capability-aware S2S relay for channel messages.
   * Send ML tokens to servers that support multiline, fallback PRIVMSGs to legacy.
   * This fixes N² duplication bug: previously we sent fallback per remote user,
   * now we send once per server with appropriate format.
   */
  if (is_channel && chptr) {
    static unsigned long s2s_relay_marker = 0;
    char s2s_batch_id[16];
    int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
    int total_lines = con_ml_msg_count(con);

    ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                  cli_yxx(sptr), (unsigned long)CurrentTime);

    /* Increment marker for this send cycle */
    s2s_relay_marker++;

    /* Iterate channel members to find servers that need the message */
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *server;

      if (MyConnect(member->user))
        continue;  /* Local users already handled above */

      server = cli_from(member->user);
      if (!IsServer(server) || cli_sentalong(server) == s2s_relay_marker)
        continue;  /* Already sent to this server */

      cli_sentalong(server) = s2s_relay_marker;

      /* Split delivery: alias numeric toward primary's server direction
       * to avoid fake direction (primary's server would drop messages
       * appearing to come from its own local client via external link). */
      {
        struct Client *from = relay_from;
        if (relay_primary && cli_from(relay_primary) == server)
          from = sptr;  /* use alias numeric toward primary's server */

      if (IsMultiline(server)) {
        /* Send ML tokens to capable servers.
         * Set S2S tags on the start token so the receiving server can
         * extract the batch's msgid and reuse it (unified delivery). */
        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (first) {
            const char *ctags = con_ml_client_tags(con);
            sendcmdto_set_s2s_tags(batch_time_ms, batch_base_msgid);
            if (ctags[0])
              sendcmdto_one(from, CMD_MULTILINE, server, "+%s @%s %s :%s",
                            s2s_batch_id, ctags, chptr->chname, text);
            else
              sendcmdto_one(from, CMD_MULTILINE, server, "+%s %s :%s",
                            s2s_batch_id, chptr->chname, text);
            first = 0;
          } else if (concat) {
            sendcmdto_one(from, CMD_MULTILINE, server, "c%s %s :%s",
                          s2s_batch_id, chptr->chname, text);
          } else {
            sendcmdto_one(from, CMD_MULTILINE, server, "%s %s :%s",
                          s2s_batch_id, chptr->chname, text);
          }
        }
        sendcmdto_one(from, CMD_MULTILINE, server, "-%s %s :%s",
                      s2s_batch_id, chptr->chname,
                      batch_paste_url ? batch_paste_url : "");
      } else {
        /* Send fallback PRIVMSGs to legacy servers (once per server,
         * not per user).  Wire is BOUNDED by max_preview + 1 NOTICE,
         * so this does not suppress the discount halving — anti-flood
         * semantics stay intact even though the legacy peer's local
         * users see truncated content. */
        int sent = 0;
        int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;

        for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
          char *text = lp->value.cp + 1;
          if (*text == '\0')
            continue;
          if (sent == 0)
            sendcmdto_set_s2s_tags(batch_time_ms, batch_base_msgid);
          if (is_notice)
            sendcmdto_one(from, CMD_NOTICE, server, "%H :%s", chptr, text);
          else
            sendcmdto_one(from, CMD_PRIVATE, server, "%H :%s", chptr, text);
          sent++;
        }

        /* Channel truncation NOTICE: server source (channel system signal).
         * Fresh msgid + tag-aware send so the notice carries msgid/time. */
        if (total_lines > max_preview) {
          int remaining = total_lines - sent;
          char trunc_msgid[S2S_MSGID_BUFSIZE];
          generate_msgid(trunc_msgid, sizeof(trunc_msgid));
          if (batch_paste_url) {
            /* URL outside the bracket so linkifiers don't grab the ']'. */
            sendcmdto_one_tags_ext(&me, CMD_NOTICE, server, trunc_msgid,
                "%H :[%d more lines] %s",
                chptr, remaining, batch_paste_url);
          } else {
            sendcmdto_one_tags_ext(&me, CMD_NOTICE, server, trunc_msgid,
                "%H :[%d more lines - connect to a multiline-capable server to view]",
                chptr, remaining);
          }
        }
      }
      } /* end split delivery block */
    }
  }

  /* Notify sender about fallback if they support standard-replies */
  if (fallback_count > 0 && feature_bool(FEAT_MULTILINE_FALLBACK_NOTIFY)
      && CapActive(sptr, CAP_STANDARDREPLIES)) {
    char desc[128];
    ircd_snprintf(0, desc, sizeof(desc), "Message truncated for %d legacy recipient%s",
                  fallback_count, fallback_count == 1 ? "" : "s");
    /* Use saved label from BATCH +id for labeled-response correlation */
    send_warn_with_label(sptr, "BATCH", "MULTILINE_FALLBACK",
                         is_channel ? chptr->chname : cli_name(acptr), desc,
                         con_ml_label(con)[0] ? con_ml_label(con) : NULL);
  }

  /* Store multiline batch to history with the base msgid.
   * Concatenate all lines (respecting concat flags) into a single message.
   * This allows CHATHISTORY retrieval by the base msgid.
   */
  log_write(LS_SYSTEM, L_INFO, 0, "multiline: history_is_available=%d, target=%s, msgid=%s",
            history_is_available(), is_channel ? chptr->chname : cli_name(acptr),
            batch_base_msgid);
  if (history_is_available()) {
    /* Compute total content size from batch messages for dynamic allocation */
    size_t total_content = 0;
    char *history_content;
    size_t content_len = 0;
    char sender_mask[256];
    char timestamp[HISTORY_TIMESTAMP_LEN];

    for (lp = con_ml_messages(con); lp; lp = lp->next)
      total_content += strlen(lp->value.cp + 1) + 1;  /* text + separator */
    history_content = (char *)MyMalloc(total_content + 1);

    /* Build sender mask nick!user@host */
    ircd_snprintf(0, sender_mask, sizeof(sender_mask), "%s!%s@%s",
                  cli_name(sptr), cli_user(sptr)->username,
                  get_displayed_host(sptr));

    /* Build concatenated content, respecting concat flags */
    for (lp = con_ml_messages(con); lp; lp = lp->next) {
      int concat = lp->value.cp[0];
      char *text = lp->value.cp + 1;
      size_t text_len = strlen(text);

      /* Add Unit Separator (\x1F) if not concat and not first line.
       * Using \x1F instead of \n avoids base64 encoding overhead in P10 federation
       * while still allowing multiline content to be stored and retrieved.
       * HistServ/chathistory converts \x1F back to newlines when displaying.
       */
      if (content_len > 0 && !concat) {
        history_content[content_len++] = '\x1F';
      }

      memcpy(history_content + content_len, text, text_len);
      content_len += text_len;
    }
    history_content[content_len] = '\0';

    /* Get timestamp for storage */
    history_format_timestamp(timestamp, sizeof(timestamp));

    /* Check if channel has +P (no storage) mode or sender has +Y */
    if ((is_channel && (chptr->mode.exmode & EXMODE_NOSTORAGE)) || IsNoStorage(sptr)) {
      /* Skip storage but still clear batch */
    } else {
      /* Store content in unified ml_content + history sentinel atomically */
      int store_result = history_store_multiline(batch_base_msgid, timestamp,
                          is_channel ? chptr->chname : cli_name(acptr),
                          sender_mask,
                          cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                          history_content, content_len,
                          batch_paste_secret[0] ? batch_paste_secret : NULL);
      log_write(LS_SYSTEM, L_INFO, 0, "multiline: history_store_multiline returned %d for msgid=%s target=%s",
                store_result, batch_base_msgid, is_channel ? chptr->chname : cli_name(acptr));
    }
    MyFree(history_content);
  }

  /* Clear the time override set at the start of this function */
  sendcmdto_set_client_time(NULL);

  clear_multiline_batch(con);
  return 0;
}

/*
 * m_batch - client message handler for BATCH command
 *
 * Handles BATCH start/end for multiline messages from clients.
 *
 * parv[0] = sender prefix
 * parv[1] = +batchid type target OR -batchid
 *
 * For draft/multiline:
 *   BATCH +id draft/multiline #channel
 *   BATCH -id
 */

/** Validate batch reference tag per IRCv3 client-batch spec.
 * Must match [a-zA-Z0-9_:-]{1,64}.
 */
static int is_valid_batch_reftag(const char *tag)
{
  const char *p;
  int len = 0;

  if (!tag || !*tag)
    return 0;

  for (p = tag; *p; p++) {
    if (!IsAlnum(*p) && *p != '_' && *p != ':' && *p != '-')
      return 0;
    if (++len > 64)
      return 0;
  }

  return 1;
}

int m_batch(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Connection *con;
  char *batch_ref;
  char *batch_type = NULL;
  char *target = NULL;
  int is_start;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (!IsUser(sptr))
    return 0;

  /* Require draft/multiline capability */
  if (!CapActive(sptr, CAP_DRAFT_MULTILINE))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");

  con = cli_connect(sptr);
  batch_ref = parv[1];

  /* Determine if this is batch start (+) or end (-) */
  if (batch_ref[0] == '+') {
    is_start = 1;
    batch_ref++;  /* Skip the + prefix */

    if (parc < 3 || EmptyString(parv[2]))
      return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");
    batch_type = parv[2];

    if (parc < 4 || EmptyString(parv[3]))
      return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");
    target = parv[3];
  }
  else if (batch_ref[0] == '-') {
    is_start = 0;
    batch_ref++;  /* Skip the - prefix */
  }
  else {
    send_fail(sptr, "BATCH", "INVALID_FORMAT", NULL,
              "Invalid batch format, expected +id or -id");
    return 0;
  }

  if (EmptyString(batch_ref))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");

  /* Validate batch reference tag charset and length */
  if (!is_valid_batch_reftag(batch_ref)) {
    send_fail(sptr, "BATCH", "INVALID_REFTAG", batch_ref,
              "Invalid batch reference tag");
    return 0;
  }

  if (is_start) {
    /* Only support draft/multiline for now */
    if (ircd_strcmp(batch_type, "draft/multiline") != 0) {
      send_fail(sptr, "BATCH", "UNKNOWN_TYPE", batch_type,
                "Unknown batch type");
      return 0;
    }

    /* Batch rate limiting (FEAT_BATCH_RATE_LIMIT) */
    {
      int rate_limit = feature_int(FEAT_BATCH_RATE_LIMIT);
      if (rate_limit > 0) {
        /* Reset counter if we're in a new minute */
        if (CurrentTime - con_batch_minute(con) >= 60) {
          con_batch_minute(con) = CurrentTime;
          con_batch_count(con) = 0;
        }
        /* Check rate limit */
        if (con_batch_count(con) >= rate_limit) {
          send_fail(sptr, "BATCH", "RATE_LIMIT_EXCEEDED", batch_ref,
                    "Too many batches per minute");
          return 0;
        }
        con_batch_count(con)++;
      }
    }

    /* Check if there's already an active batch */
    if (con_ml_batch_id(con)[0]) {
      /* Clear the old batch */
      clear_multiline_batch(con);
    }

    /* Start new multiline batch */
    ircd_strncpy(con_ml_batch_id(con), batch_ref,
                 sizeof(con->con_ml_batch_id) - 1);
    con_ml_batch_id(con)[sizeof(con->con_ml_batch_id) - 1] = '\0';

    ircd_strncpy(con_ml_target(con), target,
                 sizeof(con->con_ml_target) - 1);
    con_ml_target(con)[sizeof(con->con_ml_target) - 1] = '\0';

    con_ml_messages(con) = NULL;
    con_ml_msg_count(con) = 0;
    con_ml_total_bytes(con) = 0;
    con_ml_batch_start(con) = CurrentTime;
    con_ml_lag_accum(con) = 0;  /* Reset lag accumulator for new batch */

    /* Save the label from BATCH +id for labeled-response echo.
     * Suppress generic ACK — the label will be attached to the echo batch
     * when process_multiline_batch() delivers the content. */
    if (cli_label(sptr)[0]) {
      ircd_strncpy(con_ml_label(con), cli_label(sptr),
                   sizeof(con->con_ml_label) - 1);
      con_ml_label(con)[sizeof(con->con_ml_label) - 1] = '\0';
      cli_label_responded(sptr) = 1;  /* Suppress generic ACK */
    } else {
      con_ml_label(con)[0] = '\0';
    }

    /* Save client-only tags from BATCH open for relay to recipients */
    if (cli_client_tags(sptr)[0]) {
      ircd_strncpy(con_ml_client_tags(con), cli_client_tags(sptr),
                   sizeof(con->con_ml_client_tags));
    } else {
      con_ml_client_tags(con)[0] = '\0';
    }
  }
  else {
    /* End batch */
    if (!con_ml_batch_id(con)[0]) {
      send_fail(sptr, "BATCH", "NO_ACTIVE_BATCH", batch_ref,
                "No active batch to end");
      return 0;
    }

    if (strcmp(con_ml_batch_id(con), batch_ref) != 0) {
      send_fail(sptr, "BATCH", "BATCH_ID_MISMATCH", batch_ref,
                "Batch ID does not match active batch");
      return 0;
    }

    /* Process and deliver the batch */
    process_multiline_batch(sptr);
  }

  return 0;
}

/*
 * S2S Multiline batch relay structures and functions
 */

/** Structure to hold a pending multiline batch from S2S */
struct S2SMultilineBatch {
  char batch_id[16];            /**< Batch ID */
  char target[CHANNELLEN + 1];  /**< Target channel or nick */
  struct Client *sender;        /**< Original sender client */
  struct Client *link;          /**< S2S link the batch arrived on (for cleanup on link drop) */
  struct SLink *messages;       /**< Linked list of messages */
  int msg_count;                /**< Number of messages */
  unsigned int total_bytes;     /**< Cumulative bytes accumulated (for network_max enforcement) */
  int is_notice;                /**< 1 if NOTICE batch, 0 if PRIVMSG */
  time_t start_time;            /**< When batch started */
  char paste_url[256];          /**< Forwarded paste URL from originating server */
  char client_tags[512];        /**< Client-only tags from batch opener */
  char msgid[64];               /**< Base msgid from originating server */
  uint64_t time_ms;             /**< Timestamp (ms) from originating server */
};

/** Compute the network-wide maximum multiline byte limit.
 *
 * Walks GlobalClientList collecting every multiline-capable server's
 * advertised ml_max_bytes (set from ML burst at line 1860 below) and
 * returns the maximum, clamped to FEAT_MULTILINE_BUFFER_CEILING.
 *
 * Per s2s-multiline-limits.md plan: send-side enforcement uses local
 * FEAT_MULTILINE_MAX_BYTES (admin's choice); receive-side accepts up
 * to network max so a 4096-byte-policy server can still relay/display
 * a 16384-byte multiline from another server's larger-policy users.
 *
 * Servers with ml_max_bytes == 0 are unknown/legacy — excluded from
 * the max so they can't lower the floor. Floor is local
 * FEAT_MULTILINE_MAX_BYTES (we always accept at least what we'd
 * locally produce).
 */
static unsigned int compute_network_ml_max_bytes(void)
{
  unsigned int max_bytes = (unsigned int)feature_int(FEAT_MULTILINE_MAX_BYTES);
  unsigned int ceiling = (unsigned int)feature_int(FEAT_MULTILINE_BUFFER_CEILING);
  struct Client *srv;

  for (srv = GlobalClientList; srv; srv = cli_next(srv)) {
    if (!IsServer(srv) || IsMe(srv) || !IsMultiline(srv))
      continue;
    if (cli_serv(srv)->ml_max_bytes == 0)
      continue;  /* unknown/legacy — don't lower the floor */
    if (cli_serv(srv)->ml_max_bytes > max_bytes)
      max_bytes = cli_serv(srv)->ml_max_bytes;
  }
  if (ceiling > 0 && max_bytes > ceiling)
    max_bytes = ceiling;
  return max_bytes;
}

/** Compute the network-wide maximum multiline line count. See
 *  compute_network_ml_max_bytes() for rationale. */
static unsigned int compute_network_ml_max_lines(void)
{
  unsigned int max_lines = (unsigned int)feature_int(FEAT_MULTILINE_MAX_LINES);
  unsigned int ceiling = (unsigned int)feature_int(FEAT_MULTILINE_BUFFER_LINES_CEILING);
  struct Client *srv;

  for (srv = GlobalClientList; srv; srv = cli_next(srv)) {
    if (!IsServer(srv) || IsMe(srv) || !IsMultiline(srv))
      continue;
    if (cli_serv(srv)->ml_max_lines == 0)
      continue;
    if (cli_serv(srv)->ml_max_lines > max_lines)
      max_lines = cli_serv(srv)->ml_max_lines;
  }
  if (ceiling > 0 && max_lines > ceiling)
    max_lines = ceiling;
  return max_lines;
}

/** Global array of pending S2S multiline batches (indexed by server connection) */
static struct S2SMultilineBatch *s2s_ml_batches[MAXCONNECTIONS];

/** Find an S2S multiline batch by batch ID */
static struct S2SMultilineBatch *
find_s2s_multiline_batch(const char *batch_id)
{
  int i;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_ml_batches[i] && strcmp(s2s_ml_batches[i]->batch_id, batch_id) == 0)
      return s2s_ml_batches[i];
  }
  return NULL;
}

/** Create a new S2S multiline batch.
 * @param[in] link The directly-connected S2S link cptr the batch
 *                 arrived on.  Recorded so we can free the entry on
 *                 link drop (see s2s_multiline_cleanup_link).
 */
static struct S2SMultilineBatch *
create_s2s_multiline_batch(const char *batch_id, const char *target,
                           struct Client *sender, struct Client *link,
                           const char *client_tags,
                           const char *msgid, uint64_t time_ms)
{
  int i;
  struct S2SMultilineBatch *batch;

  /* Find an empty slot */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!s2s_ml_batches[i])
      break;
  }
  if (i >= MAXCONNECTIONS)
    return NULL;  /* No available slot */

  batch = (struct S2SMultilineBatch *)MyMalloc(sizeof(struct S2SMultilineBatch));
  ircd_strncpy(batch->batch_id, batch_id, sizeof(batch->batch_id) - 1);
  batch->batch_id[sizeof(batch->batch_id) - 1] = '\0';
  ircd_strncpy(batch->target, target, sizeof(batch->target) - 1);
  batch->target[sizeof(batch->target) - 1] = '\0';
  batch->sender = sender;
  batch->link = link;
  batch->messages = NULL;
  batch->msg_count = 0;
  batch->total_bytes = 0;
  batch->is_notice = 0;  /* Default PRIVMSG; S2S protocol extension needed for NOTICE */
  batch->start_time = CurrentTime;
  batch->paste_url[0] = '\0';
  if (client_tags && *client_tags)
    ircd_strncpy(batch->client_tags, client_tags, sizeof(batch->client_tags));
  else
    batch->client_tags[0] = '\0';
  /* Capture originating server's msgid and time for unified delivery */
  if (msgid && *msgid)
    ircd_strncpy(batch->msgid, msgid, sizeof(batch->msgid));
  else
    batch->msgid[0] = '\0';
  batch->time_ms = time_ms;

  s2s_ml_batches[i] = batch;
  return batch;
}

static void free_s2s_multiline_batch(struct S2SMultilineBatch *batch);

/** Free any S2S multiline batches buffered against \a link.
 *
 * Called from exit_one_client when a directly-connected server exits,
 * so partially-accumulated batches whose terminating "-" token will
 * never arrive don't leak their slots in the array.
 */
void s2s_multiline_cleanup_link(struct Client *link)
{
  int i;
  if (!link)
    return;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_ml_batches[i] && s2s_ml_batches[i]->link == link)
      free_s2s_multiline_batch(s2s_ml_batches[i]);
  }
}

/** Free an S2S multiline batch */
static void
free_s2s_multiline_batch(struct S2SMultilineBatch *batch)
{
  struct SLink *lp, *next;
  int i;

  if (!batch)
    return;

  /* Free messages */
  for (lp = batch->messages; lp; lp = next) {
    next = lp->next;
    if (lp->value.cp)
      MyFree(lp->value.cp);
    free_link(lp);
  }

  /* Remove from array */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_ml_batches[i] == batch) {
      s2s_ml_batches[i] = NULL;
      break;
    }
  }

  MyFree(batch);
}

/** Add a message to an S2S multiline batch */
static void
add_s2s_multiline_message(struct S2SMultilineBatch *batch, const char *text, int concat)
{
  struct SLink *lp;
  char *msgcopy;
  int len;
  unsigned int net_max_bytes;
  unsigned int net_max_lines;

  if (!batch || !text)
    return;

  len = strlen(text);

  /* Enforce network-wide multiline limits on inbound S2S batches.
   * Per s2s-multiline-limits.md: receive-side accepts up to network
   * max so smaller-policy servers still display/relay multilines from
   * larger-policy senders. Hard ceiling protects against runaway
   * peers advertising absurd values. */
  net_max_bytes = compute_network_ml_max_bytes();
  net_max_lines = compute_network_ml_max_lines();

  if ((unsigned int)batch->msg_count >= net_max_lines) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "S2S multiline batch %s exceeded network max-lines (%u); "
              "dropping additional message",
              batch->batch_id, net_max_lines);
    return;
  }
  if (batch->total_bytes + (unsigned int)len > net_max_bytes) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "S2S multiline batch %s exceeded network max-bytes "
              "(have %u, would add %d, cap %u); dropping additional message",
              batch->batch_id, batch->total_bytes, len, net_max_bytes);
    return;
  }

  msgcopy = (char *)MyMalloc(len + 2);
  msgcopy[0] = concat ? 1 : 0;  /* Flag byte */
  strcpy(msgcopy + 1, text);

  lp = make_link();
  lp->value.cp = msgcopy;
  lp->next = NULL;

  /* Append to end of list */
  if (!batch->messages) {
    batch->messages = lp;
  } else {
    struct SLink *tail;
    for (tail = batch->messages; tail->next; tail = tail->next)
      ;
    tail->next = lp;
  }

  batch->msg_count++;
  batch->total_bytes += (unsigned int)len;
}

/** Deliver a completed S2S multiline batch to local clients */
static void
deliver_s2s_multiline_batch(struct S2SMultilineBatch *batch, struct Client *cptr)
{
  struct Channel *chptr = NULL;
  struct Client *acptr = NULL;
  struct SLink *lp;
  struct Membership *member;
  int is_channel;
  int first;
  struct Client *sptr = batch->sender;
  char batch_base_msgid[64];  /* Base msgid for entire batch */
  int is_notice = batch->is_notice;
  const char *cmd_str = is_notice ? "NOTICE" : "PRIVMSG";

  if (!batch || !batch->messages || !sptr)
    return;

  /* Reuse the originating server's msgid if available (unified delivery).
   * Only generate a new one if the origin didn't provide one (legacy server). */
  if (batch->msgid[0])
    ircd_strncpy(batch_base_msgid, batch->msgid, sizeof(batch_base_msgid));
  else
    generate_msgid(batch_base_msgid, sizeof(batch_base_msgid));

  /* Pre-compute paste URL for fallback paths.
   * Prefer forwarded URL from originating server, fall back to local generation. */
  char s2s_paste_secret[12] = "";
  const char *s2s_paste_url = NULL;
  static char s2s_paste_url_buf[256];
  if (batch->paste_url[0]) {
    s2s_paste_url = batch->paste_url;
  } else {
    const char *url = generate_paste_url(batch_base_msgid,
                                         s2s_paste_secret, sizeof(s2s_paste_secret));
    if (url) {
      ircd_strncpy(s2s_paste_url_buf, url, sizeof(s2s_paste_url_buf) - 1);
      s2s_paste_url = s2s_paste_url_buf;
    }
  }

  is_channel = IsChannelName(batch->target);

  /* Validate target */
  if (is_channel) {
    chptr = FindChannel(batch->target);
    if (!chptr)
      return;  /* Channel doesn't exist locally */
  } else {
    acptr = FindUser(batch->target);
    if (!acptr || !MyConnect(acptr))
      return;  /* User doesn't exist or isn't local */
  }

  /* Deliver to local recipients */
  if (is_channel) {
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *to = member->user;

      if (!MyConnect(to))
        continue;  /* Only deliver to local users */

      if (to == sptr)
        continue;  /* Skip sender (they already got echo) */

      if (CapActive(to, CAP_DRAFT_MULTILINE) && CapActive(to, CAP_BATCH)) {
        /* Send as batch to supporting clients */
        char batchid[16];
        char timebuf[32];
        int use_tags = CapActive(to, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        /* Per IRCv3 multiline spec, server tags (time, msgid, account) and
         * client-only tags go on the BATCH + opener. */
        {
          char tagbuf[512];
          format_time_tag(timebuf, sizeof(timebuf));
          int taglen = format_batch_open_tags(tagbuf, sizeof(tagbuf), to, sptr,
                         timebuf, batch_base_msgid, NULL,
                         batch->client_tags[0] ? batch->client_tags : NULL);
          /* User-source BATCH opener per IRCv3 multiline spec. */
          if (taglen)
            sendrawto_one(to, "%s:%s!%s@%s BATCH +%s draft/multiline %s",
                          tagbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), batchid, chptr->chname);
          else
            sendcmdto_one(sptr, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                          batchid, chptr->chname);
        }

        for (lp = batch->messages; lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (concat) {
            sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cmd_str, chptr->chname, text);
          } else {
            sendrawto_one(to, "@batch=%s :%s!%s@%s %s %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cmd_str, chptr->chname, text);
          }
        }

        sendcmdto_one(sptr, CMD_BATCH_CMD, to, "-%s", batchid);
      } else {
        /* Graceful fallback for S2S channel delivery */
        send_multiline_fallback(sptr, to, NULL, batch_base_msgid,
                                 batch->messages, batch->msg_count, 1, chptr,
                                 s2s_paste_url,
                                 batch->client_tags[0] ? batch->client_tags : NULL, is_notice);
      }
    }
  } else if (acptr && MyConnect(acptr)) {
    /* Private message to local user */
    if (CapActive(acptr, CAP_DRAFT_MULTILINE) && CapActive(acptr, CAP_BATCH)) {
      char batchid[16];
      char timebuf[32];
      int use_tags = CapActive(acptr, CAP_MSGTAGS);

      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      /* Per IRCv3 multiline spec, server tags (time, msgid, account) and
       * client-only tags go on the BATCH + opener. */
      {
        char tagbuf[512];
        format_time_tag(timebuf, sizeof(timebuf));
        int taglen = format_batch_open_tags(tagbuf, sizeof(tagbuf), acptr, sptr,
                       timebuf, batch_base_msgid, NULL,
                       batch->client_tags[0] ? batch->client_tags : NULL);
        /* User-source BATCH opener per IRCv3 multiline spec. */
        if (taglen)
          sendrawto_one(acptr, "%s:%s!%s@%s BATCH +%s draft/multiline %s",
                        tagbuf, cli_name(sptr), cli_user(sptr)->username,
                        get_displayed_host(sptr), batchid, cli_name(acptr));
        else
          sendcmdto_one(sptr, CMD_BATCH_CMD, acptr, "+%s draft/multiline %s",
                        batchid, cli_name(acptr));
      }

      for (lp = batch->messages; lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        if (concat) {
          sendrawto_one(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s %s %s :%s",
                        batchid, cli_name(sptr), cli_user(sptr)->username,
                        get_displayed_host(sptr), cmd_str, cli_name(acptr), text);
        } else {
          sendrawto_one(acptr, "@batch=%s :%s!%s@%s %s %s :%s",
                        batchid, cli_name(sptr), cli_user(sptr)->username,
                        get_displayed_host(sptr), cmd_str, cli_name(acptr), text);
        }
      }

      sendcmdto_one(sptr, CMD_BATCH_CMD, acptr, "-%s", batchid);
    } else {
      /* Graceful fallback for S2S DM delivery */
      send_multiline_fallback(sptr, acptr, acptr, batch_base_msgid,
                               batch->messages, batch->msg_count, 0, NULL,
                               s2s_paste_url,
                               batch->client_tags[0] ? batch->client_tags : NULL, is_notice);
    }
  }

  /* S2S fallback relay: send fallback PRIVMSGs to legacy servers that have
   * users in the channel but don't support multiline (ms_multiline only
   * propagates ML tokens to IsMultiline servers). */
  if (is_channel && chptr) {
    static unsigned long s2s_fallback_marker = 0;
    int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
    int total_lines = batch->msg_count;

    s2s_fallback_marker++;

    for (member = chptr->members; member; member = member->next_member) {
      struct Client *server;

      if (MyConnect(member->user))
        continue;  /* Local users already handled above */

      server = cli_from(member->user);
      if (!IsServer(server) || cli_sentalong(server) == s2s_fallback_marker)
        continue;  /* Already sent to this server */
      if (server == cli_from(cptr))
        continue;  /* Don't send back toward source */
      if (IsMultiline(server))
        continue;  /* Multiline-capable servers already got ML tokens */

      cli_sentalong(server) = s2s_fallback_marker;

      /* Send fallback PRIVMSGs to legacy server.
       * Set S2S tags on first line for unified msgid. */
      {
        int sent = 0;
        int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;

        for (lp = batch->messages; lp && sent < lines_to_send; lp = lp->next) {
          char *ftext = lp->value.cp + 1;
          if (*ftext == '\0')
            continue;
          if (sent == 0)
            sendcmdto_set_s2s_tags(batch->time_ms, batch_base_msgid);
          if (is_notice)
            sendcmdto_one(sptr, CMD_NOTICE, server, "%H :%s", chptr, ftext);
          else
            sendcmdto_one(sptr, CMD_PRIVATE, server, "%H :%s", chptr, ftext);
          sent++;
        }

        if (total_lines > max_preview) {
          int remaining = total_lines - sent;
          char trunc_msgid[S2S_MSGID_BUFSIZE];
          generate_msgid(trunc_msgid, sizeof(trunc_msgid));
          if (s2s_paste_url) {
            /* URL outside the bracket so linkifiers don't grab the ']'.
             * Server source — truncation is a system signal.  Tag-aware
             * send so the notice carries msgid/time. */
            sendcmdto_one_tags_ext(&me, CMD_NOTICE, server, trunc_msgid,
                "%H :[%d more lines] %s",
                chptr, remaining, s2s_paste_url);
          } else {
            sendcmdto_one_tags_ext(&me, CMD_NOTICE, server, trunc_msgid,
                "%H :[%d more lines - connect to a multiline-capable server to view]",
                chptr, remaining);
          }
        }
      }
    }
  }

  /* Store S2S multiline batch to history.
   * The originating server may have stored it, but we store locally
   * to ensure history is available for local clients.
   */
  if (history_is_available() && sptr) {
    /* Compute total content size from batch messages for dynamic allocation */
    size_t total_content = 0;
    char *history_content;
    size_t content_len = 0;
    char sender_mask[256];
    char timestamp[HISTORY_TIMESTAMP_LEN];

    for (lp = batch->messages; lp; lp = lp->next)
      total_content += strlen(lp->value.cp + 1) + 1;  /* text + separator */
    history_content = (char *)MyMalloc(total_content + 1);

    /* Build sender mask nick!user@host */
    ircd_snprintf(0, sender_mask, sizeof(sender_mask), "%s!%s@%s",
                  cli_name(sptr), cli_user(sptr)->username,
                  get_displayed_host(sptr));

    /* Build concatenated content, respecting concat flags */
    for (lp = batch->messages; lp; lp = lp->next) {
      int concat = lp->value.cp[0];
      char *text = lp->value.cp + 1;
      size_t text_len = strlen(text);

      /* Add Unit Separator (\x1F) if not concat and not first line */
      if (content_len > 0 && !concat) {
        history_content[content_len++] = '\x1F';
      }

      memcpy(history_content + content_len, text, text_len);
      content_len += text_len;
    }
    history_content[content_len] = '\0';

    /* Get timestamp for storage */
    history_format_timestamp(timestamp, sizeof(timestamp));

    /* Check if channel has +P (no storage) mode or sender has +Y */
    if (!((is_channel && (chptr->mode.exmode & EXMODE_NOSTORAGE)) || IsNoStorage(sptr))) {
      /* Store content in unified ml_content + history sentinel atomically */
      history_store_multiline(batch_base_msgid, timestamp,
                              is_channel ? chptr->chname : cli_name(acptr),
                              sender_mask,
                              cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                              history_content, content_len,
                              s2s_paste_secret[0] ? s2s_paste_secret : NULL);
    }
    MyFree(history_content);
  }
}

/*
 * ms_multiline - server message handler for S2S multiline batch
 *
 * P10 Format:
 *   [USER_NUMERIC] ML +batchid target :first_line   (start batch + first line)
 *   [USER_NUMERIC] ML batchid target :line          (normal continuation)
 *   [USER_NUMERIC] ML cbatchid target :line         (concat continuation)
 *   [USER_NUMERIC] ML -batchid target :             (end batch)
 *   [USER_NUMERIC] ML +batchid @tags target :text   (start with client tags)
 *
 * parv[0] = sender prefix
 * parv[1] = batch_id with modifier (+, c, or -)
 * parv[2] = target (or @client-tags on start, then target shifts to parv[3])
 * parv[3] = text (may be empty for end)
 */
int ms_multiline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *batch_ref;
  char *target;
  char *text;
  char *client_tags = NULL;
  int is_start = 0, is_end = 0, is_concat = 0;
  struct S2SMultilineBatch *batch;

  assert(0 != cptr);
  assert(0 != sptr);

  /* ML from server = capability advertisement during BURST.
   * Format: AB ML [max-bytes max-lines]
   * Legacy servers send bare ML with no params (ml_max_bytes=0).
   */
  if (IsServer(sptr)) {
    SetMultiline(sptr);
    if (parc >= 2 && !EmptyString(parv[1]))
      cli_serv(sptr)->ml_max_bytes = atoi(parv[1]);
    if (parc >= 3 && !EmptyString(parv[2]))
      cli_serv(sptr)->ml_max_lines = atoi(parv[2]);
    /* Propagate with parameters */
    sendcmdto_serv_butone_v3(sptr, CMD_MULTILINE, cptr, "%u %u",
                          cli_serv(sptr)->ml_max_bytes,
                          cli_serv(sptr)->ml_max_lines);
    return 0;
  }

  /* Sender must be a user for actual multiline messages */
  if (!IsUser(sptr))
    return protocol_violation(cptr, "Non-user sending MULTILINE");

  if (parc < 3)
    return 0;

  batch_ref = parv[1];

  /* Parse batch modifier */
  if (batch_ref[0] == '+') {
    is_start = 1;
    batch_ref++;
  } else if (batch_ref[0] == '-') {
    is_end = 1;
    batch_ref++;
  } else if (batch_ref[0] == 'c') {
    is_concat = 1;
    batch_ref++;
  }

  if (EmptyString(batch_ref))
    return 0;

  /* Check for client-only tags (@-prefixed param, only on start messages) */
  client_tags = NULL;
  if (is_start && parc >= 4 && parv[2][0] == '@') {
    client_tags = parv[2] + 1;  /* skip @ prefix */
    target = parv[3];
    text = (parc >= 5 && !EmptyString(parv[4])) ? parv[4] : "";
  } else {
    target = parv[2];
    text = (parc >= 4 && !EmptyString(parv[3])) ? parv[3] : "";
  }

  /* Propagate ML tokens only to multiline-capable servers.
   * Legacy servers don't understand the ML token and silently drop it.
   * Fallback PRIVMSGs for legacy servers are sent from
   * deliver_s2s_multiline_batch() when the batch completes.
   * Set S2S tags on start token to carry the originating msgid. */
  {
    struct DLink *lp;
    for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
      struct Client *srv = lp->value.cptr;
      if (srv == cli_from(cptr))
        continue;  /* Don't send back to source */
      if (!IsMultiline(srv))
        continue;  /* Legacy server — handled by fallback at batch end */
      if (is_start) {
        /* Carry the originating server's msgid forward */
        if (cli_s2s_msgid(cptr)[0])
          sendcmdto_set_s2s_tags(cli_s2s_time_ms(cptr), cli_s2s_msgid(cptr));
        if (client_tags && *client_tags)
          sendcmdto_one(sptr, CMD_MULTILINE, srv, "+%s @%s %s :%s",
                        batch_ref, client_tags, target, text);
        else
          sendcmdto_one(sptr, CMD_MULTILINE, srv, "+%s %s :%s",
                        batch_ref, target, text);
      } else {
        sendcmdto_one(sptr, CMD_MULTILINE, srv, "%s%s %s :%s",
                      is_end ? "-" : (is_concat ? "c" : ""),
                      batch_ref, target, text);
      }
    }
  }

  if (is_start) {
    /* Start new batch */
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch) {
      /* Batch ID collision - clear old one */
      free_s2s_multiline_batch(batch);
    }

    batch = create_s2s_multiline_batch(batch_ref, target, sptr, cptr,
                                       client_tags,
                                       cli_s2s_msgid(cptr), cli_s2s_time_ms(cptr));
    if (!batch)
      return 0;  /* No room for new batch */

    /* Add first line if present */
    if (!EmptyString(text))
      add_s2s_multiline_message(batch, text, 0);
  }
  else if (is_end) {
    /* End batch and deliver */
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch) {
      /* Capture forwarded paste URL from end token text param */
      if (!EmptyString(text))
        ircd_strncpy(batch->paste_url, text, sizeof(batch->paste_url));
      deliver_s2s_multiline_batch(batch, cptr);
      free_s2s_multiline_batch(batch);
    }
  }
  else {
    /* Continuation line */
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch)
      add_s2s_multiline_message(batch, text, is_concat);
  }

  return 0;
}
