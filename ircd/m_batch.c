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
#include "ircd_relay.h"
#include "ml_split.h"
#include "msgq.h"
#include "class.h"
#include "bouncer_session.h"
#include "history.h"
#include "history_trim_codec.h"
#include "ml_content.h"
#include "ml_fallback.h"
#include "ml_route.h"
#include "paste_listener.h"
#include "persistence_profile.h"
#include "webpush.h"
#include "webpush_store.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

static void format_time_tag(char *buf, size_t buflen);   /* defined below */

/** Format an epoch-millisecond time as a server-time tag value
 * (YYYY-MM-DDThh:mm:ss.sssZ) -- the batch's one event time, not "now". */
static void ms_to_time_tag(char *buf, size_t buflen, uint64_t ms)
{
  char unix_ts[32];
  history_format_ms(unix_ts, sizeof(unix_ts), ms);
  if (history_unix_to_iso(unix_ts, buf, buflen) != 0)
    format_time_tag(buf, buflen);   /* unreachable in practice: keep a valid tag */
}

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
  size_t pos = 0;
  int use_tags = CapOwnHas(to, CAP_MSGTAGS);
  int has_label = (label && *label && LabeledResponseInUse(to));
  int has_ctags = (ctags && *ctags && use_tags);
  int has_account = (use_tags && from && IsUser(from) && IsAccount(from)
                     && CapOwnHas(to, CAP_ACCOUNTTAG));

  if (!use_tags && !has_label)
    return 0;

  buf[0] = '\0';
  str_appendf(buf, buflen, &pos, "@");
  if (has_label)
    str_appendf(buf, buflen, &pos, "label=%s", label);
  if (use_tags && timebuf && *timebuf) {
    if (pos > 1) str_appendf(buf, buflen, &pos, ";");
    str_appendf(buf, buflen, &pos, "time=%s", timebuf);
  }
  if (use_tags && msgid && *msgid) {
    if (pos > 1) str_appendf(buf, buflen, &pos, ";");
    str_appendf(buf, buflen, &pos, "msgid=%s", msgid);
  }
  if (has_account) {
    if (pos > 1) str_appendf(buf, buflen, &pos, ";");
    str_appendf(buf, buflen, &pos, "account=%s", cli_user(from)->account);
  }
  if (has_ctags) {
    if (pos > 1) str_appendf(buf, buflen, &pos, ";");
    str_appendf(buf, buflen, &pos, "%s", ctags);
  }
  str_appendf(buf, buflen, &pos, " ");
  return (int)pos;
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

  if (MultilineInUse(route_to)) {
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
  const struct SLink *lp;
  int shown, remaining, units = 0;
  const char *msg_str = is_notice ? MSG_NOTICE : MSG_PRIVATE;

  /* The preview and "[N more lines]" by the one rule (ml_fallback.h):
   * blank lines neither shown nor counted.  total_lines is not needed:
   * the count comes from the lines themselves. */
  (void)total_lines;
  ml_fallback_plan(messages, feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES),
                   &shown, &remaining);

  /* Send preview lines with server tags (time, msgid) for IRCv3 compliance.
   * Per multiline spec, only the FIRST fallback line carries msgid to avoid
   * duplicate history entries in receiving clients.
   * Client-only tags from BATCH open are included on each fallback line. */
  int msgid_sent = 0;
  int use_ctags = (client_tags && *client_tags && CapActive(to, CAP_MSGTAGS));
  for (lp = ml_fallback_next(messages, &units, shown); lp;
       lp = ml_fallback_next(lp->next, &units, shown)) {
    const char *text = lp->value.cp + 1;
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

  if (remaining <= 0)
    return;

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

/** Apply multiline cooldown for a *successfully-delivered* batch.
 *
 * Two-meter design (replaces the old per-line lag accumulation + close-time
 * discount which was applied to cli_since and froze the whole connection):
 *
 *   1. con_ml_cooldown_until is set to (now + raw_cooldown * DISCOUNT/100).
 *      Multiline-only — checked at the next BATCH +draft/multiline open.
 *      A user inside the cooldown can still /whois, /part, /privmsg, etc.;
 *      they just can't start another multiline batch yet.
 *
 *   2. A small flat MULTILINE_COOLDOWN_BASE charge (~one regular message
 *      worth) IS applied to cli_since, so multiline isn't a complete
 *      bypass of general fakelag.
 *
 * Raw cooldown formula:
 *   raw     = MULTILINE_COOLDOWN_BASE + total_bytes / MULTILINE_COOLDOWN_BYTES_PER_SEC
 *   applied = raw * MULTILINE_COOLDOWN_DISCOUNT / 100
 *
 * Constants chosen so a worst-case 16KB batch with 50% discount yields
 * ~65 seconds cooldown — livable, doesn't freeze the connection.  A
 * 4KB batch yields ~17 seconds.  Defaults retunable when FILEHOST
 * ratifies and recommended MULTILINE_MAX_BYTES drops.
 *
 * Called ONLY from process_multiline_batch's success path.  Reject paths
 * (oversize, blank, no-such-channel, batch-timeout, replaced-by-new)
 * clear state via clear_multiline_batch without invoking this — failed
 * batches are not a delivery that should incur a cooldown.
 *
 * Spec note: IRCv3 multiline's "batched lines are one logical message,
 * charge as one" framing is sender-UX, not network-cost — legacy fanout
 * expansion, S2S per-line wire, and per-line history storage all bill
 * by line.  The cooldown design splits the difference: the user feels
 * a per-batch cooldown (matches their mental model of "one big thing"),
 * but the math is byte-based (matches network cost). */
#define MULTILINE_COOLDOWN_BASE          2       /* seconds, flat per-batch component */
#define MULTILINE_COOLDOWN_BYTES_PER_SEC 128     /* roughly 1 sec per 128 bytes of batch */

static void
multiline_apply_cooldown(struct Connection *con)
{
  int discount = feature_int(FEAT_MULTILINE_COOLDOWN_DISCOUNT);
  int total_bytes = con_ml_total_bytes(con);
  int raw_cooldown;
  int applied;

  if (discount < 0)
    discount = 0;
  else if (discount > 100)
    discount = 100;

  if (discount == 0)
    return;  /* Operator override: no cooldown, no flat charge. */

  raw_cooldown = MULTILINE_COOLDOWN_BASE
               + (total_bytes / MULTILINE_COOLDOWN_BYTES_PER_SEC);
  applied = (raw_cooldown * discount) / 100;

  if (applied > 0)
    con_ml_cooldown_until(con) = CurrentTime + applied;

  /* Small flat cli_since charge — keeps multiline batches from being
   * a complete bypass of general fakelag accounting.  Independent of
   * batch size; ~one regular-message worth. */
  con_since(con) += MULTILINE_COOLDOWN_BASE;
}

/** Clear the multiline batch state for a connection */
static void
clear_multiline_batch(struct Connection *con)
{
  /* Remember the ref: any further @batch=<ref> lines are ignored per
   * spec ("all past and future messages in this batch will be
   * ignored") instead of leaking into channels as plain messages. */
  if (con_ml_batch_id(con)[0])
    ircd_strncpy(con_ml_dead_batch_id(con), con_ml_batch_id(con),
                 sizeof(con->con_ml_dead_batch_id));
  struct SLink *lp, *next;

  /* Free all stored messages */
  for (lp = con_ml_messages(con); lp; lp = next) {
    next = lp->next;
    if (lp->value.cp)
      MyFree(lp->value.cp);
    free_link(lp);
  }

  /* NOTE: cooldown application is NOT done here.  clear_multiline_batch
   * is called from many paths — successful delivery, blank-line reject,
   * no-such-channel, can't-send-to-channel, oversize, batch-timeout,
   * replaced-by-new-batch — and only successful delivery should incur
   * cooldown.  process_multiline_batch calls multiline_apply_cooldown
   * just before clearing on the success path; all other callers reach
   * this function with no cooldown side-effect. */

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

/** Discard @a cptr's open client multiline batch, if any, silently: the
 * lines collected so far are freed and never delivered, nothing is sent,
 * nothing is left to resume or to time out with a FAIL BATCH TIMEOUT
 * later (the dead-batch reference is not kept either).  For a socket that
 * is gone (a held ghost's, at its revive) and for draft/multiline going
 * inert (a CAP change). */
void multiline_discard_batch(struct Client *cptr)
{
  struct Connection *con;

  if (!cptr || !MyConnect(cptr))
    return;
  con = cli_connect(cptr);
  if (con_ml_batch_id(con)[0])
    clear_multiline_batch(con);
  con_ml_dead_batch_id(con)[0] = '\0';
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

  /* PRIVMSG/NOTICE pass NULL when the line has no text parameter; it is
   * an empty line, and it was copied with strcpy(.., NULL) below. */
  if (!text)
    text = "";

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
    /* Spec: "Each line feed used to join line messages contributes one
     * byte towards the max-bytes limit." */
    int join_extra = (con_ml_msg_count(con) > 0 && !concat) ? 1 : 0;
    int max_bytes = feature_int(FEAT_MULTILINE_MAX_BYTES);
    if (con_ml_total_bytes(con) + len + join_extra > max_bytes) {
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
  con_ml_total_bytes(con) += len
      + ((con_ml_msg_count(con) > 1 && !concat) ? 1 : 0);

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

/** Send one S2S multiline (ML) line toward \a server (audit 0.1).
 *
 * Toward a link that gets the S2S tag region (send_s2s_tags_on), the
 * framing rides in the tags and the body is one byte longer than the
 * client's PRIVMSG, so a client line at the 510-byte maximum crosses
 * whole under the receiver's 512-byte tagged cap:
 *   @A<time><msgid>,M<flag><ref>[,C<ctags>] <num> ML <target> :<text>
 * Otherwise -- tags off, a peer that is not IRCv3-aware, or no msgid to
 * restate -- the body form, byte for byte what was sent before:
 *   [@A<time><msgid>] <num> ML +<ref> [@<ctags>] <target> :<text>  (start)
 *   <num> ML [c|-]<ref> <target> :<text>                       (others)
 * except that a start line whose client tags would push the 510-byte
 * cut into its target goes without them (send_s2s_untagged_fits).
 *
 * Every tag-framed line restates the batch's ONE msgid and time
 * (\a msgid / \a time_ms): a version-A tag region must carry one, and
 * minting a fresh id per line would break one msgid per event.  The
 * start line arms them exactly as before (sendcmdto_set_s2s_tags); the
 * other lines arm the same values again, consumed by the same send.
 *
 * @param[in] from Sender (source numeric on the wire).
 * @param[in] server Destination link.
 * @param[in] flag '+' start, 'c' concat, '-' end, '.' plain.
 * @param[in] batch_ref S2S batch reference.
 * @param[in] target Channel name or nick.
 * @param[in] ctags Client-only tags (start line only; NULL or "" for none).
 * @param[in] text Line text (end line: the paste URL or "").
 * @param[in] time_ms Batch event time (epoch ms).
 * @param[in] msgid Batch msgid, or NULL/"" when none is known.
 */
static void
ml_send_line(struct Client *from, struct Client *server, char flag,
             const char *batch_ref, const char *target, const char *ctags,
             const char *text, uint64_t time_ms, const char *msgid)
{
  int has_msgid = (msgid && *msgid);

  if (flag != '+')
    ctags = NULL;  /* only a start line carries client tags */

  if (has_msgid && send_s2s_tags_on(server)) {
    sendcmdto_set_s2s_tags(time_ms, msgid);
    sendcmdto_set_s2s_ml(flag, batch_ref);
    sendcmdto_one_tags_with_client(from, CMD_MULTILINE, server, NULL,
                                   ctags, "%s :%s", target, text);
    return;
  }

  if (flag == '+') {
    if (has_msgid)
      sendcmdto_set_s2s_tags(time_ms, msgid);
    /* This line has no tag region, so it is cut at 510 bytes, and the
     * client tags come AHEAD of the target: tags long enough to push
     * the cut past them would cut the target, and the receiver
     * (ms_multiline, which checks only that the channel exists) would
     * build the batch for whatever channel the cut names.  Never cut
     * the target: when the whole line does not fit, send it without
     * the client tags -- the message crosses, only its tags are lost. */
    if (ctags && *ctags
        && send_s2s_untagged_fits(from, TOK_MULTILINE, "+%s @%s %s :%s",
                                  batch_ref, ctags, target, text))
      sendcmdto_one(from, CMD_MULTILINE, server, "+%s @%s %s :%s",
                    batch_ref, ctags, target, text);
    else
      sendcmdto_one(from, CMD_MULTILINE, server, "+%s %s :%s",
                    batch_ref, target, text);
  } else {
    sendcmdto_one(from, CMD_MULTILINE, server, "%s%s %s :%s",
                  flag == '-' ? "-" : (flag == 'c' ? "c" : ""),
                  batch_ref, target, text);
  }
}

/** Send a multiline DM to a remote user, from its originating server, as
 * the single-line fallback: the batch's lines with text, at most
 * MULTILINE_LEGACY_MAX_LINES of them, then -- when lines with text are
 * left -- one truncation NOTICE saying how many, with the paste URL.
 *
 * Used whenever the way to the target's server does not carry ML
 * (ml_route_carries_multiline): a legacy server next to us, or further
 * along behind a server that would take the batch and then have nowhere
 * to pass it.  The lines are ordinary PRIVMSG/NOTICE lines routed toward
 * the target like any single-line DM, so every server on the way, of any
 * version, forwards them.  Sent the way relay_private_message sends a
 * DM: the client tags and, on the first line, the batch's msgid and time
 * ride in the S2S tag region toward an IRCv3-aware next hop; a legacy
 * next hop gets the bare line (sendcmdto_one_tags_with_client).  The
 * other lines and the NOTICE take their own msgids.
 *
 * Every line, the NOTICE included, also carries the fallback mark
 * ,F<msgid> toward an IRCv3-aware hop: this server stores the batch
 * whole, so a fork server the lines merely pass through does not store
 * them as single PMs (server_relay_private_message); only the target's
 * own server does, as what its client saw.
 *
 * - NOTICE stays NOTICE: \a is_notice picks the command of every line.
 * - Blank lines are not sent (the fallback skips them, as the client
 *   fallback does) and so are not counted either: neither in the preview
 *   budget nor in "[N more lines]", which counts the lines with text that
 *   were not sent.  No lines left, no NOTICE.
 * - An alias sender is sent as its primary (bouncer invariant #10: a
 *   server that does not know aliases drops a line from one), except
 *   toward the primary's own direction, where the primary's numeric would
 *   come back to the server it lives on (relay_private_message's rule).
 *
 * The caller disarms the client event time after its S2S sends
 * (sendcmdto_set_s2s_tags also arms the client @time).
 *
 * @param[in] sptr Sender (local).
 * @param[in] acptr Target (remote user).
 * @param[in] messages The batch's lines (flag byte + text).
 * @param[in] client_tags The batch's client-only tags, or NULL.
 * @param[in] is_notice Non-zero for a NOTICE batch.
 * @param[in] time_ms The batch's event time (epoch ms).
 * @param[in] msgid The batch's msgid.
 * @param[in] paste_url The batch's paste URL, or NULL.
 */
static void
ml_send_dm_fallback(struct Client *sptr, struct Client *acptr,
                    struct SLink *messages, const char *client_tags,
                    int is_notice, uint64_t time_ms, const char *msgid,
                    const char *paste_url)
{
  struct Client *from = sptr;
  const struct SLink *lp;
  int shown, left, units = 0;
  int sent = 0;

  if (IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
    from = cli_alias_primary(sptr);
    if (!MyUser(from) && cli_from(from) == cli_from(acptr))
      from = sptr;
  }

  ml_fallback_plan(messages, feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES),
                   &shown, &left);
  for (lp = ml_fallback_next(messages, &units, shown); lp;
       lp = ml_fallback_next(lp->next, &units, shown)) {
    const char *text = lp->value.cp + 1;

    if (sent == 0)
      sendcmdto_set_s2s_tags(time_ms, msgid);
    sendcmdto_set_s2s_fallback(msgid);
    if (is_notice)
      sendcmdto_one_tags_with_client(from, CMD_NOTICE, acptr,
                                     sent == 0 ? msgid : NULL, client_tags,
                                     "%C :%s", acptr, text);
    else
      sendcmdto_one_tags_with_client(from, CMD_PRIVATE, acptr,
                                     sent == 0 ? msgid : NULL, client_tags,
                                     "%C :%s", acptr, text);
    sent++;
  }

  if (left > 0) {
    /* Truncation NOTICE: an event of its own (fresh msgid, its mint
     * time), sourced from the sender so it lands in the conversation. */
    char trunc_msgid[S2S_MSGID_BUFSIZE];

    generate_msgid(trunc_msgid, sizeof(trunc_msgid));
    sendcmdto_set_s2s_tags(history_event_time_ms(NULL), trunc_msgid);
    sendcmdto_set_s2s_fallback(msgid);
    if (paste_url)
      /* URL outside the bracket so linkifiers don't grab the ']'. */
      sendcmdto_one_tags_with_client(from, CMD_NOTICE, acptr, trunc_msgid,
                                     NULL, "%C :[%d more lines] %s",
                                     acptr, left, paste_url);
    else
      sendcmdto_one_tags_with_client(from, CMD_NOTICE, acptr, trunc_msgid,
                                     NULL,
                                     "%C :[%d more lines - connect to a multiline-capable server to view]",
                                     acptr, left);
  }
}

/** The number of direct server links (cli_serv(&me)->down): the most
 * distinct links ml_channel_links() can return. */
static int
ml_down_count(void)
{
  struct DLink *lp;
  int n = 0;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next)
    n++;
  return n;
}

/** The server links a channel multiline line is routed toward (W5 Task 13).
 *
 * Every distinct direct server link (IsServer) with a member of \a chptr
 * behind it that is not ours (local members are delivered here), in member
 * order, \a skip_link excluded.  Multiline's own local delivery skips no
 * member, so neither does this: every server whose local delivery would
 * reach a member -- and so every server whose receive window is open -- is
 * on the list.  Deduplicated in \a links itself: the walks this replaces
 * marked links with private counters in cli_sentalong(), a field that holds
 * send.c's own sentalong_marker values, so a link a channel send had last
 * marked with the same number was skipped (F-4).
 *
 * @param[in] chptr Channel (NULL: none).
 * @param[in] skip_link Link to leave out (the one the batch came on), or NULL.
 * @param[out] links Filled with the links found.
 * @param[in] max Size of \a links: the number of direct server links
 *            (ml_down_count()).
 * @return The number of links in \a links.
 */
static int
ml_channel_links(struct Channel *chptr, struct Client *skip_link,
                 struct Client **links, int max)
{
  struct Membership *member;
  int n = 0;
  int i;

  if (!chptr || !links || max <= 0)
    return 0;
  for (member = chptr->members; member; member = member->next_member) {
    struct Client *server;

    if (MyConnect(member->user))
      continue;
    server = cli_from(member->user);
    if (!IsServer(server) || server == skip_link)
      continue;
    for (i = 0; i < n; i++)
      if (links[i] == server)
        break;
    if (i < n)
      continue;
    if (n >= max)
      break;  /* sized to every direct link: not reached */
    links[n++] = server;
  }
  return n;
}

/** Give the sender's answers to a refused batch the batch's label.
 *
 * The label of a labeled batch rides on its BATCH + line; it is kept in
 * con_ml_label for the echo, the batch's answer.  A refused batch has no
 * echo: its refusal (the numeric its lines would get as single messages)
 * is the answer, and goes out while the BATCH - line is parsed, with no
 * label of its own.  Arm the batch's label as that line's label while the
 * send checks run, so the first answer carries it -- and a refusal that
 * answers nothing (a NOTICE, SILENCE) is answered ACK by the parser.
 * Nothing is armed when the BATCH - line has a label of its own.
 * @return Non-zero when armed (ml_label_disarm() undoes it). */
static int
ml_label_arm(struct Client *sptr)
{
  struct Connection *con = cli_connect(sptr);

  if (cli_label(sptr)[0] || !con_ml_label(con)[0])
    return 0;
  ircd_strncpy(cli_label(sptr), con_ml_label(con), sizeof(con->con_label));
  cli_label_responded(sptr) = 0;
  return 1;
}

/** Undo ml_label_arm() for an accepted batch: its echo carries the label. */
static void
ml_label_disarm(struct Client *sptr, int armed)
{
  if (armed) {
    cli_label(sptr)[0] = '\0';
    cli_label_responded(sptr) = 0;
  }
}

/** What the per-line checks of ml_batch_refused() need (ml_lines_check). */
struct ml_check_ctx {
  struct Client *sptr;
  struct Channel *chptr;
  int is_notice;
  int utf8;                 /**< worst relay_utf8_check() result seen */
  char buf[BUFSIZE];        /**< the sanitised copy of the current line */
};

/** UTF8ONLY for one line (relay_utf8_check), answering nothing: strict
 * mode refuses the line, warn mode hands back the sanitised copy. */
static const char *
ml_check_utf8(const char *text, void *v)
{
  struct ml_check_ctx *ctx = (struct ml_check_ctx *)v;
  int r = relay_utf8_check(text, ctx->buf, sizeof(ctx->buf));

  if (r > ctx->utf8)
    ctx->utf8 = r;
  if (r == RELAY_UTF8_REFUSED)
    return NULL;
  return r == RELAY_UTF8_SANITISED ? ctx->buf : text;
}

/** A channel's text checks for one line (relay_channel_text), answering
 * the refusal as the line's command would.  One target: the batch's (a
 * multi-target PRIVMSG is no batch). */
static const char *
ml_check_channel_text(const char *text, void *v)
{
  struct ml_check_ctx *ctx = (struct ml_check_ctx *)v;

  return relay_channel_text(ctx->sptr, ctx->chptr, text, text, 1,
                            ctx->is_notice);
}

/** The send checks of a multiline batch: exactly the checks its lines get
 * as single-line PRIVMSGs or NOTICEs from the same sender to the same
 * target, made once, here at the origin, before anything is delivered,
 * echoed, stored, pushed or relayed -- with the single-line relay's own
 * functions (ircd_relay.c), so the two cannot drift apart again.
 *
 * In the single-line relay's order:
 *  1. UTF8ONLY, line by line (relay_utf8_check): one invalid line refuses
 *     the batch in strict mode (FAIL <cmd> INVALID_UTF8, once); in warn
 *     mode each invalid line is sanitised, and the one WARN goes out when
 *     the batch is accepted (*\a utf8_warn), under the batch's label.
 *  2. Sanitised lines can grow the batch: it is held to
 *     MULTILINE_MAX_BYTES again here, before any check with a side effect.
 *  3. The target exists: ERR_NOSUCHCHANNEL / ERR_NOSUCHNICK for a PRIVMSG
 *     batch; a NOTICE batch is dropped silently, as NOTICE is.
 *  4. A channel: relay_channel_refused() (may speak there -- +n, +m,
 *     voice, bans, +M, +r, +O, +a, +Z by this connection; the target
 *     limit; +N), then relay_channel_text() line by line (+C, +c; +S
 *     strips the line, and a line +S leaves empty refuses the batch).
 *     A blank line is no message of its own and is not tested.
 *     A user: relay_private_refused() (target limit, SILENCE, +R, +D,
 *     +q), about the target user; its devices are served after.
 * One refused line refuses the whole batch: nothing of it goes anywhere.
 * The refusal is the numeric (or FAIL) the single-line path sends, once
 * for the batch, carrying the batch's label (the caller arms it,
 * ml_label_arm()); a NOTICE
 * batch is silent where NOTICE is.  No cooldown is charged (a refused
 * batch delivered nothing; its BATCH + line paid the parser's fakelag,
 * as a refused single line does).
 *
 * @param[in] sptr The local sender (an alias is checked as itself, as the
 *            single-line relay checks it).
 * @param[in] is_channel Non-zero for a channel target.
 * @param[out] chptr_p The target channel.
 * @param[out] acptr_p The target user.
 * @param[out] utf8_warn Set when a line was sanitised.
 * @return 0 when the batch may go on, -1 when it is refused (the caller
 *         clears it).
 */
static int
ml_batch_refused(struct Client *sptr, int is_channel, struct Channel **chptr_p,
                 struct Client **acptr_p, int *utf8_warn)
{
  struct Connection *con = cli_connect(sptr);
  int is_notice = (con_ml_is_notice(con) == 1);
  const char *cmd = is_notice ? "NOTICE" : "PRIVMSG";
  const char *target = con_ml_target(con);
  struct ml_check_ctx ctx;

  *chptr_p = NULL;
  *acptr_p = NULL;
  *utf8_warn = 0;
  ctx.sptr = sptr;
  ctx.chptr = NULL;
  ctx.is_notice = is_notice;
  ctx.utf8 = RELAY_UTF8_OK;

  /* 1. UTF8ONLY, line by line. */
  if (ml_lines_check(con_ml_messages(con), ml_check_utf8, &ctx) < 0) {
    relay_utf8_answer(sptr, cmd, RELAY_UTF8_REFUSED, NULL);
    return -1;
  }
  *utf8_warn = (ctx.utf8 == RELAY_UTF8_SANITISED);

  /* 2. The size, before anything with a side effect (the target limit,
   * SILENCE's mask sent back): only the sanitiser can grow a batch (each
   * invalid byte becomes a 3-byte U+FFFD; +S strips, which only shrinks),
   * and a batch past MULTILINE_MAX_BYTES once sanitised is refused, as at
   * acceptance.  A single line in that case is cut to fit instead; a batch
   * cannot be: past the limit, the servers it is relayed to drop its
   * lines past the network maximum (add_s2s_multiline_message), so it
   * would arrive partial.  The FAIL says why the sent size was not the
   * one held to the limit. */
  if (ctx.utf8 == RELAY_UTF8_SANITISED) {
    con_ml_total_bytes(con) = ml_lines_bytes(con_ml_messages(con));
    if (con_ml_total_bytes(con) > feature_int(FEAT_MULTILINE_MAX_BYTES)) {
      send_fail_ctx(sptr, "BATCH", "MULTILINE_MAX_BYTES",
                    "Multiline batch max-bytes exceeded once its invalid "
                    "UTF-8 was replaced", "%d",
                    feature_int(FEAT_MULTILINE_MAX_BYTES));
      return -1;
    }
  }

  /* 3. The target. */
  if (is_channel) {
    if (!(*chptr_p = FindChannel(target))) {
      if (!is_notice)
        send_reply(sptr, ERR_NOSUCHCHANNEL, target);
      return -1;
    }
  } else if (!(*acptr_p = FindUser(target))) {
    if (!is_notice)
      send_reply(sptr, ERR_NOSUCHNICK, target);
    return -1;
  }

  /* 4. The send checks. */
  if (is_channel) {
    struct Channel *chptr = *chptr_p;

    if (relay_channel_refused(sptr, chptr, is_notice))
      return -1;
    ctx.chptr = chptr;
    if (ml_lines_check(con_ml_messages(con), ml_check_channel_text, &ctx) < 0)
      return -1;
  } else if (relay_private_refused(sptr, *acptr_p, is_notice))
    return -1;

  /* +S may have shrunk lines: the count the echo and the cooldown use. */
  con_ml_total_bytes(con) = ml_lines_bytes(con_ml_messages(con));
  return 0;
}

/** Process and deliver a completed multiline batch */
static int
process_multiline_batch(struct Client *sptr)
{
  struct Connection *con = cli_connect(sptr);
  struct Channel *chptr = NULL;
  struct Client *acptr = NULL;
  struct Client *face;     /* who the message is from to others (an alias's primary) */
  struct SLink *lp;
  struct Membership *member;
  int is_channel;
  int first;
  char batch_base_msgid[64];  /* Base msgid for entire batch */
  int fallback_count = 0;  /* Track recipients who got truncated fallback */
  int is_notice = (con_ml_is_notice(con) == 1);
  const char *cmd_str = is_notice ? "NOTICE" : "PRIVMSG";
  int label_armed;
  int utf8_warn = 0;

  if (!con_ml_batch_id(con)[0])
    return 0;  /* No active batch */

  if (!con_ml_messages(con)) {
    clear_multiline_batch(con);
    return 0;  /* Empty batch */
  }

  /* A refused batch is answered under its label (ml_label_arm). */
  label_armed = ml_label_arm(sptr);

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

  /* The target, and every check its lines would get as single messages
   * (ml_batch_refused): before anything below delivers, echoes, stores,
   * pushes or relays any of it. */
  if (ml_batch_refused(sptr, is_channel, &chptr, &acptr, &utf8_warn) < 0) {
    clear_multiline_batch(con);
    return 0;
  }
  face = (IsBouncerAlias(sptr) && cli_alias_primary(sptr))
         ? cli_alias_primary(sptr) : sptr;

  /* Generate ONE base msgid for the entire multiline batch.
   * Each line will get this base msgid with a sequence suffix: base:00, base:01, etc.
   * This ensures all lines can be retrieved together via CHATHISTORY by msgid prefix.
   */
  generate_msgid(batch_base_msgid, sizeof(batch_base_msgid));

  /* Split, now the batch is accepted, every line whose relayed form
   *   ":<nick>!<user>@<host> <PRIVMSG|NOTICE> <target> :<text>"
   * passes 510 bytes into draft/multiline-concat parts (ml_split_lines),
   * so the joined message is byte-identical to the client's instead of
   * losing each long line's tail to the output cut.  The room is the
   * single-line relay's (relay_text_budget); for a DM it is also the
   * session echo's BX frame (relay_dm_text_budget), which carries the
   * lines to the sender's devices on other servers.  Done before any
   * delivery, so every path below -- multiline and fallback delivery,
   * the echo, ML / BX M to other servers, the stored record, web push --
   * walks the same lines.  Not for a service: the way to a service is
   * never multiline, so each part would reach it as a PRIVMSG of its own
   * and the tail would run as a command; its lines go as before.
   *
   * The split adds no byte to the joined message, so the byte limit and
   * the cooldown's total are unchanged.  The line count is the split
   * result's: MULTILINE_MAX_LINES is what we advertise to other servers
   * and the most they accept from us (add_s2s_multiline_message drops
   * lines past the network maximum), so a batch that passes it only once
   * split is refused here.  The client cannot predict the split, so a
   * batch within the advertised max-lines can be refused (owner's call;
   * the alternative is to count the client's lines and give S2S a larger
   * allowance). */
  {
    size_t room = 0;
    int max_lines = feature_int(FEAT_MULTILINE_MAX_LINES);
    int lines;

    if (is_channel)
      room = relay_text_budget(sptr, cmd_str, strlen(chptr->chname), 0);
    else if (!IsServiceClient(acptr))
      room = relay_dm_text_budget(sptr, cmd_str, acptr,
                                  strlen(batch_base_msgid),
                                  strlen(con_ml_client_tags(con)), 1);
    lines = ml_split_lines(con_ml_messages(con), room);
    con_ml_msg_count(con) = lines;
    if (lines > max_lines) {
      send_fail_ctx(sptr, "BATCH", "MULTILINE_MAX_LINES",
                    "Too many lines in multiline batch once lines too long "
                    "to relay are split", "%d", max_lines);
      clear_multiline_batch(con);
      return 0;
    }
  }

  /* Accepted.  The echo carries the label from here (not the armed one).
   * What the single-line relay does for an accepted message before it is
   * delivered, once for the batch: the sanitiser's WARN; for a channel,
   * reveal a delayed-join sender (members see its JOIN before the
   * message); for a user, RPL_AWAY (PRIVMSG) and the target's free reply
   * (relay_private_accepted). */
  ml_label_disarm(sptr, label_armed);
  if (utf8_warn)   /* under the batch's label, as the fallback WARN */
    relay_utf8_answer(sptr, cmd_str, RELAY_UTF8_SANITISED,
                      con_ml_label(con)[0] ? con_ml_label(con) : NULL);
  if (is_channel)
    RevealDelayedJoinIfNeeded(sptr, chptr);
  else
    relay_private_accepted(sptr, acptr, is_notice);

  /* ONE time for the whole batch: the msgid's own mint time, read right
   * after the mint (the truncation notices mint again later).  Row, live
   * @time, S2S @time and ml_content all use it -- this used to be four
   * different times under one msgid (audit 2026-09-06 #12). */
  char batch_timebuf[32];
  uint64_t batch_time_ms = history_event_time_ms(NULL);
  ms_to_time_tag(batch_timebuf, sizeof(batch_timebuf), batch_time_ms);

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

      /* The members a single line reaches (the channel relay's filter,
       * channel_member_skipped): not a zombie, not +d, not behind a
       * bursting server, not one that SILENCEs the sender's face on
       * channel messages; and, here, not a device whose profile hides the
       * channel.  A remote member filtered out reads nothing, so it is
       * not counted for the WARN either (its server filters it again). */
      if (channel_member_skipped(face, member, SKIP_DEAF | SKIP_BURST))
        continue;

      if (!MyConnect(to)) {
        /* Delivered by the S2S relay below.  Counted for the sender's
         * WARN when the way to its server does not carry ML: it gets the
         * fallback, from us or from the last server that takes ML.  Not
         * a service client (a channel service sits in every registered
         * channel and would raise the WARN on every batch). */
        if (!IsServiceClient(to)
            && !ml_route_carries_multiline(cli_user(to)->server))
          fallback_count++;
        continue;
      }

      if (!persistence_channel_visible(to, chptr->chname))
        continue;

      /* With aliases, each connection is a separate Client with its own caps.
       * CapActive checks the client's own capabilities directly. */
      if (MultilineInUse(to)) {
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
        if (MultilineInUse(sptr)) {
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

    /* Forward to acptr's session aliases: the target's other devices.
     * Skip sptr itself: when sender and recipient are aliases of the same
     * session, primary delivery already covers acptr, and forwarding to
     * sptr would echo the sender's own message back to itself.
     *
     * This server serves every device of the target, once, each in the
     * best form its route and caps allow; no other server forwards a
     * multiline DM to aliases (deliver_s2s_multiline_batch never did, and
     * a server passing the ,F fallback lines on skips
     * bounce_forward_pm_to_aliases for them).
     *
     * - Local alias: a batch or the client fallback
     *   (deliver_multiline_dm_to_one).
     * - Remote alias, addressed by its NUMERIC (never by nick: an alias
     *   carries its primary's nick and is not in the nick hash, so a batch
     *   "to <nick>" was delivered to the primary again -- twice -- and
     *   never to the alias):
     *   - with draft/multiline + batch + echo-message (its replicated
     *     BX U caps): a BX M batch, the numeric-addressed multiline frame
     *     every fork server already delivers (its receiver serves only an
     *     echo-message connection, hence the third cap);
     *   - otherwise, or with its caps not known yet: the single-line
     *     fallback with the ,F mark, addressed to the alias's numeric
     *     (ml_send_dm_fallback), which any fork server delivers.  A
     *     multiline-capable device without echo-message gets the
     *     fallback: the ML start line names its target by nick, and a
     *     numeric there would be dropped by every server built before
     *     this change. */
    if (IsAccount(acptr) && !IsBouncerAlias(acptr)) {
      struct BouncerSession *acptr_sess = bounce_get_session(acptr);
      if (acptr_sess && acptr_sess->hs_alias_count > 0) {
        struct Client *fwd_source =
            (IsBouncerAlias(sptr) && cli_alias_primary(sptr))
            ? cli_alias_primary(sptr) : sptr;
        int i;
        for (i = 0; i < acptr_sess->hs_alias_count; i++) {
          struct Client *alias = findNUser(acptr_sess->hs_aliases[i].ba_numeric);
          unsigned int caps = acptr_sess->hs_aliases[i].ba_caps;

          if (!alias || alias == acptr || alias == sptr || !IsBouncerAlias(alias))
            continue;
          if (MyConnect(alias)) {
            fallback_count += deliver_multiline_dm_to_one(sptr, alias, alias,
                                        batch_base_msgid, batch_timebuf,
                                        batch_paste_url, is_notice, cmd_str,
                                        0);
          } else if (acptr_sess->hs_aliases[i].ba_caps_known
                     && (caps & BX_CAP_DRAFT_MULTILINE) && (caps & BX_CAP_BATCH)
                     && (caps & BX_CAP_ECHO_MESSAGE)) {
            /* Wire target acptr: the alias's own conversation (it carries
             * acptr's nick).  Index -(2 + i) keeps the batch ids apart
             * from the echo loop's (i, and -1 for the primary). */
            emit_bxm_to_remote_member(alias, acptr_sess->hs_aliases[i].ba_numeric,
                                      fwd_source, acptr, con, is_notice,
                                      batch_base_msgid, batch_paste_url,
                                      -(2 + i));
          } else {
            fallback_count++;
            ml_send_dm_fallback(sptr, alias, con_ml_messages(con),
                                con_ml_client_tags(con), is_notice,
                                batch_time_ms, batch_base_msgid,
                                batch_paste_url);
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
        /* Session echoes go only to connections that negotiated
         * echo-message (see bounce_echo_pm_to_session): a client without
         * it files a self-sourced PRIVMSG under its source, i.e. a query
         * with the user's own nick.  Remote members are pre-filtered by
         * the replicated BX_CAP_ECHO_MESSAGE where known and gated again
         * on the receiving server. */
        if (sender_primary != sptr && sender_primary != acptr) {
          if (MyConnect(sender_primary)) {
            if (CapActive(sender_primary, CAP_ECHOMSG))
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
            int member_use_bxm;
            if (!member || member == sptr || member == acptr
                || !IsBouncerAlias(member))
              continue;
            if (MyConnect(member) ? !CapActive(member, CAP_ECHOMSG)
                : (sender_sess->hs_aliases[i].ba_caps_known
                   && !(sender_sess->hs_aliases[i].ba_caps & BX_CAP_ECHO_MESSAGE)))
              continue;
            /* Pick BX M when the alias's actual cap state is known
             * and includes both DRAFT_MULTILINE and BATCH.  Fall back
             * to the link-level IsMultiline proxy if the alias's home
             * server hasn't yet broadcast a BX U caps= for it (burst
             * race or older fork without per-alias cap discovery). */
            if (sender_sess->hs_aliases[i].ba_caps_known) {
              unsigned int caps = sender_sess->hs_aliases[i].ba_caps;
              member_use_bxm = (caps & BX_CAP_DRAFT_MULTILINE)
                               && (caps & BX_CAP_BATCH);
            } else {
              member_use_bxm = IsMultiline(cli_from(member));
            }
            if (MyConnect(member)) {
              deliver_multiline_dm_to_one(sptr, member, acptr,
                                          batch_base_msgid, batch_timebuf,
                                          batch_paste_url, is_notice, cmd_str,
                                          0);
            } else if (member_use_bxm) {
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

    /* A remote target: the batch goes as ML lines only when the whole
     * way to the target's server carries ML (ml_route_carries_multiline).
     * Every server forwards ML only to a link that announced it, so a
     * batch handed to a multiline next hop with a legacy hop -- or a fork
     * server with its cap off -- further on stopped there, and the target
     * got nothing.  Otherwise this server sends the fallback itself, as
     * single-line DMs every server forwards (ml_send_dm_fallback): the
     * same code for a legacy server next to us and for one further on. */
    if (!MyConnect(acptr)) {
      if (ml_route_carries_multiline(cli_user(acptr)->server)) {
        struct Client *target_server = cli_from(acptr);
        char s2s_batch_id[16];

        ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                      cli_yxx(sptr), (unsigned long)CurrentTime);
        /* Send ML tokens to capable server.  Every line carries the
         * batch's msgid (unified delivery) and, toward a tag-carrying
         * link, its framing in the tag region (ml_send_line). */
        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          ml_send_line(sptr, target_server,
                       first ? '+' : (concat ? 'c' : '.'),
                       s2s_batch_id, cli_name(acptr),
                       con_ml_client_tags(con), text,
                       batch_time_ms, batch_base_msgid);
          first = 0;
        }
        ml_send_line(sptr, target_server, '-', s2s_batch_id,
                     cli_name(acptr), NULL, "",
                     batch_time_ms, batch_base_msgid);
      } else {
        /* The target reads the fallback: counted for the WARN, unless it
         * is a service (as in a channel). */
        if (!IsServiceClient(acptr))
          fallback_count++;
        ml_send_dm_fallback(sptr, acptr, con_ml_messages(con),
                            con_ml_client_tags(con), is_notice,
                            batch_time_ms, batch_base_msgid,
                            batch_paste_url);
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
    char s2s_batch_id[16];
    int fb_shown, fb_left;   /* the fallback's preview (ml_fallback.h) */
    int max_links = ml_down_count();
    struct Client **links = max_links
        ? (struct Client **)MyMalloc(sizeof(*links) * max_links) : NULL;
    int nlinks = ml_channel_links(chptr, NULL, links, max_links);
    int li;

    ml_fallback_plan(con_ml_messages(con),
                     feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES),
                     &fb_shown, &fb_left);

    ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                  cli_yxx(sptr), (unsigned long)CurrentTime);

    /* Each server link with a member of the channel behind it, once
     * (ml_channel_links: local members were handled above). */
    for (li = 0; li < nlinks; li++) {
      struct Client *server = links[li];

      /* Split delivery: alias numeric toward primary's server direction
       * to avoid fake direction (primary's server would drop messages
       * appearing to come from its own local client via external link). */
      {
        struct Client *from = relay_from;
        if (relay_primary && cli_from(relay_primary) == server)
          from = sptr;  /* use alias numeric toward primary's server */

      if (IsMultiline(server)) {
        /* Send ML tokens to capable servers.  Every line carries the
         * batch's msgid, which the receiving server reuses (unified
         * delivery), and, toward a tag-carrying link, its framing in
         * the tag region (ml_send_line). */
        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          ml_send_line(from, server,
                       first ? '+' : (concat ? 'c' : '.'),
                       s2s_batch_id, chptr->chname,
                       con_ml_client_tags(con), text,
                       batch_time_ms, batch_base_msgid);
          first = 0;
        }
        ml_send_line(from, server, '-', s2s_batch_id, chptr->chname, NULL,
                     batch_paste_url ? batch_paste_url : "",
                     batch_time_ms, batch_base_msgid);
      } else {
        /* Send fallback PRIVMSGs to legacy servers (once per server,
         * not per user).  Wire is BOUNDED by max_preview + 1 NOTICE,
         * so this does not suppress the discount halving — anti-flood
         * semantics stay intact even though the legacy peer's local
         * users see truncated content. */
        const struct SLink *fl;
        int sent = 0, units = 0;

        for (fl = ml_fallback_next(con_ml_messages(con), &units, fb_shown); fl;
             fl = ml_fallback_next(fl->next, &units, fb_shown)) {
          const char *text = fl->value.cp + 1;
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
        if (fb_left > 0) {
          int remaining = fb_left;
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
    if (links)
      MyFree(links);
  }

  /* The S2S sends above stamp their lines with the batch's msgid and
   * time through sendcmdto_set_s2s_tags, which also arms the client-facing
   * event time; no send here consumes it.  Left armed, it would be the
   * @time of the next client line anything sends with only a client msgid
   * armed -- an AWAY change, minutes later.  Disarm it with the sends. */
  sendcmdto_set_client_event(NULL, 0);

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

    /* Row time = the batch's one event time (see batch_time_ms). */
    history_format_ms(timestamp, sizeof(timestamp), batch_time_ms);

    /* Storage keying + consent.  Channels: store under the channel
     * name gated on +P / +Y.  DMs: store under the IDENTITY PAIR-KEY --
     * the only key the PM query/replay paths ever look up
     * (normalize_pm_target / is_pm_target_for_client).  The old code
     * stored DMs under the recipient NICK (unreachable by any query)
     * and bypassed the PM consent gates entirely. */
    {
      char pm_pairkey[PM_PAIRKEY_BUFSIZE];
      char owner[HTC_OWNER_MAX];
      const char *store_target = NULL;
      int dm_gap = 0;

      /* The row's trim owner: the sender whose account it carries. */
      history_owner_of(owner, sizeof(owner), sptr);

      if (is_channel) {
        /* The storage gate every channel row passes (W5 Task 13): our
         * own user's batch is ours; the CHATHISTORY_REQUIRE_AUTH rule. */
        if (!(chptr->mode.exmode & EXMODE_NOSTORAGE) && !IsNoStorage(sptr)
            && channel_store_wanted(chptr, 1))
          store_target = chptr->chname;
      } else if (IsServer(sptr) || IsServer(acptr)
                 || IsServiceClient(sptr) || IsServiceClient(acptr)) {
        /* Service traffic is not a conversation -- the same gate as the
         * single-line PM store in ircd_relay.c.  Storing it keyed rows on
         * the bot's session id and put that id in every user's TARGETS
         * (audit 2026-09-06 #15). */
        store_target = NULL;
      } else {
        char id_s[S2S_SESSID_BUFSIZE], id_a[S2S_SESSID_BUFSIZE];
        history_pm_identity(sptr, id_s, sizeof(id_s));
        history_pm_identity(acptr, id_a, sizeof(id_a));
        if (ircd_strcmp(id_s, id_a) < 0)
          ircd_snprintf(0, pm_pairkey, sizeof(pm_pairkey), "%s:%s", id_s, id_a);
        else
          ircd_snprintf(0, pm_pairkey, sizeof(pm_pairkey), "%s:%s", id_a, id_s);

        if (!feature_bool(FEAT_CHATHISTORY_PRIVATE))
          ; /* PM history disabled -- no store */
        else if (!IsAccount(sptr) && !IsAccount(acptr))
          ; /* fully-ephemeral pair: no multiline ring exists -- no store
             * (singleline goes to the ephemeral ring; multiline skipping
             * is the conservative parity choice, noted in the plan) */
        else if (
#ifdef USE_ROCKSDB
                 has_pm_optout(sptr) || has_pm_optout(acptr) ||
#endif
                 IsNoStorage(sptr))
          dm_gap = 1; /* consent refused -- keep the msgid resolvable */
        else
          store_target = pm_pairkey;
      }

      if (dm_gap) {
        history_store_message(batch_base_msgid, timestamp, pm_pairkey,
                              cli_name(acptr), sender_mask,
                              cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                              HISTORY_GAP, "", NULL, owner);
      } else if (store_target) {
        int store_result = history_store_multiline(batch_base_msgid, timestamp,
                            store_target,
                            is_channel ? NULL : cli_name(acptr),
                            sender_mask,
                            cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                            history_content, content_len,
                            batch_paste_secret[0] ? batch_paste_secret : NULL,
                            owner);
        (void)store_result;
        log_write(LS_SYSTEM, L_INFO, 0, "multiline: history_store_multiline returned %d for msgid=%s target=%s",
                  store_result, batch_base_msgid, store_target);
      }
    }
    MyFree(history_content);
  }

  /* Web push: the batch is one message -- push its lines (one IRC message
   * per push) to unattended recipients.  Not gated on history, like the
   * single-message triggers in ircd_relay.c.  Skip the list walk and the
   * MyMalloc entirely when the feature is off. */
  if (feature_bool(FEAT_WEBPUSH_NOTIFY) && webpush_store_available()) {
    int n = 0, i = 0;
    struct webpush_batch_line *wl;
    char ml_ts[32];

    history_format_ms(ml_ts, sizeof(ml_ts), batch_time_ms);

    for (lp = con_ml_messages(con); lp; lp = lp->next)
      n++;
    wl = (struct webpush_batch_line *)MyMalloc(sizeof(*wl) * n);
    for (lp = con_ml_messages(con); lp; lp = lp->next, i++) {
      wl[i].concat = lp->value.cp[0];
      wl[i].text = lp->value.cp + 1;
    }
    webpush_notify_multiline(sptr, is_channel ? chptr : NULL,
                             is_channel ? NULL : acptr,
                             wl, n, batch_base_msgid, ml_ts, is_notice);
    MyFree(wl);
  }

  /* Clear the time override set at the start of this function */
  sendcmdto_set_client_time(NULL);

  /* Apply multiline cooldown — this is the only path where the batch
   * was actually delivered.  Reject paths above (blank, no-channel,
   * oversize, etc.) skip this and just clear state. */
  multiline_apply_cooldown(con);

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

  /* Require draft/multiline in use (MultilineInUse: the capability and
   * batch, which it MUST be negotiated with): it is the only client batch
   * type accepted.  A client that opens some other type without it (a
   * draft/authtoken batch, say) still deserves the answer the
   * client-batch spec asks for, FAIL BATCH UNKNOWN_TYPE, rather than
   * silence; batch ends and malformed starts stay quiet. */
  if (!MultilineInUse(sptr)) {
    if (parc >= 3 && parv[1][0] == '+' && !EmptyString(parv[2])
        && ircd_strcmp(parv[2], "draft/multiline") != 0)
      send_fail(sptr, "BATCH", "UNKNOWN_TYPE", parv[2], "Unknown batch type");
    return 0;
  }

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
      ircd_strncpy(cli_ml_dead_batch_id(sptr), batch_ref,
                   sizeof(cli_connect(sptr)->con_ml_dead_batch_id));
    return 0;
  }

  if (is_start) {
    /* Only support draft/multiline for now */
    if (ircd_strcmp(batch_type, "draft/multiline") != 0) {
      send_fail(sptr, "BATCH", "UNKNOWN_TYPE", batch_type,
                "Unknown batch type");
      ircd_strncpy(cli_ml_dead_batch_id(sptr), batch_ref,
                   sizeof(cli_connect(sptr)->con_ml_dead_batch_id));
      return 0;
    }

    /* Multiline cooldown gate.  Set by the previous batch's close to
     * `(now + raw_cooldown * DISCOUNT/100)` based on that batch's
     * total_bytes.  Scoped to multiline batches only — does not affect
     * other commands, which makes large batches usable without freezing
     * the connection.  See clear_multiline_batch for the formula. */
    if (con_ml_cooldown_until(con) > CurrentTime) {
      char remaining[16];
      ircd_snprintf(0, remaining, sizeof(remaining), "%ld",
                    (long)(con_ml_cooldown_until(con) - CurrentTime));
      send_fail_ctx(sptr, "BATCH", "MULTILINE_COOLDOWN",
                    "Multiline batch cooldown active; retry after the listed "
                    "seconds", "%s", remaining);
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

    /* Start new multiline batch (a fresh open also clears any
     * dead-batch swallow state from a previous failure) */
    con_ml_dead_batch_id(con)[0] = '\0';
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
    /* The batch's command is not known until its first line.  Only
     * clear_multiline_batch() set this to "not set" (-1); a new
     * Connection is zeroed, which reads as PRIVMSG, so a connection's
     * first batch could not be a NOTICE batch ("Cannot mix PRIVMSG and
     * NOTICE").  Every batch starts unset. */
    con_ml_is_notice(con) = -1;

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
  /** A channel batch's relay route (W5 Task 13): the multiline links its
   * start line was relayed to, fixed there so every later line of the
   * batch goes to exactly those links.  MyMalloc'd (NULL when empty),
   * freed with the batch.  Only ever compared with the live downlinks,
   * never dereferenced: a link gone mid-batch is simply not in the live
   * list, and nothing needs clearing on link exit. */
  struct Client **route;
  int route_count;              /**< Entries in route */
  int routed;                   /**< 1 for a channel batch (route is set) */
  /** 1 when this server refuses the channel batch, as it refuses a
   * single line (server_relay_channel_allowed at the start line): nothing
   * of it is relayed on, delivered, stored or pushed here. */
  int refused;
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

/* Forward declaration: create_s2s_multiline_batch's F-MB3 reap sweep
 * below calls this before its normal definition further down (which
 * s2s_multiline_cleanup_link also needs to see). */
static void free_s2s_multiline_batch(struct S2SMultilineBatch *batch);

/* F-MB3: bound the S2S multiline batch table against a peer that opens
 * batches without ever sending the terminating "-".  The per-link cap
 * is the hard DoS bound (cap * #direct-links << MAXCONNECTIONS); the
 * timeout is opportunistic hygiene, swept when a new batch is created
 * (no dedicated event timer — an idle server accumulates nothing). */
#define S2S_ML_MAX_BATCHES_PER_LINK 64
#define S2S_ML_BATCH_TIMEOUT_S      60

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
  int link_count = 0;
  struct S2SMultilineBatch *batch;

  /* F-MB3: opportunistically reap timed-out batches and count how many
   * this link already holds, so one peer can't exhaust the table. */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!s2s_ml_batches[i])
      continue;
    if (CurrentTime - s2s_ml_batches[i]->start_time > S2S_ML_BATCH_TIMEOUT_S) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "S2S multiline batch %s timed out (%ld s) — reaping",
                s2s_ml_batches[i]->batch_id,
                (long)(CurrentTime - s2s_ml_batches[i]->start_time));
      free_s2s_multiline_batch(s2s_ml_batches[i]);
      continue;
    }
    if (s2s_ml_batches[i]->link == link)
      link_count++;
  }
  if (link_count >= S2S_ML_MAX_BATCHES_PER_LINK) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "S2S multiline: link %s at batch cap (%d) — refusing new batch",
              link && IsServer(link) ? cli_name(link) : "?",
              S2S_ML_MAX_BATCHES_PER_LINK);
    return NULL;
  }

  /* Find an empty slot */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!s2s_ml_batches[i])
      break;
  }
  if (i >= MAXCONNECTIONS)
    return NULL;  /* No available slot */

  batch = (struct S2SMultilineBatch *)MyMalloc(sizeof(struct S2SMultilineBatch));
  ircd_strncpy(batch->batch_id, batch_id, sizeof(batch->batch_id));
  ircd_strncpy(batch->target, target, sizeof(batch->target));
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
  batch->route = NULL;
  batch->route_count = 0;
  batch->routed = 0;
  batch->refused = 0;

  s2s_ml_batches[i] = batch;
  return batch;
}

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

/** Free any S2S multiline batches whose original sender is exiting.
 *
 * Called from exit_one_client for every exiting user (not just the
 * directly-linked server), so a batch whose sender QUITs mid-stream —
 * before its terminating "-" arrives — doesn't leave batch->sender
 * dangling for deliver_s2s_multiline_batch to read (UAF). */
void s2s_multiline_cleanup_sender(struct Client *sender)
{
  int i;
  if (!sender)
    return;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_ml_batches[i] && s2s_ml_batches[i]->sender == sender)
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

  if (batch->route)
    MyFree(batch->route);
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
  struct Client *face;     /* the sender as others see it: an alias's primary */
  char batch_base_msgid[64];  /* Base msgid for entire batch */
  int is_notice = batch->is_notice;
  const char *cmd_str = is_notice ? "NOTICE" : "PRIVMSG";

  if (!batch || !batch->messages || !sptr || batch->refused)
    return;
  face = (IsBouncerAlias(sptr) && cli_alias_primary(sptr))
         ? cli_alias_primary(sptr) : sptr;

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
    /* The target's SILENCE list, which this server -- the target's --
     * holds whole: the check server_relay_private_message makes for a
     * single line.  The origin checks what it knows of the list, which
     * is only what has been forwarded to it (positive masks only with
     * SILENCE_CHANMSGS, and a server learns them lazily, as below).
     * Silenced, the batch is dropped silently, as the single line is,
     * and is_silenced() sends the mask back toward the sender's server so
     * that the next message is refused at the origin. */
    if (is_silenced(face, acptr, 0))
      return;
    /* The target may answer without spending a target, as for a single
     * line (server_relay_private_message). */
    if (MyUser(acptr))
      add_target(acptr, face);
  }

  /* Deliver to local recipients */
  if (is_channel) {
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *to = member->user;

      if (!MyConnect(to))
        continue;  /* Only deliver to local users */

      if (to == sptr)
        continue;  /* Skip sender (they already got echo) */

      /* The members a single line from another server reaches here (the
       * channel relay's filter): not +d, not one that SILENCEs the
       * sender's face on channel messages, not a device whose profile
       * hides the channel. */
      if (channel_member_skipped(face, member, SKIP_DEAF | SKIP_BURST)
          || !persistence_channel_visible(to, chptr->chname))
        continue;

      if (MultilineInUse(to)) {
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
          ms_to_time_tag(timebuf, sizeof(timebuf),
                         batch->time_ms ? batch->time_ms
                                        : msgid_decode_time_ms(batch_base_msgid));
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
    if (MultilineInUse(acptr)) {
      char batchid[16];
      char timebuf[32];
      int use_tags = CapActive(acptr, CAP_MSGTAGS);

      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      /* Per IRCv3 multiline spec, server tags (time, msgid, account) and
       * client-only tags go on the BATCH + opener. */
      {
        char tagbuf[512];
        ms_to_time_tag(timebuf, sizeof(timebuf),
                       batch->time_ms ? batch->time_ms
                                      : msgid_decode_time_ms(batch_base_msgid));
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
    int fb_shown, fb_left;   /* the fallback's preview (ml_fallback.h) */
    int max_links = ml_down_count();
    struct Client **links = max_links
        ? (struct Client **)MyMalloc(sizeof(*links) * max_links) : NULL;
    int nlinks = ml_channel_links(chptr, cli_from(cptr), links, max_links);
    int li;

    ml_fallback_plan(batch->messages, feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES),
                     &fb_shown, &fb_left);

    /* Each link with a member behind it, once, never back toward the
     * source (ml_channel_links). */
    for (li = 0; li < nlinks; li++) {
      struct Client *server = links[li];

      if (IsMultiline(server))
        continue;  /* Multiline-capable servers already got ML tokens */

      /* Send fallback PRIVMSGs to legacy server.
       * Set S2S tags on first line for unified msgid. */
      {
        const struct SLink *fl;
        int sent = 0, units = 0;

        for (fl = ml_fallback_next(batch->messages, &units, fb_shown); fl;
             fl = ml_fallback_next(fl->next, &units, fb_shown)) {
          const char *ftext = fl->value.cp + 1;
          if (sent == 0)
            sendcmdto_set_s2s_tags(batch->time_ms, batch_base_msgid);
          if (is_notice)
            sendcmdto_one(sptr, CMD_NOTICE, server, "%H :%s", chptr, ftext);
          else
            sendcmdto_one(sptr, CMD_PRIVATE, server, "%H :%s", chptr, ftext);
          sent++;
        }

        if (fb_left > 0) {
          int remaining = fb_left;
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
    if (links)
      MyFree(links);
    /* The fallback lines above armed the batch's time through
     * sendcmdto_set_s2s_tags, which arms the client-facing event time
     * too; disarm it, as the originating server does. */
    sendcmdto_set_client_event(NULL, 0);
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

    /* Row time = the ORIGIN's batch time carried on the S2S open, so
     * every server stores this msgid at one time; the msgid's intrinsic
     * mint time is the fallback for a legacy sender. */
    history_format_ms(timestamp, sizeof(timestamp),
                      batch->time_ms ? batch->time_ms
                                     : msgid_decode_time_ms(batch_base_msgid));

    /* Storage keying + consent.  Channels: store under the channel
     * name gated on +P / +Y.  DMs: store under the IDENTITY PAIR-KEY --
     * the only key the PM query/replay paths ever look up
     * (normalize_pm_target / is_pm_target_for_client).  The old code
     * stored DMs under the recipient NICK (unreachable by any query)
     * and bypassed the PM consent gates entirely. */
    {
      char pm_pairkey[PM_PAIRKEY_BUFSIZE];
      char owner[HTC_OWNER_MAX];
      const char *store_target = NULL;
      int dm_gap = 0;

      /* The row's trim owner: the sender whose account it carries. */
      history_owner_of(owner, sizeof(owner), sptr);

      if (is_channel) {
        /* The storage gate every channel row passes (W5 Task 13): a
         * relayed batch is stored only while a member of ours is in the
         * channel; and the CHATHISTORY_REQUIRE_AUTH rule. */
        if (!(chptr->mode.exmode & EXMODE_NOSTORAGE) && !IsNoStorage(sptr)
            && channel_store_wanted(chptr, 0))
          store_target = chptr->chname;
      } else if (IsServer(sptr) || IsServer(acptr)
                 || IsServiceClient(sptr) || IsServiceClient(acptr)) {
        /* Service traffic is not a conversation -- the same gate as the
         * single-line PM store in ircd_relay.c.  Storing it keyed rows on
         * the bot's session id and put that id in every user's TARGETS
         * (audit 2026-09-06 #15). */
        store_target = NULL;
      } else {
        char id_s[S2S_SESSID_BUFSIZE], id_a[S2S_SESSID_BUFSIZE];
        history_pm_identity(sptr, id_s, sizeof(id_s));
        history_pm_identity(acptr, id_a, sizeof(id_a));
        if (ircd_strcmp(id_s, id_a) < 0)
          ircd_snprintf(0, pm_pairkey, sizeof(pm_pairkey), "%s:%s", id_s, id_a);
        else
          ircd_snprintf(0, pm_pairkey, sizeof(pm_pairkey), "%s:%s", id_a, id_s);

        if (!feature_bool(FEAT_CHATHISTORY_PRIVATE))
          ; /* PM history disabled -- no store */
        else if (!IsAccount(sptr) && !IsAccount(acptr))
          ; /* fully-ephemeral pair: no multiline ring exists -- no store
             * (singleline goes to the ephemeral ring; multiline skipping
             * is the conservative parity choice, noted in the plan) */
        else if (
#ifdef USE_ROCKSDB
                 has_pm_optout(sptr) || has_pm_optout(acptr) ||
#endif
                 IsNoStorage(sptr))
          dm_gap = 1; /* consent refused -- keep the msgid resolvable */
        else
          store_target = pm_pairkey;
      }

      if (dm_gap) {
        history_store_message(batch_base_msgid, timestamp, pm_pairkey,
                              cli_name(acptr), sender_mask,
                              cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                              HISTORY_GAP, "", NULL, owner);
      } else if (store_target) {
        int store_result = history_store_multiline(batch_base_msgid, timestamp,
                            store_target,
                            is_channel ? NULL : cli_name(acptr),
                            sender_mask,
                            cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                            history_content, content_len,
                            s2s_paste_secret[0] ? s2s_paste_secret : NULL,
                            owner);
        (void)store_result;
      }
    }
    MyFree(history_content);
  }

  /* Web push for the batch, as on the local path.  The push time is the
   * originating server's batch time when it sent one.  Skip the list walk
   * and the MyMalloc entirely when the feature is off. */
  if (feature_bool(FEAT_WEBPUSH_NOTIFY) && webpush_store_available()) {
    char ml_ts[32];
    uint64_t ms = batch->time_ms;
    int n = 0, i = 0;
    struct webpush_batch_line *wl;

    if (!ms) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      ms = (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }
    history_format_ms(ml_ts, sizeof(ml_ts), ms);

    for (lp = batch->messages; lp; lp = lp->next)
      n++;
    wl = (struct webpush_batch_line *)MyMalloc(sizeof(*wl) * n);
    for (lp = batch->messages; lp; lp = lp->next, i++) {
      wl[i].concat = lp->value.cp[0];
      wl[i].text = lp->value.cp + 1;
    }
    webpush_notify_multiline(sptr, is_channel ? chptr : NULL,
                             is_channel ? NULL : acptr,
                             wl, n, batch_base_msgid, ml_ts, is_notice);
    MyFree(wl);
  }
}

/*
 * ms_multiline - server message handler for S2S multiline batch
 *
 * P10 Format, tag-framed (audit 0.1): the batch reference and its flag
 * ride in the S2S tag region as ,M<flag><batchref> (parse_server stores
 * it in cli_s2s_ml), the start line's client-only tags as ,C, and the
 * body is one byte longer than the client's PRIVMSG:
 *   @A...,M+batchid[,C<tags>] [USER_NUMERIC] ML target :first_line
 *   @A...,M.batchid [USER_NUMERIC] ML target :line   (normal continuation)
 *   @A...,Mcbatchid [USER_NUMERIC] ML target :line   (concat continuation)
 *   @A...,M-batchid [USER_NUMERIC] ML target :[url]  (end batch)
 *   parv[1] = target, parv[2] = text (may be empty for end)
 *
 * Body-framed (older senders, and any sender whose next hop gets no
 * S2S tag region):
 *   [USER_NUMERIC] ML +batchid target :first_line   (start batch + first line)
 *   [USER_NUMERIC] ML batchid target :line          (normal continuation)
 *   [USER_NUMERIC] ML cbatchid target :line         (concat continuation)
 *   [USER_NUMERIC] ML -batchid target :             (end batch)
 *   [USER_NUMERIC] ML +batchid @tags target :text   (start with client tags)
 *   parv[1] = batch_id with modifier (+, c, or -)
 *   parv[2] = target (or @client-tags on start, then target shifts to parv[3])
 *   parv[3] = text (may be empty for end)
 *
 * The ,M segment's presence decides the form, line by line.  Client tags
 * come from ,C when present, else from the body form's @ parameter.
 */
int ms_multiline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  const char *batch_ref;
  char *target;
  char *text;
  const char *client_tags = NULL;
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

  if (cli_s2s_ml(cptr)[0]) {
    /* Tag-framed: flag and reference from ,M; parv[1] is the target. */
    const char *ml = cli_s2s_ml(cptr);

    switch (ml[0]) {
    case '+': is_start = 1; break;
    case '-': is_end = 1; break;
    case 'c': is_concat = 1; break;
    case '.': break;
    default:
      return 0;  /* unknown flag, or a malformed ,M (see parse_server) */
    }
    batch_ref = ml + 1;

    if (parc < 2 || EmptyString(parv[1]))
      return 0;
    target = parv[1];
    text = (parc >= 3 && !EmptyString(parv[2])) ? parv[2] : "";
  } else {
    /* Body-framed: flag and reference lead parv[1]. */
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

    /* Check for client-only tags (@-prefixed param, only on start
     * messages).  Kept for older senders, which put them here. */
    if (is_start && parc >= 4 && parv[2][0] == '@') {
      client_tags = parv[2] + 1;  /* skip @ prefix */
      target = parv[3];
      text = (parc >= 5 && !EmptyString(parv[4])) ? parv[4] : "";
    } else {
      target = parv[2];
      text = (parc >= 4 && !EmptyString(parv[3])) ? parv[3] : "";
    }
  }

  if (EmptyString(batch_ref))
    return 0;

  /* Client-only tags in the ,C segment (audit 0.1) take precedence over
   * the body form; only a start line carries them. */
  if (is_start && cli_s2s_client_tags(cptr)[0])
    client_tags = cli_s2s_client_tags(cptr);

  /* A start line opens the batch here first (a reused reference frees
   * the old one), so a channel batch's relay route is fixed before the
   * start line goes anywhere; every later line looks the batch up. */
  if (is_start) {
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch) {
      /* Batch ID collision - clear old one */
      free_s2s_multiline_batch(batch);
    }

    batch = create_s2s_multiline_batch(batch_ref, target, sptr, cptr,
                                       client_tags,
                                       cli_s2s_msgid(cptr), cli_s2s_time_ms(cptr));
    /* A channel batch's route (W5 Task 13): the multiline links with a
     * member behind them now, never the source.  A channel unknown here
     * has no member here: the route is empty and nothing is relayed. */
    if (batch && IsChannelName(target)) {
      int max_links = ml_down_count();
      struct Client **links = max_links
          ? (struct Client **)MyMalloc(sizeof(*links) * max_links) : NULL;
      int nlinks = ml_channel_links(FindChannel(target), cli_from(cptr),
                                    links, max_links);
      int i, n = 0;

      for (i = 0; i < nlinks; i++)
        if (IsMultiline(links[i]))
          links[n++] = links[i];
      if (n) {
        batch->route = links;
      } else if (links) {
        MyFree(links);
      }
      batch->route_count = n;
      batch->routed = 1;

      /* The far side's check (server_relay_channel_allowed), as for a
       * single line from another server: the sender -- an alias as its
       * primary -- may speak by this server's view of the channel.  A
       * remote member may (a delayed-join one is revealed here now); a
       * non-member, a zombie (KICKed here, its PART not back yet)
       * included, is held to +n, +m, the bans and the off-channel modes.
       * Refused, the batch goes nowhere from here -- not relayed on (the
       * route is emptied before the start line goes out), not delivered,
       * stored or pushed -- and the sender is answered as a single line's
       * is -- the device that sent it, not its primary.  The S2S batch
       * carries no NOTICE bit, so it is answered as a PRIVMSG.  An older origin's batch and a desync are what this
       * catches: an origin that checks refuses first. */
      {
        struct Channel *chptr = FindChannel(target);
        struct Client *face = (IsBouncerAlias(sptr) && cli_alias_primary(sptr))
                              ? cli_alias_primary(sptr) : sptr;

        if (chptr && !server_relay_channel_allowed(face, chptr, 0)) {
          batch->refused = 1;
          batch->route_count = 0;
          /* The client that sent the batch -- a device, back along the
           * link it came from, not its primary, which never sent it (as
           * server_relay_channel_message answers). */
          send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
        }
      }
    }
  } else
    batch = find_s2s_multiline_batch(batch_ref);

  /* Propagate ML tokens only to multiline-capable servers.
   * Legacy servers don't understand the ML token and silently drop it.
   * Fallback PRIVMSGs for legacy servers are sent from
   * deliver_s2s_multiline_batch() when the batch completes.
   *
   * A channel batch goes only toward links with a member behind them
   * (W5 Task 13), the WHOLE batch to the links its start line went to:
   * recomputed per line, a link that lost its last member mid-batch would
   * get a start and no end (a batch slot held there until it times out),
   * and one that gained a member would get an end with no start.  A
   * channel line of a batch this server holds no record of (the create
   * failed: the per-link cap, a full table) goes to the links with a
   * member now, as best effort.  A DM batch still goes to every
   * multiline link but the source.
   *
   * Each line carries the originating server's batch msgid and time
   * forward: the ones on this line (a start line, or a tag-framed line
   * restating them), else -- an older sender's untagged continuation --
   * the ones stored with the batch here.  With neither, ml_send_line
   * keeps the body form rather than mint an id.  Toward a tag-carrying
   * link the framing and client tags go in the tag region (audit 0.1). */
  {
    struct DLink *lp;
    const char *fwd_msgid = NULL;
    uint64_t fwd_time_ms = 0;
    char flag = is_start ? '+' : (is_end ? '-' : (is_concat ? 'c' : '.'));

    if (cli_s2s_msgid(cptr)[0]) {
      fwd_msgid = cli_s2s_msgid(cptr);
      fwd_time_ms = cli_s2s_time_ms(cptr);
    } else if (!is_start && batch && batch->msgid[0]) {
      fwd_msgid = batch->msgid;
      fwd_time_ms = batch->time_ms;
    }

    if (batch && batch->routed) {
      /* The route fixed at the start line, compared with the live
       * downlinks only. */
      for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
        struct Client *srv = lp->value.cptr;
        int i;

        for (i = 0; i < batch->route_count; i++)
          if (batch->route[i] == srv)
            break;
        if (i == batch->route_count)
          continue;
        if (srv == cli_from(cptr) || !IsMultiline(srv))
          continue;  /* never in a route; a new link at a freed address */
        ml_send_line(sptr, srv, flag, batch_ref, target, client_tags, text,
                     fwd_time_ms, fwd_msgid);
      }
    } else if (IsChannelName(target)) {
      /* No record of this batch here: the links with a member now. */
      int max_links = ml_down_count();
      struct Client **links = max_links
          ? (struct Client **)MyMalloc(sizeof(*links) * max_links) : NULL;
      int nlinks = ml_channel_links(FindChannel(target), cli_from(cptr),
                                    links, max_links);
      int i;

      for (i = 0; i < nlinks; i++) {
        if (!IsMultiline(links[i]))
          continue;  /* Legacy server — handled by fallback at batch end */
        ml_send_line(sptr, links[i], flag, batch_ref, target, client_tags,
                     text, fwd_time_ms, fwd_msgid);
      }
      if (links)
        MyFree(links);
    } else {
      for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
        struct Client *srv = lp->value.cptr;
        if (srv == cli_from(cptr))
          continue;  /* Don't send back to source */
        if (!IsMultiline(srv))
          continue;  /* Legacy server — handled by fallback at batch end */
        ml_send_line(sptr, srv, flag, batch_ref, target, client_tags, text,
                     fwd_time_ms, fwd_msgid);
      }
    }
    /* ml_send_line arms the batch's time for its S2S tags, and with it
     * the client-facing event time, which no relay send consumes: left
     * armed, it stamped the next client line anything here sent with
     * only a client msgid armed (an AWAY change, much later). */
    sendcmdto_set_client_event(NULL, 0);
  }

  /* A tag-framed continuation or end line restates the batch's msgid
   * and time in its @A prefix only because version-A tags must carry
   * one; it is not an event of its own.  Once relayed, clear them so
   * the rest of this line's handling sees what an untagged continuation
   * always left: on the end line, deliver_s2s_multiline_batch's
   * fallback PRIVMSGs after the first take their tags from this link
   * and must keep minting their own msgids, not repeat the batch's. */
  if (cli_s2s_ml(cptr)[0] && !is_start) {
    cli_s2s_msgid(cptr)[0] = '\0';
    cli_s2s_time_ms(cptr) = 0;
  }

  if (is_start) {
    /* Add first line if present */
    if (batch && !EmptyString(text))
      add_s2s_multiline_message(batch, text, 0);
  }
  else if (is_end) {
    /* End batch and deliver */
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
    if (batch)
      add_s2s_multiline_message(batch, text, is_concat);
  }

  return 0;
}
