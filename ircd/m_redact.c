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
#include "history_trim_codec.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "redact_index.h"
#include "send.h"

#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>


/** Send one REDACT line to a local client that has the capability.
 * The sender only sees its own REDACT with echo-message, as with any
 * other message it originates.  The line carries the event's tags
 * (sendcmdto_one_event): the msgid and time the caller armed
 * (redact_announce_local), so the live REDACT matches its stored row.
 * sendcmdto_one, used before, tags nothing outside a labeled batch, and
 * every live REDACT went out with no msgid and no @time.  Only the
 * requester's own echo answers a command, so only it may carry that
 * command's label: any other member's line joins none of its open
 * batches (an async LIST's) and takes none of its labels. */
static void send_redact_to(struct Client *sptr, struct Client *acptr,
                           const char *target, const char *msgid,
                           const char *reason)
{
  if (!MyUser(acptr) || !CapActive(acptr, CAP_DRAFT_REDACT))
    return;
  if (acptr == sptr && !CapOwnHas(sptr, CAP_ECHOMSG))
    return;

  /* Set stc_withcap so send_buffer routes per-connection */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = CAP_DRAFT_REDACT;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  if (reason && *reason)
    sendcmdto_one_event(sptr, CMD_REDACT, acptr, acptr == sptr,
                        "%s %s :%s", target, msgid, reason);
  else
    sendcmdto_one_event(sptr, CMD_REDACT, acptr, acptr == sptr,
                        "%s %s", target, msgid);

  cap_route_ctx.stc_active = 0;
  cap_route_ctx.stc_withcap = CAP_NONE;
}

/** Propagate REDACT to the channel's local members with the capability.
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

  for (member = chptr->members; member; member = member->next_member)
    send_redact_to(sptr, member->user, target, msgid, reason);
}

/** Show one redaction to the channel's local members: the REDACT event's
 * msgid and time armed for the client tags (one event, one msgid and one
 * time: the stored row and the S2S relay carry the same pair), the fan-out
 * (the redacter's own echo included, with echo-message), then the armed
 * msgid cleared so it cannot tag the next unrelated send.  Every path that
 * applies a redaction shows it through here: a local REDACT, one from a
 * peer (redact_apply_row), and the federated completion of a local miss
 * (complete_redact_fed, m_chathistory.c).
 * @param[in] src Who redacted.
 * @param[in] chptr Channel (its canonical name is the REDACT target).
 * @param[in] msgid The redacted message.
 * @param[in] redact_msgid The REDACT event's msgid.
 * @param[in] time_ms The REDACT event's time (epoch ms).
 * @param[in] reason Reason (may be NULL).
 */
void redact_announce_local(struct Client *src, struct Channel *chptr, const char *msgid,
                           const char *redact_msgid, uint64_t time_ms, const char *reason)
{
  if (feature_bool(FEAT_MSGID))
    sendcmdto_set_client_event(redact_msgid, time_ms);
  propagate_redact_to_channel(src, chptr, chptr->chname, msgid, reason);
  sendcmdto_set_client_msgid(NULL);
}

/** Answer a repeat REDACT of an already-redacted message: the requester's
 * own echo (with echo-message, as the first time), and nothing stored,
 * shown to the channel or relayed (idempotent success, 451769d).  A
 * caller that knows the first REDACT's msgid and time arms them around
 * this call (sendcmdto_set_client_event), so the echo names that event;
 * otherwise it carries no msgid.
 * @param[in] sptr The local requester.
 * @param[in] target Target name (channel).
 * @param[in] msgid The redacted message.
 * @param[in] reason Reason (may be NULL).
 */
void redact_echo_requester(struct Client *sptr, const char *target, const char *msgid,
                           const char *reason)
{
  send_redact_to(sptr, sptr, target, msgid, reason);
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
  int is_chanop = 0;
  int is_oper = 0;
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
  /* The history store is keyed by the channel's canonical spelling
   * (build_key never folds case); a redaction typed as "#linux" for a
   * channel created as "#Linux" must delete and record under the
   * canonical name or it silently never takes effect in history. */
  target = chptr->chname;

  if (!cli_user(sptr)) {
    {
      char fctx[BUFSIZE];   /* spec: <target> <msgid> */
      ircd_snprintf(0, fctx, sizeof(fctx), "%s %s", target, msgid);
      send_fail(sptr, "REDACT", "REDACT_FORBIDDEN", fctx,
                "You must be fully registered to use REDACT");
    }
    return 0;
  }

  /* Check if user is in channel */
  member = find_member_link(chptr, sptr);
  if (!member) {
    send_fail(sptr, "REDACT", "INVALID_TARGET", target,
              "You are not in that channel");
    return 0;
  }

  /* A msgid no store can hold (HISTORY_MSGID_LEN) names no message.  One
   * with a valid time prefix made the store's key builder fail, the lookup
   * read as a store error, and the "trust the client" branch below stored,
   * showed and relayed the REDACT with no authorization at all. */
  if (strlen(msgid) >= HISTORY_MSGID_LEN) {
    char fail_ctx[BUFSIZE];   /* spec: <target> <msgid> */
    ircd_snprintf(0, fail_ctx, sizeof(fail_ctx), "%s %s", target, msgid);
    send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fail_ctx, "Message not found");
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
      /* Not in this store.  A server stores only what reached it -- a
       * channel message reaches only the servers with a member -- so the
       * row may live on a storage peer: ask them (CH Q X), as a server
       * with no store does.  complete_redact_fed (m_chathistory.c)
       * authorizes under the same rule and answers the requester. */
      if (start_redact_fed_query(sptr, chptr, target, msgid, reason,
                                 is_chanop, is_oper) == 0)
        return 0;
      send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fail_ctx,
                "Message not found");
      return 0;
    } else if (rc < 0) {
      /* Database error - allow redaction anyway (trust client): fall
       * through to the store, fan-out and relay below. */
    } else {
      /* Found the message: the one authorization rule (redact_index.c). */
      struct redact_auth_in ai;
      char current_mask[HISTORY_SENDER_LEN];
      long window = 0;
      enum redact_auth verdict;

      ircd_snprintf(0, current_mask, sizeof(current_mask), "%s!%s@%s",
                    cli_name(sptr), cli_user(sptr)->username,
                    cli_user(sptr)->host);
      memset(&ai, 0, sizeof(ai));
      ai.msg_type = msg->type;
      ai.msg_time = (long)strtoul(msg->timestamp, NULL, 10);
      ai.now = (long)CurrentTime;
      ai.msg_account = msg->account;
      ai.msg_sender = msg->sender;
      ai.req_account = cli_user(sptr)->account;
      ai.req_mask = current_mask;
      ai.header_repaired = msg->header_repaired;
      ai.is_oper = is_oper;
      ai.is_chanop = is_chanop;
      ai.chanop_others = feature_bool(FEAT_REDACT_CHANOP_OTHERS);
      ai.window = feature_int(FEAT_REDACT_WINDOW);
      ai.oper_window = feature_int(FEAT_REDACT_OPER_WINDOW);
      verdict = redact_authorize(&ai, &window);

      if (verdict != REDACT_AUTH_OK) {
        history_free_messages(msg);
        if (verdict == REDACT_AUTH_NOT_MESSAGE)
          send_fail(sptr, "REDACT", "UNKNOWN_MSGID", fail_ctx, "Not a message");
        else if (verdict == REDACT_AUTH_EXPIRED) {
          char wctx[BUFSIZE];   /* spec: <target> <msgid> <window> */
          ircd_snprintf(0, wctx, sizeof(wctx), "%s %ld", fail_ctx, window);
          send_fail(sptr, "REDACT", "REDACT_WINDOW_EXPIRED", wctx,
                    "Redaction window has expired");
        } else
          send_fail(sptr, "REDACT", "REDACT_FORBIDDEN", fail_ctx,
                    "You are not authorized to redact this message");
        return 0;
      }

      /* Already redacted: the row is kept as a placeholder with a REDACT
       * context child (the spec's second option for history), so it still
       * exists and UNKNOWN_MSGID would be wrong.  Answer the requester as a
       * success -- a client that missed the first REDACT gets a consistent
       * reply -- but store no second context row and repeat nothing to the
       * channel or the network.  The spec is silent on repeats. */
      {
        /* The REDACT child itself (history_attach_context hangs the row's
         * context children after it), so the echo names that first
         * REDACT event: its msgid and time. */
        struct HistoryMessage *c;
        history_attach_context(target, msg);
        for (c = msg->next; c; c = c->next)
          if (c->is_context && c->type == HISTORY_REDACT)
            break;
        if (c) {
          if (feature_bool(FEAT_MSGID))
            sendcmdto_set_client_event(c->msgid, history_parse_ms(c->timestamp));
          redact_echo_requester(sptr, target, msgid, reason);
          sendcmdto_set_client_msgid(NULL);
          history_free_messages(msg);
          return 0;
        }
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
    uint64_t time_ms;

    generate_msgid(redact_msgid, sizeof(redact_msgid));
    time_ms = history_event_time_ms(NULL);   /* the msgid's own mint time (audit #16) */

    /* Store REDACT event in history */
    if (history_is_available()) {
      char timestamp[32];
      char sender[HISTORY_SENDER_LEN];
      char redact_content[512];
      char owner[HTC_OWNER_MAX];

      history_format_ms(timestamp, sizeof(timestamp), time_ms);
      ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                    cli_name(sptr), cli_user(sptr)->username,
                    cli_user(sptr)->host);

      if (reason && reason[0])
        ircd_snprintf(0, redact_content, sizeof(redact_content),
                      "%s :%s", msgid, reason);
      else
        ircd_snprintf(0, redact_content, sizeof(redact_content),
                      "%s", msgid);

      history_store_message(redact_msgid, timestamp, target, NULL, sender,
                            cli_user(sptr)->account[0] ? cli_user(sptr)->account : "",
                            HISTORY_REDACT, redact_content, NULL,
                            history_owner_of(owner, sizeof(owner), sptr));

      /* Write-forward to STORE servers if we're non-STORE.  The reason
       * is client-supplied: sentinel-escape it for the CH W payload. */
      if (chptr) {
        char fwd_content[sizeof(redact_content) * 2 + 1];
        history_forward_encode(fwd_content, sizeof(fwd_content), NULL,
                               redact_content);
        forward_history_write(chptr, sptr, redact_msgid, timestamp,
                              HISTORY_REDACT, fwd_content);
      }
    }

    /* Show it to the channel's members under the event's msgid and time */
    redact_announce_local(sptr, chptr, msgid, redact_msgid, time_ms, reason);

    /* Set S2S tags for server relay */
    sendcmdto_set_s2s_tags(time_ms, redact_msgid);
    sendcmdto_want_s2s_tags(1);

    /* Propagate to other servers */
    sendcmdto_serv_butone_v3(sptr, CMD_REDACT, cptr, "%s %s :%s",
                          target, msgid, reason ? reason : "");
  }

  return 0;
}

/** Judge one redaction against this server's store (rdx_row_decide): is
 * the message here, and does a REDACT row annotate it already?  Every
 * REDACT row that reaches this store from elsewhere is judged here: a
 * peer's live REDACT and a catch-up row (redact_apply_row), and a
 * write-forwarded one (process_write_forward, m_chathistory.c).
 * @param[in] target Channel name (store keys fold; the canonical spelling).
 * @param[in] msgid The redacted message.
 * @return An enum rdx_row value (redact_index.h).
 */
int redact_row_judge(const char *target, const char *msgid)
{
  struct HistoryMessage *m = NULL;
  int rc, redacted = 0;

  rc = history_lookup_message(target, msgid, &m);
  if (m)
    history_free_messages(m);
  /* A REDACT row annotates the message through the reply index whether or
   * not the message is here: a tombstone counts as applied. */
  if (rc >= 0)
    redacted = history_message_is_redacted(target, msgid);
  return rdx_row_decide(rc, redacted);
}

/** Apply a channel redaction that reached this server from elsewhere: a
 * peer's live REDACT (ms_redact, through redact_apply_remote) or a row of
 * the redaction catch-up (complete_redact_catchup, m_chathistory.c).
 *
 * The REDACT row is stored once, under the origin's redact_msgid and time
 * (one event, one msgid, one time), unless a REDACT row annotates the
 * message already (rdx_row_decide, redact_index.h):
 * - a message this store holds: the row annotates it (APPLY);
 * - a message this store does not hold (it never reached it, or the trim
 *   evicted it), an orphan: the row is kept as a TOMBSTONE (user decision
 *   2026-11-08), never in a +P channel -- see below;
 * - a repeat (two servers or two users redacting the same message, or a
 *   catch-up re-reading one already applied or tombstoned) stores no
 *   second row;
 * - a store that cannot be read stores nothing (RETRY).
 * The trim owns deletes; nothing here deletes.
 *
 * Who sees it: a live REDACT is shown to the channel's local members
 * whatever the store decided (@a show_always): live delivery is not the
 * store's business, and a member may hold the message from a federated
 * page this store never saw.  A catch-up row is shown only when it was
 * applied: a member here saw no orphan's message, and saw an applied
 * redaction already.
 * @param[in] src Who redacted (a remote client, or &me for a catch-up row).
 * @param[in] chptr Channel (its canonical name is the store key).
 * @param[in] msgid The redacted message.
 * @param[in] redact_msgid The REDACT event's msgid.
 * @param[in] time_ms The REDACT event's time (epoch ms).
 * @param[in] reason Reason (may be NULL).
 * @param[in] sender_str Stored redacter (catch-up); NULL derives it from @a src.
 * @param[in] account_str Stored redacter's account (catch-up); NULL derives it from @a src.
 * @param[in] show_always Nonzero: show it even when nothing was stored.
 * @return The store's decision, an enum rdx_row value (redact_index.h);
 *   RDX_ROW_SKIP_ORPHAN, storing nothing, when this server has no store.
 */
int redact_apply_row(struct Client *src, struct Channel *chptr,
                     const char *msgid, const char *redact_msgid,
                     uint64_t time_ms, const char *reason,
                     const char *sender_str, const char *account_str,
                     int show_always)
{
  /* Store keys are the canonical spelling (see m_redact). */
  const char *target = chptr->chname;
  enum rdx_row d = RDX_ROW_SKIP_ORPHAN;
  int store = 0;

  if (history_is_available()) {
    d = (enum rdx_row)redact_row_judge(target, msgid);
    /* An orphan's REDACT row is a TOMBSTONE: it annotates, through the
     * reply index, a message this store does not hold, so the message
     * stays hidden if it is stored here later.  That can happen: a
     * write-forward (CH W/WB) from a server with no store can arrive after
     * a REDACT of its message -- a leaf without a store forwards a message
     * it relayed back to its uplink, and a REDACT through that uplink can
     * get there first -- and a future backfill, import or replay would
     * store rows late too.  Sending the write-forward ahead of the
     * message's own relay (forward_channel_history, ircd_relay.c) narrows
     * the window on the sender's own link; it is a best effort, not an
     * invariant, so the tombstone is what keeps the message redacted.  A
     * tombstone also serves the catch-up index: a peer that holds the
     * message applies it from here.  No tombstone in a +P channel: no new
     * rows are stored there.  An APPLY is stored even in +P: it redacts a
     * row stored before +P was set, which would otherwise stay visible
     * (m_redact's own found path does the same). */
    store = d == RDX_ROW_APPLY
            || (d == RDX_ROW_SKIP_ORPHAN
                && !(chptr->mode.exmode & EXMODE_NOSTORAGE));
  }

  if (store) {
    char timestamp[32];
    char sender[HISTORY_SENDER_LEN];
    char redact_content[512];
    char owner[HTC_OWNER_MAX];

    /* Redact message: strip content but keep entry for context */
    if (d == RDX_ROW_APPLY)
      history_redact_message(target, msgid);

    ircd_snprintf(0, timestamp, sizeof(timestamp), "%llu.%03llu",
                  (unsigned long long)(time_ms / 1000),
                  (unsigned long long)(time_ms % 1000));

    if (sender_str && sender_str[0])
      ircd_strncpy(sender, sender_str, sizeof(sender));
    else if (cli_user(src))
      ircd_snprintf(0, sender, sizeof(sender), "%s!%s@%s",
                    cli_name(src), cli_user(src)->username,
                    cli_user(src)->host);
    else
      ircd_strncpy(sender, cli_name(src), sizeof(sender));

    if (reason && reason[0])
      ircd_snprintf(0, redact_content, sizeof(redact_content),
                    "%s :%s", msgid, reason);
    else
      ircd_snprintf(0, redact_content, sizeof(redact_content),
                    "%s", msgid);

    /* The row's trim owner: the redacter.  A catch-up row names it only
     * off the wire (@a account_str, its sender's server unknown here):
     * its account, else "-"; otherwise @a src, whose account it carries. */
    if (account_str) {
      if (htc_owner_key(owner, sizeof(owner), account_str, NULL, NULL) < 0)
        ircd_strncpy(owner, HTC_OWNER_NONE, sizeof(owner));
    } else
      history_owner_of(owner, sizeof(owner), src);

    history_store_message(redact_msgid, timestamp, target, NULL, sender,
                          account_str ? account_str
                          : ((cli_user(src) && cli_user(src)->account[0])
                             ? cli_user(src)->account : ""),
                          HISTORY_REDACT, redact_content, NULL, owner);
  }

  /* Show it to the channel's members under the event's msgid and time */
  if (show_always || d == RDX_ROW_APPLY)
    redact_announce_local(src, chptr, msgid, redact_msgid, time_ms, reason);
  return (int)d;
}

/** A peer's live REDACT (ms_redact): stored beside the message when this
 * store holds it, else as a tombstone (redact_apply_row); always shown to
 * the local members. */
void redact_apply_remote(struct Client *src, const char *target,
                         const char *msgid, const char *redact_msgid,
                         uint64_t time_ms, const char *reason)
{
  struct Channel *chptr;

  if (!IsChannelName(target) || !(chptr = FindChannel(target)))
    return;
  if (redact_apply_row(src, chptr, msgid, redact_msgid, time_ms, reason,
                       NULL, NULL, 1) == RDX_ROW_RETRY)
    log_write(LS_SYSTEM, L_NOTICE, 0,
              "REDACT %s %s from %s: the store could not be read; no REDACT row stored",
              chptr->chname, msgid, cli_name(src));
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
  if (IsChannelName(target) && (chptr = FindChannel(target))) {
    char redact_msgid[HISTORY_MSGID_LEN];
    uint64_t time_ms;

    target = chptr->chname;
    /* Use incoming S2S msgid for the REDACT event, or generate new */
    if (cli_s2s_msgid(cptr)[0])
      ircd_strncpy(redact_msgid, cli_s2s_msgid(cptr), sizeof(redact_msgid));
    else
      generate_msgid(redact_msgid, sizeof(redact_msgid));
    time_ms = history_event_time_ms(cptr);   /* origin tag time, else HLC */

    redact_apply_remote(sptr, target, msgid, redact_msgid, time_ms, reason);

    /* Set S2S tags for server relay */
    sendcmdto_set_s2s_tags(time_ms, redact_msgid);
    sendcmdto_want_s2s_tags(1);
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone_v3(sptr, CMD_REDACT, cptr, "%s %s :%s",
                        target, msgid, reason ? reason : "");

  return 0;
}
