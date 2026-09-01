/*
 * IRC - Internet Relay Chat, ircd/replay.c
 * Copyright (C) 2026 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief SendQ-aware async history replay iterator.
 *
 * Modeled after the LIST async iterator (hash.c list_next_channels()),
 * this provides paced history delivery that pauses when sendQ reaches
 * a threshold and resumes when the ET_WRITE handler fires.
 */

#include "config.h"

#include "replay.h"
#include "bouncer_session.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "chathistory_presence.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_relay.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "msgq.h"
#include "s_bsd.h"
#include "send.h"

#include <string.h>

/* These are defined in m_chathistory.c and made extern for replay use */
extern void send_history_message(struct Client *sptr, struct HistoryMessage *msg,
                                  const char *target, const char *outer_batchid,
                                  const char *time_str, const char *cmd);
extern int should_send_message_type(struct Client *sptr, enum HistoryMessageType type);
extern void generate_batch_id(char *buf, size_t buflen, struct Client *sptr);
extern void send_gap_marker(struct Client *sptr, const char *target,
                             const char *batchid, const char *time_str,
                             const char *msgid, const char *sender,
                             int count);
extern const char *msg_type_cmd[];

/** Check if a PM target name involves this client.
 * PM targets are stored as "nick1:nick2" in history.
 */
static int is_pm_target_for_client(const char *target, struct Client *cptr)
{
  const char *colon = strchr(target, ':');
  if (!colon)
    return 0;
  if (history_pm_identity_matches(cptr, target, (size_t)(colon - target)))
    return 1;
  if (history_pm_identity_matches(cptr, colon + 1, strlen(colon + 1)))
    return 1;
  return 0;
}

/* Recover the counterparty DISPLAY nick from the batch's messages.
 * `me` tiebreak uses current nick — display-only (access already
 * authorized), so a mutable nick is acceptable here.  Returns 1+fills
 * buf, else 0. */
static int pm_other_nick_from_messages(struct Client *sptr,
                                       const struct HistoryMessage *msgs,
                                       char *buf, size_t buflen)
{
  const char *me = cli_name(sptr);
  const struct HistoryMessage *m;
  for (m = msgs; m; m = m->next) {
    char snick[NICKLEN + 1];
    const char *bang = strchr(m->sender, '!');
    size_t n = bang ? (size_t)(bang - m->sender) : strlen(m->sender);
    if (n >= sizeof(snick)) n = sizeof(snick) - 1;
    memcpy(snick, m->sender, n);
    snick[n] = '\0';
    if (0 != ircd_strcmp(snick, me)) { ircd_strncpy(buf, snick, buflen); return 1; }
    if (m->original_target[0])       { ircd_strncpy(buf, m->original_target, buflen); return 1; }
  }
  return 0;
}

/** Translate a PM storage-key target ("nick1:nick2") into the wire
 * target (the OTHER party's nick) and stash both in the ReplayState.
 *
 * For channel targets (no ':' present) this is a no-op apart from
 * copying through `rs->target`.  For PMs it sets `rs->is_pm = 1`,
 * `rs->other_nick` = derived other party, `rs->target` =
 * `rs->other_nick`, so BATCH and per-message wire output never carry
 * the literal `nick1:nick2` storage key.
 *
 * Shared between the bouncer auto-replay path (replay_next_pm) and
 * the on-demand CHATHISTORY query path (replay_start_batch).
 */
static void replay_set_target_from_storage(struct Client *sptr,
                                            struct ReplayState *rs,
                                            const char *storage_target)
{
  const char *colon;
  const char *mynick;
  size_t mynick_len, nick1_len;
  const char *other_nick;
  char other_nick_buf[CHANNELLEN + 1];

  if (!storage_target || !*storage_target) {
    rs->target[0] = '\0';
    rs->other_nick[0] = '\0';
    rs->is_pm = 0;
    return;
  }

  colon = strchr(storage_target, ':');
  if (!colon || IsChannelName(storage_target)) {
    /* Channel target — pass through unchanged. */
    ircd_strncpy(rs->target, storage_target, sizeof(rs->target));
    rs->other_nick[0] = '\0';
    rs->is_pm = 0;
    return;
  }

  rs->is_pm = 1;
  if (pm_other_nick_from_messages(sptr, rs->messages,
                                  rs->other_nick, sizeof(rs->other_nick))) {
    /* real nick from the stream */
  } else {
    /* Empty batch: fall back to the non-caller identity half of the key.
     * May surface an account/session id on an EMPTY PM batch — cosmetic,
     * no content, never leaks the colon. */
    size_t left_len = (size_t)(colon - storage_target);
    if (history_pm_identity_matches(sptr, storage_target, left_len))
      ircd_strncpy(rs->other_nick, colon + 1, sizeof(rs->other_nick));
    else {
      size_t cl = left_len < sizeof(rs->other_nick) ? left_len
                                                    : sizeof(rs->other_nick) - 1;
      memcpy(rs->other_nick, storage_target, cl);
      rs->other_nick[cl] = '\0';
    }
  }
  ircd_strncpy(rs->target, rs->other_nick, sizeof(rs->target));
}

/** Lazily emit the outer evilnet.github.io/bouncer-replay batch on first
 * inner-batch open.  Only relevant when wants_outer_batch is set.
 * Suppressed for empty replays because no inner batch ever opens.
 */
static void replay_emit_outer_batch_if_needed(struct Client *sptr,
                                               struct ReplayState *rs)
{
  if (!rs->wants_outer_batch || rs->outer_batch_open)
    return;
  if (!CapRecipientHas(sptr, CAP_BATCH))
    return;
  generate_batch_id(rs->outer_batch_id, sizeof(rs->outer_batch_id), sptr);
  sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s evilnet.github.io/bouncer-replay",
                rs->outer_batch_id);
  rs->outer_batch_open = 1;
}

/** Open a chathistory batch for the current target.
 * Handles labeled-response on the first batch if applicable.
 * If is_last_page is set, includes @draft/chathistory-end tag
 * on the BATCH start line to signal no more pages available.
 * When wants_outer_batch is set, also emits the outer
 * `evilnet.github.io/bouncer-replay` batch lazily on the first inner
 * open and tags subsequent inner BATCH starts with @batch=<outer>.
 */
static void replay_open_batch(struct Client *sptr, struct ReplayState *rs)
{
  const char *outer_tag = "";
  char outer_buf[64];

  generate_batch_id(rs->batch_id, sizeof(rs->batch_id), sptr);

  replay_emit_outer_batch_if_needed(sptr, rs);

  if (rs->outer_batch_open) {
    ircd_snprintf(0, outer_buf, sizeof(outer_buf), "batch=%s;", rs->outer_batch_id);
    outer_tag = outer_buf;
  }

  if (CapRecipientHas(sptr, CAP_BATCH)) {
    const char *end_tag = rs->is_last_page ? "draft/chathistory-end;" : "";

    if (!rs->label_used && rs->label[0] &&
        feature_bool(FEAT_CAP_labeled_response) &&
        CapRecipientHas(sptr, CAP_LABELEDRESP)) {
      sendrawto_one(sptr, "@%s%slabel=%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                    outer_tag, end_tag, rs->label, cli_name(&me),
                    rs->batch_id, rs->target);
      cli_label_responded(sptr) = 1;
      rs->label_used = 1;
    } else if (rs->is_last_page || outer_tag[0]) {
      sendrawto_one(sptr, "@%s%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                    outer_tag,
                    rs->is_last_page ? "draft/chathistory-end" : "",
                    cli_name(&me), rs->batch_id, rs->target);
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s chathistory %s",
                    rs->batch_id, rs->target);
    }
  }
  rs->batch_open = 1;
}

/** Close the current chathistory batch. */
static void replay_close_batch(struct Client *sptr, struct ReplayState *rs)
{
  if (rs->batch_open && CapRecipientHas(sptr, CAP_BATCH)) {
    if (rs->outer_batch_open)
      sendrawto_one(sptr, "@batch=%s :%s " MSG_BATCH_CMD " -%s",
                    rs->outer_batch_id, cli_name(&me), rs->batch_id);
    else
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", rs->batch_id);
  }
  rs->batch_open = 0;
}

/** Close the outer bouncer-replay batch if it was opened. */
static void replay_close_outer_batch(struct Client *sptr, struct ReplayState *rs)
{
  if (!rs->outer_batch_open)
    return;
  if (CapRecipientHas(sptr, CAP_BATCH))
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", rs->outer_batch_id);
  rs->outer_batch_open = 0;
}

/** Send messages from the current batch until sendQ threshold is hit.
 * @return 1 if batch completed, 0 if paused for sendQ.
 */
static int replay_send_messages(struct Client *sptr, struct ReplayState *rs)
{
  char iso_time[32];
  const char *time_str;
  const char *cmd;
  const char *batchid;

  batchid = CapRecipientHas(sptr, CAP_BATCH) ? rs->batch_id : NULL;

  while (rs->current) {
    struct HistoryMessage *msg = rs->current;

    /* Filter events based on event-playback capability */
    if (!should_send_message_type(sptr, msg->type)) {
      rs->current = msg->next;
      continue;
    }

    /* Skip typing-only TAGMSGs (legacy data stored before typing filter) */
    if (msg->type == HISTORY_TAGMSG) {
      const char *tags = msg->client_tags[0] ? msg->client_tags
                       : (msg->dyn_content ? msg->dyn_content : msg->content);
      int dominated = 1;
      const char *tp = tags;
      if (!tags[0]) { dominated = 1; }
      else while (tp && *tp) {
        const char *sep = strchr(tp, ';');
        size_t tlen = sep ? (size_t)(sep - tp) : strlen(tp);
        if (tlen < 7 || strncmp(tp, "+typing", 7) != 0 ||
            (tlen > 7 && tp[7] != '=')) {
          dominated = 0;
          break;
        }
        tp = sep ? sep + 1 : NULL;
      }
      if (dominated) {
        rs->current = msg->next;
        continue;
      }
    }

    /* Convert Unix timestamp to ISO 8601 for @time= tag */
    if (history_unix_to_iso(msg->timestamp, iso_time, sizeof(iso_time)) == 0)
      time_str = iso_time;
    else
      time_str = msg->timestamp;

    /* Handle gap markers: collapse consecutive gaps from the same sender */
    if (msg->type == HISTORY_GAP) {
      int gap_count = 1;
      struct HistoryMessage *gap_start = msg;

      while (msg->next && msg->next->type == HISTORY_GAP &&
             ircd_strcmp(msg->sender, msg->next->sender) == 0) {
        msg = msg->next;
        gap_count++;
      }

      send_gap_marker(sptr, rs->target, batchid, time_str,
                       gap_start->msgid, gap_start->sender, gap_count);
      rs->current = msg->next;
      rs->total_replayed += gap_count;
    } else {
      const char *per_msg_target = rs->target;

      cmd = (msg->type <= HISTORY_MULTILINE) ? msg_type_cmd[msg->type] : "PRIVMSG";

      /* For PM batches, the BATCH-level target (rs->target = other party's
       * nick) is correct for the BATCH start line and for the replaying
       * client's outgoing messages, but incoming messages need the
       * client's own nick as the per-message PRIVMSG target.  Prefer the
       * stored original_target (set on new entries); fall back to
       * direction reconstruction from msg->sender for legacy entries
       * predating the original_target field.
       */
      if (rs->is_pm) {
        if (msg->original_target[0]) {
          per_msg_target = msg->original_target;
        } else {
          const char *bang = strchr(msg->sender, '!');
          size_t sender_nick_len = bang ? (size_t)(bang - msg->sender)
                                         : strlen(msg->sender);
          const char *mynick = cli_name(sptr);
          size_t mynick_len = strlen(mynick);

          if (sender_nick_len == mynick_len &&
              ircd_strncmp(msg->sender, mynick, sender_nick_len) == 0) {
            /* Outgoing — sender is the replaying client; recipient is
             * the other party. */
            per_msg_target = rs->other_nick;
          } else {
            /* Incoming — sender is the other party; recipient was self. */
            per_msg_target = mynick;
          }
        }
      }

      send_history_message(sptr, msg, per_msg_target, batchid, time_str, cmd);
      rs->current = msg->next;
      if (!msg->is_context)
        rs->total_replayed++;
    }

    /* Check sendQ threshold after each message */
    if (rs->current && !sendq_replay_ok(sptr))
      return 0;  /* Paused — will resume from ET_WRITE */
  }

  return 1;  /* Batch completed */
}

/** Advance to the next channel in a bouncer replay.
 * Queries history for each channel, skipping channels with no missed messages.
 * @return 1 if a new batch was started, 0 if channels exhausted.
 */
static int replay_next_channel(struct Client *sptr, struct ReplayState *rs)
{
  while (rs->chan_index < rs->num_channels) {
    const char *channame = rs->chan_names[rs->chan_index];
    const char *chan_since = rs->since_timestamp;
    struct HistoryMessage *messages = NULL;
    struct Channel *chptr;
    int count;

    rs->chan_index++;

    /* Verify channel still exists and user is still a member */
    chptr = FindChannel(channame);
    if (!chptr || !find_member_link(chptr, sptr))
      continue;

    /* NOTE: replay used to fast-forward past the account's READ MARKER
     * here ("don't re-send what was read").  Markers are account-global
     * and every device advances them, so a phone reattaching after a
     * day of desktop use replayed NOTHING for the whole day -- "history
     * skipped all day long activity" (Rubin, 2026-08-30).  Read-on-one-
     * device is not delivered-to-another: markers are unread-pointer
     * UX, not delivery accounting.  Replay everything since the
     * cursor/detach point; msgid-deduping clients drop true dupes. */

    /* Query one past the limit: an over-limit result means this leg is
     * TRUNCATED at the server cap.  A complete leg carries the
     * @draft/chathistory-end tag on its batch opener ("no more
     * pages"); a truncated leg withholds it so the client knows to
     * backfill via CHATHISTORY (#104 note; spec: Auto-replay
     * completeness).  The list is chronological (oldest first) of the
     * LATEST results, so the overflow extra is the head -- drop it to
     * keep exactly the limit-sized set the old query returned. */
    count = history_query_latest_after(channame, rs->replay_limit + 1,
                                        chan_since, &messages);
    if (count <= 0 || !messages) {
      if (messages)
        history_free_messages(messages);
      continue;
    }
    rs->is_last_page = 1;
    if (count > rs->replay_limit) {
      struct HistoryMessage *extra = messages;
      messages = messages->next;
      extra->next = NULL;
      history_free_messages(extra);
      count = rs->replay_limit;
      rs->is_last_page = 0;
    }

    /* Strict-presence: the bouncer auto-replay bypassed the presence
     * filter entirely -- a session that joined a channel yesterday
     * replayed it from its detach point days back.  Filter exactly
     * like the CHATHISTORY query paths do (no-op unless the feature
     * is on). */
    count = presence_filter_messages(sptr, channame, &messages, count, 0);
    if (count <= 0 || !messages) {
      if (messages)
        history_free_messages(messages);
      continue;
    }

    /* Set up new batch */
    rs->messages = messages;
    rs->current = messages;
    ircd_strncpy(rs->target, channame, sizeof(rs->target));
    rs->other_nick[0] = '\0';
    rs->is_pm = 0;
    rs->chan_count++;

    replay_open_batch(sptr, rs);
    return 1;
  }

  return 0;  /* No more channels */
}

/** Advance to the next PM target in a bouncer replay.
 * @return 1 if a new batch was started, 0 if PMs exhausted.
 */
static int replay_next_pm(struct Client *sptr, struct ReplayState *rs)
{
  while (rs->pm_cursor) {
    struct HistoryTarget *tgt = rs->pm_cursor;
    struct HistoryMessage *messages = NULL;
    int count;

    rs->pm_cursor = tgt->next;

    /* Check if this PM target involves us */
    if (!strchr(tgt->target, ':') || !is_pm_target_for_client(tgt->target, sptr))
      continue;

    /* Query history -- limit+1 truncation probe, same as the channel
     * leg: complete => @draft/chathistory-end on the opener, truncated
     * => tag withheld (drop the overflow head to keep the latest
     * limit-sized set). */
    count = history_query_latest_after(tgt->target, rs->replay_limit + 1,
                                        rs->since_timestamp, &messages);
    if (count <= 0 || !messages) {
      if (messages)
        history_free_messages(messages);
      continue;
    }
    rs->is_last_page = 1;
    if (count > rs->replay_limit) {
      struct HistoryMessage *extra = messages;
      messages = messages->next;
      extra->next = NULL;
      history_free_messages(extra);
      rs->is_last_page = 0;
    }

    /* Set up new batch.  Storage key is "lowerNick:higherNick" — the
     * wire target must be the OTHER party's nick.  Shared helper with
     * replay_start_batch ensures both auto-replay and on-demand
     * CHATHISTORY queries use the same translation.  rs->messages must
     * be populated BEFORE this call — replay_set_target_from_storage
     * derives the display nick from the message stream. */
    rs->messages = messages;
    rs->current = messages;
    replay_set_target_from_storage(sptr, rs, tgt->target);

    rs->pm_count++;

    replay_open_batch(sptr, rs);
    return 1;
  }

  return 0;  /* No more PMs */
}

/** Send the bouncer replay summary notice. */
static void replay_send_summary(struct Client *sptr, struct ReplayState *rs)
{
  if (rs->total_replayed > 0) {
    if (rs->pm_count > 0 && rs->chan_count > 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. Replayed %d message(s) from %d channel(s) and %d PM(s).",
                    sptr, rs->total_replayed, rs->chan_count, rs->pm_count);
    } else if (rs->pm_count > 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. Replayed %d message(s) from %d PM(s).",
                    sptr, rs->total_replayed, rs->pm_count);
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. Replayed %d message(s) from %d channel(s).",
                    sptr, rs->total_replayed, rs->chan_count);
    }
  } else {
    struct Membership *member;
    int total_chans = 0;

    for (member = cli_user(sptr)->channel; member; member = member->next_channel)
      total_chans++;
    if (total_chans > 0) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Session resumed. You are in %d channel(s). No missed messages.",
                    sptr, total_chans);
    }
  }

  /* Diagnostic: why did the previous connection end?  Holds destroy
   * the QUIT/notice trail, so this is the user's only view of it. */
  {
    const char *why = bounce_last_hold_reason(sptr);
    if (why)
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Previous disconnect: %s", sptr, why);
  }
}

/*
 * Public API
 */

/** Check if sendQ has room for more replay messages.
 * Uses FEAT_REPLAY_SENDQ_THRESHOLD (default 50% of limit).
 */
int sendq_replay_ok(struct Client *sptr)
{
  unsigned int threshold, current, limit;

  if (!MyConnect(sptr) || IsDead(sptr))
    return 0;

  threshold = feature_int(FEAT_REPLAY_SENDQ_THRESHOLD);
  if (threshold == 0)
    return 1;  /* protection disabled */

  current = MsgQLength(&(cli_sendQ(sptr)));
  limit = get_sendq(sptr);
  return (current <= (limit * threshold / 100));
}

/** Continue sending messages from an in-progress replay.
 * Called from ET_WRITE handler and from replay_start_* functions.
 * Like list_next_channels() for LIST.
 */
void replay_continue(struct Client *sptr)
{
  struct ReplayState *rs = cli_replay(sptr);

  if (!rs)
    return;

  /* Dead client — abort */
  if (IsDead(sptr)) {
    replay_cancel(sptr);
    return;
  }

  /* If we have messages queued, keep sending */
  if (rs->current) {
    if (!replay_send_messages(sptr, rs))
      return;  /* Paused for sendQ */

    /* Batch completed — close it */
    replay_close_batch(sptr, rs);

    /* Free the completed message list */
    if (rs->messages) {
      history_free_messages(rs->messages);
      rs->messages = NULL;
    }
    rs->current = NULL;
  }

  /* Single-batch mode — we're done */
  if (rs->phase == REPLAY_PHASE_SINGLE) {
    replay_cancel(sptr);
    return;
  }

  /* Multi-channel bouncer replay — advance to next target */
  for (;;) {
    if (rs->phase == REPLAY_PHASE_CHANNELS) {
      if (replay_next_channel(sptr, rs)) {
        /* New batch opened — send messages */
        if (!replay_send_messages(sptr, rs))
          return;  /* Paused for sendQ */

        /* Batch completed */
        replay_close_batch(sptr, rs);
        if (rs->messages) {
          history_free_messages(rs->messages);
          rs->messages = NULL;
        }
        rs->current = NULL;
        continue;  /* Try next channel */
      }

      /* Channels exhausted — move to PMs */
      if (feature_bool(FEAT_CHATHISTORY_PRIVATE) && IsAccount(sptr)) {
        char now_timestamp[HISTORY_TIMESTAMP_LEN];
        ircd_snprintf(0, now_timestamp, sizeof(now_timestamp), "%lu.000",
                      (unsigned long)CurrentTime);
        history_query_targets(rs->since_timestamp, now_timestamp, 50,
                              &rs->pm_targets);
        rs->pm_cursor = rs->pm_targets;
        rs->phase = REPLAY_PHASE_PMS;
      } else {
        rs->phase = REPLAY_PHASE_DONE;
      }
    }

    if (rs->phase == REPLAY_PHASE_PMS) {
      if (replay_next_pm(sptr, rs)) {
        /* New batch opened — send messages */
        if (!replay_send_messages(sptr, rs))
          return;  /* Paused for sendQ */

        /* Batch completed */
        replay_close_batch(sptr, rs);
        if (rs->messages) {
          history_free_messages(rs->messages);
          rs->messages = NULL;
        }
        rs->current = NULL;
        continue;  /* Try next PM */
      }

      /* PMs exhausted */
      rs->phase = REPLAY_PHASE_DONE;
    }

    if (rs->phase == REPLAY_PHASE_DONE) {
      /* Close the outer bouncer-replay batch before the summary NOTICE
       * so the user-facing summary lives outside the batch wrapper. */
      if (rs->outer_batch_open && !IsDead(sptr))
        replay_close_outer_batch(sptr, rs);
      replay_send_summary(sptr, rs);
      replay_cancel(sptr);
      return;
    }
  }
}

/** Start async replay of a single chathistory batch.
 * Transfers ownership of messages to the ReplayState.
 */
void replay_start_batch(struct Client *sptr, const char *target,
                         struct HistoryMessage *messages, int count,
                         int ops_override, const char *label, int complete)
{
  struct ReplayState *rs;
  /* Translate `target` (may be a PM storage key "nick1:nick2") to the
   * wire form (other party's nick).  Without this, on-demand
   * CHATHISTORY queries on PMs leak the storage-key colon into the
   * BATCH tag and every per-message PRIVMSG target — see project
   * memory project_pm_replay_storage_key_leak. */
  struct ReplayState tmp_rs;

  /* Cancel any existing replay */
  if (cli_replay(sptr))
    replay_cancel(sptr);

  /* Pre-translate the wire target for the empty-batch path which
   * doesn't allocate a full ReplayState. */
  memset(&tmp_rs, 0, sizeof(tmp_rs));
  replay_set_target_from_storage(sptr, &tmp_rs, target);

  if (!messages || count == 0) {
    /* Empty batch.  NOT inherently the last page: reply-side filters
     * (redact originals, cap-gated REDACT events, strict presence) can
     * empty a page whose QUERY was not exhausted -- claiming finality
     * there stopped paginators with history remaining.  Honor the
     * caller's query-exhaustion verdict. */
    char batchid[REPLAY_BATCH_ID_LEN];
    const char *end_pfx = complete ? "@draft/chathistory-end" : "";
    generate_batch_id(batchid, sizeof(batchid), sptr);

    if (CapRecipientHas(sptr, CAP_BATCH)) {
      if (label && label[0] && feature_bool(FEAT_CAP_labeled_response) &&
          CapRecipientHas(sptr, CAP_LABELEDRESP)) {
        sendrawto_one(sptr, "%s%slabel=%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                      complete ? end_pfx : "@", complete ? ";" : "",
                      label, cli_name(&me), batchid, tmp_rs.target);
        cli_label_responded(sptr) = 1;
      } else if (complete) {
        sendrawto_one(sptr, "%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                      end_pfx, cli_name(&me), batchid, tmp_rs.target);
      } else {
        sendrawto_one(sptr, ":%s " MSG_BATCH_CMD " +%s chathistory %s",
                      cli_name(&me), batchid, tmp_rs.target);
      }
      sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
    }

    if (messages)
      history_free_messages(messages);
    return;
  }

  rs = MyCalloc(1, sizeof(struct ReplayState));
  rs->messages = messages;
  rs->current = messages;
  replay_set_target_from_storage(sptr, rs, target);
  rs->ops_override = ops_override;
  if (label && label[0])
    ircd_strncpy(rs->label, label, sizeof(rs->label));
  rs->phase = REPLAY_PHASE_SINGLE;
  /* Single-shot on-demand query.  "No continuation" is NOT "history
   * exhausted": the old unconditional is_last_page=1 stamped EVERY
   * page final, so end-tag-honoring paginators stopped at filter-
   * shrunk pages with history remaining.  The caller judged
   * completeness on the raw pre-filter row count. */
  rs->is_last_page = complete ? 1 : 0;

  cli_replay(sptr) = rs;

  /* Open the batch */
  replay_open_batch(sptr, rs);

  /* Start sending immediately, update_write if we pause */
  if (!replay_send_messages(sptr, rs)) {
    /* Paused for sendQ — ET_WRITE will resume */
    update_write(sptr);
    return;
  }

  /* Completed synchronously */
  replay_close_batch(sptr, rs);
  replay_cancel(sptr);
}

/** Start async bouncer auto-replay across all channels + PMs.
 * Builds channel name list from current memberships.
 */
void replay_start_bouncer(struct Client *sptr, time_t since_time, int limit)
{
  char ts[32];

  if (since_time == 0)
    return;
  ircd_snprintf(0, ts, sizeof(ts), "%lu.000", (unsigned long)since_time);
  replay_start_bouncer_at(sptr, ts, limit);
}

/** Start a bouncer auto-replay from an explicit "sec.msec" timestamp
 * cursor (millisecond-precise — used by the ATTACH catch-up cursor,
 * where the anchor comes from the msgid index rather than a time_t).
 * Same semantics as replay_start_bouncer otherwise.
 */
void replay_start_bouncer_at(struct Client *sptr, const char *since_timestamp,
                             int limit)
{
  struct ReplayState *rs;
  struct Membership *member;
  time_t since_time;
  int count = 0;

  if (!feature_bool(FEAT_BOUNCER_AUTO_REPLAY))
    return;
  if (!since_timestamp || !since_timestamp[0])
    return;
  since_time = (time_t)strtoul(since_timestamp, NULL, 10);
  if (since_time == 0)
    return;

  /* Cancel any existing replay */
  if (cli_replay(sptr))
    replay_cancel(sptr);

  /* Count channels */
  for (member = cli_user(sptr)->channel; member; member = member->next_channel)
    count++;

  if (count == 0 && !feature_bool(FEAT_CHATHISTORY_PRIVATE))
    return;

  rs = MyCalloc(1, sizeof(struct ReplayState));
  rs->phase = REPLAY_PHASE_CHANNELS;
  /* Bouncer replay wraps in the evilnet.github.io/bouncer-replay outer
   * batch when the client has negotiated draft/persistence + batch.
   * The outer batch is emitted lazily on the first inner batch open so
   * empty replays don't ship an empty wrapper. */
  /* Cap gate is `batch` only.  Unknown batch types (including
   * vendor-scoped ones like evilnet.github.io/bouncer-replay) are
   * tolerated by the batch spec; clients that understand the type
   * use it for grouping semantics, others process inner messages
   * normally. */
  rs->wants_outer_batch = CapRecipientHas(sptr, CAP_BATCH);
  rs->replay_limit = (limit > 0) ? limit : feature_int(FEAT_BOUNCER_AUTO_REPLAY_LIMIT);
  if (rs->replay_limit <= 0)
    rs->replay_limit = 100;
  rs->since_time = since_time;
  ircd_strncpy(rs->since_timestamp, since_timestamp,
               sizeof(rs->since_timestamp));

  /* Copy channel names — safe across event loop iterations */
  if (count > 0) {
    int i = 0;
    rs->chan_names = MyCalloc(count, sizeof(char *));
    for (member = cli_user(sptr)->channel; member; member = member->next_channel) {
      DupString(rs->chan_names[i], member->channel->chname);
      i++;
    }
    rs->num_channels = count;
  }

  cli_replay(sptr) = rs;
  update_write(sptr);
  replay_continue(sptr);
}

/** Start the post-revive/attach catch-up replay: resolve the client's
 * PERSISTENCE ATTACH cursor (last-seen msgid) to a millisecond
 * timestamp via the global msgid index and replay from there;
 * without a cursor — or when the msgid is unknown/evicted — fall back
 * to the server-derived since_time.  On an unknown cursor the client
 * gets FAIL PERSISTENCE CURSOR_UNKNOWN (it converged, but should
 * consider a full resync) rather than a silent divergence.
 */
void replay_start_catchup(struct Client *sptr, time_t since_time, int limit)
{
  const char *cursor = cli_attach_cursor(sptr);

  if (cursor[0]) {
    char ts[HISTORY_TIMESTAMP_LEN];

    if (history_msgid_to_timestamp(cursor, ts) == 0) {
      replay_start_bouncer_at(sptr, ts, limit);
      return;
    }
    send_fail(sptr, "PERSISTENCE", "CURSOR_UNKNOWN", cursor,
              "Cursor msgid not found; replaying from last activity");
  }
  replay_start_bouncer(sptr, since_time, limit);
}

/** Cancel and clean up any in-progress replay.
 * Called on disconnect, new CHATHISTORY, new replay, etc.
 */
void replay_cancel(struct Client *sptr)
{
  struct ReplayState *rs = cli_replay(sptr);
  int i;

  if (!rs)
    return;

  /* Close open batch */
  if (rs->batch_open && !IsDead(sptr))
    replay_close_batch(sptr, rs);

  /* Close outer bouncer-replay wrapper if it was emitted */
  if (rs->outer_batch_open && !IsDead(sptr))
    replay_close_outer_batch(sptr, rs);

  /* Free message list */
  if (rs->messages)
    history_free_messages(rs->messages);

  /* Free channel names */
  if (rs->chan_names) {
    for (i = 0; i < rs->num_channels; i++)
      MyFree(rs->chan_names[i]);
    MyFree(rs->chan_names);
  }

  /* Free PM targets */
  if (rs->pm_targets)
    history_free_targets(rs->pm_targets);

  MyFree(rs);
  cli_replay(sptr) = NULL;
  update_write(sptr);
}
