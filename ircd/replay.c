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
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
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
  const char *mynick = cli_name(cptr);
  size_t mynick_len, nick1_len;

  if (!colon)
    return 0;

  mynick_len = strlen(mynick);
  nick1_len = colon - target;

  if (nick1_len == mynick_len && ircd_strncmp(target, mynick, nick1_len) == 0)
    return 1;
  if (ircd_strcmp(colon + 1, mynick) == 0)
    return 1;

  return 0;
}

/** Open a chathistory batch for the current target.
 * Handles labeled-response on the first batch if applicable.
 * If is_last_page is set, includes @draft/chathistory-end tag
 * on the BATCH start line to signal no more pages available.
 */
static void replay_open_batch(struct Client *sptr, struct ReplayState *rs)
{
  generate_batch_id(rs->batch_id, sizeof(rs->batch_id), sptr);

  if (CapRecipientHas(sptr, CAP_BATCH)) {
    const char *end_tag = rs->is_last_page ? "draft/chathistory-end;" : "";

    if (!rs->label_used && rs->label[0] &&
        feature_bool(FEAT_CAP_labeled_response) &&
        CapRecipientHas(sptr, CAP_LABELEDRESP)) {
      sendrawto_one(sptr, "@%slabel=%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                    end_tag, rs->label, cli_name(&me), rs->batch_id, rs->target);
      cli_label_responded(sptr) = 1;
      rs->label_used = 1;
    } else if (rs->is_last_page) {
      sendrawto_one(sptr, "@draft/chathistory-end :%s " MSG_BATCH_CMD " +%s chathistory %s",
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
    sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", rs->batch_id);
  }
  rs->batch_open = 0;
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

      cmd = (msg->type <= HISTORY_REDACT) ? msg_type_cmd[msg->type] : "PRIVMSG";

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
    char marker_ts[32];
    struct HistoryMessage *messages = NULL;
    struct Channel *chptr;
    int count;

    rs->chan_index++;

    /* Verify channel still exists and user is still a member */
    chptr = FindChannel(channame);
    if (!chptr || !find_member_link(chptr, sptr))
      continue;

    /* Use read marker if it's ahead of the since time */
    if (IsAccount(sptr) &&
        metadata_readmarker_get(cli_account(sptr), channame, marker_ts) == 0 &&
        strcmp(marker_ts, rs->since_timestamp) > 0) {
      chan_since = marker_ts;
    }

    /* Query history */
    count = history_query_latest_after(channame, rs->replay_limit,
                                        chan_since, &messages);
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

    /* Query history */
    count = history_query_latest_after(tgt->target, rs->replay_limit,
                                        rs->since_timestamp, &messages);
    if (count <= 0 || !messages) {
      if (messages)
        history_free_messages(messages);
      continue;
    }

    /* Set up new batch.
     *
     * Storage key is the canonical pair "lowerNick:higherNick".  The
     * BATCH chathistory target on the wire must be the OTHER party's
     * nick (not the storage key), per the IRCv3 chathistory spec —
     * a literal `nick1:nick2` would not parse as a valid IRC target
     * and would render as a fractured query tab in IRCv3 clients.
     */
    {
      const char *colon = strchr(tgt->target, ':');
      const char *mynick = cli_name(sptr);
      size_t mynick_len = strlen(mynick);
      size_t nick1_len = colon ? (size_t)(colon - tgt->target) : 0;
      const char *other_nick;
      char other_nick_buf[CHANNELLEN + 1];

      if (colon && nick1_len == mynick_len &&
          ircd_strncmp(tgt->target, mynick, nick1_len) == 0) {
        /* Self is on the left of the pair; other party on the right. */
        other_nick = colon + 1;
      } else if (colon) {
        /* Self is on the right; other party on the left — copy out the
         * left half since it isn't NUL-terminated in the storage key. */
        size_t copy_len = nick1_len < sizeof(other_nick_buf)
                            ? nick1_len : sizeof(other_nick_buf) - 1;
        memcpy(other_nick_buf, tgt->target, copy_len);
        other_nick_buf[copy_len] = '\0';
        other_nick = other_nick_buf;
      } else {
        /* No colon — shouldn't happen for PM keys, but fall back
         * gracefully to the raw storage value. */
        other_nick = tgt->target;
      }

      ircd_strncpy(rs->target, other_nick, sizeof(rs->target));
      ircd_strncpy(rs->other_nick, other_nick, sizeof(rs->other_nick));
      rs->is_pm = 1;
    }

    rs->messages = messages;
    rs->current = messages;
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
                         int ops_override, const char *label)
{
  struct ReplayState *rs;

  /* Cancel any existing replay */
  if (cli_replay(sptr))
    replay_cancel(sptr);

  if (!messages || count == 0) {
    /* Send empty batch synchronously — always last page */
    char batchid[REPLAY_BATCH_ID_LEN];
    generate_batch_id(batchid, sizeof(batchid), sptr);

    if (CapRecipientHas(sptr, CAP_BATCH)) {
      /* Empty batch is always the last page — tag on BATCH start */
      if (label && label[0] && feature_bool(FEAT_CAP_labeled_response) &&
          CapRecipientHas(sptr, CAP_LABELEDRESP)) {
        sendrawto_one(sptr, "@draft/chathistory-end;label=%s :%s " MSG_BATCH_CMD " +%s chathistory %s",
                      label, cli_name(&me), batchid, target);
        cli_label_responded(sptr) = 1;
      } else {
        sendrawto_one(sptr, "@draft/chathistory-end :%s " MSG_BATCH_CMD " +%s chathistory %s",
                      cli_name(&me), batchid, target);
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
  ircd_strncpy(rs->target, target, sizeof(rs->target));
  rs->ops_override = ops_override;
  if (label && label[0])
    ircd_strncpy(rs->label, label, sizeof(rs->label));
  rs->phase = REPLAY_PHASE_SINGLE;

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
  struct ReplayState *rs;
  struct Membership *member;
  int count = 0;

  if (!feature_bool(FEAT_BOUNCER_AUTO_REPLAY))
    return;
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
  rs->replay_limit = (limit > 0) ? limit : feature_int(FEAT_BOUNCER_AUTO_REPLAY_LIMIT);
  if (rs->replay_limit <= 0)
    rs->replay_limit = 100;
  rs->since_time = since_time;
  ircd_snprintf(0, rs->since_timestamp, sizeof(rs->since_timestamp),
                "%lu.000", (unsigned long)since_time);

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
