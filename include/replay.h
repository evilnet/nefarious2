/*
 * IRC - Internet Relay Chat, include/replay.h
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
 * Modeled after the LIST async iterator (ListingArgs / list_next_channels),
 * this provides paced history delivery that pauses when sendQ reaches a
 * threshold and resumes when the ET_WRITE handler fires.
 *
 * Handles both single-batch CHATHISTORY commands and multi-channel bouncer
 * auto-replay.
 */
#ifndef INCLUDED_replay_h
#define INCLUDED_replay_h

#include "ircd_defs.h"
#include <time.h>

struct Client;
struct HistoryMessage;
struct HistoryTarget;

/** Maximum batch ID length (matches BATCH_ID_LEN in m_chathistory.c) */
#define REPLAY_BATCH_ID_LEN 16

/** Phases of a multi-channel bouncer replay */
enum ReplayPhase {
  REPLAY_PHASE_SINGLE   = 0,  /**< Single CHATHISTORY batch */
  REPLAY_PHASE_CHANNELS = 1,  /**< Iterating channel memberships */
  REPLAY_PHASE_PMS      = 2,  /**< Iterating PM targets */
  REPLAY_PHASE_DONE     = 3   /**< Cleanup pending */
};

/** Async replay state, stored on Connection (like ListingArgs for LIST).
 * Handles both single-batch CHATHISTORY and multi-channel bouncer replay.
 */
struct ReplayState {
  /* === Message-level iteration (current batch) === */
  struct HistoryMessage *messages;    /**< Owned linked list */
  struct HistoryMessage *current;     /**< Current send position */
  char target[CHANNELLEN + 1];       /**< Current batch target */
  char batch_id[REPLAY_BATCH_ID_LEN]; /**< Current batch ID */
  int batch_open;                     /**< Whether BATCH + has been sent */
  int ops_override;                   /**< Whether :full override active */
  char label[64];                     /**< Labeled-response label (first batch only) */
  int label_used;                     /**< Whether label was applied */

  /* === Multi-channel iteration (bouncer replay) === */
  enum ReplayPhase phase;
  char **chan_names;                  /**< Owned array of DupString'd channel names */
  int num_channels;                   /**< Array length */
  int chan_index;                      /**< Current position */
  int replay_limit;                   /**< Per-channel/PM message limit */
  time_t since_time;                  /**< Baseline for read marker comparison */
  char since_timestamp[32];          /**< Formatted "unix.000" string */
  int total_replayed;                 /**< Running total for summary */
  int chan_count;                      /**< Channels with messages */
  int pm_count;                       /**< PMs replayed */

  /* PM targets (bouncer replay) */
  struct HistoryTarget *pm_targets;  /**< Owned list (queried at PM phase start) */
  struct HistoryTarget *pm_cursor;   /**< Current PM target */
};

/* --- Public API --- */

/** Start async replay of a single chathistory batch.
 * Transfers ownership of messages to the ReplayState.
 * Cancels any existing replay on this client.
 * @param[in] sptr Client to send history to.
 * @param[in] target Channel or nick name.
 * @param[in] messages Linked list of messages (ownership transferred).
 * @param[in] count Number of messages (0 sends empty batch).
 * @param[in] ops_override Whether :full ops override is active.
 * @param[in] label Labeled-response label (may be NULL).
 */
extern void replay_start_batch(struct Client *sptr, const char *target,
                                struct HistoryMessage *messages, int count,
                                int ops_override, const char *label);

/** Start async bouncer auto-replay across all channels + PMs.
 * Builds channel name list from current memberships, starts replaying
 * from since_time.  Cancels any existing replay on this client.
 * @param[in] sptr Client to replay to.
 * @param[in] since_time Baseline timestamp for replay.
 * @param[in] limit Per-channel/PM message limit.
 */
extern void replay_start_bouncer(struct Client *sptr, time_t since_time,
                                  int limit);

/** Continue sending messages.  Called from ET_WRITE handler
 * and initially from replay_start_* functions.
 * Sends until sendQ threshold is reached, then returns.
 * Like list_next_channels() for LIST.
 * @param[in] sptr Client with active replay.
 */
extern void replay_continue(struct Client *sptr);

/** Cancel and clean up any in-progress replay.
 * Closes open batch, frees messages/channels/PMs.
 * Called on disconnect, new CHATHISTORY, new replay, etc.
 * @param[in] sptr Client to cancel replay for.
 */
extern void replay_cancel(struct Client *sptr);

/** Check if sendQ has room for more replay messages.
 * Uses FEAT_REPLAY_SENDQ_THRESHOLD (default 50% of limit).
 * Also used by federation replay paths and multiline echo.
 * @param[in] sptr Client to check.
 * @return Non-zero if OK to continue, zero if should pause.
 */
extern int sendq_replay_ok(struct Client *sptr);

#endif /* INCLUDED_replay_h */
