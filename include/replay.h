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
/** Flags for the `complete` argument of replay_start_batch and its
 * callers.  REPLAY_PARTIAL: a known storage server was away over the span
 * or a responder was cut; the opener carries
 * evilnet.github.io/chathistory-partial and never chathistory-end. */
#define REPLAY_COMPLETE 1
#define REPLAY_PARTIAL  2

/** chathistory_replay_channel_leg: the leg was federated; its page comes
 * through replay_leg_done (W5 Push F, I-2). */
#define REPLAY_LEG_PENDING (-2)

struct ReplayState {
  /* === Message-level iteration (current batch) === */
  struct HistoryMessage *messages;    /**< Owned linked list */
  struct HistoryMessage *current;     /**< Current send position */
  char target[CHANNELLEN + 1];       /**< BATCH target. Channel name for channel batches; the OTHER party's nick for PM batches (NOT the storage pair-key). */
  /** For PM batches: the other party's nick — used as the per-message
   * target for the replaying client's outgoing messages.  Empty for
   * channel batches (where target IS the per-message target). */
  char other_nick[CHANNELLEN + 1];
  /** 1 when the current batch is a PM batch (per-message target is
   * derived from msg->original_target / sender direction).  0 for
   * channel batches. */
  int is_pm;
  char batch_id[REPLAY_BATCH_ID_LEN]; /**< Current batch ID */
  int batch_open;                     /**< Whether BATCH + has been sent */
  int ops_override;                   /**< Whether :full override active */
  char label[64];                     /**< Labeled-response label (first batch only) */
  int label_used;                     /**< Whether label was applied */
  int is_last_page;                   /**< True if query returned fewer results than limit */
  /** The page's framing and contents, decided once and kept for the whole
   * page (a sendQ pause can leave it half sent across CAP changes): its
   * chathistory batch is sent when batch_framed (batch was active when it
   * opened), and its rows are filtered by type_mask, the row types the
   * page was READ with (chathistory_type_mask(): 0 = every type) -- so
   * what is sent matches what was counted for the page and its end tag. */
  int batch_framed;
  unsigned int type_mask;
  /** Whether this replay's pages are batch-framed at all: decided once,
   * when the state starts (the client holds batch), and cleared when the
   * client drops batch (replay_batch_drop()); a page's batch_framed
   * follows it, so a multi-page replay never sends a later page bare
   * inside a still-open outer batch. */
  int framed;
  int is_partial;                     /**< evilnet.github.io/chathistory-partial on the opener */

  /** A bouncer catch-up waiting for a federated channel leg (W5 Push F,
   * I-2): nothing is sent and no further channel is read until
   * replay_leg_done brings the leg whose number is leg_seq. */
  int leg_pending;
  unsigned long leg_seq;

  /** A bouncer catch-up suspended while this on-demand page is served;
   * reinstalled and continued when this state is freed (audit #26/#20:
   * the single slot used to CANCEL the catch-up on the client's first
   * own CHATHISTORY, silently dropping every later channel and PM). */
  struct ReplayState *resume;

  /* === Multi-channel iteration (bouncer replay) === */
  enum ReplayPhase phase;
  char **chan_names;                  /**< Owned array of DupString'd channel names */
  int num_channels;                   /**< Array length */
  int chan_index;                      /**< Current position */
  int replay_limit;                   /**< Per-channel/PM message limit */
  time_t since_time;                  /**< Baseline for read marker comparison */
  char since_timestamp[32];          /**< Formatted "unix.000" string */
  char since_msgid[64];               /**< Cursor row at since_timestamp
                                           (ATTACH cursor), else empty */
  int total_replayed;                 /**< Running total for summary */
  int chan_count;                      /**< Channels with messages */
  int pm_count;                       /**< PMs replayed */

  /* PM targets (bouncer replay) */
  struct HistoryTarget *pm_targets;  /**< Owned list (queried at PM phase start) */
  struct HistoryTarget *pm_cursor;   /**< Current PM target */

  /* === Outer batch for draft/persistence (bouncer replay only) === */
  char outer_batch_id[REPLAY_BATCH_ID_LEN]; /**< Outer batch id when wants_outer_batch */
  int outer_batch_open;                     /**< Whether outer BATCH + has been sent */
  int wants_outer_batch;                    /**< Client negotiated draft/persistence+batch */
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
                                int ops_override, const char *label,
                                int complete,
                               const char *requested, unsigned int type_mask);

/** Start async bouncer auto-replay across all channels + PMs.
 * Builds channel name list from current memberships, starts replaying
 * from since_time.  Cancels any existing replay on this client.
 * @param[in] sptr Client to replay to.
 * @param[in] since_time Baseline timestamp for replay.
 * @param[in] limit Per-channel/PM message limit.
 */
extern void replay_start_bouncer_at(struct Client *sptr,
                                    const char *since_timestamp,
                                    const char *since_msgid, int limit);
extern void replay_start_catchup(struct Client *sptr, time_t since_time,
                                 int limit);
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

/** Drop every replay of @a sptr (and any suspended behind it) without
 * anything on the wire: its socket is gone (a held ghost revived on a new
 * socket, bounce_revive()). */
extern void replay_forget(struct Client *sptr);

/** @a sptr drops batch (a CAP change, before its ACK): every history
 * batch its replays have open is ended now, innermost first -- the page's,
 * then the outer bouncer-replay batch, then those of a suspended catch-up
 * -- and the rest of each page, and every later page, goes out unframed
 * (chathistory's no-batch form), with the row types already decided. */
extern void replay_batch_drop(struct Client *sptr);

/** A federated catch-up leg's page arrived (m_chathistory.c's
 * complete_replay_leg; W5 Push F, I-2): @a msgs (@a count rows, owned from
 * here; NULL/0 for none) for channel @a target with @a flags
 * (REPLAY_COMPLETE / REPLAY_PARTIAL), for the catch-up of @a sptr waiting
 * on leg @a seq -- the active one, or one suspended behind an on-demand
 * page.  It is sent in the leg's place, in the same order and batching as
 * a local leg, and the catch-up goes on.  Freed when no such catch-up is
 * waiting (cancelled, replaced). */
extern void replay_leg_done(struct Client *sptr, unsigned long seq, const char *target,
                            struct HistoryMessage *msgs, int count, int flags,
                            unsigned int type_mask);

/** The row types a history page read now for @a sptr may carry, as a bit
 * mask over enum HistoryMessageType (0 = every type): the mask the walk
 * filters with (m_chathistory.c).  A page keeps the mask it was read with
 * (ReplayState.type_mask). */
extern unsigned int chathistory_type_mask(struct Client *sptr);

/** Name the other party of the PM pair key @a pair_key for @a sptr: the
 * live client on the other half's account, else the newest row's sender
 * as they last used it (own rows contribute their original target).
 * @return 1 and the nick in @a buf; 0 when there is nobody to name
 *         (the other half is a session id with no usable row) or the
 *         other party is a service bot. */
extern int replay_pm_display_nick(struct Client *sptr, const char *pair_key,
                                  char *buf, size_t buflen);

/** The reverse: the PM pair key of @a sptr's conversation whose other
 * party replay_pm_display_nick names @a nick -- how a departed
 * unauthenticated correspondent, listed by nick, is found again.
 * @return 1 and the pair key in @a out, else 0. */
extern int replay_pm_pair_for_nick(struct Client *sptr, const char *nick,
                                   char *out, size_t outsz);

/** replay_pm_pair_for_nick() for many nicks at once: the names of
 * @a sptr's newest stored PM pairs (the same REPLAY_PM_TARGETS_MAX, the
 * same order, the first pair per name), built once -- one page read per
 * pair -- instead of once per nick looked up.  Never NULL. */
struct PmNickMap;
extern struct PmNickMap *replay_pm_nick_map(struct Client *sptr);
/** The pair @a map names @a nick, as replay_pm_pair_for_nick() would.
 * @return 1 and the pair key in @a out, else 0. */
extern int replay_pm_nick_map_find(const struct PmNickMap *map, const char *nick,
                                   char *out, size_t outsz);
extern void replay_pm_nick_map_free(struct PmNickMap *map);

/** Check if sendQ has room for more replay messages.
 * Uses FEAT_REPLAY_SENDQ_THRESHOLD (default 50% of limit).
 * Also used by federation replay paths and multiline echo.
 * @param[in] sptr Client to check.
 * @return Non-zero if OK to continue, zero if should pause.
 */
extern int sendq_replay_ok(struct Client *sptr);

/** Is @a m a row @a sptr sent (by account when logged in, else by nick)?
 * Decides the wire target of a replayed or searched PM row. */
extern int pm_row_is_own(struct Client *sptr, const struct HistoryMessage *m);

#endif /* INCLUDED_replay_h */
