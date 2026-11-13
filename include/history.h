/*
 * IRC - Internet Relay Chat, include/history.h
 * Copyright (C) 2024 Nefarious Development Team
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
 * @brief Message history storage declarations (LMDB backend).
 *
 * Implements IRCv3 draft/chathistory extension storage using LMDB for
 * fast, zero-copy reads with minimal memory footprint.
 *
 * Specification: https://ircv3.net/specs/extensions/chathistory
 * Capability: draft/chathistory
 */
#ifndef INCLUDED_history_h
#define INCLUDED_history_h

#include "ircd_defs.h"
#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct HistoryMessage;

/** Query-time row filter (presence-aware paging, 2026-09-02).
 *
 * Handed to history_query_*(); NULL means an unfiltered walk.  The walk
 * calls @a fn for every row it builds; rows the hook rejects are freed
 * and do NOT count toward the limit, so a page is @a limit VISIBLE rows
 * and "fewer than limit" means the walk was exhausted (unless
 * @a truncated is set).  The hook may name the nearest time in the walk
 * direction at which rows can become visible again; the walk then seeks
 * there instead of stepping through an invisible run. */
struct HistoryRowFilter {
  /** Return 1 to keep @a msg; 0 to skip it (optionally setting
   * *@a skip_to, epoch milliseconds, to seek to); -1 to skip it and stop the
   * walk because nothing further is visible in this direction. */
  int (*fn)(const struct HistoryMessage *msg, int reverse, void *ctx,
            int64_t *skip_to);
  void *ctx;
  /** Bit per HistoryMessageType the requester can receive; 0 = every
   * type.  Rows of other types are skipped INSIDE the walk (like hook
   * rejects, uncounted) instead of at send time, so a run of JOIN/PART
   * rows longer than the limit can no longer hand a client without
   * draft/event-playback an empty page while messages sit behind it
   * (2026-09-06). */
  unsigned int type_mask;
  /** Optional per-row veto applied after the type mask: return 1 to skip
   * the row (uncounted, no seek).  For content-level rejects such as
   * typing-only TAGMSG rows that should never consume a page slot. */
  int (*veto)(const struct HistoryMessage *msg, void *veto_ctx);
  void *veto_ctx;
  int scan_max;    /**< raw rows examined before giving up; 0 = default */
  int scanned;     /**< out: raw rows examined (kept + skipped) */
  int truncated;   /**< out: scan_max hit -- page may be incomplete */
};

/** Default raw-row scan cap for a filtered walk.  Boundary seeks keep
 * real walks far below this; it is the safety net against a hook that
 * never names a boundary. */
#define HISTORY_FILTER_SCAN_MAX 20000

struct Channel;
struct Client;

/** Maximum size of a message ID */
#define HISTORY_MSGID_LEN 64

/** Maximum size of a timestamp string (Unix timestamp with milliseconds) */
#define HISTORY_TIMESTAMP_LEN 20

/** Maximum size of sender string (nick!user@host) */
#define HISTORY_SENDER_LEN (NICKLEN + USERLEN + HOSTLEN + 3)

/** Maximum size of message content in HistoryMessage struct.
 * Matches default FEAT_MULTILINE_MAX_BYTES; content exceeding this
 * is truncated on deserialization (not dropped).
 */
#define HISTORY_CONTENT_LEN 4096

/** Stack buffer size for serialized history values.
 * Used as fast-path for common single-line messages.
 * Larger content (multiline) uses dynamic allocation.
 */
#define HISTORY_VALUE_BUFSIZE 1024

/** Message types for history storage */
enum HistoryMessageType {
  HISTORY_PRIVMSG = 0,
  HISTORY_NOTICE  = 1,
  HISTORY_JOIN    = 2,
  HISTORY_PART    = 3,
  HISTORY_QUIT    = 4,
  HISTORY_KICK    = 5,
  HISTORY_MODE    = 6,
  HISTORY_TOPIC   = 7,
  HISTORY_TAGMSG  = 8,
  HISTORY_GAP     = 9,  /**< Message not stored (sender opted out via +Y/+y) */
  HISTORY_NICK    = 10, /**< Nick change event */
  HISTORY_REDACT  = 11, /**< Message redaction event */
  HISTORY_MULTILINE = 12 /**< Multiline placeholder: real content lives in
                          *   the ml_content store keyed by msgid.  The
                          *   record type (not in-band content bytes) is
                          *   what marks a record as multiline, so client
                          *   message bytes can never forge one. */
  ,HISTORY_TYPE_COUNT       /**< one past the last type (for masks) */
};

/** Is @a type a row type this server knows?  A row's type can come from
 * another server (CH R / B) or from stored data: it is checked where a
 * row comes in (hm_leg_add(), add_fed_child(), the record decoder) and
 * before it is ever used as a shift count or an index. */
static inline int history_type_valid(int type)
{
  return (unsigned int)type < (unsigned int)HISTORY_TYPE_COUNT;
}

/** Does a row of @a type pass the type mask @a mask (0 = every type)?  A
 * type out of range never does -- shifting by it is undefined. */
static inline int history_type_wanted(unsigned int mask, int type)
{
  return history_type_valid(type) && (!mask || (mask & (1u << type)));
}

/** Stored message for chathistory retrieval.
 * This structure is used both for storage and for returning
 * query results to the caller.
 */
struct HistoryMessage {
  char msgid[HISTORY_MSGID_LEN];       /**< Unique message ID */
  char timestamp[HISTORY_TIMESTAMP_LEN]; /**< Unix timestamp (seconds.milliseconds) */
  char target[CHANNELLEN + 1];         /**< Storage key: channel name or PM pair "nick1:nick2" */
  /** For PMs: the actual recipient nick at send time (one of the two
   * parties in `target`). Empty for channel messages (target IS the
   * recipient).  Also empty when reading legacy entries stored before
   * this field was added — callers must derive from sender direction
   * in that case. */
  char original_target[CHANNELLEN + 1];
  char sender[HISTORY_SENDER_LEN];     /**< nick!user@host of sender */
  char account[ACCOUNTLEN + 1];        /**< Sender's account name (or empty) */
  enum HistoryMessageType type;        /**< Message type */
  char content[HISTORY_CONTENT_LEN];   /**< Message content (inline, single-line) */
  char client_tags[512];               /**< Client-only tags (+reply=msgid, +draft/react, etc.) */
  char *dyn_content;                   /**< Resolved multiline content (MyMalloc'd, caller frees) */
  size_t dyn_content_len;              /**< Length of dyn_content */
  unsigned char *raw_content;          /**< Raw compressed content (for federation passthrough) */
  size_t raw_content_len;              /**< Length of raw_content */
  struct HistoryMessage *next;         /**< Next in linked list (for results) */
  int is_context;                      /**< Non-zero if draft/chathistory-context message */
  char ctx_parent[HISTORY_MSGID_LEN];  /**< Federated context child: parent msgid (else empty) */
  /** history_attach_context could not read one of this row's children (a
   * read error, an undecodable record, a walk cut short): it may be
   * redacted, so the page's redaction filter hides it (fail closed; W5
   * Task 15 fix round 1).  In memory only, never stored. */
  int ctx_unread;
  /** Channel incarnation the row belongs to: the channel's creationtime
   * at store time (0 = stamped before 2026-09-08, counts as current).
   * A channel recreated on the losing side of a split is a different
   * incarnation and its rows are not the surviving channel's history. */
  time_t incarnation;
  /** Non-zero when the stored header was found shifted by a '|' an older
   * binary left raw in the nick or username (history_split_header):
   * the sender was re-split, or kept as read, and the account is empty
   * because none could be trusted.  An empty account here is NOT proof
   * the sender was unauthenticated, so nothing may stand the sender
   * mask in for it (m_redact's mask fallback skips such rows). */
  int header_repaired;
};

/** Target info for CHATHISTORY TARGETS query. */
struct HistoryTarget {
  char target[CHANNELLEN + 1];         /**< Channel name or nick */
  char last_timestamp[HISTORY_TIMESTAMP_LEN]; /**< Time of last message */
  struct HistoryTarget *next;          /**< Next in linked list */
};

/** Query direction for history lookups. */
enum HistoryDirection {
  HISTORY_DIR_BEFORE = 0,  /**< Messages before reference */
  HISTORY_DIR_AFTER  = 1,  /**< Messages after reference */
  HISTORY_DIR_AROUND = 2,  /**< Messages around reference */
  HISTORY_DIR_LATEST = 3   /**< Most recent messages */
};

/** Reference type for history queries. */
enum HistoryRefType {
  HISTORY_REF_TIMESTAMP = 0,  /**< Reference by timestamp */
  HISTORY_REF_MSGID     = 1,  /**< Reference by message ID */
  HISTORY_REF_NONE      = 2   /**< No reference (for LATEST *) */
};

/** Initialize the history subsystem.
 * Opens or creates the LMDB database at the specified path.
 * @param[in] dbpath Path to the database directory.
 * @return 0 on success, -1 on error.
 */
extern int history_init(const char *dbpath);

/** Shutdown the history subsystem.
 * Closes the LMDB environment and frees resources.
 */
extern void history_shutdown(void);

/** Store a message in the history database.
 * @param[in] msgid Unique message ID.
 * @param[in] timestamp Unix timestamp (seconds.milliseconds as string).
 * @param[in] target Storage key (channel name or PM pair "nick1:nick2").
 * @param[in] original_target For PMs: actual recipient nick at send time.
 *   Pass NULL for channel messages (target IS the recipient).
 * @param[in] sender Full sender mask (nick!user@host).
 * @param[in] account Sender's account name (may be NULL).
 * @param[in] type Message type.
 * @param[in] content Message content (may be NULL for some types).
 * @param[in] client_tags Client-only tags to keep with the row (may be NULL).
 * @param[in] owner The row's trim owner key (history_owner_of, or
 *   htc_owner_key for a sender known only off the wire); NULL = "-".
 * @return 0 on success, -1 on error (including a row the trim index
 *   cannot hold).
 */
extern int history_store_message(const char *msgid, const char *timestamp,
                                  const char *target, const char *original_target,
                                  const char *sender, const char *account,
                                  enum HistoryMessageType type,
                                  const char *content, const char *client_tags,
                                  const char *owner);

/** Store a multiline message with content in the unified content store.
 * Content is stored separately in ml_content, and the history entry stores
 * a compact reference (\x1Eml sentinel). Both are written atomically.
 * @param[in] msgid        Base message ID.
 * @param[in] timestamp    Unix timestamp string.
 * @param[in] target       Channel or nick.
 * @param[in] sender       Full sender mask (nick!user@host).
 * @param[in] account      Sender's account name (may be NULL).
 * @param[in] content      Multiline content (\x1F-separated lines).
 * @param[in] content_len  Length of content.
 * @param[in] paste_secret Paste secret for URL access (NULL to skip).
 * @param[in] owner The row's trim owner key (as history_store_message).
 * @return 0 on success, -1 on error.
 */
extern int history_store_multiline(const char *msgid, const char *timestamp,
                                   const char *target, const char *original_target,
                                   const char *sender, const char *account,
                                   const char *content,
                                   size_t content_len, const char *paste_secret,
                                   const char *owner);

/** The trim owner key of a row @a sptr sends: "-" for NULL; a server
 * (or this server) -> "s:<server name>"; a user -> htc_owner_key(its
 * account, its IP, its server's name): "a:<account>", else "i:<IP
 * bucket>", else "s:<its server>".  Never a nick or a session id.
 * @return @a buf (always NUL-terminated; "-" if the key does not fit). */
extern const char *history_owner_of(char *buf, size_t size, struct Client *sptr);

/** Start the trimmer (main thread, after history_init, before the event
 * loop): the index-gap check (htrim_check_index_gap, with rows stamped up
 * to two maintenance intervals ahead counted), then the slice timer.
 * @return the newest last-activity stamp across every stored target, in
 * epoch ms (0 when the store is empty or unavailable) -- proof of life
 * for the presence boot-close: the server was alive when it stored that
 * row.  The gap check's walk of the targets CF reads it. */
extern uint64_t history_trim_start(void);

/** One trim slice under the live features; re-arms the 1 s slice timer
 * while work remains (and after a failed slice, up to 5 in a row).
 * @a pass_start marks the start of a pass: age-out opens a pass where its
 * walk stopped, or back at the oldest row indexed behind that point since
 * (htrim_pass_start).  A slice that finished the backfill with the logical
 * total over the cap's high watermark also warns the operators
 * (SNO_OLDSNO): eviction inside retention starts next. */
extern void history_trim_tick(int pass_start);

/** Make the next 1 s tick a pass start (a retention change: age-out
 * walks on under the new cutoff). */
extern void history_trim_kick(void);

/** CHATHISTORY_TRIM_SLICE_MS changed: the longest slice so far was
 * measured under the old budget (STATS max goes back to 0). */
extern void history_trim_slice_budget_changed(void);

/** The retention this store really covers, in days -- what CH A S / CH A
 * R tell peers: CHATHISTORY_RETENTION, but never further back than the
 * coverage floor oldest-overall eviction left inside it (rows older than
 * the floor may be gone), and then at least 1
 * (htc_effective_days(CHATHISTORY_RETENTION, htrim_coverage_floor_ms(),
 * now)).  Without a floor it is the configured value itself (0 =
 * unlimited, as peers read it).  Client ISUPPORT keeps the configured
 * value. */
extern int history_coverage_days(void);

/** Called on the main thread, outside any store, when
 * history_coverage_days() may have changed: a trim slice moved or cleared
 * the coverage floor, and every trim pass start (the floor ages a day).
 * It may send to peers. */
typedef void (*history_coverage_cb)(void);

/** Register the coverage callback (NULL = none). */
extern void history_set_coverage_callback(history_coverage_cb cb);

/* ---------------------------------------------------------------- */
/* Receive windows (W5 Task 9, D2 = B)                                */
/*                                                                    */
/* P10 relays a channel's messages only toward links with members     */
/* behind them, so this server holds a channel's messages only for    */
/* the time it had a local member there.  Per channel, the recv_windows */
/* CF (key: the folded name, as the targets CF) holds those windows   */
/* (chathistory_recv.h's rcv_* record), and a channel page federates  */
/* when the span it claims is not inside one of them.                 */
/* ---------------------------------------------------------------- */

struct Channel;

/** "Now" for the receive windows, epoch ms: the HLC's physical time, never
 * behind the wall clock (the time every stored row is stamped against). */
extern uint64_t history_recv_now_ms(void);

/** A local member joined or left @a chptr, or changed what it is relayed
 * (+d, its first or last positive SILENCE mask) (channel.c's hooks, called
 * only for a member with MyConnect: a remote member, a remote alias
 * membership included, never changes what this server receives), or an
 * input of the storage rule's channel half changed (W5 Task 13, R43: the
 * authenticated-member count crossing 0, ±H, ±P, the
 * CHATHISTORY_REQUIRE_AUTH feature).  Opens or closes the channel's window
 * when channel_has_local_member() AND channel_store_open() changed against
 * chptr->recv_open -- a read-modify-write of its record, clipped at the
 * local floor; nothing else is written.  An open starts at the channel's
 * creation when this very join created it, only the joiner's session is
 * there (nobody could have spoken there before) and the store has kept the
 * channel's rows since (chptr->recv_shut clear), else RCV_CLOSE_SLACK_MS
 * after now (a relay in flight before the JOIN reached its sender is not
 * routed here); a close ends RCV_CLOSE_SLACK_MS before now.  Does nothing
 * before history_recv_link_up() but note a refusing store (recv_shut). */
extern void history_recv_update(struct Channel *chptr);

/** history_recv_update() over every channel, every changed record in one
 * write batch: CHATHISTORY_REQUIRE_AUTH was set or reset (its feature
 * notify; R43). */
extern void history_recv_recheck_all(void);

/** The first storage peer's burst after boot has ended (m_chathistory.c's
 * ad_store_back): open, RCV_CLOSE_SLACK_MS after now, the window of every
 * channel with a local member.  Until then this server has not received
 * that peer's side and no window opens.  Later calls do nothing. */
extern void history_recv_link_up(void);

/** How many storage peers are linked and caught up here right now
 * (m_chathistory.c, at every change: a store back after its burst, a store
 * gone).  While one is, the receive windows' meta row recv_peer (W5 Push F,
 * I-1) holds now: written at once when the count turns non-zero, then with
 * every heartbeat. */
extern void history_recv_peers_linked(int n);

/** W5 Push F, I-1: a storage peer this server has had is not back yet since
 * it started.  1 before the first storage peer's burst after boot has ended
 * (history_recv_link_up) when the recv_peer meta row says this server had
 * one linked at some time, and that time is still within this store's
 * floor as it is now (history_live_floor_ms(); none: always) -- the absence
 * table lives in memory, so after a restart this is the only sign that a
 * page over a span never received here may be missing a peer's rows.  0
 * for a server that never had a storage peer, and once one is back. */
extern int history_recv_peer_missing(void);

/** @a chptr took another incarnation's TS -- it lost its TS in a burst
 * (m_burst.c's incarnation prune), arrived new in a burst, or a CREATE,
 * JOIN or MODE moved it: the history of that incarnation was never received
 * here.  Delete the record; reopen it RCV_CLOSE_SLACK_MS after now when a
 * window was open (local members stay). */
extern void history_recv_reset(struct Channel *chptr);

/** @a chptr was renamed in place from @a oldname (channel.c's
 * rename_channel; rows stay under the old name): close the old name's
 * window and open the new name's. */
extern void history_recv_rename(struct Channel *chptr, const char *oldname);

/** Did this server receive channel @a chname's traffic over the whole of
 * [@a lo_ms, @a hi_ms] (epoch ms)?  1 when one window holds it (a closed
 * interval of the record, or this run's open window as memory has it:
 * chptr->recv_open from chptr->recv_open_since -- never the record's own
 * open_since, which a failed write can leave stale); 0 when not,
 * when nothing is recorded or the record cannot be read, and when @a lo_ms
 * is at or below history_local_floor_ms() (rows there may be gone,
 * whatever the record says). */
extern int history_recv_covers(const char *chname, uint64_t lo_ms, uint64_t hi_ms);

/** The newest time whose rows this store may no longer hold, epoch ms
 * (rcv_clip's "at or before"): the later of the trim's coverage floor
 * (htrim_coverage_floor_ms(): the newest ms oldest-overall and emergency
 * eviction deleted) and, when CHATHISTORY_RETENTION is set, one ms before
 * now minus that many days (age-out deletes what is strictly older;
 * CurrentTime-based) -- never lower than the highest such floor this store
 * has applied (its high-water mark, kept across restarts: R40), so a
 * raised retention, retention 0 or a clock stepped back never lowers it
 * below rows already deleted.  A run never raises it past now (R41/R42: a
 * floor past now raises it only to now, logged once per episode), and a
 * stored mark beyond the last run's heartbeat (plus slack) and this run's
 * now is cut at boot as corrupt; one above a clock that is behind is kept;
 * 0 = no floor yet. */
extern uint64_t history_local_floor_ms(void);

/** The floor as it is now, without the high-water mark: the later of the
 * trim's coverage floor and the live retention's horizon (the pre-R40
 * history_local_floor_ms()).  Only for the absence age-out
 * (m_chathistory.c): the mark can sit above what was really deleted, and
 * an absence kept longer only adds fan-out (R41). */
extern uint64_t history_live_floor_ms(void);

/** Boot (ircd.c, before any client or link): every window the last run left
 * open -- a crash, or a clean DIE/RESTART, which closes the stores before
 * clients leave -- is closed at the windows' heartbeat (the last time a
 * build that keeps them was running) less RCV_CLOSE_SLACK_MS, or dropped
 * when there is no heartbeat; every record is clipped at the local floor,
 * and one left with no interval is deleted. */
extern void history_recv_boot(void);

/** The receive windows' heartbeat (a meta row in recv_windows): ircd.c's
 * minute timer, and history_shutdown. */
extern void history_recv_alive_tick(void);

/** STATS chathistory: "Federation: started N (unreceived N, short N,
 * absence N, context N), slot misses N, window misses N" (m_chathistory.c;
 * window misses: pages federated for their context only whose peers held
 * a row inside the page's own received span that this store lacks -- a
 * sign, not proof, of a wrong window; not counted when the peers' walks
 * were wider: strict presence with a requester that has no account). */
extern void chathistory_fed_report(struct Client *to);

#ifdef USE_ROCKSDB
struct db_env;
/** Get the history storage environment (for subsystems that share it). */
extern struct db_env *history_get_env(void);
#endif

/** Check if a message ID already exists in the history database.
 * Used for deduplication in CH W (write forwarding).
 * @param[in] msgid Message ID to check.
 * @return 1 if msgid exists, 0 if not found, -1 on error.
 */
extern int history_has_msgid(const char *msgid);

/** Query messages before a reference point.
 * @param[in] target Channel or nick to query.
 * @param[in] ref_type Type of reference.
 * @param[in] reference Timestamp or msgid string.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_before(const char *target, enum HistoryRefType ref_type,
                                 const char *reference, int limit,
                                 struct HistoryMessage **result,
                                 struct HistoryRowFilter *filter);

/** Query messages after a reference point.
 * @param[in] target Channel or nick to query.
 * @param[in] ref_type Type of reference.
 * @param[in] reference Timestamp or msgid string.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_after(const char *target, enum HistoryRefType ref_type,
                                const char *reference, int limit,
                                struct HistoryMessage **result,
                                struct HistoryRowFilter *filter);

/** Query the most recent messages.
 * @param[in] target Channel or nick to query.
 * @param[in] ref_type Type of reference (use HISTORY_REF_NONE for *).
 * @param[in] reference Timestamp or msgid string (ignored if ref_type is NONE).
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_latest(const char *target, enum HistoryRefType ref_type,
                                 const char *reference, int limit,
                                 struct HistoryMessage **result,
                                 struct HistoryRowFilter *filter);

/** Query the most recent messages, but no older than a floor timestamp.
 * Walks backward from the end of the target's history, collecting up to
 * \a limit messages, stopping if it reaches \a after_timestamp.
 * Returns results in chronological order (oldest first).
 * @param[in] target Channel or nick to query.
 * @param[in] limit Maximum messages to return.
 * @param[in] after_timestamp Floor timestamp (Unix or ISO 8601); messages
 *            at or before this time are excluded.
 * @param[in] after_msgid Optional msgid of the row AT the floor
 *            timestamp: the floor becomes that full row key, so rows in
 *            the same millisecond that sort after it are included and
 *            the row itself (and its earlier same-ms siblings) is not.
 *            NULL/empty = exclude the whole floor millisecond.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_latest_after(const char *target, int limit,
                                       const char *after_timestamp,
                                       const char *after_msgid,
                                       struct HistoryMessage **result,
                                       struct HistoryRowFilter *filter);

/** Query messages around a reference point: up to limit/2 rows before
 * it, the reference row itself when it is a msgid this target holds (and
 * the filter keeps), and the rest of the limit after it.
 * @param[in] target Channel or nick to query.
 * @param[in] ref_type Type of reference.
 * @param[in] reference Timestamp or msgid string.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @param[out] exhausted If non-NULL: 1 when both walks ran out before
 *             their limits -- nothing more lies on either side, the page
 *             is the last one -- else 0 (a full side may have more).  The
 *             filter's scan cap is not included.
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_around(const char *target, enum HistoryRefType ref_type,
                                 const char *reference, int limit,
                                 struct HistoryMessage **result,
                                 struct HistoryRowFilter *filter,
                                 int *exhausted);

/** Direction BETWEEN would walk for these selectors: 1 = descending
 * (first selector newer), 0 = ascending, -1 = a msgid selector could not
 * be resolved.  Shared by the walk, the federation origin's merge trim
 * and the responder's overflow trim so all three agree. */
extern time_t history_live_incarnation(const char *target);
extern int history_purge_incarnation(const char *channel, time_t incarnation);
extern int history_between_descending(const char *target,
                                      enum HistoryRefType ref_type1, const char *reference1,
                                      enum HistoryRefType ref_type2, const char *reference2);

/** Query messages between two reference points.
 * @param[in] target Channel or nick to query.
 * @param[in] ref_type1 Type of first reference.
 * @param[in] reference1 First timestamp or msgid.
 * @param[in] ref_type2 Type of second reference.
 * @param[in] reference2 Second timestamp or msgid.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_between(const char *target,
                                  enum HistoryRefType ref_type1, const char *reference1,
                                  enum HistoryRefType ref_type2, const char *reference2,
                                  int limit, struct HistoryMessage **result,
                                  struct HistoryRowFilter *filter);

/** Per-target keep/skip hook for history_identity_pm_targets: 1 keeps
 * the target, 0 skips it (it then never counts toward the limit). */
typedef int (*history_target_filter_fn)(const char *target, const char *last_ts,
                                        void *ctx);

/** The latest stamp held for one target (the targets index; W5 Task 11:
 * TARGETS reads the requester's own targets one by one instead of walking
 * every target on the server).
 * @param[in] target Channel name or PM pair key (any case).
 * @param[out] ts Its stamp, "sec.mmm".
 * @return 0 found, 1 none, -1 on a storage error. */
extern int history_target_latest(const char *target, char *ts, size_t tslen);

/** Did this start's PM pair index rebuild complete (pm_pair_index.h)?
 * When not, the index may lack pairs until a later start's rebuild does,
 * and TARGETS answers partial wherever it lists PM conversations.
 * @return 1 whole, 0 not (or no store). */
extern int history_pm_index_whole(void);

/** The PM pairs @a identity (an account, or a session id) is a half of,
 * through the pair index (pm_pair_index.h), with their stamps: those whose
 * stamp is above @a lo_ms (exclusive) and -- unless @a include_newer --
 * below @a hi_ms (exclusive), compared as integers; @a filter applied;
 * newest first; at most @a max (<= 0: all).  A pair whose targets row is
 * gone (an orphan index row) is skipped.
 * @return The count, or -1 on a storage error (nothing returned). */
extern int history_identity_pm_targets(const char *identity, uint64_t lo_ms,
                                       uint64_t hi_ms, int include_newer, int max,
                                       struct HistoryTarget **result,
                                       history_target_filter_fn filter,
                                       void *filter_ctx);

/** Find the most recent JOIN event for a nick in a channel.
 * Scans backward through the channel's history looking for a JOIN
 * whose sender matches "nick!*".  Used by bouncer replay to recover
 * the original JOIN's msgid and timestamp.
 * @param[in] channel Channel name to search.
 * @param[in] nick Nick to match (compared case-insensitively against sender prefix).
 * @param[out] out_msgid Buffer for the JOIN's message ID.
 * @param[in] msgid_len Size of out_msgid buffer.
 * @param[out] out_timestamp Buffer for the JOIN's Unix timestamp (seconds.milliseconds).
 * @param[in] timestamp_len Size of out_timestamp buffer.
 * @return 1 if found, 0 if not found or error.
 */
extern int history_find_last_join(const char *channel, const char *nick,
                                  char *out_msgid, size_t msgid_len,
                                  char *out_timestamp, size_t timestamp_len);

/** Free a list of history messages.
 * @param[in] list Head of the message list to free.
 */
extern void history_free_messages(struct HistoryMessage *list);

/** Free a list of history targets.
 * @param[in] list Head of the target list to free.
 */
extern void history_free_targets(struct HistoryTarget *list);

/** Get timestamp for a given message ID, in whatever target the store
 * holds it, else the time the id itself carries (decoded without the
 * forward bound selectors get: an id this server minted while its clock
 * ran ahead is still that message's time).  For this server's own reads
 * that are not about one target (a bouncer ATTACH cursor, a stored
 * REDACT's target); a CHATHISTORY selector
 * is resolved against its target with history_msgid_ref_timestamp().
 * @param[in] msgid Message ID to look up.
 * @param[out] timestamp Buffer for timestamp (at least HISTORY_TIMESTAMP_LEN).
 * @return 0 on success, -1 if not found.
 */
extern int history_msgid_to_timestamp(const char *msgid, char *timestamp);

/** Resolve a msgid REFERENCE on @a target (a CHATHISTORY selector) to the
 * key timestamp a walk is positioned at -- the one rule every subcommand
 * and both BETWEEN bounds follow (#214):
 *   - a row of @a target's history: that row's stamp (the walk then
 *     positions on the row itself, the msgid breaking same-ms ties);
 *   - not a row of @a target's, but an id of exactly the form this server
 *     family mints (msgid_decode_ref_time_ms): the time the id carries --
 *     it reveals no more than the id itself says, whichever conversation
 *     it came from;
 *   - anything else (a legacy id this target does not hold, garbage): no
 *     timestamp -- the caller answers FAIL ... Unknown message id.
 * @param[in] target Store key (channel, or PM pair key).
 * @param[in] msgid The reference's msgid.
 * @param[out] timestamp Buffer of HISTORY_TIMESTAMP_LEN.
 * @return 0 a row of @a target, 1 the id's own time, -1 unknown. */
extern int history_msgid_ref_timestamp(const char *target, const char *msgid,
                                       char *timestamp);

/** Check whether any PM record under @a target carries
 * `+evilnet.github.io/sid=<sessid>` in its client_tags (legacy
 * records: `+afternet.org/sid=`).  Used by the
 * chathistory PM access-check path to authorize an ephemeral
 * (unauthed) requester whose only durable identity is the session_id —
 * if the sessid appears in a stored record's tags, the requester was a
 * participant when the record was written (the tag is server-injected
 * at store time; see ircd_relay.c store_private_history).
 *
 * Scans the most recent records under @a target up to a small bounded
 * window; sufficient because PM records always carry the ephemeral
 * participant's sessid when one is present, so the very latest record
 * under a target involving an ephemeral participant carries that
 * participant's sessid.  Returns 1 on match, 0 on no match or no
 * history.
 *
 * @param target  Canonical nick-pair "nick1:nick2" (sorted).
 * @param sessid  Caller's cli_session_id to match against record tags.
 */
extern int history_pm_target_has_sessid(const char *target, const char *sessid);
extern char *history_forward_encode(char *dst, size_t dstsize,
                                    const char *client_tags, const char *text);
extern char *history_forward_split(char *content, char **tags_out);
extern int history_deserialize_record(const void *data, size_t datalen,
                                      struct HistoryMessage *msg);

/** Redact a message: strip content/tags but keep the entry in the database.
 * A redaction keeps the row (REDACT-as-context) rather than deleting it.
 * The original message remains with empty content so it can serve as the
 * parent for a REDACT context message during chathistory replay.
 * @param[in] target Channel or nick where message was sent.
 * @param[in] msgid Message ID to redact.
 * @return 0 on success, 1 if not found, -1 on error.
 */
extern int history_redact_message(const char *target, const char *msgid);

/** Has @a msgid under @a target already been redacted, i.e. does a
 * REDACT context row reference it?
 * @return 1 if redacted, 0 if not, -1 on error. */
extern int history_message_is_redacted(const char *target, const char *msgid);

/** One page's redaction lookups in one snapshot (W5 Task 15 fix round 1:
 * a page checks each context reaction it shows).  NULL with no store, or
 * when no snapshot could be taken. */
struct HistoryRedactLookup;
extern struct HistoryRedactLookup *history_redact_lookup_open(void);
/** history_message_is_redacted, read in @a h's snapshot.  A child whose
 * index entry carries its link type (ri_link_kind) is read off the index,
 * never fetched or counted; at most @a max_children legacy (untyped)
 * children are fetched (0 = all): past them, with no REDACT found, the
 * answer is unknown (-1).  -1 for a NULL @a h. */
extern int history_redact_lookup(struct HistoryRedactLookup *h, const char *target,
                                 const char *msgid, int max_children);
extern void history_redact_lookup_close(struct HistoryRedactLookup *h);
/* Redaction catch-up index (design B; redact_index.h): rows since @a since_ms
 * in time order, at most @a limit (0 = all); *truncated set when cut short. */
struct rdx_val;
typedef void (*history_rdx_cb)(uint64_t time_ms, const char *redact_msgid,
                               const struct rdx_val *v, void *ctx);
extern int history_redact_index_scan(uint64_t since_ms, int limit,
                                     history_rdx_cb cb, void *ctx, int *truncated);
extern uint64_t history_redact_watermark_get(void);
extern int history_redact_watermark_set(uint64_t ms);

/** Query context messages (reactions, redacts) for a set of parent msgids.
 * Looks up the reply index to find TAGMSG(+draft/react) and REDACT events
 * that reference any of the given parent msgids, then splices them into
 * the message list immediately after their parents.
 * @param[in] target Channel or nick to scope the query.
 * @param[in,out] messages Message list to augment with context.
 *                Context messages are spliced in with is_context=1.
 * @return Number of context messages added.
 */
extern int history_attach_context(const char *target,
                                  struct HistoryMessage *messages);

/** Check if history subsystem is initialized and available.
 * @return 1 if available, 0 if not.
 */
extern int history_is_available(void);

/*
 * Timestamp Conversion API
 *
 * Internal storage and S2S use Unix timestamps (seconds.milliseconds).
 * Client-facing @time= tags use ISO 8601 per IRCv3 spec.
 */

/** Format current time as Unix timestamp string.
 * @param[out] buf Buffer for timestamp (at least HISTORY_TIMESTAMP_LEN).
 * @param[in] buflen Size of buffer.
 * @return Pointer to buf.
 */
extern char *history_format_timestamp(char *buf, size_t buflen);

/** A stored row's time.  One rule for every store site (2026-09-02): the
 * S2S tag time when the event arrived over @a link (the origin's stamp,
 * which is also the live @time this server delivered), else the local
 * HLC's current physical time -- which, read right after
 * generate_msgid(), is exactly the mint time embedded in that msgid and
 * the time send.c stamps on the live tag.  Before this every server
 * stamped rows with its own clock at observation time, so the same
 * msgid replayed with a different @time than it was delivered with on
 * every non-origin server.  @a link may be NULL (local event). */
struct Client;
extern uint64_t history_event_time_ms(struct Client *link);

/** Format an epoch-millisecond time as the storage stamp "sec.mmm". */
extern void history_format_ms(char *buf, size_t buflen, uint64_t ms);

/** Parse a storage stamp "sec[.mmm]" back to epoch milliseconds; 0 when
 * unparseable. */
extern uint64_t history_parse_ms(const char *ts);

/** Format an epoch-millisecond time as the client @time value
 * ("YYYY-MM-DDThh:mm:ss.mmmZ"). */
extern void history_format_iso_ms(char *buf, size_t buflen, uint64_t ms);

/** Convert Unix timestamp to ISO 8601 for client display.
 * @param[in] unix_ts Unix timestamp string (seconds.milliseconds).
 * @param[out] iso_buf Buffer for ISO 8601 output (at least 32 bytes).
 * @param[in] iso_buflen Size of ISO buffer.
 * @return 0 on success, -1 on error.
 */
extern int history_unix_to_iso(const char *unix_ts, char *iso_buf, size_t iso_buflen);

/** Convert ISO 8601 timestamp to Unix timestamp.
 * @param[in] iso_ts ISO 8601 timestamp string.
 * @param[out] unix_buf Buffer for Unix timestamp (at least HISTORY_TIMESTAMP_LEN).
 * @param[in] unix_buflen Size of Unix buffer.
 * @return 0 on success, -1 on error.
 */
extern int history_iso_to_unix(const char *iso_ts, char *unix_buf, size_t unix_buflen);

/* Read Marker API moved to metadata.h (metadata_readmarker_get/set) */

/** Lookup a message by ID and verify sender.
 * Used by message-redaction to validate authorization.
 * @param[in] target Channel or nick where message was sent.
 * @param[in] msgid Message ID to look up.
 * @param[out] msg Pointer to result (caller must free with history_free_messages).
 * @return 0 on success, -1 on error, 1 if not found.
 */
extern int history_lookup_message(const char *target, const char *msgid,
                                   struct HistoryMessage **msg);

/** Callback type for channel enumeration.
 * @param[in] channel Channel name.
 * @param[in] data User data pointer.
 * @return 0 to continue, non-zero to stop enumeration.
 */
typedef int (*history_channel_callback)(const char *channel, void *data);

/** Callback type for channel removal notification (batch).
 * Called when channels' last messages are evicted/purged.
 * @param[in] channels Array of channel names that were removed.
 * @param[in] count Number of channels in array.
 */
typedef void (*history_channels_removed_cb)(const char **channels, int count);

/** Set callback for channel removal notifications.
 * Used by chathistory federation to broadcast CH A - when channels are emptied.
 * @param[in] cb Callback function (or NULL to disable).
 */
extern void history_set_channel_removed_callback(history_channels_removed_cb cb);

/** Enumerate all channels that have stored history.
 * Calls callback for each channel in the targets database.
 * @param[in] callback Function to call for each channel.
 * @param[in] data User data to pass to callback.
 * @return Number of channels enumerated, or -1 on error.
 */
extern int history_enumerate_channels(history_channel_callback callback, void *data);

/** Check if a channel exists in history (has stored messages).
 * Note: This checks targets_dbi which may be stale after eviction.
 * @param[in] target Channel name.
 * @return 1 if channel has history, 0 if not, -1 on error.
 */
extern int history_has_channel(const char *target);

struct StatDesc;

/** Report CHATHISTORY statistics for /STATS.
 * @param[in] to Client requesting stats.
 * @param[in] sd Stats descriptor.
 * @param[in] param Extra parameter (unused).
 */
extern void history_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

/** Defragment the history database environment.
 * @param[in] time_limit_seconds Maximum wall-clock time to spend (0 = no limit).
 * @return 0 on success, negative on error.
 */
extern int history_defrag(unsigned int time_limit_seconds);

/** Report defrag results for the history database.
 * @param[in] to Client to send results to.
 */
extern void history_report_defrag(struct Client *to);

/** Force sync/flush the history database to disk.
 * @return 0 on success, -1 on error.
 */
extern int history_sync(void);

/** Report detailed GC info for the history database.
 * @param[in] to Client to send results to.
 */
extern void history_report_gc(struct Client *to);

/** Report detailed MDBX environment info for the history database.
 * @param[in] to Client to send results to.
 */
extern void history_report_store_info(struct Client *to);

/*
 * Auto-replay API (for bouncer resume)
 *
 * Used to automatically replay missed messages to clients that don't
 * support draft/chathistory (legacy clients).
 */

/** Replay chathistory to a client since a given timestamp.
 * Used by bouncer auto-replay for legacy clients without draft/chathistory.
 * Build ONE page of history since a timestamp for a client exactly the way
 * the on-demand CHATHISTORY handlers do (presence hook + requester type
 * mask + typing veto inside the walk; context attached; redacted originals
 * dropped; presence post-filter).  The single page builder shared with the
 * bouncer reattach replay -- audit 2026-09-06 wave 1: the replay path had
 * its own bare walk and drifted (replayed redacted content, no type mask).
 * @param[in] sptr Requesting client.
 * @param[in] target Storage target (channel, or a:b pair key).
 * @param[in] limit Page size.
 * @param[in] since_timestamp Floor ("sec.mmm"); rows at/after it.
 * @param[out] out Page rows (oldest first), NULL when empty; caller owns.
 * @param[out] complete 1 when the walk was exhausted (no more pages).
 * @return Row count (0 = empty page), or -1 on error.
 */
extern int chathistory_page_since(struct Client *sptr, const char *target,
                                  int limit, const char *since_timestamp,
                                  const char *since_msgid,
                                  struct HistoryMessage **out, int *complete);

/** The bouncer catch-up's leg for channel @a channame on a store (W5 Push
 * F, I-2; replay.c's replay_next_channel): chathistory_page_since's walk,
 * then the on-demand LATEST page's receive-window and absence decision
 * (federation_wanted).  A leg this store did not wholly receive, or that
 * crosses a storage peer's absence, is federated -- the local rows with
 * the request, as an on-demand page's -- and its page arrives later
 * through replay_leg_done(@a sptr, @a seq, ...): REPLAY_LEG_PENDING.  A leg
 * that cannot be federated while a storage peer that may hold the rest is
 * linked (no request slot, federation off here), or while one is away, is
 * the local rows, REPLAY_PARTIAL.
 * @param[out] out Page rows (oldest first), NULL when empty; caller owns.
 * @param[out] flags REPLAY_COMPLETE / REPLAY_PARTIAL for the batch opener.
 * @return Row count (0 = nothing to replay), -1 on error, or
 *   REPLAY_LEG_PENDING. */
extern int chathistory_replay_channel_leg(struct Client *sptr, const char *channame,
                                          int limit, const char *since_timestamp,
                                          const char *since_msgid, unsigned long seq,
                                          struct HistoryMessage **out, int *flags);

/** Free partial federation chunk reassembly buffers (CH B read responses and
 *  CH WB writes) that arrived from a server link that is now exiting, so they
 *  don't leak when a peer squits mid-stream. Call from exit_one_client. */
extern void chathistory_fed_cleanup_link(struct Client *link);

/** Start a federated REDACT query (exact message lookup via CH Q X).
 * Used by m_redact when this server does not hold the message (no store,
 * or a local miss) to look up its metadata on the storage servers for
 * authorization before showing and propagating the REDACT.
 * @param[in] sptr Client requesting the redaction.
 * @param[in] chptr Channel containing the message.
 * @param[in] target Channel name.
 * @param[in] msgid Message ID to look up.
 * @param[in] reason Redaction reason (may be NULL).
 * @param[in] is_chanop Whether requester is chanop.
 * @param[in] is_oper Whether requester is oper.
 * @return 0 on success (query started), -1 on failure.
 */
extern int start_redact_fed_query(struct Client *sptr, struct Channel *chptr,
                                  const char *target, const char *msgid,
                                  const char *reason, int is_chanop, int is_oper);

/** Start federated auto-replay for a bouncer alias.
 * Issues CHATHISTORY LATEST * queries to storage servers for each channel
 * the alias is in.  Results are delivered as chathistory batches.
 * @param[in] sptr The alias client.
 * @param[in] since_time Baseline timestamp (for read marker optimization, may be 0).
 * @param[in] limit Per-channel message limit.
 * @return 0 on success (replay started), -1 if federation unavailable.
 */
extern int chathistory_auto_replay_fed(struct Client *sptr, time_t since_time,
                                       int limit);

/** A bouncer revive replaces @a sptr's socket: its federated requests in
 * flight (keyed by its numeric) go with the old one -- the queries and the
 * catch-up legs dropped, a REDACT's label dropped (m_chathistory.c). */
extern void chathistory_forget_client(struct Client *sptr);

#endif /* INCLUDED_history_h */
