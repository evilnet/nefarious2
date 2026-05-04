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
#include <time.h>

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
  HISTORY_REDACT  = 11  /**< Message redaction event */
};

/** Stored message for chathistory retrieval.
 * This structure is used both for storage and for returning
 * query results to the caller.
 */
struct HistoryMessage {
  char msgid[HISTORY_MSGID_LEN];       /**< Unique message ID */
  char timestamp[HISTORY_TIMESTAMP_LEN]; /**< Unix timestamp (seconds.milliseconds) */
  char target[CHANNELLEN + 1];         /**< Channel name or nick */
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

/** Storage state for graceful degradation. */
enum HistoryStorageState {
  HISTORY_STORAGE_NORMAL   = 0, /**< Normal operation (<HIGH_WATERMARK) */
  HISTORY_STORAGE_WARNING  = 1, /**< Eviction active (HIGH-95%) */
  HISTORY_STORAGE_CRITICAL = 2, /**< Aggressive eviction (95-99%) */
  HISTORY_STORAGE_SUSPENDED= 3  /**< No new writes (>99%) */
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
 * @param[in] target Channel or nick.
 * @param[in] sender Full sender mask (nick!user@host).
 * @param[in] account Sender's account name (may be NULL).
 * @param[in] type Message type.
 * @param[in] content Message content (may be NULL for some types).
 * @return 0 on success, -1 on error.
 */
extern int history_store_message(const char *msgid, const char *timestamp,
                                  const char *target, const char *sender,
                                  const char *account, enum HistoryMessageType type,
                                  const char *content, const char *client_tags);

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
 * @return 0 on success, -1 on error.
 */
extern int history_store_multiline(const char *msgid, const char *timestamp,
                                   const char *target, const char *sender,
                                   const char *account, const char *content,
                                   size_t content_len, const char *paste_secret);

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
                                 struct HistoryMessage **result);

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
                                struct HistoryMessage **result);

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
                                 struct HistoryMessage **result);

/** Query the most recent messages, but no older than a floor timestamp.
 * Walks backward from the end of the target's history, collecting up to
 * \a limit messages, stopping if it reaches \a after_timestamp.
 * Returns results in chronological order (oldest first).
 * @param[in] target Channel or nick to query.
 * @param[in] limit Maximum messages to return.
 * @param[in] after_timestamp Floor timestamp (Unix or ISO 8601); messages
 *            at or before this time are excluded.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_latest_after(const char *target, int limit,
                                       const char *after_timestamp,
                                       struct HistoryMessage **result);

/** Query messages around a reference point.
 * Returns limit/2 messages before and limit/2 messages after.
 * @param[in] target Channel or nick to query.
 * @param[in] ref_type Type of reference.
 * @param[in] reference Timestamp or msgid string.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of messages returned, or -1 on error.
 */
extern int history_query_around(const char *target, enum HistoryRefType ref_type,
                                 const char *reference, int limit,
                                 struct HistoryMessage **result);

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
                                  int limit, struct HistoryMessage **result);

/** Query targets with recent message activity.
 * Used for CHATHISTORY TARGETS command.
 * @param[in] timestamp1 Start of time range (Unix timestamp).
 * @param[in] timestamp2 End of time range (Unix timestamp).
 * @param[in] limit Maximum targets to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of targets returned, or -1 on error.
 */
extern int history_query_targets(const char *timestamp1, const char *timestamp2,
                                  int limit, struct HistoryTarget **result);

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

/** Purge old messages from the database.
 * Called periodically to enforce retention policy.
 * @param[in] max_age_seconds Maximum age of messages to keep.
 * @return Number of messages deleted, or -1 on error.
 */
extern int history_purge_old(unsigned long max_age_seconds);

/** Get timestamp for a given message ID.
 * Useful for converting msgid references to timestamps.
 * @param[in] msgid Message ID to look up.
 * @param[out] timestamp Buffer for timestamp (at least HISTORY_TIMESTAMP_LEN).
 * @return 0 on success, -1 if not found.
 */
extern int history_msgid_to_timestamp(const char *msgid, char *timestamp);

/** Redact a message: strip content/tags but keep the entry in the database.
 * Used instead of history_delete_message() to support REDACT-as-context.
 * The original message remains with empty content so it can serve as the
 * parent for a REDACT context message during chathistory replay.
 * @param[in] target Channel or nick where message was sent.
 * @param[in] msgid Message ID to redact.
 * @return 0 on success, 1 if not found, -1 on error.
 */
extern int history_redact_message(const char *target, const char *msgid);

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

/** Delete a message from the history database.
 * Used by message-redaction to remove redacted messages.
 * @param[in] target Channel or nick where message was sent.
 * @param[in] msgid Message ID to delete.
 * @return 0 on success, -1 on error, 1 if not found.
 */
extern int history_delete_message(const char *target, const char *msgid);

/** Lookup a message by ID and verify sender.
 * Used by message-redaction to validate authorization.
 * @param[in] target Channel or nick where message was sent.
 * @param[in] msgid Message ID to look up.
 * @param[out] msg Pointer to result (caller must free with history_free_messages).
 * @return 0 on success, -1 on error, 1 if not found.
 */
extern int history_lookup_message(const char *target, const char *msgid,
                                   struct HistoryMessage **msg);

/** Set history database map size.
 * Must be called before history_init().
 * @param[in] size_mb Size in megabytes.
 */
extern void history_set_map_size(size_t size_mb);

/** Get history database map size.
 * @return Current map size in bytes.
 */
extern size_t history_get_map_size(void);

/** Get current database utilization.
 * @return Utilization as percentage (0-100), or -1 on error.
 */
extern int history_db_utilization(void);

/** Get current storage state.
 * @return Current storage state enum value.
 */
extern enum HistoryStorageState history_storage_state(void);

/** Evict messages until target utilization is reached.
 * @param[in] target_percent Target utilization percentage (e.g., 75).
 * @return Number of messages evicted, or -1 on error.
 */
extern int history_evict_to_target(int target_percent);

/** Periodic maintenance function.
 * Checks utilization and evicts if necessary.
 * Should be called from the main event loop.
 */
extern void history_maintenance_tick(void);

/** Get last eviction statistics.
 * @param[out] count Number of messages evicted in last run.
 * @param[out] timestamp Unix timestamp of last eviction.
 */
extern void history_last_eviction(int *count, time_t *timestamp);

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

/** Check if a channel has any actual messages in history_dbi.
 * More accurate than history_has_channel() after eviction/purge.
 * @param[in] target Channel name.
 * @return 1 if channel has messages, 0 if empty, -1 on error.
 */
extern int history_channel_has_messages(const char *target);

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
 * Per-User Quota API (anti-flood protection)
 *
 * Tracks message counts per user per channel to prevent a single user
 * from dominating channel history. When a user exceeds their quota
 * percentage, warnings are logged.
 */

/** Get the current message count for a user in a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name.
 * @return Message count, or 0 if not found.
 */
extern int history_quota_get_count(const char *channel, const char *account);

/** Check if a user is over their quota for a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name.
 * @param[in] channel_limit Total messages allowed in channel.
 * @return 1 if over quota, 0 if not.
 */
extern int history_quota_check(const char *channel, const char *account, int channel_limit);

/*
 * Auto-replay API (for bouncer resume)
 *
 * Used to automatically replay missed messages to clients that don't
 * support draft/chathistory (legacy clients).
 */

/** Replay chathistory to a client since a given timestamp.
 * Used by bouncer auto-replay for legacy clients without draft/chathistory.
 * @param[in] sptr Client to send history to.
 * @param[in] target Channel or nick to replay.
 * @param[in] since_timestamp Unix timestamp (seconds.milliseconds) to replay from.
 * @param[in] limit Maximum messages to replay.
 * @return Number of messages replayed, or -1 on error.
 */
extern int chathistory_auto_replay(struct Client *sptr, const char *target,
                                   const char *since_timestamp, int limit);

/** Start a federated REDACT query (exact message lookup via CH Q X).
 * Used by m_redact on non-storing servers to look up message metadata
 * from storage servers for authorization before propagating REDACT.
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

#endif /* INCLUDED_history_h */
