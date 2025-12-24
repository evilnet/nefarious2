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

struct Client;

/** Maximum size of a message ID */
#define HISTORY_MSGID_LEN 64

/** Maximum size of a timestamp string (ISO 8601) */
#define HISTORY_TIMESTAMP_LEN 32

/** Maximum size of sender string (nick!user@host) */
#define HISTORY_SENDER_LEN (NICKLEN + USERLEN + HOSTLEN + 3)

/** Maximum size of message content */
#define HISTORY_CONTENT_LEN 512

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
  HISTORY_TAGMSG  = 8
};

/** Stored message for chathistory retrieval.
 * This structure is used both for storage and for returning
 * query results to the caller.
 */
struct HistoryMessage {
  char msgid[HISTORY_MSGID_LEN];       /**< Unique message ID */
  char timestamp[HISTORY_TIMESTAMP_LEN]; /**< ISO 8601 UTC timestamp */
  char target[CHANNELLEN + 1];         /**< Channel name or nick */
  char sender[HISTORY_SENDER_LEN];     /**< nick!user@host of sender */
  char account[ACCOUNTLEN + 1];        /**< Sender's account name (or empty) */
  enum HistoryMessageType type;        /**< Message type */
  char content[HISTORY_CONTENT_LEN];   /**< Message content */
  struct HistoryMessage *next;         /**< Next in linked list (for results) */
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
 * @param[in] timestamp ISO 8601 UTC timestamp.
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
                                  const char *content);

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
 * @param[in] timestamp1 Start of time range (ISO 8601).
 * @param[in] timestamp2 End of time range (ISO 8601).
 * @param[in] limit Maximum targets to return.
 * @param[out] result Pointer to result list head (caller must free).
 * @return Number of targets returned, or -1 on error.
 */
extern int history_query_targets(const char *timestamp1, const char *timestamp2,
                                  int limit, struct HistoryTarget **result);

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

/** Check if history subsystem is initialized and available.
 * @return 1 if available, 0 if not.
 */
extern int history_is_available(void);

#endif /* INCLUDED_history_h */
