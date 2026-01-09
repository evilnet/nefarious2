/*
 * IRC - Internet Relay Chat, include/ml_storage.h
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
 * @brief Multiline message storage for &ml- virtual channel retrieval.
 *
 * Provides ephemeral in-memory storage for truncated multiline messages.
 * Legacy clients can retrieve full content via /join &ml-<msgid>.
 * Storage is local-only (not synced across servers) and expires after TTL.
 */
#ifndef INCLUDED_ml_storage_h
#define INCLUDED_ml_storage_h

#include "ircd_defs.h"
#include <time.h>

struct Client;
struct SLink;

/** Maximum length of stored msgid (base msgid without sequence suffix) */
#define ML_STORAGE_MSGID_LEN 64

/** Hash table size for storage entries */
#define ML_STORAGE_HASHSIZE 1024

/** Default maximum entries (memory bound) */
#define ML_STORAGE_DEFAULT_MAX 10000

/** Stored multiline message entry */
struct ml_stored_msg {
  char msgid[ML_STORAGE_MSGID_LEN];   /**< Base msgid (without sequence suffix) */
  char sender[NICKLEN + 1];           /**< Sender nick */
  char target[CHANNELLEN + 1];        /**< Target channel or nick */
  char *lines;                        /**< Newline-separated content */
  int line_count;                     /**< Number of lines */
  time_t stored;                      /**< When stored */
  time_t expires;                     /**< When to expire */
  struct ml_stored_msg *next;         /**< Hash chain */
};

/** Initialize the multiline storage system.
 * Must be called at server startup.
 */
extern void ml_storage_init(void);

/** Shutdown the multiline storage system.
 * Frees all stored entries.
 */
extern void ml_storage_shutdown(void);

/** Store multiline content for later retrieval.
 * @param[in] msgid Base message ID (without sequence suffix).
 * @param[in] sender Sender's nick.
 * @param[in] target Target channel or nick.
 * @param[in] lines Linked list of message lines (SLink with value.cp).
 * @param[in] count Number of lines in the list.
 * @return 0 on success, -1 on error (e.g., storage full).
 */
extern int ml_storage_store(const char *msgid, const char *sender,
                            const char *target, struct SLink *lines, int count);

/** Retrieve stored content by message ID.
 * @param[in] msgid Base message ID to look up.
 * @return Pointer to stored message, or NULL if not found/expired.
 * @note Returned pointer is internal; do not free. Content is valid
 *       until ml_storage_expire() runs or ml_storage_shutdown() is called.
 */
extern struct ml_stored_msg *ml_storage_get(const char *msgid);

/** Remove a specific entry from storage.
 * @param[in] msgid Base message ID to remove.
 * @return 0 if removed, 1 if not found.
 */
extern int ml_storage_remove(const char *msgid);

/** Expire old entries from storage.
 * Should be called periodically (e.g., every 5 minutes).
 * @return Number of entries expired.
 */
extern int ml_storage_expire(void);

/** Get storage statistics.
 * @param[out] count Current number of stored entries.
 * @param[out] max Maximum allowed entries.
 * @param[out] bytes Total bytes used by stored content (approximate).
 */
extern void ml_storage_stats(int *count, int *max, size_t *bytes);

/** Deliver stored content to a client via NOTICEs.
 * Called when client tries to /join &ml-<msgid>.
 * @param[in] sptr Client requesting the content.
 * @param[in] msgid Message ID to retrieve (without "&ml-" prefix).
 * @return 0 on success (content delivered or not found notice sent).
 */
extern int ml_storage_deliver(struct Client *sptr, const char *msgid);

/** Check if a channel name is a virtual &ml- channel.
 * @param[in] name Channel name to check.
 * @return 1 if it's an &ml- channel, 0 otherwise.
 */
extern int ml_storage_is_virtual_channel(const char *name);

/** Memory usage reporting for /STATS.
 * @param[in] cptr Client requesting stats.
 */
extern void ml_storage_meminfo(struct Client *cptr);

#endif /* INCLUDED_ml_storage_h */
