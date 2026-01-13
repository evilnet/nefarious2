/*
 * IRC - Internet Relay Chat, include/metadata.h
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
 * @brief Metadata storage declarations (IRCv3 draft/metadata-2).
 *
 * Implements IRCv3 draft/metadata-2 extension for user/channel key-value storage.
 *
 * Specification: https://ircv3.net/specs/extensions/metadata
 * Capability: draft/metadata-2
 */
#ifndef INCLUDED_metadata_h
#define INCLUDED_metadata_h

struct Client;
struct Channel;

/** Maximum length of a metadata key name */
#define METADATA_KEY_LEN 64

/** Maximum length of a metadata value */
#define METADATA_VALUE_LEN 1024

/** Maximum number of metadata entries per target */
#define METADATA_MAX_KEYS 20

/** Maximum number of subscriptions per client */
#define METADATA_MAX_SUBS 50

/** Visibility levels for metadata */
#define METADATA_VIS_PUBLIC  0  /* Anyone can see */
#define METADATA_VIS_PRIVATE 1  /* Only owner can see */
#define METADATA_VIS_ERROR   2  /* Error response (no such target) */

/** Metadata entry structure */
struct MetadataEntry {
  char key[METADATA_KEY_LEN];           /**< Key name */
  char *value;                          /**< Value (dynamically allocated) */
  int visibility;                       /**< Visibility level */
  struct MetadataEntry *next;           /**< Next entry in list */
};

/** Metadata subscription for a client */
struct MetadataSub {
  char key[METADATA_KEY_LEN];           /**< Key being subscribed to */
  struct MetadataSub *next;             /**< Next subscription in list */
};

/** Initialize the metadata subsystem */
extern void metadata_init(void);

/** Shutdown the metadata subsystem */
extern void metadata_shutdown(void);

/** Initialize LMDB for metadata persistence.
 * @param[in] dbpath Path to the database directory.
 * @return 0 on success, -1 on error.
 */
extern int metadata_lmdb_init(const char *dbpath);

/** Shutdown LMDB metadata storage. */
extern void metadata_lmdb_shutdown(void);

/** Check if LMDB metadata storage is available.
 * @return 1 if available, 0 if not.
 */
extern int metadata_lmdb_is_available(void);

/** Get account metadata from LMDB.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] value Buffer for value (at least METADATA_VALUE_LEN).
 * @return 0 on success, 1 if not found, -1 on error.
 */
extern int metadata_account_get(const char *account, const char *key, char *value);

/** Set account metadata in LMDB.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set (NULL to delete).
 * @return 0 on success, -1 on error.
 */
extern int metadata_account_set(const char *account, const char *key, const char *value);

/** Set account metadata in LMDB without compression (raw passthrough).
 * Used for compression passthrough when data is already compressed.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] raw_value Raw (possibly compressed) data.
 * @param[in] raw_len Length of raw data.
 * @return 0 on success, -1 on error.
 */
extern int metadata_account_set_raw(const char *account, const char *key,
                                    const unsigned char *raw_value, size_t raw_len);

/** List all metadata for an account from LMDB.
 * @param[in] account Account name.
 * @return Head of metadata list (caller must free).
 */
extern struct MetadataEntry *metadata_account_list(const char *account);

/** Clear all metadata for an account in LMDB.
 * @param[in] account Account name.
 * @return 0 on success, -1 on error.
 */
extern int metadata_account_clear(const char *account);

/** Purge expired metadata entries from LMDB.
 * Called periodically to enforce METADATA_CACHE_TTL.
 * @return Number of entries purged, or -1 on error.
 */
extern int metadata_account_purge_expired(void);

/** Load metadata from LMDB for a logged-in user.
 * Called when a user logs into an account.
 * @param[in] cptr Client that just logged in.
 * @param[in] account Account name.
 */
extern void metadata_load_account(struct Client *cptr, const char *account);

/** Validate a metadata key name.
 * @param[in] key Key name to validate.
 * @return 1 if valid, 0 if invalid.
 */
extern int metadata_valid_key(const char *key);

/** Get metadata for a client.
 * @param[in] cptr Client to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
extern struct MetadataEntry *metadata_get_client(struct Client *cptr, const char *key);

/** Set metadata for a client.
 * @param[in] cptr Client to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
extern int metadata_set_client(struct Client *cptr, const char *key, const char *value, int visibility);

/** List all metadata for a client.
 * @param[in] cptr Client to list metadata for.
 * @return Head of metadata list (read-only).
 */
extern struct MetadataEntry *metadata_list_client(struct Client *cptr);

/** Clear all metadata for a client.
 * @param[in] cptr Client to clear.
 */
extern void metadata_clear_client(struct Client *cptr);

/** Get metadata for a channel.
 * @param[in] chptr Channel to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
extern struct MetadataEntry *metadata_get_channel(struct Channel *chptr, const char *key);

/** Set metadata for a channel.
 * @param[in] chptr Channel to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
extern int metadata_set_channel(struct Channel *chptr, const char *key, const char *value, int visibility);

/** List all metadata for a channel.
 * @param[in] chptr Channel to list metadata for.
 * @return Head of metadata list (read-only).
 */
extern struct MetadataEntry *metadata_list_channel(struct Channel *chptr);

/** Clear all metadata for a channel.
 * @param[in] chptr Channel to clear.
 */
extern void metadata_clear_channel(struct Channel *chptr);

/** Count metadata entries for a client.
 * @param[in] cptr Client to count.
 * @return Number of metadata entries.
 */
extern int metadata_count_client(struct Client *cptr);

/** Count metadata entries for a channel.
 * @param[in] chptr Channel to count.
 * @return Number of metadata entries.
 */
extern int metadata_count_channel(struct Channel *chptr);

/** Free a metadata entry.
 * @param[in] entry Entry to free.
 */
extern void metadata_free_entry(struct MetadataEntry *entry);

/** Free all metadata for a client (called on disconnect).
 * @param[in] cptr Client being freed.
 */
extern void metadata_free_client(struct Client *cptr);

/** Free all metadata for a channel (called on channel destruction).
 * @param[in] chptr Channel being freed.
 */
extern void metadata_free_channel(struct Channel *chptr);

/* Subscription functions */

/** Add a subscription for a client.
 * @param[in] cptr Client subscribing.
 * @param[in] key Key to subscribe to.
 * @return 0 on success, -1 if limit reached.
 */
extern int metadata_sub_add(struct Client *cptr, const char *key);

/** Remove a subscription for a client.
 * @param[in] cptr Client unsubscribing.
 * @param[in] key Key to unsubscribe from.
 * @return 0 on success, -1 if not subscribed.
 */
extern int metadata_sub_del(struct Client *cptr, const char *key);

/** Check if a client is subscribed to a key.
 * @param[in] cptr Client to check.
 * @param[in] key Key to check.
 * @return 1 if subscribed, 0 if not.
 */
extern int metadata_sub_check(struct Client *cptr, const char *key);

/** List subscriptions for a client.
 * @param[in] cptr Client to list.
 * @return Head of subscription list.
 */
extern struct MetadataSub *metadata_sub_list(struct Client *cptr);

/** Count subscriptions for a client.
 * @param[in] cptr Client to count.
 * @return Number of subscriptions.
 */
extern int metadata_sub_count(struct Client *cptr);

/** Free all subscriptions for a client.
 * @param[in] cptr Client being freed.
 */
extern void metadata_sub_free(struct Client *cptr);

/* ========== Cache-Aware Metadata Operations ========== */

/** Get metadata for a client with cache-through behavior.
 * Checks in-memory first, then LMDB cache for logged-in users.
 * @param[in] cptr Client to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
extern struct MetadataEntry *metadata_get_client_cached(struct Client *cptr, const char *key);

/* ========== X3 Availability Tracking ========== */

/** Check if X3 services are available.
 * @return 1 if X3 is available, 0 if not.
 */
extern int metadata_x3_is_available(void);

/** Signal that X3 has sent a message (heartbeat).
 * Called when X3 sends any P10 message to update availability status.
 */
extern void metadata_x3_heartbeat(void);

/** Check X3 availability status based on timeout.
 * Called periodically to detect X3 outages.
 */
extern void metadata_x3_check(void);

/** Handle X3 reconnection - replay queued writes.
 * Called when X3 reconnects after an outage.
 */
extern void metadata_x3_reconnected(void);

/** Check if metadata writes can be sent to X3.
 * @return 1 if writes can be sent, 0 if they should be queued.
 */
extern int metadata_can_write_x3(void);

/* ========== Write Queue for X3 Unavailability ========== */

/** Queue a metadata write for later replay.
 * Called when X3 is unavailable to queue writes for later.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set.
 * @param[in] visibility Visibility level.
 * @return 0 on success, -1 if queue is full.
 */
extern int metadata_queue_write(const char *account, const char *key,
                                const char *value, int visibility);

/** Replay all queued metadata writes to X3.
 * Called when X3 becomes available again.
 */
extern void metadata_replay_queue(void);

/** Clear the write queue without replaying.
 */
extern void metadata_clear_queue(void);

/** Get the number of queued writes.
 * @return Number of entries in the write queue.
 */
extern int metadata_queue_count(void);

/* ========== Netburst Metadata ========== */

/** Burst all metadata for a client to a server.
 * @param[in] sptr Client whose metadata to send.
 * @param[in] cptr Server to send metadata to.
 */
extern void metadata_burst_client(struct Client *sptr, struct Client *cptr);

/** Burst all metadata for a channel to a server.
 * @param[in] chptr Channel whose metadata to send.
 * @param[in] cptr Server to send metadata to.
 */
extern void metadata_burst_channel(struct Channel *chptr, struct Client *cptr);

/* ========== MDQ Request Tracking ========== */

/** Maximum pending MDQ requests */
#define METADATA_MAX_PENDING 100

/** Timeout for pending MDQ requests (seconds) */
#define METADATA_REQUEST_TIMEOUT 30

/** Pending MDQ request structure */
struct MetadataRequest {
  struct Client *client;              /**< Client waiting for response */
  char target[ACCOUNTLEN + 1];        /**< Target account/channel */
  char key[METADATA_KEY_LEN];         /**< Key requested (or "*") */
  time_t timestamp;                   /**< When request was made */
  struct MetadataRequest *next;       /**< Next in list */
};

/** Send an MDQ query to services for a target.
 * @param[in] sptr Client requesting metadata.
 * @param[in] target Target account or channel name.
 * @param[in] key Key to query (or "*" for all).
 * @return 0 on success, -1 on error.
 */
extern int metadata_send_query(struct Client *sptr, const char *target, const char *key);

/** Check if there are pending MDQ requests for a target/key.
 * Called when MD response is received to forward to waiting clients.
 * @param[in] target Target that metadata was received for.
 * @param[in] key Key that was received.
 * @param[in] value Value received.
 * @param[in] visibility Visibility level.
 */
extern void metadata_handle_response(const char *target, const char *key,
                                     const char *value, int visibility);

/** Clean up expired MDQ requests.
 * Called periodically from the main loop.
 */
extern void metadata_expire_requests(void);

/** Clean up MDQ requests for a disconnecting client.
 * @param[in] cptr Client that is disconnecting.
 */
extern void metadata_cleanup_client_requests(struct Client *cptr);

/** Initialize MDQ request tracking. */
extern void metadata_request_init(void);

struct StatDesc;

/** Report METADATA statistics for /STATS.
 * @param[in] to Client requesting stats.
 * @param[in] sd Stats descriptor.
 * @param[in] param Extra parameter (unused).
 */
extern void metadata_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

#endif /* INCLUDED_metadata_h */
