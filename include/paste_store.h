/*
 * paste_store.h - LMDB storage for multiline paste content
 *
 * Provides persistent storage for:
 *   - Multiline message content accessible via HTTP URLs
 *   - Ephemeral storage with TTL-based expiration
 *
 * Used as fallback for legacy clients that don't support multiline.
 * Content is served via TLS HTTP on a dedicated port.
 */

#ifndef INCLUDED_paste_store_h
#define INCLUDED_paste_store_h

#include <stddef.h>
#include <time.h>

/* Forward declarations */
struct Client;
struct StatDesc;

/** Maximum length of paste_id (msgid + "-" + secret) */
#define PASTE_ID_MAX 80

/** Maximum length of filename hint */
#define PASTE_FILENAME_MAX 64

/** Flags byte stored with paste */
#define PASTE_FLAG_COMPRESSED 0x01  /**< Content is zstd compressed */

/**
 * Structure returned by paste_store_get().
 * Caller must free content when done.
 */
struct paste_entry {
  char paste_id[PASTE_ID_MAX];
  char sender[32];              /**< Sender nick (truncated if needed) */
  char target[64];              /**< Target channel or nick */
  char filename[PASTE_FILENAME_MAX]; /**< Optional filename hint (empty if none) */
  time_t created;               /**< When paste was stored */
  time_t expires;               /**< When paste expires */
  char *content;                /**< Decompressed content (caller must free) */
  size_t content_len;           /**< Length of content */
};

/**
 * Storage statistics.
 */
struct paste_store_stats {
  unsigned long count;          /**< Number of pastes stored */
  unsigned long bytes;          /**< Total bytes (compressed) */
  unsigned long expired;        /**< Total pastes expired since startup */
};

/**
 * Initialize the paste LMDB storage.
 * @param[in] dbpath Directory for the LMDB environment.
 * @return 0 on success, -1 on error.
 */
int paste_store_init(const char *dbpath);

/**
 * Shutdown and close the LMDB environment.
 */
void paste_store_shutdown(void);

/**
 * Check if store is available.
 * @return 1 if available, 0 if not.
 */
int paste_store_available(void);

/**
 * Store a paste.
 * @param[in] paste_id   Unique paste ID (msgid + "-" + secret).
 * @param[in] sender     Sender nick.
 * @param[in] target     Target channel or nick.
 * @param[in] filename   Optional filename hint (NULL or "" for none).
 * @param[in] content    Paste content (will be compressed if above threshold).
 * @param[in] content_len Length of content.
 * @param[in] ttl        Time-to-live in seconds.
 * @return 0 on success, -1 on error.
 */
int paste_store_add(const char *paste_id, const char *sender,
                    const char *target, const char *filename,
                    const char *content, size_t content_len, time_t ttl);

/**
 * Retrieve a paste by ID.
 * @param[in]  paste_id  Paste ID to look up.
 * @param[out] out       Structure to populate (content is allocated).
 * @return 0 on success, 1 if not found/expired, -1 on error.
 * Caller must free out->content when done.
 */
int paste_store_get(const char *paste_id, struct paste_entry *out);

/**
 * Remove a paste by ID.
 * @param[in] paste_id Paste ID to remove.
 * @return 0 on success, 1 if not found, -1 on error.
 */
int paste_store_remove(const char *paste_id);

/**
 * Expire old pastes based on TTL.
 * Called periodically by timer.
 * @return Number of pastes expired.
 */
int paste_store_expire(void);

/**
 * Get storage statistics.
 * @param[out] stats Structure to populate.
 * @return 0 on success, -1 on error.
 */
int paste_store_get_stats(struct paste_store_stats *stats);

/**
 * Free a paste entry's allocated content.
 * @param[in] entry Entry whose content to free.
 */
void paste_entry_free(struct paste_entry *entry);

/**
 * Report paste store statistics via /STATS.
 * @param[in] to     Client to send stats to.
 * @param[in] sd     Stats descriptor.
 * @param[in] param  Optional parameter (unused).
 */
void paste_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

#endif /* INCLUDED_paste_store_h */
