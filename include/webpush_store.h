/*
 * webpush_store.h - LMDB storage for Web Push subscriptions and VAPID keys
 *
 * Provides persistent storage for:
 *   - Per-account Web Push subscriptions
 *   - VAPID keypair (survives restarts)
 *
 * Uses a dedicated LMDB environment, separate from history/metadata.
 */

#ifndef INCLUDED_webpush_store_h
#define INCLUDED_webpush_store_h

#include <stddef.h>

struct webpush_subscription;  /* forward decl from webpush.h */

/*
 * Initialize the webpush LMDB storage.
 * dbpath: directory for the LMDB environment
 * Returns 0 on success, -1 on error.
 */
int webpush_store_init(const char *dbpath);

/*
 * Shutdown and close the LMDB environment.
 */
void webpush_store_shutdown(void);

/*
 * Check if store is available.
 */
int webpush_store_available(void);

/*
 * Store a subscription for an account.
 * Keyed by account + SHA256 hash of endpoint URL.
 * value format: "endpoint|p256dh_b64|auth_b64"
 *
 * account: IRC account name
 * stored: serialized subscription string
 * Returns 0 on success, -1 on error.
 */
int webpush_store_add(const char *account, const char *stored);

/*
 * Remove a subscription for an account by endpoint URL.
 * Returns 0 on success (or not found), -1 on error.
 */
int webpush_store_remove(const char *account, const char *endpoint);

/*
 * Remove all subscriptions for an account.
 * Returns number of subscriptions removed, or -1 on error.
 */
int webpush_store_clear(const char *account);

/*
 * Count subscriptions for an account.
 * Returns count (>= 0), or -1 on error.
 */
int webpush_store_count(const char *account);

/*
 * Callback for iterating subscriptions for a single account.
 * stored: serialized subscription string ("endpoint|p256dh|auth")
 * data: opaque user data
 * Return 0 to continue iteration, nonzero to stop.
 */
typedef int (*webpush_store_iter_cb)(const char *stored, void *data);

/*
 * Iterate all subscriptions for an account.
 * Calls cb for each subscription.
 * Returns number of subscriptions iterated, or -1 on error.
 */
int webpush_store_foreach(const char *account, webpush_store_iter_cb cb,
                          void *data);

/*
 * Callback for iterating ALL subscriptions across all accounts.
 * account: the account name for this subscription
 * stored: serialized subscription string ("endpoint|p256dh|auth")
 * data: opaque user data
 * Return 0 to continue iteration, nonzero to stop.
 */
typedef int (*webpush_store_iter_all_cb)(const char *account,
                                         const char *stored, void *data);

/*
 * Iterate ALL subscriptions across all accounts.
 * Calls cb for each subscription with both account name and stored value.
 * Useful for burst synchronization during server link.
 * Returns number of subscriptions iterated, or -1 on error.
 */
int webpush_store_foreach_all(webpush_store_iter_all_cb cb, void *data);

/*
 * Store VAPID private key for persistence across restarts.
 * privkey: 32-byte P-256 private key scalar
 * Returns 0 on success, -1 on error.
 */
int webpush_store_set_vapid_key(const unsigned char *privkey, size_t privkey_len);

/*
 * Load VAPID private key from storage.
 * privkey: buffer to receive 32-byte key
 * privkey_len: in/out buffer size (must be >= 32)
 * Returns 0 on success, -1 if not found or error.
 */
int webpush_store_get_vapid_key(unsigned char *privkey, size_t *privkey_len);

/*
 * Get storage statistics.
 */
struct webpush_store_stats {
  unsigned long total_subscriptions;
  unsigned long total_accounts;
  unsigned long db_size_bytes;
};

int webpush_store_get_stats(struct webpush_store_stats *stats);

#endif /* INCLUDED_webpush_store_h */
