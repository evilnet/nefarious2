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
 * Fetch the stored record for an account's endpoint into out (NUL-
 * terminated).  Returns 0 when found, 1 when absent, -1 on error.
 */
int webpush_store_get(const char *account, const char *endpoint,
                      char *out, size_t outsz);

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
 * Server-level config records (the "config" column family).
 *
 * Key ring entries live under "key/<id>" with the text record produced by
 * webpush_key_format().  The pre-ring single key lives under
 * "vapid_privkey" (32 raw bytes) and is migrated into the ring at setup.
 * Arbitrary records (bad-key quarantine, markers) use the generic calls.
 */

/* Put/get/delete a config record.  get returns 0 when found (NUL-
 * terminated copy in out, *outlen bytes), 1 when absent, -1 on error;
 * binary values are fine (outlen tells the real length). */
int webpush_store_cfg_put(const char *name, const void *val, size_t len);
int webpush_store_cfg_get(const char *name, char *out, size_t outsz, size_t *outlen);
int webpush_store_cfg_del(const char *name);

/* Persist / drop a ring key ("key/<id>" -> text). */
int webpush_store_key_put(const char *id, const char *text);
int webpush_store_key_del(const char *id);

/* Iterate the persisted ring: cb(id, text, data); return nonzero to
 * stop.  Returns the number of keys visited or -1. */
typedef int (*webpush_store_key_cb)(const char *id, const char *text, void *data);
int webpush_store_key_foreach(webpush_store_key_cb cb, void *data);

/*
 * Load the pre-ring VAPID private key ("vapid_privkey", 32 raw bytes).
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
