/*
 * kc_cache.h - Keycloak caching subsystem for libkc
 *
 * User ID cache: Maps IRC username → Keycloak UUID (short-lived, for
 * avoiding HTTP round-trips during registration/activation flows).
 *
 * User representation cache: Maps Keycloak UUID → full JSON user object
 * (for safe PUT merging of attribute updates).
 */

#ifndef KC_CACHE_H
#define KC_CACHE_H

#include <jansson.h>

/* Cache statistics */
struct kc_cache_stats {
    unsigned long user_cache_hits;
    unsigned long user_cache_misses;
};

/*
 * Initialize the cache subsystem.
 * Uses libkc logging macros (kc_log_debug, etc.) — no log handle needed.
 */
void kc_cache_init(void);

/*
 * Shutdown and free all cache resources.
 */
void kc_cache_cleanup(void);

/*
 * Get a snapshot of cache statistics.
 */
void kc_cache_stats_get(struct kc_cache_stats *out);

/* === User ID Cache === */

/*
 * Cache a username → Keycloak user ID mapping.
 * Called after successful user creation (ID from Location header).
 */
void kc_userid_cache_put(const char *username, const char *user_id);

/*
 * Look up a cached Keycloak user ID by IRC username.
 * Returns pointer to cached ID string, or NULL if not found/expired.
 * The returned pointer is valid until the next cache modification.
 */
const char *kc_userid_cache_get(const char *username);

/*
 * Remove a username from the cache (e.g., on user deletion).
 */
void kc_userid_cache_remove(const char *username);

/* === User Representation Cache === */

/*
 * Store/update a full user JSON representation.
 * The cache takes a deep copy (with credentials stripped).
 * @param user_id  Keycloak UUID
 * @param repr     Full user JSON object (borrowed; cache copies it)
 */
void kc_user_repr_cache_put(const char *user_id, json_t *repr);

/*
 * Get a cached user representation.
 * Returns borrowed reference (do NOT json_decref), or NULL if not found.
 */
json_t *kc_user_repr_cache_get(const char *user_id);

/*
 * Remove a user representation from the cache.
 */
void kc_user_repr_cache_remove(const char *user_id);

#endif /* KC_CACHE_H */
