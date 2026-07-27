/*
 * kc_cache.c - Keycloak caching subsystem for libkc
 *
 * Ported from X3's kc_cache.c to use libkc logging macros.
 */

#include <kc/kc.h>
#include <kc/kc_cache.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <strings.h>  /* strcasecmp */

/*
 * =============================================================================
 * User ID Cache for HTTP Round-trip Optimization
 * =============================================================================
 *
 * When creating a user, Keycloak returns the user ID in the Location header
 * of the HTTP 201 response. We cache this to avoid a GET lookup when we need
 * to update the user (e.g., syncing password hash after registration).
 *
 * Cache entries are short-lived (5 minutes) and used primarily during the
 * registration -> activation flow where multiple operations target the same user.
 */

#define KC_USERID_CACHE_TTL 300  /* 5 minutes */
#define KC_USERID_CACHE_MAX 64   /* Max cached entries */

struct kc_userid_entry {
    char username[64];
    char user_id[64];
    time_t created;
};

static struct {
    struct kc_userid_entry entries[KC_USERID_CACHE_MAX];
    int count;
} userid_cache = {0};

/* Cache statistics */
static struct kc_cache_stats cache_stats = {0};

/*
 * =============================================================================
 * User Representation Cache for Safe Attribute Updates
 * =============================================================================
 *
 * Keycloak's PUT /admin/realms/{realm}/users/{id} does FULL replacement of
 * the user object. This means sending {"attributes": {"foo": ["bar"]}} will
 * CLEAR the user's email, firstName, etc.
 *
 * This cache stores full user representations (from webhooks or GET) so that
 * when updating attributes we can merge the new attribute into the existing
 * representation and PUT the complete object.
 *
 * Cache population sources:
 * - Webhook USER UPDATE events (contain full representation in payload)
 * - Explicit GET when cache miss occurs during attribute update
 *
 * Cache invalidation:
 * - User deleted: remove from cache
 * - Webhook USER UPDATE: replace with new representation
 */

#define KC_USER_REPR_CACHE_MAX 128  /* Max cached user representations */

struct kc_user_repr_entry {
    char user_id[64];      /* Keycloak user UUID (key) */
    json_t *repr;          /* Full user JSON object (jansson) */
    time_t last_updated;   /* When this entry was last refreshed */
};

static struct {
    struct kc_user_repr_entry entries[KC_USER_REPR_CACHE_MAX];
    int count;
} repr_cache = {0};

/* =============================================================================
 * Public API
 * =============================================================================
 */

void
kc_cache_init(void)
{
    /* Nothing to initialize — static arrays are zero-initialized */
}

void
kc_cache_cleanup(void)
{
    /* Clean up user repr cache */
    for (int i = 0; i < repr_cache.count; i++) {
        if (repr_cache.entries[i].repr) {
            json_decref(repr_cache.entries[i].repr);
            repr_cache.entries[i].repr = NULL;
        }
    }
    repr_cache.count = 0;

    /* Clean up userid cache */
    userid_cache.count = 0;

    kc_log_debug("kc_cache: Cleaned up");
}

void
kc_cache_stats_get(struct kc_cache_stats *out)
{
    if (out)
        *out = cache_stats;
}

/* =============================================================================
 * User ID Cache
 * =============================================================================
 */

void
kc_userid_cache_put(const char *username, const char *user_id)
{
    if (!username || !user_id) return;

    /* Check if already cached (update timestamp) */
    for (int i = 0; i < userid_cache.count; i++) {
        if (strcasecmp(userid_cache.entries[i].username, username) == 0) {
            snprintf(userid_cache.entries[i].user_id,
                     sizeof(userid_cache.entries[i].user_id),
                     "%s", user_id);
            userid_cache.entries[i].created = time(NULL);
            kc_log_debug("userid_cache: Updated %s -> %s", username, user_id);
            return;
        }
    }

    /* Evict stale entries if full */
    if (userid_cache.count >= KC_USERID_CACHE_MAX) {
        time_t now = time(NULL);
        int oldest_idx = 0;
        time_t oldest_time = userid_cache.entries[0].created;

        for (int i = 0; i < userid_cache.count; i++) {
            /* Prefer evicting expired entries */
            if (now - userid_cache.entries[i].created > KC_USERID_CACHE_TTL) {
                oldest_idx = i;
                break;
            }
            /* Otherwise evict oldest */
            if (userid_cache.entries[i].created < oldest_time) {
                oldest_time = userid_cache.entries[i].created;
                oldest_idx = i;
            }
        }

        kc_log_debug("userid_cache: Evicting %s to make room",
                     userid_cache.entries[oldest_idx].username);

        /* Shift remaining entries if not last */
        if (oldest_idx < userid_cache.count - 1) {
            memmove(&userid_cache.entries[oldest_idx],
                    &userid_cache.entries[oldest_idx + 1],
                    (userid_cache.count - oldest_idx - 1) * sizeof(struct kc_userid_entry));
        }
        userid_cache.count--;
    }

    /* Add new entry */
    int idx = userid_cache.count++;
    snprintf(userid_cache.entries[idx].username,
             sizeof(userid_cache.entries[idx].username),
             "%s", username);
    snprintf(userid_cache.entries[idx].user_id,
             sizeof(userid_cache.entries[idx].user_id),
             "%s", user_id);
    userid_cache.entries[idx].created = time(NULL);

    kc_log_debug("userid_cache: Added %s -> %s (count=%d)",
                 username, user_id, userid_cache.count);
}

const char *
kc_userid_cache_get(const char *username)
{
    if (!username) return NULL;

    time_t now = time(NULL);

    for (int i = 0; i < userid_cache.count; i++) {
        if (strcasecmp(userid_cache.entries[i].username, username) == 0) {
            if (now - userid_cache.entries[i].created > KC_USERID_CACHE_TTL) {
                kc_log_debug("userid_cache: %s expired", username);
                cache_stats.user_cache_misses++;
                return NULL;
            }
            kc_log_debug("userid_cache: Hit %s -> %s",
                         username, userid_cache.entries[i].user_id);
            cache_stats.user_cache_hits++;
            return userid_cache.entries[i].user_id;
        }
    }

    cache_stats.user_cache_misses++;
    return NULL;
}

void
kc_userid_cache_remove(const char *username)
{
    if (!username) return;

    for (int i = 0; i < userid_cache.count; i++) {
        if (strcasecmp(userid_cache.entries[i].username, username) == 0) {
            if (i < userid_cache.count - 1) {
                memmove(&userid_cache.entries[i],
                        &userid_cache.entries[i + 1],
                        (userid_cache.count - i - 1) * sizeof(struct kc_userid_entry));
            }
            userid_cache.count--;
            kc_log_debug("userid_cache: Removed %s", username);
            return;
        }
    }
}

/* =============================================================================
 * User Representation Cache
 * =============================================================================
 */

void
kc_user_repr_cache_put(const char *user_id, json_t *repr)
{
    if (!user_id || !repr) return;

    /* Create a sanitized copy - strip credentials to avoid duplicate password creation.
     * Keycloak GET returns credentials array, but including it in PUT adds new credentials
     * rather than replacing. Credentials should be managed via separate endpoint. */
    json_t *sanitized = json_deep_copy(repr);
    if (!sanitized) {
        kc_log_error("user_repr_cache: Failed to copy repr for %s", user_id);
        return;
    }
    json_object_del(sanitized, "credentials");

    /* Check if already cached (update in place) */
    for (int i = 0; i < repr_cache.count; i++) {
        if (strcmp(repr_cache.entries[i].user_id, user_id) == 0) {
            /* Replace existing representation */
            if (repr_cache.entries[i].repr)
                json_decref(repr_cache.entries[i].repr);
            repr_cache.entries[i].repr = sanitized;  /* Takes ownership */
            repr_cache.entries[i].last_updated = time(NULL);
            kc_log_debug("user_repr_cache: Updated %s (credentials stripped)", user_id);
            return;
        }
    }

    /* Evict oldest entry if full */
    if (repr_cache.count >= KC_USER_REPR_CACHE_MAX) {
        int oldest_idx = 0;
        time_t oldest_time = repr_cache.entries[0].last_updated;

        for (int i = 1; i < repr_cache.count; i++) {
            if (repr_cache.entries[i].last_updated < oldest_time) {
                oldest_time = repr_cache.entries[i].last_updated;
                oldest_idx = i;
            }
        }

        kc_log_debug("user_repr_cache: Evicting %s to make room",
                     repr_cache.entries[oldest_idx].user_id);

        /* Free the old representation */
        if (repr_cache.entries[oldest_idx].repr)
            json_decref(repr_cache.entries[oldest_idx].repr);

        /* Shift remaining entries if not last */
        if (oldest_idx < repr_cache.count - 1) {
            memmove(&repr_cache.entries[oldest_idx],
                    &repr_cache.entries[oldest_idx + 1],
                    (repr_cache.count - oldest_idx - 1) *
                    sizeof(struct kc_user_repr_entry));
        }
        repr_cache.count--;
    }

    /* Add new entry */
    int idx = repr_cache.count++;
    snprintf(repr_cache.entries[idx].user_id,
             sizeof(repr_cache.entries[idx].user_id),
             "%s", user_id);
    repr_cache.entries[idx].repr = sanitized;  /* Takes ownership */
    repr_cache.entries[idx].last_updated = time(NULL);

    kc_log_debug("user_repr_cache: Added %s (count=%d, credentials stripped)",
                 user_id, repr_cache.count);
}

json_t *
kc_user_repr_cache_get(const char *user_id)
{
    if (!user_id) return NULL;

    for (int i = 0; i < repr_cache.count; i++) {
        if (strcmp(repr_cache.entries[i].user_id, user_id) == 0) {
            kc_log_debug("user_repr_cache: Hit for %s", user_id);
            return repr_cache.entries[i].repr;
        }
    }

    kc_log_debug("user_repr_cache: Miss for %s", user_id);
    return NULL;
}

void
kc_user_repr_cache_remove(const char *user_id)
{
    if (!user_id) return;

    for (int i = 0; i < repr_cache.count; i++) {
        if (strcmp(repr_cache.entries[i].user_id, user_id) == 0) {
            if (repr_cache.entries[i].repr)
                json_decref(repr_cache.entries[i].repr);

            if (i < repr_cache.count - 1) {
                memmove(&repr_cache.entries[i],
                        &repr_cache.entries[i + 1],
                        (repr_cache.count - i - 1) *
                        sizeof(struct kc_user_repr_entry));
            }
            repr_cache.count--;
            kc_log_debug("user_repr_cache: Removed %s", user_id);
            return;
        }
    }
}
