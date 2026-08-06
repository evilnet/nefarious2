/*
 * kc_keycloak.c - Keycloak REST API client
 *
 * Async Keycloak operations using kc_http for transport.
 * Extracted from X3's keycloak.c (~9400 lines).
 *
 * Implementation order:
 *   Phase C.1: Token management (ensure, cache, refresh)
 *   Phase C.2: URL building helpers
 *   Phase C.3: User CRUD (get, create, update, delete)
 *   Phase C.4: Password operations (set, verify)
 *   Phase C.5: Group operations (stub)
 *   Phase C.6: Token introspection + JWKS (stub)
 */

#include <kc/kc_keycloak.h>
#include <kc/kc.h>
#include <kc/kc_error_classify.h>
#include <kc/kc_http.h>
#include <kc/kc_jwt.h>
#include <kc/kc_url.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ================================================================
 * Internal state
 * ================================================================ */

static struct kc_config g_config;
static int g_initialized = 0;
static struct kc_keycloak_stats g_kc_stats;

/* ================================================================
 * Token management
 * ================================================================ */

/* Cached admin token + expiry */
static struct kc_access_token *g_cached_token = NULL;
static time_t g_token_expires = 0;
static int g_token_refreshing = 0;

/* Token refresh margin: refresh 60s before expiry */
#define TOKEN_REFRESH_MARGIN 60

/* Waiter queue: callers waiting for token refresh to complete */
#define TOKEN_WAITER_LIMIT 100

struct token_waiter {
    kc_token_cb callback;
    void *data;
    struct token_waiter *next;
};

static struct token_waiter *g_token_waiters = NULL;
static int g_token_waiter_count = 0;

/* Forward declarations */
static void token_refresh_done(struct kc_http_response *resp, void *data);
static void notify_token_waiters(int result, const struct kc_access_token *token);

static struct kc_realm get_realm(void) {
    return (struct kc_realm){ .base_url = g_config.base_url, .realm = g_config.realm };
}

/* ================================================================
 * JSON parsing helpers
 * ================================================================ */

static char *json_get_string(json_t *obj, const char *key)
{
    json_t *val = json_object_get(obj, key);
    if (!val || !json_is_string(val))
        return NULL;
    return strdup(json_string_value(val));
}

static long json_get_long(json_t *obj, const char *key, long def)
{
    json_t *val = json_object_get(obj, key);
    if (!val || !json_is_integer(val))
        return def;
    return (long)json_integer_value(val);
}

static int json_get_bool(json_t *obj, const char *key, int def)
{
    json_t *val = json_object_get(obj, key);
    if (!val)
        return def;
    if (json_is_boolean(val))
        return json_is_true(val) ? 1 : 0;
    return def;
}

/* Extract first string from a Keycloak user attribute (stored as ["value"]) */
static char *json_get_attr_string(json_t *attrs, const char *key)
{
    json_t *arr = json_object_get(attrs, key);
    if (!arr || !json_is_array(arr) || json_array_size(arr) == 0)
        return NULL;
    json_t *first = json_array_get(arr, 0);
    if (!first || !json_is_string(first))
        return NULL;
    return strdup(json_string_value(first));
}

/*
 * Parse LDAP generalized time format (YYYYMMDDHHMMSSZ) to epoch seconds.
 * Returns 0 on failure.
 */
static long
parse_ldap_time(const char *s)
{
    int y, mo, d, h, mi, sec;
    struct tm tm;

    if (!s || sscanf(s, "%4d%2d%2d%2d%2d%2d", &y, &mo, &d, &h, &mi, &sec) != 6)
        return 0;

    memset(&tm, 0, sizeof(tm));
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = sec;
    tm.tm_isdst = 0;

    return (long)timegm(&tm);
}

static struct kc_access_token *parse_access_token(json_t *json)
{
    struct kc_access_token *tok;

    if (!json || !json_is_object(json))
        return NULL;

    tok = calloc(1, sizeof(*tok));
    if (!tok)
        return NULL;

    tok->access_token = json_get_string(json, "access_token");
    if (tok->access_token)
        tok->access_token_size = strlen(tok->access_token);

    tok->refresh_token = json_get_string(json, "refresh_token");
    if (tok->refresh_token)
        tok->refresh_token_size = strlen(tok->refresh_token);

    tok->token_type = json_get_string(json, "token_type");
    if (tok->token_type)
        tok->token_type_size = strlen(tok->token_type);

    tok->session_state = json_get_string(json, "session_state");
    if (tok->session_state)
        tok->session_state_size = strlen(tok->session_state);

    tok->scope = json_get_string(json, "scope");
    if (tok->scope)
        tok->scope_size = strlen(tok->scope);

    tok->expires_in = json_get_long(json, "expires_in", 0);
    tok->refresh_expires_in = json_get_long(json, "refresh_expires_in", 0);

    if (!tok->access_token) {
        kc_access_token_free(tok);
        return NULL;
    }

    /* Extract created_at from the JWT access token without verification */
    tok->created_at = kc_jwt_extract_created_at(tok->access_token);

    return tok;
}

static int parse_user(json_t *json, struct kc_user *user)
{
    if (!json || !json_is_object(json) || !user)
        return -1;

    memset(user, 0, sizeof(*user));

    user->id = json_get_string(json, "id");
    if (user->id)
        user->id_size = strlen(user->id);

    user->username = json_get_string(json, "username");
    if (user->username)
        user->username_size = strlen(user->username);

    user->email = json_get_string(json, "email");
    if (user->email)
        user->email_size = strlen(user->email);

    user->email_verified = json_get_bool(json, "emailVerified", 0);

    /* Top-level requiredActions: the only action the ircd cares about is
     * VERIFY_EMAIL (set by kc_user_create_full under the verification
     * policy).  Absent or empty array => false (the memset above).
     * Confirmed live 2026-08-06 that the search-by-username
     * representation used by kc_user_get() carries this field. */
    {
        json_t *actions = json_object_get(json, "requiredActions");
        if (actions && json_is_array(actions)) {
            size_t ai;
            for (ai = 0; ai < json_array_size(actions); ai++) {
                json_t *act = json_array_get(actions, ai);
                if (act && json_is_string(act)
                    && strcmp(json_string_value(act), "VERIFY_EMAIL") == 0) {
                    user->verify_email_pending = true;
                    break;
                }
            }
        }
    }

    /* Extract custom attributes (Keycloak stores as {"key": ["value"]}) */
    json_t *attrs = json_object_get(json, "attributes");
    if (attrs && json_is_object(attrs)) {
        json_t *olevel = json_object_get(attrs, "x3_opserv_level");
        if (olevel && json_is_array(olevel) && json_array_size(olevel) > 0) {
            json_t *first = json_array_get(olevel, 0);
            if (first && json_is_string(first))
                user->opserv_level = atoi(json_string_value(first));
        }

        /* SCRAM-SHA-256 credentials — three tiers, checked in order:
         *   1. scram_sha256_* — written at account-REGISTER time by this
         *      client's own kc_cred_derive.c (scram_sha256_derive()) and,
         *      in lockstep, by keycloak-webhook-spi's ScramCredentialProvider.
         *      Both write byte-identical SHA-256/4096-iteration/16-byte-salt
         *      material under these names; change one, change both.
         *   2. x3_scram_* — legacy X3-set names.
         *   3. x3_scram_sha256_* — older legacy fallback.
         */
        user->scram_salt       = json_get_attr_string(attrs, "scram_sha256_salt");
        if (!user->scram_salt)
            user->scram_salt   = json_get_attr_string(attrs, "x3_scram_salt");
        if (!user->scram_salt)
            user->scram_salt   = json_get_attr_string(attrs, "x3_scram_sha256_salt");

        user->scram_stored_key = json_get_attr_string(attrs, "scram_sha256_stored_key");
        if (!user->scram_stored_key)
            user->scram_stored_key = json_get_attr_string(attrs, "x3_scram_stored_key");
        if (!user->scram_stored_key)
            user->scram_stored_key = json_get_attr_string(attrs, "x3_scram_sha256_stored_key");

        user->scram_server_key = json_get_attr_string(attrs, "scram_sha256_server_key");
        if (!user->scram_server_key)
            user->scram_server_key = json_get_attr_string(attrs, "x3_scram_server_key");
        if (!user->scram_server_key)
            user->scram_server_key = json_get_attr_string(attrs, "x3_scram_sha256_server_key");

        json_t *iter = json_object_get(attrs, "scram_sha256_iterations");
        if (!iter)
            iter = json_object_get(attrs, "x3_scram_iterations");
        if (!iter)
            iter = json_object_get(attrs, "x3_scram_sha256_iterations");
        if (iter && json_is_array(iter) && json_array_size(iter) > 0) {
            json_t *first = json_array_get(iter, 0);
            if (first && json_is_string(first))
                user->scram_iterations = atoi(json_string_value(first));
        }

        /* ECDSA public key */
        user->ecdsa_pubkey = json_get_attr_string(attrs, "ecdsa_pubkey");

        /* Account creation time (LDAP generalized time from Keycloak's built-in
         * LDAP User Attribute Mapper for createTimestamp) */
        char *created_str = json_get_attr_string(attrs, "createTimestamp");
        if (created_str) {
            user->created_at = parse_ldap_time(created_str);
            free(created_str);
        }
    }

    return 0;
}

static int parse_group(json_t *json, struct kc_group *group)
{
    if (!json || !json_is_object(json) || !group)
        return -1;

    memset(group, 0, sizeof(*group));

    group->id = json_get_string(json, "id");
    if (group->id)
        group->id_size = strlen(group->id);

    group->name = json_get_string(json, "name");
    if (group->name)
        group->name_size = strlen(group->name);

    group->path = json_get_string(json, "path");
    if (group->path)
        group->path_size = strlen(group->path);

    return 0;
}

/* ================================================================
 * User ID cache (simple LRU)
 * ================================================================ */

#define USERID_CACHE_MAX 64
#define USERID_CACHE_TTL 300  /* 5 minutes */

struct userid_cache_entry {
    char *username;
    char *user_id;
    time_t expires;
};

static struct userid_cache_entry g_userid_cache[USERID_CACHE_MAX];
static int g_userid_cache_count = 0;

static void userid_cache_put(const char *username, const char *user_id)
{
    const struct kc_event_ops *ops = kc_get_event_ops();
    unsigned long now = ops ? ops->now() : 0;

    /* Check if already cached */
    for (int i = 0; i < g_userid_cache_count; i++) {
        if (g_userid_cache[i].username &&
            strcmp(g_userid_cache[i].username, username) == 0) {
            free(g_userid_cache[i].user_id);
            g_userid_cache[i].user_id = strdup(user_id);
            g_userid_cache[i].expires = now + USERID_CACHE_TTL;
            return;
        }
    }

    /* Evict oldest if full */
    if (g_userid_cache_count >= USERID_CACHE_MAX) {
        int oldest = 0;
        for (int i = 1; i < g_userid_cache_count; i++) {
            if (g_userid_cache[i].expires < g_userid_cache[oldest].expires)
                oldest = i;
        }
        free(g_userid_cache[oldest].username);
        free(g_userid_cache[oldest].user_id);
        g_userid_cache[oldest] = g_userid_cache[--g_userid_cache_count];
    }

    /* Add new entry */
    g_userid_cache[g_userid_cache_count].username = strdup(username);
    g_userid_cache[g_userid_cache_count].user_id = strdup(user_id);
    g_userid_cache[g_userid_cache_count].expires = now + USERID_CACHE_TTL;
    g_userid_cache_count++;
}

static void userid_cache_invalidate(const char *username)
{
    for (int i = 0; i < g_userid_cache_count; i++) {
        if (g_userid_cache[i].username &&
            strcmp(g_userid_cache[i].username, username) == 0) {
            free(g_userid_cache[i].username);
            free(g_userid_cache[i].user_id);
            g_userid_cache[i] = g_userid_cache[--g_userid_cache_count];
            return;
        }
    }
}

static void userid_cache_clear(void)
{
    for (int i = 0; i < g_userid_cache_count; i++) {
        free(g_userid_cache[i].username);
        free(g_userid_cache[i].user_id);
    }
    g_userid_cache_count = 0;
}

/* ================================================================
 * Token management implementation
 * ================================================================ */

static void notify_token_waiters(int result, const struct kc_access_token *token)
{
    struct token_waiter *w = g_token_waiters;
    g_token_waiters = NULL;
    g_token_waiter_count = 0;

    while (w) {
        struct token_waiter *next = w->next;
        if (w->callback)
            w->callback(result, token, w->data);
        free(w);
        w = next;
    }
}

static void token_refresh_done(struct kc_http_response *resp, void *data)
{
    (void)data;

    g_token_refreshing = 0;

    if (!resp || resp->status_code != 200 || !resp->json) {
        kc_log_error("kc_keycloak: token refresh failed (status=%ld)",
                     resp ? resp->status_code : 0);
        notify_token_waiters(KC_TOKEN_ERROR, NULL);
        return;
    }

    /* Parse new token */
    struct kc_access_token *new_token = parse_access_token(resp->json);
    if (!new_token) {
        kc_log_error("kc_keycloak: failed to parse token response");
        notify_token_waiters(KC_TOKEN_ERROR, NULL);
        return;
    }

    /* Replace cached token */
    if (g_cached_token)
        kc_access_token_free(g_cached_token);
    g_cached_token = new_token;

    /* Set expiry */
    const struct kc_event_ops *ops = kc_get_event_ops();
    g_token_expires = (ops ? ops->now() : (unsigned long)time(NULL)) + new_token->expires_in;

    kc_log_debug("kc_keycloak: token refreshed, expires_in=%ld", new_token->expires_in);

    /* Notify all waiters */
    notify_token_waiters(KC_SUCCESS, g_cached_token);
}

static int start_token_refresh(void)
{
    char *url;
    char body[1024];
    struct kc_http_request req;
    struct curl_slist *headers = NULL;

    if (g_token_refreshing)
        return 0;  /* Already in progress */

    url = kc_url_token(get_realm());
    if (!url)
        return -1;

    snprintf(body, sizeof(body),
             "grant_type=client_credentials&client_id=%s&client_secret=%s",
             g_config.client_id, g_config.client_secret);

    headers = curl_slist_append(NULL, "Content-Type: application/x-www-form-urlencoded");

    memset(&req, 0, sizeof(req));
    req.url = url;
    req.method = "POST";
    req.body = body;
    req.body_len = strlen(body);
    req.headers = headers;
    req.timeout_ms = 10000;

    g_token_refreshing = 1;

    int rc = kc_http_request(&req, token_refresh_done, NULL);

    curl_slist_free_all(headers);
    free(url);

    if (rc != 0) {
        g_token_refreshing = 0;
        return -1;
    }

    return 0;
}

int kc_token_ensure(kc_token_cb cb, void *data)
{
    if (!g_initialized || !cb)
        return -1;

    const struct kc_event_ops *ops = kc_get_event_ops();
    unsigned long now = ops ? ops->now() : (unsigned long)time(NULL);

    /* Token still valid? */
    if (g_cached_token && (unsigned long)g_token_expires > now + TOKEN_REFRESH_MARGIN) {
        /* Invoke callback synchronously */
        cb(KC_SUCCESS, g_cached_token, data);
        return 0;
    }

    /* Need to refresh. Add to waiter queue. */
    if (g_token_waiter_count >= TOKEN_WAITER_LIMIT) {
        kc_log_error("kc_keycloak: token waiter queue full");
        cb(KC_UNAVAILABLE, NULL, data);
        return 0;
    }

    struct token_waiter *w = calloc(1, sizeof(*w));
    if (!w)
        return -1;

    w->callback = cb;
    w->data = data;
    w->next = g_token_waiters;
    g_token_waiters = w;
    g_token_waiter_count++;

    /* Start refresh if not already in progress */
    if (!g_token_refreshing) {
        if (start_token_refresh() != 0) {
            /* Failed to start — notify all waiters, ourselves included.
             *
             * Return SUCCESS, not -1: the contract every caller relies on is
             * "non-zero return => the callback was NOT and will NOT be
             * invoked, so the caller still owns its context".  We just ran
             * the callback (which frees that context), so reporting failure
             * here invites a double free in the caller's error path. */
            notify_token_waiters(KC_TOKEN_ERROR, NULL);
            return 0;
        }
    }

    return 0;
}

const struct kc_access_token *kc_token_cached(void)
{
    return g_cached_token;
}

/* ================================================================
 * Token-then-request pattern
 *
 * Most Keycloak operations need a valid token before making the
 * actual API call. This helper chains: ensure_token → build request
 * → submit HTTP → parse response → invoke user callback.
 * ================================================================ */

/* Context for a token-gated operation */
struct kc_op_ctx {
    /* User callback */
    union {
        kc_user_cb user;
        kc_users_cb users;
        kc_result_cb result;
        kc_token_cb token;
        kc_groups_cb groups;
        kc_introspect_cb introspect;
    } cb;
    void *cb_data;

    /* Request details (built before token acquisition) */
    char *url;
    char *method;
    char *body;
    struct curl_slist *headers;

    /* Operation type for response dispatch */
    enum {
        OP_GET_USER,
        OP_CREATE_USER,
        OP_DELETE_USER,
        OP_UPDATE_USER,
        OP_SET_PASSWORD,
        OP_VERIFY_PASSWORD,
        OP_SEND_VERIFY_EMAIL,
        OP_GET_GROUPS,
        OP_ADD_GROUP,
        OP_REMOVE_GROUP,
        OP_SEARCH_USERS,
        OP_INTROSPECT,
        OP_JWKS_REFRESH
    } op;

    /* Extra context for specific operations */
    char *username;  /* For user ID caching */
};

static void op_ctx_free(struct kc_op_ctx *ctx)
{
    if (!ctx)
        return;
    free(ctx->url);
    free(ctx->body);
    free(ctx->username);
    if (ctx->headers)
        curl_slist_free_all(ctx->headers);
    free(ctx);
}

/* Response handler: dispatch based on operation type */
static void op_response_handler(struct kc_http_response *resp, void *data)
{
    struct kc_op_ctx *ctx = (struct kc_op_ctx *)data;

    if (!ctx)
        return;

    switch (ctx->op) {

    case OP_GET_USER: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.user(KC_ERROR, NULL, ctx->cb_data);
            break;
        }
        if (resp->status_code == 404) {
            ctx->cb.user(KC_NOT_FOUND, NULL, ctx->cb_data);
            break;
        }
        if (resp->status_code != 200 || !resp->json) {
            ctx->cb.user(KC_ERROR, NULL, ctx->cb_data);
            break;
        }

        /* Response is an array (even for exact username match) */
        if (json_is_array(resp->json)) {
            size_t count = json_array_size(resp->json);
            if (count == 0) {
                ctx->cb.user(KC_NOT_FOUND, NULL, ctx->cb_data);
                break;
            }
            if (count > 1) {
                kc_log_warning("kc_keycloak: get_user returned %zu results", count);
                ctx->cb.user(KC_ERROR, NULL, ctx->cb_data);
                break;
            }
            struct kc_user user;
            if (parse_user(json_array_get(resp->json, 0), &user) == 0) {
                /* Cache user ID */
                if (user.username && user.id)
                    userid_cache_put(user.username, user.id);
                ctx->cb.user(KC_SUCCESS, &user, ctx->cb_data);
                kc_user_free(&user);
            } else {
                ctx->cb.user(KC_INVALID_RESPONSE, NULL, ctx->cb_data);
            }
        } else if (json_is_object(resp->json)) {
            /* Direct object response (get by ID) */
            struct kc_user user;
            if (parse_user(resp->json, &user) == 0) {
                if (user.username && user.id)
                    userid_cache_put(user.username, user.id);
                ctx->cb.user(KC_SUCCESS, &user, ctx->cb_data);
                kc_user_free(&user);
            } else {
                ctx->cb.user(KC_INVALID_RESPONSE, NULL, ctx->cb_data);
            }
        } else {
            ctx->cb.user(KC_INVALID_RESPONSE, NULL, ctx->cb_data);
        }
        break;
    }

    case OP_SEARCH_USERS: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.users(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        }
        if (resp->status_code != 200 || !resp->json) {
            ctx->cb.users(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        }
        if (!json_is_array(resp->json)) {
            ctx->cb.users(KC_INVALID_RESPONSE, NULL, 0, ctx->cb_data);
            break;
        }

        size_t count = json_array_size(resp->json);
        if (count == 0) {
            ctx->cb.users(KC_NOT_FOUND, NULL, 0, ctx->cb_data);
            break;
        }

        struct kc_user *users = calloc(count, sizeof(*users));
        if (!users) {
            ctx->cb.users(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        }

        size_t valid = 0;
        for (size_t i = 0; i < count; i++) {
            if (parse_user(json_array_get(resp->json, i), &users[valid]) == 0)
                valid++;
        }

        if (valid == 0) {
            free(users);
            ctx->cb.users(KC_NOT_FOUND, NULL, 0, ctx->cb_data);
        } else {
            ctx->cb.users(KC_SUCCESS, users, (int)valid, ctx->cb_data);
            for (size_t i = 0; i < valid; i++)
                kc_user_free(&users[i]);
            free(users);
        }
        break;
    }

    case OP_CREATE_USER: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        if (resp->status_code == 201) {
            /* Extract user ID from Location header if available */
            /* TODO: capture Location header from response */
            ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        } else if (resp->status_code == 409) {
            /* username/email already exists — kc_user_create_full and its
             * thin-wrapper kc_user_create share this dispatch arm. */
            ctx->cb.result(KC_CONFLICT, ctx->cb_data);
        } else {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
        }
        break;
    }

    case OP_DELETE_USER: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        if (resp->status_code == 204 || resp->status_code == 200) {
            /* Invalidate caches */
            if (ctx->username)
                userid_cache_invalidate(ctx->username);
            ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        } else if (resp->status_code == 404) {
            ctx->cb.result(KC_NOT_FOUND, ctx->cb_data);
        } else {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
        }
        break;
    }

    case OP_UPDATE_USER: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        if (resp->status_code == 204 || resp->status_code == 200) {
            ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        } else if (resp->status_code == 404) {
            ctx->cb.result(KC_NOT_FOUND, ctx->cb_data);
        } else {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
        }
        break;
    }

    case OP_SET_PASSWORD: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        if (resp->status_code == 204 || resp->status_code == 200) {
            ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        } else {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
        }
        break;
    }

    case OP_SEND_VERIFY_EMAIL: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        if (resp->status_code == 204 || resp->status_code == 200) {
            ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        } else {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
        }
        break;
    }

    case OP_VERIFY_PASSWORD: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.token(KC_ERROR, NULL, ctx->cb_data);
            break;
        }
        if (resp->status_code == 200 && resp->json) {
            struct kc_access_token *tok = parse_access_token(resp->json);
            if (tok) {
                ctx->cb.token(KC_SUCCESS, tok, ctx->cb_data);
                kc_access_token_free(tok);
            } else {
                ctx->cb.token(KC_INVALID_RESPONSE, NULL, ctx->cb_data);
            }
        } else if (resp->status_code == 401 || resp->status_code == 400) {
            /* resp->json is populated for any status code whenever the body
             * parses as JSON (see kc_http.c's completion handler — parsing
             * isn't gated on 2xx), so no local re-parse is needed here.
             * Distinguish "bad credentials" from "account not fully set up"
             * (pending a required action) via the error_description body. */
            ctx->cb.token(kc_classify_grant_error(resp->json), NULL, ctx->cb_data);
        } else {
            ctx->cb.token(KC_ERROR, NULL, ctx->cb_data);
        }
        break;
    }

    case OP_GET_GROUPS: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.groups(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        }
        if (resp->status_code != 200 || !resp->json || !json_is_array(resp->json)) {
            ctx->cb.groups(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        }
        size_t count = json_array_size(resp->json);
        struct kc_group *groups = NULL;
        if (count > 0) {
            groups = calloc(count, sizeof(*groups));
            for (size_t i = 0; i < count; i++)
                parse_group(json_array_get(resp->json, i), &groups[i]);
        }
        ctx->cb.groups(KC_SUCCESS, groups, (int)count, ctx->cb_data);
        if (groups) {
            for (size_t i = 0; i < count; i++)
                kc_group_free(&groups[i]);
            free(groups);
        }
        break;
    }

    case OP_ADD_GROUP:
    case OP_REMOVE_GROUP: {
        if (!resp || resp->status_code == 0) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        if (resp->status_code == 204 || resp->status_code == 200) {
            ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        } else if (resp->status_code == 404) {
            ctx->cb.result(KC_NOT_FOUND, ctx->cb_data);
        } else {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
        }
        break;
    }

    case OP_INTROSPECT: {
        if (!resp || resp->status_code == 0 || !resp->json) {
            ctx->cb.introspect(KC_ERROR, NULL, ctx->cb_data);
            break;
        }
        struct kc_token_info info;
        memset(&info, 0, sizeof(info));
        info.active = json_get_bool(resp->json, "active", 0);
        info.username = json_get_string(resp->json, "username");
        if (info.username) info.username_size = strlen(info.username);
        info.email = json_get_string(resp->json, "email");
        if (info.email) info.email_size = strlen(info.email);
        info.sub = json_get_string(resp->json, "sub");
        if (info.sub) info.sub_size = strlen(info.sub);
        info.exp = json_get_long(resp->json, "exp", 0);
        info.iat = json_get_long(resp->json, "iat", 0);
        /* Issuer and authorized-party: the introspection response carries the
         * same iss/azp claims as the token itself, so the caller can apply the
         * identical deployment policy (expected-issuer + allowed-client) on the
         * introspection path as on local JWT validation. */
        info.iss = json_get_string(resp->json, "iss");
        if (info.iss) info.iss_size = strlen(info.iss);
        info.azp = json_get_string(resp->json, "azp");
        if (info.azp) info.azp_size = strlen(info.azp);
        ctx->cb.introspect(KC_SUCCESS, &info, ctx->cb_data);
        kc_token_info_free(&info);
        break;
    }

    case OP_JWKS_REFRESH: {
        if (!resp || resp->status_code != 200) {
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        /* TODO: Phase C.6 - parse and cache JWKS keys */
        ctx->cb.result(KC_SUCCESS, ctx->cb_data);
        break;
    }

    } /* switch */

    op_ctx_free(ctx);
}

/*
 * Token callback: once we have a valid token, submit the actual HTTP request.
 */
static void op_token_ready(int result, const struct kc_access_token *token, void *data)
{
    struct kc_op_ctx *ctx = (struct kc_op_ctx *)data;

    if (result != KC_SUCCESS || !token || !token->access_token) {
        /* Token acquisition failed — propagate error */
        switch (ctx->op) {
        case OP_GET_USER:
            ctx->cb.user(KC_TOKEN_ERROR, NULL, ctx->cb_data);
            break;
        case OP_SEARCH_USERS:
            ctx->cb.users(KC_TOKEN_ERROR, NULL, 0, ctx->cb_data);
            break;
        case OP_VERIFY_PASSWORD:
            ctx->cb.token(KC_TOKEN_ERROR, NULL, ctx->cb_data);
            break;
        case OP_GET_GROUPS:
            ctx->cb.groups(KC_TOKEN_ERROR, NULL, 0, ctx->cb_data);
            break;
        case OP_INTROSPECT:
            ctx->cb.introspect(KC_TOKEN_ERROR, NULL, ctx->cb_data);
            break;
        default:
            ctx->cb.result(KC_TOKEN_ERROR, ctx->cb_data);
            break;
        }
        op_ctx_free(ctx);
        return;
    }

    /* Build the HTTP request with the token */
    struct kc_http_request req;
    memset(&req, 0, sizeof(req));
    req.url = ctx->url;
    req.method = ctx->method;
    req.body = ctx->body;
    req.body_len = ctx->body ? strlen(ctx->body) : 0;
    req.headers = ctx->headers;
    req.bearer_token = token->access_token;
    req.timeout_ms = 10000;

    if (kc_http_request(&req, op_response_handler, ctx) != 0) {
        /* HTTP request failed to submit */
        switch (ctx->op) {
        case OP_GET_USER:
            ctx->cb.user(KC_ERROR, NULL, ctx->cb_data);
            break;
        case OP_SEARCH_USERS:
            ctx->cb.users(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        case OP_VERIFY_PASSWORD:
            ctx->cb.token(KC_ERROR, NULL, ctx->cb_data);
            break;
        case OP_GET_GROUPS:
            ctx->cb.groups(KC_ERROR, NULL, 0, ctx->cb_data);
            break;
        case OP_INTROSPECT:
            ctx->cb.introspect(KC_ERROR, NULL, ctx->cb_data);
            break;
        default:
            ctx->cb.result(KC_ERROR, ctx->cb_data);
            break;
        }
        op_ctx_free(ctx);
    }
    /* On success, ctx is owned by op_response_handler */
}

/*
 * Helper to start a token-gated operation.
 */
static int start_op(struct kc_op_ctx *ctx)
{
    if (!g_initialized) {
        op_ctx_free(ctx);
        return -1;
    }
    return kc_token_ensure(op_token_ready, ctx);
}

/* ================================================================
 * Public API: Init/Shutdown
 * ================================================================ */

int kc_keycloak_init(const struct kc_config *config)
{
    if (g_initialized || !config)
        return -1;

    memset(&g_config, 0, sizeof(g_config));
    if (config->base_url)
        g_config.base_url = strdup(config->base_url);
    if (config->realm)
        g_config.realm = strdup(config->realm);
    if (config->client_id)
        g_config.client_id = strdup(config->client_id);
    if (config->client_secret)
        g_config.client_secret = strdup(config->client_secret);

    memset(&g_kc_stats, 0, sizeof(g_kc_stats));
    g_initialized = 1;

    kc_log_info("kc_keycloak: initialized for %s realm=%s",
                g_config.base_url ? g_config.base_url : "(null)",
                g_config.realm ? g_config.realm : "(null)");

    return 0;
}

void kc_keycloak_shutdown(void)
{
    if (!g_initialized)
        return;

    /* Notify pending waiters of shutdown */
    notify_token_waiters(KC_UNAVAILABLE, NULL);

    free((void *)g_config.base_url);
    free((void *)g_config.realm);
    free((void *)g_config.client_id);
    free((void *)g_config.client_secret);
    memset(&g_config, 0, sizeof(g_config));

    if (g_cached_token) {
        kc_access_token_free(g_cached_token);
        g_cached_token = NULL;
    }
    g_token_expires = 0;
    g_token_refreshing = 0;

    userid_cache_clear();

    g_initialized = 0;
    kc_log_info("kc_keycloak: shutdown");
}

/* ================================================================
 * Public API: User operations
 * ================================================================ */

int kc_user_get(const char *username, kc_user_cb cb, void *data)
{
    if (!username || !cb)
        return -1;

    /* Check user ID cache — if hit, we could build a direct /users/{id} URL,
     * but the callback still needs the full user struct. For now, always
     * query by username. The cache accelerates X3's pattern where it
     * first gets user to obtain the ID. */

    char *escaped = curl_easy_escape(NULL, username, 0);
    if (!escaped)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        curl_free(escaped);
        return -1;
    }

    ctx->op = OP_GET_USER;
    ctx->cb.user = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user_by_username(get_realm(), escaped, 1);
    ctx->method = "GET";
    ctx->username = strdup(username);

    curl_free(escaped);

    return start_op(ctx);
}

int kc_user_get_by_id(const char *id, kc_user_cb cb, void *data)
{
    if (!id || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_GET_USER;
    ctx->cb.user = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user(get_realm(), id);
    ctx->method = "GET";

    return start_op(ctx);
}

int kc_user_search(const char *query, bool exact, kc_users_cb cb, void *data)
{
    if (!query || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_SEARCH_USERS;
    ctx->cb.users = cb;
    ctx->cb_data = data;
    ctx->method = "GET";

    /* If query contains ':', it's an attribute search (e.g. "x509_fingerprints:ABC").
     * kc_url_fingerprint_search builds the full q= parameter — only escape the
     * value part (after the colon).
     * Otherwise, it's a username search — escape the whole query. */
    const char *colon = strchr(query, ':');
    if (colon) {
        const char *value = colon + 1;
        char *escaped = curl_easy_escape(NULL, value, 0);
        if (!escaped) {
            op_ctx_free(ctx);
            return -1;
        }
        ctx->url = kc_url_fingerprint_search(get_realm(), escaped);
        curl_free(escaped);
    } else {
        char *escaped = curl_easy_escape(NULL, query, 0);
        if (!escaped) {
            op_ctx_free(ctx);
            return -1;
        }
        ctx->url = kc_url_user_by_username(get_realm(), escaped, exact ? 1 : 0);
        curl_free(escaped);
    }

    if (!ctx->url) {
        op_ctx_free(ctx);
        return -1;
    }

    return start_op(ctx);
}

int kc_user_create_full(const struct kc_user_create_req *req,
                        kc_result_cb cb, void *data)
{
    json_t *user_repr;
    size_t i;

    if (!req || !req->username || !req->cred_data || !req->secret_data || !cb)
        return -1;

    user_repr = json_object();
    json_object_set_new(user_repr, "username", json_string(req->username));
    json_object_set_new(user_repr, "enabled", json_true());
    if (req->email && req->email[0])
        json_object_set_new(user_repr, "email", json_string(req->email));

    if (req->set_email_verified) {
        json_object_set_new(user_repr, "emailVerified", json_false());
        json_t *ra = json_array();
        json_array_append_new(ra, json_string("VERIFY_EMAIL"));
        json_object_set_new(user_repr, "requiredActions", ra);
    }

    if (req->n_attrs) {
        json_t *attrs = json_object();
        for (i = 0; i < req->n_attrs; i++) {
            json_t *arr = json_array();
            json_array_append_new(arr, json_string(req->attr_values[i]));
            json_object_set_new(attrs, req->attr_keys[i], arr);
        }
        json_object_set_new(user_repr, "attributes", attrs);
    }

    /* credentials: Keycloak's admin REST schema wants credentialData/
     * secretData as JSON-*encoded strings* nested inside the credential
     * object, not as parsed JSON objects -- confirmed against a live
     * Keycloak 26.4.7 (Task 0's probe, and reproduced directly: embedding
     * them as objects gets a verbatim 400 "Cannot parse the JSON" from the
     * admin API; embedding the same content as strings gets 201). Still
     * json_loads() req->cred_data/secret_data first as a well-formedness
     * check on the derived credential material -- reject rather than send
     * Keycloak something we already know is broken -- but embed the
     * *original strings*, not the parsed objects. */
    {
        json_error_t err;
        json_t *cred_obj = json_loads(req->cred_data, 0, &err);
        json_t *secret_obj = json_loads(req->secret_data, 0, &err);
        if (!cred_obj || !secret_obj) {
            if (cred_obj) json_decref(cred_obj);
            if (secret_obj) json_decref(secret_obj);
            json_decref(user_repr);
            return -1;
        }
        json_decref(cred_obj);
        json_decref(secret_obj);
        json_t *cred = json_object();
        json_object_set_new(cred, "type", json_string("password"));
        json_object_set_new(cred, "credentialData", json_string(req->cred_data));
        json_object_set_new(cred, "secretData", json_string(req->secret_data));
        json_t *creds = json_array();
        json_array_append_new(creds, cred);
        json_object_set_new(user_repr, "credentials", creds);
    }

    char *body = json_dumps(user_repr, JSON_COMPACT);
    json_decref(user_repr);

    if (!body)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(body);
        return -1;
    }

    ctx->op = OP_CREATE_USER;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_users(get_realm());
    ctx->method = "POST";
    ctx->body = body;
    ctx->headers = curl_slist_append(NULL, "Content-Type: application/json");
    ctx->username = strdup(req->username);

    return start_op(ctx);
}

int kc_user_create(const char *username, const char *email,
                   const char *cred_data, const char *secret_data,
                   kc_result_cb cb, void *data)
{
    struct kc_user_create_req req;

    memset(&req, 0, sizeof(req));
    req.username = username;
    req.email = email;
    req.cred_data = cred_data;
    req.secret_data = secret_data;

    return kc_user_create_full(&req, cb, data);
}

int kc_user_delete(const char *id, kc_result_cb cb, void *data)
{
    if (!id || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_DELETE_USER;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user(get_realm(), id);
    ctx->method = "DELETE";

    return start_op(ctx);
}

int kc_user_update(const char *id, json_t *repr, kc_result_cb cb, void *data)
{
    if (!id || !repr || !cb)
        return -1;

    char *body = json_dumps(repr, JSON_COMPACT);
    if (!body)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(body);
        return -1;
    }

    ctx->op = OP_UPDATE_USER;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user(get_realm(), id);
    ctx->method = "PUT";
    ctx->body = body;
    ctx->headers = curl_slist_append(NULL, "Content-Type: application/json");

    return start_op(ctx);
}

/* ================================================================
 * Public API: Password operations
 * ================================================================ */

int kc_user_set_password(const char *id, const char *password,
                         kc_result_cb cb, void *data)
{
    if (!id || !password || !cb)
        return -1;

    json_t *body_json = json_object();
    json_object_set_new(body_json, "type", json_string("password"));
    json_object_set_new(body_json, "temporary", json_false());
    json_object_set_new(body_json, "value", json_string(password));

    char *body = json_dumps(body_json, JSON_COMPACT);
    json_decref(body_json);

    if (!body)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(body);
        return -1;
    }

    ctx->op = OP_SET_PASSWORD;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user_reset_password(get_realm(), id);
    ctx->method = "PUT";
    ctx->body = body;
    ctx->headers = curl_slist_append(NULL, "Content-Type: application/json");

    return start_op(ctx);
}

int kc_user_send_verify_email(const char *id, kc_result_cb cb, void *data)
{
    if (!id || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_SEND_VERIFY_EMAIL;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user_send_verify_email(get_realm(), id);
    ctx->method = "PUT";
    ctx->body = NULL;

    return start_op(ctx);
}

int kc_user_verify_password(const char *username, const char *password,
                            kc_token_cb cb, void *data)
{
    if (!username || !password || !cb)
        return -1;

    /* Resource owner password grant — doesn't need admin token */
    char *url = kc_url_token(get_realm());
    if (!url)
        return -1;

    char *body = NULL;
    size_t body_len;
    char *escaped_user = curl_easy_escape(NULL, username, 0);
    char *escaped_pass = curl_easy_escape(NULL, password, 0);

    if (!escaped_user || !escaped_pass) {
        curl_free(escaped_user);
        curl_free(escaped_pass);
        free(url);
        return -1;
    }

    body_len = snprintf(NULL, 0,
        "grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
        g_config.client_id, g_config.client_secret, escaped_user, escaped_pass);
    body = malloc(body_len + 1);
    snprintf(body, body_len + 1,
        "grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
        g_config.client_id, g_config.client_secret, escaped_user, escaped_pass);

    curl_free(escaped_user);
    curl_free(escaped_pass);

    /* This operation doesn't need a bearer token — it IS the token request.
     * Submit directly without going through kc_token_ensure. */
    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(url);
        free(body);
        return -1;
    }

    ctx->op = OP_VERIFY_PASSWORD;
    ctx->cb.token = cb;
    ctx->cb_data = data;

    struct kc_http_request req;
    memset(&req, 0, sizeof(req));
    req.url = url;
    req.method = "POST";
    req.body = body;
    req.body_len = strlen(body);
    req.headers = curl_slist_append(NULL, "Content-Type: application/x-www-form-urlencoded");
    req.timeout_ms = 10000;

    int rc = kc_http_request(&req, op_response_handler, ctx);

    curl_slist_free_all(req.headers);
    free(url);
    free(body);

    if (rc != 0) {
        op_ctx_free(ctx);
        return -1;
    }

    return 0;
}

/* ================================================================
 * Public API: Group operations
 * ================================================================ */

int kc_user_get_groups(const char *user_id, kc_groups_cb cb, void *data)
{
    if (!user_id || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_GET_GROUPS;
    ctx->cb.groups = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user_groups(get_realm(), user_id);
    ctx->method = "GET";

    return start_op(ctx);
}

int kc_user_add_group(const char *user_id, const char *group_id,
                      kc_result_cb cb, void *data)
{
    if (!user_id || !group_id || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_ADD_GROUP;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user_group(get_realm(), user_id, group_id);
    ctx->method = "PUT";

    return start_op(ctx);
}

int kc_user_remove_group(const char *user_id, const char *group_id,
                         kc_result_cb cb, void *data)
{
    if (!user_id || !group_id || !cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_REMOVE_GROUP;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_user_group(get_realm(), user_id, group_id);
    ctx->method = "DELETE";

    return start_op(ctx);
}

/* ================================================================
 * Public API: Token introspection
 * ================================================================ */

int kc_token_introspect(const char *token, kc_introspect_cb cb, void *data)
{
    if (!token || !cb)
        return -1;

    char *url = kc_url_introspect(get_realm());
    if (!url)
        return -1;

    /* Introspect uses client credentials in POST body, not bearer token */
    char *escaped_token = curl_easy_escape(NULL, token, 0);
    if (!escaped_token) {
        free(url);
        return -1;
    }

    size_t body_len = snprintf(NULL, 0,
        "token=%s&client_id=%s&client_secret=%s",
        escaped_token, g_config.client_id, g_config.client_secret);
    char *body = malloc(body_len + 1);
    snprintf(body, body_len + 1,
        "token=%s&client_id=%s&client_secret=%s",
        escaped_token, g_config.client_id, g_config.client_secret);

    curl_free(escaped_token);

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(url);
        free(body);
        return -1;
    }

    ctx->op = OP_INTROSPECT;
    ctx->cb.introspect = cb;
    ctx->cb_data = data;

    /* Introspect doesn't need admin bearer token */
    struct kc_http_request req;
    memset(&req, 0, sizeof(req));
    req.url = url;
    req.method = "POST";
    req.body = body;
    req.body_len = strlen(body);
    req.headers = curl_slist_append(NULL, "Content-Type: application/x-www-form-urlencoded");
    req.timeout_ms = 10000;

    int rc = kc_http_request(&req, op_response_handler, ctx);

    curl_slist_free_all(req.headers);
    free(url);
    free(body);

    if (rc != 0) {
        op_ctx_free(ctx);
        return -1;
    }

    return 0;
}

/* ================================================================
 * Public API: JWKS
 * ================================================================ */

int kc_jwks_refresh(kc_result_cb cb, void *data)
{
    if (!cb)
        return -1;

    struct kc_op_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;

    ctx->op = OP_JWKS_REFRESH;
    ctx->cb.result = cb;
    ctx->cb_data = data;
    ctx->url = kc_url_jwks(get_realm());
    ctx->method = "GET";

    /* JWKS endpoint is public — no token needed */
    struct kc_http_request req;
    memset(&req, 0, sizeof(req));
    req.url = ctx->url;
    req.method = "GET";
    req.timeout_ms = 10000;

    int rc = kc_http_request(&req, op_response_handler, ctx);
    if (rc != 0) {
        op_ctx_free(ctx);
        return -1;
    }

    return 0;
}

int kc_token_verify_offline(const char *token, struct kc_token_info *info)
{
    (void)token; (void)info;
    /* TODO: Phase C.6 - implement offline JWT verification using cached JWKS */
    return -1;
}

/* ================================================================
 * Public API: Statistics
 * ================================================================ */

void kc_keycloak_stats_get(struct kc_keycloak_stats *out)
{
    if (out)
        *out = g_kc_stats;
}

/* ================================================================
 * Memory management
 * ================================================================ */

void kc_access_token_free(struct kc_access_token *token)
{
    if (!token)
        return;
    /* Securely zero sensitive token data */
    if (token->access_token) {
        memset(token->access_token, 0, token->access_token_size);
        free(token->access_token);
    }
    if (token->refresh_token) {
        memset(token->refresh_token, 0, token->refresh_token_size);
        free(token->refresh_token);
    }
    free(token->token_type);
    free(token->session_state);
    free(token->scope);
    free(token);
}

void kc_user_free(struct kc_user *user)
{
    if (!user)
        return;
    free(user->id);
    free(user->username);
    free(user->email);
    free(user->scram_salt);
    free(user->scram_stored_key);
    free(user->scram_server_key);
    free(user->ecdsa_pubkey);
}

void kc_token_info_free(struct kc_token_info *info)
{
    if (!info)
        return;
    free(info->username);
    free(info->email);
    free(info->sub);
    free(info->iss);
    free(info->azp);
}

void kc_group_free(struct kc_group *group)
{
    if (!group)
        return;
    free(group->id);
    free(group->name);
    free(group->path);
}
