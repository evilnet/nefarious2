/*
 * kc_keycloak.h - Keycloak REST API client for libkc
 *
 * Async Keycloak operations: token management, user CRUD, groups,
 * token introspection, JWKS. All operations are non-blocking and
 * use callbacks.
 *
 * Extracted from X3's keycloak.c (~9400 lines).
 */

#ifndef KC_KEYCLOAK_H
#define KC_KEYCLOAK_H

#include <stdbool.h>
#include <stddef.h>
#include <jansson.h>

/* Error codes */
enum kc_error {
    KC_SUCCESS          =  0,
    KC_ERROR            = -1,   /* Generic/unknown error */
    KC_USER_EXISTS      = -2,   /* User already exists */
    KC_FORBIDDEN        = -3,   /* Invalid credentials / access denied */
    KC_NOT_FOUND        = -4,   /* User not found */
    KC_COLLISION        = -5,   /* Multiple users matched */
    KC_TIMEOUT          = -6,   /* Connection timeout */
    KC_UNAVAILABLE      = -7,   /* Server unavailable */
    KC_TOKEN_ERROR      = -8,   /* Token refresh/acquisition failed */
    KC_INVALID_RESPONSE = -9,   /* Server returned unexpected response */
    KC_UNVERIFIED       = -10,  /* credentials OK-shaped but account not fully set up (pending required action) */
    KC_CONFLICT         = -11,  /* create: the username already exists (HTTP 409) */
    KC_CONFLICT_EMAIL   = -12,  /* create: the email is another user's (HTTP 409) */
    KC_BAD_USERNAME     = -13,  /* create: Keycloak refused the username (HTTP 400) */
    KC_BAD_EMAIL        = -14,  /* create: Keycloak refused the email (HTTP 400) */
    KC_BAD_PASSWORD     = -15,  /* create: Keycloak refused the credential (HTTP 400) */
    KC_REJECTED         = -16,  /* create: refused (HTTP 400), for no reason above */
    KC_DISABLED         = -17,  /* password grant: the account is disabled */
    KC_CLIENT_REFUSED   = -18   /* password grant: Keycloak refused the caller's own client
                                 * (bad client secret, or the client may not use the grant) */
};

/* Keycloak configuration */
struct kc_config {
    const char *base_url;         /* e.g., "http://keycloak:8080" */
    const char *realm;
    const char *client_id;
    const char *client_secret;
    long timeout_ms;              /* per-request limit in ms; <= 0 means 10000 */
};

/* Access token */
struct kc_access_token {
    char *access_token;
    size_t access_token_size;
    long expires_in;
    long refresh_expires_in;
    char *refresh_token;
    size_t refresh_token_size;
    char *token_type;
    size_t token_type_size;
    char *session_state;
    size_t session_state_size;
    char *scope;
    size_t scope_size;
    char *id_token;               /* OpenID Connect ID token; NULL when the grant did not ask for one */
    size_t id_token_size;
    long created_at;              /* Account creation time (epoch), from JWT created_at claim */
};

/* User representation */
struct kc_user {
    char *id;
    size_t id_size;
    char *username;
    size_t username_size;
    char *email;
    size_t email_size;
    bool email_verified;
    /* Top-level requiredActions[] contains "VERIFY_EMAIL": verification
     * was requested for this account and is still pending.  Distinguishes
     * a daemon-born unverified account (action pending -> refuse) from a
     * legacy account that merely predates emailVerified (no action ->
     * allow).  Parsed in parse_user(); scalar, so kc_user_free() is
     * untouched. */
    bool verify_email_pending;
    int opserv_level;             /* Custom attribute: x3_opserv_level */

    /* SCRAM-SHA-256 credentials (from user attributes, may be NULL).
     * Read order: scram_sha256_* (registration-time; kc_cred_derive.c /
     * keycloak-webhook-spi lockstep) then x3_scram_* then x3_scram_sha256_*
     * (legacy). See parse_user() in kc_keycloak.c. */
    char *scram_salt;             /* base64 */
    int   scram_iterations;
    char *scram_stored_key;       /* base64 */
    char *scram_server_key;       /* base64 */

    /* ECDSA public key (from user attributes, may be NULL) */
    char *ecdsa_pubkey;           /* ecdsa_pubkey (PEM or base64) */

    long created_at;              /* Account creation time (epoch), from createdAt user attribute */
};

/* Token introspection result */
struct kc_token_info {
    bool active;
    char *username;
    size_t username_size;
    char *email;
    size_t email_size;
    char *sub;                    /* Subject (user ID) */
    size_t sub_size;
    int opserv_level;
    long exp;                     /* Expiration timestamp */
    long iat;                     /* Issued at timestamp */
    long nbf;                     /* Not-before timestamp (0 if the claim is absent) */
    long created_at;              /* Account creation time (epoch), from created_at JWT claim */
    char *iss;                    /* Issuer (iss claim) - for deployment issuer policy */
    size_t iss_size;
    char *azp;                    /* Authorized party (azp claim) - the issuing client id */
    size_t azp_size;
};

/* Group representation */
struct kc_group {
    char *id;
    size_t id_size;
    char *name;
    size_t name_size;
    char *path;
    size_t path_size;
};

/*
 * Callback types
 */
typedef void (*kc_token_cb)(int result, const struct kc_access_token *token, void *data);
/* A password grant's answer.  On KC_SUCCESS, token is the user's token
 * (borrowed, valid during the call); NULL on any other result.  reason is
 * Keycloak's error_description exactly as sent, or NULL when the answer
 * had none (always NULL on KC_SUCCESS); borrowed, valid during the call.
 * reason is unvalidated bytes from the network, of any length: strip
 * control characters and bound its length before showing or storing it. */
typedef void (*kc_grant_cb)(int result, const struct kc_access_token *token,
                            const char *reason, void *data);
typedef void (*kc_user_cb)(int result, const struct kc_user *user, void *data);
typedef void (*kc_users_cb)(int result, const struct kc_user *users, int count, void *data);
typedef void (*kc_result_cb)(int result, void *data);
typedef void (*kc_groups_cb)(int result, const struct kc_group *groups, int count, void *data);
typedef void (*kc_introspect_cb)(int result, const struct kc_token_info *info, void *data);
/* A user create's answer.  On KC_SUCCESS, id is the new user's Keycloak id
 * as the answer's Location header names it (borrowed, valid during the
 * call), or NULL when the answer named none; NULL on any other result. */
typedef void (*kc_create_cb)(int result, const char *id, void *data);
/* A group lookup's answer.  On KC_SUCCESS, group is the group (borrowed,
 * valid during the call) and group->id is set; NULL on any other result
 * (KC_INVALID_RESPONSE when Keycloak's answer named no id). */
typedef void (*kc_group_cb)(int result, const struct kc_group *group, void *data);
/* A user representation's answer.  On KC_SUCCESS, repr is the user's full
 * JSON representation as Keycloak sent it; NULL on any other result.  It is
 * borrowed: valid during the call, and released after it, so json_incref()
 * it to keep it.  The callback may modify it in place (nothing reads it
 * after the call), e.g. to change a field and hand it to kc_user_update(). */
typedef void (*kc_user_repr_cb)(int result, json_t *repr, void *data);

/*
 * Initialize Keycloak subsystem. Called after kc_init().
 * Config is copied internally.
 * Returns 0 on success, -1 on error.
 */
int kc_keycloak_init(const struct kc_config *config);

/*
 * Shutdown Keycloak subsystem. Called before kc_shutdown().
 *
 * Drops the configuration, the cached admin token and the user-id cache;
 * kc_keycloak_init() may be called again afterwards (also from a callback
 * this call makes).
 *   - Operations still waiting for an admin token are answered inside this
 *     call: an operation's callback gets KC_TOKEN_ERROR (a kc_token_ensure()
 *     callback gets KC_UNAVAILABLE).
 *   - Requests already in flight are NOT cancelled: each still calls back
 *     later, exactly once, with the old configuration's result, so the
 *     `data` of any operation started before a shutdown must outlive it.
 *     An admin-token refresh in flight is the exception: its answer is
 *     dropped (it installs no token and answers no one under a later
 *     kc_keycloak_init()).
 *   - kc_shutdown() (the HTTP layer) by contrast drops every transfer in
 *     flight without calling back.
 */
void kc_keycloak_shutdown(void);

/*
 * Token management
 */

/* Ensure a valid client token is available. If expired, refreshes async. */
int kc_token_ensure(kc_token_cb cb, void *data);

/* Get the currently cached token (may be NULL or expired). */
const struct kc_access_token *kc_token_cached(void);

/*
 * User operations (all async)
 *
 * CALLBACK CONTRACT, relied on by every caller that heap-allocates its
 * `data` context:
 *   - return 0  => the callback WILL be invoked exactly once and takes
 *                  ownership of `data`.  It may fire synchronously, before
 *                  the start function returns, so the caller must not touch
 *                  `data` after a successful start.
 *   - return -1 => the callback was NOT and will NOT be invoked; `data` is
 *                  still the caller's to free.  Every operation returns -1
 *                  for a NULL required argument or callback and when it is
 *                  called before kc_keycloak_init() (or after
 *                  kc_keycloak_shutdown()); most also when an allocation
 *                  fails.  Some operations list their cases in full below.
 */

/* Get user by exact username match */
int kc_user_get(const char *username, kc_user_cb cb, void *data);

/* Get user by Keycloak user ID */
int kc_user_get_by_id(const char *id, kc_user_cb cb, void *data);

/* Search users (may return multiple) */
int kc_user_search(const char *query, bool exact, kc_users_cb cb, void *data);

/* Create user with pre-hashed password (PBKDF2 credential import).
 * Thin wrapper over kc_user_create_full(): username, cred_data, and
 * secret_data are all REQUIRED — NULL in any of them (or a NULL cb)
 * returns -1 without making a request; there is no credential-less create
 * path (via this function or kc_user_create_full()). This differs from
 * the pre-Task-2 behavior, which silently created a credential-less user
 * when cred_data/secret_data were NULL; that shorthand no longer exists.
 * To set emailVerified/requiredActions or custom attributes on create,
 * call kc_user_create_full() directly (it still requires credentials). */
int kc_user_create(const char *username, const char *email,
                   const char *cred_data, const char *secret_data,
                   kc_create_cb cb, void *data);

/* Full user-create request: pre-hashed credential (Task 1
 * kc_pbkdf2_cred_build output) plus optional emailVerified/requiredActions
 * and parallel attribute-name/value arrays (e.g. registration-time
 * scram_sha256_* SCRAM attributes). */
struct kc_user_create_req {
    const char *username;            /* required */
    const char *email;               /* optional */
    const char *cred_data;           /* required: Task 1 kc_pbkdf2_cred_build output */
    const char *secret_data;         /* required */
    int set_email_verified;          /* 1 => include emailVerified:false + requiredActions */
    const char *const *attr_keys;    /* optional parallel arrays (SCRAM attrs) */
    const char *const *attr_values;
    size_t n_attrs;
};

/* Create user with the full request shape above. req->username,
 * req->cred_data, and req->secret_data are all REQUIRED (see the struct's
 * field comments) — NULL in any of them (or a NULL req/cb) returns -1
 * without making a request; there is no credential-less create path.
 * The callback receives on success the new user's id from the 201's
 * Location header (no extra request), or NULL if the answer named none;
 * on a refusal what Keycloak's body says (kc_classify_create_error()):
 * KC_CONFLICT (not KC_USER_EXISTS) or KC_CONFLICT_EMAIL on HTTP 409,
 * KC_BAD_USERNAME / KC_BAD_EMAIL / KC_BAD_PASSWORD / KC_REJECTED on 400,
 * KC_ERROR otherwise. */
int kc_user_create_full(const struct kc_user_create_req *req,
                        kc_create_cb cb, void *data);

/* Delete user by ID */
int kc_user_delete(const char *id, kc_result_cb cb, void *data);

/* Update user (full representation PUT) */
int kc_user_update(const char *id, json_t *repr, kc_result_cb cb, void *data);

/* Read a user's full representation by Keycloak user ID (GET of the user):
 * the base for a read-change-write through kc_user_update(), since a user
 * PUT replaces what it is sent.  The result: KC_SUCCESS with the JSON
 * object (see kc_user_repr_cb); KC_NOT_FOUND on 404; KC_TOKEN_ERROR when
 * no admin token could be had; KC_ERROR for no answer, any other status,
 * or a 200 that is not a JSON object.  Returns -1 without calling back
 * (the general contract above) exactly when: id or cb is NULL; it is
 * called before kc_keycloak_init() or after kc_keycloak_shutdown(), or the
 * configuration has no base URL or realm (no URL can be built); or an
 * allocation fails (the URL, the operation, or its place in the queue for
 * an admin token). */
int kc_user_get_repr(const char *id, kc_user_repr_cb cb, void *data);

/*
 * Password operations
 */

/* Set password for user by ID */
int kc_user_set_password(const char *id, const char *password,
                         kc_result_cb cb, void *data);

/* Verify password via resource owner password grant.  Returns 0 when the
 * callback will fire exactly once (possibly before this returns), -1 when
 * it never will.  The result: KC_SUCCESS; on a 400/401 refusal what
 * kc_classify_grant_error() makes of it (KC_FORBIDDEN wrong credentials,
 * KC_DISABLED, KC_UNVERIFIED account not fully set up, KC_CLIENT_REFUSED,
 * KC_ERROR for a body that is no Keycloak error object);
 * KC_INVALID_RESPONSE for a 200 without a usable token; KC_ERROR for no
 * answer or any other status. */
int kc_user_verify_password(const char *username, const char *password,
                            kc_grant_cb cb, void *data);

/* Trigger Keycloak's built-in "verify email" flow for user id (PUT
 * .../send-verify-email; no body). */
int kc_user_send_verify_email(const char *id, kc_result_cb cb, void *data);

/*
 * Group operations
 */

/* List groups for a user */
int kc_user_get_groups(const char *user_id, kc_groups_cb cb, void *data);

/* Add user to group */
int kc_user_add_group(const char *user_id, const char *group_id,
                      kc_result_cb cb, void *data);

/* Remove user from group */
int kc_user_remove_group(const char *user_id, const char *group_id,
                         kc_result_cb cb, void *data);

/* Look a group up by its path ("/parent/child"; it must start with '/').
 * The result: KC_SUCCESS with the group (see kc_group_cb), whose id is
 * then always set; KC_NOT_FOUND on 404; KC_TOKEN_ERROR when no admin token
 * could be had; KC_INVALID_RESPONSE for a 200 JSON object without a string
 * "id"; KC_ERROR for no answer, any other status, or a 200 that is not a
 * JSON object.  Returns -1 without calling back (the general contract
 * above) exactly when: path or cb is NULL, or path does not start with
 * '/'; it is called before kc_keycloak_init() or after
 * kc_keycloak_shutdown(), or the configuration has no base URL or realm
 * (no URL can be built); or an allocation fails (the URL, the operation,
 * or its place in the queue for an admin token). */
int kc_group_get_by_path(const char *path, kc_group_cb cb, void *data);

/*
 * Token introspection (for SASL)
 */
int kc_token_introspect(const char *token, kc_introspect_cb cb, void *data);

/*
 * JWKS (for offline token validation)
 */
int kc_jwks_refresh(kc_result_cb cb, void *data);
int kc_token_verify_offline(const char *token, struct kc_token_info *info);

/*
 * Statistics
 */
struct kc_keycloak_stats {
    unsigned long requests_total;
    unsigned long requests_success;
    unsigned long requests_error;
    unsigned long avg_latency_ms;
    unsigned long max_latency_ms;
    unsigned long cache_hits;
    unsigned long cache_misses;
};

void kc_keycloak_stats_get(struct kc_keycloak_stats *out);

/*
 * Memory management - free structures returned by callbacks
 */
void kc_access_token_free(struct kc_access_token *token);
void kc_user_free(struct kc_user *user);
void kc_token_info_free(struct kc_token_info *info);
void kc_group_free(struct kc_group *group);

#endif /* KC_KEYCLOAK_H */
