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
    KC_CONFLICT         = -11   /* create: username/email already exists (HTTP 409) */
};

/* Keycloak configuration */
struct kc_config {
    const char *base_url;         /* e.g., "http://keycloak:8080" */
    const char *realm;
    const char *client_id;
    const char *client_secret;
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
typedef void (*kc_user_cb)(int result, const struct kc_user *user, void *data);
typedef void (*kc_users_cb)(int result, const struct kc_user *users, int count, void *data);
typedef void (*kc_result_cb)(int result, void *data);
typedef void (*kc_groups_cb)(int result, const struct kc_group *groups, int count, void *data);
typedef void (*kc_introspect_cb)(int result, const struct kc_token_info *info, void *data);

/*
 * Initialize Keycloak subsystem. Called after kc_init().
 * Config is copied internally.
 * Returns 0 on success, -1 on error.
 */
int kc_keycloak_init(const struct kc_config *config);

/*
 * Shutdown Keycloak subsystem. Called before kc_shutdown().
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
 */

/* Get user by exact username match */
int kc_user_get(const char *username, kc_user_cb cb, void *data);

/* Get user by Keycloak user ID */
int kc_user_get_by_id(const char *id, kc_user_cb cb, void *data);

/* Search users (may return multiple) */
int kc_user_search(const char *query, bool exact, kc_users_cb cb, void *data);

/* Create user with pre-hashed password (PBKDF2 credential import).
 * Thin wrapper over kc_user_create_full(). */
int kc_user_create(const char *username, const char *email,
                   const char *cred_data, const char *secret_data,
                   kc_result_cb cb, void *data);

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

/* Create user with the full request shape above. Result callback receives
 * KC_CONFLICT (not KC_USER_EXISTS) on HTTP 409. */
int kc_user_create_full(const struct kc_user_create_req *req,
                        kc_result_cb cb, void *data);

/* Delete user by ID */
int kc_user_delete(const char *id, kc_result_cb cb, void *data);

/* Update user (full representation PUT) */
int kc_user_update(const char *id, json_t *repr, kc_result_cb cb, void *data);

/*
 * Password operations
 */

/* Set password for user by ID */
int kc_user_set_password(const char *id, const char *password,
                         kc_result_cb cb, void *data);

/* Verify password via resource owner password grant */
int kc_user_verify_password(const char *username, const char *password,
                            kc_token_cb cb, void *data);

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
