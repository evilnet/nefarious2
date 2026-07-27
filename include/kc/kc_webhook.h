/*
 * kc_webhook.h - Keycloak webhook HTTP server for libkc
 *
 * Generic TCP listener, HTTP/1.1 parsing, secret validation, event queuing,
 * and JSON event parsing. The host application provides a callback to handle
 * parsed events.
 *
 * Extracted from X3's keycloak_webhook.c to allow both X3 and Nefarious
 * to receive Keycloak admin events without duplicating HTTP server code.
 *
 * Usage:
 *   kc_init(ops, log);                  // Must be called first
 *   struct kc_webhook_config cfg = {
 *       .port = 8081,
 *       .secret = "my-webhook-secret",
 *   };
 *   kc_webhook_init(&cfg, my_event_handler, my_data);
 *   // ... event loop runs ...
 *   kc_webhook_shutdown();
 */

#ifndef KC_WEBHOOK_H
#define KC_WEBHOOK_H

#include <stddef.h>
#include <time.h>
#include <jansson.h>

/* Resource types from Keycloak admin events */
enum kc_webhook_resource_type {
    KC_WH_RESOURCE_UNKNOWN = 0,
    KC_WH_RESOURCE_USER,
    KC_WH_RESOURCE_CREDENTIAL,
    KC_WH_RESOURCE_GROUP_MEMBERSHIP,
    KC_WH_RESOURCE_GROUP,
    KC_WH_RESOURCE_USER_SESSION,
    KC_WH_RESOURCE_ADMIN_EVENT
};

/* Operation types from Keycloak admin events */
enum kc_webhook_operation_type {
    KC_WH_OP_UNKNOWN = 0,
    KC_WH_OP_CREATE,
    KC_WH_OP_UPDATE,
    KC_WH_OP_DELETE,
    KC_WH_OP_ACTION
};

/* SCRAM credentials (from Keycloak webhook SPI extension) */
struct kc_webhook_scram {
    const char *salt;           /* Base64-encoded salt */
    int         iterations;     /* PBKDF2 iteration count */
    const char *stored_key;     /* Base64-encoded StoredKey */
    const char *server_key;     /* Base64-encoded ServerKey */
};

/* Auth details from the admin who triggered the event */
struct kc_webhook_auth_details {
    const char *user_id;        /* Admin user UUID */
    const char *username;       /* Admin username */
    const char *ip_address;     /* Admin's IP */
    const char *realm_id;       /* Realm UUID */
};

/*
 * Parsed webhook event.
 *
 * All string/json pointers are borrowed from internal storage and are
 * valid ONLY during the callback invocation. Copy any data you need
 * to keep.
 */
struct kc_webhook_event {
    /* Event metadata */
    const char *id;                         /* Event UUID */
    long long   time;                       /* Event timestamp (ms since epoch) */
    const char *realm_id;                   /* Realm UUID */

    /* Resource/operation as enum + original string */
    enum kc_webhook_resource_type  resource_type;
    const char                    *resource_type_str;
    enum kc_webhook_operation_type operation_type;
    const char                    *operation_type_str;

    /* Resource path (e.g. "users/<uuid>/credentials/<cred-id>") */
    const char *resource_path;

    /* User ID extracted from resource_path (if path starts with "users/") */
    const char *user_id;

    /* Representation: the JSON string from the event + parsed form */
    const char *representation_str;         /* Raw JSON string, or NULL */
    json_t     *representation;             /* Parsed json_t, or NULL */

    /* Username resolved from multiple locations */
    const char *username;

    /* Auth details (who triggered the event) */
    int has_auth_details;
    struct kc_webhook_auth_details auth_details;

    /* SCRAM data (from webhook SPI extension, not standard Keycloak) */
    int has_scram;
    struct kc_webhook_scram scram;

    /* Full raw event JSON */
    json_t *raw;
};

/*
 * Event callback.
 * Called once per parsed event. The event pointer is valid only during
 * the callback. Copy any data you need to retain.
 */
typedef void (*kc_webhook_event_cb)(const struct kc_webhook_event *event,
                                     void *data);

/* Webhook server configuration */
struct kc_webhook_config {
    int         port;               /* Listen port (0 = disabled) */
    const char *bind_address;       /* Bind address (NULL = all interfaces) */
    const char *secret;             /* X-Webhook-Secret value (NULL = no auth) */
    const char *path;               /* URL path to accept (NULL = default paths) */
    size_t      max_request_size;   /* Max HTTP request size (0 = 64KB default) */
    int         max_connections;    /* Max concurrent connections (0 = 16 default) */
    int         queue_max;          /* Max queued events (0 = 1000 default) */
    int         batch_size;         /* Events per processing tick (0 = 10 default) */
};

/* Webhook statistics */
struct kc_webhook_stats {
    unsigned long events_received;
    unsigned long events_processed;
    unsigned long events_invalid;
    unsigned long events_dropped;       /* Dropped due to full queue */
    unsigned long queue_depth;          /* Current queue depth */
    unsigned long connections_total;
    unsigned long connections_active;
    unsigned long connections_rejected; /* Over max_connections */
    unsigned long bytes_received;
    time_t        last_event_time;
};

/*
 * Initialize the webhook server.
 * Requires kc_init() to have been called first.
 * The callback will be invoked in the host's event loop context.
 * Returns 0 on success, -1 on error.
 */
int kc_webhook_init(const struct kc_webhook_config *config,
                    kc_webhook_event_cb cb, void *cb_data);

/*
 * Shutdown the webhook server.
 * Closes the listener, drains the event queue, frees resources.
 */
void kc_webhook_shutdown(void);

/*
 * Check if the webhook server is running.
 */
int kc_webhook_is_running(void);

/*
 * Update the webhook secret at runtime (e.g. on rehash).
 */
void kc_webhook_set_secret(const char *secret);

/*
 * Get a copy of the current statistics.
 */
void kc_webhook_stats_get(struct kc_webhook_stats *out);

/*
 * Reset statistics counters.
 */
void kc_webhook_stats_reset(void);

/*
 * Parse resource type string to enum.
 */
enum kc_webhook_resource_type kc_webhook_parse_resource_type(const char *str);

/*
 * Parse operation type string to enum.
 */
enum kc_webhook_operation_type kc_webhook_parse_operation_type(const char *str);

/*
 * Extract user UUID from a resource path like "users/<uuid>/..." .
 * Returns pointer into path (not allocated), or NULL if not found.
 */
const char *kc_webhook_extract_user_id(const char *path);

#endif /* KC_WEBHOOK_H */
