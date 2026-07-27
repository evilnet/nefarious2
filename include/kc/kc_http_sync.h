/*
 * kc_http_sync.h - Synchronous (blocking) HTTP for libkc
 *
 * Provides a blocking HTTP client with retry logic, used by kc_jwt
 * for JWKS fetching and available for any sync Keycloak operation.
 *
 * Ported from X3's keycloak.c sync HTTP infrastructure.
 */

#ifndef KC_HTTP_SYNC_H
#define KC_HTTP_SYNC_H

#include <stddef.h>
#include <time.h>

/*
 * Response buffer — caller must free response when done.
 */
struct kc_http_sync_mem {
    char *response;
    size_t size;
};

/*
 * HTTP methods.
 */
enum kc_http_method {
    KC_HTTP_GET = 0,
    KC_HTTP_POST,
    KC_HTTP_PUT,
    KC_HTTP_DELETE
};

/*
 * Header callback type — receives each response header line.
 */
typedef size_t (*kc_http_header_cb)(char *buffer, size_t size,
                                    size_t nitems, void *userdata);

/*
 * Request options.
 */
struct kc_http_sync_opts {
    const char *uri;
    const char *header_list[10];
    size_t header_count;
    const char *post_fields;
    const char *auth_user;
    const char *auth_passwd;
    const char *xoauth2_bearer;
    enum kc_http_method method;

    /* Retry configuration */
    int max_retries;         /* 0 = no retry (default), 1-3 typical */
    int retry_delay_ms;      /* Base delay between retries (default 100ms) */

    /* Logging */
    const char *request_id;  /* Optional: for log correlation */

    /* Binary POST data (alternative to post_fields) */
    const void *post_data;
    size_t post_data_len;

    /* Response header capture (optional) */
    kc_http_header_cb header_callback;
    void *header_userdata;
};

/*
 * Convenience initializer with sensible defaults.
 */
#define KC_HTTP_SYNC_OPTS_INIT { \
    .method = KC_HTTP_GET,       \
    .header_count = 0,           \
    .max_retries = 0,            \
    .retry_delay_ms = 100,       \
    .request_id = NULL           \
}

/*
 * Perform a synchronous (blocking) HTTP request with retry logic.
 *
 * Returns the HTTP status code on success, or a negative kc_error on failure.
 * On success, chunk_out->response is allocated and must be freed by the caller.
 * On failure, chunk_out->response is freed and set to NULL.
 */
long kc_http_sync_perform(struct kc_http_sync_opts opts,
                          struct kc_http_sync_mem *chunk_out);

/*
 * Check if a curl/HTTP error combination is retryable.
 * Returns 1 if retryable, 0 otherwise.
 */
int kc_http_sync_is_retryable(int curl_code, long http_code);

/*
 * Performance statistics for sync HTTP requests.
 */
struct kc_http_sync_stats {
    unsigned long http_requests;
    unsigned long http_errors;
    unsigned long total_latency_ms;
    unsigned long max_latency_ms;
    unsigned long min_latency_ms;
    time_t last_request_time;
};

/*
 * Get a snapshot of sync HTTP stats.
 */
void kc_http_sync_stats_get(struct kc_http_sync_stats *out);

/*
 * Reset sync HTTP stats to zero.
 */
void kc_http_sync_stats_reset(void);

#endif /* KC_HTTP_SYNC_H */
