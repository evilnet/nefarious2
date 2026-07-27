/*
 * kc_http.h - Async HTTP client for libkc
 *
 * Wraps libcurl's curl_multi interface with the kc_event adapter,
 * providing a simple async HTTP request API. Extracted from X3's
 * keycloak.c curl_multi integration.
 */

#ifndef KC_HTTP_H
#define KC_HTTP_H

#include <stddef.h>
#include <curl/curl.h>
#include <jansson.h>

#include <kc/kc_event.h>
#include <kc/kc_log.h>

/* HTTP request configuration */
struct kc_http_request {
    const char *url;              /* Full URL (required) */
    const char *method;           /* GET, POST, PUT, DELETE, PATCH (default: GET) */
    const char *body;             /* Request body, or NULL */
    size_t body_len;              /* Length of body (0 if NULL) */
    struct curl_slist *headers;   /* Additional headers, or NULL */
    const char *bearer_token;     /* Authorization: Bearer <token>, or NULL */
    const char *auth_user;        /* HTTP Basic auth username, or NULL */
    const char *auth_passwd;      /* HTTP Basic auth password, or NULL */
    long timeout_ms;              /* Per-request timeout (0 = default) */
};

/* HTTP response (passed to callback, caller must not free) */
struct kc_http_response {
    long status_code;             /* HTTP status (200, 404, etc.) or 0 on error */
    char *body;                   /* Response body (null-terminated) */
    size_t body_len;              /* Length of body */
    json_t *json;                 /* Parsed JSON if Content-Type is application/json, else NULL */
    const char *error;            /* Error message if status_code == 0, else NULL */
};

/* Callback invoked when an async HTTP request completes */
typedef void (*kc_http_callback)(struct kc_http_response *resp, void *data);

/*
 * Initialize the HTTP subsystem. Called internally by kc_init().
 * ops and log must remain valid for the lifetime of the library.
 * Returns 0 on success, -1 on error.
 */
int kc_http_init(const struct kc_event_ops *ops, const struct kc_log_ops *log);

/*
 * Shutdown the HTTP subsystem. Called internally by kc_shutdown().
 * Cancels any pending requests.
 */
void kc_http_shutdown(void);

/*
 * Submit an async HTTP request.
 * The callback is invoked when the request completes (success or failure).
 * The kc_http_response is only valid for the duration of the callback.
 * Returns 0 on success (request queued), -1 on error (callback not invoked).
 */
int kc_http_request(const struct kc_http_request *req,
                    kc_http_callback cb, void *data);

/*
 * HTTP statistics.
 */
struct kc_http_stats {
    unsigned long requests_total;
    unsigned long requests_success;   /* 2xx responses */
    unsigned long requests_error;     /* Non-2xx or connection errors */
    unsigned long total_latency_ms;   /* Sum of all request latencies */
    unsigned long max_latency_ms;
};

void kc_http_stats_get(struct kc_http_stats *out);
void kc_http_stats_reset(void);

#endif /* KC_HTTP_H */
