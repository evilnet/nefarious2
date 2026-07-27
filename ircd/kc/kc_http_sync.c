/*
 * kc_http_sync.c - Synchronous (blocking) HTTP for libkc
 *
 * Ported from X3's keycloak.c sync HTTP infrastructure:
 *   curl_write_cb(), curl_apply_opts(), curl_perform(),
 *   is_retryable_error(), kc_stats_record_request()
 *
 * Unlike X3, this module does NOT use a persistent CURL handle.
 * Each kc_http_sync_perform() call creates and destroys its own handle.
 * Connection reuse can be added later via a connection pool if needed.
 */

#include <kc/kc.h>
#include <kc/kc_http_sync.h>
#include <kc/kc_keycloak.h>  /* for KC_ERROR */

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

/*
 * =============================================================================
 * Performance Statistics
 * =============================================================================
 */

static struct kc_http_sync_stats sync_stats = {0};

static void
record_request(unsigned long latency_ms, int is_error)
{
    sync_stats.http_requests++;
    sync_stats.total_latency_ms += latency_ms;
    sync_stats.last_request_time = time(NULL);

    if (latency_ms > sync_stats.max_latency_ms) {
        sync_stats.max_latency_ms = latency_ms;
    }
    if (sync_stats.min_latency_ms == 0 || latency_ms < sync_stats.min_latency_ms) {
        sync_stats.min_latency_ms = latency_ms;
    }
    if (is_error) {
        sync_stats.http_errors++;
    }
}

void
kc_http_sync_stats_get(struct kc_http_sync_stats *out)
{
    if (out) {
        *out = sync_stats;
    }
}

void
kc_http_sync_stats_reset(void)
{
    memset(&sync_stats, 0, sizeof(sync_stats));
}

/*
 * =============================================================================
 * CURL Write Callback
 * =============================================================================
 */

static size_t
write_cb(char *data, size_t size, size_t nmemb, void *clientp)
{
    size_t realsize = size * nmemb;
    struct kc_http_sync_mem *mem = (struct kc_http_sync_mem *)clientp;

    char *ptr = realloc(mem->response, mem->size + realsize + 1);
    if (!ptr) return 0;  /* Out of memory */

    mem->response = ptr;
    memcpy(&(mem->response[mem->size]), data, realsize);
    mem->size += realsize;
    mem->response[mem->size] = 0;

    return realsize;
}

/*
 * =============================================================================
 * Apply Options to CURL Handle
 * =============================================================================
 */

static int
apply_opts(CURL *curl, struct kc_http_sync_opts opts,
           struct kc_http_sync_mem *chunk_out,
           struct curl_slist **header_list_out)
{
    struct curl_slist *header_list = NULL;

    if (!curl || !opts.uri) return -1;

    /* Performance optimizations */
    curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 60L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 30L);

    /* Timeouts */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    /* URL */
    curl_easy_setopt(curl, CURLOPT_URL, opts.uri);

    /* Setup write callback if output buffer provided */
    if (chunk_out) {
        if (!chunk_out->response) {
            chunk_out->response = malloc(1);
            if (!chunk_out->response) return -1;
            chunk_out->response[0] = 0;
            chunk_out->size = 0;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)chunk_out);
    }

    /* HTTP method */
    switch (opts.method) {
        case KC_HTTP_PUT:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
            break;
        case KC_HTTP_DELETE:
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
            break;
        case KC_HTTP_POST:
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            break;
        case KC_HTTP_GET:
        default:
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
            break;
    }

    /* POST/PUT fields — binary data takes priority over string fields */
    if (opts.post_data && opts.post_data_len > 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, opts.post_data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)opts.post_data_len);
    } else if (opts.post_fields) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, opts.post_fields);
    }

    /* Headers */
    if (opts.header_count > 0) {
        for (size_t i = 0; i < opts.header_count; i++) {
            header_list = curl_slist_append(header_list, opts.header_list[i]);
        }
        if (!header_list) return -1;
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header_list);
        if (header_list_out) *header_list_out = header_list;
    }

    /* Basic auth */
    if (opts.auth_user && opts.auth_passwd) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, opts.auth_user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, opts.auth_passwd);
    }

    /* Bearer auth */
    if (opts.xoauth2_bearer) {
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, opts.xoauth2_bearer);
    }

    /* Response header capture (optional) */
    if (opts.header_callback) {
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, opts.header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, opts.header_userdata);
    }

    return 0;
}

/*
 * =============================================================================
 * Error Classification
 * =============================================================================
 */

int
kc_http_sync_is_retryable(int curl_code, long http_code)
{
    /* Retryable curl errors */
    if (curl_code == CURLE_COULDNT_CONNECT ||
        curl_code == CURLE_OPERATION_TIMEDOUT ||
        curl_code == CURLE_GOT_NOTHING ||
        curl_code == CURLE_RECV_ERROR ||
        curl_code == CURLE_SEND_ERROR) {
        return 1;
    }
    /* Retryable HTTP codes (server errors, rate limiting) */
    if (http_code >= 500 || http_code == 429) {
        return 1;
    }
    return 0;
}

/*
 * =============================================================================
 * Synchronous HTTP Perform
 * =============================================================================
 */

long
kc_http_sync_perform(struct kc_http_sync_opts opts,
                     struct kc_http_sync_mem *chunk_out)
{
    CURL *curl = NULL;
    CURLcode res = CURLE_FAILED_INIT;
    long result = KC_ERROR;
    long http_code = 0;
    struct curl_slist *header_list = NULL;
    int attempt = 0;
    int max_attempts = opts.max_retries + 1;
    int delay_ms = opts.retry_delay_ms > 0 ? opts.retry_delay_ms : 100;
    const char *req_id = opts.request_id ? opts.request_id : "-";

    if (!opts.uri) {
        kc_log_debug("[%s] kc_http_sync_perform: Invalid arguments", req_id);
        return KC_ERROR;
    }

    /* Create a new CURL handle per call (no persistent handle in libkc) */
    curl = curl_easy_init();
    if (!curl) {
        kc_log_debug("[%s] kc_http_sync_perform: Failed to init curl", req_id);
        return KC_ERROR;
    }

    for (attempt = 0; attempt < max_attempts; attempt++) {
        /* Reset for retry */
        if (attempt > 0) {
            kc_log_debug("[%s] Retry %d/%d after %dms",
                         req_id, attempt, opts.max_retries, delay_ms * attempt);

            /* Exponential backoff */
            struct timespec ts = { .tv_sec = 0, .tv_nsec = delay_ms * attempt * 1000000L };
            nanosleep(&ts, NULL);

            /* Reset response buffer for retry */
            if (chunk_out && chunk_out->response) {
                free(chunk_out->response);
                chunk_out->response = NULL;
                chunk_out->size = 0;
            }

            /* Free previous headers */
            if (header_list) {
                curl_slist_free_all(header_list);
                header_list = NULL;
            }

            /* Reset curl handle for retry */
            curl_easy_reset(curl);
        }

        /* Apply options */
        if (apply_opts(curl, opts, chunk_out, &header_list) < 0) {
            kc_log_debug("[%s] kc_http_sync_perform: Failed to apply options", req_id);
            continue;  /* Try again if retries left */
        }

        /* Perform request (blocking) with timing */
        {
            struct timeval tv_start, tv_end;
            unsigned long latency_ms;
            int is_error;

            gettimeofday(&tv_start, NULL);
            res = curl_easy_perform(curl);
            gettimeofday(&tv_end, NULL);

            http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

            /* Calculate latency */
            latency_ms = (unsigned long)(
                (tv_end.tv_sec - tv_start.tv_sec) * 1000 +
                (tv_end.tv_usec - tv_start.tv_usec) / 1000);
            is_error = (res != CURLE_OK || http_code >= 500);

            /* Record stats */
            record_request(latency_ms, is_error);

            /* Log slow requests */
            if (latency_ms > 1000) {
                kc_log_info("[%s] Slow request: %lu ms (HTTP %ld)",
                            req_id, latency_ms, http_code);
            }
        }

        if (res == CURLE_OK && http_code > 0 && http_code < 500 && http_code != 429) {
            /* Success or non-retryable client error */
            result = http_code;
            break;
        }

        /* Check if error is retryable */
        if (!kc_http_sync_is_retryable((int)res, http_code) || attempt >= max_attempts - 1) {
            if (res != CURLE_OK) {
                kc_log_debug("[%s] kc_http_sync_perform failed: %s",
                             req_id, curl_easy_strerror(res));
            } else {
                kc_log_debug("[%s] kc_http_sync_perform: HTTP %ld (non-retryable)",
                             req_id, http_code);
                result = http_code;
            }
            break;
        }

        kc_log_debug("[%s] Retryable error: curl=%d http=%ld",
                     req_id, (int)res, http_code);
    }

    if (header_list) {
        curl_slist_free_all(header_list);
    }

    if (result < 0 && chunk_out && chunk_out->response) {
        free(chunk_out->response);
        chunk_out->response = NULL;
        chunk_out->size = 0;
    }

    curl_easy_cleanup(curl);

    return result;
}
