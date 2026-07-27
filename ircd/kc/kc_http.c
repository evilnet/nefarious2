/*
 * kc_http.c - Async HTTP client using curl_multi + event loop adapter
 *
 * Extracted from X3's keycloak.c curl_multi integration.
 * Uses the kc_event adapter to integrate with any event loop.
 */

#include <kc/kc_http.h>
#include <kc/kc.h>

#include <stdlib.h>
#include <string.h>

/* --- Internal state --- */

static CURLM *g_multi = NULL;
static const struct kc_event_ops *g_ops = NULL;
static const struct kc_log_ops *g_log = NULL;
static int g_running = 0;  /* Number of active curl handles */

static struct kc_http_stats g_stats;

/*
 * Socket tracking for curl_multi.
 * curl_multi tells us about sockets it wants to monitor via
 * CURLMOPT_SOCKETFUNCTION, and we register them with the event loop.
 */
struct kc_sock_info {
    curl_socket_t sockfd;
    int action;                   /* CURL_POLL_IN, CURL_POLL_OUT, etc. */
    struct kc_sock_info *next_pending;  /* Deferred cleanup list */
};

/* Deferred cleanup: curl can close sockets during callbacks.
 * We defer kc_sock_info cleanup until after curl_multi_socket_action returns. */
static struct kc_sock_info *g_pending_cleanup = NULL;

/*
 * Per-request context: tracks the curl easy handle, response buffer,
 * and user callback.
 */
struct kc_request_ctx {
    CURL *easy;
    struct kc_http_response response;
    kc_http_callback callback;
    void *callback_data;
    char *response_buf;
    size_t response_buf_len;
    size_t response_buf_alloc;
    unsigned long start_time;
    struct curl_slist *owned_headers;  /* Headers owned by this request */
};

/* --- Forward declarations --- */

static int curl_socket_cb(CURL *easy, curl_socket_t s, int what,
                          void *userp, void *sockp);
static int curl_timer_cb(CURLM *multi, long timeout_ms, void *userp);
static void socket_event_cb(int fd, int events, void *data);
static void timer_fired_cb(void *data);
static void check_multi_info(void);
static void process_pending_cleanup(void);
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
static void request_ctx_free(struct kc_request_ctx *ctx);

/* --- Timer handle --- */
static void *g_timer_handle = NULL;

/* --- Public API --- */

int kc_http_init(const struct kc_event_ops *ops, const struct kc_log_ops *log)
{
    if (g_multi)
        return -1;

    g_ops = ops;
    g_log = log;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    g_multi = curl_multi_init();
    if (!g_multi) {
        if (log)
            log->log(KC_LOG_ERROR, "kc_http: curl_multi_init() failed");
        return -1;
    }

    curl_multi_setopt(g_multi, CURLMOPT_SOCKETFUNCTION, curl_socket_cb);
    curl_multi_setopt(g_multi, CURLMOPT_SOCKETDATA, NULL);
    curl_multi_setopt(g_multi, CURLMOPT_TIMERFUNCTION, curl_timer_cb);
    curl_multi_setopt(g_multi, CURLMOPT_TIMERDATA, NULL);

    /* Cap libcurl's connection cache.  Without these, the default
     * MAXCONNECTS grows monotonically with the high-water of easy
     * handles ever added, and curl_easy_cleanup parks the easy
     * handle's connection in the share cache rather than closing it.
     * Under bursty SASL/ROPC traffic the cache grows unbounded and
     * the cached sockets are alive in the kernel's TCP slab but not
     * visible in /proc/net/tcp* (they're idle keep-alive parks).
     * Observed on testnet: 4 SASL hold/revive cyclers drove +85
     * FDs/min linear growth that didn't drain; 227 of 253 socket FDs
     * unaccounted in /proc/net/* listings. */
    curl_multi_setopt(g_multi, CURLMOPT_MAXCONNECTS,           (long)32);
    curl_multi_setopt(g_multi, CURLMOPT_MAX_TOTAL_CONNECTIONS, (long)64);
    curl_multi_setopt(g_multi, CURLMOPT_MAX_HOST_CONNECTIONS,  (long)16);

    memset(&g_stats, 0, sizeof(g_stats));
    g_running = 0;

    return 0;
}

void kc_http_shutdown(void)
{
    if (!g_multi)
        return;

    /* Cancel pending timer */
    if (g_timer_handle && g_ops && g_ops->timer_cancel) {
        g_ops->timer_cancel(g_timer_handle);
        g_timer_handle = NULL;
    }

    /* Clean up pending requests */
    process_pending_cleanup();

    curl_multi_cleanup(g_multi);
    g_multi = NULL;

    curl_global_cleanup();

    g_ops = NULL;
    g_log = NULL;
}

int kc_http_request(const struct kc_http_request *req,
                    kc_http_callback cb, void *data)
{
    CURL *easy;
    struct kc_request_ctx *ctx;
    CURLMcode rc;

    if (!g_multi || !req || !req->url || !cb)
        return -1;

    easy = curl_easy_init();
    if (!easy)
        return -1;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        curl_easy_cleanup(easy);
        return -1;
    }

    ctx->easy = easy;
    ctx->callback = cb;
    ctx->callback_data = data;
    ctx->start_time = g_ops ? g_ops->now() : 0;

    /* URL */
    curl_easy_setopt(easy, CURLOPT_URL, req->url);

    /* Method */
    if (req->method) {
        if (strcmp(req->method, "POST") == 0)
            curl_easy_setopt(easy, CURLOPT_POST, 1L);
        else if (strcmp(req->method, "PUT") == 0)
            curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "PUT");
        else if (strcmp(req->method, "DELETE") == 0)
            curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "DELETE");
        else if (strcmp(req->method, "PATCH") == 0)
            curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "PATCH");
        /* GET is default */
    }

    /* Body — use COPYPOSTFIELDS so curl owns the data and callers
     * can safely free their buffer after kc_http_request returns.
     * POSTFIELDSIZE must be set BEFORE COPYPOSTFIELDS per curl docs. */
    if (req->body && req->body_len > 0) {
        curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)req->body_len);
        curl_easy_setopt(easy, CURLOPT_COPYPOSTFIELDS, req->body);
    }

    /* Headers — deep-copy into a new slist owned by the request context.
     * Callers free their slist after kc_http_request returns, but curl
     * still references the headers until the transfer completes. */
    {
        struct curl_slist *owned = NULL;
        const struct curl_slist *src;

        /* Copy caller's headers */
        for (src = req->headers; src; src = src->next)
            owned = curl_slist_append(owned, src->data);

        /* Append bearer token header if present */
        if (req->bearer_token) {
            char auth_header[2048];
            snprintf(auth_header, sizeof(auth_header),
                     "Authorization: Bearer %s", req->bearer_token);
            owned = curl_slist_append(owned, auth_header);
        }

        if (owned) {
            curl_easy_setopt(easy, CURLOPT_HTTPHEADER, owned);
            ctx->owned_headers = owned;
        }
    }

    /* HTTP Basic auth */
    if (req->auth_user) {
        curl_easy_setopt(easy, CURLOPT_USERNAME, req->auth_user);
        if (req->auth_passwd)
            curl_easy_setopt(easy, CURLOPT_PASSWORD, req->auth_passwd);
        curl_easy_setopt(easy, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    }

    /* Timeout */
    if (req->timeout_ms > 0)
        curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, req->timeout_ms);

    /* Response buffer */
    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, ctx);

    /* Store context for retrieval in check_multi_info */
    curl_easy_setopt(easy, CURLOPT_PRIVATE, ctx);

    /* SSL: verify by default */
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L);

    /* Add to multi handle */
    rc = curl_multi_add_handle(g_multi, easy);
    if (rc != CURLM_OK) {
        if (g_log)
            g_log->log(KC_LOG_ERROR, "kc_http: curl_multi_add_handle failed: %s",
                       curl_multi_strerror(rc));
        request_ctx_free(ctx);
        return -1;
    }

    /* Kick curl to start processing the new handle immediately.
     * curl_multi_socket_action with CURL_SOCKET_TIMEOUT triggers DNS
     * resolution and socket creation, which registers fds with the
     * event loop via curl_socket_cb. Without this, curl has no sockets
     * registered and the event loop never delivers events to drive
     * the transfer forward. */
    curl_multi_socket_action(g_multi, CURL_SOCKET_TIMEOUT, 0, &g_running);
    check_multi_info();

    g_stats.requests_total++;
    return 0;
}

void kc_http_stats_get(struct kc_http_stats *out)
{
    if (out)
        *out = g_stats;
}

void kc_http_stats_reset(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

/* --- curl_multi callbacks --- */

/*
 * Called by curl_multi when it wants to monitor a socket.
 * We register/update/remove the socket with the event loop adapter.
 */
static int curl_socket_cb(CURL *easy, curl_socket_t s, int what,
                          void *userp, void *sockp)
{
    struct kc_sock_info *si = (struct kc_sock_info *)sockp;

    (void)easy;
    (void)userp;

    if (what == CURL_POLL_REMOVE) {
        if (si) {
            if (g_ops)
                g_ops->socket_remove(s);
            /* Defer free - may be called during socket_action */
            si->next_pending = g_pending_cleanup;
            g_pending_cleanup = si;
        }
        curl_multi_assign(g_multi, s, NULL);
        return 0;
    }

    if (!si) {
        /* New socket */
        si = calloc(1, sizeof(*si));
        if (!si)
            return -1;
        si->sockfd = s;
        si->action = what;

        int events = 0;
        if (what & CURL_POLL_IN)  events |= KC_EVENT_READ;
        if (what & CURL_POLL_OUT) events |= KC_EVENT_WRITE;

        if (g_ops && g_ops->socket_add(s, events, socket_event_cb, si) != 0) {
            free(si);
            return -1;
        }

        curl_multi_assign(g_multi, s, si);
    } else {
        /* Update existing socket */
        si->action = what;

        int events = 0;
        if (what & CURL_POLL_IN)  events |= KC_EVENT_READ;
        if (what & CURL_POLL_OUT) events |= KC_EVENT_WRITE;

        if (g_ops)
            g_ops->socket_update(s, events);
    }

    return 0;
}

/*
 * Called by curl_multi when it wants a timeout.
 * We schedule a timer via the event loop adapter.
 */
static int curl_timer_cb(CURLM *multi, long timeout_ms, void *userp)
{
    (void)multi;
    (void)userp;

    /* Cancel existing timer */
    if (g_timer_handle && g_ops) {
        g_ops->timer_cancel(g_timer_handle);
        g_timer_handle = NULL;
    }

    if (timeout_ms == -1) {
        /* curl says delete the timer */
        return 0;
    }

    if (timeout_ms == 0) {
        /* Fire immediately */
        timer_fired_cb(NULL);
        return 0;
    }

    /* Schedule timer */
    if (g_ops) {
        /* Use poll_hint for sub-second precision */
        if (timeout_ms < 1000 && g_ops->poll_hint_ms)
            g_ops->poll_hint_ms(timeout_ms);

        /* Schedule at second granularity (minimum 1 second) */
        unsigned long ms = (unsigned long)timeout_ms;
        g_timer_handle = g_ops->timer_add(ms, timer_fired_cb, NULL);
    }

    return 0;
}

/* --- Event loop callbacks --- */

/*
 * Called by the event loop when a socket is ready.
 */
static void socket_event_cb(int fd, int events, void *data)
{
    struct kc_sock_info *si = (struct kc_sock_info *)data;
    int action = 0;

    (void)fd;

    if (!si || !g_multi)
        return;

    if (events & KC_EVENT_READ)  action |= CURL_CSELECT_IN;
    if (events & KC_EVENT_WRITE) action |= CURL_CSELECT_OUT;

    curl_multi_socket_action(g_multi, si->sockfd, action, &g_running);
    check_multi_info();
    process_pending_cleanup();
}

/*
 * Called by the event loop when the curl timer fires.
 */
static void timer_fired_cb(void *data)
{
    (void)data;

    if (!g_multi)
        return;

    g_timer_handle = NULL;
    curl_multi_socket_action(g_multi, CURL_SOCKET_TIMEOUT, 0, &g_running);
    check_multi_info();
    process_pending_cleanup();
}

/* --- Internal helpers --- */

/*
 * Check for completed transfers and invoke callbacks.
 */
static void check_multi_info(void)
{
    CURLMsg *msg;
    int msgs_left;

    while ((msg = curl_multi_info_read(g_multi, &msgs_left))) {
        if (msg->msg == CURLMSG_DONE) {
            CURL *easy = msg->easy_handle;
            struct kc_request_ctx *ctx = NULL;
            long status_code = 0;

            curl_easy_getinfo(easy, CURLINFO_PRIVATE, &ctx);
            if (!ctx)
                continue;

            curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status_code);

            /* Populate response */
            ctx->response.status_code = status_code;
            ctx->response.body = ctx->response_buf;
            ctx->response.body_len = ctx->response_buf_len;

            if (msg->data.result != CURLE_OK) {
                ctx->response.status_code = 0;
                ctx->response.error = curl_easy_strerror(msg->data.result);
                g_stats.requests_error++;
                if (g_log) {
                    char *url = NULL;
                    curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
                    g_log->log(KC_LOG_ERROR, "kc_http: request failed: %s (url=%s)",
                               ctx->response.error, url ? url : "?");
                }
            } else if (status_code >= 200 && status_code < 300) {
                g_stats.requests_success++;
            } else {
                g_stats.requests_error++;
                if (g_log) {
                    char *url = NULL;
                    curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &url);
                    g_log->log(KC_LOG_WARNING, "kc_http: HTTP %ld from %s",
                               status_code, url ? url : "?");
                }
            }

            /* Try to parse JSON response */
            ctx->response.json = NULL;
            if (ctx->response.body && ctx->response.body_len > 0) {
                json_error_t jerr;
                ctx->response.json = json_loadb(ctx->response.body,
                                                 ctx->response.body_len,
                                                 0, &jerr);
                /* json may be NULL if not valid JSON — that's fine */
            }

            /* Track latency */
            if (g_ops) {
                unsigned long elapsed = g_ops->now() - ctx->start_time;
                /* Approximate: now() is in seconds, we want ms */
                unsigned long elapsed_ms = elapsed * 1000;
                g_stats.total_latency_ms += elapsed_ms;
                if (elapsed_ms > g_stats.max_latency_ms)
                    g_stats.max_latency_ms = elapsed_ms;
            }

            /* Invoke callback */
            if (ctx->callback)
                ctx->callback(&ctx->response, ctx->callback_data);

            /* Cleanup */
            if (ctx->response.json)
                json_decref(ctx->response.json);

            curl_multi_remove_handle(g_multi, easy);
            request_ctx_free(ctx);
        }
    }
}

/*
 * Free deferred socket info structures.
 */
static void process_pending_cleanup(void)
{
    while (g_pending_cleanup) {
        struct kc_sock_info *next = g_pending_cleanup->next_pending;
        free(g_pending_cleanup);
        g_pending_cleanup = next;
    }
}

/*
 * curl write callback: accumulate response body.
 */
static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    struct kc_request_ctx *ctx = (struct kc_request_ctx *)userdata;
    size_t total = size * nmemb;
    size_t needed = ctx->response_buf_len + total + 1;

    if (needed > ctx->response_buf_alloc) {
        size_t new_alloc = ctx->response_buf_alloc ? ctx->response_buf_alloc * 2 : 4096;
        while (new_alloc < needed)
            new_alloc *= 2;
        char *new_buf = realloc(ctx->response_buf, new_alloc);
        if (!new_buf)
            return 0; /* Signal error to curl */
        ctx->response_buf = new_buf;
        ctx->response_buf_alloc = new_alloc;
    }

    memcpy(ctx->response_buf + ctx->response_buf_len, ptr, total);
    ctx->response_buf_len += total;
    ctx->response_buf[ctx->response_buf_len] = '\0';

    return total;
}

/*
 * Free a request context and its curl handle.
 */
static void request_ctx_free(struct kc_request_ctx *ctx)
{
    if (!ctx)
        return;
    if (ctx->easy)
        curl_easy_cleanup(ctx->easy);
    if (ctx->owned_headers)
        curl_slist_free_all(ctx->owned_headers);
    free(ctx->response_buf);
    free(ctx);
}
