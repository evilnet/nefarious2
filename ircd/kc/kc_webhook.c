/*
 * kc_webhook.c - Keycloak webhook HTTP server for libkc
 *
 * Generic TCP listener with HTTP/1.1 parsing, secret validation,
 * async event queue, and JSON event parsing. Extracted from X3's
 * keycloak_webhook.c.
 *
 * Uses POSIX socket API for the listener (curl has no server mode),
 * but all fd monitoring and timers go through kc_event_ops.
 */

#include <kc/kc.h>
#include <kc/kc_webhook.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/crypto.h>   /* CRYPTO_memcmp - constant-time secret compare */

/* ===================================================================
 * Defaults
 * =================================================================== */

#define DEFAULT_MAX_REQUEST_SIZE  65536
#define DEFAULT_MAX_CONNECTIONS   16
#define DEFAULT_QUEUE_MAX         1000
#define DEFAULT_BATCH_SIZE        10
#define CONN_TIMEOUT_MS           10000  /* 10s slow-client timeout */

/* ===================================================================
 * Static state
 * =================================================================== */

/* Configuration (copied at init) */
static int         cfg_port = 0;
static char       *cfg_bind_address = NULL;
static char       *cfg_secret = NULL;
static char       *cfg_path = NULL;
static size_t      cfg_max_request_size = DEFAULT_MAX_REQUEST_SIZE;
static int         cfg_max_connections = DEFAULT_MAX_CONNECTIONS;
static int         cfg_queue_max = DEFAULT_QUEUE_MAX;
static int         cfg_batch_size = DEFAULT_BATCH_SIZE;

/* Listener */
static int         listener_fd = -1;

/* Callback */
static kc_webhook_event_cb  event_callback = NULL;
static void                *event_cb_data = NULL;

/* Statistics */
static struct kc_webhook_stats stats;

/* Active connections */
static int active_connections = 0;

/* ===================================================================
 * HTTP connection state
 * =================================================================== */

struct wh_conn {
    int         fd;
    char       *buffer;
    size_t      buf_size;
    size_t      buf_used;
    int         headers_complete;
    size_t      content_length;
    char        method[16];
    char        path[256];
    char        secret_header[256];   /* X-Webhook-Secret or Authorization value */
    void       *timeout_handle;       /* Slow-client timeout timer */
};

/* ===================================================================
 * Event queue
 * =================================================================== */

struct wh_queued_event {
    char   *payload;
    size_t  payload_len;
    struct wh_queued_event *next;
};

static struct wh_queued_event *queue_head = NULL;
static struct wh_queued_event *queue_tail = NULL;
static unsigned int queue_size = 0;
static void *queue_timer = NULL;

/* ===================================================================
 * Forward declarations
 * =================================================================== */

static void listener_readable(int fd, int events, void *data);
static void conn_readable(int fd, int events, void *data);
static void conn_timeout(void *data);
static void conn_close(struct wh_conn *conn);
static int  parse_http_headers(struct wh_conn *conn);
static int  process_request(struct wh_conn *conn);
static void send_response(int fd, int status, const char *message);
static int  queue_event(const char *payload, size_t len);
static void process_queue(void *data);
static void dispatch_event(const char *payload, size_t payload_len);

/* ===================================================================
 * Utility: enum parsers
 * =================================================================== */

enum kc_webhook_resource_type
kc_webhook_parse_resource_type(const char *str)
{
    if (!str) return KC_WH_RESOURCE_UNKNOWN;
    if (strcmp(str, "USER") == 0) return KC_WH_RESOURCE_USER;
    if (strcmp(str, "CREDENTIAL") == 0) return KC_WH_RESOURCE_CREDENTIAL;
    if (strcmp(str, "GROUP_MEMBERSHIP") == 0) return KC_WH_RESOURCE_GROUP_MEMBERSHIP;
    if (strcmp(str, "GROUP") == 0) return KC_WH_RESOURCE_GROUP;
    if (strcmp(str, "USER_SESSION") == 0) return KC_WH_RESOURCE_USER_SESSION;
    if (strcmp(str, "ADMIN_EVENT") == 0) return KC_WH_RESOURCE_ADMIN_EVENT;
    return KC_WH_RESOURCE_UNKNOWN;
}

enum kc_webhook_operation_type
kc_webhook_parse_operation_type(const char *str)
{
    if (!str) return KC_WH_OP_UNKNOWN;
    if (strcmp(str, "CREATE") == 0) return KC_WH_OP_CREATE;
    if (strcmp(str, "UPDATE") == 0) return KC_WH_OP_UPDATE;
    if (strcmp(str, "DELETE") == 0) return KC_WH_OP_DELETE;
    if (strcmp(str, "ACTION") == 0) return KC_WH_OP_ACTION;
    return KC_WH_OP_UNKNOWN;
}

const char *
kc_webhook_extract_user_id(const char *path)
{
    if (!path) return NULL;
    if (strncmp(path, "users/", 6) != 0) return NULL;
    const char *uuid_start = path + 6;
    /* UUID is 36 chars (8-4-4-4-12) - validate minimally */
    if (strlen(uuid_start) < 36) return NULL;
    /* Check for slash or end after UUID */
    if (uuid_start[36] != '\0' && uuid_start[36] != '/') return NULL;
    return uuid_start;
}

/* ===================================================================
 * Public API
 * =================================================================== */

int
kc_webhook_init(const struct kc_webhook_config *config,
                kc_webhook_event_cb cb, void *cb_data)
{
    const struct kc_event_ops *ops;
    struct addrinfo hints, *ai;
    char port_str[16];
    int res, optval = 1;

    if (!config || !cb)
        return -1;

    ops = kc_get_event_ops();
    if (!ops) {
        kc_log_error("kc_webhook: kc_init() not called");
        return -1;
    }

    /* Apply config with defaults */
    cfg_port = config->port;
    if (cfg_port <= 0) {
        kc_log_debug("kc_webhook: disabled (port=0)");
        return 0;
    }

    free(cfg_bind_address);
    cfg_bind_address = config->bind_address ? strdup(config->bind_address) : NULL;

    free(cfg_secret);
    cfg_secret = config->secret ? strdup(config->secret) : NULL;

    if (!cfg_secret || !cfg_secret[0])
        kc_log_warning("kc_webhook: SECURITY - no webhook secret configured; "
                       "all incoming webhook events will be REJECTED. Set a "
                       "secret to enable the endpoint.");

    free(cfg_path);
    cfg_path = config->path ? strdup(config->path) : NULL;

    cfg_max_request_size = config->max_request_size > 0
        ? config->max_request_size : DEFAULT_MAX_REQUEST_SIZE;
    cfg_max_connections = config->max_connections > 0
        ? config->max_connections : DEFAULT_MAX_CONNECTIONS;
    cfg_queue_max = config->queue_max > 0
        ? config->queue_max : DEFAULT_QUEUE_MAX;
    cfg_batch_size = config->batch_size > 0
        ? config->batch_size : DEFAULT_BATCH_SIZE;

    event_callback = cb;
    event_cb_data = cb_data;

    /* Close existing listener if any */
    if (listener_fd >= 0) {
        ops->socket_remove(listener_fd);
        close(listener_fd);
        listener_fd = -1;
    }

    /* Resolve address */
    memset(&hints, 0, sizeof(hints));
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    snprintf(port_str, sizeof(port_str), "%d", cfg_port);
    res = getaddrinfo(cfg_bind_address, port_str, &hints, &ai);
    if (res) {
        kc_log_error("kc_webhook: getaddrinfo failed: %s", gai_strerror(res));
        return -1;
    }

    /* Create, bind, listen */
    listener_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (listener_fd < 0) {
        kc_log_error("kc_webhook: socket() failed: %s", strerror(errno));
        freeaddrinfo(ai);
        return -1;
    }

    setsockopt(listener_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    /* Set non-blocking */
    {
        int flags = fcntl(listener_fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(listener_fd, F_SETFL, flags | O_NONBLOCK);
    }

    if (bind(listener_fd, ai->ai_addr, ai->ai_addrlen) < 0) {
        kc_log_error("kc_webhook: bind() failed on port %d: %s",
                     cfg_port, strerror(errno));
        close(listener_fd);
        listener_fd = -1;
        freeaddrinfo(ai);
        return -1;
    }

    freeaddrinfo(ai);

    if (listen(listener_fd, 16) < 0) {
        kc_log_error("kc_webhook: listen() failed: %s", strerror(errno));
        close(listener_fd);
        listener_fd = -1;
        return -1;
    }

    /* Register with event loop for read events */
    if (ops->socket_add(listener_fd, KC_EVENT_READ,
                        listener_readable, NULL) != 0) {
        kc_log_error("kc_webhook: socket_add() failed for listener");
        close(listener_fd);
        listener_fd = -1;
        return -1;
    }

    memset(&stats, 0, sizeof(stats));
    kc_log_info("kc_webhook: listening on port %d", cfg_port);
    return 0;
}

void
kc_webhook_shutdown(void)
{
    const struct kc_event_ops *ops = kc_get_event_ops();
    struct wh_queued_event *evt, *next;

    if (listener_fd >= 0) {
        if (ops)
            ops->socket_remove(listener_fd);
        close(listener_fd);
        listener_fd = -1;
        kc_log_info("kc_webhook: listener closed");
    }

    /* Cancel queue timer */
    if (queue_timer && ops) {
        ops->timer_cancel(queue_timer);
        queue_timer = NULL;
    }

    /* Drain event queue */
    for (evt = queue_head; evt; evt = next) {
        next = evt->next;
        free(evt->payload);
        free(evt);
    }
    queue_head = queue_tail = NULL;
    queue_size = 0;

    /* Free config strings */
    free(cfg_bind_address);
    cfg_bind_address = NULL;
    free(cfg_secret);
    cfg_secret = NULL;
    free(cfg_path);
    cfg_path = NULL;

    event_callback = NULL;
    event_cb_data = NULL;
    active_connections = 0;
}

int
kc_webhook_is_running(void)
{
    return listener_fd >= 0;
}

void
kc_webhook_set_secret(const char *secret)
{
    free(cfg_secret);
    cfg_secret = secret ? strdup(secret) : NULL;
}

void
kc_webhook_stats_get(struct kc_webhook_stats *out)
{
    if (out) {
        *out = stats;
        out->queue_depth = queue_size;
        out->connections_active = active_connections;
    }
}

void
kc_webhook_stats_reset(void)
{
    time_t last = stats.last_event_time;
    memset(&stats, 0, sizeof(stats));
    stats.last_event_time = last;
}

/* ===================================================================
 * Listener: accept new connections
 * =================================================================== */

static void
listener_readable(int fd, int events, void *data)
{
    const struct kc_event_ops *ops = kc_get_event_ops();
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int client_fd;
    struct wh_conn *conn;

    (void)events;
    (void)data;

    client_fd = accept(fd, (struct sockaddr *)&addr, &addrlen);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            kc_log_error("kc_webhook: accept() failed: %s", strerror(errno));
        return;
    }

    /* Enforce max connections */
    if (active_connections >= cfg_max_connections) {
        kc_log_warning("kc_webhook: max connections reached (%d), rejecting",
                       cfg_max_connections);
        close(client_fd);
        stats.connections_rejected++;
        return;
    }

    /* Set non-blocking */
    {
        int flags = fcntl(client_fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
    }

    /* Allocate connection state */
    conn = calloc(1, sizeof(*conn));
    if (!conn) {
        close(client_fd);
        return;
    }

    conn->fd = client_fd;
    conn->buf_size = 4096;
    conn->buffer = malloc(conn->buf_size);
    if (!conn->buffer) {
        free(conn);
        close(client_fd);
        return;
    }

    /* Register for read events */
    if (ops->socket_add(client_fd, KC_EVENT_READ, conn_readable, conn) != 0) {
        free(conn->buffer);
        free(conn);
        close(client_fd);
        return;
    }

    /* Start slow-client timeout */
    conn->timeout_handle = ops->timer_add(CONN_TIMEOUT_MS, conn_timeout, conn);

    active_connections++;
    stats.connections_total++;
    kc_log_debug("kc_webhook: connection accepted (active: %d)", active_connections);
}

/* ===================================================================
 * Connection: read and process HTTP data
 * =================================================================== */

static void
conn_readable(int fd, int events, void *data)
{
    struct wh_conn *conn = data;
    char readbuf[4096];
    ssize_t nbytes;

    (void)events;
    (void)fd;

    nbytes = recv(conn->fd, readbuf, sizeof(readbuf), 0);
    if (nbytes <= 0) {
        conn_close(conn);
        return;
    }

    stats.bytes_received += (unsigned long)nbytes;

    /* Expand buffer if needed */
    if (conn->buf_used + (size_t)nbytes > conn->buf_size) {
        size_t new_size = conn->buf_size * 2;
        if (new_size > cfg_max_request_size) {
            kc_log_warning("kc_webhook: request too large");
            send_response(conn->fd, 413, "Request Too Large");
            conn_close(conn);
            return;
        }
        char *new_buf = realloc(conn->buffer, new_size);
        if (!new_buf) {
            conn_close(conn);
            return;
        }
        conn->buffer = new_buf;
        conn->buf_size = new_size;
    }

    memcpy(conn->buffer + conn->buf_used, readbuf, (size_t)nbytes);
    conn->buf_used += (size_t)nbytes;

    /* Try to parse headers if not done yet */
    if (!conn->headers_complete) {
        int rc = parse_http_headers(conn);
        if (rc < 0) {
            send_response(conn->fd, 400, "Bad Request");
            conn_close(conn);
            return;
        }
        if (!conn->headers_complete)
            return;  /* Need more data */
    }

    /* Check if we have the complete body */
    char *body_start = strstr(conn->buffer, "\r\n\r\n");
    if (!body_start)
        return;
    body_start += 4;

    size_t headers_len = (size_t)(body_start - conn->buffer);
    size_t body_received = conn->buf_used - headers_len;

    if (body_received < conn->content_length)
        return;  /* Need more body data */

    /* Process the complete request */
    stats.events_received++;
    if (process_request(conn) == 0) {
        send_response(conn->fd, 200, "OK");
    } else {
        send_response(conn->fd, 400, "Bad Request");
    }

    conn_close(conn);
}

static void
conn_timeout(void *data)
{
    struct wh_conn *conn = data;
    kc_log_warning("kc_webhook: connection timeout");
    conn->timeout_handle = NULL;  /* Timer already fired */
    send_response(conn->fd, 408, "Request Timeout");
    conn_close(conn);
}

static void
conn_close(struct wh_conn *conn)
{
    const struct kc_event_ops *ops = kc_get_event_ops();

    if (!conn) return;

    if (ops) {
        ops->socket_remove(conn->fd);
        if (conn->timeout_handle)
            ops->timer_cancel(conn->timeout_handle);
    }

    close(conn->fd);
    free(conn->buffer);
    free(conn);

    if (active_connections > 0)
        active_connections--;
}

/* ===================================================================
 * HTTP parsing
 * =================================================================== */

static int
parse_http_headers(struct wh_conn *conn)
{
    char *line_end;
    char *p = conn->buffer;

    /* Null-terminate for string operations */
    if (conn->buf_used >= conn->buf_size)
        return -1;
    conn->buffer[conn->buf_used] = '\0';

    /* Parse request line */
    line_end = strstr(p, "\r\n");
    if (!line_end)
        return 0;  /* Need more data */

    if (sscanf(p, "%15s %255s", conn->method, conn->path) != 2)
        return -1;

    p = line_end + 2;

    /* Parse headers */
    while ((line_end = strstr(p, "\r\n")) != NULL) {
        if (p == line_end) {
            /* Empty line = end of headers */
            conn->headers_complete = 1;
            return 0;
        }

        *line_end = '\0';

        if (strncasecmp(p, "Content-Length:", 15) == 0) {
            conn->content_length = (size_t)atoi(p + 15);
        } else if (strncasecmp(p, "X-Webhook-Secret:", 17) == 0) {
            const char *val = p + 17;
            while (*val == ' ') val++;
            snprintf(conn->secret_header, sizeof(conn->secret_header), "%s", val);
        } else if (strncasecmp(p, "Authorization:", 14) == 0) {
            /* Fall back to Authorization header if no X-Webhook-Secret */
            if (!conn->secret_header[0]) {
                const char *val = p + 14;
                while (*val == ' ') val++;
                snprintf(conn->secret_header, sizeof(conn->secret_header), "%s", val);
            }
        }

        *line_end = '\r';  /* Restore */
        p = line_end + 2;
    }

    return 0;  /* Need more data */
}

/* ===================================================================
 * Request processing
 * =================================================================== */

static int
process_request(struct wh_conn *conn)
{
    char *body;
    size_t body_len;

    /* Verify method */
    if (strcmp(conn->method, "POST") != 0) {
        kc_log_debug("kc_webhook: ignoring %s request", conn->method);
        return 0;
    }

    /* Verify path */
    if (cfg_path) {
        if (strcmp(conn->path, cfg_path) != 0) {
            kc_log_debug("kc_webhook: ignoring request to %s", conn->path);
            return 0;
        }
    } else {
        /* Default: accept /keycloak-webhook, /webhook, or / */
        if (strcmp(conn->path, "/keycloak-webhook") != 0 &&
            strcmp(conn->path, "/webhook") != 0 &&
            strcmp(conn->path, "/") != 0) {
            kc_log_debug("kc_webhook: ignoring request to %s", conn->path);
            return 0;
        }
    }

    /* Verify secret (fail closed).  A webhook with no configured secret is an
     * unauthenticated destructive endpoint, so reject every request when none
     * is set (a loud warning is also logged once at init).  When a secret is
     * set, compare in constant time (length check, then CRYPTO_memcmp) so the
     * secret is not leaked through a comparison timing side-channel. */
    if (!cfg_secret || !cfg_secret[0]) {
        kc_log_warning("kc_webhook: rejecting event - no webhook secret "
                       "configured (endpoint disabled until one is set)");
        stats.events_invalid++;
        return -1;
    }
    {
        size_t provided_len = strlen(conn->secret_header);
        size_t expected_len = strlen(cfg_secret);
        if (provided_len != expected_len ||
            CRYPTO_memcmp(conn->secret_header, cfg_secret, expected_len) != 0) {
            kc_log_warning("kc_webhook: invalid/missing secret");
            stats.events_invalid++;
            return -1;
        }
    }

    /* Find body */
    body = strstr(conn->buffer, "\r\n\r\n");
    if (!body) {
        stats.events_invalid++;
        return -1;
    }
    body += 4;
    body_len = conn->content_length;

    /* Queue for async processing */
    if (queue_event(body, body_len) < 0) {
        stats.events_dropped++;
        return -1;
    }

    return 0;
}

static void
send_response(int fd, int status, const char *message)
{
    char response[512];
    const char *status_text;

    switch (status) {
    case 200: status_text = "OK"; break;
    case 400: status_text = "Bad Request"; break;
    case 401: status_text = "Unauthorized"; break;
    case 403: status_text = "Forbidden"; break;
    case 404: status_text = "Not Found"; break;
    case 408: status_text = "Request Timeout"; break;
    case 413: status_text = "Payload Too Large"; break;
    case 500: status_text = "Internal Server Error"; break;
    default:  status_text = "Unknown"; break;
    }

    snprintf(response, sizeof(response),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: text/plain\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n"
             "\r\n"
             "%s",
             status, status_text, strlen(message), message);

    /* Best-effort send - connection closing anyway */
    (void)send(fd, response, strlen(response), MSG_NOSIGNAL);
}

/* ===================================================================
 * Event queue
 * =================================================================== */

static int
queue_event(const char *payload, size_t len)
{
    const struct kc_event_ops *ops = kc_get_event_ops();
    struct wh_queued_event *evt;

    if ((int)queue_size >= cfg_queue_max) {
        kc_log_warning("kc_webhook: queue full (%u events), dropping", queue_size);
        return -1;
    }

    evt = calloc(1, sizeof(*evt));
    if (!evt)
        return -1;

    evt->payload = malloc(len + 1);
    if (!evt->payload) {
        free(evt);
        return -1;
    }

    memcpy(evt->payload, payload, len);
    evt->payload[len] = '\0';
    evt->payload_len = len;
    evt->next = NULL;

    if (queue_tail) {
        queue_tail->next = evt;
    } else {
        queue_head = evt;
    }
    queue_tail = evt;
    queue_size++;

    /* Schedule processing if not already scheduled */
    if (!queue_timer && ops) {
        queue_timer = ops->timer_add(0, process_queue, NULL);
    }

    return 0;
}

static void
process_queue(void *data)
{
    const struct kc_event_ops *ops = kc_get_event_ops();
    struct wh_queued_event *evt;
    int batch = 0;

    (void)data;
    queue_timer = NULL;

    while (queue_head && batch < cfg_batch_size) {
        evt = queue_head;
        queue_head = evt->next;
        if (!queue_head)
            queue_tail = NULL;
        queue_size--;

        dispatch_event(evt->payload, evt->payload_len);

        free(evt->payload);
        free(evt);
        batch++;
    }

    /* If more events remain, schedule another round */
    if (queue_head && ops) {
        queue_timer = ops->timer_add(0, process_queue, NULL);
    }
}

/* ===================================================================
 * Event dispatch: JSON parsing → callback
 * =================================================================== */

static void
dispatch_event(const char *payload, size_t payload_len)
{
    json_t *root = NULL;
    json_error_t error;
    struct kc_webhook_event event;
    /* Static buffer for user_id extraction (UUID = 36 chars) */
    static char user_id_buf[40];

    memset(&event, 0, sizeof(event));

    /* Parse JSON */
    root = json_loadb(payload, payload_len, 0, &error);
    if (!root) {
        kc_log_warning("kc_webhook: JSON parse error: %s", error.text);
        stats.events_invalid++;
        return;
    }

    event.raw = root;

    /* Extract standard fields */
    {
        json_t *v;

        v = json_object_get(root, "id");
        if (v && json_is_string(v))
            event.id = json_string_value(v);

        v = json_object_get(root, "time");
        if (v && json_is_integer(v))
            event.time = json_integer_value(v);

        v = json_object_get(root, "realmId");
        if (v && json_is_string(v))
            event.realm_id = json_string_value(v);
    }

    /* Resource and operation types */
    {
        json_t *rt = json_object_get(root, "resourceType");
        json_t *ot = json_object_get(root, "operationType");

        if (rt && json_is_string(rt)) {
            event.resource_type_str = json_string_value(rt);
            event.resource_type = kc_webhook_parse_resource_type(event.resource_type_str);
        }
        if (ot && json_is_string(ot)) {
            event.operation_type_str = json_string_value(ot);
            event.operation_type = kc_webhook_parse_operation_type(event.operation_type_str);
        }
    }

    /* Resource path + user_id extraction */
    {
        json_t *rp = json_object_get(root, "resourcePath");
        if (rp && json_is_string(rp)) {
            event.resource_path = json_string_value(rp);
            /* Extract user UUID from "users/<uuid>/..." */
            const char *uid = kc_webhook_extract_user_id(event.resource_path);
            if (uid) {
                /* Copy to static buffer so it's null-terminated at 36 chars */
                size_t uid_len = strlen(uid);
                /* Find end of UUID (until '/' or end) */
                const char *slash = strchr(uid, '/');
                if (slash)
                    uid_len = (size_t)(slash - uid);
                if (uid_len < sizeof(user_id_buf)) {
                    memcpy(user_id_buf, uid, uid_len);
                    user_id_buf[uid_len] = '\0';
                    event.user_id = user_id_buf;
                }
            }
        }
    }

    /* Representation: parse the JSON string into json_t */
    {
        json_t *rep = json_object_get(root, "representation");
        if (rep && json_is_string(rep)) {
            event.representation_str = json_string_value(rep);
            /* Parse the nested JSON string */
            event.representation = json_loads(event.representation_str, 0, NULL);
        }
    }

    /* Resolve username from multiple locations:
     * 1. Root-level "username" (from custom webhook SPI)
     * 2. authDetails.username
     * 3. representation.username */
    {
        json_t *v;

        v = json_object_get(root, "username");
        if (v && json_is_string(v)) {
            event.username = json_string_value(v);
        }

        if (!event.username) {
            json_t *auth = json_object_get(root, "authDetails");
            if (auth && json_is_object(auth)) {
                v = json_object_get(auth, "username");
                if (v && json_is_string(v))
                    event.username = json_string_value(v);
            }
        }

        if (!event.username && event.representation) {
            v = json_object_get(event.representation, "username");
            if (v && json_is_string(v))
                event.username = json_string_value(v);
        }
    }

    /* Auth details */
    {
        json_t *auth = json_object_get(root, "authDetails");
        if (auth && json_is_object(auth)) {
            event.has_auth_details = 1;
            json_t *v;

            v = json_object_get(auth, "userId");
            if (v && json_is_string(v))
                event.auth_details.user_id = json_string_value(v);

            v = json_object_get(auth, "username");
            if (v && json_is_string(v))
                event.auth_details.username = json_string_value(v);

            v = json_object_get(auth, "ipAddress");
            if (v && json_is_string(v))
                event.auth_details.ip_address = json_string_value(v);

            v = json_object_get(auth, "realmId");
            if (v && json_is_string(v))
                event.auth_details.realm_id = json_string_value(v);
        }
    }

    /* SCRAM data (custom webhook SPI extension) */
    {
        json_t *scram = json_object_get(root, "scram");
        if (scram && json_is_object(scram)) {
            json_t *salt = json_object_get(scram, "salt");
            json_t *iter = json_object_get(scram, "iterations");
            json_t *sk   = json_object_get(scram, "storedKey");
            json_t *svk  = json_object_get(scram, "serverKey");

            if (salt && json_is_string(salt) &&
                iter && json_is_integer(iter) &&
                sk && json_is_string(sk) &&
                svk && json_is_string(svk)) {
                event.has_scram = 1;
                event.scram.salt = json_string_value(salt);
                event.scram.iterations = (int)json_integer_value(iter);
                event.scram.stored_key = json_string_value(sk);
                event.scram.server_key = json_string_value(svk);
            }
        }
    }

    /* Update stats */
    stats.last_event_time = time(NULL);

    /* Deliver to callback */
    kc_log_debug("kc_webhook: dispatching event: resource=%s op=%s user=%s",
                 event.resource_type_str ? event.resource_type_str : "(null)",
                 event.operation_type_str ? event.operation_type_str : "(null)",
                 event.username ? event.username : "(null)");

    if (event_callback)
        event_callback(&event, event_cb_data);

    stats.events_processed++;

    /* Cleanup */
    if (event.representation)
        json_decref(event.representation);
    json_decref(root);
}
