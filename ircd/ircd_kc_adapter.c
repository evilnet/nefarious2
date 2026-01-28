/*
 * ircd_kc_adapter.c - Bridge between Nefarious's event loop and libkc
 *
 * Maps Nefarious's ircd_events.h Socket/Timer API to libkc's kc_event_ops,
 * and Nefarious's ircd_log.h to libkc's kc_log_ops.
 *
 * Architecture:
 *   libkc curl_multi  →  kc_event_ops  →  Nefarious Socket/Timer API
 *   libkc logging     →  kc_log_ops    →  log_write(LS_SYSTEM, ...)
 */

#include "config.h"

#ifdef USE_LIBKC

#include "ircd_kc_adapter.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd.h"      /* CurrentTime */

#include <kc/kc_event.h>
#include <kc/kc_log.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * =============================================================================
 * Socket Adapter
 *
 * libkc provides an fd and event mask. Nefarious uses struct Socket
 * with socket_add/del/events. We maintain a mapping from fd → per-socket
 * context that holds the Socket struct and the libkc callback.
 * =============================================================================
 */

#define MAX_KC_SOCKETS 256

struct kc_sock_ctx {
    struct Socket sock;                        /* Nefarious socket struct */
    void (*kc_callback)(int fd, int events, void *data);  /* libkc callback */
    void *kc_data;                             /* libkc callback data */
    int fd;                                    /* file descriptor */
    int in_use;                                /* slot is active */
};

static struct kc_sock_ctx kc_sockets[MAX_KC_SOCKETS];

/* Find a socket context by fd */
static struct kc_sock_ctx *
find_sock_ctx(int fd)
{
    if (fd >= 0 && fd < MAX_KC_SOCKETS && kc_sockets[fd].in_use)
        return &kc_sockets[fd];
    return NULL;
}

/* Nefarious event callback - translates Event to libkc callback */
static void
kc_socket_event_cb(struct Event *ev)
{
    struct Socket *sock = ev_socket(ev);
    struct kc_sock_ctx *ctx = (struct kc_sock_ctx *)s_data(sock);

    if (!ctx || !ctx->kc_callback)
        return;

    switch (ev_type(ev)) {
    case ET_READ:
        ctx->kc_callback(ctx->fd, KC_EVENT_READ, ctx->kc_data);
        break;
    case ET_WRITE:
        ctx->kc_callback(ctx->fd, KC_EVENT_WRITE, ctx->kc_data);
        break;
    case ET_DESTROY:
        /* Socket being destroyed by event engine - clean up our tracking */
        if (ctx->fd >= 0 && ctx->fd < MAX_KC_SOCKETS)
            ctx->in_use = 0;
        break;
    default:
        break;
    }
}

/* Map KC_EVENT flags to Nefarious SOCK_EVENT flags */
static unsigned int
kc_to_sock_events(int kc_events)
{
    unsigned int ev = 0;
    if (kc_events & KC_EVENT_READ)
        ev |= SOCK_EVENT_READABLE;
    if (kc_events & KC_EVENT_WRITE)
        ev |= SOCK_EVENT_WRITABLE;
    return ev;
}

/* kc_event_ops: socket_add */
static int
ircd_kc_socket_add(int fd, int events,
                   void (*callback)(int fd, int events, void *data),
                   void *data)
{
    struct kc_sock_ctx *ctx;

    if (fd < 0 || fd >= MAX_KC_SOCKETS)
        return -1;

    ctx = &kc_sockets[fd];
    if (ctx->in_use) {
        /* Already tracked — update instead */
        ctx->kc_callback = callback;
        ctx->kc_data = data;
        socket_events(&ctx->sock, kc_to_sock_events(events));
        return 0;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->kc_callback = callback;
    ctx->kc_data = data;
    ctx->fd = fd;

    if (socket_add(&ctx->sock, kc_socket_event_cb, ctx,
                   SS_CONNECTED, kc_to_sock_events(events), fd) < 0) {
        return -1;
    }

    ctx->in_use = 1;
    return 0;
}

/* kc_event_ops: socket_update */
static int
ircd_kc_socket_update(int fd, int events)
{
    struct kc_sock_ctx *ctx = find_sock_ctx(fd);
    if (!ctx)
        return -1;

    socket_events(&ctx->sock, kc_to_sock_events(events));
    return 0;
}

/* kc_event_ops: socket_remove */
static void
ircd_kc_socket_remove(int fd)
{
    struct kc_sock_ctx *ctx = find_sock_ctx(fd);
    if (!ctx)
        return;

    socket_del(&ctx->sock);
    ctx->in_use = 0;
}

/*
 * =============================================================================
 * Timer Adapter
 *
 * libkc needs millisecond-resolution one-shot timers. Nefarious Timer has
 * second resolution with TT_RELATIVE type. We round up ms to seconds, and
 * use poll_hint_ms for sub-second accuracy (similar to X3 adapter).
 *
 * Each timer is heap-allocated since libkc may cancel them.
 * =============================================================================
 */

struct kc_timer_ctx {
    struct Timer timer;                    /* Nefarious timer struct */
    void (*kc_callback)(void *data);       /* libkc callback */
    void *kc_data;                         /* libkc callback data */
    int active;                            /* still valid */
};

/* Nefarious timer event callback.
 *
 * For one-shot timers (TT_RELATIVE without GEN_READD), Nefarious fires
 * ET_EXPIRE followed by ET_DESTROY. We invoke the libkc callback on
 * ET_EXPIRE but defer freeing to ET_DESTROY to avoid double-free.
 */
static void
kc_timer_event_cb(struct Event *ev)
{
    struct Timer *timer = ev_timer(ev);
    struct kc_timer_ctx *ctx = (struct kc_timer_ctx *)t_data(timer);

    if (!ctx)
        return;

    switch (ev_type(ev)) {
    case ET_EXPIRE:
        if (ctx->active && ctx->kc_callback) {
            ctx->active = 0;
            ctx->kc_callback(ctx->kc_data);
        }
        /* Don't free here — ET_DESTROY follows for one-shot timers */
        break;
    case ET_DESTROY:
        /* Final cleanup — safe to free now */
        free(ctx);
        break;
    default:
        break;
    }
}

/* kc_event_ops: timer_add */
static void *
ircd_kc_timer_add(unsigned long ms,
                  void (*callback)(void *data), void *data)
{
    struct kc_timer_ctx *ctx;
    time_t seconds;

    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;

    ctx->kc_callback = callback;
    ctx->kc_data = data;
    ctx->active = 1;

    /* Round up to at least 1 second */
    seconds = (time_t)(ms / 1000);
    if (ms % 1000)
        seconds++;
    if (seconds < 1)
        seconds = 1;

    timer_add(timer_init(&ctx->timer), kc_timer_event_cb, ctx,
              TT_RELATIVE, seconds);

    return ctx;
}

/* kc_event_ops: timer_cancel */
static void
ircd_kc_timer_cancel(void *timer_handle)
{
    struct kc_timer_ctx *ctx = (struct kc_timer_ctx *)timer_handle;
    if (!ctx)
        return;

    ctx->active = 0;
    ctx->kc_callback = NULL;

    if (t_active(&ctx->timer)) {
        /* timer_del generates ET_DESTROY, which frees ctx.
         * After this call, ctx is invalid. */
        timer_del(&ctx->timer);
    } else {
        /* Timer already expired/destroyed — free directly */
        free(ctx);
    }
}

/*
 * =============================================================================
 * Time + Poll Hint
 * =============================================================================
 */

static unsigned long
ircd_kc_now(void)
{
    return (unsigned long)CurrentTime;
}

static void
ircd_kc_poll_hint_ms(long timeout_ms)
{
    /* Nefarious engine_loop calculates wait from timer_next.
     * For sub-second accuracy, we add a short-lived timer to wake
     * the event loop quickly. If timeout_ms <= 0, no hint needed. */
    (void)timeout_ms;
    /* TODO: Nefarious doesn't have a poll_hint mechanism like X3's ioset.
     * The timer adapter rounds up to 1 second which is sufficient for
     * curl_multi timeouts. If more precision is needed, the engine_loop
     * could be extended. */
}

/*
 * =============================================================================
 * Log Adapter
 * =============================================================================
 */

static void
ircd_kc_log_fn(enum kc_log_level level, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    enum LogLevel ll;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    switch (level) {
    case KC_LOG_DEBUG:   ll = L_DEBUG;   break;
    case KC_LOG_INFO:    ll = L_INFO;    break;
    case KC_LOG_WARNING: ll = L_WARNING; break;
    case KC_LOG_ERROR:   ll = L_ERROR;   break;
    default:             ll = L_DEBUG;   break;
    }

    log_write(LS_SYSTEM, ll, 0, "libkc: %s", buf);
}

/*
 * =============================================================================
 * Static ops structs and public API
 * =============================================================================
 */

static const struct kc_event_ops ircd_kc_event_ops = {
    .socket_add    = ircd_kc_socket_add,
    .socket_update = ircd_kc_socket_update,
    .socket_remove = ircd_kc_socket_remove,
    .timer_add     = ircd_kc_timer_add,
    .timer_cancel  = ircd_kc_timer_cancel,
    .now           = ircd_kc_now,
    .poll_hint_ms  = ircd_kc_poll_hint_ms,
};

static const struct kc_log_ops ircd_kc_log_ops = {
    .log = ircd_kc_log_fn,
};

void
ircd_kc_adapter_init(void)
{
    memset(kc_sockets, 0, sizeof(kc_sockets));
}

const struct kc_event_ops *
ircd_kc_get_event_ops(void)
{
    return &ircd_kc_event_ops;
}

const struct kc_log_ops *
ircd_kc_get_log_ops(void)
{
    return &ircd_kc_log_ops;
}

void
ircd_kc_adapter_cleanup(void)
{
    int i;
    for (i = 0; i < MAX_KC_SOCKETS; i++) {
        if (kc_sockets[i].in_use) {
            socket_del(&kc_sockets[i].sock);
            kc_sockets[i].in_use = 0;
        }
    }
}

#endif /* USE_LIBKC */
