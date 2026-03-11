/*
 * ircd_kc_adapter.c - Bridge between Nefarious's event loop and libkc
 *
 * Maps Nefarious's ircd_events.h Socket/Timer API to libkc's kc_event_ops,
 * and Nefarious's ircd_log.h to libkc's kc_log_ops.
 *
 * Architecture:
 *   libkc curl_multi  →  kc_event_ops  →  Nefarious Socket/Timer API
 *   libkc logging     →  kc_log_ops    →  log_write(LS_SYSTEM, ...)
 *
 * Socket lifecycle:
 *   curl_multi recycles fds during callbacks (DNS socket close → TCP socket
 *   open with same fd number). The adapter handles this with two strategies:
 *
 *   1. FD recycled (remove + re-add same fd): Use socket_reattach() to
 *      re-register with epoll without touching gh_ref/gh_flags. Safe to
 *      call from within callbacks.
 *
 *   2. Simple removal (no re-add): Defer socket_del to a 0-second timer.
 *      timer_run() executes after engine_loop's event dispatch completes
 *      and all gen_ref's are released.
 */

#include "config.h"

#ifdef USE_LIBKC

#include "ircd_kc_adapter.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd.h"      /* CurrentTime */
#include "s_debug.h"   /* Debug(), DEBUG_INFO */

#include <kc/kc_event.h>
#include <kc/kc_log.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * =============================================================================
 * Socket Adapter
 * =============================================================================
 */

#define MAX_KC_SOCKETS 256

struct kc_sock_ctx {
    struct Socket sock;                        /* Nefarious socket struct */
    void (*kc_callback)(int fd, int events, void *data);  /* libkc callback */
    void *kc_data;                             /* libkc callback data */
    int fd;                                    /* file descriptor */
    int in_use;                                /* slot is active */
    int pending_remove;                        /* deferred socket_del needed */
};

static struct kc_sock_ctx kc_sockets[MAX_KC_SOCKETS];

/* Deferred removal timer: fires in timer_run() after engine_loop's
 * event dispatch is complete and all gen_ref's are released. */
static struct Timer kc_deferred_timer;
static int kc_deferred_scheduled = 0;

/* Forward declarations */
static void kc_socket_event_cb(struct Event *ev);
static unsigned int kc_to_sock_events(int kc_events);
static void kc_schedule_deferred(void);

/* Find a socket context by fd */
static struct kc_sock_ctx *
find_sock_ctx(int fd)
{
    if (fd >= 0 && fd < MAX_KC_SOCKETS && kc_sockets[fd].in_use)
        return &kc_sockets[fd];
    return NULL;
}

/* Timer callback for deferred socket removals.
 * Runs in timer_run() AFTER engine_loop's event dispatch loop completes,
 * so all gen_ref's have been released and socket_del is safe. */
static void
kc_deferred_timer_cb(struct Event *ev)
{
    int i;

    switch (ev_type(ev)) {
    case ET_EXPIRE:
        kc_deferred_scheduled = 0;

        for (i = 0; i < MAX_KC_SOCKETS; i++) {
            struct kc_sock_ctx *ctx = &kc_sockets[i];

            if (!ctx->pending_remove || !ctx->in_use)
                continue;

            Debug((DEBUG_INFO, "kc_adapter: deferred socket_del fd=%d", i));
            ctx->pending_remove = 0;
            socket_del(&ctx->sock);
            ctx->in_use = 0;
        }
        break;

    case ET_DESTROY:
        /* Static timer — nothing to free */
        break;

    default:
        break;
    }
}

/* Schedule the deferred removal timer if not already scheduled */
static void
kc_schedule_deferred(void)
{
    if (kc_deferred_scheduled)
        return;
    kc_deferred_scheduled = 1;
    timer_add(timer_init(&kc_deferred_timer), kc_deferred_timer_cb, NULL,
              TT_RELATIVE, 0);
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
    case ET_WRITE:
        Debug((DEBUG_INFO, "kc_adapter: socket_event fd=%d type=%s",
               ctx->fd, ev_type(ev) == ET_READ ? "READ" : "WRITE"));
        ctx->kc_callback(ctx->fd,
                          ev_type(ev) == ET_READ ? KC_EVENT_READ : KC_EVENT_WRITE,
                          ctx->kc_data);
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

    Debug((DEBUG_INFO, "kc_adapter: socket_add fd=%d events=%d", fd, events));

    if (fd < 0 || fd >= MAX_KC_SOCKETS) {
        log_write(LS_SYSTEM, L_ERROR, 0,
                  "kc_adapter: socket_add fd=%d out of range (max %d)",
                  fd, MAX_KC_SOCKETS);
        return -1;
    }

    ctx = &kc_sockets[fd];

    if (ctx->in_use && ctx->pending_remove) {
        /* Strategy A: FD recycled — curl removed the old socket and is
         * re-adding the same fd (e.g., DNS close → TCP open with same fd).
         *
         * Cancel the deferred remove. Use socket_reattach() to re-register
         * with epoll without touching gh_ref/gh_flags, then update the
         * event interest mask. The Socket struct stays alive. */
        Debug((DEBUG_INFO, "kc_adapter: socket_reattach fd=%d events=%d", fd, events));
        ctx->pending_remove = 0;
        ctx->kc_callback = callback;
        ctx->kc_data = data;
        socket_reattach(&ctx->sock, fd);
        socket_events(&ctx->sock, kc_to_sock_events(events));
        return 0;
    }

    if (ctx->in_use) {
        /* Already tracked, not pending remove — just update */
        ctx->kc_callback = callback;
        ctx->kc_data = data;
        socket_events(&ctx->sock, kc_to_sock_events(events));
        return 0;
    }

    /* Brand new fd — fresh registration */
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

    Debug((DEBUG_INFO, "kc_adapter: socket_remove fd=%d", fd));

    /* Strategy B: Defer socket_del to a 0-second timer.
     * socket_del is unsafe during event dispatch (clears GEN_ACTIVE while
     * engine_loop holds a gen_ref). The timer fires in timer_run() after
     * all socket events are processed and gen_ref's released.
     *
     * If socket_add is called for this fd before the timer fires
     * (fd recycling), Strategy A kicks in and cancels the deferred remove. */
    ctx->pending_remove = 1;
    ctx->kc_callback = NULL;  /* Stop delivering events */
    kc_schedule_deferred();
}

/*
 * =============================================================================
 * Timer Adapter
 * =============================================================================
 */

struct kc_timer_ctx {
    struct Timer timer;                    /* Nefarious timer struct */
    void (*kc_callback)(void *data);       /* libkc callback */
    void *kc_data;                         /* libkc callback data */
    int active;                            /* still valid */
};

/* Nefarious timer event callback. */
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
            Debug((DEBUG_INFO, "kc_adapter: timer_expire"));
            ctx->active = 0;
            ctx->kc_callback(ctx->kc_data);
        }
        break;
    case ET_DESTROY:
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

    /* Round up ms to seconds. Allow 0 — fires on next timer_run() pass. */
    seconds = (time_t)(ms / 1000);
    if (ms % 1000)
        seconds++;

    Debug((DEBUG_INFO, "kc_adapter: timer_add ms=%lu seconds=%ld", ms, (long)seconds));

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
        timer_del(&ctx->timer);
    } else {
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
    (void)timeout_ms;
    /* TODO: Nefarious doesn't have a poll_hint mechanism like X3's ioset. */
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
    kc_deferred_scheduled = 0;
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
    if (kc_deferred_scheduled) {
        timer_del(&kc_deferred_timer);
        kc_deferred_scheduled = 0;
    }
}

#endif /* USE_LIBKC */
