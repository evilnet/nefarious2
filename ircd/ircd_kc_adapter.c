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
 *   libkc owns its descriptors.  For each one it registered, it calls
 *   socket_remove(fd) and only then close(fd): the webhook's conn_close
 *   and listener teardown, and curl's CURL_POLL_REMOVE, which curl issues
 *   before closing a socket.  Once close() returns, the kernel may hand
 *   the number to anyone -- the next accept() on a client listener, an
 *   ident query, a server link -- and epoll registrations are keyed by
 *   the number.  So every engine call this adapter makes for a descriptor
 *   happens before socket_remove returns:
 *
 *   - Each registration has its own context.  socket_remove takes it out
 *     of the fd lookup and calls socket_del() at once, while the number
 *     still names libkc's socket, so the engine's EPOLL_CTL_DEL removes
 *     the right registration.
 *   - The context is freed on ET_DESTROY, which the event core delivers
 *     only when no event in flight still holds the socket -- also when
 *     libkc removes a socket from inside that socket's own callback.
 *   - A number libkc adds again, even inside the callback that removed it
 *     (curl recycles descriptors that way), gets a fresh context and a
 *     fresh registration.
 *
 *   The adapter used to keep one embedded Socket per descriptor number and
 *   defer socket_del to a 0-second timer.  By the time the timer ran,
 *   libkc had closed the descriptor; if a client had been accepted on the
 *   same number meanwhile, the stale EPOLL_CTL_DEL removed the client's
 *   registration, and the client's next interest change failed inside
 *   send_buffer and took the server down.
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

/* One registration: from socket_add until its ET_DESTROY. */
struct kc_sock_ctx {
    struct Socket sock;                        /* Nefarious socket struct */
    void (*kc_callback)(int fd, int events, void *data);  /* NULL once removed */
    void *kc_data;                             /* libkc callback data */
    int fd;                                    /* file descriptor */
    struct kc_sock_ctx *next;                  /* kc_live linkage */
};

/* Registrations libkc has not removed.  A handful at a time (curl's
 * connection caps, the webhook listener and its connections), so a list
 * keyed by nothing but the descriptor: no size limit on the number. */
static struct kc_sock_ctx *kc_live;

/* Find the live registration for fd */
static struct kc_sock_ctx *
find_live(int fd)
{
    struct kc_sock_ctx *ctx;

    for (ctx = kc_live; ctx; ctx = ctx->next)
        if (ctx->fd == fd)
            return ctx;
    return NULL;
}

/* Take a registration out of the fd lookup */
static void
unlink_live(struct kc_sock_ctx *ctx)
{
    struct kc_sock_ctx **pp;

    for (pp = &kc_live; *pp; pp = &(*pp)->next)
        if (*pp == ctx) {
            *pp = ctx->next;
            ctx->next = NULL;
            return;
        }
}

/* Nefarious event callback - translates Event to libkc callback */
static void
kc_socket_event_cb(struct Event *ev)
{
    struct kc_sock_ctx *ctx = (struct kc_sock_ctx *)s_data(ev_socket(ev));

    switch (ev_type(ev)) {
    case ET_READ:
    case ET_WRITE:
        if (!ctx->kc_callback)
            break;              /* removed while this event was in flight */
        Debug((DEBUG_INFO, "kc_adapter: socket_event fd=%d type=%s",
               ctx->fd, ev_type(ev) == ET_READ ? "READ" : "WRITE"));
        ctx->kc_callback(ctx->fd,
                          ev_type(ev) == ET_READ ? KC_EVENT_READ : KC_EVENT_WRITE,
                          ctx->kc_data);
        /* ctx may be removed now; it stays valid until this event ends */
        break;
    case ET_DESTROY:
        /* No event holds the socket any more; the registration is over. */
        free(ctx);
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

    if (fd < 0)
        return -1;

    if ((ctx = find_live(fd))) {
        /* Registered and not removed: only the interest changes */
        ctx->kc_callback = callback;
        ctx->kc_data = data;
        socket_events(&ctx->sock, SOCK_ACTION_SET | kc_to_sock_events(events));
        return 0;
    }

    /* New descriptor, or a number libkc removed and is using again: a
     * fresh registration either way.  A removed one is not reused -- it
     * may still be held by the event that is running right now. */
    ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return -1;
    ctx->kc_callback = callback;
    ctx->kc_data = data;
    ctx->fd = fd;

    if (!socket_add(&ctx->sock, kc_socket_event_cb, ctx,
                    SS_CONNECTED, kc_to_sock_events(events), fd)) {
        /* The engine refused it, so there is no registration to delete:
         * unlink the generator socket_add() linked in, and drop it. */
        log_write(LS_SYSTEM, L_ERROR, 0,
                  "kc_adapter: event engine refused fd=%d", fd);
        gen_dequeue(&ctx->sock);
        free(ctx);
        return -1;
    }

    ctx->next = kc_live;
    kc_live = ctx;
    return 0;
}

/* kc_event_ops: socket_update */
static int
ircd_kc_socket_update(int fd, int events)
{
    struct kc_sock_ctx *ctx = find_live(fd);

    /* Never added, or already removed: the number may be someone else's */
    if (!ctx)
        return -1;

    socket_events(&ctx->sock, SOCK_ACTION_SET | kc_to_sock_events(events));
    return 0;
}

/* kc_event_ops: socket_remove */
static void
ircd_kc_socket_remove(int fd)
{
    struct kc_sock_ctx *ctx = find_live(fd);
    if (!ctx)
        return;

    Debug((DEBUG_INFO, "kc_adapter: socket_remove fd=%d", fd));

    /* Delete it from the engine now, while fd still names libkc's socket:
     * libkc closes it as soon as we return, and the next accept() may get
     * the same number.  If an event on this socket is running (libkc
     * removing it from its own callback), the event core holds the
     * destroy until that event ends; ET_DESTROY then frees ctx. */
    unlink_live(ctx);
    ctx->kc_callback = NULL;
    socket_del(&ctx->sock);
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
    kc_live = NULL;
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
    while (kc_live) {
        struct kc_sock_ctx *ctx = kc_live;

        kc_live = ctx->next;
        ctx->next = NULL;
        ctx->kc_callback = NULL;
        socket_del(&ctx->sock);
    }
}

#endif /* USE_LIBKC */
