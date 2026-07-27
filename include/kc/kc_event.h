/*
 * kc_event.h - Event loop adapter interface for libkc
 *
 * The host application (X3 or Nefarious) provides implementations of
 * these callbacks at init time. libkc uses them to integrate curl_multi
 * with whatever event loop the host uses.
 *
 * X3 adapter maps to: ioset, timeq
 * Nefarious adapter maps to: ircd_events.h socket/timer API
 */

#ifndef KC_EVENT_H
#define KC_EVENT_H

/* Event interest flags for socket operations */
#define KC_EVENT_READ   1
#define KC_EVENT_WRITE  2

struct kc_event_ops {
    /*
     * Socket management (for curl_multi socket callbacks).
     *
     * socket_add: Register a new fd for monitoring. events is a bitmask
     *   of KC_EVENT_READ | KC_EVENT_WRITE. When the fd is ready, call
     *   callback(fd, triggered_events, data).
     *   Returns 0 on success, -1 on error.
     *
     * socket_update: Change the event interest for an already-registered fd.
     *   Returns 0 on success, -1 on error.
     *
     * socket_remove: Stop monitoring fd and free associated resources.
     */
    int  (*socket_add)(int fd, int events,
                       void (*callback)(int fd, int events, void *data),
                       void *data);
    int  (*socket_update)(int fd, int events);
    void (*socket_remove)(int fd);

    /*
     * Timer management.
     *
     * timer_add: Schedule callback(data) to fire after ms milliseconds.
     *   Returns an opaque handle for cancellation, or NULL on error.
     *
     * timer_cancel: Cancel a previously scheduled timer. The handle
     *   becomes invalid after this call.
     */
    void *(*timer_add)(unsigned long ms,
                       void (*callback)(void *data), void *data);
    void  (*timer_cancel)(void *timer_handle);

    /*
     * Current monotonic time in seconds.
     * X3: return global `now`
     * Nefarious: return `CurrentTime`
     */
    unsigned long (*now)(void);

    /*
     * Hint to the event loop that it should wake within timeout_ms.
     * Used by curl_multi for sub-second timeouts that the timer_add
     * interface (second granularity) can't express.
     * May be a no-op if the event loop doesn't support poll hints.
     */
    void (*poll_hint_ms)(long timeout_ms);
};

#endif /* KC_EVENT_H */
