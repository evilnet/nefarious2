/*
 * ircd_kc_adapter.h - Bridge between Nefarious's event loop and libkc
 *
 * Implements kc_event_ops and kc_log_ops using Nefarious's native event loop
 * (ircd_events.h Socket/Timer API) and logging (ircd_log.h).
 *
 * Used by libkc for HTTP transport when delivering webpush notifications.
 */

#ifndef IRCD_KC_ADAPTER_H
#define IRCD_KC_ADAPTER_H

struct kc_event_ops;
struct kc_log_ops;

/* Initialize the adapter.
 * Must be called after the event engine is initialized. */
void ircd_kc_adapter_init(void);

/* Get the event ops struct for passing to kc_init(). */
const struct kc_event_ops *ircd_kc_get_event_ops(void);

/* Get the log ops struct for passing to kc_init(). */
const struct kc_log_ops *ircd_kc_get_log_ops(void);

/* Cleanup adapter state (call before kc_shutdown). */
void ircd_kc_adapter_cleanup(void);

#endif /* IRCD_KC_ADAPTER_H */
