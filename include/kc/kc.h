/*
 * kc.h - Top-level libkc API
 *
 * Initialize the library by providing event loop and logging adapters.
 * After init, use kc_http.h for raw HTTP and kc_keycloak.h for
 * Keycloak operations.
 */

#ifndef KC_H
#define KC_H

#include <kc/kc_event.h>
#include <kc/kc_log.h>

/*
 * Initialize libkc with event loop and logging adapters.
 * Both ops and log must remain valid until kc_shutdown() is called.
 * Returns 0 on success, -1 on error.
 */
int kc_init(const struct kc_event_ops *ops, const struct kc_log_ops *log);

/*
 * Shutdown libkc. Cancels pending HTTP requests and frees resources.
 */
void kc_shutdown(void);

/*
 * Get the event ops provided at init (for internal use).
 */
const struct kc_event_ops *kc_get_event_ops(void);

/*
 * Get the log ops provided at init (for internal use).
 */
const struct kc_log_ops *kc_get_log_ops(void);

/*
 * Convenience logging macros.
 */
#define kc_log_debug(fmt, ...)   do { const struct kc_log_ops *_l = kc_get_log_ops(); if (_l) _l->log(KC_LOG_DEBUG, fmt, ##__VA_ARGS__); } while(0)
#define kc_log_info(fmt, ...)    do { const struct kc_log_ops *_l = kc_get_log_ops(); if (_l) _l->log(KC_LOG_INFO, fmt, ##__VA_ARGS__); } while(0)
#define kc_log_warning(fmt, ...) do { const struct kc_log_ops *_l = kc_get_log_ops(); if (_l) _l->log(KC_LOG_WARNING, fmt, ##__VA_ARGS__); } while(0)
#define kc_log_error(fmt, ...)   do { const struct kc_log_ops *_l = kc_get_log_ops(); if (_l) _l->log(KC_LOG_ERROR, fmt, ##__VA_ARGS__); } while(0)

#endif /* KC_H */
