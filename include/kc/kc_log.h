/*
 * kc_log.h - Logging adapter interface for libkc
 *
 * Host application provides a logging implementation at init time.
 * The library never calls host-specific logging directly.
 */

#ifndef KC_LOG_H
#define KC_LOG_H

enum kc_log_level {
    KC_LOG_DEBUG   = 0,
    KC_LOG_INFO    = 1,
    KC_LOG_WARNING = 2,
    KC_LOG_ERROR   = 3
};

struct kc_log_ops {
    void (*log)(enum kc_log_level level, const char *fmt, ...)
        __attribute__((format(printf, 2, 3)));
};

#endif /* KC_LOG_H */
