/*
 * kc.c - Top-level libkc initialization
 */

#include <kc/kc.h>
#include <kc/kc_http.h>

static const struct kc_event_ops *g_event_ops = NULL;
static const struct kc_log_ops *g_log_ops = NULL;
static int g_initialized = 0;

int kc_init(const struct kc_event_ops *ops, const struct kc_log_ops *log)
{
    if (g_initialized)
        return -1;

    if (!ops || !ops->socket_add || !ops->socket_update || !ops->socket_remove
        || !ops->timer_add || !ops->timer_cancel || !ops->now) {
        return -1;
    }

    g_event_ops = ops;
    g_log_ops = log;

    if (kc_http_init(ops, log) != 0) {
        g_event_ops = NULL;
        g_log_ops = NULL;
        return -1;
    }

    g_initialized = 1;

    if (log)
        log->log(KC_LOG_INFO, "libkc: initialized");

    return 0;
}

void kc_shutdown(void)
{
    if (!g_initialized)
        return;

    kc_http_shutdown();

    if (g_log_ops)
        g_log_ops->log(KC_LOG_INFO, "libkc: shutdown");

    g_event_ops = NULL;
    g_log_ops = NULL;
    g_initialized = 0;
}

const struct kc_event_ops *kc_get_event_ops(void)
{
    return g_event_ops;
}

const struct kc_log_ops *kc_get_log_ops(void)
{
    return g_log_ops;
}
