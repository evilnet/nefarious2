/*
 * kc_http_cmocka.c - unit tests for the vendored libkc async HTTP client.
 *
 * libcurl offers no getter for an easy handle's options, so the link
 * wraps curl_easy_setopt (-Wl,--wrap) to record every option kc_http.c
 * sets on a handle, then forwards it to the real libcurl.  It also wraps
 * curl_version_info so kc_http_init() can be shown a libcurl without the
 * threaded resolver, or one older than 7.87.0.
 *
 * No async transfer runs: the fake event ops never fire curl's timer, so
 * a request is added to the multi handle and left there.  The sync case
 * (kc_http_sync.c) performs against 127.0.0.1:1, refused at once, so its
 * retry runs too.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include <kc/kc_event.h>
#include <kc/kc_http.h>
#include <kc/kc_http_sync.h>
#include <kc/kc_log.h>

/* kc_url.c's kc_log_* macros call kc.c's kc_get_log_ops(); kc.o stays out. */
const struct kc_log_ops *kc_get_log_ops(void);
const struct kc_log_ops *kc_get_log_ops(void) { return NULL; }

/* --- curl_easy_setopt recorder --- */

#define MAX_SETOPTS 256

struct setopt_rec {
    CURL *easy;
    CURLoption option;
    long lval;          /* the value, for a long-typed option */
    CURLcode rc;        /* what the real libcurl answered */
};

static struct setopt_rec g_setopts[MAX_SETOPTS];
static int g_nsetopts;

CURLcode __real_curl_easy_setopt(CURL *easy, CURLoption option, ...);
CURLcode __wrap_curl_easy_setopt(CURL *easy, CURLoption option, ...);

CURLcode __wrap_curl_easy_setopt(CURL *easy, CURLoption option, ...)
{
    va_list ap;
    CURLcode rc;

    va_start(ap, option);
    if (g_nsetopts < MAX_SETOPTS) {
        g_setopts[g_nsetopts].easy = easy;
        g_setopts[g_nsetopts].option = option;
        g_setopts[g_nsetopts].lval = 0;
    }
    if (option < CURLOPTTYPE_OBJECTPOINT) {
        long v = va_arg(ap, long);
        if (g_nsetopts < MAX_SETOPTS)
            g_setopts[g_nsetopts].lval = v;
        rc = __real_curl_easy_setopt(easy, option, v);
    } else if (option < CURLOPTTYPE_FUNCTIONPOINT) {
        rc = __real_curl_easy_setopt(easy, option, va_arg(ap, void *));
    } else if (option < CURLOPTTYPE_OFF_T) {
        rc = __real_curl_easy_setopt(easy, option, va_arg(ap, void (*)(void)));
    } else if (option < CURLOPTTYPE_BLOB) {
        rc = __real_curl_easy_setopt(easy, option, va_arg(ap, curl_off_t));
    } else {
        rc = __real_curl_easy_setopt(easy, option, va_arg(ap, void *));
    }
    va_end(ap);
    if (g_nsetopts < MAX_SETOPTS)
        g_setopts[g_nsetopts].rc = rc;
    g_nsetopts++;
    return rc;
}

/* --- curl_version_info override --- */

static int g_version_override;
static int g_version_asynchdns;
static unsigned int g_version_num;

curl_version_info_data *__real_curl_version_info(CURLversion v);
curl_version_info_data *__wrap_curl_version_info(CURLversion v);

curl_version_info_data *__wrap_curl_version_info(CURLversion v)
{
    static curl_version_info_data copy;
    curl_version_info_data *real = __real_curl_version_info(v);

    if (!g_version_override || !real)
        return real;
    copy = *real;
    if (g_version_asynchdns)
        copy.features |= CURL_VERSION_ASYNCHDNS;
    else
        copy.features &= ~CURL_VERSION_ASYNCHDNS;
    copy.version_num = g_version_num;
    return &copy;
}

/* --- fake event loop: nothing ever fires --- */

static int dummy_timer;

static int fake_socket_add(int fd, int events,
                           void (*cb)(int fd, int events, void *data),
                           void *data)
{
    (void)fd; (void)events; (void)cb; (void)data;
    return 0;
}
static int fake_socket_update(int fd, int events) { (void)fd; (void)events; return 0; }
static void fake_socket_remove(int fd) { (void)fd; }
static void *fake_timer_add(unsigned long ms, void (*cb)(void *data), void *data)
{
    (void)ms; (void)cb; (void)data;
    return &dummy_timer;
}
static void fake_timer_cancel(void *h) { (void)h; }
static unsigned long fake_now(void) { return 0; }
static void fake_poll_hint_ms(long ms) { (void)ms; }

static const struct kc_event_ops fake_ops = {
    fake_socket_add, fake_socket_update, fake_socket_remove,
    fake_timer_add, fake_timer_cancel, fake_now, fake_poll_hint_ms
};

/* --- log capture --- */

static int g_warnings;
static char g_last_warning[512];

static void capture_log(enum kc_log_level level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void capture_log(enum kc_log_level level, const char *fmt, ...)
{
    va_list ap;

    if (level != KC_LOG_WARNING)
        return;
    g_warnings++;
    va_start(ap, fmt);
    vsnprintf(g_last_warning, sizeof(g_last_warning), fmt, ap);
    va_end(ap);
}

static const struct kc_log_ops capture_ops = { capture_log };

static void ignore_response(struct kc_http_response *resp, void *data)
{
    (void)resp; (void)data;
}

static int reset(void **state)
{
    (void)state;
    g_nsetopts = 0;
    g_warnings = 0;
    g_last_warning[0] = '\0';
    g_version_override = 0;
    return 0;
}

static int teardown(void **state)
{
    (void)state;
    kc_http_shutdown();
    g_version_override = 0;
    return 0;
}

/* Every request handle kc_http_request() configures has CURLOPT_QUICK_EXIT
 * set to 1: a transfer that times out while libcurl's threaded resolver is
 * still waiting on getaddrinfo() would otherwise join that thread inside
 * the caller's event loop. */
static void test_request_handle_sets_quick_exit(void **state)
{
    struct kc_http_request reqs[3];
    CURL *handles[3];
    int nhandles = 0;
    int i, j;

    (void)state;
    assert_int_equal(kc_http_init(&fake_ops, &capture_ops), 0);

    memset(reqs, 0, sizeof(reqs));
    reqs[0].url = "http://127.0.0.1:9/a";            /* GET, no timeout */
    reqs[1].url = "http://127.0.0.1:9/b";            /* POST, a timeout */
    reqs[1].method = "POST";
    reqs[1].body = "x=1";
    reqs[1].body_len = 3;
    reqs[1].timeout_ms = 2500;
    reqs[2].url = "http://127.0.0.1:9/c";            /* Basic auth, timeout */
    reqs[2].auth_user = "u";
    reqs[2].auth_passwd = "p";
    reqs[2].timeout_ms = 100;

    for (i = 0; i < 3; i++)
        assert_int_equal(kc_http_request(&reqs[i], ignore_response, NULL), 0);
    assert_true(g_nsetopts <= MAX_SETOPTS);

    /* One handle per request, found by its CURLOPT_URL. */
    for (i = 0; i < g_nsetopts; i++)
        if (g_setopts[i].option == CURLOPT_URL && nhandles < 3)
            handles[nhandles++] = g_setopts[i].easy;
    assert_int_equal(nhandles, 3);

#if LIBCURL_VERSION_NUM >= 0x075700
    for (j = 0; j < nhandles; j++) {
        int found = 0;
        for (i = 0; i < g_nsetopts; i++)
            if (g_setopts[i].easy == handles[j]
                && g_setopts[i].option == CURLOPT_QUICK_EXIT) {
                assert_int_equal(g_setopts[i].lval, 1);
                /* and the linked libcurl knows the option */
                assert_int_equal(g_setopts[i].rc, CURLE_OK);
                found = 1;
            }
        if (!found)
            fail_msg("request handle %d has no CURLOPT_QUICK_EXIT", j);
    }
#else
    (void)j;
    skip();
#endif
}

/* The blocking path (kc_http_sync_perform, the JWKS fetch in the main
 * loop) sets CURLOPT_QUICK_EXIT on every attempt: a retry runs after
 * curl_easy_reset(), which clears every option, so each attempt (each
 * CURLOPT_URL) must be preceded by its own QUICK_EXIT. */
static void test_sync_every_attempt_sets_quick_exit(void **state)
{
    struct kc_http_sync_opts opts = KC_HTTP_SYNC_OPTS_INIT;
    struct kc_http_sync_mem chunk = { NULL, 0 };
    int attempts = 0, armed = 0;
    int i;

    (void)state;
    opts.uri = "http://127.0.0.1:1/certs";
    opts.max_retries = 1;
    opts.retry_delay_ms = 1;
    (void)kc_http_sync_perform(opts, &chunk);
    free(chunk.response);
    assert_true(g_nsetopts <= MAX_SETOPTS);

#if LIBCURL_VERSION_NUM >= 0x075700
    for (i = 0; i < g_nsetopts; i++) {
        if (g_setopts[i].option == CURLOPT_QUICK_EXIT) {
            assert_int_equal(g_setopts[i].lval, 1);
            assert_int_equal(g_setopts[i].rc, CURLE_OK);
            armed = 1;
        } else if (g_setopts[i].option == CURLOPT_URL) {
            if (!armed)
                fail_msg("sync attempt %d has no CURLOPT_QUICK_EXIT", attempts);
            armed = 0;
            attempts++;
        }
    }
    assert_int_equal(attempts, 2);      /* the first try and its retry */
#else
    (void)i; (void)attempts; (void)armed;
    skip();
#endif
}

/* A libcurl with no asynchronous resolver: one warning that name
 * resolution blocks the caller's loop.  kc_http still starts. */
static void test_init_warns_without_asynchdns(void **state)
{
    (void)state;
    g_version_override = 1;
    g_version_asynchdns = 0;
    g_version_num = 0x075801;
    assert_int_equal(kc_http_init(&fake_ops, &capture_ops), 0);
    assert_int_equal(g_warnings, 1);
    assert_non_null(strstr(g_last_warning, "resolver"));
    assert_non_null(strstr(g_last_warning, "block"));
}

/* A runtime libcurl older than 7.87.0 (no CURLOPT_QUICK_EXIT): one
 * warning that a stalled DNS lookup can block the loop after a timeout. */
static void test_init_warns_old_libcurl(void **state)
{
    (void)state;
    g_version_override = 1;
    g_version_asynchdns = 1;
    g_version_num = 0x075600;
    assert_int_equal(kc_http_init(&fake_ops, &capture_ops), 0);
    assert_int_equal(g_warnings, 1);
    assert_non_null(strstr(g_last_warning, "7.87.0"));
    assert_non_null(strstr(g_last_warning, "block"));
}

/* Threaded resolver and 7.87.0 or later: no warning. */
static void test_init_quiet_on_capable_libcurl(void **state)
{
    (void)state;
    g_version_override = 1;
    g_version_asynchdns = 1;
    g_version_num = 0x075801;
    assert_int_equal(kc_http_init(&fake_ops, &capture_ops), 0);
#if LIBCURL_VERSION_NUM >= 0x075700
    assert_int_equal(g_warnings, 0);
#else
    /* Built without the option: the warning stands whatever the runtime. */
    assert_int_equal(g_warnings, 1);
#endif
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_request_handle_sets_quick_exit, reset, teardown),
        cmocka_unit_test_setup_teardown(test_sync_every_attempt_sets_quick_exit, reset, teardown),
        cmocka_unit_test_setup_teardown(test_init_warns_without_asynchdns, reset, teardown),
        cmocka_unit_test_setup_teardown(test_init_warns_old_libcurl, reset, teardown),
        cmocka_unit_test_setup_teardown(test_init_quiet_on_capable_libcurl, reset, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
