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
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

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
    void *pval;         /* the value, for an object or string option */
    void (*fval)(void); /* the value, for a function option */
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
        g_setopts[g_nsetopts].pval = NULL;
        g_setopts[g_nsetopts].fval = NULL;
    }
    if (option < CURLOPTTYPE_OBJECTPOINT) {
        long v = va_arg(ap, long);
        if (g_nsetopts < MAX_SETOPTS)
            g_setopts[g_nsetopts].lval = v;
        rc = __real_curl_easy_setopt(easy, option, v);
    } else if (option < CURLOPTTYPE_FUNCTIONPOINT) {
        void *v = va_arg(ap, void *);
        if (g_nsetopts < MAX_SETOPTS)
            g_setopts[g_nsetopts].pval = v;
        rc = __real_curl_easy_setopt(easy, option, v);
    } else if (option < CURLOPTTYPE_OFF_T) {
        void (*f)(void) = va_arg(ap, void (*)(void));
        if (g_nsetopts < MAX_SETOPTS)
            g_setopts[g_nsetopts].fval = f;
        rc = __real_curl_easy_setopt(easy, option, f);
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

/* --- connect_check --- */

static int g_check_allow;
static int g_check_calls;
static int g_check_family;
static void *g_check_data;
static struct sockaddr_in g_check_sin;   /* the last IPv4 address asked about */

static int record_check(const struct sockaddr *addr, size_t addrlen, void *data)
{
    g_check_calls++;
    g_check_family = addr->sa_family;
    g_check_data = data;
    if (addr->sa_family == AF_INET && addrlen >= sizeof(g_check_sin))
        memcpy(&g_check_sin, addr, sizeof(g_check_sin));
    return g_check_allow;
}

/* The setopt record for option \a opt on handle \a easy, or NULL. */
static const struct setopt_rec *find_setopt(CURL *easy, CURLoption opt)
{
    int i;
    for (i = 0; i < g_nsetopts && i < MAX_SETOPTS; i++)
        if (g_setopts[i].easy == easy && g_setopts[i].option == opt)
            return &g_setopts[i];
    return NULL;
}

static CURL *handle_of(const char *url)
{
    int i;
    for (i = 0; i < g_nsetopts && i < MAX_SETOPTS; i++)
        if (g_setopts[i].option == CURLOPT_URL && g_setopts[i].pval
            && !strcmp((const char *)g_setopts[i].pval, url))
            return g_setopts[i].easy;
    return NULL;
}

/* A request with a connect_check gets a socket hook that asks it about
 * each address before a socket is opened (refused: no socket, curl's
 * CURL_SOCKET_BAD), and nothing that would connect it past the hook: https
 * only, no proxy (whatever the environment says), no redirect, no pooled
 * connection.  A request without one (every Keycloak call) gets none of
 * this. */
static void test_connect_check_request(void **state)
{
    struct kc_http_request plain, checked;
    const char *plain_url = "http://127.0.0.1:9/plain";
    const char *checked_url = "https://127.0.0.1:9/checked";
    const struct setopt_rec *fn, *data, *proto;
    curl_opensocket_callback open_cb;
    struct curl_sockaddr sa;
    struct sockaddr_in sin;
    CURL *hp, *hc;
    curl_socket_t s;
    int marker;

    (void)state;
    assert_int_equal(kc_http_init(&fake_ops, &capture_ops), 0);
    memset(&plain, 0, sizeof(plain));
    plain.url = plain_url;
    memset(&checked, 0, sizeof(checked));
    checked.url = checked_url;
    checked.method = "POST";
    checked.connect_check = record_check;
    checked.connect_check_data = &marker;
    g_check_allow = 0;
    assert_int_equal(kc_http_request(&plain, ignore_response, NULL), 0);
    assert_int_equal(kc_http_request(&checked, ignore_response, NULL), 0);
    assert_true(g_nsetopts <= MAX_SETOPTS);
    hp = handle_of(plain_url);
    hc = handle_of(checked_url);
    assert_non_null(hp);
    assert_non_null(hc);

    /* No hook, no protocol limit, pooled connections without them. */
    assert_null(find_setopt(hp, CURLOPT_OPENSOCKETFUNCTION));
    assert_null(find_setopt(hp, CURLOPT_FRESH_CONNECT));
    assert_null(find_setopt(hp, CURLOPT_FORBID_REUSE));
    assert_null(find_setopt(hp, CURLOPT_PROXY));
    assert_null(find_setopt(hp, CURLOPT_NOPROXY));
    assert_null(find_setopt(hp, CURLOPT_FOLLOWLOCATION));
#if LIBCURL_VERSION_NUM >= 0x075500
    assert_null(find_setopt(hp, CURLOPT_PROTOCOLS_STR));
    assert_null(find_setopt(hp, CURLOPT_REDIR_PROTOCOLS_STR));
#else
    assert_null(find_setopt(hp, CURLOPT_PROTOCOLS));
    assert_null(find_setopt(hp, CURLOPT_REDIR_PROTOCOLS));
#endif

    /* https only, as the linked libcurl understood it. */
#if LIBCURL_VERSION_NUM >= 0x075500
    proto = find_setopt(hc, CURLOPT_PROTOCOLS_STR);
    assert_non_null(proto);
    assert_string_equal((const char *)proto->pval, "https");
#else
    proto = find_setopt(hc, CURLOPT_PROTOCOLS);
    assert_non_null(proto);
    assert_int_equal(proto->lval, CURLPROTO_HTTPS);
#endif
    assert_int_equal(proto->rc, CURLE_OK);
#if LIBCURL_VERSION_NUM >= 0x075500
    proto = find_setopt(hc, CURLOPT_REDIR_PROTOCOLS_STR);
    assert_non_null(proto);
    assert_string_equal((const char *)proto->pval, "https");
#else
    proto = find_setopt(hc, CURLOPT_REDIR_PROTOCOLS);
    assert_non_null(proto);
    assert_int_equal(proto->lval, CURLPROTO_HTTPS);
#endif
    assert_int_equal(proto->rc, CURLE_OK);

    /* No redirect is followed. */
    proto = find_setopt(hc, CURLOPT_FOLLOWLOCATION);
    assert_non_null(proto);
    assert_int_equal(proto->lval, 0);

    /* No proxy: the socket the hook judges is the endpoint's own. */
    proto = find_setopt(hc, CURLOPT_PROXY);
    assert_non_null(proto);
    assert_string_equal((const char *)proto->pval, "");
    assert_int_equal(proto->rc, CURLE_OK);
    proto = find_setopt(hc, CURLOPT_NOPROXY);
    assert_non_null(proto);
    assert_string_equal((const char *)proto->pval, "*");
    assert_int_equal(proto->rc, CURLE_OK);

    /* A checked request never rides a pooled connection (libcurl does
     * not open a socket for one, so the hook would not be asked) and
     * leaves none behind for another request. */
    proto = find_setopt(hc, CURLOPT_FRESH_CONNECT);
    assert_non_null(proto);
    assert_int_equal(proto->lval, 1);
    proto = find_setopt(hc, CURLOPT_FORBID_REUSE);
    assert_non_null(proto);
    assert_int_equal(proto->lval, 1);

    /* The hook, driven as libcurl drives it. */
    fn = find_setopt(hc, CURLOPT_OPENSOCKETFUNCTION);
    data = find_setopt(hc, CURLOPT_OPENSOCKETDATA);
    assert_non_null(fn);
    assert_non_null(data);
    assert_int_equal(fn->rc, CURLE_OK);
    open_cb = (curl_opensocket_callback)fn->fval;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(9);
    sin.sin_addr.s_addr = htonl(0x7f000001);
    memset(&sa, 0, sizeof(sa));
    sa.family = AF_INET;
    sa.socktype = SOCK_STREAM;
    sa.protocol = IPPROTO_TCP;
    sa.addrlen = sizeof(sin);
    memcpy(&sa.addr, &sin, sizeof(sin));

    g_check_calls = 0;
    g_check_allow = 0;
    s = open_cb(data->pval, CURLSOCKTYPE_IPCXN, &sa);
    assert_int_equal(s, CURL_SOCKET_BAD);
    assert_int_equal(g_check_calls, 1);
    assert_int_equal(g_check_family, AF_INET);
    assert_ptr_equal(g_check_data, &marker);

    g_check_allow = 1;
    s = open_cb(data->pval, CURLSOCKTYPE_IPCXN, &sa);
    assert_true(s != CURL_SOCKET_BAD);
    assert_int_equal(g_check_calls, 2);
    close(s);
}

/* With a proxy named in the environment, a checked request still connects
 * (and asks the hook about) the endpoint's address, not the proxy's.  The
 * hook refuses, so nothing is ever connected.  libcurl starts the connect
 * of an IP-literal URL inside kc_http_request()'s first kick; if a libcurl
 * did not, the hook is not asked and the case says so and skips. */
static void test_connect_check_ignores_env_proxy(void **state)
{
    static const char *vars[] = { "https_proxy", "HTTPS_PROXY", "all_proxy",
                                  "ALL_PROXY" };
    struct kc_http_request checked;
    size_t i;

    (void)state;
    for (i = 0; i < sizeof(vars) / sizeof(vars[0]); i++)
        setenv(vars[i], "http://127.0.0.2:3128", 1);
    unsetenv("no_proxy");
    unsetenv("NO_PROXY");
    assert_int_equal(kc_http_init(&fake_ops, &capture_ops), 0);
    memset(&checked, 0, sizeof(checked));
    checked.url = "https://127.0.0.3:9/checked";
    checked.method = "POST";
    checked.connect_check = record_check;
    g_check_allow = 0;
    g_check_calls = 0;
    memset(&g_check_sin, 0, sizeof(g_check_sin));
    assert_int_equal(kc_http_request(&checked, ignore_response, NULL), 0);
    for (i = 0; i < sizeof(vars) / sizeof(vars[0]); i++)
        unsetenv(vars[i]);
    if (g_check_calls == 0) {
        print_message("  libcurl opened no socket in the first kick\n");
        skip();
    }
    assert_int_equal(g_check_family, AF_INET);
    assert_int_equal(ntohl(g_check_sin.sin_addr.s_addr), 0x7f000003);
    assert_int_equal(ntohs(g_check_sin.sin_port), 9);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_connect_check_request, reset, teardown),
        cmocka_unit_test_setup_teardown(test_connect_check_ignores_env_proxy, reset, teardown),
        cmocka_unit_test_setup_teardown(test_request_handle_sets_quick_exit, reset, teardown),
        cmocka_unit_test_setup_teardown(test_sync_every_attempt_sets_quick_exit, reset, teardown),
        cmocka_unit_test_setup_teardown(test_init_warns_without_asynchdns, reset, teardown),
        cmocka_unit_test_setup_teardown(test_init_warns_old_libcurl, reset, teardown),
        cmocka_unit_test_setup_teardown(test_init_quiet_on_capable_libcurl, reset, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
