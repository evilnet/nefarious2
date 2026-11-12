/*
 * kc_url_cmocka.c - unit tests for the vendored libkc URL builders.
 *
 * kc_url.c uses the kc_log_* macros, which call kc_get_log_ops() from
 * kc.c.  We stub it here rather than link kc.o, which would drag in the
 * whole HTTP stack for a set of string-building tests.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <kc/kc_log.h>
#include <kc/kc_realm.h>
#include <kc/kc_url.h>

const struct kc_log_ops *kc_get_log_ops(void);
const struct kc_log_ops *kc_get_log_ops(void) { return NULL; }

static const struct kc_realm R = { "http://keycloak:8080", "afternet" };

static void test_token_endpoint(void **state) {
    (void)state;
    char *u = kc_url_token(R);
    assert_non_null(u);
    assert_string_equal(u,
        "http://keycloak:8080/realms/afternet/protocol/openid-connect/token");
    free(u);
}

static void test_introspect_endpoint(void **state) {
    (void)state;
    /* Keycloak's introspection endpoint lives under /token/; the bare
     * /openid-connect/introspect answers 405 (and a JSON body libkc used
     * to read as "inactive"). */
    char *u = kc_url_introspect(R);
    assert_non_null(u);
    assert_string_equal(u,
        "http://keycloak:8080/realms/afternet/protocol/openid-connect/token/introspect");
    free(u);
}

static void test_jwks_endpoint(void **state) {
    (void)state;
    char *u = kc_url_jwks(R);
    assert_non_null(u);
    assert_string_equal(u,
        "http://keycloak:8080/realms/afternet/protocol/openid-connect/certs");
    free(u);
}

static void test_user_by_id(void **state) {
    (void)state;
    char *u = kc_url_user(R, "abc-123");
    assert_non_null(u);
    assert_string_equal(u,
        "http://keycloak:8080/admin/realms/afternet/users/abc-123");
    free(u);
}

static void test_user_by_username_exact(void **state) {
    (void)state;
    char *u = kc_url_user_by_username(R, "alice", 1);
    assert_non_null(u);
    assert_non_null(strstr(u, "username=alice"));
    assert_non_null(strstr(u, "exact=true"));
    free(u);
}

static void test_user_by_username_inexact(void **state) {
    (void)state;
    char *u = kc_url_user_by_username(R, "alice", 0);
    assert_non_null(u);
    assert_null(strstr(u, "exact=true"));
    free(u);
}

/* Every builder must reject a NULL realm rather than format "(null)". */
static void test_null_realm_rejected(void **state) {
    (void)state;
    struct kc_realm bad = { NULL, NULL };
    assert_null(kc_url_token(bad));
    assert_null(kc_url_jwks(bad));
    assert_null(kc_url_users(bad));
}

static void test_user_send_verify_email(void **state) {
    (void)state;
    char *u = kc_url_user_send_verify_email(R, "abc-123");
    assert_non_null(u);
    assert_string_equal(u,
        "http://keycloak:8080/admin/realms/afternet/users/abc-123/send-verify-email");
    free(u);
}

/* group_by_path percent-encodes via curl but must keep literal slashes. */
static void test_group_by_path_keeps_slashes(void **state) {
    (void)state;
    char *u = kc_url_group_by_path(R, "/staff/opers");
    assert_non_null(u);
    assert_non_null(strstr(u, "/staff/opers"));
    assert_null(strstr(u, "%2F"));
    free(u);
}

/* A create's 201 answer names the new user in its Location header, at the
 * users URL the create was sent to: exactly <users_url>/<uuid>. */
#define USERS "http://keycloak:8080/admin/realms/afternet/users"
#define UUID  "1b4e28ba-2fa1-11d2-883f-0016d3cca427"

static void test_location_user_id(void **state) {
    char id[64];
    (void)state;
    assert_int_equal(kc_url_location_user_id(USERS "/" UUID, USERS, id, sizeof(id)), 1);
    assert_string_equal(id, UUID);
    /* scheme and host without case, upper-case hex */
    assert_int_equal(kc_url_location_user_id(
        "HTTP://KeyCloak:8080/admin/realms/afternet/users/1B4E28BA-2FA1-11D2-883F-0016D3CCA427",
        USERS, id, sizeof(id)), 1);
    assert_string_equal(id, "1B4E28BA-2FA1-11D2-883F-0016D3CCA427");
    /* the path alone */
    assert_int_equal(kc_url_location_user_id("/admin/realms/afternet/users/" UUID,
                                             USERS, id, sizeof(id)), 1);
    assert_string_equal(id, UUID);
    /* a users URL given with a trailing slash */
    assert_int_equal(kc_url_location_user_id(USERS "/" UUID, USERS "/", id, sizeof(id)), 1);
    /* the URL the ircd builds for its realm */
    {
        char *u = kc_url_users(R);
        assert_int_equal(kc_url_location_user_id(USERS "/" UUID, u, id, sizeof(id)), 1);
        free(u);
    }
}

/* Anything else names no user: 0, the id empty. */
static void test_location_user_id_hostile(void **state) {
    static const char *const bad[] = {
        "http://evil.example:8080/admin/realms/afternet/users/" UUID, /* other host */
        "http://keycloak:8081/admin/realms/afternet/users/" UUID,     /* other port */
        "https://keycloak:8080/admin/realms/afternet/users/" UUID,    /* other scheme */
        "http://keycloak:8080/admin/realms/other/users/" UUID,        /* other realm */
        "/admin/realms/other/users/" UUID,
        "http://keycloak:8080/admin/realms/AFTERNET/users/" UUID,     /* path case */
        USERS "/..",
        USERS "/.",
        USERS "/../" UUID,
        USERS "/" UUID "/",                                      /* trailing slash */
        USERS "/" UUID "?x=1",                                   /* query */
        USERS "/" UUID "#f",                                     /* fragment */
        USERS "/1b4e28ba%2D2fa1-11d2-883f-0016d3cca427",         /* escaped */
        USERS "/1b4e28ba-2fa1-11d2-883f-0016d3cca4270",          /* over-long */
        USERS "/1b4e28ba-2fa1-11d2-883f-0016d3cca42",            /* short */
        USERS "/1b4e28ba-2fa1-11d2-883f-0016d3cca42\r",          /* control byte */
        USERS "/1b4e28ba-2fa1-11d2-883f-0016d3cca427\r\nX: y",
        USERS "/1b4e28ba_2fa1_11d2_883f_0016d3cca427",           /* not 8-4-4-4-12 */
        USERS "/1b4e28ba-2fa1-11d2-883f-0016d3cca42g",           /* not hex */
        USERS "/f:5b0d:abc",                                     /* not a UUID */
        USERS "/",
        USERS,
        USERS "x/" UUID,                                         /* wrong path */
        "http://keycloak:8080/admin/realms/afternet/groups/" UUID,
        "http://keycloak:8080/admin/realms/afternet/users/" UUID "/groups",
        "keycloak:8080/admin/realms/afternet/users/" UUID,       /* no scheme */
        UUID,
        "",
    };
    char id[64];
    size_t i;
    (void)state;
    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        strcpy(id, "stale");
        if (kc_url_location_user_id(bad[i], USERS, id, sizeof(id)) != 0)
            fail_msg("accepted \"%s\"", bad[i]);
        assert_string_equal(id, "");
    }
    strcpy(id, "stale");
    assert_int_equal(kc_url_location_user_id(NULL, USERS, id, sizeof(id)), 0);
    assert_string_equal(id, "");
    assert_int_equal(kc_url_location_user_id(USERS "/" UUID, NULL, id, sizeof(id)), 0);
    assert_int_equal(kc_url_location_user_id(USERS "/" UUID, "not-a-url", id, sizeof(id)), 0);
    /* no room for the id: refused, never cut */
    assert_int_equal(kc_url_location_user_id(USERS "/" UUID, USERS, id, 36), 0);
    assert_int_equal(kc_url_is_uuid(UUID, 36), 1);
    assert_int_equal(kc_url_is_uuid(UUID, 35), 0);
}

/* The header lines of one response, as libcurl hands them to the header
 * callback, through the capture. */
static const char *capture(struct kc_location_capture *c, const char *const *lines)
{
    for (; *lines; lines++)
        kc_location_capture_line(c, *lines, strlen(*lines));
    return c->value;
}

static void test_location_capture(void **state) {
    struct kc_location_capture c;
    (void)state;

    /* the 201's Location, trimmed, any case of the name */
    {
        static const char *const l[] = { "HTTP/1.1 201 Created\r\n",
            "Content-Length: 0\r\n", "location:  " USERS "/" UUID " \r\n", "\r\n", NULL };
        memset(&c, 0, sizeof(c));
        assert_string_equal(capture(&c, l), USERS "/" UUID);
        kc_location_capture_free(&c);
        assert_null(c.value);
    }
    /* an interim 100 Continue's header is forgotten; the final one counts */
    {
        static const char *const l[] = { "HTTP/1.1 100 Continue\r\n",
            "Location: http://x/admin/realms/afternet/users/early\r\n", "\r\n",
            "HTTP/1.1 201 Created\r\n", "Location: " USERS "/" UUID "\r\n", "\r\n", NULL };
        memset(&c, 0, sizeof(c));
        assert_string_equal(capture(&c, l), USERS "/" UUID);
        kc_location_capture_free(&c);
    }
    /* a later block without one keeps nothing from the earlier block */
    {
        static const char *const l[] = { "HTTP/1.1 302 Found\r\n",
            "Location: " USERS "/" UUID "\r\n", "\r\n",
            "HTTP/1.1 201 Created\r\n", "\r\n", NULL };
        memset(&c, 0, sizeof(c));
        assert_null(capture(&c, l));
        kc_location_capture_free(&c);
    }
    /* two in one block: none; an empty second one: none */
    {
        static const char *const l[] = { "HTTP/1.1 201 Created\r\n",
            "Location: " USERS "/" UUID "\r\n",
            "Location: " USERS "/2b4e28ba-2fa1-11d2-883f-0016d3cca427\r\n", "\r\n", NULL };
        static const char *const l2[] = { "HTTP/1.1 201 Created\r\n",
            "Location: " USERS "/" UUID "\r\n", "Location:\r\n", "\r\n", NULL };
        static const char *const l3[] = { "HTTP/1.1 201 Created\r\n",
            "Location: \r\n", "\r\n", NULL };
        memset(&c, 0, sizeof(c));
        assert_null(capture(&c, l));
        kc_location_capture_free(&c);
        memset(&c, 0, sizeof(c));
        assert_null(capture(&c, l2));
        kc_location_capture_free(&c);
        memset(&c, 0, sizeof(c));
        assert_null(capture(&c, l3));
        kc_location_capture_free(&c);
    }
    /* a trailer never names it, nor overrides it */
    {
        static const char *const l[] = { "HTTP/1.1 201 Created\r\n",
            "Transfer-Encoding: chunked\r\n", "\r\n",
            "Location: " USERS "/2b4e28ba-2fa1-11d2-883f-0016d3cca427\r\n", NULL };
        static const char *const l2[] = { "HTTP/1.1 201 Created\r\n",
            "Location: " USERS "/" UUID "\r\n", "\r\n",
            "Location: " USERS "/2b4e28ba-2fa1-11d2-883f-0016d3cca427\r\n", NULL };
        memset(&c, 0, sizeof(c));
        assert_null(capture(&c, l));
        kc_location_capture_free(&c);
        memset(&c, 0, sizeof(c));
        assert_string_equal(capture(&c, l2), USERS "/" UUID);
        kc_location_capture_free(&c);
    }
    /* a header line before any status line, or a name that only starts
     * the same, is not it */
    {
        static const char *const l[] = { "Location: " USERS "/" UUID "\r\n",
            "HTTP/1.1 201 Created\r\n", "Locations: x\r\n", "X-Location: y\r\n",
            "\r\n", NULL };
        memset(&c, 0, sizeof(c));
        assert_null(capture(&c, l));
        kc_location_capture_free(&c);
    }
}

/* What a log line gets of a wire value. */
static void test_log_safe(void **state) {
    char out[16];
    (void)state;
    kc_url_log_safe("ab\r\ncd\x01\x7f\xff", out, sizeof(out));
    assert_string_equal(out, "ab??cd???");
    kc_url_log_safe("0123456789abcdefghij", out, sizeof(out));
    assert_string_equal(out, "0123456789ab...");
    kc_url_log_safe(NULL, out, sizeof(out));
    assert_string_equal(out, "(none)");
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_token_endpoint),
        cmocka_unit_test(test_introspect_endpoint),
        cmocka_unit_test(test_jwks_endpoint),
        cmocka_unit_test(test_user_by_id),
        cmocka_unit_test(test_user_by_username_exact),
        cmocka_unit_test(test_user_by_username_inexact),
        cmocka_unit_test(test_user_send_verify_email),
        cmocka_unit_test(test_null_realm_rejected),
        cmocka_unit_test(test_group_by_path_keeps_slashes),
        cmocka_unit_test(test_location_user_id),
        cmocka_unit_test(test_location_user_id_hostile),
        cmocka_unit_test(test_location_capture),
        cmocka_unit_test(test_log_safe),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
