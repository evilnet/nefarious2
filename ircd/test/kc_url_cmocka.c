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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_token_endpoint),
        cmocka_unit_test(test_jwks_endpoint),
        cmocka_unit_test(test_user_by_id),
        cmocka_unit_test(test_user_by_username_exact),
        cmocka_unit_test(test_user_by_username_inexact),
        cmocka_unit_test(test_user_send_verify_email),
        cmocka_unit_test(test_null_realm_rejected),
        cmocka_unit_test(test_group_by_path_keeps_slashes),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
