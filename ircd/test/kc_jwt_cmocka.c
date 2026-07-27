/*
 * kc_jwt_cmocka.c - unit tests for JWT claim validation (F-K3).
 *
 * jwt_parse_claims() is static and sits behind the JWKS fetch in
 * kc_jwt_validate_local(), so we #include the .c to reach it — the same
 * approach ircd_cloaking_cmocka.c and crule_cmocka.c use.  No network,
 * no JWKS, no signature verification is exercised here: this covers the
 * claim policy only.
 *
 * Payloads are base64url of:
 *   VALID       {"exp":4102444800,"sub":"u1","preferred_username":"alice"}
 *   NOEXP       {"sub":"u1","preferred_username":"alice"}
 *   EXPIRED     {"exp":1000000000,"sub":"u1"}
 *   FUTURE_NBF  {"exp":4102444800,"nbf":4102444800,"sub":"u1"}
 * exp 4102444800 = 2100-01-01; exp 1000000000 = 2001-09-09.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <kc/kc_log.h>

const struct kc_log_ops *kc_get_log_ops(void);
const struct kc_log_ops *kc_get_log_ops(void) { return NULL; }

/*
 * kc_jwt_token_info_free() (compiled in below via #include, though no test
 * here calls it) calls kc_token_info_free(), which lives in kc_keycloak.c.
 * That object is not linked — it would drag in the whole async
 * Keycloak/curl-multi client for a symbol no test exercises — so stub it
 * here, same rationale as the kc_get_log_ops() stub above.
 */
struct kc_token_info;
void kc_token_info_free(struct kc_token_info *info);
void kc_token_info_free(struct kc_token_info *info) { (void)info; }

#include "../kc/kc_jwt.c"

#define P_VALID      "eyJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UifQ"
#define P_NOEXP      "eyJzdWIiOiJ1MSIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIn0"
#define P_EXPIRED    "eyJleHAiOjEwMDAwMDAwMDAsInN1YiI6InUxIn0"
#define P_FUTURE_NBF "eyJleHAiOjQxMDI0NDQ4MDAsIm5iZiI6NDEwMjQ0NDgwMCwic3ViIjoidTEifQ"

static void free_info_fields(struct kc_token_info *i) {
    free(i->username); free(i->email); free(i->sub);
    free(i->iss); free(i->azp);
}

static void test_valid_claims_accepted(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_VALID, &info), KC_SUCCESS);
    assert_true(info.active);
    assert_int_equal(info.exp, 4102444800L);
    assert_string_equal(info.sub, "u1");
    assert_string_equal(info.username, "alice");
    free_info_fields(&info);
}

/* F-K3: a token with no exp would otherwise be valid forever. */
static void test_missing_exp_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_NOEXP, &info), KC_FORBIDDEN);
    free_info_fields(&info);
}

static void test_expired_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_EXPIRED, &info), KC_FORBIDDEN);
    free_info_fields(&info);
}

/* F-K3: nbf enforced when present, beyond the 60s skew tolerance. */
static void test_future_nbf_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_FUTURE_NBF, &info), KC_FORBIDDEN);
    free_info_fields(&info);
}

/* An absent nbf is not an error — Keycloak does not always emit it. */
static void test_absent_nbf_is_not_an_error(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_VALID, &info), KC_SUCCESS);
    assert_int_equal(info.nbf, 0);
    free_info_fields(&info);
}

static void test_garbage_payload_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    int rc = jwt_parse_claims("!!!not-base64!!!", &info);
    assert_int_not_equal(rc, KC_SUCCESS);
    free_info_fields(&info);
}

static void test_extract_created_at_handles_malformed(void **state) {
    (void)state;
    assert_int_equal(kc_jwt_extract_created_at(NULL), 0);
    assert_int_equal(kc_jwt_extract_created_at("no-dots-here"), 0);
    assert_int_equal(kc_jwt_extract_created_at("only.one-dot"), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_claims_accepted),
        cmocka_unit_test(test_missing_exp_rejected),
        cmocka_unit_test(test_expired_rejected),
        cmocka_unit_test(test_future_nbf_rejected),
        cmocka_unit_test(test_absent_nbf_is_not_an_error),
        cmocka_unit_test(test_garbage_payload_rejected),
        cmocka_unit_test(test_extract_created_at_handles_malformed),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
