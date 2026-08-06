/*
 * kc_cred_derive_cmocka.c - unit tests for registration-time credential
 * derivation (SCRAM-SHA-256 + Keycloak PBKDF2 credential-import JSON).
 *
 * Reference vectors (Step 1 of the task brief) generated with:
 *
 *   python3 - <<'EOF'
 *   import hashlib, hmac, base64
 *   for pw, salt_b64, iters in [(b"pencil", "W22ZaJ0SNY7soEsUEjb6gQ==", 4096),
 *                               (b"probe-password-1", "AAAAAAAAAAAAAAAAAAAAAA==", 4096)]:
 *       salt = base64.b64decode(salt_b64)
 *       sp = hashlib.pbkdf2_hmac('sha256', pw, salt, iters, dklen=32)
 *       ck = hmac.new(sp, b"Client Key", hashlib.sha256).digest()
 *       sk = hmac.new(sp, b"Server Key", hashlib.sha256).digest()
 *       print(pw, salt_b64, base64.b64encode(hashlib.sha256(ck).digest()).decode(),
 *             base64.b64encode(sk).decode())
 *   EOF
 *
 * which is byte-identical to keycloak-webhook-spi's ScramCredentialProvider
 * (see kc_cred_derive.c's lockstep-contract comment) — that identity is the
 * guard this test enforces.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <jansson.h>
#include "kc/kc_cred_derive.h"
#include "kc/kc_base64.h"

static void test_scram_fixed_vector(void **state) {
    (void)state;
    /* RFC 7677 inputs: password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==, 4096 */
    unsigned char salt[SCRAM_SHA256_SALT_LEN];
    size_t slen = sizeof(salt);
    struct scram_sha256_creds c;
    assert_true(kc_base64_decode("W22ZaJ0SNY7soEsUEjb6gQ==", 24, (char*)salt, &slen));
    assert_int_equal(0, scram_sha256_derive("pencil", salt, slen, 4096, &c));
    assert_string_equal(c.stored_key_b64, "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=");
    assert_string_equal(c.server_key_b64, "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=");
    assert_int_equal(c.iterations, 4096);
    assert_string_equal(c.salt_b64, "W22ZaJ0SNY7soEsUEjb6gQ==");
}

static void test_scram_fixed_vector_probe(void **state) {
    (void)state;
    /* Task 0 probe inputs: password "probe-password-1",
     * salt AAAAAAAAAAAAAAAAAAAAAA==, 4096 */
    unsigned char salt[SCRAM_SHA256_SALT_LEN];
    size_t slen = sizeof(salt);
    struct scram_sha256_creds c;
    assert_true(kc_base64_decode("AAAAAAAAAAAAAAAAAAAAAA==", 24, (char*)salt, &slen));
    assert_int_equal(0, scram_sha256_derive("probe-password-1", salt, slen, 4096, &c));
    assert_string_equal(c.stored_key_b64, "2hdPaKT6RylO8ixdfatXPJ70yNQSWh0Hs8rJLvUgay0=");
    assert_string_equal(c.server_key_b64, "Wjwq1UsUVcfnCq0OucU8W+hYxFqf09z4nxuKJ3Ykf1o=");
}

static void test_scram_random_salt_differs(void **state) {
    (void)state;
    struct scram_sha256_creds a, b;
    assert_int_equal(0, scram_sha256_derive_random("hunter22", &a));
    assert_int_equal(0, scram_sha256_derive_random("hunter22", &b));
    assert_string_not_equal(a.salt_b64, b.salt_b64);
    assert_string_not_equal(a.stored_key_b64, b.stored_key_b64);
    assert_int_equal(a.iterations, SCRAM_SHA256_ITERATIONS);
}

static void test_pbkdf2_cred_shape(void **state) {
    (void)state;
    char *cred = NULL, *secret = NULL;
    json_error_t err;
    assert_int_equal(0, kc_pbkdf2_cred_build("hunter22", &cred, &secret));
    json_t *cj = json_loads(cred, 0, &err), *sj = json_loads(secret, 0, &err);
    assert_non_null(cj); assert_non_null(sj);
    assert_int_equal(json_integer_value(json_object_get(cj, "hashIterations")), KC_PBKDF2_ITERATIONS);
    assert_string_equal(json_string_value(json_object_get(cj, "algorithm")), "pbkdf2-sha256");
    assert_non_null(json_object_get(sj, "value"));
    assert_non_null(json_object_get(sj, "salt"));
    json_decref(cj); json_decref(sj); free(cred); free(secret);
}

static void test_null_inputs(void **state) {
    (void)state;
    struct scram_sha256_creds c;
    assert_int_equal(-1, scram_sha256_derive(NULL, (unsigned char*)"x", 1, 1, &c));
    assert_int_equal(-1, scram_sha256_derive_random("pw", NULL));
    assert_int_equal(-1, kc_pbkdf2_cred_build(NULL, NULL, NULL));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_scram_fixed_vector),
        cmocka_unit_test(test_scram_fixed_vector_probe),
        cmocka_unit_test(test_scram_random_salt_differs),
        cmocka_unit_test(test_pbkdf2_cred_shape),
        cmocka_unit_test(test_null_inputs),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
