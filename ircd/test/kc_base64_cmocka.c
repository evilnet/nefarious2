/*
 * kc_base64_cmocka.c - unit tests for the vendored libkc base64 codec.
 * kc_base64.c has no libkc dependencies at all — no log stub needed.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <kc/kc_base64.h>

static void test_encode_alloc_roundtrip(void **state) {
    (void)state;
    const char *in = "nefarious";
    char *enc = NULL;
    size_t enc_len = kc_base64_encode_alloc(in, strlen(in), &enc);
    assert_non_null(enc);
    assert_int_equal(enc_len, KC_BASE64_LENGTH(strlen(in)));
    assert_string_equal(enc, "bmVmYXJpb3Vz");

    char *dec = NULL;
    size_t dec_len = 0;
    assert_true(kc_base64_decode_alloc(enc, enc_len, &dec, &dec_len));
    assert_int_equal(dec_len, strlen(in));
    assert_memory_equal(dec, in, dec_len);

    free(enc);
    free(dec);
}

/* One and two padding characters — the two off-by-one-prone cases. */
static void test_padding_one(void **state) {
    (void)state;
    char *enc = NULL;
    kc_base64_encode_alloc("ab", 2, &enc);
    assert_string_equal(enc, "YWI=");
    free(enc);
}

static void test_padding_two(void **state) {
    (void)state;
    char *enc = NULL;
    kc_base64_encode_alloc("a", 1, &enc);
    assert_string_equal(enc, "YQ==");
    free(enc);
}

static void test_empty_input(void **state) {
    (void)state;
    char *enc = NULL;
    size_t n = kc_base64_encode_alloc("", 0, &enc);
    assert_int_equal(n, 0);
    assert_non_null(enc);
    assert_string_equal(enc, "");
    free(enc);
}

/* Binary payloads must survive — JWKS moduli are not text. */
static void test_binary_roundtrip(void **state) {
    (void)state;
    const char raw[] = { 0x00, (char)0xff, 0x10, (char)0x80, 0x7f };
    char *enc = NULL;
    size_t enc_len = kc_base64_encode_alloc(raw, sizeof raw, &enc);
    assert_non_null(enc);

    char *dec = NULL;
    size_t dec_len = 0;
    assert_true(kc_base64_decode_alloc(enc, enc_len, &dec, &dec_len));
    assert_int_equal(dec_len, sizeof raw);
    assert_memory_equal(dec, raw, sizeof raw);

    free(enc);
    free(dec);
}

static void test_reject_invalid(void **state) {
    (void)state;
    char *dec = NULL;
    size_t dec_len = 0;
    /* '!' is not in the base64 alphabet. */
    assert_false(kc_base64_decode_alloc("YWJ!", 4, &dec, &dec_len));
    free(dec);
}

static void test_isbase64(void **state) {
    (void)state;
    assert_true(kc_isbase64('A'));
    assert_true(kc_isbase64('z'));
    assert_true(kc_isbase64('0'));
    assert_true(kc_isbase64('+'));
    assert_true(kc_isbase64('/'));
    assert_false(kc_isbase64('!'));
    assert_false(kc_isbase64('-'));   /* url-safe alphabet is NOT accepted here */
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_encode_alloc_roundtrip),
        cmocka_unit_test(test_padding_one),
        cmocka_unit_test(test_padding_two),
        cmocka_unit_test(test_empty_input),
        cmocka_unit_test(test_binary_roundtrip),
        cmocka_unit_test(test_reject_invalid),
        cmocka_unit_test(test_isbase64),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
