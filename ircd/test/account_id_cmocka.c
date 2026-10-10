/*
 * account_id_cmocka.c - the compact Keycloak user id: 16 UUID bytes as
 * 22 unpadded base64url characters, the form carried on the wire.
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include "account_id.h"
#include "webpush_keyring.h"

static void canonical_uuid_encodes_to_22_chars(void **state)
{
  char out[ACCOUNT_ID_LEN + 1];
  unsigned char raw[16]; size_t n = 0;
  (void)state;
  assert_int_equal(account_id_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8", out), 1);
  assert_int_equal(strlen(out), ACCOUNT_ID_LEN);
  assert_int_equal(account_id_valid(out), 1);
  /* round trip: the 22 chars decode to the UUID's bytes */
  assert_int_equal(webpush_b64url_decode(out, strlen(out), raw, sizeof(raw), &n), 0);
  assert_int_equal(n, 16);
  assert_int_equal(raw[0], 0x6b); assert_int_equal(raw[15], 0xc8);
}

static void zero_uuid_is_all_A(void **state)
{
  char out[ACCOUNT_ID_LEN + 1];
  (void)state;
  assert_int_equal(account_id_from_uuid("00000000-0000-0000-0000-000000000000", out), 1);
  assert_string_equal(out, "AAAAAAAAAAAAAAAAAAAAAA");
}

static void hex_case_and_hyphens_do_not_matter(void **state)
{
  char a[ACCOUNT_ID_LEN + 1], b[ACCOUNT_ID_LEN + 1], c[ACCOUNT_ID_LEN + 1];
  (void)state;
  assert_true(account_id_from_uuid("6BA7B810-9DAD-11D1-80B4-00C04FD430C8", a));
  assert_true(account_id_from_uuid("6ba7b8109dad11d180b400c04fd430c8", b));
  assert_true(account_id_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8", c));
  assert_string_equal(a, b);
  assert_string_equal(b, c);
}

static void malformed_uuid_is_refused(void **state)
{
  char out[ACCOUNT_ID_LEN + 1] = "keep";
  (void)state;
  assert_int_equal(account_id_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c", out), 0);  /* 31 digits */
  assert_int_equal(account_id_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430c8f", out), 0); /* 33 */
  assert_int_equal(account_id_from_uuid("6ba7b810-9dad-11d1-80b4-00c04fd430cg", out), 0);  /* not hex */
  assert_int_equal(account_id_from_uuid("", out), 0);
  assert_int_equal(account_id_from_uuid(NULL, out), 0);
  assert_string_equal(out, "keep");                                                  /* untouched */
}

static void only_22_base64url_chars_are_valid(void **state)
{
  (void)state;
  assert_true(account_id_valid("a6p7gJ2tEdGAtADAT9QwyA"));
  assert_true(account_id_valid("AAAAAAAAAAAAAAAAAAAAAA"));
  assert_true(account_id_valid("-_-_-_-_-_-_-_-_-_-_-_"));
  assert_false(account_id_valid("a6p7gJ2tEdGAtADAT9Qwy"));   /* 21 */
  assert_false(account_id_valid("a6p7gJ2tEdGAtADAT9QwyAA")); /* 23 */
  assert_false(account_id_valid("a6p7gJ2tEdGAtADAT9Qwy="));  /* padding */
  assert_false(account_id_valid("a6p7gJ2tEdGAtADAT9Qw+A"));  /* standard alphabet */
  assert_false(account_id_valid("RENAME"));
  assert_false(account_id_valid(""));
  assert_false(account_id_valid(NULL));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(canonical_uuid_encodes_to_22_chars),
    cmocka_unit_test(zero_uuid_is_all_A),
    cmocka_unit_test(hex_case_and_hyphens_do_not_matter),
    cmocka_unit_test(malformed_uuid_is_refused),
    cmocka_unit_test(only_22_base64url_chars_are_valid),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
