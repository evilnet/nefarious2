/*
 * ircd_crypt_pbkdf2_cmocka.c - CMocka unit tests for the PBKDF2 password
 * hash module's base64 codec and hash/verify round trip.
 *
 * base64_decode(), base64_encode(), parse_pbkdf2_hash() and
 * parse_pbkdf2_sha512_hash() are static, so we #include the .c to reach
 * them -- the same approach kc_jwt_cmocka.c and websocket_cmocka.c use.
 *
 * RED (pre-fix, da48caf3): base64_decode(input, output) took no
 * output_size and wrote 3 bytes per 4-character group before trimming
 * for the missing padding -- the unpadded encoder's own output
 * overflowed the buffer it decoded into (16-byte salt -> 18 bytes,
 * 32-byte SHA256 hash -> 33 bytes, 64-byte SHA512 hash -> 66 bytes).
 * The decode_*_roundtrip tests below place a canary immediately after
 * an exactly-sized output buffer in a packed struct -- member order in
 * a struct is fixed by the C standard (only padding may be inserted,
 * never reordering), so the canary is guaranteed adjacent in memory --
 * and assert it survives the decode. Before the fix (base64_decode()
 * taking just (input, output), with no output_size argument) these
 * three failed with the canary clobbered by exactly 2, 1 and 2 bytes --
 * see the RED evidence capture in the task record. They now exercise
 * the fixed, sized base64_decode(input, output, output_size) and pass.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../ircd_crypt_pbkdf2.c"

/* ---- stubs for ircd_crypt_pbkdf2.c's external dependencies ----
 * ircd_register_crypt_pbkdf2() / _sha512() are compiled in (they live in
 * the same .c) but never exercised by these tests; they still reference
 * MyMalloc (-> DoMalloc) and ircd_crypt_register_mech, so the TU needs
 * both to link. */
void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  (void)type; (void)file; (void)line;
  return malloc(len);
}

int ircd_crypt_register_mech(crypt_mech_t *mechanism)
{
  (void)mechanism;
  return 0;
}

/* ========== base64_decode: canary-guarded round trip ========== */

/* Member order in a struct cannot be reordered by the compiler (only
 * padding may be inserted between members), so canary is guaranteed to
 * sit immediately after buf in memory -- any write past buf's declared
 * size lands in canary first. */
#define CANARY_PATTERN "\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF"
#define CANARY_LEN 8

struct guard16  { unsigned char buf[16]; unsigned char canary[CANARY_LEN]; };
struct guard32  { unsigned char buf[32]; unsigned char canary[CANARY_LEN]; };
struct guard64  { unsigned char buf[64]; unsigned char canary[CANARY_LEN]; };

static void test_decode_salt_roundtrip_no_overflow(void **state)
{
  (void)state;
  struct guard16 g;
  char salt_b64[32];
  unsigned char raw_salt[PBKDF2_SALT_LEN];
  int i, n;

  for (i = 0; i < PBKDF2_SALT_LEN; i++)
    raw_salt[i] = (unsigned char)(0x11 * (i + 1));

  base64_encode(raw_salt, PBKDF2_SALT_LEN, salt_b64);
  assert_int_equal((int)strlen(salt_b64), 22); /* unpadded 16-byte salt */

  memcpy(g.canary, CANARY_PATTERN, CANARY_LEN);
  n = base64_decode(salt_b64, g.buf, sizeof(g.buf));

  assert_int_equal(n, PBKDF2_SALT_LEN);
  assert_memory_equal(g.canary, CANARY_PATTERN, CANARY_LEN);
  assert_memory_equal(g.buf, raw_salt, PBKDF2_SALT_LEN);
}

static void test_decode_sha256_hash_roundtrip_no_overflow(void **state)
{
  (void)state;
  struct guard32 g;
  char hash_b64[64];
  unsigned char raw_hash[PBKDF2_SHA256_LEN];
  int i, n;

  for (i = 0; i < PBKDF2_SHA256_LEN; i++)
    raw_hash[i] = (unsigned char)(i ^ 0x5A);

  base64_encode(raw_hash, PBKDF2_SHA256_LEN, hash_b64);
  assert_int_equal((int)strlen(hash_b64), 43); /* unpadded 32-byte hash */

  memcpy(g.canary, CANARY_PATTERN, CANARY_LEN);
  n = base64_decode(hash_b64, g.buf, sizeof(g.buf));

  assert_int_equal(n, PBKDF2_SHA256_LEN);
  assert_memory_equal(g.canary, CANARY_PATTERN, CANARY_LEN);
  assert_memory_equal(g.buf, raw_hash, PBKDF2_SHA256_LEN);
}

static void test_decode_sha512_hash_roundtrip_no_overflow(void **state)
{
  (void)state;
  struct guard64 g;
  char hash_b64[128];
  unsigned char raw_hash[PBKDF2_SHA512_LEN];
  int i, n;

  for (i = 0; i < PBKDF2_SHA512_LEN; i++)
    raw_hash[i] = (unsigned char)(i * 3 + 7);

  base64_encode(raw_hash, PBKDF2_SHA512_LEN, hash_b64);
  assert_int_equal((int)strlen(hash_b64), 86); /* unpadded 64-byte hash */

  memcpy(g.canary, CANARY_PATTERN, CANARY_LEN);
  n = base64_decode(hash_b64, g.buf, sizeof(g.buf));

  assert_int_equal(n, PBKDF2_SHA512_LEN);
  assert_memory_equal(g.canary, CANARY_PATTERN, CANARY_LEN);
  assert_memory_equal(g.buf, raw_hash, PBKDF2_SHA512_LEN);
}

/* ========== base64_decode: malformed / over-long input ========== */

/* An invalid character in the very first group means zero bytes should
 * ever be written -- both buf and canary stay exactly as seeded. */
static void test_decode_rejects_invalid_character(void **state)
{
  (void)state;
  struct guard16 g;
  int n;

  memset(g.buf, 0x42, sizeof(g.buf));
  memcpy(g.canary, CANARY_PATTERN, CANARY_LEN);

  /* '@' is not in base64_chars; valid length (4 chars). */
  n = base64_decode("AB@D", g.buf, sizeof(g.buf));

  assert_int_equal(n, -1);
  assert_memory_equal(g.canary, CANARY_PATTERN, CANARY_LEN);
  for (int i = 0; i < 16; i++)
    assert_int_equal(g.buf[i], 0x42);
}

/* A length that is 1 mod 4 cannot be valid unpadded base64 (one
 * leftover character cannot encode a whole trailing byte). */
static void test_decode_rejects_invalid_length(void **state)
{
  (void)state;
  struct guard16 g;
  int n;

  memset(g.buf, 0x42, sizeof(g.buf));
  memcpy(g.canary, CANARY_PATTERN, CANARY_LEN);

  n = base64_decode("AAAAA", g.buf, sizeof(g.buf)); /* len == 5, 5%4==1 */

  assert_int_equal(n, -1);
  assert_memory_equal(g.canary, CANARY_PATTERN, CANARY_LEN);
  for (int i = 0; i < 16; i++)
    assert_int_equal(g.buf[i], 0x42);
}

/* The over-long-config-string case from the bug report: a valid,
 * well-formed base64 string whose decoded length exceeds the output
 * buffer. Must be refused before a single byte is written -- exactly
 * what let a config file's $PBKDF2$ salt/hash field overflow
 * salt_bytes[16] / stored_hash[32|64] by up to 48 or 96 bytes. */
static void test_decode_rejects_over_long_input(void **state)
{
  (void)state;
  struct guard16 g;
  unsigned char raw[40];
  char encoded[64];
  int i, n;

  for (i = 0; i < (int)sizeof(raw); i++)
    raw[i] = (unsigned char)i;
  base64_encode(raw, sizeof(raw), encoded); /* decodes to 40 bytes */

  memset(g.buf, 0x42, sizeof(g.buf));
  memcpy(g.canary, CANARY_PATTERN, CANARY_LEN);

  n = base64_decode(encoded, g.buf, sizeof(g.buf)); /* buf is only 16 */

  assert_int_equal(n, -1);
  assert_memory_equal(g.canary, CANARY_PATTERN, CANARY_LEN);
  for (i = 0; i < 16; i++)
    assert_int_equal(g.buf[i], 0x42);
}

/* Same scenario, end to end: a config file with an over-long salt field
 * must not corrupt parse_pbkdf2_hash()'s caller-supplied buffers; it
 * should simply report "not a valid existing hash" (0), same as any
 * other malformed field, instead of overflowing the 16-byte salt
 * buffer by up to 48 bytes. */
static void test_parse_rejects_over_long_salt_field(void **state)
{
  (void)state;
  char hash[256];
  int iterations, salt_len, hash_len;
  unsigned char salt[PBKDF2_SALT_LEN];
  unsigned char stored_hash[PBKDF2_SHA256_LEN];
  int rc;

  /* 60 'A' characters: valid base64 alphabet, decodes to 45 bytes --
   * well past the 16-byte salt buffer. */
  snprintf(hash, sizeof(hash), "$PBKDF2$100000$%.*s$%.*s",
           60, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
           43, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

  rc = parse_pbkdf2_hash(hash, &iterations, salt, &salt_len,
                          stored_hash, &hash_len);

  assert_int_equal(rc, 0); /* refused, not a crash or a silent overflow */
}

/* ========== Hash / verify round trip (public API) ========== */

static void test_pbkdf2_sha256_roundtrip(void **state)
{
  (void)state;
  char stored[256];
  const char *r;

  r = ircd_crypt_pbkdf2("correct horse battery staple", PBKDF2_TOKEN);
  assert_non_null(r);
  snprintf(stored, sizeof(stored), "%s", r);

  /* Correct password re-derives to the identical stored string. */
  r = ircd_crypt_pbkdf2("correct horse battery staple", stored);
  assert_non_null(r);
  assert_string_equal(r, stored);

  /* Wrong password re-derives to a different hash. */
  r = ircd_crypt_pbkdf2("wrong password", stored);
  assert_non_null(r);
  assert_string_not_equal(r, stored);
}

static void test_pbkdf2_sha512_roundtrip(void **state)
{
  (void)state;
  char stored[512];
  const char *r;

  r = ircd_crypt_pbkdf2_sha512("correct horse battery staple", PBKDF2_SHA512_TOKEN);
  assert_non_null(r);
  snprintf(stored, sizeof(stored), "%s", r);

  r = ircd_crypt_pbkdf2_sha512("correct horse battery staple", stored);
  assert_non_null(r);
  assert_string_equal(r, stored);

  r = ircd_crypt_pbkdf2_sha512("wrong password", stored);
  assert_non_null(r);
  assert_string_not_equal(r, stored);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_decode_salt_roundtrip_no_overflow),
    cmocka_unit_test(test_decode_sha256_hash_roundtrip_no_overflow),
    cmocka_unit_test(test_decode_sha512_hash_roundtrip_no_overflow),
    cmocka_unit_test(test_decode_rejects_invalid_character),
    cmocka_unit_test(test_decode_rejects_invalid_length),
    cmocka_unit_test(test_decode_rejects_over_long_input),
    cmocka_unit_test(test_parse_rejects_over_long_salt_field),
    cmocka_unit_test(test_pbkdf2_sha256_roundtrip),
    cmocka_unit_test(test_pbkdf2_sha512_roundtrip),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
