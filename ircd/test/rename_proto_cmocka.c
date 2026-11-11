/*
 * rename_proto_cmocka.c - the argument-only parts of channel RENAME: the
 * cookie a services permission query travels under ("<numeric>.<n>", and
 * the bare "<n>" older servers send).
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <string.h>
#include <cmocka.h>

#include "rename_proto.h"

/* ========== cookie: format ========== */

static void format_two_character_numeric(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN];
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "Bj", 17), 5);
  assert_string_equal(buf, "Bj.17");
}

static void format_one_character_numeric(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN];
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "A", 1), 3);
  assert_string_equal(buf, "A.1");
}

static void format_largest_value_fits_the_documented_buffer(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN];
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "]]", UINT_MAX),
                   RENAME_COOKIE_BUFLEN - 1);
  assert_string_equal(buf, "]].4294967295");
}

static void format_refuses_what_is_not_a_server_numeric(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN] = "keep";
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "", 1), 0);
  assert_string_equal(buf, "");
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), NULL, 1), 0);
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "ABC", 1), 0);   /* a user's prefix, not a server */
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "A.", 1), 0);
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "A ", 1), 0);
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "-A", 1), 0);
  assert_string_equal(buf, "");
}

static void format_refuses_a_buffer_too_small(void **state)
{
  char buf[5] = "keep";
  (void)state;
  /* "Bj.17" needs six bytes */
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "Bj", 17), 0);
  assert_string_equal(buf, "");
  assert_int_equal(rename_cookie_format(buf, 0, "Bj", 17), 0);
  assert_int_equal(rename_cookie_format(NULL, 16, "Bj", 17), 0);
}

/* ========== cookie: parse ========== */

static void parse_round_trips_every_numeric_length(void **state)
{
  static const char *const numerics[] = { "A", "]", "0", "Bj", "AC", "[]", "09", "]]" };
  static const unsigned int values[] = { 0, 1, 9, 10, 17, 4096, 2147483647u,
                                         2147483648u, UINT_MAX };
  size_t i, j;
  (void)state;

  for (i = 0; i < sizeof(numerics) / sizeof(numerics[0]); i++) {
    for (j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
      char buf[RENAME_COOKIE_BUFLEN];
      char numeric[3] = "??";
      unsigned int n = 12345;

      assert_true(rename_cookie_format(buf, sizeof(buf), numerics[i], values[j]) > 0);
      assert_int_equal(rename_cookie_parse(buf, numeric, &n), RENAME_COOKIE_ROUTED);
      assert_string_equal(numeric, numerics[i]);
      assert_true(n == values[j]);
    }
  }
}

static void parse_old_undotted_form(void **state)
{
  char numeric[3] = "??";
  unsigned int n = 12345;
  (void)state;

  assert_int_equal(rename_cookie_parse("17", numeric, &n), RENAME_COOKIE_LEGACY);
  assert_string_equal(numeric, "");
  assert_int_equal(n, 17);

  assert_int_equal(rename_cookie_parse("0", numeric, &n), RENAME_COOKIE_LEGACY);
  assert_int_equal(n, 0);

  assert_int_equal(rename_cookie_parse("4294967295", numeric, &n), RENAME_COOKIE_LEGACY);
  assert_true(n == UINT_MAX);
}

/* A digit is a legal numeric character, so "12.7" is server "12", request
 * 7 -- not request 12 with something after it. */
static void parse_all_digit_numeric_is_still_a_numeric(void **state)
{
  char numeric[3];
  unsigned int n = 0;
  (void)state;

  assert_int_equal(rename_cookie_parse("12.7", numeric, &n), RENAME_COOKIE_ROUTED);
  assert_string_equal(numeric, "12");
  assert_int_equal(n, 7);
}

static void expect_invalid(const char *text)
{
  char numeric[3] = "??";
  unsigned int n = 12345;

  assert_int_equal(rename_cookie_parse(text, numeric, &n), RENAME_COOKIE_INVALID);
  assert_string_equal(numeric, "");     /* never a stale numeric */
  assert_int_equal(n, 12345);           /* untouched */
}

static void parse_empty_parts(void **state)
{
  (void)state;
  expect_invalid(NULL);
  expect_invalid("");
  expect_invalid(".");
  expect_invalid(".17");        /* no numeric */
  expect_invalid("Bj.");        /* a dot with nothing after it */
  expect_invalid("B.");
  expect_invalid("..");
  expect_invalid("Bj..17");
}

static void parse_garbage(void **state)
{
  (void)state;
  expect_invalid("Bj");                 /* a numeric and nothing else */
  expect_invalid("RENAME");
  expect_invalid("#channel");
  expect_invalid("Bj.17.3");            /* a second dot */
  expect_invalid("Bj.17 ");
  expect_invalid(" Bj.17");
  expect_invalid("Bj.-1");
  expect_invalid("Bj.+1");
  expect_invalid("Bj.1x");
  expect_invalid("Bj.0x11");
  expect_invalid("-17");
  expect_invalid("+17");
  expect_invalid("17x");
  expect_invalid("1 7");
  expect_invalid("B-.17");              /* '-' and '_' are base64url, not P10 */
  expect_invalid("B_.17");
  expect_invalid("B\xe9.17");
  expect_invalid("Bj\t.17");
  expect_invalid("ABAAB");              /* a user numeric */
  expect_invalid(".12.34");             /* the LOC request id shape */
}

static void parse_numeric_too_long(void **state)
{
  (void)state;
  expect_invalid("ABC.17");
  expect_invalid("ABAAB.17");
}

static void parse_leading_zero_is_not_what_a_server_prints(void **state)
{
  (void)state;
  expect_invalid("017");
  expect_invalid("00");
  expect_invalid("Bj.017");
  expect_invalid("Bj.00");
}

static void parse_overflow(void **state)
{
  (void)state;
  expect_invalid("4294967296");                 /* UINT_MAX + 1 */
  expect_invalid("Bj.4294967296");
  expect_invalid("9999999999");                 /* ten digits, too large */
  expect_invalid("Bj.9999999999");
  expect_invalid("42949672950");                /* eleven digits */
  expect_invalid("Bj.42949672950");
  expect_invalid("Bj.18446744073709551616");    /* past 64 bits: must not wrap to 0 */
  expect_invalid("18446744073709551617");       /* ... nor to 1 */
}

static void parse_over_long(void **state)
{
  char big[600];
  (void)state;

  memset(big, '7', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  expect_invalid(big);

  big[0] = 'B'; big[1] = 'j'; big[2] = '.';
  expect_invalid(big);

  memset(big, 'A', sizeof(big) - 1);
  expect_invalid(big);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(format_two_character_numeric),
    cmocka_unit_test(format_one_character_numeric),
    cmocka_unit_test(format_largest_value_fits_the_documented_buffer),
    cmocka_unit_test(format_refuses_what_is_not_a_server_numeric),
    cmocka_unit_test(format_refuses_a_buffer_too_small),
    cmocka_unit_test(parse_round_trips_every_numeric_length),
    cmocka_unit_test(parse_old_undotted_form),
    cmocka_unit_test(parse_all_digit_numeric_is_still_a_numeric),
    cmocka_unit_test(parse_empty_parts),
    cmocka_unit_test(parse_garbage),
    cmocka_unit_test(parse_numeric_too_long),
    cmocka_unit_test(parse_leading_zero_is_not_what_a_server_prints),
    cmocka_unit_test(parse_overflow),
    cmocka_unit_test(parse_over_long),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
