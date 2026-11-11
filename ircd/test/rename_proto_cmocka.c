/*
 * rename_proto_cmocka.c - the argument-only parts of channel RENAME: the
 * cookie a services permission query travels under ("<numeric>.<n>", and
 * the bare "<n>" older servers send), and the rules a pair of channel
 * names has to pass.
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <limits.h>
#include <string.h>
#include <cmocka.h>

#include "ircd_defs.h"
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

/* ========== names ========== */

#define OK(o, n)        assert_int_equal(rename_check_names((o), (n), CHANNELLEN, 0), RENAME_NAME_OK)
#define BAD(o, n, why)  assert_int_equal(rename_check_names((o), (n), CHANNELLEN, 0), (why))

static void names_plain_rename_is_fine(void **state)
{
  (void)state;
  OK("#old", "#new");
  OK("#old", "#");
  OK("#old", "#new-name_[with]{odd}|chars^`'");
  OK("#old", "#caf\xc3\xa9");                   /* UTF-8, no 0xA0 byte */
  OK("#old", "#\xe9t\xe9");                     /* Latin-1: JOIN takes it unless UTF-8 only */
  OK("#old", "#a:b");
  OK("#old", "##");
  OK("#old", "#a&b");
}

static void names_local_channels_are_refused_on_either_side(void **state)
{
  (void)state;
  BAD("&ops", "#leak", RENAME_NAME_OLD_LOCAL);
  BAD("&ops", "&staff", RENAME_NAME_OLD_LOCAL);
  BAD("#chan", "&chan", RENAME_NAME_NEW_LOCAL);
  BAD("#chan", "&", RENAME_NAME_NEW_LOCAL);
}

static void names_without_a_channel_prefix(void **state)
{
  (void)state;
  BAD("#old", "new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", "", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", NULL, RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", "+new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", "!new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", " #new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("old", "#new", RENAME_NAME_OLD_NOT_CHANNEL);
  BAD("", "#new", RENAME_NAME_OLD_NOT_CHANNEL);
  BAD(NULL, "#new", RENAME_NAME_OLD_NOT_CHANNEL);
  /* the old name is judged first */
  BAD("old", "&new", RENAME_NAME_OLD_NOT_CHANNEL);
}

static void names_comma(void **state)
{
  (void)state;
  BAD("#a", "#a,b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#a", "#a,#b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#a", "#,", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#a", "#b,", RENAME_NAME_NEW_BAD_CHARS);
}

static void names_control_characters_and_space(void **state)
{
  char name[8];
  int c;
  (void)state;

  /* every byte from 0x01 to 0x20 */
  for (c = 1; c <= 0x20; c++) {
    name[0] = '#'; name[1] = 'a'; name[2] = (char)c; name[3] = 'b'; name[4] = '\0';
    BAD("#old", name, RENAME_NAME_NEW_BAD_CHARS);
  }
  BAD("#old", "#bell\007", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#a b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#tab\there", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#\001", RENAME_NAME_NEW_BAD_CHARS);
  /* 0x21 and 0x7f are in JOIN's set, so they are in ours */
  OK("#old", "#a!b");
  OK("#old", "#a\177");
}

static void names_nbsp_byte(void **state)
{
  (void)state;
  BAD("#old", "#a\xa0" "b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#\xa0", RENAME_NAME_NEW_BAD_CHARS);
  /* also when it is the second byte of a UTF-8 sequence ("a grave"):
   * JOIN refuses the byte wherever it stands, and so does this */
  BAD("#old", "#voil\xc3\xa0", RENAME_NAME_NEW_BAD_CHARS);
}

static void names_length_cap(void **state)
{
  char name[CHANNELLEN + 3];
  (void)state;

  memset(name, 'x', sizeof(name));
  name[0] = '#';

  name[CHANNELLEN] = '\0';              /* exactly CHANNELLEN bytes */
  assert_int_equal(rename_check_names("#old", name, CHANNELLEN, 0), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", name, CHANNELLEN - 1, 0),
                   RENAME_NAME_NEW_TOO_LONG);

  name[CHANNELLEN] = 'x';
  name[CHANNELLEN + 1] = '\0';          /* one over */
  assert_int_equal(rename_check_names("#old", name, CHANNELLEN, 0),
                   RENAME_NAME_NEW_TOO_LONG);

  /* a lower configured cap (FEAT_CHANNELLEN) */
  assert_int_equal(rename_check_names("#old", "#12345", 6, 0), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", "#123456", 6, 0), RENAME_NAME_NEW_TOO_LONG);
  /* the old name's length is nobody's business */
  assert_int_equal(rename_check_names("#a-long-old-name", "#new", 6, 0), RENAME_NAME_OK);
}

static void names_utf8_only_when_asked(void **state)
{
  (void)state;
  assert_int_equal(rename_check_names("#old", "#\xe9t\xe9", CHANNELLEN, 0), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", "#\xe9t\xe9", CHANNELLEN, 1),
                   RENAME_NAME_NEW_BAD_UTF8);
  assert_int_equal(rename_check_names("#old", "#caf\xc3\xa9", CHANNELLEN, 1), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", "#ascii", CHANNELLEN, 1), RENAME_NAME_OK);
  /* a truncated sequence */
  assert_int_equal(rename_check_names("#old", "#caf\xc3", CHANNELLEN, 1),
                   RENAME_NAME_NEW_BAD_UTF8);
}

/* With # and & the only prefixes, two names of different type always have
 * a local channel on one side, and that is what is reported. */
static void names_mixed_prefix(void **state)
{
  (void)state;
  BAD("&a", "#a", RENAME_NAME_OLD_LOCAL);
  BAD("#a", "&a", RENAME_NAME_NEW_LOCAL);
  assert_int_not_equal(rename_check_names("&a", "#a", CHANNELLEN, 0), RENAME_NAME_OK);
  assert_int_not_equal(rename_check_names("#a", "&a", CHANNELLEN, 0), RENAME_NAME_OK);
}

static void names_first_broken_rule_wins(void **state)
{
  char name[CHANNELLEN + 8];
  (void)state;

  /* local beats bad characters */
  BAD("#a", "&a,b", RENAME_NAME_NEW_LOCAL);
  /* bad characters beat length */
  memset(name, 'x', sizeof(name));
  name[0] = '#';
  name[5] = ',';
  name[sizeof(name) - 1] = '\0';
  BAD("#a", name, RENAME_NAME_NEW_BAD_CHARS);
}

static void names_every_error_has_its_own_text(void **state)
{
  enum RenameNameError all[] = {
    RENAME_NAME_OLD_NOT_CHANNEL, RENAME_NAME_OLD_LOCAL,
    RENAME_NAME_NEW_NOT_CHANNEL, RENAME_NAME_NEW_LOCAL,
    RENAME_NAME_NEW_BAD_CHARS, RENAME_NAME_NEW_BAD_UTF8,
    RENAME_NAME_NEW_TOO_LONG, RENAME_NAME_PREFIX_MISMATCH
  };
  size_t i, j, count = sizeof(all) / sizeof(all[0]);
  (void)state;

  for (i = 0; i < count; i++) {
    const char *text = rename_name_error_text(all[i]);
    assert_non_null(text);
    assert_true(strlen(text) > 0);
    /* a FAIL description is one trailing parameter */
    assert_null(strchr(text, '\n'));
    assert_null(strchr(text, '\r'));
    for (j = 0; j < i; j++)
      assert_string_not_equal(text, rename_name_error_text(all[j]));
  }
  assert_non_null(rename_name_error_text(RENAME_NAME_OK));
  assert_non_null(rename_name_error_text((enum RenameNameError)999));
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
    cmocka_unit_test(names_plain_rename_is_fine),
    cmocka_unit_test(names_local_channels_are_refused_on_either_side),
    cmocka_unit_test(names_without_a_channel_prefix),
    cmocka_unit_test(names_comma),
    cmocka_unit_test(names_control_characters_and_space),
    cmocka_unit_test(names_nbsp_byte),
    cmocka_unit_test(names_length_cap),
    cmocka_unit_test(names_utf8_only_when_asked),
    cmocka_unit_test(names_mixed_prefix),
    cmocka_unit_test(names_first_broken_rule_wins),
    cmocka_unit_test(names_every_error_has_its_own_text),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
