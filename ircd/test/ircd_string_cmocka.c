/*
 * ircd_string_cmocka.c - CMocka unit tests for IRC string utilities
 *
 * Tests various string manipulation functions used throughout the IRC daemon.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "ircd_string.h"
#include "ircd_chattr.h"


/* ========== ircd_strncpy ========== */

static void test_ircd_strncpy_normal(void **state)
{
    (void)state;
    char dest[32];

    /* Normal copy */
    ircd_strncpy(dest, "hello", sizeof(dest));
    assert_string_equal(dest, "hello");

    /* Copy with exact size */
    ircd_strncpy(dest, "world", 6);
    assert_string_equal(dest, "world");
}

static void test_ircd_strncpy_truncation(void **state)
{
    (void)state;
    char dest[8];

    /* Source longer than dest - should truncate.  ircd_strncpy is strlcpy-like:
     * the size arg is the FULL buffer size and it writes at most size-1 chars
     * + NUL, so an 8-byte dest yields a 7-char result. */
    ircd_strncpy(dest, "hello world", sizeof(dest));
    assert_int_equal(strlen(dest), 7);
}

static void test_ircd_strncpy_empty(void **state)
{
    (void)state;
    char dest[32];

    /* Empty string copy */
    ircd_strncpy(dest, "", sizeof(dest));
    assert_string_equal(dest, "");
    assert_int_equal(strlen(dest), 0);
}


/* ========== ircd_strcmp (case-insensitive IRC comparison) ========== */

static void test_ircd_strcmp_equal(void **state)
{
    (void)state;

    /* Same case */
    assert_int_equal(0, ircd_strcmp("hello", "hello"));
    assert_int_equal(0, ircd_strcmp("HELLO", "HELLO"));
    assert_int_equal(0, ircd_strcmp("", ""));

    /* Different case - should still be equal for IRC */
    assert_int_equal(0, ircd_strcmp("hello", "HELLO"));
    assert_int_equal(0, ircd_strcmp("HeLLo", "hElLO"));
    assert_int_equal(0, ircd_strcmp("Nick123", "NICK123"));
}

static void test_ircd_strcmp_not_equal(void **state)
{
    (void)state;

    assert_int_not_equal(0, ircd_strcmp("hello", "world"));
    assert_int_not_equal(0, ircd_strcmp("abc", "abcd"));
    assert_int_not_equal(0, ircd_strcmp("abcd", "abc"));
    assert_int_not_equal(0, ircd_strcmp("", "x"));
}

static void test_ircd_strcmp_irc_special_chars(void **state)
{
    (void)state;

    /* IRC treats {}|^ as lowercase of []\~ */
    /* These should be considered equal */
    assert_int_equal(0, ircd_strcmp("[", "{"));
    assert_int_equal(0, ircd_strcmp("]", "}"));
    assert_int_equal(0, ircd_strcmp("\\", "|"));
    assert_int_equal(0, ircd_strcmp("~", "^"));

    /* Mixed with regular chars */
    assert_int_equal(0, ircd_strcmp("nick[away]", "nick{away}"));
}


/* ========== ircd_strncmp ========== */

static void test_ircd_strncmp_basic(void **state)
{
    (void)state;

    /* Compare first n characters */
    assert_int_equal(0, ircd_strncmp("hello", "hello world", 5));
    assert_int_equal(0, ircd_strncmp("HELLO", "hello", 5));
    assert_int_equal(0, ircd_strncmp("abcdef", "abcxyz", 3));

    assert_int_not_equal(0, ircd_strncmp("abcdef", "abcxyz", 4));
}


/* ========== unique_name_vector ========== */

static void test_unique_name_vector_basic(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Basic comma-separated list */
    names = strdup("a,b,c");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 3);
    assert_string_equal(vector[0], "a");
    assert_string_equal(vector[1], "b");
    assert_string_equal(vector[2], "c");
    free(names);
}

static void test_unique_name_vector_duplicates(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Duplicates should be removed (case-insensitive) */
    names = strdup("a,b,a,c,B,C");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 3);  /* Only a, b, c should remain */
    free(names);
}

static void test_unique_name_vector_empty_elements(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Empty elements should be skipped */
    names = strdup(",,,a,,b,,");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 2);
    free(names);
}

static void test_unique_name_vector_single(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Single element */
    names = strdup("foo");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 1);
    assert_string_equal(vector[0], "foo");
    free(names);
}

static void test_unique_name_vector_empty(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Empty string */
    names = strdup("");
    count = unique_name_vector(names, ',', vector, 20);
    assert_int_equal(count, 0);
    free(names);
}

static void test_unique_name_vector_limit(void **state)
{
    (void)state;
    char *vector[5];
    char *names;
    int count;

    /* More elements than vector can hold */
    names = strdup("a,b,c,d,e,f,g,h");
    count = unique_name_vector(names, ',', vector, 5);
    assert_true(count <= 5);  /* Should not exceed limit */
    free(names);
}


/* ========== token_vector ========== */

static void test_token_vector_basic(void **state)
{
    (void)state;
    char *vector[20];
    char *names;
    int count;

    /* Unlike unique_name_vector, keeps duplicates and empty elements */
    names = strdup("a,b,c");
    count = token_vector(names, ',', vector, 20);
    assert_int_equal(count, 3);
    free(names);
}


/* ========== EmptyString macro ========== */

static void test_EmptyString_macro(void **state)
{
    (void)state;
    const char *null_str = NULL;
    const char *empty_str = "";
    const char *x_str = "x";
    const char *hello_str = "hello";

    /* Use variables to avoid macro expansion issues with assert_true */
    assert_int_not_equal(0, EmptyString(null_str));
    assert_int_not_equal(0, EmptyString(empty_str));
    assert_int_equal(0, EmptyString(x_str));
    assert_int_equal(0, EmptyString(hello_str));
}


/* ========== string_has_wildcards ========== */

static void test_string_has_wildcards(void **state)
{
    (void)state;

    /* Strings with wildcards */
    assert_true(string_has_wildcards("*"));
    assert_true(string_has_wildcards("hello*"));
    assert_true(string_has_wildcards("?"));
    assert_true(string_has_wildcards("a?b"));
    assert_true(string_has_wildcards("*?*"));

    /* Strings without wildcards */
    assert_false(string_has_wildcards("hello"));
    assert_false(string_has_wildcards(""));
    assert_false(string_has_wildcards("test123"));
}


/* ========== ParseInterval ========== */

static void test_ParseInterval_seconds(void **state)
{
    (void)state;

    /* Plain numbers are seconds */
    assert_int_equal(60, ParseInterval("60"));
    assert_int_equal(3600, ParseInterval("3600"));
    assert_int_equal(0, ParseInterval("0"));
}

static void test_ParseInterval_with_units(void **state)
{
    (void)state;

    /* Minutes */
    assert_int_equal(60, ParseInterval("1m"));
    assert_int_equal(300, ParseInterval("5m"));

    /* Hours */
    assert_int_equal(3600, ParseInterval("1h"));
    assert_int_equal(7200, ParseInterval("2h"));

    /* Days */
    assert_int_equal(86400, ParseInterval("1d"));
    assert_int_equal(172800, ParseInterval("2d"));

    /* Weeks */
    assert_int_equal(604800, ParseInterval("1w"));
}

static void test_ParseInterval_combined(void **state)
{
    (void)state;

    /* Combined intervals */
    assert_int_equal(3661, ParseInterval("1h1m1"));  /* 1 hour + 1 min + 1 sec */
    assert_int_equal(90061, ParseInterval("1d1h1m1")); /* 1 day + 1 hour + 1 min + 1 sec */
}


/* ========== is_timestamp ========== */

/* Test is_timestamp - checks if string contains only digits (and dots).
 * Note: ircu implementation returns true for empty string because the loop
 * "while (IsDigit(*str)) ++str" immediately hits NUL, then "*str == '\0'"
 * returns true. This is vacuous truth - callers should check for empty first
 * if that matters. This is historical ircu behavior preserved in nefarious. */
static void test_is_timestamp(void **state)
{
    (void)state;

    /* Valid timestamps (all digits) */
    assert_true(is_timestamp("1234567890"));
    assert_true(is_timestamp("0"));
    assert_true(is_timestamp("999999999"));

    /* Empty string: ircu returns true (vacuously valid - no invalid chars) */
    assert_true(is_timestamp(""));

    /* Invalid timestamps */
    assert_false(is_timestamp("abc"));
    assert_false(is_timestamp("123abc"));
    assert_false(is_timestamp("-123"));
}


/* ========== valid_username ========== */

/* Test valid_username - checks if all chars are valid user ID chars.
 * Note: ircu implementation returns true for empty string because the loop
 * "for (c = name; *c; c++)" never executes, so it returns 1. This is vacuous
 * truth - callers should check for empty first if that matters.
 * Compare to valid_hostname() which explicitly rejects empty strings.
 * This is historical ircu behavior preserved in nefarious. */
static void test_valid_username(void **state)
{
    (void)state;

    /* Valid usernames */
    assert_true(valid_username("user"));
    assert_true(valid_username("user123"));
    assert_true(valid_username("a"));

    /* Empty string: ircu returns true (vacuously valid - no invalid chars) */
    assert_true(valid_username(""));

    /* Invalid usernames */
    assert_false(valid_username("user name"));  /* No spaces */
}


/* ========== valid_hostname ========== */

static void test_valid_hostname(void **state)
{
    (void)state;

    /* Valid hostnames */
    assert_true(valid_hostname("example.com"));
    assert_true(valid_hostname("irc.example.org"));
    assert_true(valid_hostname("host-name.domain.tld"));
    assert_true(valid_hostname("localhost"));

    /* Invalid hostnames */
    assert_false(valid_hostname(""));
    assert_false(valid_hostname("host name.com"));  /* No spaces */
}


/* ========== Character classification string functions ========== */
/* NOTE: strIsDigit/strIsAlpha/strIsAlnum tests removed because strChattr()
 * is conditionally compiled with FORCEINLINE and difficult to link in tests.
 * The underlying character classification is tested in ircd_chattr_cmocka.c */


/* ========== str_appendf ========== */

static void test_str_appendf_basic(void **state)
{
    (void)state;
    char buf[16];
    size_t pos = 0;
    buf[0] = '\0';
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "%s", "ab"), 2);
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "%d", 34), 2);
    assert_string_equal(buf, "ab34");
    assert_int_equal((int)pos, 4);
}

static void test_str_appendf_clamps_at_buffer_end(void **state)
{
    (void)state;
    char buf[8];              /* 7 usable + NUL */
    size_t pos = 0;
    buf[0] = '\0';
    /* would-be 11 chars, but only 7 fit; pos must clamp to 7, not 11 */
    str_appendf(buf, sizeof(buf), &pos, "%s", "hello world");
    assert_true(pos <= sizeof(buf) - 1);
    assert_int_equal(buf[sizeof(buf) - 1], '\0');
    /* a further append must be a safe no-op, never writing past the buffer */
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "%s", "XYZ"), 0);
    assert_true(pos <= sizeof(buf) - 1);
}

static void test_str_appendf_noop_when_pos_at_end(void **state)
{
    (void)state;
    char buf[4] = "abc";
    size_t pos = 3;
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "z"), 0);
    assert_string_equal(buf, "abc");
    assert_int_equal((int)pos, 3);
}

static void test_str_appendf_guard_pos_at_or_past_buflen(void **state)
{
    (void)state;
    char buf[8] = "abcdefg";        /* full: 7 chars + NUL */
    size_t pos = sizeof(buf);       /* pos == buflen: initial guard must no-op */
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "X"), 0);
    assert_int_equal((int)pos, (int)sizeof(buf));
    assert_string_equal(buf, "abcdefg");

    pos = sizeof(buf) + 5;          /* pos > buflen: still a safe no-op */
    assert_int_equal(str_appendf(buf, sizeof(buf), &pos, "X"), 0);
    assert_string_equal(buf, "abcdefg");
}


/* ========== csv_contains_token ========== */

static void test_csv_contains_token_empty_denies(void **state)
{
    (void)state;
    assert_int_equal(csv_contains_token(NULL, "svc"), 0);
    assert_int_equal(csv_contains_token("", "svc"), 0);
}

static void test_csv_contains_token_match_and_case(void **state)
{
    (void)state;
    assert_int_equal(csv_contains_token("bnc,svc,relay", "svc"), 1);
    assert_int_equal(csv_contains_token("bnc,svc,relay", "SVC"), 1); /* ci */
    assert_int_equal(csv_contains_token("bnc svc relay", "relay"), 1); /* space-sep */
    assert_int_equal(csv_contains_token("bnc,svc", "mallory"), 0);
    assert_int_equal(csv_contains_token("bnc,svc", "sv"), 0);       /* no prefix match */
}


/* --- ircd_utf8_clamp --- */

static void test_utf8_clamp_fits_untouched(void **state)
{
  char buf[32] = "hello";
  (void)state;
  assert_int_equal(0, ircd_utf8_clamp(buf, 10));
  assert_string_equal(buf, "hello");
  assert_int_equal(0, ircd_utf8_clamp(buf, 5)); /* exact fit */
  assert_string_equal(buf, "hello");
}

static void test_utf8_clamp_ascii_cut(void **state)
{
  char buf[32] = "hello world";
  (void)state;
  assert_int_equal(1, ircd_utf8_clamp(buf, 5));
  assert_string_equal(buf, "hello");
}

static void test_utf8_clamp_multibyte_boundary(void **state)
{
  /* "aX" where X = 2-byte U+00E9 (0xC3 0xA9).  Cutting at 2 lands on
   * the continuation byte -> whole sequence dropped. */
  char buf[8] = "a\303\251";
  (void)state;
  assert_int_equal(1, ircd_utf8_clamp(buf, 2));
  assert_string_equal(buf, "a");
}

static void test_utf8_clamp_keeps_complete_sequence(void **state)
{
  /* Cutting exactly after the full 2-byte sequence keeps it. */
  char buf[8] = "a\303\251b";
  (void)state;
  assert_int_equal(1, ircd_utf8_clamp(buf, 3));
  assert_string_equal(buf, "a\303\251");
}

static void test_utf8_clamp_null_safe(void **state)
{
  (void)state;
  assert_int_equal(0, ircd_utf8_clamp(NULL, 5));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        /* ircd_strncpy */
        cmocka_unit_test(test_ircd_strncpy_normal),
        cmocka_unit_test(test_ircd_strncpy_truncation),
        cmocka_unit_test(test_ircd_strncpy_empty),

        /* ircd_strcmp */
        cmocka_unit_test(test_ircd_strcmp_equal),
        cmocka_unit_test(test_ircd_strcmp_not_equal),
        cmocka_unit_test(test_ircd_strcmp_irc_special_chars),

        /* ircd_strncmp */
        cmocka_unit_test(test_ircd_strncmp_basic),

        /* unique_name_vector */
        cmocka_unit_test(test_unique_name_vector_basic),
        cmocka_unit_test(test_unique_name_vector_duplicates),
        cmocka_unit_test(test_unique_name_vector_empty_elements),
        cmocka_unit_test(test_unique_name_vector_single),
        cmocka_unit_test(test_unique_name_vector_empty),
        cmocka_unit_test(test_unique_name_vector_limit),

        /* token_vector */
        cmocka_unit_test(test_token_vector_basic),

        /* EmptyString */
        cmocka_unit_test(test_EmptyString_macro),

        /* Wildcard detection */
        cmocka_unit_test(test_string_has_wildcards),

        /* Interval parsing */
        cmocka_unit_test(test_ParseInterval_seconds),
        cmocka_unit_test(test_ParseInterval_with_units),
        cmocka_unit_test(test_ParseInterval_combined),

        /* Timestamp validation */
        cmocka_unit_test(test_is_timestamp),

        /* Username/hostname validation */
        cmocka_unit_test(test_valid_username),
        cmocka_unit_test(test_valid_hostname),

        /* str_appendf */
        cmocka_unit_test(test_str_appendf_basic),
        cmocka_unit_test(test_str_appendf_clamps_at_buffer_end),
        cmocka_unit_test(test_str_appendf_noop_when_pos_at_end),
        cmocka_unit_test(test_str_appendf_guard_pos_at_or_past_buflen),

        /* csv_contains_token */
        cmocka_unit_test(test_csv_contains_token_empty_denies),
        cmocka_unit_test(test_csv_contains_token_match_and_case),

        /* ircd_utf8_clamp */
        cmocka_unit_test(test_utf8_clamp_fits_untouched),
        cmocka_unit_test(test_utf8_clamp_ascii_cut),
        cmocka_unit_test(test_utf8_clamp_multibyte_boundary),
        cmocka_unit_test(test_utf8_clamp_keeps_complete_sequence),
        cmocka_unit_test(test_utf8_clamp_null_safe),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
