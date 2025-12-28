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

    /* Source longer than dest - should truncate */
    ircd_strncpy(dest, "hello world", sizeof(dest) - 1);
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

    assert_true(EmptyString(NULL));
    assert_true(EmptyString(""));
    assert_false(EmptyString("x"));
    assert_false(EmptyString("hello"));
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

static void test_is_timestamp(void **state)
{
    (void)state;

    /* Valid timestamps (all digits) */
    assert_true(is_timestamp("1234567890"));
    assert_true(is_timestamp("0"));
    assert_true(is_timestamp("999999999"));

    /* Invalid timestamps */
    assert_false(is_timestamp("abc"));
    assert_false(is_timestamp("123abc"));
    assert_false(is_timestamp(""));
    assert_false(is_timestamp("-123"));
}


/* ========== valid_username ========== */

static void test_valid_username(void **state)
{
    (void)state;

    /* Valid usernames */
    assert_true(valid_username("user"));
    assert_true(valid_username("user123"));
    assert_true(valid_username("a"));

    /* Invalid usernames */
    assert_false(valid_username(""));
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

static void test_strIsDigit(void **state)
{
    (void)state;

    assert_true(strIsDigit("12345"));
    assert_true(strIsDigit("0"));
    assert_true(strIsDigit("999"));

    assert_false(strIsDigit("12a45"));
    assert_false(strIsDigit("hello"));
    /* Note: empty string behavior may vary */
}

static void test_strIsAlpha(void **state)
{
    (void)state;

    assert_true(strIsAlpha("hello"));
    assert_true(strIsAlpha("HELLO"));
    assert_true(strIsAlpha("HeLLo"));

    assert_false(strIsAlpha("hello123"));
    assert_false(strIsAlpha("hello world"));
}

static void test_strIsAlnum(void **state)
{
    (void)state;

    assert_true(strIsAlnum("hello123"));
    assert_true(strIsAlnum("abc"));
    assert_true(strIsAlnum("123"));

    assert_false(strIsAlnum("hello!"));
    assert_false(strIsAlnum("hello world"));
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

        /* String character classification */
        cmocka_unit_test(test_strIsDigit),
        cmocka_unit_test(test_strIsAlpha),
        cmocka_unit_test(test_strIsAlnum),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
