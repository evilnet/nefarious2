/*
 * ircd_match_cmocka.c - CMocka unit tests for IRC glob/wildcard matching
 *
 * Tests the match() function which implements IRC-style wildcard matching.
 * NOTE: match() returns 0 on match, non-zero on no match (inverted from
 * typical boolean conventions).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "match.h"

/*
 * Helper macros to make tests more readable.
 * Remember: match() returns 0 on success, so we invert the logic.
 */
#define ASSERT_MATCHES(glob, str) \
    assert_int_equal(0, match((glob), (str)))

#define ASSERT_NO_MATCH(glob, str) \
    assert_int_not_equal(0, match((glob), (str)))


/* ========== Basic Literal Matching ========== */

static void test_exact_match(void **state)
{
    (void)state;

    ASSERT_MATCHES("abc", "abc");
    ASSERT_MATCHES("hello", "hello");
    ASSERT_MATCHES("test123", "test123");
    ASSERT_MATCHES("", "");  /* Empty strings match */
}

static void test_exact_no_match(void **state)
{
    (void)state;

    ASSERT_NO_MATCH("abc", "abcd");
    ASSERT_NO_MATCH("abcd", "abc");
    ASSERT_NO_MATCH("hello", "world");
    /* IRC matching is case-insensitive */
    ASSERT_MATCHES("abc", "ABC");
    ASSERT_MATCHES("Hello", "hELLO");
}


/* ========== Single Character Wildcard (?) ========== */

static void test_question_mark_basic(void **state)
{
    (void)state;

    /* ? matches exactly one character */
    ASSERT_MATCHES("?", "a");
    ASSERT_MATCHES("?", "x");
    ASSERT_MATCHES("?", "*");  /* ? matches literal * */
    ASSERT_MATCHES("?", "?");  /* ? matches literal ? */
}

static void test_question_mark_no_match(void **state)
{
    (void)state;

    /* ? must match exactly one character */
    ASSERT_NO_MATCH("?", "");       /* Empty string - no char to match */
    ASSERT_NO_MATCH("?", "ab");     /* Too many characters */
    ASSERT_NO_MATCH("?", "abc");
}

static void test_question_mark_in_pattern(void **state)
{
    (void)state;

    ASSERT_MATCHES("a?c", "abc");
    ASSERT_MATCHES("a?c", "aXc");
    ASSERT_MATCHES("???", "abc");
    ASSERT_MATCHES("h?llo", "hello");
    ASSERT_MATCHES("h?llo", "hallo");

    ASSERT_NO_MATCH("a?c", "ac");   /* Missing character */
    ASSERT_NO_MATCH("a?c", "abbc"); /* Too many characters */
}


/* ========== Multi-Character Wildcard (*) ========== */

static void test_asterisk_basic(void **state)
{
    (void)state;

    /* * matches zero or more characters */
    ASSERT_MATCHES("*", "");
    ASSERT_MATCHES("*", "a");
    ASSERT_MATCHES("*", "anything");
    ASSERT_MATCHES("*", "literally anything at all");
}

static void test_asterisk_prefix(void **state)
{
    (void)state;

    ASSERT_MATCHES("*abc", "abc");
    ASSERT_MATCHES("*abc", "xyzabc");
    ASSERT_MATCHES("*abc", "123abc");

    ASSERT_NO_MATCH("*abc", "abcd");
    ASSERT_NO_MATCH("*abc", "ab");
}

static void test_asterisk_suffix(void **state)
{
    (void)state;

    ASSERT_MATCHES("abc*", "abc");
    ASSERT_MATCHES("abc*", "abcdef");
    ASSERT_MATCHES("abc*", "abc123");

    ASSERT_NO_MATCH("abc*", "ab");
    ASSERT_NO_MATCH("abc*", "xabc");
}

static void test_asterisk_middle(void **state)
{
    (void)state;

    ASSERT_MATCHES("a*c", "ac");
    ASSERT_MATCHES("a*c", "abc");
    ASSERT_MATCHES("a*c", "aXXXXXc");

    ASSERT_NO_MATCH("a*c", "ab");
    ASSERT_NO_MATCH("a*c", "acd");
}

static void test_asterisk_multiple(void **state)
{
    (void)state;

    ASSERT_MATCHES("*a*", "a");
    ASSERT_MATCHES("*a*", "abc");
    ASSERT_MATCHES("*a*", "xax");
    ASSERT_MATCHES("*a*", "xxaxx");

    ASSERT_NO_MATCH("*a*", "b");
    ASSERT_NO_MATCH("*a*", "xyz");
}


/* ========== Escape Sequences ========== */

static void test_escaped_asterisk(void **state)
{
    (void)state;

    /* \* matches literal asterisk */
    ASSERT_MATCHES("\\*", "*");
    ASSERT_NO_MATCH("\\*", "a");
    ASSERT_NO_MATCH("\\*", "\\*");  /* Should not match backslash-asterisk */
}

static void test_escaped_question_mark(void **state)
{
    (void)state;

    /* \? matches literal question mark */
    ASSERT_MATCHES("\\?", "?");
    ASSERT_NO_MATCH("\\?", "a");
    ASSERT_NO_MATCH("\\?", "\\?");
}

static void test_escaped_backslash(void **state)
{
    (void)state;

    /* \\ matches literal backslash */
    ASSERT_MATCHES("\\\\", "\\");
    ASSERT_NO_MATCH("\\\\", "\\\\");
}


/* ========== IRC-Specific Patterns ========== */

static void test_irc_hostmask_patterns(void **state)
{
    (void)state;

    /* nick!user@host patterns */
    ASSERT_MATCHES("*!*@*", "nick!user@host.com");
    ASSERT_MATCHES("nick!*@*", "nick!user@host.com");
    ASSERT_MATCHES("*!user@*", "nick!user@host.com");
    ASSERT_MATCHES("*!*@*.com", "nick!user@host.com");

    ASSERT_NO_MATCH("*!*@*", "nick@host");  /* Missing ! */
    ASSERT_NO_MATCH("other!*@*", "nick!user@host");
}

static void test_irc_channel_patterns(void **state)
{
    (void)state;

    ASSERT_MATCHES("#*", "#channel");
    ASSERT_MATCHES("#test*", "#testing");
    ASSERT_MATCHES("#*chat*", "#superchat");
    ASSERT_MATCHES("&*", "&localchan");

    ASSERT_NO_MATCH("#*", "channel");  /* Missing # */
}


/* ========== Edge Cases ========== */

static void test_consecutive_wildcards(void **state)
{
    (void)state;

    /* Multiple consecutive wildcards should work */
    ASSERT_MATCHES("**", "anything");
    ASSERT_MATCHES("***", "anything");
    ASSERT_MATCHES("*?*", "a");
    ASSERT_MATCHES("*?*", "abc");
    ASSERT_MATCHES("??*", "ab");
    ASSERT_MATCHES("??*", "abc");

    ASSERT_NO_MATCH("??*", "a");  /* Need at least 2 chars */
}

static void test_complex_patterns(void **state)
{
    (void)state;

    /* Complex real-world patterns */
    ASSERT_MATCHES("*\\\\[*!~*", "har\\[dy!~boy");
    ASSERT_NO_MATCH("*\\\\[*!~*", "dark\\s|de!pimp");
    ASSERT_NO_MATCH("*\\\\[*!~*", "joe\\[mama");
}


/* ========== mmatch() - Mask matching ========== */

static void test_mmatch_basic(void **state)
{
    (void)state;

    /* mmatch compares two masks - returns 0 if old_mask encompasses new_mask */
    assert_int_equal(0, mmatch("*", "anything"));
    assert_int_equal(0, mmatch("*!*@*", "*!*@*.com"));
    assert_int_equal(0, mmatch("*!*@*.com", "*!*@host.com"));

    /* These should NOT match (new is broader than old) */
    assert_int_not_equal(0, mmatch("*!*@*.com", "*!*@*"));
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* Basic literal matching */
        cmocka_unit_test(test_exact_match),
        cmocka_unit_test(test_exact_no_match),

        /* Single character wildcard */
        cmocka_unit_test(test_question_mark_basic),
        cmocka_unit_test(test_question_mark_no_match),
        cmocka_unit_test(test_question_mark_in_pattern),

        /* Multi-character wildcard */
        cmocka_unit_test(test_asterisk_basic),
        cmocka_unit_test(test_asterisk_prefix),
        cmocka_unit_test(test_asterisk_suffix),
        cmocka_unit_test(test_asterisk_middle),
        cmocka_unit_test(test_asterisk_multiple),

        /* Escape sequences */
        cmocka_unit_test(test_escaped_asterisk),
        cmocka_unit_test(test_escaped_question_mark),
        cmocka_unit_test(test_escaped_backslash),

        /* IRC-specific patterns */
        cmocka_unit_test(test_irc_hostmask_patterns),
        cmocka_unit_test(test_irc_channel_patterns),

        /* Edge cases */
        cmocka_unit_test(test_consecutive_wildcards),
        cmocka_unit_test(test_complex_patterns),

        /* mmatch */
        cmocka_unit_test(test_mmatch_basic),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
