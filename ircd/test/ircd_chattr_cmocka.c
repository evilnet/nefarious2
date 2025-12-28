/*
 * ircd_chattr_cmocka.c - CMocka unit tests for character attributes
 *
 * This demonstrates CMocka-style testing for nefarious IRCd.
 * Unlike the original ircd_chattr_t.c which just prints output,
 * these tests have proper assertions.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "ircd_chattr.h"

/* Test that digits 0-9 are recognized as digits */
static void test_IsDigit(void **state)
{
    (void)state;

    /* All digits should pass */
    assert_true(IsDigit('0'));
    assert_true(IsDigit('5'));
    assert_true(IsDigit('9'));

    /* Letters should not be digits */
    assert_false(IsDigit('a'));
    assert_false(IsDigit('Z'));

    /* Special chars should not be digits */
    assert_false(IsDigit(' '));
    assert_false(IsDigit('#'));
    assert_false(IsDigit('\0'));
}

/* Test alpha character classification */
static void test_IsAlpha(void **state)
{
    (void)state;

    /* Lowercase letters */
    assert_true(IsAlpha('a'));
    assert_true(IsAlpha('m'));
    assert_true(IsAlpha('z'));

    /* Uppercase letters */
    assert_true(IsAlpha('A'));
    assert_true(IsAlpha('M'));
    assert_true(IsAlpha('Z'));

    /* Non-alpha */
    assert_false(IsAlpha('0'));
    assert_false(IsAlpha(' '));
    assert_false(IsAlpha('#'));
}

/* Test alphanumeric classification */
static void test_IsAlnum(void **state)
{
    (void)state;

    /* Alpha */
    assert_true(IsAlnum('a'));
    assert_true(IsAlnum('Z'));

    /* Numeric */
    assert_true(IsAlnum('0'));
    assert_true(IsAlnum('9'));

    /* Non-alnum */
    assert_false(IsAlnum(' '));
    assert_false(IsAlnum('#'));
    assert_false(IsAlnum('\n'));
}

/* Test channel prefix characters */
static void test_IsChannelPrefix(void **state)
{
    (void)state;

    /* Valid channel prefixes */
    assert_true(IsChannelPrefix('#'));
    assert_true(IsChannelPrefix('&'));

    /* Invalid channel prefixes */
    assert_false(IsChannelPrefix('!'));  /* Not supported in nefarious */
    assert_false(IsChannelPrefix('+'));  /* Modeless channels not default */
    assert_false(IsChannelPrefix('a'));
    assert_false(IsChannelPrefix('1'));
}

/* Test valid nickname characters */
static void test_IsNickChar(void **state)
{
    (void)state;

    /* Letters are valid */
    assert_true(IsNickChar('a'));
    assert_true(IsNickChar('Z'));

    /* Digits are valid */
    assert_true(IsNickChar('0'));
    assert_true(IsNickChar('9'));

    /* Special nick chars */
    assert_true(IsNickChar('['));
    assert_true(IsNickChar(']'));
    assert_true(IsNickChar('\\'));
    assert_true(IsNickChar('`'));
    assert_true(IsNickChar('^'));
    assert_true(IsNickChar('{'));
    assert_true(IsNickChar('}'));
    assert_true(IsNickChar('|'));
    assert_true(IsNickChar('-'));
    assert_true(IsNickChar('_'));

    /* Invalid nick chars */
    assert_false(IsNickChar(' '));
    assert_false(IsNickChar('#'));
    assert_false(IsNickChar('@'));
    assert_false(IsNickChar('!'));
    assert_false(IsNickChar('\0'));
    assert_false(IsNickChar('\n'));
}

/* Test channel name characters (excluding prefix) */
static void test_IsChannelChar(void **state)
{
    (void)state;

    /* Valid channel chars */
    assert_true(IsChannelChar('a'));
    assert_true(IsChannelChar('Z'));
    assert_true(IsChannelChar('0'));
    assert_true(IsChannelChar('-'));
    assert_true(IsChannelChar('_'));

    /* Invalid channel chars */
    assert_false(IsChannelChar(' '));   /* No spaces */
    assert_false(IsChannelChar('\007')); /* No bell */
    assert_false(IsChannelChar(','));   /* No comma (separator) */
    assert_false(IsChannelChar('\0'));  /* No null */
}

/* Test control characters */
static void test_IsCntrl(void **state)
{
    (void)state;

    /* Control characters (0x00-0x1F) */
    assert_true(IsCntrl('\0'));
    assert_true(IsCntrl('\t'));
    assert_true(IsCntrl('\n'));
    assert_true(IsCntrl('\r'));
    assert_true(IsCntrl('\007'));  /* Bell */
    assert_true(IsCntrl(0x1F));

    /* Not control characters */
    assert_false(IsCntrl(' '));
    assert_false(IsCntrl('a'));
    assert_false(IsCntrl('~'));
    assert_false(IsCntrl(0x7F));   /* DEL is not classified as control in IRC */
}

/* Test end-of-line characters */
static void test_IsEol(void **state)
{
    (void)state;

    /* EOL chars - only \n and \r */
    assert_true(IsEol('\n'));
    assert_true(IsEol('\r'));

    /* Not EOL - null is not classified as EOL in IRC */
    assert_false(IsEol('\0'));
    assert_false(IsEol(' '));
    assert_false(IsEol('a'));
    assert_false(IsEol('\t'));
}

/* Test IP address characters - IsIPChar is for IPv4 only (digits and .) */
static void test_IsIPChar(void **state)
{
    (void)state;

    /* Digits for IPv4 */
    assert_true(IsIPChar('0'));
    assert_true(IsIPChar('9'));

    /* Dot for IPv4 */
    assert_true(IsIPChar('.'));

    /* Invalid IPv4 chars - hex letters and colon are for IPv6 (IsIP6Char) */
    assert_false(IsIPChar('A'));
    assert_false(IsIPChar('F'));
    assert_false(IsIPChar(':'));
    assert_false(IsIPChar('a'));
    assert_false(IsIPChar('f'));
    assert_false(IsIPChar('g'));
    assert_false(IsIPChar('z'));
    assert_false(IsIPChar(' '));
    assert_false(IsIPChar('#'));
}

/* Test IPv6 address characters - IsIP6Char includes hex and colon */
static void test_IsIP6Char(void **state)
{
    (void)state;

    /* Digits */
    assert_true(IsIP6Char('0'));
    assert_true(IsIP6Char('9'));

    /* Dot for IPv4-mapped addresses */
    assert_true(IsIP6Char('.'));

    /* Hex digits (upper and lower) */
    assert_true(IsIP6Char('A'));
    assert_true(IsIP6Char('F'));
    assert_true(IsIP6Char('a'));
    assert_true(IsIP6Char('f'));

    /* Colon separator */
    assert_true(IsIP6Char(':'));

    /* Invalid IPv6 chars */
    assert_false(IsIP6Char('G'));
    assert_false(IsIP6Char('g'));
    assert_false(IsIP6Char('z'));
    assert_false(IsIP6Char(' '));
    assert_false(IsIP6Char('#'));
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_IsDigit),
        cmocka_unit_test(test_IsAlpha),
        cmocka_unit_test(test_IsAlnum),
        cmocka_unit_test(test_IsChannelPrefix),
        cmocka_unit_test(test_IsNickChar),
        cmocka_unit_test(test_IsChannelChar),
        cmocka_unit_test(test_IsCntrl),
        cmocka_unit_test(test_IsEol),
        cmocka_unit_test(test_IsIPChar),
        cmocka_unit_test(test_IsIP6Char),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
