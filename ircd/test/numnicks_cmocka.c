/*
 * numnicks_cmocka.c - CMocka unit tests for numeric nick/base64 functions
 *
 * Tests the base64 encoding/decoding used for server-to-server communication.
 * IRC uses a custom base64 alphabet for encoding client/server numerics.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <netinet/in.h>

#include "numnicks.h"
#include "res.h"


/* ========== base64toint ========== */

static void test_base64toint_single_char(void **state)
{
    (void)state;

    /* IRC base64 alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[] */
    assert_int_equal(0, base64toint("A"));
    assert_int_equal(1, base64toint("B"));
    assert_int_equal(25, base64toint("Z"));
    assert_int_equal(26, base64toint("a"));
    assert_int_equal(51, base64toint("z"));
    assert_int_equal(52, base64toint("0"));
    assert_int_equal(61, base64toint("9"));
    assert_int_equal(62, base64toint("["));
    assert_int_equal(63, base64toint("]"));
}

static void test_base64toint_multi_char(void **state)
{
    (void)state;

    /* Two character values */
    assert_int_equal(64, base64toint("BA"));  /* 1*64 + 0 */
    assert_int_equal(65, base64toint("BB"));  /* 1*64 + 1 */
    assert_int_equal(128, base64toint("CA")); /* 2*64 + 0 */

    /* Three character values (server numerics) */
    assert_int_equal(0, base64toint("AAA"));
    assert_int_equal(1, base64toint("AAB"));
    assert_int_equal(64, base64toint("ABA"));
    assert_int_equal(4095, base64toint("]]"));  /* Max 2-char value */
}

static void test_base64toint_server_numerics(void **state)
{
    (void)state;

    /* Typical server numeric patterns */
    /* Server numerics are usually 2 chars (YY) */
    unsigned int val;

    val = base64toint("AB");
    assert_int_equal(1, val);

    val = base64toint("Bj");
    assert_true(val > 0 && val < 4096);  /* Valid range for 2-char */
}


/* ========== inttobase64 ========== */

static void test_inttobase64_single_digit(void **state)
{
    (void)state;
    char buf[16];

    /* Single digit values with count=1 */
    inttobase64(buf, 0, 1);
    assert_string_equal(buf, "A");

    inttobase64(buf, 1, 1);
    assert_string_equal(buf, "B");

    inttobase64(buf, 63, 1);
    assert_string_equal(buf, "]");
}

static void test_inttobase64_two_digits(void **state)
{
    (void)state;
    char buf[16];

    /* Two digit values */
    inttobase64(buf, 0, 2);
    assert_string_equal(buf, "AA");

    inttobase64(buf, 1, 2);
    assert_string_equal(buf, "AB");

    inttobase64(buf, 64, 2);
    assert_string_equal(buf, "BA");

    inttobase64(buf, 4095, 2);
    assert_string_equal(buf, "]]");  /* Max 2-digit */
}

static void test_inttobase64_three_digits(void **state)
{
    (void)state;
    char buf[16];

    /* Three digit values (client numerics) */
    inttobase64(buf, 0, 3);
    assert_string_equal(buf, "AAA");

    inttobase64(buf, 1, 3);
    assert_string_equal(buf, "AAB");

    inttobase64(buf, 262143, 3);
    assert_string_equal(buf, "]]]");  /* Max 3-digit: 64^3 - 1 */
}


/* ========== Round-trip tests ========== */

static void test_base64_roundtrip(void **state)
{
    (void)state;
    char buf[16];
    unsigned int original, decoded;

    /* Test various values for round-trip consistency */
    unsigned int test_values[] = { 0, 1, 63, 64, 100, 1000, 4095, 10000, 100000, 262143 };

    for (size_t i = 0; i < sizeof(test_values)/sizeof(test_values[0]); i++) {
        original = test_values[i];

        /* Determine count based on value */
        int count = (original < 64) ? 1 : (original < 4096) ? 2 : 3;

        inttobase64(buf, original, count);
        decoded = base64toint(buf);

        assert_int_equal(original, decoded);
    }
}


/* ========== iptobase64 / base64toip ========== */

static void test_iptobase64_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char buf[32];

    /* Create an IPv4-mapped IPv6 address for 127.0.0.1 */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[5] = htons(0xffff);  /* IPv4-mapped prefix */
    addr.in6_16[6] = htons(0x7f00);  /* 127.0 */
    addr.in6_16[7] = htons(0x0001);  /* 0.1 */

    /* v4-only encoding (6 chars) */
    iptobase64(buf, &addr, sizeof(buf), 0);
    assert_int_equal(strlen(buf), 6);

    /* The result should be decodable */
    struct irc_in_addr decoded;
    base64toip(buf, &decoded);

    /* Last 4 bytes (IPv4) should match */
    assert_int_equal(addr.in6_16[6], decoded.in6_16[6]);
    assert_int_equal(addr.in6_16[7], decoded.in6_16[7]);
}

static void test_iptobase64_ipv6(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char buf[32];

    /* Create an IPv6 address ::1 */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[7] = htons(1);

    /* v6 encoding */
    iptobase64(buf, &addr, sizeof(buf), 1);

    /* Should produce valid base64 output */
    assert_true(strlen(buf) > 0);
}

static void test_ip_base64_roundtrip(void **state)
{
    (void)state;
    struct irc_in_addr original, decoded;
    char buf[32];

    /* Test with 127.0.0.1 (IPv4-mapped) */
    memset(&original, 0, sizeof(original));
    original.in6_16[5] = htons(0xffff);
    original.in6_16[6] = htons(0x7f00);
    original.in6_16[7] = htons(0x0001);

    iptobase64(buf, &original, sizeof(buf), 0);
    base64toip(buf, &decoded);

    /* IPv4 portion should match */
    assert_int_equal(original.in6_16[6], decoded.in6_16[6]);
    assert_int_equal(original.in6_16[7], decoded.in6_16[7]);
}


/* ========== Edge cases ========== */

static void test_base64_empty_string(void **state)
{
    (void)state;

    /* Empty string should return 0 */
    assert_int_equal(0, base64toint(""));
}

static void test_base64_max_values(void **state)
{
    (void)state;
    char buf[16];

    /* Test maximum values for each digit count */
    inttobase64(buf, 63, 1);
    assert_int_equal(63, base64toint(buf));

    inttobase64(buf, 4095, 2);
    assert_int_equal(4095, base64toint(buf));

    inttobase64(buf, 262143, 3);
    assert_int_equal(262143, base64toint(buf));
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* base64toint */
        cmocka_unit_test(test_base64toint_single_char),
        cmocka_unit_test(test_base64toint_multi_char),
        cmocka_unit_test(test_base64toint_server_numerics),

        /* inttobase64 */
        cmocka_unit_test(test_inttobase64_single_digit),
        cmocka_unit_test(test_inttobase64_two_digits),
        cmocka_unit_test(test_inttobase64_three_digits),

        /* Round-trip */
        cmocka_unit_test(test_base64_roundtrip),

        /* IP address encoding */
        cmocka_unit_test(test_iptobase64_ipv4),
        cmocka_unit_test(test_iptobase64_ipv6),
        cmocka_unit_test(test_ip_base64_roundtrip),

        /* Edge cases */
        cmocka_unit_test(test_base64_empty_string),
        cmocka_unit_test(test_base64_max_values),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
