/*
 * ircd_in_addr_cmocka.c - CMocka unit tests for IP address handling
 *
 * Tests IPv4 and IPv6 address parsing, formatting, and validation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include <netinet/in.h>

#include "ircd_string.h"
#include "numnicks.h"
#include "res.h"


/* ========== Helper to create IPv4-mapped address ========== */

static void make_ipv4_addr(struct irc_in_addr *addr,
                           unsigned char a, unsigned char b,
                           unsigned char c, unsigned char d)
{
    memset(addr, 0, sizeof(*addr));
    addr->in6_16[5] = htons(0xffff);  /* IPv4-mapped prefix */
    addr->in6_16[6] = htons((a << 8) | b);
    addr->in6_16[7] = htons((c << 8) | d);
}


/* ========== ircd_aton (parse IP address) ========== */

static void test_aton_ipv4_localhost(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    int len;

    len = ircd_aton(&addr, "127.0.0.1");
    assert_int_equal(len, strlen("127.0.0.1"));

    /* Check it's IPv4-mapped */
    assert_int_equal(ntohs(addr.in6_16[5]), 0xffff);
    assert_int_equal(ntohs(addr.in6_16[6]), 0x7f00);
    assert_int_equal(ntohs(addr.in6_16[7]), 0x0001);
}

static void test_aton_ipv4_various(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    int len;

    /* 0.0.0.0 */
    len = ircd_aton(&addr, "0.0.0.0");
    assert_true(len > 0);
    assert_int_equal(ntohs(addr.in6_16[6]), 0x0000);
    assert_int_equal(ntohs(addr.in6_16[7]), 0x0000);

    /* 255.255.255.255 */
    len = ircd_aton(&addr, "255.255.255.255");
    assert_true(len > 0);
    assert_int_equal(ntohs(addr.in6_16[6]), 0xffff);
    assert_int_equal(ntohs(addr.in6_16[7]), 0xffff);

    /* 192.168.1.1 */
    len = ircd_aton(&addr, "192.168.1.1");
    assert_true(len > 0);
    assert_int_equal(ntohs(addr.in6_16[6]), 0xc0a8);
    assert_int_equal(ntohs(addr.in6_16[7]), 0x0101);
}

static void test_aton_ipv6_localhost(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    int len;

    len = ircd_aton(&addr, "::1");
    assert_true(len > 0);

    /* First 7 segments should be 0 */
    for (int i = 0; i < 7; i++) {
        assert_int_equal(addr.in6_16[i], 0);
    }
    /* Last segment is 1 */
    assert_int_equal(ntohs(addr.in6_16[7]), 1);
}

static void test_aton_ipv6_full(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    int len;

    len = ircd_aton(&addr, "2001:db8::1");
    assert_true(len > 0);
    assert_int_equal(ntohs(addr.in6_16[0]), 0x2001);
    assert_int_equal(ntohs(addr.in6_16[1]), 0x0db8);
}

static void test_aton_ipv6_all_segments(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    int len;

    len = ircd_aton(&addr, "1:2:3:4:5:6:7:8");
    assert_true(len > 0);

    assert_int_equal(ntohs(addr.in6_16[0]), 1);
    assert_int_equal(ntohs(addr.in6_16[1]), 2);
    assert_int_equal(ntohs(addr.in6_16[2]), 3);
    assert_int_equal(ntohs(addr.in6_16[3]), 4);
    assert_int_equal(ntohs(addr.in6_16[4]), 5);
    assert_int_equal(ntohs(addr.in6_16[5]), 6);
    assert_int_equal(ntohs(addr.in6_16[6]), 7);
    assert_int_equal(ntohs(addr.in6_16[7]), 8);
}

static void test_aton_ipv4_mapped_ipv6(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    int len;

    /* ::ffff:127.0.0.1 notation */
    len = ircd_aton(&addr, "::ffff:127.0.0.1");
    assert_true(len > 0);
    assert_int_equal(ntohs(addr.in6_16[5]), 0xffff);
    assert_int_equal(ntohs(addr.in6_16[6]), 0x7f00);
    assert_int_equal(ntohs(addr.in6_16[7]), 0x0001);
}


/* ========== ircd_ntoa (format IP address) ========== */

static void test_ntoa_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    const char *result;

    make_ipv4_addr(&addr, 127, 0, 0, 1);
    result = ircd_ntoa(&addr);
    assert_string_equal(result, "127.0.0.1");

    make_ipv4_addr(&addr, 192, 168, 1, 1);
    result = ircd_ntoa(&addr);
    assert_string_equal(result, "192.168.1.1");

    make_ipv4_addr(&addr, 10, 0, 0, 1);
    result = ircd_ntoa(&addr);
    assert_string_equal(result, "10.0.0.1");
}

static void test_ntoa_ipv6(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    const char *result;

    /* ::1 */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[7] = htons(1);
    result = ircd_ntoa(&addr);
    assert_non_null(result);
    /* Should contain ::1 or 0::1 */
    assert_non_null(strstr(result, "1"));
}

static void test_ntoa_r_buffer(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char buf[64];

    make_ipv4_addr(&addr, 8, 8, 8, 8);
    ircd_ntoa_r(buf, &addr);
    assert_string_equal(buf, "8.8.8.8");
}


/* ========== irc_in_addr_is_ipv4 ========== */

static void test_is_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr addr;

    /* IPv4-mapped address */
    make_ipv4_addr(&addr, 192, 168, 1, 1);
    assert_true(irc_in_addr_is_ipv4(&addr));

    /* Pure IPv6 */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[0] = htons(0x2001);
    addr.in6_16[7] = htons(1);
    assert_false(irc_in_addr_is_ipv4(&addr));
}


/* ========== irc_in_addr_is_loopback ========== */

static void test_is_loopback_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr addr;

    /* 127.0.0.1 is loopback */
    make_ipv4_addr(&addr, 127, 0, 0, 1);
    assert_true(irc_in_addr_is_loopback(&addr));

    /* 127.255.255.255 is also loopback (127.0.0.0/8) */
    make_ipv4_addr(&addr, 127, 255, 255, 255);
    assert_true(irc_in_addr_is_loopback(&addr));

    /* 192.168.1.1 is not loopback */
    make_ipv4_addr(&addr, 192, 168, 1, 1);
    assert_false(irc_in_addr_is_loopback(&addr));
}

static void test_is_loopback_ipv6(void **state)
{
    (void)state;
    struct irc_in_addr addr;

    /* ::1 is loopback */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[7] = htons(1);
    assert_true(irc_in_addr_is_loopback(&addr));

    /* 2001:db8::1 is not loopback */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[0] = htons(0x2001);
    addr.in6_16[7] = htons(1);
    assert_false(irc_in_addr_is_loopback(&addr));
}


/* ========== irc_in_addr_valid ========== */

static void test_addr_valid(void **state)
{
    (void)state;
    struct irc_in_addr addr;

    /* 127.0.0.1 is valid */
    make_ipv4_addr(&addr, 127, 0, 0, 1);
    assert_true(irc_in_addr_valid(&addr));

    /* :: (all zeros) is not valid */
    memset(&addr, 0, sizeof(addr));
    assert_false(irc_in_addr_valid(&addr));

    /* ::1 is valid */
    memset(&addr, 0, sizeof(addr));
    addr.in6_16[7] = htons(1);
    assert_true(irc_in_addr_valid(&addr));
}


/* ========== irc_in_addr_cmp ========== */

static void test_addr_cmp_equal(void **state)
{
    (void)state;
    struct irc_in_addr addr1, addr2;

    make_ipv4_addr(&addr1, 192, 168, 1, 1);
    make_ipv4_addr(&addr2, 192, 168, 1, 1);
    assert_int_equal(0, irc_in_addr_cmp(&addr1, &addr2));
}

static void test_addr_cmp_not_equal(void **state)
{
    (void)state;
    struct irc_in_addr addr1, addr2;

    make_ipv4_addr(&addr1, 192, 168, 1, 1);
    make_ipv4_addr(&addr2, 192, 168, 1, 2);
    assert_int_not_equal(0, irc_in_addr_cmp(&addr1, &addr2));
}


/* ========== ipmask_parse ========== */

static void test_ipmask_parse_ipv4_cidr(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    unsigned char bits;
    int len;

    /* 192.168.0.0/16 style is only valid as ipmask */
    len = ipmask_parse("192.168/16", &addr, &bits);
    assert_true(len > 0);
    assert_int_equal(bits, 112);  /* 96 (ipv4 prefix) + 16 */
}

static void test_ipmask_parse_wildcard(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    unsigned char bits;
    int len;

    /* 192.* wildcard */
    len = ipmask_parse("192.*", &addr, &bits);
    assert_true(len > 0);
    assert_int_equal(bits, 104);  /* 96 + 8 bits */

    /* Broader wildcard */
    len = ipmask_parse("*", &addr, &bits);
    assert_true(len > 0);
    assert_int_equal(bits, 0);  /* Match all */
}

static void test_ipmask_parse_invalid(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    unsigned char bits;
    int len;

    /* Invalid: can't mix wildcard and CIDR */
    len = ipmask_parse("192.*/8", &addr, &bits);
    assert_int_equal(len, 0);  /* Should fail */

    /* Invalid: not an IP */
    len = ipmask_parse("not-an-ip", &addr, &bits);
    assert_int_equal(len, 0);
}


/* ========== Round-trip tests ========== */

static void test_ip_roundtrip_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr original, parsed;
    char buf[64];

    /* Create address, format it, parse it back */
    make_ipv4_addr(&original, 203, 0, 113, 42);
    ircd_ntoa_r(buf, &original);
    ircd_aton(&parsed, buf);

    /* Should match */
    assert_int_equal(0, irc_in_addr_cmp(&original, &parsed));
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* ircd_aton - IPv4 */
        cmocka_unit_test(test_aton_ipv4_localhost),
        cmocka_unit_test(test_aton_ipv4_various),

        /* ircd_aton - IPv6 */
        cmocka_unit_test(test_aton_ipv6_localhost),
        cmocka_unit_test(test_aton_ipv6_full),
        cmocka_unit_test(test_aton_ipv6_all_segments),
        cmocka_unit_test(test_aton_ipv4_mapped_ipv6),

        /* ircd_ntoa */
        cmocka_unit_test(test_ntoa_ipv4),
        cmocka_unit_test(test_ntoa_ipv6),
        cmocka_unit_test(test_ntoa_r_buffer),

        /* Address type detection */
        cmocka_unit_test(test_is_ipv4),
        cmocka_unit_test(test_is_loopback_ipv4),
        cmocka_unit_test(test_is_loopback_ipv6),
        cmocka_unit_test(test_addr_valid),

        /* Address comparison */
        cmocka_unit_test(test_addr_cmp_equal),
        cmocka_unit_test(test_addr_cmp_not_equal),

        /* IP mask parsing */
        cmocka_unit_test(test_ipmask_parse_ipv4_cidr),
        cmocka_unit_test(test_ipmask_parse_wildcard),
        cmocka_unit_test(test_ipmask_parse_invalid),

        /* Round-trip */
        cmocka_unit_test(test_ip_roundtrip_ipv4),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
