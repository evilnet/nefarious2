/*
 * ircd_cloaking_cmocka.c - CMocka unit tests for IP/host cloaking
 *
 * Tests the cloaking functions used to hide user IP addresses and hostnames.
 * Uses deterministic keys for reproducible test results.
 *
 * Copyright (C) 2024 AfterNET Development Team
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <cmocka.h>
#include <netinet/in.h>

/* Include headers needed by ircd_cloaking.c first */
#include "ircd_chattr.h"
#include "ircd_defs.h"
#include "ircd_md5.h"
#include "res.h"

/* Mock the feature macros used by ircd_cloaking.c
 * We override KEY1/KEY2/KEY3/PREFIX with test values */
#define KEY1 "TestKey1ForCloaking"
#define KEY2 "TestKey2ForCloaking"
#define KEY3 "TestKey3ForCloaking"
#define PREFIX "hidden"

/* Stub ircd_snprintf - use regular snprintf */
#define ircd_snprintf(client, buf, size, fmt, ...) snprintf(buf, size, fmt, ##__VA_ARGS__)

/* Inline the static functions from ircd_cloaking.c directly
 * This avoids header conflicts while allowing us to test the functions */

/** Downsamples a 128bit result to 32bits (md5 -> unsigned int) */
static inline unsigned int downsample(unsigned char *i)
{
    unsigned char r[4];

    r[0] = i[0] ^ i[1] ^ i[2] ^ i[3];
    r[1] = i[4] ^ i[5] ^ i[6] ^ i[7];
    r[2] = i[8] ^ i[9] ^ i[10] ^ i[11];
    r[3] = i[12] ^ i[13] ^ i[14] ^ i[15];

    return ( ((unsigned int)r[0] << 24) +
             ((unsigned int)r[1] << 16) +
             ((unsigned int)r[2] << 8) +
             (unsigned int)r[3]);
}

/** Downsamples a 128bit result to 24bits (md5 -> unsigned int) */
static inline unsigned int downsample24(unsigned char *i)
{
    unsigned char r[4];

    r[0] = i[0] ^ i[1] ^ i[2] ^ i[3] ^ i[4];
    r[1] = i[5] ^ i[6] ^ i[7] ^ i[8] ^ i[9] ^ i[10];
    r[2] = i[11] ^ i[12] ^ i[13] ^ i[14] ^ i[15];

    return ( ((unsigned int)r[0] << 16) +
             ((unsigned int)r[1] << 8) +
             (unsigned int)r[2]);
}

/* Forward declaration for mutual recursion */
static char *hidehost_ipv6(struct irc_in_addr *ip);

static char *hidehost_ipv4(struct irc_in_addr *ip)
{
    unsigned int a, b, c, d;
    static char buf[512], res[512], res2[512], result[128];
    unsigned long n;
    unsigned int alpha, beta, gamma, delta;
    unsigned char *pch;

    if (!irc_in_addr_is_ipv4(ip))
        return hidehost_ipv6(ip);

    pch = (unsigned char*)&ip->in6_16[6];
    a = *pch++;
    b = *pch;
    pch = (unsigned char*)&ip->in6_16[7];
    c = *pch++;
    d = *pch;

    /* ALPHA... */
    snprintf(buf, 512, "%s:%d.%d.%d.%d:%s", KEY2, a, b, c, d, KEY3);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY1);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    alpha = downsample24((unsigned char *)&res2);

    /* BETA... */
    snprintf(buf, 512, "%s:%d.%d.%d:%s", KEY3, a, b, c, KEY1);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY2);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    beta = downsample24((unsigned char *)&res2);

    /* GAMMA... */
    snprintf(buf, 512, "%s:%d.%d:%s", KEY1, a, b, KEY2);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY3);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    gamma = downsample24((unsigned char *)&res2);

    /* DELTA... */
    snprintf(buf, 512, "%s:%d:%s:%s", KEY2, a, KEY1, KEY3);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY1);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    delta = downsample24((unsigned char *)&res2);

    snprintf(result, HOSTLEN, "%X.%X.%X.%X.IP", alpha, beta, gamma, delta);
    return result;
}

static char *hidehost_ipv6(struct irc_in_addr *ip)
{
    unsigned int a, b, c, d, e, f, g, h;
    static char buf[512], res[512], res2[512], result[128];
    unsigned long n;
    unsigned int alpha, beta, gamma, delta;

    if (irc_in_addr_is_ipv4(ip))
        return hidehost_ipv4(ip);

    a = ntohs(ip->in6_16[0]);
    b = ntohs(ip->in6_16[1]);
    c = ntohs(ip->in6_16[2]);
    d = ntohs(ip->in6_16[3]);
    e = ntohs(ip->in6_16[4]);
    f = ntohs(ip->in6_16[5]);
    g = ntohs(ip->in6_16[6]);
    h = ntohs(ip->in6_16[7]);

    /* ALPHA... */
    snprintf(buf, 512, "%s:%x:%x:%x:%x:%x:%x:%x:%x:%s", KEY2, a, b, c, d, e, f, g, h, KEY3);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY1);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    alpha = downsample24((unsigned char *)&res2);

    /* BETA... */
    snprintf(buf, 512, "%s:%x:%x:%x:%x:%x:%x:%x:%s", KEY3, a, b, c, d, e, f, g, KEY1);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY2);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    beta = downsample24((unsigned char *)&res2);

    /* GAMMA... */
    snprintf(buf, 512, "%s:%x:%x:%x:%x:%s", KEY1, a, b, c, d, KEY2);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY3);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    gamma = downsample24((unsigned char *)&res2);

    /* DELTA... */
    snprintf(buf, 512, "%s:%x:%x:%s:%s", KEY2, a, b, KEY1, KEY3);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY1);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    delta = downsample24((unsigned char *)&res2);

    snprintf(result, HOSTLEN, "%X:%X:%X:%X:IP", alpha, beta, gamma, delta);
    return result;
}

static char *hidehost_normalhost(char *host, int components)
{
    char *p;
    static char buf[512], res[512], res2[512], result[HOSTLEN+1];
    unsigned int alpha, n;
    int comps = 0;

    snprintf(buf, 512, "%s:%s:%s", KEY1, host, KEY2);
    DoMD5((unsigned char *)&res, (unsigned char *)&buf, strlen(buf));
    strcpy(res+16, KEY3);
    n = strlen(res+16) + 16;
    DoMD5((unsigned char *)&res2, (unsigned char *)&res, n);
    alpha = downsample((unsigned char *)&res2);

    for (p = host; *p; p++) {
        if (*p == '.') {
            comps++;
            if ((comps >= components) && IsHostChar(*(p + 1)))
                break;
        }
    }

    if (*p)
    {
        unsigned int len;
        char *c;
        p++;

        snprintf(result, HOSTLEN, "%s-%X.", PREFIX, alpha);
        len = strlen(result) + strlen(p);
        if (len <= HOSTLEN)
            strcat(result, p);
        else
        {
            c = p + (len - HOSTLEN);
            if ((*c == '.') && *(c+1))
                c++;
            strcat(result, c);
        }
    } else
        snprintf(result, HOSTLEN, "%s-%X", PREFIX, alpha);

    return result;
}


/* ========== Helper functions ========== */

static void make_ipv4_addr(struct irc_in_addr *addr, unsigned char a, unsigned char b,
                           unsigned char c, unsigned char d)
{
    memset(addr, 0, sizeof(*addr));
    /* IPv4-mapped IPv6 format: ::ffff:a.b.c.d */
    addr->in6_16[5] = htons(0xffff);
    addr->in6_16[6] = htons((a << 8) | b);
    addr->in6_16[7] = htons((c << 8) | d);
}

static void make_ipv6_addr(struct irc_in_addr *addr,
                           uint16_t a, uint16_t b, uint16_t c, uint16_t d,
                           uint16_t e, uint16_t f, uint16_t g, uint16_t h)
{
    addr->in6_16[0] = htons(a);
    addr->in6_16[1] = htons(b);
    addr->in6_16[2] = htons(c);
    addr->in6_16[3] = htons(d);
    addr->in6_16[4] = htons(e);
    addr->in6_16[5] = htons(f);
    addr->in6_16[6] = htons(g);
    addr->in6_16[7] = htons(h);
}


/* ========== downsample() tests ========== */

static void test_downsample_zeros(void **state)
{
    (void)state;
    unsigned char input[16] = {0};

    /* All zeros should produce zero */
    assert_int_equal(0, downsample(input));
}

static void test_downsample_ones(void **state)
{
    (void)state;
    unsigned char input[16];
    memset(input, 0xFF, sizeof(input));

    /* All 0xFF bytes:
     * r[0] = 0xFF ^ 0xFF ^ 0xFF ^ 0xFF = 0
     * r[1] = 0xFF ^ 0xFF ^ 0xFF ^ 0xFF = 0
     * r[2] = 0xFF ^ 0xFF ^ 0xFF ^ 0xFF = 0
     * r[3] = 0xFF ^ 0xFF ^ 0xFF ^ 0xFF = 0
     */
    assert_int_equal(0, downsample(input));
}

static void test_downsample_sequential(void **state)
{
    (void)state;
    unsigned char input[16];

    /* Fill with 0-15 */
    for (int i = 0; i < 16; i++) {
        input[i] = (unsigned char)i;
    }

    /* r[0] = 0 ^ 1 ^ 2 ^ 3 = 0
     * r[1] = 4 ^ 5 ^ 6 ^ 7 = 0
     * r[2] = 8 ^ 9 ^ 10 ^ 11 = 0
     * r[3] = 12 ^ 13 ^ 14 ^ 15 = 0
     */
    assert_int_equal(0, downsample(input));
}

static void test_downsample_known_value(void **state)
{
    (void)state;
    unsigned char input[16] = {
        0x01, 0x00, 0x00, 0x00,  /* r[0] = 0x01 */
        0x02, 0x00, 0x00, 0x00,  /* r[1] = 0x02 */
        0x03, 0x00, 0x00, 0x00,  /* r[2] = 0x03 */
        0x04, 0x00, 0x00, 0x00   /* r[3] = 0x04 */
    };

    /* Expected: (0x01 << 24) + (0x02 << 16) + (0x03 << 8) + 0x04 */
    assert_int_equal(0x01020304, downsample(input));
}


/* ========== downsample24() tests ========== */

static void test_downsample24_zeros(void **state)
{
    (void)state;
    unsigned char input[16] = {0};

    assert_int_equal(0, downsample24(input));
}

static void test_downsample24_known_value(void **state)
{
    (void)state;
    unsigned char input[16] = {
        0x01, 0x00, 0x00, 0x00, 0x00,  /* r[0] = 0x01 */
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00,  /* r[1] = 0x02 */
        0x03, 0x00, 0x00, 0x00, 0x00   /* r[2] = 0x03 */
    };

    /* Expected: (0x01 << 16) + (0x02 << 8) + 0x03 = 0x010203 */
    assert_int_equal(0x010203, downsample24(input));
}

static void test_downsample24_max(void **state)
{
    (void)state;
    /* downsample24 produces a 24-bit value, max is 0xFFFFFF */
    unsigned char input[16] = {
        0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0x00, 0x00, 0x00, 0x00
    };

    unsigned int result = downsample24(input);
    assert_true(result <= 0xFFFFFF);
}


/* ========== hidehost_ipv4() tests ========== */

static void test_hidehost_ipv4_format(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char *result;

    make_ipv4_addr(&addr, 127, 0, 0, 1);
    result = hidehost_ipv4(&addr);

    /* Result should be in format: ALPHA.BETA.GAMMA.DELTA.IP */
    assert_non_null(result);
    assert_true(strlen(result) > 0);

    /* Should end with .IP */
    assert_non_null(strstr(result, ".IP"));

    /* Should contain 4 dots (X.X.X.X.IP) */
    int dots = 0;
    for (char *p = result; *p; p++) {
        if (*p == '.') dots++;
    }
    assert_int_equal(4, dots);
}

static void test_hidehost_ipv4_deterministic(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char result1[128], result2[128];

    /* Same IP should produce same cloak */
    make_ipv4_addr(&addr, 192, 168, 1, 100);

    strncpy(result1, hidehost_ipv4(&addr), sizeof(result1) - 1);
    result1[sizeof(result1) - 1] = '\0';

    strncpy(result2, hidehost_ipv4(&addr), sizeof(result2) - 1);
    result2[sizeof(result2) - 1] = '\0';

    assert_string_equal(result1, result2);
}

static void test_hidehost_ipv4_different_ips(void **state)
{
    (void)state;
    struct irc_in_addr addr1, addr2;
    char result1[128], result2[128];

    /* Different IPs should produce different cloaks */
    make_ipv4_addr(&addr1, 10, 0, 0, 1);
    make_ipv4_addr(&addr2, 10, 0, 0, 2);

    strncpy(result1, hidehost_ipv4(&addr1), sizeof(result1) - 1);
    result1[sizeof(result1) - 1] = '\0';

    strncpy(result2, hidehost_ipv4(&addr2), sizeof(result2) - 1);
    result2[sizeof(result2) - 1] = '\0';

    assert_string_not_equal(result1, result2);
}

static void test_hidehost_ipv4_same_class_c(void **state)
{
    (void)state;
    struct irc_in_addr addr1, addr2;
    char *result1, *result2;
    char *dot1, *dot2;

    /* IPs in same /24 should share some cloak components (BETA, GAMMA, DELTA) */
    make_ipv4_addr(&addr1, 192, 168, 1, 10);
    make_ipv4_addr(&addr2, 192, 168, 1, 20);

    result1 = hidehost_ipv4(&addr1);
    result2 = hidehost_ipv4(&addr2);

    /* Find first dot (after ALPHA) */
    dot1 = strchr(result1, '.');
    dot2 = strchr(result2, '.');

    assert_non_null(dot1);
    assert_non_null(dot2);

    /* Everything after first dot should be same (BETA.GAMMA.DELTA.IP) */
    assert_string_equal(dot1, dot2);
}


/* ========== hidehost_ipv6() tests ========== */

static void test_hidehost_ipv6_format(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char *result;

    /* ::1 */
    make_ipv6_addr(&addr, 0, 0, 0, 0, 0, 0, 0, 1);
    result = hidehost_ipv6(&addr);

    /* Result should be in format: ALPHA:BETA:GAMMA:DELTA:IP */
    assert_non_null(result);
    assert_true(strlen(result) > 0);

    /* Should end with :IP */
    assert_non_null(strstr(result, ":IP"));
}

static void test_hidehost_ipv6_deterministic(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char result1[128], result2[128];

    make_ipv6_addr(&addr, 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

    strncpy(result1, hidehost_ipv6(&addr), sizeof(result1) - 1);
    result1[sizeof(result1) - 1] = '\0';

    strncpy(result2, hidehost_ipv6(&addr), sizeof(result2) - 1);
    result2[sizeof(result2) - 1] = '\0';

    assert_string_equal(result1, result2);
}

static void test_hidehost_ipv6_different_ips(void **state)
{
    (void)state;
    struct irc_in_addr addr1, addr2;
    char result1[128], result2[128];

    make_ipv6_addr(&addr1, 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    make_ipv6_addr(&addr2, 0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

    strncpy(result1, hidehost_ipv6(&addr1), sizeof(result1) - 1);
    result1[sizeof(result1) - 1] = '\0';

    strncpy(result2, hidehost_ipv6(&addr2), sizeof(result2) - 1);
    result2[sizeof(result2) - 1] = '\0';

    assert_string_not_equal(result1, result2);
}


/* ========== hidehost_normalhost() tests ========== */

static void test_hidehost_normalhost_format(void **state)
{
    (void)state;
    char host[] = "user.example.com";
    char *result;

    result = hidehost_normalhost(host, 1);

    assert_non_null(result);
    assert_true(strlen(result) > 0);

    /* Should start with PREFIX- */
    assert_int_equal(0, strncmp(result, PREFIX "-", strlen(PREFIX) + 1));

    /* Should contain the domain suffix */
    assert_non_null(strstr(result, "example.com"));
}

static void test_hidehost_normalhost_deterministic(void **state)
{
    (void)state;
    char host[] = "test.host.example.org";
    char result1[128], result2[128];

    strncpy(result1, hidehost_normalhost(host, 2), sizeof(result1) - 1);
    result1[sizeof(result1) - 1] = '\0';

    strncpy(result2, hidehost_normalhost(host, 2), sizeof(result2) - 1);
    result2[sizeof(result2) - 1] = '\0';

    assert_string_equal(result1, result2);
}

static void test_hidehost_normalhost_different_hosts(void **state)
{
    (void)state;
    char host1[] = "user1.example.com";
    char host2[] = "user2.example.com";
    char result1[128], result2[128];

    strncpy(result1, hidehost_normalhost(host1, 1), sizeof(result1) - 1);
    result1[sizeof(result1) - 1] = '\0';

    strncpy(result2, hidehost_normalhost(host2, 1), sizeof(result2) - 1);
    result2[sizeof(result2) - 1] = '\0';

    /* Different hosts should produce different cloaks */
    assert_string_not_equal(result1, result2);
}

static void test_hidehost_normalhost_components(void **state)
{
    (void)state;
    char host[] = "a.b.c.example.com";
    char *result;

    /* With components=2, should preserve example.com */
    result = hidehost_normalhost(host, 2);
    assert_non_null(strstr(result, "example.com"));

    /* With components=1, should preserve c.example.com */
    result = hidehost_normalhost(host, 1);
    assert_non_null(strstr(result, "c.example.com"));
}

static void test_hidehost_normalhost_single_label(void **state)
{
    (void)state;
    char host[] = "localhost";
    char *result;

    /* Single-label hostname should still produce valid output */
    result = hidehost_normalhost(host, 1);

    assert_non_null(result);
    assert_true(strlen(result) > 0);
    /* Should start with PREFIX- */
    assert_int_equal(0, strncmp(result, PREFIX "-", strlen(PREFIX) + 1));
}


/* ========== IPv4/IPv6 detection ========== */

static void test_hidehost_ipv4_called_for_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char *result;

    /* IPv4-mapped address */
    make_ipv4_addr(&addr, 8, 8, 8, 8);
    result = hidehost_ipv4(&addr);

    /* Should end with .IP (IPv4 format) */
    assert_non_null(strstr(result, ".IP"));
}

static void test_hidehost_ipv6_redirects_ipv4(void **state)
{
    (void)state;
    struct irc_in_addr addr;
    char *result;

    /* IPv4-mapped address passed to ipv6 function */
    make_ipv4_addr(&addr, 1, 2, 3, 4);
    result = hidehost_ipv6(&addr);

    /* Should be redirected to IPv4 cloaking, ending with .IP */
    assert_non_null(strstr(result, ".IP"));
}


int main(void)
{
    const struct CMUnitTest tests[] = {
        /* downsample */
        cmocka_unit_test(test_downsample_zeros),
        cmocka_unit_test(test_downsample_ones),
        cmocka_unit_test(test_downsample_sequential),
        cmocka_unit_test(test_downsample_known_value),

        /* downsample24 */
        cmocka_unit_test(test_downsample24_zeros),
        cmocka_unit_test(test_downsample24_known_value),
        cmocka_unit_test(test_downsample24_max),

        /* hidehost_ipv4 */
        cmocka_unit_test(test_hidehost_ipv4_format),
        cmocka_unit_test(test_hidehost_ipv4_deterministic),
        cmocka_unit_test(test_hidehost_ipv4_different_ips),
        cmocka_unit_test(test_hidehost_ipv4_same_class_c),

        /* hidehost_ipv6 */
        cmocka_unit_test(test_hidehost_ipv6_format),
        cmocka_unit_test(test_hidehost_ipv6_deterministic),
        cmocka_unit_test(test_hidehost_ipv6_different_ips),

        /* hidehost_normalhost */
        cmocka_unit_test(test_hidehost_normalhost_format),
        cmocka_unit_test(test_hidehost_normalhost_deterministic),
        cmocka_unit_test(test_hidehost_normalhost_different_hosts),
        cmocka_unit_test(test_hidehost_normalhost_components),
        cmocka_unit_test(test_hidehost_normalhost_single_label),

        /* IPv4/IPv6 detection */
        cmocka_unit_test(test_hidehost_ipv4_called_for_ipv4),
        cmocka_unit_test(test_hidehost_ipv6_redirects_ipv4),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
