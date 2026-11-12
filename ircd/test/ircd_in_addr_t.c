/* ircd_in_addr_t.c - Test file for IP address manipulation */

#include "client.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "numnicks.h"
#include "res.h"
#include "struct.h"
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

/** Structure to describe a test for IP address parsing and unparsing. */
struct address_test {
    const char *text; /**< Textual address to parse. */
    const char *canonical; /**< Canonical form of address. */
    struct irc_in_addr expected; /**< Parsed address. */
    const char *base64_v4; /**< v4-only compatible base64 encoding. */
    const char *base64_v6; /**< v6-compatible base64 encoding. */
    unsigned int is_valid : 1; /**< is address valid? */
    unsigned int is_ipv4 : 1; /**< is address ipv4? */
    unsigned int is_loopback : 1; /**< is address loopback? */
};

/** Array of addresses to test with. */
static struct address_test test_addrs[] = {
    { "::", "0::",
      {{ 0, 0, 0, 0, 0, 0, 0, 0 }},
      "AAAAAA", "_", 0, 0, 0 },
    { "::1", "0::1",
      {{ 0, 0, 0, 0, 0, 0, 0, 1 }},
      "AAAAAA", "_AAB", 1, 0, 1 },
    { "127.0.0.1", "127.0.0.1",
      {{ 0, 0, 0, 0, 0, 0xffff, 0x7f00, 1 }},
      "B]AAAB", "B]AAAB", 1, 1, 1 },
    { "::ffff:127.0.0.3", "127.0.0.3",
      {{ 0, 0, 0, 0, 0, 0xffff, 0x7f00, 3 }},
      "B]AAAD", "B]AAAD", 1, 1, 1 },
    { "::127.0.0.1", "127.0.0.1",
      {{ 0, 0, 0, 0, 0, 0, 0x7f00, 1 }},
      "B]AAAB", "B]AAAB", 1, 1, 1 },
    { "2002:7f00:3::1", "2002:7f00:3::1",
      {{ 0x2002, 0x7f00, 3, 0, 0, 0, 0, 1 }},
      "B]AAAD", "CACH8AAAD_AAB", 1, 0, 0 },
    { "8352:0344:0:0:0:0:2001:1204", "8352:344::2001:1204",
      {{ 0x8352, 0x344, 0, 0, 0, 0, 0x2001, 0x1204 }},
      "AAAAAA", "INSANE_CABBIE", 1, 0, 0 },
    { "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8",
      {{ 1, 2, 3, 4, 5, 6, 7, 8 }},
      "AAAAAA", "AABAACAADAAEAAFAAGAAHAAI", 1, 0, 0 },
    { "1:0:2:0:3:0:0:4", "1:0:2:0:3::4",
      {{ 1, 0, 2, 0, 3, 0, 0, 4 }},
      "AAAAAA", "AABAAAAACAAAAAD_AAE", 1, 0, 0 },
    { "a:0:b:0:c:0:d:e", "a::b:0:c:0:d:e",
      {{ 0xa, 0, 0xb, 0, 0xc, 0, 0xd, 0xe }},
      "AAAAAA", "AAK_AALAAAAAMAAAAANAAO", 1, 0, 0 },
    /* The high 16 bits of each 32-bit encoding are 0x8000 or more. */
    { "200.0.0.1", "200.0.0.1",
      {{ 0, 0, 0, 0, 0, 0xffff, 0xc800, 1 }},
      "DIAAAB", "DIAAAB", 1, 1, 0 },
    { "255.255.255.255", "255.255.255.255",
      {{ 0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff }},
      "D]]]]]", "D]]]]]", 1, 1, 0 },
    { "2002:c800:1::1", "2002:c800:1::1",
      {{ 0x2002, 0xc800, 1, 0, 0, 0, 0, 1 }},
      "DIAAAB", "CACMgAAAB_AAB", 1, 0, 0 },
    { "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001::4136:e378:8000:63bf:3fff:fdd2",
      {{ 0x2001, 0, 0x4136, 0xe378, 0x8000, 0x63bf, 0x3fff, 0xfdd2 }},
      "DAAAIt", "CAB_EE2ON4IAAGO]D]]P3S", 1, 0, 0 },
    { 0 },
};

/** Perform tests for a single IP address.
 * @param[in] addr Address test structure.
 */
static void
test_address(struct address_test *addr)
{
    struct irc_in_addr parsed;
    unsigned int ii, len, val;
    char unparsed[64], base64_v4[64], base64_v6[64];
    int ret;

    /* Convert expected address to network order. */
    for (ii = 0; ii < 8; ++ii)
        addr->expected.in6_16[ii] = htons(addr->expected.in6_16[ii]);
    /* Make sure the text form is parsed as expected. */
    len = ircd_aton(&parsed, addr->text);
    assert(len == strlen(addr->text));
    assert(!irc_in_addr_cmp(&parsed, &addr->expected));
    /* Make sure it converts back to ASCII. */
    ircd_ntoa_r(unparsed, &parsed);
    assert(!strcmp(unparsed, addr->canonical));
    /* Check IP-to-base64 conversion. */
    iptobase64(base64_v4, &parsed, sizeof(base64_v4), 0);
    iptobase64(base64_v6, &parsed, sizeof(base64_v6), 1);
    if (addr->base64_v4)
        assert(!strcmp(base64_v4, addr->base64_v4));
    if (addr->base64_v6)
        assert(!strcmp(base64_v6, addr->base64_v6));
    /* Check testable attributes. */
    val = irc_in_addr_valid(&parsed);
    assert(!!val == addr->is_valid);
    val = irc_in_addr_is_ipv4(&parsed);
    assert(!!val == addr->is_ipv4);
    val = irc_in_addr_is_loopback(&parsed);
    assert(!!val == addr->is_loopback);
    /* Check base64-to-IP conversion. */
    if (addr->is_ipv4) {
        ret = base64toip(addr->base64_v4, &parsed);
        assert(ret == 0);
        assert(!memcmp(parsed.in6_16+6, addr->expected.in6_16+6, 4));
    } else {
        ret = base64toip(addr->base64_v6, &parsed);
        assert(ret == 0);
        assert(!memcmp(&parsed, &addr->expected, sizeof(parsed)));
    }
    /* Tests completed. */
    printf("Passed: %s (%s/%s)\n", addr->text, base64_v4, base64_v6);
}

/** Structure to describe a test for IP mask parsing. */
struct ipmask_test {
    const char *text; /**< Textual IP mask to parse. */
    struct irc_in_addr expected; /**< Canonical form of address. */
    unsigned int is_ipmask : 1; /**< Parse as an ipmask? */
    unsigned int is_parseable : 1; /**< Is address parseable? */
    unsigned int exp_bits : 8; /**< Number of bits expected in netmask */
};

/** Array of ipmasks to test with. */
static struct ipmask_test test_masks[] = {
    { "::", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 128 },
    { "::/0", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 0 },
    { "::10.0.0.0", {{ 0, 0, 0, 0, 0, 0, 0xa00, 0 }}, 1, 1, 128 },
    { "192.168/16", {{ 0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0 }}, 1, 1, 112 },
    { "192.*", {{ 0, 0, 0, 0, 0, 0xffff, 0xc000, 0 }}, 1, 1, 104 },
    { "192.*.*.*", {{ 0, 0, 0, 0, 0, 0xffff, 0xc000, 0 }}, 1, 1, 104 },
    { "192.*/8", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "192*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "192.168.0.0/16", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 0, 0, 0 },
    { "ab.*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "a*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 0 },
    { "a:b", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "a::*", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { "a:*", {{ 0xa, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 16 },
    { "a:*:*", {{ 0xa, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 16 },
    { "a:/16", {{ 0xa, 0, 0, 0, 0, 0, 0, 0 }}, 1, 1, 16 },
    { "0.0.0.0.0/1", {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 0, 0, 0 },
    { "2607:3f00:1:30c:9999*",
      {{ 0x2607, 0x3f00, 1, 0x30c, 0x9999, 0, 0, 0 }}, 1, 1, 80 },
    { "1234:5678:9abc:def0:feed:abba:cabb:1e55::",
      {{ 0, 0, 0, 0, 0, 0, 0, 0 }}, 1, 0, 0 },
    { 0 }
};

/** Perform tests for a single IP mask.
 * @param[in] mask IP mask test structure.
 */
static void
test_ipmask(struct ipmask_test *mask)
{
    struct irc_in_addr parsed;
    unsigned int len, ii;
    unsigned char bits = 0;

    /* Convert expected address to network order. */
    for (ii = 0; ii < 8; ++ii)
        mask->expected.in6_16[ii] = htons(mask->expected.in6_16[ii]);
    /* Try to parse; make sure its parseability and netmask length are
     * as expected. */
    len = ipmask_parse(mask->text, &parsed, mask->is_ipmask ? &bits : 0);
    assert(!!len == mask->is_parseable);
    if (!len) {
        printf("X-Fail: %s\n", mask->text);
        return;
    }
    if (mask->is_ipmask)
        assert(bits == mask->exp_bits);
    assert(!memcmp(&parsed, &mask->expected, sizeof(parsed)));
    printf("Passed: %s (%s/%u)\n", mask->text, ircd_ntoa(&parsed), bits);
}

/** Structure to describe a test for decoding a peer's IPv6 field. */
struct b64ip_test {
    const char *base64; /**< Field as iptobase64() emits it. */
    struct irc_in_addr expected; /**< Address it decodes to. */
};

/** IPv6 fields, each exactly as iptobase64() encodes the address. */
static struct b64ip_test test_b64ips[] = {
    { "_", {{ 0, 0, 0, 0, 0, 0, 0, 0 }} },
    { "_AAB", {{ 0, 0, 0, 0, 0, 0, 0, 1 }} },
    { "P6A_", {{ 0xfe80, 0, 0, 0, 0, 0, 0, 0 }} },
    { "CABA24_AAB", {{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 1 }} },
    { "AABAAAAAC_AADAAEAAF", {{ 1, 0, 2, 0, 0, 3, 4, 5 }} },
    { "AABAACAADAAEAAFAAGAAHAAI", {{ 1, 2, 3, 4, 5, 6, 7, 8 }} },
    { "P]]P]]P]]P]]P]]P]]P]]P][",
      {{ 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xfffe }} },
    { 0 }
};

/** Check that a well-formed IPv6 field decodes to its address.
 * @param[in] test Field and expected address.
 */
static void
test_b64ip(struct b64ip_test *test)
{
    struct irc_in_addr parsed;
    unsigned int ii;
    int ret;

    for (ii = 0; ii < 8; ++ii)
        test->expected.in6_16[ii] = htons(test->expected.in6_16[ii]);
    ret = base64toip(test->base64, &parsed);
    assert(ret == 0);
    assert(!memcmp(&parsed, &test->expected, sizeof(parsed)));
    printf("Passed: %s (%s)\n", test->base64, ircd_ntoa(&parsed));
}

/** IP fields a peer can send that iptobase64() never emits. */
static const char *test_bad_b64ips[] = {
    "____________________________",          /* zero-run length wraps */
    "__",                                    /* two zero runs */
    "AAB_AAB_AAB",                           /* two zero runs */
    "AABAABAABAABAABAABAABAABAABAABAABAAB_", /* 12 groups and a zero run */
    "AABAABAABAABAABAABAABAABAABAABAABAAB",  /* 12 groups */
    "AABAABAABAABAABAABAAB",                 /* 7 groups, no zero run */
    "A_AB",                                  /* '_' inside a group */
    "AAB_A",                                 /* partial group */
    "AAB",                                   /* short */
    "AABA",
    "",
    "AAB!AB",                                /* not base64 */
    "_AAAAB",                                /* 6 characters is IPv4 */
    0
};

/** Check that a malformed IP field is rejected and decodes to the
 * all-zero address, reading nothing past its terminator and writing
 * nothing past the irc_in_addr.
 * @param[in] bad Malformed field.
 */
static void
test_bad_b64ip(const char *bad)
{
    struct {
        struct irc_in_addr addr;
        unsigned char guard[64];
    } out;
    char input[128];
    unsigned int ii;
    int ret;

    /* Pad past the terminator with non-zero digits, so a decoder that
     * reads beyond it decodes something other than zero. */
    memset(input, 'B', sizeof(input));
    memcpy(input, bad, strlen(bad) + 1);
    memset(&out, 0xA5, sizeof(out));
    ret = base64toip(input, &out.addr);
    assert(ret == -1);
    for (ii = 0; ii < 8; ++ii)
        assert(out.addr.in6_16[ii] == 0);
    for (ii = 0; ii < sizeof(out.guard); ++ii)
        assert(out.guard[ii] == 0xA5);
    printf("Passed: \"%s\" (rejected)\n", bad);
}

/** Structure to describe a test for user numnick validation. */
struct numnick_test {
    const char *numnick; /**< Numnick a peer sends. */
    unsigned int is_valid : 1; /**< Is it a well-formed user numnick? */
};

/** Array of user numnicks to test with. */
static struct numnick_test test_user_numnicks[] = {
    { "ABAAA", 1 },
    { "B]A", 1 },
    { "z09[]", 1 },
    { "", 0 },
    { "A", 0 },
    { "AB", 0 },
    { "ABAA", 0 },
    { "ABAAAA", 0 },
    { "AB AA", 0 },
    { "AB:AA", 0 },
    { "A_A", 0 },
    { 0 }
};

/** Check ValidUserNumNick() on a single numnick.
 * @param[in] test Numnick and whether it is well-formed.
 */
static void
test_user_numnick(struct numnick_test *test)
{
    assert(!!ValidUserNumNick(test->numnick) == test->is_valid);
    printf("Passed: \"%s\" (%s)\n", test->numnick,
           test->is_valid ? "valid" : "invalid");
}

/** Check that an empty numnick decodes to 0 without reading past its
 * terminator.  A peer can send one: an empty BURST member, an empty
 * MODE -o parameter.
 */
static void
test_b64_empty(void)
{
    static const char empty[] = { '\0', 'v', 'v', 'v', 'v', '\0' };

    assert(base64toint(empty) == 0);
    printf("Passed: base64toint(\"\") == 0\n");
}

/** Check that findNUser() and FindNServer() resolve only numnicks of a
 * length that can name a user or server.  A 1-character numnick used to
 * resolve server "A" and then client "" to slot 0.
 */
static void
test_short_numnicks(void)
{
    static struct Client server, user;
    static struct Server serv;
    static struct Client *clients[64];
    /* A lookup that decodes past the terminator sees zeros here, which
     * name the registered server and the client in its slot 0. */
    static const char empty[] = { '\0', '\0', '\0', '\0' };
    static const char one[] = { 'A', '\0', '\0', '\0', '\0' };

    cli_serv(&server) = &serv;
    serv.client_list = clients;
    serv.nn_mask = 63;
    SetYXXServerName(&server, 0);       /* "AA" */
    clients[0] = &user;

    assert(FindNServer("AA") == &server);
    assert(FindNServer("A") == &server);
    assert(findNUser("AAAAA") == &user);
    assert(findNUser("AAA") == &user);

    assert(FindNServer(empty) == NULL);
    assert(findNUser(empty) == NULL);
    assert(findNUser(one) == NULL);
    assert(findNUser("AA") == NULL);
    assert(findNUser("AAAA") == NULL);

    ClearServerYXX(&server);
    printf("Passed: numnick lookups by length\n");
}

int
main(int argc, char *argv[])
{
    unsigned int ii;

    printf("Testing address parsing..\n");
    for (ii = 0; test_addrs[ii].text; ++ii)
        test_address(&test_addrs[ii]);

    printf("\nTesting ipmask parsing..\n");
    for (ii = 0; test_masks[ii].text; ++ii)
        test_ipmask(&test_masks[ii]);

    printf("\nTesting base64 decoding of peer fields..\n");
    for (ii = 0; test_b64ips[ii].base64; ++ii)
        test_b64ip(&test_b64ips[ii]);
    for (ii = 0; test_bad_b64ips[ii]; ++ii)
        test_bad_b64ip(test_bad_b64ips[ii]);
    test_b64_empty();
    for (ii = 0; test_user_numnicks[ii].numnick; ++ii)
        test_user_numnick(&test_user_numnicks[ii]);
    test_short_numnicks();

    return 0;
}
