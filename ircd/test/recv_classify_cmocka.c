/*
 * recv_classify_cmocka.c - CMocka unit tests for recv_classify().
 *
 * Tests cover:
 *   - Client vs server caps (4095/FULL_MSG_SIZE vs 8191/512).
 *   - State transitions (TAG → MSG on SPACE, reset on CR/LF).
 *   - Resumability across split inputs (the production hot-path property).
 *   - Tag-only lines (TAGMSG shape).
 *   - Property-style fuzz: random splits of well-formed input give the
 *     same end state as a single-buffer feed.
 *
 * Plan: .claude/para/projects/per-class-recvq-buffers.md
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "client.h"
#include "ircd_defs.h"
#include "recv_classify.h"

/* Set up a Client + Connection pair for a single test.  All fields are
 * zero-initialised; the caller flips status to STAT_SERVER if exercising
 * the server-side caps. */
static void
setup_client(struct Client *cli, struct Connection *con)
{
    memset(cli, 0, sizeof(*cli));
    memset(con, 0, sizeof(*con));
    cli_connect(cli) = con;
    cli_status(cli) = STAT_UNKNOWN;  /* client-side caps */
}

static void
setup_server(struct Client *cli, struct Connection *con)
{
    setup_client(cli, con);
    cli_status(cli) = STAT_SERVER;
}

/* Convenience: feed bytes one byte at a time to exercise resumability. */
static int
feed_one_at_a_time(struct Client *cli, const char *buf, unsigned int len)
{
    unsigned int i;
    int last = RECV_CLASSIFY_OK;
    for (i = 0; i < len; i++) {
        int r = recv_classify(cli, buf + i, 1);
        if (r != RECV_CLASSIFY_OK && last == RECV_CLASSIFY_OK)
            last = r;
    }
    return last;
}

/* ========== Basic state tracking ========== */

static void test_simple_msg(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char line[] = "PING :foo\r\n";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, line, sizeof(line) - 1),
                     RECV_CLASSIFY_OK);
    /* Counters reset after \r\n. */
    assert_int_equal(con_recv_tag_bytes(&con), 0);
    assert_int_equal(con_recv_msg_bytes(&con), 0);
    assert_int_equal(con_recv_state(&con), RECV_TAGS);
}

static void test_msg_no_terminator(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char line[] = "PING :foo";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, line, sizeof(line) - 1),
                     RECV_CLASSIFY_OK);
    /* No \r\n yet — counters still hold in-flight count. */
    assert_int_equal(con_recv_msg_bytes(&con), 9);
    assert_int_equal(con_recv_state(&con), RECV_MSG);
}

static void test_tag_then_msg(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char line[] = "@a=b PING :ok\r\n";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, line, sizeof(line) - 1),
                     RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_tag_bytes(&con), 0);  /* reset after \r\n */
    assert_int_equal(con_recv_msg_bytes(&con), 0);
}

static void test_tagmsg_shape(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    /* Tag region followed directly by \r\n — TAGMSG / @-only line. */
    const char line[] = "@a=b\r\n";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, line, sizeof(line) - 1),
                     RECV_CLASSIFY_OK);
    /* Reset after terminator; state must NOT have switched to MSG mode
     * en route, since there's no SPACE separator. */
    assert_int_equal(con_recv_state(&con), RECV_TAGS);
    assert_int_equal(con_recv_tag_bytes(&con), 0);
    assert_int_equal(con_recv_msg_bytes(&con), 0);
}

/* ========== Per-class caps — client direction ========== */

static void test_client_tag_just_under_cap(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char line[5000];

    setup_client(&cli, &con);
    /* '@' + 4094 'x' = 4095 byte tag region (exactly at cap). */
    line[0] = '@';
    memset(line + 1, 'x', 4094);
    assert_int_equal(recv_classify(&cli, line, 4095), RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_tag_bytes(&con), 4095);
}

static void test_client_tag_over_cap(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char line[5000];

    setup_client(&cli, &con);
    /* '@' + 4096 'x' = 4097 byte tag region (one over cap). */
    line[0] = '@';
    memset(line + 1, 'x', 4096);
    assert_int_equal(recv_classify(&cli, line, 4097),
                     RECV_CLASSIFY_TAG_OVERRUN);
}

static void test_client_msg_at_512(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char line[513];

    setup_client(&cli, &con);
    memset(line, 'A', 512);
    /* Body cap = BUFSIZE (512) per IRCv3 message-tags spec: tags grow,
     * body stays at the standard 510-byte tag-less message limit. */
    assert_int_equal(recv_classify(&cli, line, 512), RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_msg_bytes(&con), 512);
}

static void test_client_msg_over_512(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char line[513];

    setup_client(&cli, &con);
    memset(line, 'A', 513);
    assert_int_equal(recv_classify(&cli, line, 513),
                     RECV_CLASSIFY_MSG_OVERRUN);
}

/* ========== Per-class caps — server direction ========== */

static void test_server_tag_just_under_cap(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char *line;

    setup_server(&cli, &con);
    line = malloc(8192);
    line[0] = '@';
    memset(line + 1, 'x', 8190);
    assert_int_equal(recv_classify(&cli, line, 8191), RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_tag_bytes(&con), 8191);
    free(line);
}

static void test_server_tag_over_cap(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char *line;

    setup_server(&cli, &con);
    line = malloc(8200);
    line[0] = '@';
    memset(line + 1, 'x', 8192);
    assert_int_equal(recv_classify(&cli, line, 8193),
                     RECV_CLASSIFY_TAG_OVERRUN);
    free(line);
}

static void test_server_msg_at_512(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char line[513];

    setup_server(&cli, &con);
    memset(line, 'A', 512);
    assert_int_equal(recv_classify(&cli, line, 512), RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_msg_bytes(&con), 512);
}

static void test_server_msg_over_512(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char line[513];

    setup_server(&cli, &con);
    memset(line, 'A', 513);
    /* Server body cap = 512 (legacy P10).  513 must overrun. */
    assert_int_equal(recv_classify(&cli, line, 513),
                     RECV_CLASSIFY_MSG_OVERRUN);
}

/* ========== Resumability across calls ========== */

static void test_split_feed_matches_whole(void **state)
{
    (void)state;
    struct Client cli_a, cli_b;
    struct Connection con_a, con_b;
    const char line[] = "@aaa=bbb;ccc=ddd PRIVMSG #chan :hello there\r\n";

    setup_client(&cli_a, &con_a);
    setup_client(&cli_b, &con_b);

    /* Whole-buffer feed. */
    (void)recv_classify(&cli_a, line, sizeof(line) - 1);
    /* Byte-at-a-time feed. */
    (void)feed_one_at_a_time(&cli_b, line, sizeof(line) - 1);

    assert_int_equal(con_recv_state(&con_a), con_recv_state(&con_b));
    assert_int_equal(con_recv_tag_bytes(&con_a), con_recv_tag_bytes(&con_b));
    assert_int_equal(con_recv_msg_bytes(&con_a), con_recv_msg_bytes(&con_b));
}

static void test_split_at_tag_boundary(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    /* Split exactly at the SPACE between tag and msg. */
    const char part1[] = "@a=b";
    const char part2[] = " PING :ok\r\n";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, part1, sizeof(part1) - 1),
                     RECV_CLASSIFY_OK);
    /* Mid-tag: counters non-zero, state still TAGS. */
    assert_int_equal(con_recv_state(&con), RECV_TAGS);
    assert_int_equal(con_recv_tag_bytes(&con), 4);

    assert_int_equal(recv_classify(&cli, part2, sizeof(part2) - 1),
                     RECV_CLASSIFY_OK);
    /* After \r\n: reset. */
    assert_int_equal(con_recv_state(&con), RECV_TAGS);
    assert_int_equal(con_recv_tag_bytes(&con), 0);
    assert_int_equal(con_recv_msg_bytes(&con), 0);
}

static void test_split_mid_tag_overrun(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    char *part1;
    char *part2;
    int r1, r2;

    setup_client(&cli, &con);
    /* First half: '@' + 2000 'x' — no overrun yet. */
    part1 = malloc(2001);
    part1[0] = '@';
    memset(part1 + 1, 'x', 2000);
    r1 = recv_classify(&cli, part1, 2001);
    assert_int_equal(r1, RECV_CLASSIFY_OK);

    /* Second half: 2096 more 'x' to push past 4095 cap. */
    part2 = malloc(2096);
    memset(part2, 'x', 2096);
    r2 = recv_classify(&cli, part2, 2096);
    assert_int_equal(r2, RECV_CLASSIFY_TAG_OVERRUN);

    free(part1);
    free(part2);
}

/* ========== Edge cases ========== */

static void test_back_to_back_lines(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char lines[] = "PING :a\r\nPONG :b\r\n@x=y NICK c\r\n";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, lines, sizeof(lines) - 1),
                     RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_state(&con), RECV_TAGS);
    assert_int_equal(con_recv_tag_bytes(&con), 0);
    assert_int_equal(con_recv_msg_bytes(&con), 0);
}

static void test_lone_lf(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char line[] = "PING :foo\n";

    setup_client(&cli, &con);
    /* Bare \n is accepted by dbuf_getmsg as terminator; classifier
     * must treat it the same way for symmetry. */
    assert_int_equal(recv_classify(&cli, line, sizeof(line) - 1),
                     RECV_CLASSIFY_OK);
    assert_int_equal(con_recv_msg_bytes(&con), 0);  /* reset after \n */
}

static void test_lone_cr(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char line[] = "PING :foo\r";

    setup_client(&cli, &con);
    assert_int_equal(recv_classify(&cli, line, sizeof(line) - 1),
                     RECV_CLASSIFY_OK);
    /* \r alone also resets — both terminator bytes are line boundaries. */
    assert_int_equal(con_recv_msg_bytes(&con), 0);
}

/* ========== Property fuzz: any split yields the same end state ========== */

static void test_property_random_splits(void **state)
{
    (void)state;
    /* A representative well-formed line — modest tag region, modest body. */
    const char line[] =
        "@time=2026-01-01T00:00:00.000Z;account=alice PRIVMSG #chan "
        ":hello everyone, this is a normal-ish line.\r\n";
    const unsigned int len = sizeof(line) - 1;
    struct Client cli_ref, cli_split;
    struct Connection con_ref, con_split;
    int trial;

    /* Whole-buffer reference run. */
    setup_client(&cli_ref, &con_ref);
    (void)recv_classify(&cli_ref, line, len);

    srand(0xC1A551F1);
    for (trial = 0; trial < 256; trial++) {
        unsigned int consumed = 0;
        setup_client(&cli_split, &con_split);
        while (consumed < len) {
            unsigned int chunk = (rand() % 7) + 1;
            if (consumed + chunk > len)
                chunk = len - consumed;
            (void)recv_classify(&cli_split, line + consumed, chunk);
            consumed += chunk;
        }
        assert_int_equal(con_recv_state(&con_ref),
                         con_recv_state(&con_split));
        assert_int_equal(con_recv_tag_bytes(&con_ref),
                         con_recv_tag_bytes(&con_split));
        assert_int_equal(con_recv_msg_bytes(&con_ref),
                         con_recv_msg_bytes(&con_split));
    }
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_simple_msg),
        cmocka_unit_test(test_msg_no_terminator),
        cmocka_unit_test(test_tag_then_msg),
        cmocka_unit_test(test_tagmsg_shape),

        cmocka_unit_test(test_client_tag_just_under_cap),
        cmocka_unit_test(test_client_tag_over_cap),
        cmocka_unit_test(test_client_msg_at_512),
        cmocka_unit_test(test_client_msg_over_512),

        cmocka_unit_test(test_server_tag_just_under_cap),
        cmocka_unit_test(test_server_tag_over_cap),
        cmocka_unit_test(test_server_msg_at_512),
        cmocka_unit_test(test_server_msg_over_512),

        cmocka_unit_test(test_split_feed_matches_whole),
        cmocka_unit_test(test_split_at_tag_boundary),
        cmocka_unit_test(test_split_mid_tag_overrun),

        cmocka_unit_test(test_back_to_back_lines),
        cmocka_unit_test(test_lone_lf),
        cmocka_unit_test(test_lone_cr),

        cmocka_unit_test(test_property_random_splits),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
