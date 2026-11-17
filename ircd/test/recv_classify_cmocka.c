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

/* ========== recv_clip(): a client's overlong line is cut, not fatal ========== */

/* Clip @a in (copied, since recv_clip() works in place) and return the
 * kept bytes' length in *out_len. */
static int
clip_copy(struct Client *cli, const char *in, unsigned int len, char *out,
          unsigned int *out_len)
{
    memcpy(out, in, len);
    *out_len = len;
    return recv_clip(cli, out, out_len);
}

static void test_clip_short_line_unchanged(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    const char line[] = "@a=b PRIVMSG #c :hi\r\nPING x\r\n";
    char out[64];
    unsigned int n;

    setup_client(&cli, &con);
    assert_int_equal(clip_copy(&cli, line, sizeof(line) - 1, out, &n),
                     RECV_CLASSIFY_OK);
    assert_int_equal(n, sizeof(line) - 1);
    assert_memory_equal(out, line, n);
}

static void test_clip_body_keeps_one_over_cap(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char line[2000], out[2000];
    unsigned int n;

    setup_client(&cli, &con);
    memset(line, 'A', 1000);
    memcpy(line + 1000, "\r\nPING x\r\n", 10);
    assert_int_equal(clip_copy(&cli, line, 1010, out, &n), RECV_CLASSIFY_OK);
    /* 513 body bytes kept: one over the cap marks the line as overlong
     * (recv_line_overlong()); the next line is whole. */
    assert_int_equal(n, 513 + 10);
    assert_memory_equal(out + 513, "\r\nPING x\r\n", 10);
    assert_int_equal(recv_line_overlong(&cli, out, 513), 1);
    assert_int_equal(recv_line_overlong(&cli, out + 515, 6), 0);
}

static void test_clip_tags_keep_one_over_cap(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char line[6000], out[6000];
    unsigned int n;

    setup_client(&cli, &con);
    line[0] = '@';
    memset(line + 1, 'x', 5000);
    memcpy(line + 5001, " PRIVMSG #c :hi\n", 16);
    assert_int_equal(clip_copy(&cli, line, 5017, out, &n), RECV_CLASSIFY_OK);
    assert_int_equal(n, 4096 + 16);
    assert_memory_equal(out + 4096, " PRIVMSG #c :hi\n", 16);
    assert_int_equal(recv_line_overlong(&cli, out, n - 1), 1);
}

static void test_clip_split_feed_matches_whole(void **state)
{
    (void)state;
    struct Client a, b;
    struct Connection ca, cb;
    static char line[3000], whole[3000], split[3000];
    unsigned int n, i, m, total = 0;

    setup_client(&a, &ca);
    setup_client(&b, &cb);
    memset(line, 'B', 2000);
    memcpy(line + 2000, "\nPING y\n", 8);
    assert_int_equal(clip_copy(&a, line, 2008, whole, &n), RECV_CLASSIFY_OK);
    for (i = 0; i < 2008; i += 7) {
        m = 2008 - i < 7 ? 2008 - i : 7;
        memcpy(split + total, line + i, m);
        assert_int_equal(recv_clip(&b, split + total, &m), RECV_CLASSIFY_OK);
        total += m;
    }
    assert_int_equal(total, n);
    assert_memory_equal(whole, split, n);
}

static void test_clip_at_cap_not_overlong(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char line[600], out[600];
    unsigned int n;

    setup_client(&cli, &con);
    memset(line, 'A', 512);
    line[512] = '\n';
    assert_int_equal(clip_copy(&cli, line, 513, out, &n), RECV_CLASSIFY_OK);
    assert_int_equal(n, 513);
    assert_int_equal(recv_line_overlong(&cli, out, 512), 0);
}

static void test_clip_endless_line_is_fatal(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char chunk[4096];
    unsigned int i, n;
    int r = RECV_CLASSIFY_OK;

    setup_client(&cli, &con);
    memset(chunk, 'Z', sizeof(chunk));
    /* A line that never ends is a flood, not a long message. */
    for (i = 0; i < 64 && r == RECV_CLASSIFY_OK; i++) {
        n = sizeof(chunk);
        r = recv_clip(&cli, chunk, &n);
    }
    assert_int_equal(r, RECV_CLASSIFY_MSG_OVERRUN);
}

static void test_overlong_tag_only_line(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char line[4200];

    setup_client(&cli, &con);
    line[0] = '@';
    memset(line + 1, 'x', 4095);
    assert_int_equal(recv_line_overlong(&cli, line, 4096), 1);
    assert_int_equal(recv_line_overlong(&cli, line, 4095), 0);
}

static void test_clip_split_inside_tags(void **state)
{
    (void)state;
    struct Client a, b;
    struct Connection ca, cb;
    static char line[6000], whole[6000], split[6000];
    unsigned int n, i, m, total = 0, step;

    for (step = 1; step < 9; step++) {
        setup_client(&a, &ca);
        setup_client(&b, &cb);
        total = 0;
        line[0] = '@';
        memset(line + 1, 't', 4500);
        memcpy(line + 4501, " PRIVMSG #c :", 13);
        memset(line + 4514, 'b', 700);
        memcpy(line + 5214, "\r\nPING z\r\n", 10);
        assert_int_equal(clip_copy(&a, line, 5224, whole, &n), RECV_CLASSIFY_OK);
        /* 4096 tag bytes, the space, 513 body bytes, then the next line. */
        assert_int_equal(n, 4096 + 1 + 513 + 10);
        for (i = 0; i < 5224; i += m) {
            m = 5224 - i < step * 997 ? 5224 - i : step * 997;
            memcpy(split + total, line + i, m);
            assert_int_equal(recv_clip(&b, split + total, &m), RECV_CLASSIFY_OK);
            total += m;
            m = 5224 - i < step * 997 ? 5224 - i : step * 997;
        }
        assert_int_equal(total, n);
        assert_memory_equal(whole, split, n);
    }
}

static void test_clip_fatal_boundary(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char chunk[65536];
    unsigned int n;

    setup_client(&cli, &con);
    memset(chunk, 'Z', sizeof(chunk));
    n = 65535;
    assert_int_equal(recv_clip(&cli, chunk, &n), RECV_CLASSIFY_OK);
    n = 1;
    assert_int_equal(recv_clip(&cli, chunk, &n), RECV_CLASSIFY_MSG_OVERRUN);
}

static void test_reset_forgets_line(void **state)
{
    (void)state;
    struct Client cli;
    struct Connection con;
    static char buf[1000];
    unsigned int n = 600;

    setup_client(&cli, &con);
    memset(buf, 'Q', 600);
    recv_clip(&cli, buf, &n);
    recv_classify_reset(&con);
    memcpy(buf, "PING a\n", 7);
    n = 7;
    assert_int_equal(recv_clip(&cli, buf, &n), RECV_CLASSIFY_OK);
    assert_int_equal(n, 7);
    assert_memory_equal(buf, "PING a\n", 7);
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

        cmocka_unit_test(test_clip_short_line_unchanged),
        cmocka_unit_test(test_clip_body_keeps_one_over_cap),
        cmocka_unit_test(test_clip_tags_keep_one_over_cap),
        cmocka_unit_test(test_clip_split_feed_matches_whole),
        cmocka_unit_test(test_clip_at_cap_not_overlong),
        cmocka_unit_test(test_clip_endless_line_is_fatal),
        cmocka_unit_test(test_overlong_tag_only_line),
        cmocka_unit_test(test_clip_split_inside_tags),
        cmocka_unit_test(test_clip_fatal_boundary),
        cmocka_unit_test(test_reset_forgets_line),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
