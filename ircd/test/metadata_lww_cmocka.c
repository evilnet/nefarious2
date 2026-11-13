/* cmocka suite for the pure LWW rule, HLC stamp text and MD wire codec
 * (include/metadata_lww.h). */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/metadata_lww.h"

static void test_stamp_roundtrip(void **state)
{
  struct md_stamp s;
  char buf[MD_STAMP_BUFSIZE];
  int n;

  (void)state;

  assert_int_equal(0, md_stamp_parse("1729781234567.3.42", &s));
  assert_true(s.ms == 1729781234567ULL);
  assert_int_equal(s.logical, 3);
  assert_int_equal(s.node, 42);

  n = md_stamp_format(buf, sizeof(buf), &s);
  assert_true(n > 0);
  assert_string_equal(buf, "1729781234567.3.42");
}

static void test_stamp_parse_rejects(void **state)
{
  static const char *const bad[] = {
    "", "1.2", "a.b.c", "1.65536.1", "1.1.65536", "1.2.3x", "-1.0.0"
  };
  struct md_stamp s;
  size_t i;

  (void)state;

  for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    assert_int_equal(-1, md_stamp_parse(bad[i], &s));
}

/* Review fix round 1, Important #2: md_stamp_parse's ms field used to
 * be checked with a post-hoc "v > max" guard where max == UINT64_MAX,
 * which can never fire no matter how far v has wrapped. A 20-digit ms
 * field over UINT64_MAX silently wrapped and was accepted instead of
 * rejected. */
static void test_stamp_parse_ms_overflow_rejected(void **state)
{
  struct md_stamp s;

  (void)state;

  /* Comfortably over UINT64_MAX (20 nines). */
  assert_int_equal(-1, md_stamp_parse("99999999999999999999.0.0", &s));
  /* Exactly UINT64_MAX + 1. */
  assert_int_equal(-1, md_stamp_parse("18446744073709551616.0.0", &s));
  /* Exactly UINT64_MAX is still a valid ms value and must be accepted. */
  assert_int_equal(0, md_stamp_parse("18446744073709551615.0.0", &s));
  assert_true(s.ms == 18446744073709551615ULL);
}

static void test_stamp_cmp_order(void **state)
{
  struct md_stamp a = { 5, 0, 9 };
  struct md_stamp b = { 5, 1, 0 };
  struct md_stamp c = { 6, 0, 0 };

  (void)state;

  assert_true(md_stamp_cmp(&a, &b) < 0);
  assert_true(md_stamp_cmp(&b, &c) < 0);
  assert_true(md_stamp_cmp(&a, &c) < 0);
  assert_true(md_stamp_cmp(&b, &a) > 0);
  assert_int_equal(0, md_stamp_cmp(&a, &a));
}

static void test_stamp_ahead_boundary(void **state)
{
  uint64_t now = 1000000;
  struct md_stamp at_limit = { now + 60000, 0, 0 };
  struct md_stamp past_limit = { now + 60001, 0, 0 };

  (void)state;

  assert_int_equal(0, md_stamp_ahead(&at_limit, now, 60000));
  assert_int_equal(1, md_stamp_ahead(&past_limit, now, 60000));
}

static void test_take_when_absent(void **state)
{
  struct md_version live = { { 5, 0, 0 }, 0, 0, "v", 1 };
  struct md_version tomb = { { 5, 0, 0 }, 1, 0, NULL, 0 };

  (void)state;

  assert_int_equal(1, md_lww_take(NULL, &live));
  assert_int_equal(1, md_lww_take(NULL, &tomb));
}

static void test_newer_wins_older_loses(void **state)
{
  struct md_version a = { { 5, 0, 0 }, 0, 0, "x", 1 };
  struct md_version b = { { 6, 0, 0 }, 0, 0, "y", 1 };

  (void)state;

  assert_int_equal(1, md_lww_take(&a, &b));
  assert_int_equal(0, md_lww_take(&b, &a));
}

static void test_later_delete_beats_set(void **state)
{
  struct md_version live5 = { { 5, 0, 0 }, 0, 0, "x", 1 };
  struct md_version tomb6 = { { 6, 0, 0 }, 1, 0, NULL, 0 };

  (void)state;

  assert_int_equal(1, md_lww_take(&live5, &tomb6));
}

static void test_later_set_beats_delete(void **state)
{
  struct md_version tomb5 = { { 5, 0, 0 }, 1, 0, NULL, 0 };
  struct md_version live6 = { { 6, 0, 0 }, 0, 0, "x", 1 };

  (void)state;

  assert_int_equal(1, md_lww_take(&tomb5, &live6));
}

static void test_equal_live_beats_tomb(void **state)
{
  struct md_version tomb5 = { { 5, 0, 0 }, 1, 0, NULL, 0 };
  struct md_version live5 = { { 5, 0, 0 }, 0, 0, "x", 1 };

  (void)state;

  assert_int_equal(1, md_lww_take(&tomb5, &live5));
  assert_int_equal(0, md_lww_take(&live5, &tomb5));
}

static void test_equal_value_tiebreak_symmetric(void **state)
{
  struct md_version a = { { 0, 0, 0 }, 0, 0, "abc", 3 };
  struct md_version b = { { 0, 0, 0 }, 0, 0, "abd", 3 };
  struct md_version ab = { { 0, 0, 0 }, 0, 0, "ab", 2 };
  struct md_version abc = { { 0, 0, 0 }, 0, 0, "abc", 3 };

  (void)state;

  assert_int_equal(1, md_lww_take(&a, &b));
  assert_int_equal(0, md_lww_take(&b, &a));

  /* "ab" vs "abc": the longer wins regardless of which side it's on. */
  assert_int_equal(1, md_lww_take(&ab, &abc));
  assert_int_equal(0, md_lww_take(&abc, &ab));
}

static void test_identical_keeps(void **state)
{
  struct md_version x = { { 5, 0, 0 }, 0, 0, "same", 4 };

  (void)state;

  assert_int_equal(0, md_lww_take(&x, &x));
}

static void test_clock_codec(void **state)
{
  struct md_stamp s = { 7, 1, 2 };
  char buf[MD_STAMP_BUFSIZE + 2];
  struct md_stamp out;
  int tomb;
  int n;

  (void)state;

  n = md_clock_encode(buf, sizeof(buf), &s, 0);
  assert_true(n > 0);
  assert_string_equal(buf, "L7.1.2");

  n = md_clock_encode(buf, sizeof(buf), &s, 1);
  assert_true(n > 0);
  assert_string_equal(buf, "D7.1.2");

  assert_int_equal(0, md_clock_decode("L7.1.2", strlen("L7.1.2"), &out, &tomb));
  assert_int_equal(tomb, 0);
  assert_true(out.ms == 7 && out.logical == 1 && out.node == 2);

  assert_int_equal(0, md_clock_decode("D7.1.2", strlen("D7.1.2"), &out, &tomb));
  assert_int_equal(tomb, 1);
  assert_true(out.ms == 7 && out.logical == 1 && out.node == 2);

  assert_int_equal(-1, md_clock_decode("X7.1.2", strlen("X7.1.2"), &out, &tomb));
  assert_int_equal(-1, md_clock_decode("L", strlen("L"), &out, &tomb));
  assert_int_equal(-1, md_clock_decode("", 0, &out, &tomb));
}

static void test_wire_keys(void **state)
{
  char longkey[65];
  char validpersist[71];
  char longpersist[139];
  size_t i, pos;
  const char *prefix1 = "draft/persistence/profile/";
  const char *suffix1 = "/auto-replay";
  const char *prefix2 = "draft/persistence/";

  (void)state;

  assert_int_equal(1, md_wire_key_valid("pronouns"));
  assert_int_equal(1, md_wire_key_valid("a.b-c/d_e"));
  assert_int_equal(0, md_wire_key_valid("1abc"));
  assert_int_equal(0, md_wire_key_valid(""));
  assert_int_equal(0, md_wire_key_valid("has space"));

  for (i = 0; i < 64; i++)
    longkey[i] = 'a';
  longkey[64] = '\0';
  assert_int_equal(0, md_wire_key_valid(longkey));

  pos = strlen(prefix1);
  memcpy(validpersist, prefix1, pos);
  for (i = 0; i < 32; i++)
    validpersist[pos++] = 'p';
  memcpy(validpersist + pos, suffix1, strlen(suffix1));
  pos += strlen(suffix1);
  validpersist[pos] = '\0';
  assert_int_equal((int)pos, 70);
  assert_int_equal(1, md_wire_key_valid(validpersist));

  pos = strlen(prefix2);
  memcpy(longpersist, prefix2, pos);
  for (i = 0; i < 120; i++)
    longpersist[pos++] = 'x';
  longpersist[pos] = '\0';
  assert_int_equal((int)pos, 138);
  assert_int_equal(0, md_wire_key_valid(longpersist));
}

static void test_classify_table(void **state)
{
  (void)state;

  assert_int_equal(MD_T_CHANNEL, md_target_classify("#c"));
  assert_int_equal(MD_T_CHANNEL, md_target_classify("&c"));
  assert_int_equal(MD_T_ACCOUNT, md_target_classify("*acct"));
  assert_int_equal(MD_T_ACCOUNT_STAMPED, md_target_classify("=acct"));
  assert_int_equal(MD_T_SESSION, md_target_classify("!Ab+/9"));
  assert_int_equal(MD_T_PULL, md_target_classify("?"));
  assert_int_equal(MD_T_PULL_END, md_target_classify("."));
  assert_int_equal(MD_T_INVALID, md_target_classify("*"));
  assert_int_equal(MD_T_INVALID, md_target_classify("="));
  assert_int_equal(MD_T_INVALID, md_target_classify("!"));
  assert_int_equal(MD_T_INVALID, md_target_classify(""));
  assert_int_equal(MD_T_INVALID, md_target_classify("?x"));
  assert_int_equal(MD_T_INVALID, md_target_classify(".x"));
  assert_int_equal(MD_T_NICK, md_target_classify("Nick[1]"));
}

static void test_flags_table(void **state)
{
  int vis, tomb, more;

  (void)state;

  assert_int_equal(0, md_flags_parse("*", &vis, &tomb, &more));
  assert_int_equal(vis, 0);
  assert_int_equal(tomb, 0);
  assert_int_equal(more, 0);

  assert_int_equal(0, md_flags_parse("P", &vis, &tomb, &more));
  assert_int_equal(vis, 1);
  assert_int_equal(tomb, 0);
  assert_int_equal(more, 0);

  assert_int_equal(0, md_flags_parse("D", &vis, &tomb, &more));
  assert_int_equal(tomb, 1);
  assert_int_equal(more, 0);

  assert_int_equal(0, md_flags_parse("*+", &vis, &tomb, &more));
  assert_int_equal(vis, 0);
  assert_int_equal(tomb, 0);
  assert_int_equal(more, 1);

  assert_int_equal(0, md_flags_parse("P+", &vis, &tomb, &more));
  assert_int_equal(vis, 1);
  assert_int_equal(tomb, 0);
  assert_int_equal(more, 1);

  assert_int_equal(-1, md_flags_parse("D+", &vis, &tomb, &more));
  assert_int_equal(-1, md_flags_parse("x", &vis, &tomb, &more));
  assert_int_equal(-1, md_flags_parse("", &vis, &tomb, &more));
}

static void test_chunk_three_pieces(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "key1", 0, 1, "aaa"));
  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "key1", 0, 1, "bbb"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "key1", 0, 0, "cc"));
  assert_string_equal(c.value, "aaabbbcc");
  assert_int_equal(c.dropped, 0);
}

static void test_chunk_single_line(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "key1", 0, 0, "v"));
  assert_string_equal(c.value, "v");
}

static void test_chunk_mismatch_restarts(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "xxx"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k2", 0, 0, "yyy"));
  assert_string_equal(c.value, "yyy");
  assert_int_equal(c.dropped, 1);
}

static void test_chunk_overflow(void **state)
{
  struct md_chunk c;
  char piece[1024];

  (void)state;
  memset(&c, 0, sizeof(c));
  memset(piece, 'z', sizeof(piece));
  piece[sizeof(piece) - 1] = '\0'; /* 1023 'z' bytes */

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, piece));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "x"));
  assert_int_equal(c.active, 0);
}

/* Final push-1 review M1(a): after an overflow, the rest of that row's
 * pieces must not assemble a tail that the final piece then hands back
 * as the whole value. The row stays poisoned until its own more=0
 * piece; the next row (even one with the same identity) is clean. */
static void test_chunk_overflow_discards_rest_of_row(void **state)
{
  struct md_chunk c;
  char piece[1024];

  (void)state;
  memset(&c, 0, sizeof(c));
  memset(piece, 'z', sizeof(piece));
  piece[sizeof(piece) - 1] = '\0'; /* 1023 'z' bytes */

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, piece));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "x"));
  /* The rest of the overflowed row: swallowed, never a fresh start. */
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "tail1"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "tail2"));
  assert_int_equal(c.active, 0);
  /* Its more=0 piece ended the poison: the next row is taken. */
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "whole"));
  assert_string_equal(c.value, "whole");
}

/* An overflow on the row's own final piece leaves nothing to discard. */
static void test_chunk_overflow_on_final_piece_no_poison(void **state)
{
  struct md_chunk c;
  char piece[1024];

  (void)state;
  memset(&c, 0, sizeof(c));
  memset(piece, 'z', sizeof(piece));
  piece[sizeof(piece) - 1] = '\0';

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, piece));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "x"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "v"));
  assert_string_equal(c.value, "v");
}

/* M1(b), an orphaned row: a row whose accumulation another row's line
 * interrupted. Its later pieces are discarded, not merged as a tail. */
static void test_chunk_mismatch_discards_rest_of_abandoned_row(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "head"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k2", 0, 0, "other"));
  assert_int_equal(c.dropped, 1);
  assert_string_equal(c.value, "other");
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "mid"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "end"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "whole"));
  assert_string_equal(c.value, "whole");
}

/* W4 push-1 fix-wave N3(a): nested interruptions.  X is interrupted by
 * Y, Y by Z: each interrupted row keeps its own poison, so X's tail is
 * swallowed rather than merged as X's whole value (one poison slot let
 * Y's poison overwrite X's), and Z's pending value survives the
 * swallowed tails. */
static void test_chunk_nested_interrupts_discard_each_row(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "kx", 0, 1, "xh"));
  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "ky", 0, 1, "yh"));
  assert_int_equal(c.dropped, 1);
  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "kz", 0, 1, "zh"));
  assert_int_equal(c.dropped, 1);
  /* X's tail: swallowed, not handed back as X's whole value. */
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "kx", 0, 0, "xt"));
  /* Y's tail: swallowed too. */
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "ky", 0, 0, "yt"));
  /* Z was never interrupted: it completes whole. */
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "kz", 0, 0, "zt"));
  assert_string_equal(c.value, "zhzt");
  /* The tails ended both poisons: fresh deliveries of X and Y are taken. */
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "kx", 0, 0, "xw"));
  assert_string_equal(c.value, "xw");
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "ky", 0, 0, "yw"));
  assert_string_equal(c.value, "yw");
}

/* N3(a), at the slot count: MD_CHUNK_POISON_SLOTS rows interrupted in a
 * chain each keep their poison; every one of their tails is swallowed. */
static void test_chunk_poison_slots_hold_a_chain(void **state)
{
  struct md_chunk c;
  char key[8];
  int i;

  (void)state;
  memset(&c, 0, sizeof(c));

  /* Rows k0..kN, each head interrupting the one before: k0..k(N-1) are
   * poisoned, kN is pending. */
  for (i = 0; i <= MD_CHUNK_POISON_SLOTS; i++) {
    snprintf(key, sizeof(key), "k%d", i);
    assert_int_equal(MD_CHUNK_PENDING,
                     md_chunk_feed(&c, "acct", "7.0.1", key, 0, 1, "h"));
  }
  for (i = 0; i < MD_CHUNK_POISON_SLOTS; i++) {
    snprintf(key, sizeof(key), "k%d", i);
    assert_int_equal(MD_CHUNK_ERROR,
                     md_chunk_feed(&c, "acct", "7.0.1", key, 0, 0, "t"));
  }
  snprintf(key, sizeof(key), "k%d", MD_CHUNK_POISON_SLOTS);
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", key, 0, 0, "t"));
  assert_string_equal(c.value, "ht");
}

/* A piece of the pending row that disagrees on visibility is the same
 * row (account, stamp, key) arriving inconsistent: the whole row goes. */
static void test_chunk_vis_flip_discards_row(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "aaa"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 1, 1, "bbb"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "cc"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "v"));
  assert_string_equal(c.value, "v");
}

/* md_chunk_abandon: a caller-side refusal of one piece (e.g. a bad
 * flags token) that says more pieces follow (more=1) discards the
 * pending row it belongs to and the rest of that row -- whether a value
 * was pending or not. */
static void test_chunk_abandon_discards_row(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "aaa"));
  md_chunk_abandon(&c, "acct", "7.0.1", "k1", 1);
  assert_int_equal(c.active, 0);
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "cc"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "v"));

  /* A refused head: nothing pending yet, the rest still goes. */
  md_chunk_abandon(&c, "acct", "8.0.1", "k2", 1);
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "8.0.1", "k2", 0, 1, "p2"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "8.0.1", "k2", 0, 0, "p3"));
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "8.0.1", "k2", 0, 0, "w"));
  assert_string_equal(c.value, "w");

  /* Abandoning another row leaves a pending one alone. */
  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "9.0.1", "k3", 0, 1, "aa"));
  md_chunk_abandon(&c, "acct", "9.0.1", "zz", 1);
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "9.0.1", "k3", 0, 0, "bb"));
  assert_string_equal(c.value, "aabb");
}

/* W4 push-1 fix-wave N3(b): a refused piece that is its row's final
 * (or only) one (more=0) leaves nothing to discard after it.  The
 * pending value of that row goes, but the row is not poisoned: the next
 * delivery of the same (account, stamp, key) -- a re-send, a pull
 * reply -- is taken, not swallowed once. */
static void test_chunk_abandon_final_piece_no_poison(void **state)
{
  struct md_chunk c;

  (void)state;
  memset(&c, 0, sizeof(c));

  /* A refused only piece. */
  md_chunk_abandon(&c, "acct", "10.0.1", "k4", 0);
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "10.0.1", "k4", 0, 0, "v"));
  assert_string_equal(c.value, "v");

  /* A refused final piece of a pending row: the head is dropped (never
   * completed into "aa" + the next delivery), and the next delivery of
   * the row is taken whole. */
  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "11.0.1", "k5", 0, 1, "aa"));
  md_chunk_abandon(&c, "acct", "11.0.1", "k5", 0);
  assert_int_equal(c.active, 0);
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "11.0.1", "k5", 0, 0, "w"));
  assert_string_equal(c.value, "w");
}

/* M2: an identity field that does not fit its buffer (an account over
 * ACCOUNTLEN, a stamp text over MD_STAMP_BUFSIZE - 1) is refused, never
 * truncated into a name that could match another row's, and the
 * pending row is left alone. */
static void test_chunk_rejects_oversize_identity(void **state)
{
  struct md_chunk c;
  char longkey[200];

  (void)state;
  memset(&c, 0, sizeof(c));
  memset(longkey, 'k', sizeof(longkey));
  longkey[sizeof(longkey) - 1] = '\0';

  assert_int_equal(MD_CHUNK_PENDING,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 1, "aaa"));
  /* 16 chars: one over ACCOUNTLEN; would truncate to "acct567890123456"'s
   * first 15 and could pass for that account's row. */
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct567890123456", "7.0.1", "k1", 0, 0, "x"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "12345678901234567890.65535.65535", "k1", 0, 0, "x"));
  assert_int_equal(MD_CHUNK_ERROR,
                   md_chunk_feed(&c, "acct", "7.0.1", longkey, 0, 0, "x"));
  assert_int_equal(c.active, 1);
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct", "7.0.1", "k1", 0, 0, "b"));
  assert_string_equal(c.value, "aaab");
  /* Exactly 15 is a valid account. */
  assert_int_equal(MD_CHUNK_DONE,
                   md_chunk_feed(&c, "acct56789012345", "7.0.1", "k1", 0, 0, "y"));
}

/* M2: a stamp text of MD_STAMP_BUFSIZE (32) characters or more -- a
 * 20-digit ms with both 16-bit fields at five digits -- cannot be
 * formatted back, kept as a chunk identity or clock-encoded into the
 * buffers sized from MD_STAMP_BUFSIZE, so it is malformed. 31 is fine. */
static void test_stamp_parse_rejects_over_bufsize(void **state)
{
  struct md_stamp s;
  char buf[MD_STAMP_BUFSIZE];
  char clk[MD_STAMP_BUFSIZE + 1];

  (void)state;

  assert_int_equal(-1, md_stamp_parse("12345678901234567890.65535.65535", &s));
  assert_int_equal(-1, md_stamp_parse("00000000000000000001.00000.00000", &s));
  assert_int_equal(0, md_stamp_parse("1234567890123456789.65535.65535", &s));
  assert_true(md_stamp_format(buf, sizeof(buf), &s) == 31);
  assert_true(md_clock_encode(clk, sizeof(clk), &s, 0) == 32);
}

static void test_pull_parse_ok(void **state)
{
  char cmd[] = "MD", tgt[] = "?", seqs[] = "7", scope_s[] = "A";
  char names[] = "acct1,acct2";
  char *parv[5];
  char *accounts[16];
  unsigned long seq;
  char scope;
  int n;

  (void)state;

  parv[0] = cmd;
  parv[1] = tgt;
  parv[2] = seqs;
  parv[3] = scope_s;
  parv[4] = names;

  n = md_pull_parse(5, parv, &seq, &scope, accounts, 16);
  assert_int_equal(n, 2);
  assert_true(seq == 7);
  assert_int_equal(scope, 'A');
  assert_string_equal(accounts[0], "acct1");
  assert_string_equal(accounts[1], "acct2");
}

static void test_pull_parse_rejects(void **state)
{
  char *accounts[20];
  unsigned long seq;
  char scope;
  char cmd[] = "MD", tgt[] = "?";

  (void)state;

  /* scope "X" */
  {
    char seqs[] = "7", scope_s[] = "X", names[] = "acct1";
    char *parv[5] = { cmd, tgt, seqs, scope_s, names };
    assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 16));
  }

  /* seq "7x" */
  {
    char seqs[] = "7x", scope_s[] = "A", names[] = "acct1";
    char *parv[5] = { cmd, tgt, seqs, scope_s, names };
    assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 16));
  }

  /* 17 names */
  {
    char seqs[] = "7", scope_s[] = "A";
    char names[] = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q";
    char *parv[5] = { cmd, tgt, seqs, scope_s, names };
    assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 20));
  }

  /* a 16-char name */
  {
    char seqs[] = "7", scope_s[] = "A";
    char names[] = "aaaaaaaaaaaaaaaa,b";
    char *parv[5] = { cmd, tgt, seqs, scope_s, names };
    assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 20));
  }

  /* empty list */
  {
    char seqs[] = "7", scope_s[] = "A", names[] = "";
    char *parv[5] = { cmd, tgt, seqs, scope_s, names };
    assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 16));
  }
}

/* Review fix round 1, Critical #1: an empty scope token used to be read
 * at parv[3][1] before confirming parv[3][0] wasn't already the
 * terminating NUL -- a one-byte out-of-bounds read on exactly this
 * input (reproduced with ASan against the pre-fix code). scope_s is
 * sized to exactly one byte (just the NUL), matching the ASan repro,
 * so any OOB read here is as directly exercised as a stack-allocated
 * C string can make it. */
static void test_pull_parse_empty_scope_no_oob(void **state)
{
  char *accounts[16];
  unsigned long seq;
  char scope;
  char cmd[] = "MD", tgt[] = "?", seqs[] = "7", scope_s[] = "", names[] = "acct1";
  char *parv[5] = { cmd, tgt, seqs, scope_s, names };

  (void)state;

  assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 16));
}

/* Review fix round 1, Important #3: parv[2]'s sequence number was
 * parsed by a second, unguarded hand-rolled loop (not
 * md_parse_uint_field), so a 20-digit seq silently wrapped instead of
 * being rejected. */
static void test_pull_parse_seq_overflow_rejected(void **state)
{
  char *accounts[16];
  unsigned long seq;
  char scope;
  char cmd[] = "MD", tgt[] = "?";
  char seqs[] = "99999999999999999999", scope_s[] = "A", names[] = "acct1";
  char *parv[5] = { cmd, tgt, seqs, scope_s, names };

  (void)state;

  assert_int_equal(-1, md_pull_parse(5, parv, &seq, &scope, accounts, 16));
}

/* ------------------------------------------------------------------ */
/* md_topn_place (fix round 1, 2026-11-02)                             */
/* ------------------------------------------------------------------ */

/* A tiny driver that applies md_topn_place the way
 * mdsync_row_select_cb (ircd/metadata_sync.c) will: insert-or-discard,
 * shifting the caller's own array by the returned index. The real
 * caller also shifts a parallel payload array (key/value/vis/tombstone)
 * in lockstep; these pure tests only need the stamps themselves. */
static void topn_apply(struct md_stamp *kept, int *count, int cap,
                        const struct md_stamp *incoming)
{
  int idx = md_topn_place(kept, *count, cap, incoming);
  int i;

  if (idx < 0)
    return;

  if (*count < cap) {
    for (i = *count; i > idx; i--)
      kept[i] = kept[i - 1];
    (*count)++;
  } else {
    for (i = 0; i < idx; i++)
      kept[i] = kept[i + 1];
  }
  kept[idx] = *incoming;
}

static void test_topn_fewer_than_cap(void **state)
{
  struct md_stamp kept[8];
  int count = 0;
  struct md_stamp s1 = { 5, 0, 0 }, s2 = { 3, 0, 0 }, s3 = { 9, 0, 0 };

  (void)state;

  topn_apply(kept, &count, 8, &s1);
  topn_apply(kept, &count, 8, &s2);
  topn_apply(kept, &count, 8, &s3);

  assert_int_equal(3, count);
  assert_true(kept[0].ms == 3);
  assert_true(kept[1].ms == 5);
  assert_true(kept[2].ms == 9);
}

static void test_topn_exactly_cap(void **state)
{
  struct md_stamp kept[4];
  int count = 0;
  int i;

  (void)state;

  /* Inserted newest-first (10,9,8,7): no eviction should ever trigger
   * since count never exceeds cap, and the kept array must still end
   * up ascending. */
  for (i = 0; i < 4; i++) {
    struct md_stamp s;
    s.ms = (uint64_t)(10 - i);
    s.logical = 0;
    s.node = 0;
    topn_apply(kept, &count, 4, &s);
  }

  assert_int_equal(4, count);
  assert_true(kept[0].ms == 7);
  assert_true(kept[1].ms == 8);
  assert_true(kept[2].ms == 9);
  assert_true(kept[3].ms == 10);
}

/* The exact shape of the row-cap bug (fix round 1): a raw key-order
 * walk can deliver the truly newest row LAST, long after the cap is
 * already full of older ones. md_topn_place must still let it evict
 * the current oldest kept row instead of being discarded outright. */
static void test_topn_more_than_cap_newest_last(void **state)
{
  struct md_stamp kept[3];
  int count = 0;
  struct md_stamp s1 = { 1, 0, 0 }, s2 = { 2, 0, 0 }, s3 = { 3, 0, 0 };
  struct md_stamp newest = { 100, 0, 0 };

  (void)state;

  topn_apply(kept, &count, 3, &s1);
  topn_apply(kept, &count, 3, &s2);
  topn_apply(kept, &count, 3, &s3);
  assert_int_equal(3, count);

  topn_apply(kept, &count, 3, &newest);

  assert_int_equal(3, count);
  assert_true(kept[0].ms == 2);
  assert_true(kept[1].ms == 3);
  assert_true(kept[2].ms == 100);
}

static void test_topn_ties(void **state)
{
  struct md_stamp kept[2];
  int count = 0;
  struct md_stamp a = { 5, 0, 0 }, b = { 5, 0, 0 }, c = { 5, 0, 0 };

  (void)state;

  topn_apply(kept, &count, 2, &a);
  topn_apply(kept, &count, 2, &b);
  assert_int_equal(2, count);

  /* Full, and c ties the current minimum (kept[0], stamp 5) exactly --
   * not strictly newer, so discarded outright; the kept array is left
   * untouched. */
  assert_int_equal(-1, md_topn_place(kept, count, 2, &c));
  assert_true(kept[0].ms == 5 && kept[1].ms == 5);
}

/* A row with no clock entry at all defaults to stamp 0.0.0 -- the
 * controller ruling's "counts as oldest" rule. */
static void test_topn_unstamped_is_oldest(void **state)
{
  struct md_stamp kept[2];
  int count = 0;
  struct md_stamp unstamped = { 0, 0, 0 };
  struct md_stamp real = { 1, 0, 0 };
  struct md_stamp newer = { 2, 0, 0 };

  (void)state;

  topn_apply(kept, &count, 2, &unstamped);
  topn_apply(kept, &count, 2, &real);
  assert_int_equal(2, count);
  assert_true(kept[0].ms == 0);
  assert_true(kept[1].ms == 1);

  /* Cap full; a newer row must evict the unstamped one, not the real
   * one -- 0.0.0 is the oldest, so it's the one at kept[0]. */
  topn_apply(kept, &count, 2, &newer);
  assert_int_equal(2, count);
  assert_true(kept[0].ms == 1);
  assert_true(kept[1].ms == 2);
}

/* ------------------------------------------------------------------ */
/* md_topn_insert (push-2 final fix wave, M-4)                         */
/* ------------------------------------------------------------------ */

/* The caller's payload pool, as mdsync_row_select_cb keeps it: one
 * entry per pool slot, written once when md_topn_insert hands that slot
 * out and never moved after.  Here the payload is the stamp's ms, so a
 * test can check that slot[] still names the right payload for each
 * ordered position. */
static void topn_insert_apply(struct md_stamp *kept, int *slot, int *count,
                              int cap, uint64_t *pool,
                              const struct md_stamp *incoming)
{
  int ps = md_topn_insert(kept, slot, count, cap, incoming);

  if (ps >= 0)
    pool[ps] = incoming->ms;
}

/* Every ordered position's payload is its stamp, and the slots used are
 * a permutation of 0..count-1 (no slot handed out twice, none lost). */
static void topn_insert_check(const struct md_stamp *kept, const int *slot,
                              int count, const uint64_t *pool)
{
  int seen[64] = { 0 };
  int i;

  for (i = 0; i < count; i++) {
    assert_true(slot[i] >= 0 && slot[i] < count);
    assert_int_equal(0, seen[slot[i]]);
    seen[slot[i]] = 1;
    assert_true(pool[slot[i]] == kept[i].ms);
    if (i > 0)
      assert_true(md_stamp_cmp(&kept[i - 1], &kept[i]) <= 0);
  }
}

static void test_topn_insert_fill(void **state)
{
  struct md_stamp kept[8];
  int slot[8];
  uint64_t pool[8];
  int count = 0;
  struct md_stamp s1 = { 5, 0, 0 }, s2 = { 3, 0, 0 }, s3 = { 9, 0, 0 };

  (void)state;

  topn_insert_apply(kept, slot, &count, 8, pool, &s1);
  topn_insert_apply(kept, slot, &count, 8, pool, &s2);
  topn_insert_apply(kept, slot, &count, 8, pool, &s3);

  assert_int_equal(3, count);
  assert_true(kept[0].ms == 3 && kept[1].ms == 5 && kept[2].ms == 9);
  /* Below the cap a row takes the next unused slot: 5 -> 0, 3 -> 1,
   * 9 -> 2, whatever its ordered position. */
  assert_int_equal(1, slot[0]);
  assert_int_equal(0, slot[1]);
  assert_int_equal(2, slot[2]);
  topn_insert_check(kept, slot, count, pool);
}

/* Full: the newest-last shape of the row-cap bug.  The evicted row's
 * slot is the one handed back, and nothing else moves in the pool. */
static void test_topn_insert_evicts_into_oldest_slot(void **state)
{
  struct md_stamp kept[3];
  int slot[3];
  uint64_t pool[3];
  int count = 0;
  struct md_stamp s1 = { 1, 0, 0 }, s2 = { 2, 0, 0 }, s3 = { 3, 0, 0 };
  struct md_stamp mid = { 2, 5, 0 }, newest = { 100, 0, 0 }, old = { 0, 1, 0 };
  int oldest_slot;

  (void)state;

  topn_insert_apply(kept, slot, &count, 3, pool, &s3);
  topn_insert_apply(kept, slot, &count, 3, pool, &s1);
  topn_insert_apply(kept, slot, &count, 3, pool, &s2);
  assert_int_equal(3, count);
  topn_insert_check(kept, slot, count, pool);

  oldest_slot = slot[0];
  assert_int_equal(oldest_slot, md_topn_insert(kept, slot, &count, 3, &newest));
  pool[oldest_slot] = newest.ms;
  assert_int_equal(3, count);
  assert_true(kept[0].ms == 2 && kept[1].ms == 3 && kept[2].ms == 100);
  topn_insert_check(kept, slot, count, pool);

  /* A row landing in the middle evicts the oldest too. */
  topn_insert_apply(kept, slot, &count, 3, pool, &mid);
  assert_true(kept[0].ms == 2 && kept[0].logical == 5);
  assert_true(kept[1].ms == 3 && kept[2].ms == 100);
  topn_insert_check(kept, slot, count, pool);

  /* Not newer than the oldest kept: discarded, nothing changes. */
  assert_int_equal(-1, md_topn_insert(kept, slot, &count, 3, &old));
  assert_int_equal(3, count);
  topn_insert_check(kept, slot, count, pool);
}

/* A long ascending walk (the worst case for the old whole-row shift):
 * the newest cap rows survive, every pool slot stays in use once. */
static void test_topn_insert_ascending_walk(void **state)
{
  struct md_stamp kept[16];
  int slot[16];
  uint64_t pool[16];
  int count = 0;
  int i;

  (void)state;

  for (i = 1; i <= 200; i++) {
    struct md_stamp s;

    s.ms = (uint64_t)i;
    s.logical = 0;
    s.node = 0;
    topn_insert_apply(kept, slot, &count, 16, pool, &s);
  }
  assert_int_equal(16, count);
  for (i = 0; i < 16; i++)
    assert_true(kept[i].ms == (uint64_t)(185 + i));
  topn_insert_check(kept, slot, count, pool);
}

static void test_topn_insert_rejects_bad_args(void **state)
{
  struct md_stamp kept[2];
  int slot[2];
  int count = 0;
  struct md_stamp s = { 1, 0, 0 };

  (void)state;

  assert_int_equal(-1, md_topn_insert(NULL, slot, &count, 2, &s));
  assert_int_equal(-1, md_topn_insert(kept, NULL, &count, 2, &s));
  assert_int_equal(-1, md_topn_insert(kept, slot, NULL, 2, &s));
  assert_int_equal(-1, md_topn_insert(kept, slot, &count, 0, &s));
  assert_int_equal(-1, md_topn_insert(kept, slot, &count, 2, NULL));
  count = 3;
  assert_int_equal(-1, md_topn_insert(kept, slot, &count, 2, &s));
}

/* ------------------------------------------------------------------ */
/* md_key_replicable (push-2 final fix wave, M-2)                      */
/* ------------------------------------------------------------------ */

static void test_key_replicable(void **state)
{
  char longkey[65];
  size_t i;

  (void)state;

  /* The user's own keys and the mode-synced / persistence keys travel. */
  assert_int_equal(1, md_key_replicable("pronouns"));
  assert_int_equal(1, md_key_replicable("umode.invisible"));
  assert_int_equal(1, md_key_replicable("draft/persistence/hold"));
  assert_int_equal(1, md_key_replicable("draft/persistence/profile/x/auto-replay"));
  /* last_present is this server's own observation (a TTL row): never
   * replicated or cleared, in any case. */
  assert_int_equal(0, md_key_replicable("last_present"));
  assert_int_equal(0, md_key_replicable("LAST_PRESENT"));
  assert_int_equal(1, md_key_replicable("last_present2"));
  assert_int_equal(1, md_key_replicable("last_presen"));
  /* A key the wire validator refuses never goes out either. */
  assert_int_equal(0, md_key_replicable(NULL));
  assert_int_equal(0, md_key_replicable(""));
  assert_int_equal(0, md_key_replicable("1abc"));
  assert_int_equal(0, md_key_replicable("has space"));
  for (i = 0; i < 64; i++)
    longkey[i] = 'a';
  longkey[64] = '\0';
  assert_int_equal(0, md_key_replicable(longkey));
}

/* A taken row that says what the replaced one said (owner 2026-11-13:
 * fork peers skip the announcement for an unchanged row): same value and
 * visibility, or tombstone over tombstone, stamps aside. */
static void test_same_content(void **state)
{
  struct md_version a, b;

  (void)state;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));
  a.st.ms = 1; b.st.ms = 2;
  a.value = "same"; a.vlen = 4;
  b.value = "same"; b.vlen = 4;
  assert_int_equal(1, md_version_same_content(&a, &b));
  b.vis = 1;                                   /* another visibility */
  assert_int_equal(0, md_version_same_content(&a, &b));
  b.vis = 0;
  b.value = "samf";                            /* another value */
  assert_int_equal(0, md_version_same_content(&a, &b));
  b.value = "same!"; b.vlen = 5;               /* a longer one */
  assert_int_equal(0, md_version_same_content(&a, &b));
  a.value = ""; a.vlen = 0; b.value = ""; b.vlen = 0;   /* both empty */
  assert_int_equal(1, md_version_same_content(&a, &b));
  b.tombstone = 1; b.value = NULL;             /* live vs tombstone */
  assert_int_equal(0, md_version_same_content(&a, &b));
  a.tombstone = 1; a.value = NULL;             /* two tombstones */
  assert_int_equal(1, md_version_same_content(&a, &b));
  assert_int_equal(0, md_version_same_content(NULL, &b));
}

/* For the notification only (third review): a row taken over no row
 * changes nothing a subscriber saw when it is a tombstone, and is news
 * when it is live; over a row, the same content is no news. */
static void test_row_unchanged(void **state)
{
  struct md_version live, live2, tomb;

  (void)state;
  memset(&live, 0, sizeof(live));
  memset(&tomb, 0, sizeof(tomb));
  live.value = "v"; live.vlen = 1; live.st.ms = 1;
  live2 = live; live2.st.ms = 2;
  tomb.tombstone = 1; tomb.st.ms = 3;
  assert_int_equal(1, md_row_unchanged(NULL, &tomb));    /* absent -> tombstone */
  assert_int_equal(0, md_row_unchanged(NULL, &live));    /* absent -> live: news */
  assert_int_equal(0, md_row_unchanged(&live, &tomb));   /* live -> tombstone: news */
  assert_int_equal(1, md_row_unchanged(&live, &live2));  /* same content */
  assert_int_equal(1, md_row_unchanged(&tomb, &tomb));   /* tombstone over tombstone */
  assert_int_equal(0, md_row_unchanged(&tomb, &live));   /* tombstone -> live: news */
  assert_int_equal(0, md_row_unchanged(&live, NULL));
}

/* The owner's rule for a local write (2026-11-13: "it should be silent,
 * nothing changed"): md_row_unchanged() of the row before and the write. */
static void test_local_write_unchanged(void **state)
{
  struct md_version stored, set_same, set_other, set_private, unset;

  (void)state;
  memset(&stored, 0, sizeof(stored));
  stored.value = "v"; stored.vlen = 1; stored.st.ms = 100;
  set_same = stored; set_same.st.ms = 200;
  set_other = set_same; set_other.value = "w";
  set_private = set_same; set_private.vis = 1;
  memset(&unset, 0, sizeof(unset));
  unset.tombstone = 1; unset.st.ms = 200;
  assert_int_equal(1, md_row_unchanged(&stored, &set_same));     /* same value: silent */
  assert_int_equal(0, md_row_unchanged(&stored, &set_other));    /* another value: told */
  assert_int_equal(0, md_row_unchanged(&stored, &set_private));  /* visibility only: told */
  assert_int_equal(1, md_row_unchanged(NULL, &unset));           /* unset of no row: silent */
  stored.tombstone = 1; stored.value = NULL; stored.vlen = 0;
  assert_int_equal(1, md_row_unchanged(&stored, &unset));        /* unset of a deleted key */
  assert_int_equal(0, md_row_unchanged(NULL, &set_same));        /* a first value: told */
}

/* The CLEAR floor (owner, 2026-11-13). */
static void test_clear_floor(void **state)
{
  struct md_stamp floor = { 1000000, 0, 1 };   /* 1000 s */
  struct md_stamp later = { 2000000, 0, 1 };
  struct md_version older, newer, tomb, equal;

  (void)state;
  memset(&older, 0, sizeof(older));
  older.value = "v"; older.vlen = 1; older.st.ms = 900000;   /* 100 s before */
  newer = older; newer.st.ms = 1001000;
  equal = older; equal.st = floor;
  tomb = older; tomb.tombstone = 1; tomb.value = NULL; tomb.vlen = 0;

  /* older live -> converted; newer, equal and tombstones untouched */
  assert_int_equal(1, md_floor_converts(&floor, &older, 1, 1500, 0));
  assert_int_equal(0, md_floor_converts(&floor, &newer, 1, 1500, 0));
  assert_int_equal(0, md_floor_converts(&floor, &equal, 1, 1500, 0));
  assert_int_equal(0, md_floor_converts(&floor, &tomb, 1, 1500, 0));
  /* a server-managed or internal key is not the CLEAR's */
  assert_int_equal(0, md_floor_converts(&floor, &older, 0, 1500, 0));
  /* no floor */
  assert_int_equal(0, md_floor_converts(NULL, &older, 1, 1500, 0));
  /* expiry with the tombstones: in force through 1000 + ttl, not after */
  assert_int_equal(1, md_floor_in_force(&floor, 1100, 100));
  assert_int_equal(0, md_floor_in_force(&floor, 1101, 100));
  assert_int_equal(0, md_floor_converts(&floor, &older, 1, 1101, 100));
  assert_int_equal(1, md_floor_in_force(&floor, 999999, 0));   /* ttl 0: never */
  /* raised by a later CLEAR, never lowered */
  assert_int_equal(1, md_floor_raises(NULL, &floor));
  assert_int_equal(1, md_floor_raises(&floor, &later));
  assert_int_equal(0, md_floor_raises(&later, &floor));
  assert_int_equal(0, md_floor_raises(&floor, &floor));
}

/* Review c1: the margin.  A row older than the floor by more than
 * MD_FLOOR_MARGIN_MS is converted; one within it (a write just after the
 * CLEAR on a server whose clock lags, or one just before it) is not; a
 * floor nearer the epoch than the margin converts nothing. */
static void test_floor_margin(void **state)
{
  struct md_stamp floor = { 1000000, 0, 1 };
  struct md_stamp tiny = { 30000, 0, 1 };
  struct md_version row;

  (void)state;
  memset(&row, 0, sizeof(row));
  row.value = "v"; row.vlen = 1;
  row.st.ms = 1000000 - MD_FLOOR_MARGIN_MS - 1;       /* just past the margin */
  assert_int_equal(1, md_floor_converts(&floor, &row, 1, 1500, 0));
  row.st.ms = 1000000 - MD_FLOOR_MARGIN_MS;           /* on the edge: kept */
  assert_int_equal(0, md_floor_converts(&floor, &row, 1, 1500, 0));
  row.st.ms = 1000000 - 5000;                          /* a lagging clock's "after" */
  assert_int_equal(0, md_floor_converts(&floor, &row, 1, 1500, 0));
  row.st.ms = 0;
  assert_int_equal(0, md_floor_converts(&tiny, &row, 1, 100, 0));
}

/* No loop: a floor tombstone arriving over an equal-stamp tombstone (its
 * own echo, or another server's conversion of the same CLEAR) is kept,
 * not taken -- so not relayed; between two floors the later one wins.
 * Stamps order by ms, then the logical counter, then the node
 * (md_stamp_cmp()); only a stamp equal in all three is a tie, and an equal
 * pair of tombstones keeps the one held (md_lww_take()). */
static void test_floor_no_loop(void **state)
{
  struct md_version a, b, row;

  (void)state;
  memset(&a, 0, sizeof(a));
  a.tombstone = 1; a.st.ms = 1000; a.st.node = 1;
  b = a;
  assert_int_equal(0, md_lww_take(&a, &b));          /* equal tombstones: kept */
  b.st.node = 2;                                       /* same ms and logical, a higher node */
  assert_int_equal(1, md_lww_take(&a, &b));           /* ordered by the node: taken, then equal */
  assert_int_equal(0, md_lww_take(&b, &b));
  memset(&row, 0, sizeof(row));
  row.value = "v"; row.vlen = 1; row.st.ms = 1500;   /* between floors 1000 and 2000 */
  a.st.ms = 2000;
  assert_int_equal(1, md_lww_take(&row, &a));         /* the later floor's tombstone wins */
}

/* A delete is announced as the row it replaces was visible: a tombstone
 * carries none ("D"), and an unset need not name it. */
static void test_notify_vis(void **state)
{
  struct md_version priv, pub, tomb, set;

  (void)state;
  memset(&priv, 0, sizeof(priv));
  priv.value = "v"; priv.vlen = 1; priv.vis = 1;
  pub = priv; pub.vis = 0;
  memset(&tomb, 0, sizeof(tomb));
  tomb.tombstone = 1;
  set = pub; set.vis = 0;
  assert_int_equal(1, md_notify_vis(&priv, &tomb, 0));   /* private row deleted: private */
  assert_int_equal(0, md_notify_vis(&pub, &tomb, 1));    /* public row deleted: public */
  assert_int_equal(0, md_notify_vis(NULL, &tomb, 0));    /* no row: the write's */
  assert_int_equal(0, md_notify_vis(&tomb, &tomb, 0));   /* already deleted: the write's */
  assert_int_equal(0, md_notify_vis(&priv, &set, 0));    /* a live write: its own */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_stamp_roundtrip),
    cmocka_unit_test(test_same_content),
    cmocka_unit_test(test_row_unchanged),
    cmocka_unit_test(test_local_write_unchanged),
    cmocka_unit_test(test_clear_floor),
    cmocka_unit_test(test_notify_vis),
    cmocka_unit_test(test_floor_margin),
    cmocka_unit_test(test_floor_no_loop),
    cmocka_unit_test(test_stamp_parse_rejects),
    cmocka_unit_test(test_stamp_parse_ms_overflow_rejected),
    cmocka_unit_test(test_stamp_cmp_order),
    cmocka_unit_test(test_stamp_ahead_boundary),
    cmocka_unit_test(test_take_when_absent),
    cmocka_unit_test(test_newer_wins_older_loses),
    cmocka_unit_test(test_later_delete_beats_set),
    cmocka_unit_test(test_later_set_beats_delete),
    cmocka_unit_test(test_equal_live_beats_tomb),
    cmocka_unit_test(test_equal_value_tiebreak_symmetric),
    cmocka_unit_test(test_identical_keeps),
    cmocka_unit_test(test_clock_codec),
    cmocka_unit_test(test_wire_keys),
    cmocka_unit_test(test_classify_table),
    cmocka_unit_test(test_flags_table),
    cmocka_unit_test(test_chunk_three_pieces),
    cmocka_unit_test(test_chunk_single_line),
    cmocka_unit_test(test_chunk_mismatch_restarts),
    cmocka_unit_test(test_chunk_overflow),
    cmocka_unit_test(test_chunk_overflow_discards_rest_of_row),
    cmocka_unit_test(test_chunk_overflow_on_final_piece_no_poison),
    cmocka_unit_test(test_chunk_mismatch_discards_rest_of_abandoned_row),
    cmocka_unit_test(test_chunk_nested_interrupts_discard_each_row),
    cmocka_unit_test(test_chunk_poison_slots_hold_a_chain),
    cmocka_unit_test(test_chunk_vis_flip_discards_row),
    cmocka_unit_test(test_chunk_abandon_discards_row),
    cmocka_unit_test(test_chunk_abandon_final_piece_no_poison),
    cmocka_unit_test(test_chunk_rejects_oversize_identity),
    cmocka_unit_test(test_stamp_parse_rejects_over_bufsize),
    cmocka_unit_test(test_pull_parse_ok),
    cmocka_unit_test(test_pull_parse_rejects),
    cmocka_unit_test(test_pull_parse_empty_scope_no_oob),
    cmocka_unit_test(test_pull_parse_seq_overflow_rejected),
    cmocka_unit_test(test_topn_fewer_than_cap),
    cmocka_unit_test(test_topn_exactly_cap),
    cmocka_unit_test(test_topn_more_than_cap_newest_last),
    cmocka_unit_test(test_topn_ties),
    cmocka_unit_test(test_topn_unstamped_is_oldest),
    cmocka_unit_test(test_topn_insert_fill),
    cmocka_unit_test(test_topn_insert_evicts_into_oldest_slot),
    cmocka_unit_test(test_topn_insert_ascending_walk),
    cmocka_unit_test(test_topn_insert_rejects_bad_args),
    cmocka_unit_test(test_key_replicable),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
