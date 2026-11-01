/* cmocka suite for the pure LWW rule, HLC stamp text and MD wire codec
 * (include/metadata_lww.h). */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
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

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_stamp_roundtrip),
    cmocka_unit_test(test_stamp_parse_rejects),
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
    cmocka_unit_test(test_pull_parse_ok),
    cmocka_unit_test(test_pull_parse_rejects),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
