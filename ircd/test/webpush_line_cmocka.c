/* webpush_line_cmocka.c - CMocka tests for the push payload line builder
 * (webpush_line.c).  The module is pure: no ircd deps.
 *
 * Pins the wire contract of docs/projects/push-payload-multiline.md §3
 * (Seance repo): one IRC line per push, tags in the order
 * batch;msgid;time;account;evilnet.github.io/line;draft/multiline-concat.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/webpush_line.h"

#define T "2026-09-04T10:20:30.123Z"

static struct webpush_line_src src_alice(const char *account)
{
  struct webpush_line_src s;
  s.nick = "alice"; s.user = "u"; s.host = "h.example"; s.account = account;
  return s;
}

static void test_tag_escape(void **state)
{
  char out[64];
  (void)state;
  assert_int_equal((int)webpush_tag_escape(out, sizeof(out), "a;b c\\d\r\n"), 14);
  assert_string_equal(out, "a\\:b\\sc\\\\d\\r\\n");
  assert_int_equal((int)webpush_tag_escape(out, sizeof(out), ""), 0);
  assert_string_equal(out, "");
  /* does not fit: 3 escaped bytes + NUL need 4 */
  assert_true(webpush_tag_escape(out, 3, ";a") == (size_t)-1);
}

static void test_pm_with_account(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice("alice");
  int n;
  (void)state;
  n = webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "bob", "hi there",
                           "abc123", T, NULL);
  assert_string_equal(out, "@msgid=abc123;time=" T ";account=alice"
                           " :alice!u@h.example PRIVMSG bob :hi there");
  assert_int_equal(n, (int)strlen(out));
}

static void test_notice_without_account(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  (void)state;
  assert_true(webpush_line_message(out, sizeof(out), &s, "NOTICE", "bob", "hi",
                                   "abc123", T, NULL) > 0);
  assert_string_equal(out, "@msgid=abc123;time=" T " :alice!u@h.example NOTICE bob :hi");
  s.account = "";   /* empty account is "no account" too */
  assert_true(webpush_line_message(out, sizeof(out), &s, "NOTICE", "bob", "hi",
                                   "abc123", T, NULL) > 0);
  assert_string_equal(out, "@msgid=abc123;time=" T " :alice!u@h.example NOTICE bob :hi");
}

static void test_no_tags_at_all(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  (void)state;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#chan", "x",
                                   NULL, NULL, NULL) > 0);
  assert_string_equal(out, ":alice!u@h.example PRIVMSG #chan :x");
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#chan", "x",
                                   "", "", NULL) > 0);
  assert_string_equal(out, ":alice!u@h.example PRIVMSG #chan :x");
}

static void test_ctcp_action_verbatim(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  (void)state;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#chan",
                                   "\001ACTION waves\001", "m1", NULL, NULL) > 0);
  assert_string_equal(out, "@msgid=m1 :alice!u@h.example PRIVMSG #chan :\001ACTION waves\001");
}

static void test_tag_values_are_escaped(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice("a;b");
  (void)state;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "bob", "x",
                                   "id with space", NULL, NULL) > 0);
  assert_string_equal(out, "@msgid=id\\swith\\sspace;account=a\\:b :alice!u@h.example PRIVMSG bob :x");
}

static void test_multiline_lines(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice("alice");
  struct webpush_line_ml ml;
  (void)state;
  ml.batch = "base1"; ml.index = 1; ml.sent = 3; ml.total = 5; ml.concat = 0;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#chan", "line one",
                                   "base1", T, &ml) > 0);
  assert_string_equal(out, "@batch=base1;msgid=base1;time=" T ";account=alice"
                           ";evilnet.github.io/line=1/3/5"
                           " :alice!u@h.example PRIVMSG #chan :line one");
  ml.index = 2; ml.concat = 1;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#chan", " continued",
                                   "base1", T, &ml) > 0);
  assert_string_equal(out, "@batch=base1;msgid=base1;time=" T ";account=alice"
                           ";evilnet.github.io/line=2/3/5;draft/multiline-concat"
                           " :alice!u@h.example PRIVMSG #chan : continued");
}

static void test_multiline_rejects_bad_index(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  struct webpush_line_ml ml;
  (void)state;
  ml.batch = "base1"; ml.index = 0; ml.sent = 1; ml.total = 1; ml.concat = 0;
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#c", "x",
                                        "base1", T, &ml), -1);
  ml.index = 1; ml.batch = "";
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#c", "x",
                                        "base1", T, &ml), -1);
  /* index beyond sent, and sent beyond total */
  ml.batch = "base1"; ml.index = 2; ml.sent = 1; ml.total = 3; ml.concat = 0;
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#c", "x",
                                        "base1", T, &ml), -1);
  ml.index = 1; ml.sent = 4; ml.total = 3;
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#c", "x",
                                        "base1", T, &ml), -1);
}

static void test_rejects_embedded_crlf(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  (void)state;
  out[0] = 'Z';
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#c",
                                        "hi\r\nEVIL bob :pwned", NULL, NULL, NULL), -1);
  assert_string_equal(out, "");
  out[0] = 'Z';
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "#c\r\n",
                                        "x", NULL, NULL, NULL), -1);
  assert_string_equal(out, "");
  out[0] = 'Z';
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIV\r\nMSG", "#c",
                                        "x", NULL, NULL, NULL), -1);
  assert_string_equal(out, "");
  out[0] = 'Z';
  assert_int_equal(webpush_line_markread(out, sizeof(out), "irc.example\r\n", "#c", T), -1);
  assert_string_equal(out, "");
  out[0] = 'Z';
  assert_int_equal(webpush_line_markread(out, sizeof(out), "irc.example", "#c\nbad", T), -1);
  assert_string_equal(out, "");
}

static void test_tag_escape_null_args(void **state)
{
  char out[16];
  (void)state;
  assert_true(webpush_tag_escape(NULL, sizeof(out), "x") == (size_t)-1);
  assert_true(webpush_tag_escape(out, sizeof(out), NULL) == (size_t)-1);
  assert_true(webpush_tag_escape(out, 0, "x") == (size_t)-1);
}

static void test_time_and_batch_tag_values_are_escaped(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  struct webpush_line_ml ml;
  (void)state;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "bob", "x",
                                   NULL, "2026-09-04 10:20;30", NULL) > 0);
  assert_string_equal(out, "@time=2026-09-04\\s10:20\\:30 :alice!u@h.example PRIVMSG bob :x");

  ml.batch = "base;1 2"; ml.index = 1; ml.sent = 1; ml.total = 1; ml.concat = 0;
  assert_true(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "bob", "x",
                                   NULL, NULL, &ml) > 0);
  assert_string_equal(out, "@batch=base\\:1\\s2;evilnet.github.io/line=1/1/1"
                           " :alice!u@h.example PRIVMSG bob :x");
}

static void test_missing_arguments(void **state)
{
  char out[512];
  struct webpush_line_src s = src_alice(NULL);
  (void)state;
  assert_int_equal(webpush_line_message(out, sizeof(out), NULL, "PRIVMSG", "b", "x", NULL, NULL, NULL), -1);
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, NULL, "b", "x", NULL, NULL, NULL), -1);
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", NULL, "x", NULL, NULL, NULL), -1);
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "b", NULL, NULL, NULL, NULL), -1);
  s.host = NULL;
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "b", "x", NULL, NULL, NULL), -1);
  assert_int_equal(webpush_line_message(NULL, 0, &s, "PRIVMSG", "b", "x", NULL, NULL, NULL), -1);
}

static void test_does_not_fit(void **state)
{
  char out[40];
  struct webpush_line_src s = src_alice("alice");
  (void)state;
  out[0] = 'Z';
  assert_int_equal(webpush_line_message(out, sizeof(out), &s, "PRIVMSG", "bob",
                                        "a fairly long text that overflows", "abc123", T, NULL), -1);
  assert_string_equal(out, "");
  /* exactly fits: length + NUL == outlen */
  {
    char tight[35];
    s.account = NULL;
    assert_int_equal(webpush_line_message(tight, sizeof(tight), &s, "PRIVMSG", "bob", "hi",
                                          NULL, NULL, NULL), 34);
    assert_string_equal(tight, ":alice!u@h.example PRIVMSG bob :hi");
  }
}

static void test_markread(void **state)
{
  char out[256];
  (void)state;
  assert_true(webpush_line_markread(out, sizeof(out), "irc.example", "#chan", T) > 0);
  assert_string_equal(out, ":irc.example MARKREAD #chan timestamp=" T);
  assert_true(webpush_line_markread(out, sizeof(out), "irc.example", "bob", "*") > 0);
  assert_string_equal(out, ":irc.example MARKREAD bob *");
  assert_true(webpush_line_markread(out, sizeof(out), "irc.example", "bob", NULL) > 0);
  assert_string_equal(out, ":irc.example MARKREAD bob *");
  assert_int_equal(webpush_line_markread(out, 10, "irc.example", "bob", T), -1);
  assert_int_equal(webpush_line_markread(out, sizeof(out), NULL, "bob", T), -1);
  assert_int_equal(webpush_line_markread(out, sizeof(out), "irc.example", NULL, T), -1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_tag_escape),
    cmocka_unit_test(test_pm_with_account),
    cmocka_unit_test(test_notice_without_account),
    cmocka_unit_test(test_no_tags_at_all),
    cmocka_unit_test(test_ctcp_action_verbatim),
    cmocka_unit_test(test_tag_values_are_escaped),
    cmocka_unit_test(test_multiline_lines),
    cmocka_unit_test(test_multiline_rejects_bad_index),
    cmocka_unit_test(test_rejects_embedded_crlf),
    cmocka_unit_test(test_tag_escape_null_args),
    cmocka_unit_test(test_time_and_batch_tag_values_are_escaped),
    cmocka_unit_test(test_missing_arguments),
    cmocka_unit_test(test_does_not_fit),
    cmocka_unit_test(test_markread),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
