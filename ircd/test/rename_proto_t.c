/*
 * rename_proto_t.c - the argument-only parts of channel RENAME: the
 * cookie a services permission query travels under ("<numeric>.<n>", and
 * the bare "<n>" older servers send), who may relay a query and whose
 * reply is applied, relayed or dropped, the rules a pair of channel
 * names has to pass, and the rules of relocation mode every server
 * applies alike (the deadline on the wire and its bound, which of two
 * crossing relocations wins, what an announced tombstone means).
 *
 * The cases are those of the ircv3.2-upgrade branch's
 * rename_proto_cmocka.c, unchanged.  That suite is written for CMocka,
 * which this tree does not use, so the few assertions it needs are
 * defined below: a failed one prints where and what, and the program
 * exits non-zero at the end.
 */
#include "config.h"
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "channel.h"            /* CHANNELLEN */
#include "ircd_string.h"        /* ircd_strcmp */
#include "rename_proto.h"

static int checks;              /**< assertions evaluated */
static int failures;            /**< assertions that did not hold */

static void check(int ok, const char *file, int line, const char *what)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED %s:%d: %s\n", file, line, what);
  }
}

static int same_string(const char *a, const char *b)
{
  return a && b && 0 == strcmp(a, b);
}

#define CHECK(cond, text)       check((cond), __FILE__, __LINE__, text)
#define assert_true(c)          CHECK((c) ? 1 : 0, #c)
#define assert_false(c)         CHECK((c) ? 0 : 1, "!(" #c ")")
#define assert_null(p)          CHECK((p) == NULL, #p " == NULL")
#define assert_non_null(p)      CHECK((p) != NULL, #p " != NULL")
#define assert_ptr_equal(a, b) \
  CHECK((const void *)(a) == (const void *)(b), #a " == " #b)
#define assert_int_equal(a, b) \
  CHECK((long)(a) == (long)(b), #a " == " #b)
#define assert_int_not_equal(a, b) \
  CHECK((long)(a) != (long)(b), #a " != " #b)
#define assert_string_equal(a, b) \
  CHECK(same_string((a), (b)), #a " equals " #b)
#define assert_string_not_equal(a, b) \
  CHECK(!same_string((a), (b)), #a " differs from " #b)

/* ========== cookie: format ========== */

static void format_two_character_numeric(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN];
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "Bj", 17), 5);
  assert_string_equal(buf, "Bj.17");
}

static void format_one_character_numeric(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN];
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "A", 1), 3);
  assert_string_equal(buf, "A.1");
}

static void format_largest_value_fits_the_documented_buffer(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN];
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "]]", UINT_MAX),
                   RENAME_COOKIE_BUFLEN - 1);
  assert_string_equal(buf, "]].4294967295");
}

static void format_refuses_what_is_not_a_server_numeric(void **state)
{
  char buf[RENAME_COOKIE_BUFLEN] = "keep";
  (void)state;
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "", 1), 0);
  assert_string_equal(buf, "");
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), NULL, 1), 0);
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "ABC", 1), 0);   /* a user's prefix, not a server */
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "A.", 1), 0);
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "A ", 1), 0);
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "-A", 1), 0);
  assert_string_equal(buf, "");
}

static void format_refuses_a_buffer_too_small(void **state)
{
  char buf[5] = "keep";
  (void)state;
  /* "Bj.17" needs six bytes */
  assert_int_equal(rename_cookie_format(buf, sizeof(buf), "Bj", 17), 0);
  assert_string_equal(buf, "");
  assert_int_equal(rename_cookie_format(buf, 0, "Bj", 17), 0);
  assert_int_equal(rename_cookie_format(NULL, 16, "Bj", 17), 0);
}

/* ========== cookie: parse ========== */

static void parse_round_trips_every_numeric_length(void **state)
{
  static const char *const numerics[] = { "A", "]", "0", "Bj", "AC", "[]", "09", "]]" };
  static const unsigned int values[] = { 0, 1, 9, 10, 17, 4096, 2147483647u,
                                         2147483648u, UINT_MAX };
  size_t i, j;
  (void)state;

  for (i = 0; i < sizeof(numerics) / sizeof(numerics[0]); i++) {
    for (j = 0; j < sizeof(values) / sizeof(values[0]); j++) {
      char buf[RENAME_COOKIE_BUFLEN];
      char numeric[3] = "??";
      unsigned int n = 12345;

      assert_true(rename_cookie_format(buf, sizeof(buf), numerics[i], values[j]) > 0);
      assert_int_equal(rename_cookie_parse(buf, numeric, &n), RENAME_COOKIE_ROUTED);
      assert_string_equal(numeric, numerics[i]);
      assert_true(n == values[j]);
    }
  }
}

static void parse_old_undotted_form(void **state)
{
  char numeric[3] = "??";
  unsigned int n = 12345;
  (void)state;

  assert_int_equal(rename_cookie_parse("17", numeric, &n), RENAME_COOKIE_LEGACY);
  assert_string_equal(numeric, "");
  assert_int_equal(n, 17);

  assert_int_equal(rename_cookie_parse("0", numeric, &n), RENAME_COOKIE_LEGACY);
  assert_int_equal(n, 0);

  assert_int_equal(rename_cookie_parse("4294967295", numeric, &n), RENAME_COOKIE_LEGACY);
  assert_true(n == UINT_MAX);
}

/* A digit is a legal numeric character, so "12.7" is server "12", request
 * 7 -- not request 12 with something after it. */
static void parse_all_digit_numeric_is_still_a_numeric(void **state)
{
  char numeric[3];
  unsigned int n = 0;
  (void)state;

  assert_int_equal(rename_cookie_parse("12.7", numeric, &n), RENAME_COOKIE_ROUTED);
  assert_string_equal(numeric, "12");
  assert_int_equal(n, 7);
}

static void expect_invalid(const char *text)
{
  char numeric[3] = "??";
  unsigned int n = 12345;

  assert_int_equal(rename_cookie_parse(text, numeric, &n), RENAME_COOKIE_INVALID);
  assert_string_equal(numeric, "");     /* never a stale numeric */
  assert_int_equal(n, 12345);           /* untouched */
}

static void parse_empty_parts(void **state)
{
  (void)state;
  expect_invalid(NULL);
  expect_invalid("");
  expect_invalid(".");
  expect_invalid(".17");        /* no numeric */
  expect_invalid("Bj.");        /* a dot with nothing after it */
  expect_invalid("B.");
  expect_invalid("..");
  expect_invalid("Bj..17");
}

static void parse_garbage(void **state)
{
  (void)state;
  expect_invalid("Bj");                 /* a numeric and nothing else */
  expect_invalid("RENAME");
  expect_invalid("#channel");
  expect_invalid("Bj.17.3");            /* a second dot */
  expect_invalid("Bj.17 ");
  expect_invalid(" Bj.17");
  expect_invalid("Bj.-1");
  expect_invalid("Bj.+1");
  expect_invalid("Bj.1x");
  expect_invalid("Bj.0x11");
  expect_invalid("-17");
  expect_invalid("+17");
  expect_invalid("17x");
  expect_invalid("1 7");
  expect_invalid("B-.17");              /* '-' and '_' are base64url, not P10 */
  expect_invalid("B_.17");
  expect_invalid("B\xe9.17");
  expect_invalid("Bj\t.17");
  expect_invalid("ABAAB");              /* a user numeric */
  expect_invalid(".12.34");             /* the LOC request id shape */
}

static void parse_numeric_too_long(void **state)
{
  (void)state;
  expect_invalid("ABC.17");
  expect_invalid("ABAAB.17");
}

static void parse_leading_zero_is_not_what_a_server_prints(void **state)
{
  (void)state;
  expect_invalid("017");
  expect_invalid("00");
  expect_invalid("Bj.017");
  expect_invalid("Bj.00");
}

static void parse_overflow(void **state)
{
  (void)state;
  expect_invalid("4294967296");                 /* UINT_MAX + 1 */
  expect_invalid("Bj.4294967296");
  expect_invalid("9999999999");                 /* ten digits, too large */
  expect_invalid("Bj.9999999999");
  expect_invalid("42949672950");                /* eleven digits */
  expect_invalid("Bj.42949672950");
  expect_invalid("Bj.18446744073709551616");    /* past 64 bits: must not wrap to 0 */
  expect_invalid("18446744073709551617");       /* ... nor to 1 */
}

static void parse_over_long(void **state)
{
  char big[600];
  (void)state;

  memset(big, '7', sizeof(big) - 1);
  big[sizeof(big) - 1] = '\0';
  expect_invalid(big);

  big[0] = 'B'; big[1] = 'j'; big[2] = '.';
  expect_invalid(big);

  memset(big, 'A', sizeof(big) - 1);
  expect_invalid(big);
}

/* ========== who may move or answer a request ========== */

static void query_is_relayed_only_when_its_cookie_names_its_source(void **state)
{
  (void)state;
  assert_true(rename_query_relayable(RENAME_COOKIE_ROUTED, 1));
  /* a routed cookie naming some other server */
  assert_false(rename_query_relayable(RENAME_COOKIE_ROUTED, 0));
  /* the bare number of a server that does not name itself */
  assert_false(rename_query_relayable(RENAME_COOKIE_LEGACY, 0));
  assert_false(rename_query_relayable(RENAME_COOKIE_LEGACY, 1));
  assert_false(rename_query_relayable(RENAME_COOKIE_INVALID, 0));
  assert_false(rename_query_relayable(RENAME_COOKIE_INVALID, 1));
}

/** A reply from services "x3.services", linked here, about our own
 * pending request that was sent to x3.services: the case that applies. */
static struct RenameReplyFacts good_reply(enum RenameCookieForm form)
{
  struct RenameReplyFacts f;

  memset(&f, 0, sizeof(f));
  f.form = form;
  f.source_is_services = 1;
  f.source_is_direct = 1;
  f.source_name = "x3.services";
  f.cookie_is_ours = (form == RENAME_COOKIE_ROUTED);
  f.bound_name = "x3.services";
  return f;
}

static void reply_for_our_request_from_its_services_server_applies(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_ROUTED);
  (void)state;

  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_APPLY);
  /* services two hops away are still the server the request went to */
  f.source_is_direct = 0;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_APPLY);
  /* server names compare the way the ircd compares them */
  f.source_name = "X3.Services";
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_APPLY);
}

static void reply_from_a_non_services_source_does_nothing(void **state)
{
  enum RenameCookieForm forms[] = { RENAME_COOKIE_ROUTED, RENAME_COOKIE_LEGACY,
                                    RENAME_COOKIE_INVALID };
  size_t i;
  (void)state;

  for (i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
    struct RenameReplyFacts f = good_reply(forms[i]);

    f.source_is_services = 0;
    assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_SERVICES);
    /* ... not even when it claims the name the request was sent to, and
     * not when the cookie is another server's: a relay does not carry a
     * forged answer */
    f.cookie_is_ours = 0;
    f.cookie_server_known = 1;
    assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_SERVICES);
  }
}

static void reply_with_a_cookie_of_neither_form_is_dropped(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_INVALID);
  (void)state;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_BAD_COOKIE);
}

static void reply_for_another_server_is_relayed(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_ROUTED);
  (void)state;

  f.cookie_is_ours = 0;
  f.cookie_server_known = 1;
  f.bound_name = NULL;                  /* a relay holds no request */
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_RELAY);
  f.source_is_direct = 0;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_RELAY);

  f.cookie_server_is_back = 1;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_BACKWARD);

  f.cookie_server_is_back = 0;
  f.cookie_server_known = 0;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_UNKNOWN_SERVER);
}

/* A request with the same number may well be pending HERE while a reply
 * for another server's request passes through: it is relayed, never
 * applied. */
static void reply_for_another_server_never_touches_our_request(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_ROUTED);
  (void)state;

  f.cookie_is_ours = 0;
  f.cookie_server_known = 1;
  f.bound_name = "x3.services";         /* our own request <n>, same services */
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_RELAY);
}

static void reply_without_a_pending_request_is_dropped(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_ROUTED);
  (void)state;

  f.bound_name = NULL;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NO_REQUEST);
  f = good_reply(RENAME_COOKIE_LEGACY);
  f.bound_name = NULL;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NO_REQUEST);
}

/* The request went to one services server; another one answers. */
static void reply_from_a_services_server_the_request_was_not_sent_to(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_ROUTED);
  (void)state;

  f.source_name = "other.services";
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_BOUND);
  f.source_is_direct = 0;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_BOUND);

  f = good_reply(RENAME_COOKIE_LEGACY);
  f.source_name = "other.services";
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_BOUND);

  /* a name that merely starts the same */
  f = good_reply(RENAME_COOKIE_ROUTED);
  f.source_name = "x3.services.example";
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_BOUND);
  f.source_name = "";
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_BOUND);
  f.source_name = NULL;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_NOT_BOUND);
}

/* The bare number: only from the services server the request went to,
 * and only when that server is linked here. */
static void bare_number_reply(void **state)
{
  struct RenameReplyFacts f = good_reply(RENAME_COOKIE_LEGACY);
  (void)state;

  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_APPLY);

  f.source_is_direct = 0;
  assert_int_equal(rename_reply_decide(&f), RENAME_REPLY_BARE_INDIRECT);
}

/* Every combination of the facts: a bare number is never relayed, and
 * nothing is ever applied without the source being the services server
 * the pending request was sent to. */
static void reply_decision_invariants(void **state)
{
  enum RenameCookieForm forms[] = { RENAME_COOKIE_INVALID, RENAME_COOKIE_LEGACY,
                                    RENAME_COOKIE_ROUTED };
  const char *names[] = { NULL, "x3.services", "other.services" };
  unsigned int bits;
  size_t fi, si, bi;
  (void)state;

  for (fi = 0; fi < 3; fi++)
    for (si = 0; si < 3; si++)
      for (bi = 0; bi < 3; bi++)
        for (bits = 0; bits < 32; bits++) {
          struct RenameReplyFacts f;
          enum RenameReplyVerdict v;

          memset(&f, 0, sizeof(f));
          f.form = forms[fi];
          f.source_name = names[si];
          f.bound_name = names[bi];
          f.source_is_services = bits & 1;
          f.source_is_direct = (bits >> 1) & 1;
          f.cookie_is_ours = (bits >> 2) & 1;
          f.cookie_server_known = (bits >> 3) & 1;
          f.cookie_server_is_back = (bits >> 4) & 1;
          v = rename_reply_decide(&f);

          if (v == RENAME_REPLY_APPLY) {
            assert_true(f.source_is_services);
            assert_non_null(f.bound_name);
            assert_non_null(f.source_name);
            assert_string_equal(f.bound_name, f.source_name);
            assert_true(f.form == RENAME_COOKIE_LEGACY
                        || (f.form == RENAME_COOKIE_ROUTED && f.cookie_is_ours));
            if (f.form == RENAME_COOKIE_LEGACY)
              assert_true(f.source_is_direct);
          }
          if (v == RENAME_REPLY_RELAY) {
            assert_true(f.source_is_services);
            assert_int_equal(f.form, RENAME_COOKIE_ROUTED);
            assert_false(f.cookie_is_ours);
            assert_true(f.cookie_server_known);
            assert_false(f.cookie_server_is_back);
          }
          assert_non_null(rename_reply_verdict_text(v));
        }
}

/* ========== names ========== */

#define OK(o, n)        assert_int_equal(rename_check_names((o), (n), CHANNELLEN, 0), RENAME_NAME_OK)
#define BAD(o, n, why)  assert_int_equal(rename_check_names((o), (n), CHANNELLEN, 0), (why))

static void names_plain_rename_is_fine(void **state)
{
  (void)state;
  OK("#old", "#new");
  OK("#old", "#");
  OK("#old", "#new-name_[with]{odd}|chars^`'");
  OK("#old", "#caf\xc3\xa9");                   /* UTF-8, no 0xA0 byte */
  OK("#old", "#\xe9t\xe9");                     /* Latin-1: JOIN takes it unless UTF-8 only */
  OK("#old", "#a:b");
  OK("#old", "##");
  OK("#old", "#a&b");
}

static void names_local_channels_are_refused_on_either_side(void **state)
{
  (void)state;
  BAD("&ops", "#leak", RENAME_NAME_OLD_LOCAL);
  BAD("&ops", "&staff", RENAME_NAME_OLD_LOCAL);
  BAD("#chan", "&chan", RENAME_NAME_NEW_LOCAL);
  BAD("#chan", "&", RENAME_NAME_NEW_LOCAL);
}

static void names_without_a_channel_prefix(void **state)
{
  (void)state;
  BAD("#old", "new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", "", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", NULL, RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", "+new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", "!new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("#old", " #new", RENAME_NAME_NEW_NOT_CHANNEL);
  BAD("old", "#new", RENAME_NAME_OLD_NOT_CHANNEL);
  BAD("", "#new", RENAME_NAME_OLD_NOT_CHANNEL);
  BAD(NULL, "#new", RENAME_NAME_OLD_NOT_CHANNEL);
  /* the old name is judged first */
  BAD("old", "&new", RENAME_NAME_OLD_NOT_CHANNEL);
}

static void names_comma(void **state)
{
  (void)state;
  BAD("#a", "#a,b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#a", "#a,#b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#a", "#,", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#a", "#b,", RENAME_NAME_NEW_BAD_CHARS);
}

static void names_control_characters_and_space(void **state)
{
  char name[8];
  int c;
  (void)state;

  /* every byte from 0x01 to 0x20 */
  for (c = 1; c <= 0x20; c++) {
    name[0] = '#'; name[1] = 'a'; name[2] = (char)c; name[3] = 'b'; name[4] = '\0';
    BAD("#old", name, RENAME_NAME_NEW_BAD_CHARS);
  }
  BAD("#old", "#bell\007", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#a b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#tab\there", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#\001", RENAME_NAME_NEW_BAD_CHARS);
  /* 0x21 and 0x7f are in JOIN's set, so they are in ours */
  OK("#old", "#a!b");
  OK("#old", "#a\177");
}

static void names_nbsp_byte(void **state)
{
  (void)state;
  BAD("#old", "#a\xa0" "b", RENAME_NAME_NEW_BAD_CHARS);
  BAD("#old", "#\xa0", RENAME_NAME_NEW_BAD_CHARS);
  /* also when it is the second byte of a UTF-8 sequence ("a grave"):
   * JOIN refuses the byte wherever it stands, and so does this */
  BAD("#old", "#voil\xc3\xa0", RENAME_NAME_NEW_BAD_CHARS);
}

static void names_length_cap(void **state)
{
  char name[CHANNELLEN + 3];
  (void)state;

  memset(name, 'x', sizeof(name));
  name[0] = '#';

  name[CHANNELLEN] = '\0';              /* exactly CHANNELLEN bytes */
  assert_int_equal(rename_check_names("#old", name, CHANNELLEN, 0), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", name, CHANNELLEN - 1, 0),
                   RENAME_NAME_NEW_TOO_LONG);

  name[CHANNELLEN] = 'x';
  name[CHANNELLEN + 1] = '\0';          /* one over */
  assert_int_equal(rename_check_names("#old", name, CHANNELLEN, 0),
                   RENAME_NAME_NEW_TOO_LONG);

  /* a lower configured cap (FEAT_CHANNELLEN) */
  assert_int_equal(rename_check_names("#old", "#12345", 6, 0), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", "#123456", 6, 0), RENAME_NAME_NEW_TOO_LONG);
  /* the old name's length is nobody's business */
  assert_int_equal(rename_check_names("#a-long-old-name", "#new", 6, 0), RENAME_NAME_OK);
}

static void names_utf8_only_when_asked(void **state)
{
  (void)state;
  assert_int_equal(rename_check_names("#old", "#\xe9t\xe9", CHANNELLEN, 0), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", "#\xe9t\xe9", CHANNELLEN, 1),
                   RENAME_NAME_NEW_BAD_UTF8);
  assert_int_equal(rename_check_names("#old", "#caf\xc3\xa9", CHANNELLEN, 1), RENAME_NAME_OK);
  assert_int_equal(rename_check_names("#old", "#ascii", CHANNELLEN, 1), RENAME_NAME_OK);
  /* a truncated sequence */
  assert_int_equal(rename_check_names("#old", "#caf\xc3", CHANNELLEN, 1),
                   RENAME_NAME_NEW_BAD_UTF8);
}

/* With # and & the only prefixes, two names of different type always have
 * a local channel on one side, and that is what is reported. */
static void names_mixed_prefix(void **state)
{
  (void)state;
  BAD("&a", "#a", RENAME_NAME_OLD_LOCAL);
  BAD("#a", "&a", RENAME_NAME_NEW_LOCAL);
  assert_int_not_equal(rename_check_names("&a", "#a", CHANNELLEN, 0), RENAME_NAME_OK);
  assert_int_not_equal(rename_check_names("#a", "&a", CHANNELLEN, 0), RENAME_NAME_OK);
}

static void names_first_broken_rule_wins(void **state)
{
  char name[CHANNELLEN + 8];
  (void)state;

  /* local beats bad characters */
  BAD("#a", "&a,b", RENAME_NAME_NEW_LOCAL);
  /* bad characters beat length */
  memset(name, 'x', sizeof(name));
  name[0] = '#';
  name[5] = ',';
  name[sizeof(name) - 1] = '\0';
  BAD("#a", name, RENAME_NAME_NEW_BAD_CHARS);
}

static void names_every_error_has_its_own_text(void **state)
{
  enum RenameNameError all[] = {
    RENAME_NAME_OLD_NOT_CHANNEL, RENAME_NAME_OLD_LOCAL,
    RENAME_NAME_NEW_NOT_CHANNEL, RENAME_NAME_NEW_LOCAL,
    RENAME_NAME_NEW_BAD_CHARS, RENAME_NAME_NEW_BAD_UTF8,
    RENAME_NAME_NEW_TOO_LONG, RENAME_NAME_PREFIX_MISMATCH
  };
  size_t i, j, count = sizeof(all) / sizeof(all[0]);
  (void)state;

  for (i = 0; i < count; i++) {
    const char *text = rename_name_error_text(all[i]);
    assert_non_null(text);
    assert_true(strlen(text) > 0);
    /* a FAIL description is one trailing parameter */
    assert_null(strchr(text, '\n'));
    assert_null(strchr(text, '\r'));
    for (j = 0; j < i; j++)
      assert_string_not_equal(text, rename_name_error_text(all[j]));
  }
  assert_non_null(rename_name_error_text(RENAME_NAME_OK));
  assert_non_null(rename_name_error_text((enum RenameNameError)999));
}

/* ========== relocation: the deadline on the wire ========== */

static void expiry_round_trips(void **state)
{
  static const time_t values[] = { 0, 1, 9, 10, 1731340000, 2147483647 };
  char buf[RELOCATE_EXPIRY_BUFLEN];
  size_t i;
  (void)state;

  for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
    time_t back = -1;
    int len = relocate_expiry_format(buf, sizeof(buf), values[i]);

    assert_true(len > 0);
    assert_int_equal((size_t)len, strlen(buf));
    assert_int_equal(relocate_expiry_parse(buf, &back), 1);
    assert_true(back == values[i]);
  }
  assert_int_equal(relocate_expiry_format(buf, sizeof(buf), 1731340000), 10);
  assert_string_equal(buf, "1731340000");
}

static void expiry_format_largest_value_fits_the_documented_buffer(void **state)
{
  char buf[RELOCATE_EXPIRY_BUFLEN];
  time_t big = (time_t)(((unsigned long long)1 << (sizeof(time_t) * 8 - 1)) - 1);
  time_t back = 0;
  (void)state;

  assert_true(relocate_expiry_format(buf, sizeof(buf), big) > 0);
  assert_int_equal(relocate_expiry_parse(buf, &back), 1);
  assert_true(back == big);
}

static void expiry_format_refuses_a_buffer_too_small(void **state)
{
  char buf[RELOCATE_EXPIRY_BUFLEN] = "x";
  (void)state;

  assert_int_equal(relocate_expiry_format(buf, 10, 1731340000), 0);
  assert_string_equal(buf, "");
  assert_int_equal(relocate_expiry_format(buf, 11, 1731340000), 10);
  assert_int_equal(relocate_expiry_format(buf, 0, 5), 0);
  assert_int_equal(relocate_expiry_format(NULL, 5, 5), 0);
}

/* A time before 1970 is no deadline anybody set; it is written as 0,
 * which every receiver reads as "already past". */
static void expiry_format_writes_a_negative_time_as_zero(void **state)
{
  char buf[RELOCATE_EXPIRY_BUFLEN];
  (void)state;

  assert_int_equal(relocate_expiry_format(buf, sizeof(buf), (time_t)-5), 1);
  assert_string_equal(buf, "0");
}

static void expiry_parse_garbage(void **state)
{
  static const char *const bad[] = {
    "", " ", "-1", "+1", "1 ", " 1", "1x", "x1", "0x10", "1.5", "1e9",
    "moving", ":", "C", "17313400OO", "\xff", "١٢٣",
  };
  time_t out = 4242;
  size_t i;
  (void)state;

  for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    assert_int_equal(relocate_expiry_parse(bad[i], &out), 0);
    assert_true(out == 4242);       /* untouched */
  }
  assert_int_equal(relocate_expiry_parse(NULL, &out), 0);
}

static void expiry_parse_leading_zero_is_not_what_a_server_prints(void **state)
{
  time_t out = 4242;
  (void)state;

  assert_int_equal(relocate_expiry_parse("0", &out), 1);
  assert_true(out == 0);
  out = 4242;
  assert_int_equal(relocate_expiry_parse("00", &out), 0);
  assert_int_equal(relocate_expiry_parse("01731340000", &out), 0);
  assert_true(out == 4242);
}

static void expiry_parse_overflow(void **state)
{
  time_t out = 4242;
  char longer[700];
  (void)state;

  /* one past the largest signed 64-bit value, and far past it */
  assert_int_equal(relocate_expiry_parse("9223372036854775808", &out), 0);
  assert_int_equal(relocate_expiry_parse("18446744073709551616", &out), 0);
  assert_int_equal(relocate_expiry_parse("99999999999999999999999999", &out), 0);
  memset(longer, '9', sizeof(longer) - 1);
  longer[sizeof(longer) - 1] = '\0';
  assert_int_equal(relocate_expiry_parse(longer, &out), 0);
  assert_true(out == 4242);
  if (sizeof(time_t) == 8)
    assert_int_equal(relocate_expiry_parse("9223372036854775807", &out), 1);
}

/* ========== relocation: what a receiver makes of a deadline ========== */

static void deadline_from_grace(void **state)
{
  (void)state;
  assert_true(relocate_expiry_from_grace(1000000, 900) == 1000900);
  assert_true(relocate_expiry_from_grace(1000000, 45) == 1000045);
  /* 0 is "dissolve at once"; a negative setting means the same */
  assert_true(relocate_expiry_from_grace(1000000, 0) == 1000000);
  assert_true(relocate_expiry_from_grace(1000000, -30) == 1000000);
  /* no server announces a deadline another would have to clamp */
  assert_true(relocate_expiry_from_grace(1000000, RELOCATE_GRACE_MAX)
              == 1000000 + RELOCATE_GRACE_MAX);
  assert_true(relocate_expiry_from_grace(1000000, RELOCATE_GRACE_MAX + 1)
              == 1000000 + RELOCATE_GRACE_MAX);
  assert_true(relocate_expiry_from_grace(1000000, INT_MAX)
              == 1000000 + RELOCATE_GRACE_MAX);
}

static void deadline_in_the_future_is_taken_as_it_is(void **state)
{
  time_t e = 1000900;
  (void)state;

  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_LIVE);
  assert_true(e == 1000900);
  e = 1000001;
  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_LIVE);
  assert_true(e == 1000001);
  e = 1000000 + RELOCATE_GRACE_MAX;
  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_LIVE);
  assert_true(e == 1000000 + RELOCATE_GRACE_MAX);
}

static void deadline_now_or_past_dissolves_at_once(void **state)
{
  time_t e = 1000000;
  (void)state;

  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_PAST);
  assert_true(e == 1000000);          /* relayed as received */
  e = 999999;
  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_PAST);
  assert_true(e == 999999);
  e = 0;
  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_PAST);
  assert_true(e == 0);
}

static void deadline_absurdly_far_is_clamped(void **state)
{
  time_t e = 1000000 + RELOCATE_GRACE_MAX + 1;
  (void)state;

  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_CLAMPED);
  assert_true(e == 1000000 + RELOCATE_GRACE_MAX);
  e = 2147483647;
  assert_int_equal(relocate_expiry_check(&e, 1000000), RELOCATE_EXPIRY_CLAMPED);
  assert_true(e == 1000000 + RELOCATE_GRACE_MAX);
  if (sizeof(time_t) == 8) {
    e = (time_t)0x7fffffffffffffffLL;
    assert_int_equal(relocate_expiry_check(&e, 1000000),
                     RELOCATE_EXPIRY_CLAMPED);
    assert_true(e == 1000000 + RELOCATE_GRACE_MAX);
  }
}

/* ========== relocation: which of two new names wins ========== */

static int sign(int v)
{
  return (v > 0) - (v < 0);
}

static void winner_is_the_name_that_sorts_first(void **state)
{
  (void)state;
  assert_true(relocate_name_cmp("#alpha", "#beta") < 0);
  assert_true(relocate_name_cmp("#beta", "#alpha") > 0);
  assert_true(relocate_name_cmp("#a", "#ab") < 0);       /* a prefix first */
  assert_true(relocate_name_cmp("#ab", "#a") > 0);
  assert_true(relocate_name_cmp("#x1", "#x2") < 0);
  assert_int_equal(relocate_name_cmp("#same", "#same"), 0);

  assert_string_equal(relocate_winner("#alpha", "#beta"), "#alpha");
  assert_string_equal(relocate_winner("#beta", "#alpha"), "#alpha");
}

/* Two spellings of one channel are one name: nobody wins. */
static void winner_comparison_follows_the_casemapping(void **state)
{
  (void)state;
  assert_int_equal(relocate_name_cmp("#Alpha", "#aLPHA"), 0);
  /* rfc1459: [ \ ] ^ are the upper case of { | } ~ */
  assert_int_equal(relocate_name_cmp("#a[b]", "#a{b}"), 0);
  assert_int_equal(relocate_name_cmp("#a\\^", "#a|~"), 0);
  /* case does not decide the order either */
  assert_true(relocate_name_cmp("#ALPHA", "#beta") < 0);
  assert_true(relocate_name_cmp("#alpha", "#BETA") < 0);
  assert_true(relocate_name_cmp("#Zeta", "#alpha") > 0);
}

/* A name with bytes above 127 (UTF-8) is compared the way ircd_strcmp()
 * compares it on the platforms the network runs on -- as signed bytes, so
 * it sorts BEFORE every ASCII name -- and that is pinned here: the result
 * must not depend on whether plain char is signed on the build host. */
static void winner_comparison_is_pinned_for_bytes_above_127(void **state)
{
  (void)state;
  assert_true(relocate_name_cmp("#\xc3\xa9t\xc3\xa9", "#zebra") < 0);
  assert_true(relocate_name_cmp("#zebra", "#\xc3\xa9t\xc3\xa9") > 0);
  assert_true(relocate_name_cmp("#\xc3\xa9", "#!") < 0);
  assert_true(relocate_name_cmp("#\x80", "#\xff") < 0);
  assert_true(relocate_name_cmp("#a\xc3\xa9", "#a") < 0);  /* before the NUL too */
  assert_string_equal(relocate_winner("#zebra", "#\xc3\xa9"), "#\xc3\xa9");
}

/* The rule both servers apply must give both the same answer: it is
 * antisymmetric, and it agrees with the comparison the rest of the ircd
 * makes for channel names (the +L burst merge among them). */
static void winner_comparison_is_antisymmetric_and_agrees_with_the_ircd(void **state)
{
  static const char *const names[] = {
    "#a", "#A", "#b", "#ab", "#a[", "#a{", "#a^", "#a~", "#a|", "#a\\",
    "#zebra", "#Zebra", "#\xc3\xa9", "#\xc3\x89", "#\xe2\x82\xac", "#1", "#!",
    "#", "##", "#a b", "#\x80", "#\xff",
  };
  size_t i, j, n = sizeof(names) / sizeof(names[0]);
  (void)state;

  for (i = 0; i < n; i++) {
    for (j = 0; j < n; j++) {
      int fwd = relocate_name_cmp(names[i], names[j]);
      int back = relocate_name_cmp(names[j], names[i]);

      assert_int_equal(sign(fwd), -sign(back));
      if (CHAR_MIN < 0)
        assert_int_equal(sign(fwd), sign(ircd_strcmp(names[i], names[j])));
      assert_int_equal(fwd == 0, 0 == ircd_strcmp(names[i], names[j]));
      /* the winner is the same string whichever way round it is asked */
      if (fwd != 0)
        assert_ptr_equal(relocate_winner(names[i], names[j]),
                         relocate_winner(names[j], names[i]));
    }
  }
}

/* ========== relocation: one deadline from two ========== */

static void deadline_merge_keeps_the_later(void **state)
{
  (void)state;
  assert_true(relocate_deadline_merge(1000900, 1000300) == 1000900);
  assert_true(relocate_deadline_merge(1000300, 1000900) == 1000900);
  assert_true(relocate_deadline_merge(1000900, 1000900) == 1000900);
  assert_true(relocate_deadline_merge(0, 5) == 5);
}

/* Symmetric, idempotent and associative: whatever order servers hear the
 * deadlines in, and however often, they end with the same one. */
static void deadline_merge_is_order_independent(void **state)
{
  static const time_t v[] = { 0, 1, 999990, 1000000, 1000300, 1000900, 2147483647 };
  size_t i, j, k, n = sizeof(v) / sizeof(v[0]);
  (void)state;

  for (i = 0; i < n; i++) {
    assert_true(relocate_deadline_merge(v[i], v[i]) == v[i]);
    for (j = 0; j < n; j++) {
      time_t m = relocate_deadline_merge(v[i], v[j]);

      assert_true(m == relocate_deadline_merge(v[j], v[i]));
      assert_true(m == v[i] || m == v[j]);
      assert_true(m >= v[i] && m >= v[j]);
      for (k = 0; k < n; k++)
        assert_true(relocate_deadline_merge(m, v[k])
                    == relocate_deadline_merge(v[i],
                                               relocate_deadline_merge(v[j], v[k])));
    }
  }
}

/* ========== relocation: what a burst announcement means here ========== */

static enum RelocateAnnounceVerdict announce(int exists, int ts_matches,
                                             int have_record, int same_target)
{
  struct RelocateAnnounceFacts f;

  memset(&f, 0, sizeof(f));
  f.channel_exists = exists;
  f.ts_matches = ts_matches;
  f.have_record = have_record;
  f.same_target = same_target;
  return relocate_announce_decide(&f);
}

static void announcement_for_a_channel_not_here_is_nothing(void **state)
{
  int rec, same, ts;
  (void)state;

  /* whatever else is claimed: no channel, nothing to make a tombstone of */
  for (rec = 0; rec < 2; rec++)
    for (same = 0; same < 2; same++)
      for (ts = 0; ts < 2; ts++)
        assert_int_equal(announce(0, ts, rec, same),
                         RELOCATE_ANNOUNCE_NO_CHANNEL);
}

/* The same name with another creation timestamp is another channel: the
 * BURST that preceded the announcement lost on timestamp here. */
static void announcement_for_another_incarnation_is_nothing(void **state)
{
  int rec, same;
  (void)state;

  for (rec = 0; rec < 2; rec++)
    for (same = 0; same < 2; same++)
      assert_int_equal(announce(1, 0, rec, same),
                       RELOCATE_ANNOUNCE_OTHER_CHANNEL);
}

static void announcement_without_a_record_builds_one(void **state)
{
  (void)state;
  assert_int_equal(announce(1, 1, 0, 0), RELOCATE_ANNOUNCE_BUILD);
  /* "same target" means nothing without a record */
  assert_int_equal(announce(1, 1, 0, 1), RELOCATE_ANNOUNCE_BUILD);
}

static void announcement_meeting_a_record_merges_or_crosses(void **state)
{
  (void)state;
  assert_int_equal(announce(1, 1, 1, 1), RELOCATE_ANNOUNCE_MERGE);
  assert_int_equal(announce(1, 1, 1, 0), RELOCATE_ANNOUNCE_CROSS);
}

/* ========== relocation: is the announced channel the one here ========== */

/* Equal creation timestamps: the same channel. */
static void announced_timestamp_equal_is_the_channel(void **state)
{
  (void)state;
  assert_true(relocate_announce_ts_matches(500000, 500000));
}

/* The BURST that precedes an announcement merges into a channel here that
 * is up to four seconds younger and has users (m_burst.c: "do not deop our
 * side"); that channel then carries the tombstone's +z and +L under its
 * own timestamp, and the announcement is about it. */
static void announced_timestamp_within_the_burst_fuzz_is_the_channel(void **state)
{
  int d;
  (void)state;

  for (d = 1; d <= RELOCATE_TS_FUZZ; d++)
    assert_true(relocate_announce_ts_matches(500000, 500000 + d));
  assert_false(relocate_announce_ts_matches(500000, 500000 + RELOCATE_TS_FUZZ + 1));
  assert_false(relocate_announce_ts_matches(500000, 600000));
}

/* A channel here that is OLDER than the announced one won the BURST: it
 * took none of the tombstone's modes and is not it, by however little. */
static void announced_timestamp_newer_than_ours_is_another_channel(void **state)
{
  (void)state;
  assert_false(relocate_announce_ts_matches(500000, 499999));
  assert_false(relocate_announce_ts_matches(500000, 499996));
  assert_false(relocate_announce_ts_matches(500000, 400000));
  assert_false(relocate_announce_ts_matches(500000, 0));
}

/** One test: its name and the function, which takes the unused state
 * pointer the CMocka original takes. */
struct rename_test {
  const char *name;
  void (*run)(void **state);
};

#define TEST(fn) { #fn, fn }

int main(void)
{
  static const struct rename_test tests[] = {
    TEST(format_two_character_numeric),
    TEST(format_one_character_numeric),
    TEST(format_largest_value_fits_the_documented_buffer),
    TEST(format_refuses_what_is_not_a_server_numeric),
    TEST(format_refuses_a_buffer_too_small),
    TEST(parse_round_trips_every_numeric_length),
    TEST(parse_old_undotted_form),
    TEST(parse_all_digit_numeric_is_still_a_numeric),
    TEST(parse_empty_parts),
    TEST(parse_garbage),
    TEST(parse_numeric_too_long),
    TEST(parse_leading_zero_is_not_what_a_server_prints),
    TEST(parse_overflow),
    TEST(parse_over_long),
    TEST(query_is_relayed_only_when_its_cookie_names_its_source),
    TEST(reply_for_our_request_from_its_services_server_applies),
    TEST(reply_from_a_non_services_source_does_nothing),
    TEST(reply_with_a_cookie_of_neither_form_is_dropped),
    TEST(reply_for_another_server_is_relayed),
    TEST(reply_for_another_server_never_touches_our_request),
    TEST(reply_without_a_pending_request_is_dropped),
    TEST(reply_from_a_services_server_the_request_was_not_sent_to),
    TEST(bare_number_reply),
    TEST(reply_decision_invariants),
    TEST(names_plain_rename_is_fine),
    TEST(names_local_channels_are_refused_on_either_side),
    TEST(names_without_a_channel_prefix),
    TEST(names_comma),
    TEST(names_control_characters_and_space),
    TEST(names_nbsp_byte),
    TEST(names_length_cap),
    TEST(names_utf8_only_when_asked),
    TEST(names_mixed_prefix),
    TEST(names_first_broken_rule_wins),
    TEST(names_every_error_has_its_own_text),
    TEST(expiry_round_trips),
    TEST(expiry_format_largest_value_fits_the_documented_buffer),
    TEST(expiry_format_refuses_a_buffer_too_small),
    TEST(expiry_format_writes_a_negative_time_as_zero),
    TEST(expiry_parse_garbage),
    TEST(expiry_parse_leading_zero_is_not_what_a_server_prints),
    TEST(expiry_parse_overflow),
    TEST(deadline_from_grace),
    TEST(deadline_in_the_future_is_taken_as_it_is),
    TEST(deadline_now_or_past_dissolves_at_once),
    TEST(deadline_absurdly_far_is_clamped),
    TEST(winner_is_the_name_that_sorts_first),
    TEST(winner_comparison_follows_the_casemapping),
    TEST(winner_comparison_is_pinned_for_bytes_above_127),
    TEST(winner_comparison_is_antisymmetric_and_agrees_with_the_ircd),
    TEST(deadline_merge_keeps_the_later),
    TEST(deadline_merge_is_order_independent),
    TEST(announcement_for_a_channel_not_here_is_nothing),
    TEST(announcement_for_another_incarnation_is_nothing),
    TEST(announcement_without_a_record_builds_one),
    TEST(announcement_meeting_a_record_merges_or_crosses),
    TEST(announced_timestamp_equal_is_the_channel),
    TEST(announced_timestamp_within_the_burst_fuzz_is_the_channel),
    TEST(announced_timestamp_newer_than_ours_is_another_channel)
  };
  size_t i;

  for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
    int before = failures;

    tests[i].run(NULL);
    printf("%s: %s\n", failures == before ? "Passed" : "FAILED",
           tests[i].name);
  }

  printf("%d checks in %d tests, %d failed\n", checks,
         (int)(sizeof(tests) / sizeof(tests[0])), failures);
  return failures ? 1 : 0;
}
