/*
 * chathistory_ref_cmocka.c - CHATHISTORY references on the S2S wire
 * (chathistory_ref.c): the form a requester puts a client's reference in
 * on a CH Q query, and how a responder reads it back -- above all a msgid
 * minted by a server whose numnick starts with a digit (numerics
 * 3328-3967), which a responder used to read as a timestamp.
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "chathistory_ref.h"
#include "history.h"

/* A msgid as generate_msgid() mints it on numeric 3328 ("0A"), and one
 * on an ordinary letter numeric. */
#define DIGIT_MSGID  "0AAAAaDCF3KvTd"
#define LETTER_MSGID "ADAAAaDCF3KvTd"

static void read_back(const char *wire, enum HistoryRefType want_type,
                      const char *want_value)
{
  enum HistoryRefType t = HISTORY_REF_NONE;
  const char *v = NULL;

  assert_int_equal(chathistory_parse_s2s_ref(wire, &t, &v), 0);
  assert_int_equal(t, want_type);
  assert_string_equal(v, want_value);
}

/* ========== the requester's side ========== */

static void a_msgid_goes_out_marked(void **state)
{
  char buf[HISTORY_MSGID_LEN + 8];
  (void)state;
  assert_non_null(chathistory_ref_to_s2s("msgid=" DIGIT_MSGID, buf, sizeof(buf)));
  assert_string_equal(buf, "msgid=" DIGIT_MSGID);
}

static void a_timestamp_goes_out_bare(void **state)
{
  char buf[HISTORY_MSGID_LEN + 8];
  (void)state;
  assert_non_null(chathistory_ref_to_s2s("timestamp=2026-11-16T18:00:00.000Z",
                                         buf, sizeof(buf)));
  assert_string_equal(buf, "2026-11-16T18:00:00.000Z");
  assert_non_null(chathistory_ref_to_s2s("*", buf, sizeof(buf)));
  assert_string_equal(buf, "*");
}

static void an_empty_or_unknown_reference_is_refused(void **state)
{
  char buf[HISTORY_MSGID_LEN + 8];
  (void)state;
  assert_null(chathistory_ref_to_s2s("msgid=", buf, sizeof(buf)));
  assert_null(chathistory_ref_to_s2s("bogus=1", buf, sizeof(buf)));
  assert_null(chathistory_ref_to_s2s(DIGIT_MSGID, buf, sizeof(buf)));
}

/* ========== the responder's side ========== */

static void a_marked_msgid_reads_as_a_msgid(void **state)
{
  (void)state;
  read_back("msgid=" DIGIT_MSGID, HISTORY_REF_MSGID, DIGIT_MSGID);
  read_back("msgid=" LETTER_MSGID, HISTORY_REF_MSGID, LETTER_MSGID);
}

/* What an older requester sends: the msgid bare. */
static void a_bare_digit_led_msgid_reads_as_a_msgid(void **state)
{
  (void)state;
  read_back(DIGIT_MSGID, HISTORY_REF_MSGID, DIGIT_MSGID);
  read_back("9]AAAaDCF3KvTd", HISTORY_REF_MSGID, "9]AAAaDCF3KvTd");
  read_back(LETTER_MSGID, HISTORY_REF_MSGID, LETTER_MSGID);
}

static void bare_timestamps_read_as_timestamps(void **state)
{
  (void)state;
  read_back("1735689600.123", HISTORY_REF_TIMESTAMP, "1735689600.123");
  read_back("1735689600", HISTORY_REF_TIMESTAMP, "1735689600");
  read_back("2026-11-16T18:00:00.000Z", HISTORY_REF_TIMESTAMP,
            "2026-11-16T18:00:00.000Z");
  read_back("2026-11-16T18:00:00Z", HISTORY_REF_TIMESTAMP,
            "2026-11-16T18:00:00Z");
  read_back("timestamp=1735689600.123", HISTORY_REF_TIMESTAMP,
            "1735689600.123");
}

/* Starts with a digit but is no timestamp: a msgid, as a bare reference
 * that is not a timestamp always was. */
static void a_digit_led_non_timestamp_reads_as_a_msgid(void **state)
{
  (void)state;
  read_back("1735689600-5", HISTORY_REF_MSGID, "1735689600-5");
}

static void a_unix_timestamp_goes_out_bare(void **state)
{
  char buf[HISTORY_MSGID_LEN + 8];
  (void)state;
  assert_non_null(chathistory_ref_to_s2s("timestamp=1735689600.123",
                                         buf, sizeof(buf)));
  assert_string_equal(buf, "1735689600.123");
  read_back(buf, HISTORY_REF_TIMESTAMP, "1735689600.123");
}

static void none_and_empty(void **state)
{
  enum HistoryRefType t;
  const char *v;
  (void)state;
  read_back("*", HISTORY_REF_NONE, "*");
  assert_int_equal(chathistory_parse_s2s_ref("", &t, &v), -1);
  assert_int_equal(chathistory_parse_s2s_ref(NULL, &t, &v), -1);
  /* A marker with nothing after it names nothing: refused, as the
   * client's parse_reference() refuses "msgid=". */
  assert_int_equal(chathistory_parse_s2s_ref("msgid=", &t, &v), -1);
  assert_int_equal(chathistory_parse_s2s_ref("timestamp=", &t, &v), -1);
}

/* ========== both sides ========== */

static void a_digit_led_msgid_survives_the_round_trip(void **state)
{
  char buf[HISTORY_MSGID_LEN + 8];
  (void)state;
  assert_non_null(chathistory_ref_to_s2s("msgid=" DIGIT_MSGID, buf, sizeof(buf)));
  read_back(buf, HISTORY_REF_MSGID, DIGIT_MSGID);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(a_msgid_goes_out_marked),
    cmocka_unit_test(a_timestamp_goes_out_bare),
    cmocka_unit_test(an_empty_or_unknown_reference_is_refused),
    cmocka_unit_test(a_marked_msgid_reads_as_a_msgid),
    cmocka_unit_test(a_bare_digit_led_msgid_reads_as_a_msgid),
    cmocka_unit_test(bare_timestamps_read_as_timestamps),
    cmocka_unit_test(a_digit_led_non_timestamp_reads_as_a_msgid),
    cmocka_unit_test(a_unix_timestamp_goes_out_bare),
    cmocka_unit_test(none_and_empty),
    cmocka_unit_test(a_digit_led_msgid_survives_the_round_trip),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
