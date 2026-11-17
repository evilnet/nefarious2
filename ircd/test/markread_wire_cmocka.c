/*
 * markread_wire_cmocka.c - the MARKREAD parameter forms of
 * draft/read-marker (markread_wire.h).
 *
 * The spec: a client get command has no timestamp; a client set command
 * carries "timestamp=..." and "MUST NOT be a literal `*`" (INVALID_PARAMS
 * otherwise); the server sends a literal `*` when it knows no timestamp,
 * never "timestamp=*".
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include "markread_wire.h"

/** No second parameter, or an empty one: a get. */
static void no_timestamp_is_get(void **state)
{
  (void)state;
  assert_int_equal(markread_arg_kind(2, NULL), MARKREAD_ARG_GET);
  assert_int_equal(markread_arg_kind(3, NULL), MARKREAD_ARG_GET);
  assert_int_equal(markread_arg_kind(3, ""), MARKREAD_ARG_GET);
}

/** "timestamp=...": a set, whatever follows (checked later). */
static void timestamp_is_set(void **state)
{
  (void)state;
  assert_int_equal(markread_arg_kind(3, "timestamp=2025-01-01T00:00:00.000Z"),
                   MARKREAD_ARG_SET);
  assert_int_equal(markread_arg_kind(3, "timestamp=not-a-timestamp"),
                   MARKREAD_ARG_SET);
  assert_int_equal(markread_arg_kind(3, "timestamp=*"), MARKREAD_ARG_SET);
}

/** The literal `*`, or anything not "timestamp=": invalid, not a get
 * (irctest read_marker.py testWildcardTimestampRejected). */
static void wildcard_and_other_are_invalid(void **state)
{
  (void)state;
  assert_int_equal(markread_arg_kind(3, "*"), MARKREAD_ARG_INVALID);
  assert_int_equal(markread_arg_kind(3, "2025-01-01T00:00:00.000Z"),
                   MARKREAD_ARG_INVALID);
  assert_int_equal(markread_arg_kind(3, "time=x"), MARKREAD_ARG_INVALID);
}

/** No stored timestamp: the server sends the literal `*`. */
static void unknown_timestamp(void **state)
{
  (void)state;
  assert_true(markread_ts_unknown(NULL));
  assert_true(markread_ts_unknown(""));
  assert_true(markread_ts_unknown("*"));
  assert_false(markread_ts_unknown("1735689600.000"));
}

/** The FAIL context is the client's parameter when it is one word, else
 * "*" (MARKREAD #c :foo bar, MARKREAD #c ::x). */
static void fail_context(void **state)
{
  (void)state;
  assert_string_equal(markread_fail_context("*"), "*");
  assert_string_equal(markread_fail_context("timestamp=x"), "timestamp=x");
  assert_string_equal(markread_fail_context("foo bar"), "*");
  assert_string_equal(markread_fail_context(":x"), "*");
  assert_string_equal(markread_fail_context(""), "*");
  assert_string_equal(markread_fail_context(NULL), "*");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(no_timestamp_is_get),
    cmocka_unit_test(timestamp_is_set),
    cmocka_unit_test(wildcard_and_other_are_invalid),
    cmocka_unit_test(unknown_timestamp),
    cmocka_unit_test(fail_context),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
