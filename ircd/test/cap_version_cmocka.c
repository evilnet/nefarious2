/*
 * cap_version_cmocka.c - a connection's CAP version is the highest it ever
 * sent in CAP LS (cap_version_after_ls(), what cap_ls() in m_cap.c stores).
 *
 * The capability-negotiation spec: a client that sent CAP LS 302 is
 * presumed to support CAP 302's features for the life of the connection
 * (cap values, cap-notify, SASL 3.2's re-authentication).  A later CAP LS
 * with no version, a lower one or a malformed one leaves it a 302 client;
 * a higher one raises it.
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include "capab.h"

/** No version, an empty one: the version stays what it was. */
static void no_version_keeps(void **state)
{
  (void)state;
  assert_int_equal(cap_version_after_ls(0, NULL), 0);
  assert_int_equal(cap_version_after_ls(0, ""), 0);
  assert_int_equal(cap_version_after_ls(302, NULL), 302);
  assert_int_equal(cap_version_after_ls(302, ""), 302);
  assert_int_equal(cap_version_after_ls(301, NULL), 301);
}

/** A version is taken when it is higher. */
static void higher_version_raises(void **state)
{
  (void)state;
  assert_int_equal(cap_version_after_ls(0, "302"), 302);
  assert_int_equal(cap_version_after_ls(0, "301"), 301);
  assert_int_equal(cap_version_after_ls(301, "302"), 302);
  assert_int_equal(cap_version_after_ls(302, "303"), 303);
  assert_int_equal(cap_version_after_ls(0, "+302"), 302);   /* as atoi() read it */
}

/** A lower version never lowers it: a 302 client stays one. */
static void lower_version_never_lowers(void **state)
{
  (void)state;
  assert_int_equal(cap_version_after_ls(302, "301"), 302);
  assert_int_equal(cap_version_after_ls(302, "1"), 302);
  assert_int_equal(cap_version_after_ls(302, "302"), 302);
  assert_int_equal(cap_version_after_ls(303, "302"), 303);
}

/** Not a positive number: no version (as before, atoi() <= 0). */
static void malformed_is_no_version(void **state)
{
  (void)state;
  assert_int_equal(cap_version_after_ls(0, "0"), 0);
  assert_int_equal(cap_version_after_ls(0, "-302"), 0);
  assert_int_equal(cap_version_after_ls(0, "abc"), 0);
  assert_int_equal(cap_version_after_ls(302, "-1"), 302);
  assert_int_equal(cap_version_after_ls(302, "x302"), 302);
  assert_int_equal(cap_version_after_ls(0, "302abc"), 302); /* atoi() too */
}

/** A number past the field's range is the field's highest value, never one
 * that wrapped around below 302 (65537 stored in an unsigned short is 1). */
static void huge_version_saturates(void **state)
{
  (void)state;
  assert_int_equal(cap_version_after_ls(0, "65537"), 65535);
  assert_int_equal(cap_version_after_ls(302, "65537"), 65535);
  assert_int_equal(cap_version_after_ls(0, "99999999999999999999"), 65535);
}

/** The rows the SASL rules are pinned against (sasl_handler_cmocka):
 * what each sequence of CAP LS lines leaves. */
static void sequences(void **state)
{
  unsigned short v;
  (void)state;

  v = 0;                                          /* no CAP LS at all */
  assert_true(v < 302);
  v = cap_version_after_ls(0, NULL);              /* CAP LS */
  assert_true(v < 302);
  v = cap_version_after_ls(0, "301");             /* CAP LS 301 */
  assert_true(v < 302);
  v = cap_version_after_ls(0, "302");             /* CAP LS 302 */
  assert_true(v >= 302);
  v = cap_version_after_ls(cap_version_after_ls(0, "302"), NULL);
  assert_true(v >= 302);                          /* 302, then CAP LS */
  v = cap_version_after_ls(cap_version_after_ls(0, "302"), "301");
  assert_true(v >= 302);                          /* 302, then CAP LS 301 */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(no_version_keeps),
    cmocka_unit_test(higher_version_raises),
    cmocka_unit_test(lower_version_never_lowers),
    cmocka_unit_test(malformed_is_no_version),
    cmocka_unit_test(huge_version_saturates),
    cmocka_unit_test(sequences),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
