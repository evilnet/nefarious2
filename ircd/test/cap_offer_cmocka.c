/*
 * cap_offer_cmocka.c - which capabilities CAP LS offers (cap_offered()),
 * and which CAP REQ entries the server refuses (cap_req_refused()), both
 * in capab.h; m_cap.c gathers the facts and applies them.
 *
 * The capability-negotiation spec: a client requests capabilities the
 * server listed, and "if any of the requested capabilities are not
 * supported or cannot be enabled, the server MUST reject the whole
 * request with NAK".  A capability the server does not offer now (its
 * feature is off, what it needs is down, it is hidden) is one it does
 * not support for this client, so a request to add it is refused.
 * Removing one is never refused unless it is sticky.
 */
#include "config.h"
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>
#include "capab.h"

/** An ordinary capability with its feature on is offered at any version. */
static void plain_cap_offered(void **state)
{
  (void)state;
  assert_true(cap_offered(0, 1, 1, 0, 0));
  assert_true(cap_offered(0, 1, 1, 0, 302));
  assert_true(cap_offered(CAPFL_STICKY, 1, 1, 0, 0));
  assert_true(cap_offered(CAPFL_PROTO, 1, 1, 0, 0));
}

/** Its feature off: not offered. */
static void feature_off_not_offered(void **state)
{
  (void)state;
  assert_false(cap_offered(0, 0, 1, 0, 302));
}

/** What it needs is down (sasl with no SASL server, draft/authtoken
 * with no service): not offered. */
static void unavailable_not_offered(void **state)
{
  (void)state;
  assert_false(cap_offered(0, 1, 0, 0, 302));
}

/** Hidden: never offered. */
static void hidden_not_offered(void **state)
{
  (void)state;
  assert_false(cap_offered(CAPFL_HIDDEN, 1, 1, 0, 302));
  assert_false(cap_offered(CAPFL_HIDDEN | CAPFL_PROHIBIT, 1, 1, 0, 302));
}

/** A capability for CAP 302 clients (sts) only: offered from 302 on. */
static void minimum_version(void **state)
{
  (void)state;
  assert_false(cap_offered(0, 1, 1, CAP_VERSION_302, 0));
  assert_false(cap_offered(0, 1, 1, CAP_VERSION_302, 301));
  assert_true(cap_offered(0, 1, 1, CAP_VERSION_302, 302));
  assert_true(cap_offered(0, 1, 1, CAP_VERSION_302, 303));
}

/** Requesting an offered capability is accepted. */
static void req_offered_accepted(void **state)
{
  (void)state;
  assert_false(cap_req_refused(0, 0, 1));
  assert_false(cap_req_refused(CAPFL_STICKY, 0, 1));
}

/** Requesting one that is not offered is refused: the NAK the spec asks
 * for (irctest cap.py testNakWhole; draft/account-registration with its
 * feature off used to be ACKed). */
static void req_not_offered_refused(void **state)
{
  (void)state;
  assert_true(cap_req_refused(0, 0, 0));
}

/** Prohibited: refused even if it were offered (sts, none). */
static void req_prohibited_refused(void **state)
{
  (void)state;
  assert_true(cap_req_refused(CAPFL_PROHIBIT, 0, 1));
  assert_true(cap_req_refused(CAPFL_PROHIBIT, 0, 0));
}

/** Removing a capability is accepted whether or not it is offered now,
 * so a client can always drop one the server stopped offering. */
static void removal_accepted(void **state)
{
  (void)state;
  assert_false(cap_req_refused(0, 1, 1));
  assert_false(cap_req_refused(0, 1, 0));
  assert_false(cap_req_refused(CAPFL_PROHIBIT, 1, 0));
}

/** Removing a sticky capability is refused. */
static void sticky_removal_refused(void **state)
{
  (void)state;
  assert_true(cap_req_refused(CAPFL_STICKY, 1, 1));
  assert_true(cap_req_refused(CAPFL_STICKY, 1, 0));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(plain_cap_offered),
    cmocka_unit_test(feature_off_not_offered),
    cmocka_unit_test(unavailable_not_offered),
    cmocka_unit_test(hidden_not_offered),
    cmocka_unit_test(minimum_version),
    cmocka_unit_test(req_offered_accepted),
    cmocka_unit_test(req_not_offered_refused),
    cmocka_unit_test(req_prohibited_refused),
    cmocka_unit_test(removal_accepted),
    cmocka_unit_test(sticky_removal_refused),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
