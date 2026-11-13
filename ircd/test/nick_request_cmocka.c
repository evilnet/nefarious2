/*
 * nick_request_cmocka.c - a nick change over a link meeting the nick's
 * holder (include/nick_request.h).
 *
 * A user of ours renamed over a link is a bouncer device's request for its
 * session user, and the primary's server decides it: refused, never the
 * classic collision (which KILLs the user and, with asserts on, aborts on
 * assert(!MyConnect(sptr)) first).
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "nick_request.h"

/* A device's request for its primary, ours, meets a registered holder
 * (a user here or on a third server, a held ghost, a dying client):
 * refused. */
static void test_device_request_is_refused(void **state)
{
  (void)state;
  assert_int_equal(nick_change_meets(1, 0), NICK_MEET_REFUSE);
}

/* Another server's user meets a holder: the classic rules, unchanged. */
static void test_remote_user_is_classic(void **state)
{
  (void)state;
  assert_int_equal(nick_change_meets(0, 0), NICK_MEET_CLASSIC);
}

/* Our unregistered holder gives way whoever is renamed. */
static void test_unregistered_holder_gives_way(void **state)
{
  (void)state;
  assert_int_equal(nick_change_meets(0, 1), NICK_MEET_OVERRIDE);
  assert_int_equal(nick_change_meets(1, 1), NICK_MEET_OVERRIDE);
}

/* The classic rules never see a user of ours. */
static void test_classic_never_for_ours(void **state)
{
  int h;

  (void)state;
  for (h = 0; h <= 1; h++)
    assert_int_not_equal(nick_change_meets(1, h), NICK_MEET_CLASSIC);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_device_request_is_refused),
    cmocka_unit_test(test_remote_user_is_classic),
    cmocka_unit_test(test_unregistered_holder_gives_way),
    cmocka_unit_test(test_classic_never_for_ours),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
