/* cmocka suite for the pure bouncer wire decisions (include/bouncer_wire.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_wire.h"

/* bounce_legacy_link_knows(link_aware, link_gated, face_behind_link,
 *                          recorded_face, face_numeric) */

static void aware_link_never_knows(void **s)
{
  (void)s;
  /* An IRCv3-aware link follows the session through BX/BS (it got the
   * BX X or BX P itself); it never needs a legacy retraction. */
  assert_false(bounce_legacy_link_knows(1, 0, 0, NULL, "BjAAB"));
  assert_false(bounce_legacy_link_knows(1, 0, 0, "BjAAB", "BjAAB"));
}

static void gated_link_knows_nothing(void **s)
{
  (void)s;
  /* No N has gone to a gated link yet; its burst at release carries the
   * final face once. */
  assert_false(bounce_legacy_link_knows(0, 1, 0, NULL, "BjAAB"));
  assert_false(bounce_legacy_link_knows(0, 1, 0, "BjAAB", "BjAAB"));
}

static void own_direction_excluded(void **s)
{
  (void)s;
  /* The link the face lives behind introduced it to us. */
  assert_false(bounce_legacy_link_knows(0, 0, 1, NULL, "ACAAB"));
  assert_false(bounce_legacy_link_knows(0, 0, 1, "ACAAB", "ACAAB"));
}

static void other_face_recorded(void **s)
{
  (void)s;
  /* The burst gave this link another face of the session and suppressed
   * this one. */
  assert_false(bounce_legacy_link_knows(0, 0, 0, "BjAAC", "BjAAB"));
}

static void same_or_no_record(void **s)
{
  (void)s;
  assert_true(bounce_legacy_link_knows(0, 0, 0, "BjAAB", "BjAAB"));
  assert_true(bounce_legacy_link_knows(0, 0, 0, NULL, "BjAAB"));
  assert_true(bounce_legacy_link_knows(0, 0, 0, "", "BjAAB"));
}

static void no_face_numeric_knows_nothing(void **s)
{
  (void)s;
  /* Nothing to retract without a numeric. */
  assert_false(bounce_legacy_link_knows(0, 0, 0, NULL, NULL));
  assert_false(bounce_legacy_link_knows(0, 0, 0, "BjAAB", ""));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(aware_link_never_knows),
    cmocka_unit_test(gated_link_knows_nothing),
    cmocka_unit_test(own_direction_excluded),
    cmocka_unit_test(other_face_recorded),
    cmocka_unit_test(same_or_no_record),
    cmocka_unit_test(no_face_numeric_knows_nothing),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
