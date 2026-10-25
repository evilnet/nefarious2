/* cmocka suite for the pure bouncer wire decisions (include/bouncer_wire.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_wire.h"

/* bounce_legacy_link_knows(link_aware, link_gated, face_behind_link) */

static void aware_link_never_knows(void **s)
{
  (void)s;
  /* An IRCv3-aware link follows the session through BX/BS (it got the
   * BX X or BX P itself); it never needs a legacy retraction. */
  assert_false(bounce_legacy_link_knows(1, 0, 0));
}

static void gated_link_knows_nothing(void **s)
{
  (void)s;
  /* No N has gone to a gated link yet; its burst at release carries the
   * final face once. */
  assert_false(bounce_legacy_link_knows(0, 1, 0));
}

static void own_direction_excluded(void **s)
{
  (void)s;
  /* The link the face lives behind introduced it to us. */
  assert_false(bounce_legacy_link_knows(0, 0, 1));
}

static void legacy_link_may_know_whatever_is_recorded(void **s)
{
  (void)s;
  /* A legacy link that is neither gated nor the face's own direction may
   * know the face, even when the session's burst records name another
   * face toward it: a relayed N records nothing, and a record can be
   * stale.  The records are not an input. */
  assert_true(bounce_legacy_link_knows(0, 0, 0));
}

static void only_a_plain_legacy_link_knows(void **s)
{
  int aware, gated, behind;
  (void)s;
  for (aware = 0; aware < 2; aware++)
    for (gated = 0; gated < 2; gated++)
      for (behind = 0; behind < 2; behind++)
        assert_int_equal(bounce_legacy_link_knows(aware, gated, behind),
                         !aware && !gated && !behind);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(aware_link_never_knows),
    cmocka_unit_test(gated_link_knows_nothing),
    cmocka_unit_test(own_direction_excluded),
    cmocka_unit_test(legacy_link_may_know_whatever_is_recorded),
    cmocka_unit_test(only_a_plain_legacy_link_knows),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
