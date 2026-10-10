/* cmocka suite for bounce_converge_peer_wins (include/bouncer_converge.h). */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../include/bouncer_converge.h"

#define OLDER "AaCcFXwvcGOUX/PyoTpM1Q"   /* lexicographically lower = older UUID v7 */
#define NEWER "AaCrYZ3QcGOHqRsexudEHQ"

static void test_active_beats_holding_whatever_the_age(void **state)
{
  (void)state;
  /* The field case: our record is an older, clientless HOLDING replica;
   * the peer announces the live session.  The peer must win. */
  assert_int_equal(bounce_converge_peer_wins(1, OLDER, 0, NEWER), 1);
  /* Mirror image on the other server: we hold the live one. */
  assert_int_equal(bounce_converge_peer_wins(0, NEWER, 1, OLDER), 0);
  /* Age in the other direction changes nothing. */
  assert_int_equal(bounce_converge_peer_wins(1, NEWER, 0, OLDER), 1);
  assert_int_equal(bounce_converge_peer_wins(0, OLDER, 1, NEWER), 0);
}

static void test_same_state_older_id_wins(void **state)
{
  (void)state;
  assert_int_equal(bounce_converge_peer_wins(0, NEWER, 0, OLDER), 1);
  assert_int_equal(bounce_converge_peer_wins(0, OLDER, 0, NEWER), 0);
  assert_int_equal(bounce_converge_peer_wins(1, NEWER, 1, OLDER), 1);
  assert_int_equal(bounce_converge_peer_wins(1, OLDER, 1, NEWER), 0);
}

static void test_identical_id_keeps_ours(void **state)
{
  (void)state;
  assert_int_equal(bounce_converge_peer_wins(0, OLDER, 0, OLDER), 0);
  assert_int_equal(bounce_converge_peer_wins(1, OLDER, 1, OLDER), 0);
}

static void test_both_sides_agree(void **state)
{
  (void)state;
  /* Determinism: for every pairing exactly one side wins. */
  static const char *ids[2] = { OLDER, NEWER };
  int ls, ps, li, pi;
  for (ls = 0; ls < 2; ls++)
    for (ps = 0; ps < 2; ps++)
      for (li = 0; li < 2; li++)
        for (pi = 0; pi < 2; pi++) {
          int a = bounce_converge_peer_wins(ls, ids[li], ps, ids[pi]);
          int b = bounce_converge_peer_wins(ps, ids[pi], ls, ids[li]);
          if (li == pi && ls == ps)
            assert_int_equal(a + b, 0);   /* same record: nobody yields */
          else
            assert_int_equal(a + b, 1);   /* exactly one side yields */
        }
}

static void test_null_ids_do_not_crash(void **state)
{
  (void)state;
  assert_int_equal(bounce_converge_peer_wins(1, NULL, 0, NULL), 1);
  assert_int_equal(bounce_converge_peer_wins(0, NULL, 0, NULL), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_active_beats_holding_whatever_the_age),
    cmocka_unit_test(test_same_state_older_id_wins),
    cmocka_unit_test(test_identical_id_keeps_ours),
    cmocka_unit_test(test_both_sides_agree),
    cmocka_unit_test(test_null_ids_do_not_crash),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
