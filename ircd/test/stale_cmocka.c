/*
 * stale_cmocka.c - the stale-data limit's decisions (ircd/stale.c, pure)
 *
 * One limit (STALE_AFTER, seconds) bounds how long anything about an
 * absent server is kept:
 *
 *  - stale_limit_clamp(): the setting as read -- never below a minute;
 *  - stale_decide(): is this server's own store stale?  Split from every
 *    other server for longer than the limit (a mark from the future
 *    beyond the allowed skew counts too); a store with no mark is never
 *    stale (it predates the mark, or holds nothing);
 *  - stale_lifetime(): how long a deletion record is kept -- never less
 *    than the limit, and "forever" (0) stays forever.
 */
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <cmocka.h>

#include "stale.h"

#define DAY   86400
#define LIMIT (14 * DAY)
#define NOW   ((time_t)1700000000)

/* ------------------------------------------------------------------ */
/* stale_limit_clamp                                                   */
/* ------------------------------------------------------------------ */

static void the_limit_is_never_below_a_minute(void **state)
{
  assert_int_equal(stale_limit_clamp(1209600), 1209600);
  assert_int_equal(stale_limit_clamp(61), 61);
  assert_int_equal(stale_limit_clamp(60), 60);
  assert_int_equal(stale_limit_clamp(59), 60);
  assert_int_equal(stale_limit_clamp(1), 60);
  assert_int_equal(stale_limit_clamp(0), 60);
  assert_int_equal(stale_limit_clamp(-5), 60);
  assert_int_equal(STALE_LIMIT_MIN, 60);
}

/* ------------------------------------------------------------------ */
/* stale_decide                                                        */
/* ------------------------------------------------------------------ */

/** Split for longer than the limit: stale; for exactly the limit or less:
 * not. */
static void a_store_past_the_limit_is_stale(void **state)
{
  assert_true(stale_decide(NOW - LIMIT - 1, NOW, LIMIT, 1));
  assert_true(stale_decide(NOW - 100 * DAY, NOW, LIMIT, 1));
  assert_false(stale_decide(NOW - LIMIT, NOW, LIMIT, 1));
  assert_false(stale_decide(NOW - LIMIT + 1, NOW, LIMIT, 1));
  assert_false(stale_decide(NOW - 60, NOW, LIMIT, 1));
  assert_false(stale_decide(NOW, NOW, LIMIT, 1));
}

/** Whether it holds rows does not matter once there is a mark. */
static void with_a_mark_the_rows_do_not_matter(void **state)
{
  assert_true(stale_decide(NOW - LIMIT - 1, NOW, LIMIT, 0));
  assert_false(stale_decide(NOW - LIMIT, NOW, LIMIT, 0));
}

/** A mark from the future: within the allowed skew it is now; past it, the
 * clock that wrote it cannot be trusted, and neither can the store. */
static void a_mark_from_the_future_past_the_skew_is_stale(void **state)
{
  assert_int_equal(STALE_FUTURE_SKEW, 120);
  assert_false(stale_decide(NOW + 1, NOW, LIMIT, 1));
  assert_false(stale_decide(NOW + 120, NOW, LIMIT, 1));
  assert_true(stale_decide(NOW + 121, NOW, LIMIT, 1));
  assert_true(stale_decide(NOW + 10 * DAY, NOW, LIMIT, 0));
}

/** No mark: a store from before the mark existed is not discarded at the
 * first start that reads one; an empty store has nothing to discard. */
static void without_a_mark_it_is_not_stale(void **state)
{
  assert_false(stale_decide(0, NOW, LIMIT, 1));
  assert_false(stale_decide(0, NOW, LIMIT, 0));
}

/** The limit as configured, the smallest included. */
static void the_boundary_holds_at_the_smallest_limit(void **state)
{
  assert_false(stale_decide(NOW - 60, NOW, 60, 1));
  assert_true(stale_decide(NOW - 61, NOW, 60, 1));
}

/* ------------------------------------------------------------------ */
/* stale_lifetime                                                      */
/* ------------------------------------------------------------------ */

static void a_deletion_record_lives_at_least_the_limit(void **state)
{
  /* configured shorter: the limit */
  assert_int_equal(stale_lifetime(3600, LIMIT), LIMIT);
  assert_int_equal(stale_lifetime(1, 60), 60);
  /* configured longer: as configured */
  assert_int_equal(stale_lifetime(30 * DAY, LIMIT), 30 * DAY);
  assert_int_equal(stale_lifetime(LIMIT + 1, LIMIT), LIMIT + 1);
  /* equal */
  assert_int_equal(stale_lifetime(LIMIT, LIMIT), LIMIT);
}

/** 0 or less configured is "keep for ever", and stays so. */
static void forever_stays_forever(void **state)
{
  assert_int_equal(stale_lifetime(0, LIMIT), 0);
  assert_int_equal(stale_lifetime(-1, LIMIT), 0);
  assert_int_equal(stale_lifetime(-30 * DAY, 60), 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(the_limit_is_never_below_a_minute),
    cmocka_unit_test(a_store_past_the_limit_is_stale),
    cmocka_unit_test(with_a_mark_the_rows_do_not_matter),
    cmocka_unit_test(a_mark_from_the_future_past_the_skew_is_stale),
    cmocka_unit_test(without_a_mark_it_is_not_stale),
    cmocka_unit_test(the_boundary_holds_at_the_smallest_limit),
    cmocka_unit_test(a_deletion_record_lives_at_least_the_limit),
    cmocka_unit_test(forever_stays_forever),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
