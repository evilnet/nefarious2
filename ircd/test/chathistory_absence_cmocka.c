/*
 * chathistory_absence_cmocka.c - the storage-server absence table
 *
 * Each storage server that leaves gets an absence in m_chathistory.c's
 * table (absence_open at its SQUIT, absence_close when its burst has
 * ended after it is back).  A page whose span meets an absence fans out;
 * one that meets an OPEN absence (that store is away now) is answered
 * partial, and so is a page over a span never received here while any
 * store is away (store_away_now).  These cases hold the table to its
 * rules, on the REAL code:
 *
 *  - an absence younger than the stale-data limit (STALE_AFTER) is kept,
 *    open or closed, and an open one makes the pages over it partial;
 *  - an absent server not back within the limit is forgotten: its open
 *    absence goes, so it no longer makes a page partial or counts as
 *    away; whether or not a page asked in between, so its return finds
 *    nothing to close (a later SQUIT opens a new absence from then);
 *  - a closed absence is left to its own age-out (the store's floor),
 *    however old.
 *
 * m_chathistory.c is included, compiled with -ffunction-sections and
 * linked with --gc-sections (as chathistory_search_job_cmocka does), so
 * the program keeps only what the table and the partial decision reach;
 * the rest of the ircd they reach is the test's, below.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../m_chathistory.c"

#include "stale.h"

#define DAY   86400
#define T0    ((time_t)1700000000)

/* ------------------------------------------------------------------ */
/* The ircd around the table                                           */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;
struct Client me;

static int stale_after;           /**< STALE_AFTER */
static int peer_missing;          /**< history_recv_peer_missing() */
static int received;              /**< history_recv_covers() */
static uint64_t live_floor_ms;    /**< history_live_floor_ms() */

time_t stale_limit(void) { return stale_limit_clamp(stale_after); }
int history_recv_peer_missing(void) { return peer_missing; }
uint64_t history_live_floor_ms(void) { return live_floor_ms; }
uint64_t history_recv_now_ms(void) { return (uint64_t)CurrentTime * 1000ULL; }
int history_recv_covers(const char *chname, uint64_t lo_ms, uint64_t hi_ms)
{
  (void)chname; (void)lo_ms; (void)hi_ms;
  return received;
}
struct Channel *hSeekChannel(const char *name) { (void)name; return NULL; }
int feature_int(enum Feature feat) { (void)feat; return 0; }
int feature_bool(enum Feature feat) { (void)feat; return 0; }
void debug(int level, const char *form, ...) { (void)level; (void)form; }
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

#define SERVER 5                  /**< the absent store's table index */

/** Is a channel page over [lo, hi] (0: open) partial? */
static int page_partial(time_t lo, time_t hi)
{
  int partial = 0;

  channel_range_check("#chan", lo, hi, &partial);
  return partial;
}

/** Does a span meet any absence, and is the one it meets open? */
static int overlaps(time_t lo, time_t hi, int *open_hit)
{
  return absence_overlap(lo, hi, open_hit);
}

static int setup(void **state)
{
  (void)state;
  CurrentTime = T0;
  stale_after = 14 * DAY;
  peer_missing = 0;
  received = 1;
  live_floor_ms = 0;
  memset(absences, 0, sizeof(absences));
  return 0;
}

static int teardown(void **state)
{
  int i;

  (void)state;
  for (i = 0; i < MAX_AD_SERVERS; i++)
    if (absences[i]) {
      MyFree(absences[i]);
      absences[i] = NULL;
    }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** Within the limit an open absence stays: the store is away, a page over
 * its time is partial and fans out -- at exactly the limit too. */
static void an_open_absence_within_the_limit_stays(void **state)
{
  int open_hit;

  absence_open(SERVER);
  CurrentTime = T0 + 60;
  assert_true(store_away_now());
  assert_true(page_partial(0, 0));
  CurrentTime = T0 + 14 * DAY;
  assert_true(store_away_now());
  assert_true(page_partial(0, 0));
  assert_int_equal(channel_range_check("#chan", 0, 0, &(int){0}),
                   FED_WHY_ABSENCE);
  assert_true(overlaps(T0 - 10, T0 + 10, &open_hit));
  assert_true(open_hit);
}

/** Past the limit the absent store is forgotten: it no longer makes a page
 * partial, is no longer away, and no page fans out for it. */
static void an_open_absence_past_the_limit_is_forgotten(void **state)
{
  int open_hit;

  absence_open(SERVER);
  CurrentTime = T0 + 14 * DAY + 1;
  assert_false(store_away_now());
  assert_false(page_partial(0, 0));
  assert_int_equal(channel_range_check("#chan", 0, 0, &(int){0}),
                   FED_WHY_NONE);
  assert_false(overlaps(T0 - 10, T0 + 10, &open_hit));
  assert_false(open_hit);
}

/** The limit as set, the smallest one included. */
static void the_smallest_limit_is_a_minute(void **state)
{
  stale_after = 1;                 /* read as 60 */
  absence_open(SERVER);
  CurrentTime = T0 + 60;
  assert_true(store_away_now());
  CurrentTime = T0 + 61;
  assert_false(store_away_now());
  assert_false(page_partial(0, 0));
}

/** A page over a span never received here is partial while a store is
 * away -- and no longer once that store is forgotten (unless the on-disk
 * mark still says one is missing). */
static void an_unreceived_span_follows_the_absence(void **state)
{
  received = 0;
  absence_open(SERVER);
  CurrentTime = T0 + DAY;
  assert_true(page_partial(T0 + 10, T0 + 20));
  CurrentTime = T0 + 15 * DAY;
  assert_false(page_partial(T0 + 10, T0 + 20));
  peer_missing = 1;
  assert_true(page_partial(T0 + 10, T0 + 20));
}

/** Its return finds nothing to close when it was forgotten, whether or not
 * a page asked about it in between: no absence covers the time it was
 * away. */
static void a_store_back_past_the_limit_has_no_absence(void **state)
{
  int open_hit;

  absence_open(SERVER);
  CurrentTime = T0 + 20 * DAY;
  absence_close(SERVER);           /* back; no page asked since it left */
  assert_false(overlaps(T0, T0 + 20 * DAY, &open_hit));
  assert_false(store_away_now());
}

/** A store back within the limit keeps its closed absence: pages over it
 * fan out and are not partial; it stays however old, until the floor. */
static void a_closed_absence_keeps_its_own_rule(void **state)
{
  int open_hit;

  absence_open(SERVER);
  CurrentTime = T0 + 10 * DAY;
  absence_close(SERVER);
  CurrentTime = T0 + 100 * DAY;
  assert_true(overlaps(T0 + DAY, T0 + 2 * DAY, &open_hit));
  assert_false(open_hit);
  assert_false(store_away_now());
  /* The floor passes its end: it ages out as before. */
  live_floor_ms = (uint64_t)(T0 + 10 * DAY + 1) * 1000ULL;
  assert_false(overlaps(T0 + DAY, T0 + 2 * DAY, &open_hit));
}

/** Leaving again after it was forgotten opens a new absence from then. */
static void a_new_absence_after_a_forgotten_one_starts_now(void **state)
{
  int open_hit;

  absence_open(SERVER);
  CurrentTime = T0 + 20 * DAY;
  absence_open(SERVER);            /* left again (its last EB never came) */
  CurrentTime = T0 + 20 * DAY + 60;
  assert_true(store_away_now());
  assert_false(overlaps(T0 + DAY, T0 + 2 * DAY, &open_hit));
  assert_true(overlaps(T0 + 20 * DAY, 0, &open_hit));
  assert_true(open_hit);
}

/** The forgotten open absence goes alone: an older closed one of the same
 * store, and another store's open one, stay. */
static void only_the_forgotten_absence_goes(void **state)
{
  int open_hit;

  absence_open(SERVER);
  CurrentTime = T0 + DAY;
  absence_close(SERVER);
  CurrentTime = T0 + 2 * DAY;
  absence_open(SERVER);
  CurrentTime = T0 + 10 * DAY;
  absence_open(SERVER + 1);
  CurrentTime = T0 + 17 * DAY;     /* SERVER's open one: 15 days */
  assert_true(store_away_now());   /* SERVER + 1: 7 days */
  assert_true(overlaps(T0 + 100, T0 + 200, &open_hit));   /* the closed one */
  assert_false(open_hit);
  assert_true(overlaps(T0 + 3 * DAY, T0 + 4 * DAY, &open_hit) == 0);
  CurrentTime = T0 + 25 * DAY;
  assert_false(store_away_now());
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(an_open_absence_within_the_limit_stays, setup, teardown),
    cmocka_unit_test_setup_teardown(an_open_absence_past_the_limit_is_forgotten, setup, teardown),
    cmocka_unit_test_setup_teardown(the_smallest_limit_is_a_minute, setup, teardown),
    cmocka_unit_test_setup_teardown(an_unreceived_span_follows_the_absence, setup, teardown),
    cmocka_unit_test_setup_teardown(a_store_back_past_the_limit_has_no_absence, setup, teardown),
    cmocka_unit_test_setup_teardown(a_closed_absence_keeps_its_own_rule, setup, teardown),
    cmocka_unit_test_setup_teardown(a_new_absence_after_a_forgotten_one_starts_now, setup, teardown),
    cmocka_unit_test_setup_teardown(only_the_forgotten_absence_goes, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
