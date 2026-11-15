/*
 * gitsync_timer_cmocka.c - GitSync's first sync runs a moment after
 * GitSync starts, from the event loop, once; the periodic sync follows
 * GITSYNC_INTERVAL after it
 *
 * Starting GitSync (GITSYNC_ENABLE true: at boot from the feature notify
 * in the middle of the parse and again from ircd.c, with SET, or with a
 * rehash that turns it on) schedules one sync GITSYNC_FIRST_DELAY seconds
 * later; that sync arms the periodic timer.  Starting again while either
 * is pending -- every rehash, GitSync's own after it applies content
 * among them -- schedules nothing.  Stopping cancels both; off and on
 * again schedules a first sync again.  An interval change re-arms only
 * the periodic timer, from inside its own expiry too.
 *
 * This includes the real ircd_events.c (its timer queue: timer_add,
 * timer_del, timer_run with their GEN_MARKED/GEN_READD handling) and the
 * real gitsync_timer.c, compiled with -ffunction-sections and linked with
 * --gc-sections.  gitsync_trigger() -- the sync itself -- is a stub that
 * records each call and can do what a sync's rehash does.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../ircd_events.c"
#include "../gitsync_timer.c"

#ifdef USE_LIBGIT2

/* ------------------------------------------------------------------ */
/* The ircd around the timers                                          */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;
struct Client me;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
}

int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
                  const char *format, ...)
{
  va_list vl;
  int n;

  (void)dest;
  va_start(vl, format);
  n = vsnprintf(buf, buf_len, format, vl);
  va_end(vl);
  return n;
}

static int f_enable;
static int f_interval;

int feature_bool(enum Feature feat)
{
  assert_int_equal(FEAT_GITSYNC_ENABLE, feat);
  return f_enable;
}

int feature_int(enum Feature feat)
{
  assert_int_equal(FEAT_GITSYNC_INTERVAL, feat);
  return f_interval;
}

/** What a sync does besides syncing, as the content it applies would. */
static enum { SYNC_PLAIN, SYNC_REHASH, SYNC_NEW_INTERVAL, SYNC_DISABLES,
              SYNC_OFF_AND_ON } sync_does;

/** The syncs run: their force flag, and when. */
static int nsyncs;
static int sync_force[16];
static time_t sync_time[16];

int gitsync_trigger(struct Client *cptr, struct Client *sptr, int force)
{
  assert_ptr_equal(&me, cptr);
  assert_null(sptr);
  assert_true(nsyncs < 16);
  sync_force[nsyncs] = force;
  sync_time[nsyncs++] = CurrentTime;

  switch (sync_does) {
  case SYNC_PLAIN:
    break;
  case SYNC_REHASH:             /* GITSYNC_ENABLE set again by the rehash */
    gitsync_start_timer();
    break;
  case SYNC_NEW_INTERVAL:       /* the rehash changes GITSYNC_INTERVAL */
    f_interval = 120;
    gitsync_start_timer();
    gitsync_restart_timer();
    break;
  case SYNC_DISABLES:           /* the rehash turns GitSync off */
    f_enable = 0;
    gitsync_stop_timer();
    break;
  case SYNC_OFF_AND_ON:         /* content turning GitSync off does not */
    f_enable = 0;               /* parse: the rehash turns it off, the */
    gitsync_stop_timer();       /* restore's rehash on again */
    f_enable = 1;
    gitsync_start_timer();
    break;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

static int setup(void **state)
{
  (void)state;
  CurrentTime = 1000;
  f_enable = 1;
  f_interval = 300;
  sync_does = SYNC_PLAIN;
  nsyncs = 0;
  return 0;
}

static int teardown(void **state)
{
  (void)state;
  f_enable = 0;
  gitsync_stop_timer();
  assert_false(t_active(&gitsync_timer));
  assert_false(t_active(&gitsync_first_timer));
  assert_null(evInfo.gens.g_timer);
  return 0;
}

/** Let \a secs seconds pass, running the timers each second. */
static void pass(int secs)
{
  while (secs-- > 0) {
    CurrentTime++;
    timer_run();
  }
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** Boot: the notify mid-parse and ircd.c both start GitSync; one sync
 * runs a second later, forced, and the periodic one an interval after
 * it -- not skipped as "not time yet". */
static void boot_runs_one_first_sync(void **state)
{
  (void)state;
  gitsync_start_timer();        /* feature notify, mid-parse */
  gitsync_start_timer();        /* ircd.c, after init_conf() */
  assert_int_equal(0, nsyncs);  /* never inline */
  assert_false(t_active(&gitsync_timer));
  pass(1);
  assert_int_equal(1, nsyncs);
  assert_int_equal(1, sync_force[0]);
  assert_int_equal(1001, sync_time[0]);
  assert_true(t_active(&gitsync_timer));
  assert_false(t_active(&gitsync_first_timer));
  pass(299);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);
  assert_int_equal(0, sync_force[1]);
  assert_int_equal(1301, sync_time[1]);
  pass(300);
  assert_int_equal(3, nsyncs);
}

/** GitSync off: starting does nothing. */
static void disabled_does_nothing(void **state)
{
  (void)state;
  f_enable = 0;
  gitsync_start_timer();
  pass(400);
  assert_int_equal(0, nsyncs);
  assert_false(t_active(&gitsync_first_timer));
}

/** A rehash while GitSync runs (the notify starts it again): nothing
 * more is scheduled, before or after the first sync. */
static void rehash_schedules_nothing(void **state)
{
  (void)state;
  gitsync_start_timer();
  gitsync_start_timer();        /* rehash before the first sync */
  pass(1);
  assert_int_equal(1, nsyncs);
  gitsync_start_timer();        /* rehash after it */
  pass(299);
  assert_int_equal(1, nsyncs);
}

/** The first sync's own rehash (GitSync applying content) finds GitSync
 * running: no second immediate sync, no loop. */
static void first_sync_rehash_does_not_loop(void **state)
{
  (void)state;
  sync_does = SYNC_REHASH;
  gitsync_start_timer();
  pass(10);
  assert_int_equal(1, nsyncs);
  pass(290);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);  /* the periodic one, at 1301 */
  assert_int_equal(0, sync_force[1]);
}

/** Turned off before the first sync: it never runs. */
static void stop_cancels_first_sync(void **state)
{
  (void)state;
  gitsync_start_timer();
  f_enable = 0;
  gitsync_stop_timer();
  assert_false(t_active(&gitsync_first_timer));
  pass(400);
  assert_int_equal(0, nsyncs);
}

/** Off and on again later: a first sync again, forced. */
static void off_then_on_syncs_again(void **state)
{
  (void)state;
  gitsync_start_timer();
  pass(1);
  assert_int_equal(1, nsyncs);
  f_enable = 0;
  gitsync_stop_timer();
  pass(50);
  f_enable = 1;
  gitsync_start_timer();
  pass(1);
  assert_int_equal(2, nsyncs);
  assert_int_equal(1, sync_force[1]);
  assert_int_equal(1052, sync_time[1]);
  pass(299);
  assert_int_equal(2, nsyncs);
  pass(1);
  assert_int_equal(3, nsyncs);
}

/** An interval change before the first sync arms nothing early; the
 * first sync arms the periodic timer with the interval then. */
static void interval_change_before_first_sync(void **state)
{
  (void)state;
  gitsync_start_timer();
  f_interval = 600;
  gitsync_restart_timer();
  assert_false(t_active(&gitsync_timer));
  pass(1);
  assert_int_equal(1, nsyncs);
  pass(599);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);
}

/** An interval change while running re-arms the periodic timer only. */
static void interval_change_while_running(void **state)
{
  (void)state;
  gitsync_start_timer();
  pass(1);
  pass(100);
  f_interval = 900;
  gitsync_restart_timer();
  assert_false(t_active(&gitsync_first_timer));
  pass(899);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);
  assert_int_equal(0, sync_force[1]);
}

/** Content applied by the first sync changes the interval: the periodic
 * timer armed just before it is re-armed with it. */
static void first_sync_changes_interval(void **state)
{
  (void)state;
  sync_does = SYNC_NEW_INTERVAL;
  gitsync_start_timer();
  pass(1);
  assert_int_equal(1, nsyncs);
  sync_does = SYNC_PLAIN;
  pass(119);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);
  pass(120);
  assert_int_equal(3, nsyncs);
}

/** Content applied by a periodic sync changes the interval: the timer,
 * inside its own expiry, keeps running at the new interval. */
static void periodic_sync_changes_interval(void **state)
{
  (void)state;
  gitsync_start_timer();
  pass(1);
  sync_does = SYNC_NEW_INTERVAL;
  pass(300);
  assert_int_equal(2, nsyncs);
  sync_does = SYNC_PLAIN;
  assert_true(t_active(&gitsync_timer));
  pass(119);
  assert_int_equal(2, nsyncs);
  pass(1);
  assert_int_equal(3, nsyncs);
  pass(120);
  assert_int_equal(4, nsyncs);
}

/** Content applied by the first sync turns GitSync off: nothing runs
 * after it. */
static void first_sync_disables(void **state)
{
  (void)state;
  sync_does = SYNC_DISABLES;
  gitsync_start_timer();
  pass(1);
  assert_int_equal(1, nsyncs);
  assert_false(t_active(&gitsync_timer));
  assert_false(t_active(&gitsync_first_timer));
  pass(600);
  assert_int_equal(1, nsyncs);
}

/** The first sync turns GitSync off and on again (content that disables
 * it and does not parse, then the backup restored): it keeps running --
 * the periodic sync an interval later, no second immediate one. */
static void first_sync_off_and_on(void **state)
{
  (void)state;
  sync_does = SYNC_OFF_AND_ON;
  gitsync_start_timer();
  pass(1);
  assert_int_equal(1, nsyncs);
  sync_does = SYNC_PLAIN;
  assert_true(t_active(&gitsync_timer));
  pass(299);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);
  assert_int_equal(0, sync_force[1]);
  pass(300);
  assert_int_equal(3, nsyncs);
}

/** A periodic sync turns GitSync off and on again: the periodic timer,
 * inside its own expiry, keeps running. */
static void periodic_sync_off_and_on(void **state)
{
  (void)state;
  gitsync_start_timer();
  pass(1);
  sync_does = SYNC_OFF_AND_ON;
  pass(300);
  assert_int_equal(2, nsyncs);
  sync_does = SYNC_PLAIN;
  assert_true(t_active(&gitsync_timer));
  pass(299);
  assert_int_equal(2, nsyncs);
  pass(1);
  assert_int_equal(3, nsyncs);
  assert_int_equal(0, sync_force[2]);
}

/** An interval under a minute is a minute. */
static void interval_at_least_a_minute(void **state)
{
  (void)state;
  f_interval = 5;
  gitsync_start_timer();
  pass(1);
  pass(59);
  assert_int_equal(1, nsyncs);
  pass(1);
  assert_int_equal(2, nsyncs);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(boot_runs_one_first_sync, setup, teardown),
    cmocka_unit_test_setup_teardown(disabled_does_nothing, setup, teardown),
    cmocka_unit_test_setup_teardown(rehash_schedules_nothing, setup, teardown),
    cmocka_unit_test_setup_teardown(first_sync_rehash_does_not_loop, setup, teardown),
    cmocka_unit_test_setup_teardown(stop_cancels_first_sync, setup, teardown),
    cmocka_unit_test_setup_teardown(off_then_on_syncs_again, setup, teardown),
    cmocka_unit_test_setup_teardown(interval_change_before_first_sync, setup, teardown),
    cmocka_unit_test_setup_teardown(interval_change_while_running, setup, teardown),
    cmocka_unit_test_setup_teardown(first_sync_changes_interval, setup, teardown),
    cmocka_unit_test_setup_teardown(periodic_sync_changes_interval, setup, teardown),
    cmocka_unit_test_setup_teardown(first_sync_disables, setup, teardown),
    cmocka_unit_test_setup_teardown(interval_at_least_a_minute, setup, teardown),
    cmocka_unit_test_setup_teardown(first_sync_off_and_on, setup, teardown),
    cmocka_unit_test_setup_teardown(periodic_sync_off_and_on, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}

#else /* !USE_LIBGIT2 */

int main(void)
{
  printf("gitsync_timer_cmocka: GitSync not built (no libgit2), nothing to test\n");
  return 0;
}

#endif /* USE_LIBGIT2 */
