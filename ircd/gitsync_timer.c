/*
 * IRC - Internet Relay Chat, ircd/gitsync_timer.c
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief GitSync - when the syncs run.
 *
 * GitSync starts when GITSYNC_ENABLE becomes true: at boot (from the
 * feature notify in the middle of the configuration parse, else from
 * ircd.c once the configuration is read), with SET, or with a rehash
 * that turns it on.  Starting schedules the first sync a moment later,
 * from the event loop -- never inline: the feature notify runs before
 * the rest of the configuration (the repository among it) is read, and
 * at boot before the event loop exists.  The first sync arms the
 * periodic timer, GITSYNC_INTERVAL apart from then on.  Starting again
 * while either is pending does nothing, so a rehash -- GitSync's own
 * after it applies content among them -- schedules nothing more.
 * Stopping cancels both; an interval change re-arms the periodic timer
 * only.
 */
#include "config.h"

#ifdef USE_LIBGIT2

#include "gitsync.h"
#include "client.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "s_debug.h"

/** Seconds from GitSync starting to its first sync. */
#define GITSYNC_FIRST_DELAY 1

/** Timer for periodic gitsync */
static struct Timer gitsync_timer;

/** One-shot timer for the first sync after GitSync starts. */
static struct Timer gitsync_first_timer;

/** Timer callback for periodic gitsync
 * @param ev Timer event
 */
static void
gitsync_timer_callback(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE) {
    gitsync_trigger(&me, NULL, 0);
  }
}

/** The periodic sync's interval: GITSYNC_INTERVAL, at least 60 seconds. */
static int
gitsync_interval(void)
{
  int interval = feature_int(FEAT_GITSYNC_INTERVAL);

  return interval < 60 ? 60 : interval; /* Minimum 1 minute */
}

/** Arm the periodic timer, one interval from now. */
static void
gitsync_arm_periodic(void)
{
  int interval = gitsync_interval();

  timer_add(timer_init(&gitsync_timer), gitsync_timer_callback,
            NULL, TT_PERIODIC, interval);

  Debug((DEBUG_INFO, "GitSync: Timer started with interval %d seconds", interval));
}

/** The first sync after GitSync started: the periodic timer counts from
 * here (armed first, so that the sync's own rehash finds GitSync running
 * and an interval change in the content it applies re-arms it), then the
 * sync runs, forced: whenever the last one was, starting GitSync syncs.
 * It reports as a periodic sync does.
 * @param ev Timer event
 */
static void
gitsync_first_callback(struct Event *ev)
{
  if (ev_type(ev) != ET_EXPIRE)
    return;
  if (!t_active(&gitsync_timer))
    gitsync_arm_periodic();
  gitsync_trigger(&me, NULL, 1);
}

/** Whether \a tim is inside its own expiry callback (timer_run() marks
 * it): timer_del() then only stops a periodic timer being re-queued, and
 * it must never be timer_init()ed. */
#define t_running(tim) ((tim)->t_header.gh_flags & GEN_MARKED)

void
gitsync_start_timer(void)
{
  if (!feature_bool(FEAT_GITSYNC_ENABLE))
    return;

  /* A sync's rehash turned GitSync off and another (the restore's) on
   * again, inside one expiry.  The periodic timer's own: timer_del() only
   * cleared its re-queue; timer_add() without timer_init() sets it again,
   * and timer_run() re-queues the timer at the interval when the callback
   * returns.  The first sync's: the stop deleted the periodic timer armed
   * just before it; arm it again. */
  if (t_running(&gitsync_timer)) {
    if (!(gitsync_timer.t_header.gh_flags & GEN_READD))
      timer_add(&gitsync_timer, gitsync_timer_callback, NULL, TT_PERIODIC,
                gitsync_interval());
    return;
  }
  if (t_running(&gitsync_first_timer)) {
    if (!t_active(&gitsync_timer))
      gitsync_arm_periodic();
    return;
  }

  /* Idempotent: GitSync is running, or its first sync is scheduled.
   * Notify callbacks fire during init_conf() before ircd.c calls us at
   * boot, and on every rehash that sets GITSYNC_ENABLE. */
  if (t_active(&gitsync_timer) || t_active(&gitsync_first_timer))
    return;

  /* An include of the configuration file that does not exist yet is read
   * as empty, and its placeholder written, by the configuration pass that
   * reads it (s_conf.c conf_settle_absent_includes()). */

  /* Starting (again): whatever was applied before, the first sync
   * writes the file. */
  gitsync_forget_applied();
  timer_add(timer_init(&gitsync_first_timer), gitsync_first_callback,
            NULL, TT_RELATIVE, GITSYNC_FIRST_DELAY);

  Debug((DEBUG_INFO, "GitSync: started, first sync in %d seconds",
         GITSYNC_FIRST_DELAY));
}

void
gitsync_stop_timer(void)
{
  if (t_active(&gitsync_first_timer))
    timer_del(&gitsync_first_timer);
  if (t_active(&gitsync_timer))
    timer_del(&gitsync_timer);
}

void
gitsync_restart_timer(void)
{
  /* Only re-arm a running periodic timer.  Before the first sync (at boot
   * the notify fires from init_conf()) the first sync arms it with the
   * interval in force then. */
  if (!t_active(&gitsync_timer))
    return;
  /* Inside its own expiry (a periodic sync applied content that changes
   * the interval): timer_run() re-queues it after the callback, at its
   * value from then.  Deleting and re-adding it here would have it
   * destroyed after the callback while queued. */
  if (t_running(&gitsync_timer)) {
    gitsync_timer.t_value = gitsync_interval();
    return;
  }
  timer_del(&gitsync_timer);
  gitsync_arm_periodic();
}

/** GitSync's configuration file was replaced by a placeholder (it was
 * removed, or GITSYNC_CONF_FILE names a new one, and a configuration pass
 * read it as empty): the content is gone from the live configuration.
 * What was applied is forgotten, and a sync runs a second from now, as
 * when GitSync starts -- unless one is already scheduled, or this is a
 * sync's own rehash (no loop).
 */
void
gitsync_conf_file_lost(void)
{
  gitsync_forget_applied();
  if (!feature_bool(FEAT_GITSYNC_ENABLE) || gitsync_busy() ||
      t_active(&gitsync_first_timer))
    return;
  timer_add(timer_init(&gitsync_first_timer), gitsync_first_callback,
            NULL, TT_RELATIVE, GITSYNC_FIRST_DELAY);
  Debug((DEBUG_INFO, "GitSync: configuration file replaced by a "
         "placeholder, sync in %d seconds", GITSYNC_FIRST_DELAY));
}

#endif /* USE_LIBGIT2 */
