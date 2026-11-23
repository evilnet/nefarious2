/*
 * IRC - Internet Relay Chat, include/stale.h
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
 */
/** @file
 * @brief The stale-data limit (STALE_AFTER): how long anything about an
 *   absent server is kept, and when a server's own stored data is out of
 *   date.
 *
 * A server can come back after any absence with the state it stored
 * before it left.  One limit bounds that: a server split from the rest of
 * the network for longer than the limit treats its own stored data as
 * stale; the others keep their deletion records at least that long, so a
 * server back within it can catch up; and an absent server is forgotten
 * once it has been gone longer.  Every server of a network should use the
 * same value.
 *
 * This module is PURE (no ircd dependencies) so the cmocka suite runs it
 * standalone (ircd/test/stale_cmocka.c).  The setting itself is read
 * through stale_limit() (ircd_features.c), which clamps it with
 * stale_limit_clamp().
 */
#ifndef INCLUDED_stale_h
#define INCLUDED_stale_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif
#ifndef INCLUDED_time_h
#include <time.h>
#define INCLUDED_time_h
#endif

/** The limit (STALE_AFTER) as every reader reads it: clamped by
 * stale_limit_clamp().  Defined in ircd_features.c, not here. */
extern time_t stale_limit(void);

/** The smallest limit honoured, in seconds: a lower setting reads as this. */
#define STALE_LIMIT_MIN 60

/** How far in the future (seconds) a last-linked mark may be before the
 * clock that wrote it, and the store with it, is not trusted. */
#define STALE_FUTURE_SKEW 120

/** The limit as configured, clamped to at least STALE_LIMIT_MIN. */
extern time_t stale_limit_clamp(long configured);

/** Is a store stale?
 * @param[in] last_linked When (unix seconds) this server last had another
 *   server linked; 0 when it has no such mark.
 * @param[in] now The current time.
 * @param[in] limit The limit (seconds).
 * @param[in] has_rows Whether the store holds any rows.
 * @return 1 when the mark is older than @a limit (equal is not), or more
 *   than STALE_FUTURE_SKEW seconds in the future; 0 otherwise -- always 0
 *   with no mark, rows or not (a store from before the mark existed is
 *   not stale at the first start that could read one).
 */
extern int stale_decide(time_t last_linked, time_t now, time_t limit,
                        int has_rows);

/** How long a deletion record must be kept: the longer of the configured
 * lifetime and the limit.  A configured lifetime of 0 or less means "keep
 * for ever" and stays 0. */
extern time_t stale_lifetime(time_t configured_ttl, time_t limit);

/** Is an absent server forgotten?  An absence from @a start (unix
 * seconds; 0: none) to @a end (0: still away) is forgotten when the server
 * is still away and has been for longer than @a limit (equal is not).  An
 * absence that ended is not this rule's: it keeps its own age-out.  A
 * start in the future (the clock went back) is not forgotten.
 * @return 1 when forgotten. */
extern int stale_absence_forgotten(time_t start, time_t end, time_t now,
                                   time_t limit);

#endif /* INCLUDED_stale_h */
