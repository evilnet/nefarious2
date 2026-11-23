/*
 * IRC - Internet Relay Chat, ircd/stale.c
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
 * @brief The stale-data limit's decisions.  See include/stale.h.  Keep
 *   this file free of ircd headers: it is compiled standalone for the
 *   cmocka suite.
 */
#include "stale.h"

time_t stale_limit_clamp(long configured)
{
  return configured < STALE_LIMIT_MIN ? (time_t)STALE_LIMIT_MIN
                                      : (time_t)configured;
}

int stale_decide(time_t last_linked, time_t now, time_t limit, int has_rows)
{
  /* No mark: the store predates it (it must not be thrown away at the
   * first start that could have written one), or it is empty. */
  (void)has_rows;
  if (last_linked <= 0)
    return 0;
  if (last_linked > now)
    return last_linked - now > STALE_FUTURE_SKEW;
  return now - last_linked > limit;
}

time_t stale_lifetime(time_t configured_ttl, time_t limit)
{
  if (configured_ttl <= 0)
    return 0;   /* kept for ever */
  return configured_ttl > limit ? configured_ttl : limit;
}

int stale_absence_forgotten(time_t start, time_t end, time_t now, time_t limit)
{
  /* Back (end set): the absence keeps its own age-out.  A start ahead of
   * the clock (it went back) is kept rather than forgotten early. */
  if (start <= 0 || end != 0 || start > now)
    return 0;
  return now - start > limit;
}
