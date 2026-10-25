/*
 * IRC - Internet Relay Chat, ircd/bouncer_wire.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_wire.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_wire.h"

int bounce_legacy_link_knows(int link_aware, int link_gated,
                             int face_behind_link)
{
  /* An aware link follows the session itself; a gated one has been sent
   * nothing yet; the face's own direction introduced it to us. */
  if (link_aware || link_gated || face_behind_link)
    return 0;
  return 1;
}
