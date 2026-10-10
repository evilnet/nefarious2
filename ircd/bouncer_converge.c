/*
 * IRC - Internet Relay Chat, ircd/bouncer_converge.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_converge.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_converge.h"

#include <string.h>

int bounce_converge_peer_wins(int local_holding, const char *local_sessid,
                              int peer_holding, const char *peer_sessid)
{
  if (!local_sessid)
    local_sessid = "";
  if (!peer_sessid)
    peer_sessid = "";

  /* State first: a live session outranks a held or clientless one. */
  if (!local_holding && peer_holding)
    return 0;
  if (local_holding && !peer_holding)
    return 1;

  /* Same state: the older session id (lexicographically lower UUID v7)
   * wins; identical ids are the same session, ours stays. */
  return strcmp(peer_sessid, local_sessid) < 0;
}
