/*
 * IRC - Internet Relay Chat, ircd/nick_route.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
/** @file
 * @brief Whether the way to a session primary's server carries a bouncer
 *   device's nick request (BX W).  Kept apart so the CMocka suite
 *   (ircd/test/nick_route_cmocka.c) links it alone.
 */
#include "config.h"

#include "nick_route.h"

#include "bouncer_wire.h"
#include "client.h"
#include "ircd.h"
#include "struct.h"

/** Whether a device of ours may ask the server @a home, where its primary
 * is, for a rename (BX W) instead of renaming the user itself: every
 * server from @a home (included) up the server tree to our own link is
 * IRCv3-aware and announced SERVER flag N.  A legacy server never
 * repeats a letter it does not know when it relays a SERVER line, and an
 * older fork server prints only the letters it knows, so every server
 * behind such a hop is seen here without N.
 * @param[in] home The primary's server (cli_user(primary)->server).
 * @return Non-zero when BX W may be sent; never for &me or NULL.
 */
int nick_writer_route(struct Client *home)
{
  struct Client *s;
  int hops = 0, hops_ok = 0, reached_us = 0;

  for (s = home; s && IsServer(s) && !IsMe(s) && cli_serv(s);
       s = cli_serv(s)->up) {
    if (++hops > BOUNCE_MAX_SERVER_DEPTH)
      return 0;
    if (IsIRCv3Aware(s) && IsNickWriter(s))
      hops_ok++;
    if (cli_serv(s)->up && IsMe(cli_serv(s)->up)) {
      reached_us = 1;
      break;
    }
  }
  return nick_writer_route_path(hops, hops_ok, reached_us);
}
