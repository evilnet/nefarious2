/*
 * IRC - Internet Relay Chat, ircd/bouncer_count.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/bouncer_count.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "bouncer_count.h"

#include <string.h>

void bounce_count_held(int local, int alias, int socket_counted,
                       struct bounce_counts *out)
{
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (local) {
    /* Count_clientdisconnects */
    out->clients = 1;
    out->local_clients = socket_counted ? 1 : 0;
    out->local_announced = alias ? 0 : 1;
    out->announced = alias ? 0 : 1;
  } else if (!alias) {
    /* Count_remoteclientquits */
    out->clients = 1;
    out->server_clients = 1;
    out->announced = 1;
  }
  /* Another server's alias came by BX C and was counted nowhere. */
}

void bounce_count_delta(const struct bounce_counts *from,
                        const struct bounce_counts *to,
                        struct bounce_counts *out)
{
  if (!out)
    return;
  memset(out, 0, sizeof(*out));
  if (!from || !to)
    return;
  out->clients = to->clients - from->clients;
  out->local_clients = to->local_clients - from->local_clients;
  out->server_clients = to->server_clients - from->server_clients;
  out->local_announced = to->local_announced - from->local_announced;
  out->announced = to->announced - from->announced;
}
