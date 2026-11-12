/*
 * IRC - Internet Relay Chat, ircd/ml_route.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
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
 * @brief Whether the way from this server to another carries multiline
 *   (ML) batches.  Kept apart from m_batch.c so the CMocka suite
 *   (ircd/test/ml_route_cmocka.c) links it alone.
 */
#include "config.h"

#include "ml_route.h"

#include "client.h"
#include "ircd.h"
#include "struct.h"

/** Whether an ML batch this server sends toward \a server reaches it
 * whole: every server on the way from here to \a server, \a server
 * included and this server left out, takes ML.  The way is the server
 * tree, walked from \a server up (cli_serv()->up) to &me.
 *
 * A server takes ML when both hold:
 *
 * - It is IRCv3-aware (the 'v' of its SERVER line, FLAG_IRCV3AWARE).
 *   A legacy server never sends 'v' and never repeats it when it relays
 *   the SERVER line of a server behind it, so a fork server behind a
 *   legacy hop is seen here without it.  This is the shape of the way,
 *   carried by the lines that build the tree.
 *
 * - It announced ML (FLAG_MULTILINE, set by ms_multiline).  A server
 *   announces ML at link time only with its draft/multiline cap on, and
 *   the server before it on the way forwards a batch only to a link that
 *   announced it: process_multiline_batch for the first hop, ms_multiline
 *   on every later one.  So a fork server whose cap is off gets no batch
 *   at all -- the hop before it drops a DM batch and gives a channel
 *   batch the fallback -- although, handed one, it would deliver it
 *   (ms_multiline has no feature test, and a local client without the
 *   cap gets the fallback there).  Turning the cap off at run time sends
 *   nothing to the other servers: the flag stays, and so does the
 *   server's handling of ML, so the flag still tells the truth.
 *
 * Either flag missing on any server of the way makes this false; the
 * caller then sends the fallback as ordinary PRIVMSG/NOTICE lines, which
 * every server forwards.  A flag that should be there and is not (an ML
 * line a peer sent before it introduced the server, see server_estab)
 * costs a fallback where the batch would have arrived; no flag is ever
 * set for a server that does not take ML, so a batch is never sent where
 * a hop would drop it.
 *
 * @param[in] server Server the recipient is on (cli_user()->server), or
 *   &me.  NULL answers no.
 * @return Non-zero when the way carries ML (always for &me).
 */
int ml_route_carries_multiline(struct Client *server)
{
  struct Client *x = server;
  int hops = 0;

  while (x && x != &me) {
    if (!IsServer(x) || !cli_serv(x) || !IsIRCv3Aware(x) || !IsMultiline(x))
      return 0;
    if (++hops > ML_ROUTE_MAX_HOPS)
      return 0;
    x = cli_serv(x)->up;
  }
  return x == &me;
}
