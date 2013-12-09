/*
 * IRC - Internet Relay Chat, ircd/m_ircops.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
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
 *
 * $Id: m_ircops.c 1271 2004-12-11 05:14:07Z klmitch $
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * m_ircops - generic message handler
 */
int m_ircops(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct Client *server = 0;
  char buf[BUFSIZE];
  int ircops = 0;

  if (!IsAnOper(sptr) && feature_bool(FEAT_HIS_IRCOPS))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  /*
   * If user is only looking for opers on a specific server, we need
   * to find that server.
   */
  if (parc > 1)
  {
    if (!string_has_wildcards(parv[1]))
      server = FindServer(parv[1]);
    else
      server = find_match_server(parv[1]);

    if (!server || IsService(server))
      return send_reply(sptr, ERR_NOSUCHSERVER, parv[1]);
  }

  send_reply(sptr, RPL_IRCOPSHEADER, (parc > 1) ? cli_name(server) :
             feature_str(FEAT_NETWORK));

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr))
  {
    if (acptr->cli_user && IsOper(acptr) && !IsChannelService(acptr)
        && !IsService(acptr->cli_user->server))
    {
      if ((parc == 1) || (acptr->cli_user->server == server))
      {
        if (SeeOper(sptr, acptr))
        {
          ircd_snprintf(0, buf, sizeof(buf), "[%c] %s%s%s%s%s - Idle: %d",
                        (IsAdmin(acptr) ? 'A' : (IsOper(acptr) ? 'O' : 'o')),
                        cli_name(acptr), (cli_user(acptr)->away ? " (AWAY)" : ""),
                        (parc == 1 ? " [" : ""),
                        (parc == 1 ? ((feature_bool(FEAT_HIS_IRCOPS_SERVERS) && !IsAnOper(sptr)) ?
                         feature_str(FEAT_HIS_SERVERNAME) : cli_name(cli_user(acptr)->server)) : ""),
                        (parc == 1 ? "]" : ""),
                        (IsNoIdle(acptr) && !IsAnOper(sptr) ? 0 : CurrentTime - cli_user(acptr)->last)
                       );
          send_reply(sptr, RPL_IRCOPS, buf);
        }
        ircops++;
      }
    }
  }

  ircd_snprintf(0, buf, sizeof(buf), "Total: %d IRCop%s connected",
                ircops, (ircops != 1) ? "s" : "");
  send_reply(sptr, RPL_ENDOFIRCOPS, buf);

  return 0;
}

