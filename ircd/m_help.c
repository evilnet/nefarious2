/*
 * IRC - Internet Relay Chat, ircd/m_help.c
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
 * $Id: m_help.c 1271 2004-12-11 05:14:07Z klmitch $
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
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * m_help - generic message handler
 */
int m_help(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int i;
  char *cmd;


  if (parc < 2) {
    send_reply(sptr, RPL_HELPSTART, "*", "Nefarious Help System");
    for (i = 0; msgtab[i].cmd; i++)
      send_reply(sptr, RPL_HELPTXT, "*", msgtab[i].cmd, msgtab[i].help);
    return send_reply(sptr, RPL_ENDOFHELP, "*", "End of HELP");
  }
  else {
    cmd = parv[1];
    for (i = 0; cmd[i]; i++) {
      if (cmd[i] == ' ') {
        /* Not a valid command */
        cmd = "*";
        break;
      }
    }
    send_reply(sptr, RPL_HELPSTART, cmd, "Nefarious Help System");
    for (i = 0; msgtab[i].cmd; i++) {
      if (!strcmp(cmd, msgtab[i].cmd)) {
        send_reply(sptr, RPL_HELPTXT, cmd, msgtab[i].cmd, msgtab[i].help);
        return send_reply(sptr, RPL_ENDOFHELP, cmd, "");
      }
    }
    /* FIXME: We should return ERR_HELPNOTFOUND on unknown command (and only that);
     * but this would conflict with ERR_QUARANTINED */
    send_reply(sptr, RPL_HELPTXT, cmd, cmd, "is not a command");
    return send_reply(sptr, RPL_ENDOFHELP, cmd, "End of HELP");
  }
}

