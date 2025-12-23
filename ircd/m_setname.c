/*
 * IRC - Internet Relay Chat, ircd/m_setname.c
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

#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/*
 * m_setname - local client message handler
 *
 * parv[0] = sender prefix
 * parv[1] = new realname
 *
 * Allow users to change their realname (GECOS) field.
 * IRCv3 setname specification: https://ircv3.net/specs/extensions/setname
 */
int m_setname(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *newname;

  assert(0 != cptr);
  assert(cptr == sptr);

  /* Check if setname capability is enabled */
  if (!feature_bool(FEAT_CAP_setname))
    return send_reply(sptr, ERR_UNKNOWNCOMMAND, "SETNAME");

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "SETNAME");

  newname = parv[1];

  /* Truncate if necessary */
  if (strlen(newname) > REALLEN)
    newname[REALLEN] = '\0';

  /* Check if realname actually changed */
  if (ircd_strcmp(cli_info(sptr), newname) == 0)
    return 0;

  /* Update the realname */
  ircd_strncpy(cli_info(sptr), newname, REALLEN);

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_SETNAME, cptr, ":%s", cli_info(sptr));

  /* Notify channel members with setname capability */
  sendcmdto_common_channels_capab_butone(sptr, CMD_SETNAME, sptr,
                                         CAP_SETNAME, CAP_NONE,
                                         ":%s", cli_info(sptr));

  return 0;
}

/*
 * ms_setname - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = new realname
 *
 * Handle SETNAME from other servers (P10: SE token).
 */
int ms_setname(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *newname;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Servers can't set realname */
  if (IsServer(sptr))
    return protocol_violation(sptr, "Server trying to set realname");

  if (parc < 2 || EmptyString(parv[1]))
    return 0;

  newname = parv[1];

  /* Truncate if necessary */
  if (strlen(newname) > REALLEN)
    newname[REALLEN] = '\0';

  /* Check if realname actually changed */
  if (ircd_strcmp(cli_info(sptr), newname) == 0)
    return 0;

  /* Update the realname */
  ircd_strncpy(cli_info(sptr), newname, REALLEN);

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_SETNAME, cptr, ":%s", cli_info(sptr));

  /* Notify local channel members with setname capability */
  sendcmdto_common_channels_capab_butone(sptr, CMD_SETNAME, sptr,
                                         CAP_SETNAME, CAP_NONE,
                                         ":%s", cli_info(sptr));

  return 0;
}
