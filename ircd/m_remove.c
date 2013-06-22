/*
 * IRC - Internet Relay Chat, ircd/m_remove.c
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
 * $Id:$
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
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "shun.h"
#include "zline.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Handle a REMOVE message from an operator.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the type- gline, zline or shun.
 * \li \a parv[2] is mask that needs to be cancelled.
 * \li \a parv[\a parc - 1] is the reason
 *
 * All fields must be present.  Additionally, the time interval should
 * not be 0 for messages sent to "*", as that may not function
 * reliably due to buffering in the server.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int mo_remove(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *type, *mask, *reason;
  int r;

  if (!HasPriv(sptr, PRIV_REMOVE))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  type = parc > 1 ? parv[1] : 0;

  if (EmptyString(type))
    return need_more_params(sptr, "REMOVE");

  mask = parc > 2 ? parv[2] : 0;
  reason = parc > 3 ? parv[parc - 1] : 0;

  if (EmptyString(mask) || EmptyString(reason))
    return need_more_params(sptr, "REMOVE");

  if (!ircd_strcmp(type, "gline"))
    r = gline_remove(sptr, mask, reason);
  else if (!ircd_strcmp(type, "zline"))
    r = zline_remove(sptr, mask, reason);
  else if (!ircd_strcmp(type, "shun"))
    r = shun_remove(sptr, mask, reason);

  sendcmdto_serv_butone(sptr, CMD_REMOVE, cptr, "%C %s %s :%s", sptr, type, mask, reason);
  return 0;
}

/** Handle a REMOVE message from a server connection.
 *
 * \a parv has the following elements:
 * \li \a parv[1] is the type- gline, zline or shun.
 * \li \a parv[2] is mask that needs to be cancelled.
 * \li \a parv[\a parc - 1] is the reason
 *
 * All fields must be present.  Additionally, the time interval should
 * not be 0 for messages sent to "*", as that may not function
 * reliably due to buffering in the server.
 *
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_remove(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *type, *mask, *reason;
  int r;

  type = parc > 2 ? parv[2] : 0;

  mask = parc > 3 ? parv[3] : 0;
  reason = parc > 4 ? parv[parc - 1] : 0;

  /* should never happen */
  if (EmptyString(type) || EmptyString(mask) || EmptyString(reason))
    return protocol_violation(cptr, "REMOVE recieved with missing arguements.");

  if (!ircd_strcmp(type, "gline"))
    r = gline_remove(sptr, mask, reason);
  else if (!ircd_strcmp(type, "zline"))
    r = zline_remove(sptr, mask, reason);
  else if (!ircd_strcmp(type, "shun"))
    r = shun_remove(sptr, mask, reason);

  sendcmdto_serv_butone(sptr, CMD_REMOVE, cptr, "%C %s %s :%s", sptr, type, mask, reason);
  return 0;
}

