/*
 * IRC - Internet Relay Chat, ircd/m_tempshun.c
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
 * $Id: m_tempshun.c 1271 2004-12-11 05:14:07Z klmitch $
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
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * ms_tempshun - server message handler
 *
 * parv[0]      = sender prefix
 * parv[1]      = +/-
 * parv[2]      = victim numeric
 * parv[parc-1] = comment
 */
int ms_tempshun(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  int remove = 0;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if (parc < 4) {
    protocol_violation(sptr, "Too few arguments for TEMPSHUN");
    return need_more_params(sptr, "TEMPSHUN");
  }

  if (parv[1][0] == '-')
    remove = -1;

  if (!(acptr = findNUser(parv[2])))
    return 0;

  if (MyUser(acptr)) {
    if (remove) {
      if (IsTempShun(acptr)) {
        /* let the ops know about it */
        sendto_opmask_butone_global(&me, SNO_GLINE, "Temporary shun removed from %s (%s)",
                                    get_client_name(acptr, SHOW_IP), parv[parc-1]);
      }
      ClearTempShun(acptr);
    } else {
      if (!IsTempShun(acptr)) {
        if (!feature_bool(FEAT_HIS_SHUN_REASON)) {
          sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :You are shunned: %s",
                        acptr, parv[parc-1]);
        }

        /* let the ops know about it */
        sendto_opmask_butone_global(&me, SNO_GLINE, "Temporary shun applied to %s (%s)",
                                    get_client_name(acptr, SHOW_IP), parv[parc-1]);
      }

      SetTempShun(acptr);
    }
  } else {
    sendcmdto_serv_butone(sptr, CMD_TEMPSHUN, cptr, "%c %C :%s",
                          (remove ? '-' : '+'), acptr, parv[parc-1]);
  }

  return 0;
}

/*
 * mo_tempshun - tempshun message handler
 *
 * parv[0]      = sender prefix
 * parv[1]      = [+/-]victim
 * parv[parc-1] = comment
 */
int mo_tempshun(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char* name;
  char* reason = "no reason";
  int remove = 0;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);
  assert(IsAnOper(sptr));

  if (!HasPriv(sptr, PRIV_TEMPSHUN))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  if (parc < 2)
    return need_more_params(sptr, "TEMPSHUN");

  if (parc > 3)
    reason = parv[parc-1];

  if (parv[1][0] == '-') {
    name = parv[1]+1;
    remove = -1;
  } else if (parv[1][0] == '+') {
    name = parv[1]+1;
  } else
    name = parv[1];

  if (!(acptr = FindUser(name)))
    return send_reply(sptr, ERR_NOSUCHNICK, name);

  if (MyUser(acptr)) {
    if (remove) {
      if (IsTempShun(acptr)) {
        /* let the ops know about it */
        sendto_opmask_butone_global(&me, SNO_GLINE, "Temporary shun removed from %s (%s)",
                                    get_client_name(acptr, SHOW_IP), parv[parc-1]);
      }
      ClearTempShun(acptr);
    } else {
      if (!IsTempShun(acptr)) {
        if (!feature_bool(FEAT_HIS_SHUN_REASON)) {
          sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :You are shunned: %s",
                        acptr, reason);
        }

        /* let the ops know about it */
        sendto_opmask_butone_global(&me, SNO_GLINE, "Temporary shun applied to %s (%s)",
                                    get_client_name(acptr, SHOW_IP), reason);
      }

      SetTempShun(acptr);
    }
  } else {
    sendcmdto_serv_butone(sptr, CMD_TEMPSHUN, cptr, "%c %C :%s",
                          (remove ? '-' : '+'), acptr, reason);
  }

  return 0;
}
