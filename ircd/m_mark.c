/*
 * IRC - Internet Relay Chat, ircd/m_mark.c
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
 * $Id: m_tmpl.c 1271 2004-12-11 05:14:07Z klmitch $
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
#include "ircd_geoip.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "mark.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_conf.h"

#include <stdlib.h>  /* for strtoul */

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * ms_mark - server message handler
 */
int ms_mark(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;

  if (!IsServer(sptr))
    return protocol_violation(sptr, "MARK from non-server %s", cli_name(sptr));

  if (!strcmp(parv[2], MARK_WEBIRC)) {
    if(parc < 4)
      return protocol_violation(sptr, "MARK webirc received too few parameters (%u)", parc);

    if ((acptr = FindUser(parv[1]))) {
      ircd_strncpy(cli_webirc(acptr), parv[3], BUFSIZE + 1);
      sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s :%s", cli_name(acptr), MARK_WEBIRC, parv[3]);
    }
  } else if (!strcmp(parv[2], MARK_GEOIP)) {
    if(parc < 5)
      return protocol_violation(sptr, "MARK geoip received too few parameters (%u)", parc);
    if ((acptr = FindUser(parv[1]))) {
      geoip_apply_mark(acptr, parv[3], parv[4], (parc > 5 ? parv[5] : NULL));
      if (parc > 5)
        sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s %s %s :%s", cli_name(acptr), MARK_GEOIP, parv[3], parv[4], parv[5]);
      else
        sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s %s %s", cli_name(acptr), MARK_GEOIP, parv[3], parv[4]);
    }
  } else if (!strcmp(parv[2], MARK_CVERSION)) {
    if(parc < 4)
      return protocol_violation(sptr, "MARK client version received too few parameters (%u)", parc);

    if ((acptr = FindUser(parv[1]))) {
       ircd_strncpy(cli_version(acptr), parv[3], VERSIONLEN + 1);
       sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s :%s", cli_name(acptr), MARK_CVERSION, parv[3]);
    }
  } else if (!strcmp(parv[2], MARK_SSLCLIFP)) {
    if(parc < 4)
      return protocol_violation(sptr, "MARK SSL client certificate fingerprint received too few parameters (%u)", parc);

    if ((acptr = FindUser(parv[1]))) {
       ircd_strncpy(cli_sslclifp(acptr), parv[3], BUFSIZE + 1);
       sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s :%s", cli_name(acptr), MARK_SSLCLIFP, parv[3]);
    }
  } else if (!strcmp(parv[2], MARK_SSLCLIEXP)) {
    if(parc < 4)
      return protocol_violation(sptr, "MARK SSL client certificate expiry received too few parameters (%u)", parc);

    if ((acptr = FindUser(parv[1]))) {
       cli_sslcliexp(acptr) = strtoul(parv[3], NULL, 10);
       sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s :%s", cli_name(acptr), MARK_SSLCLIEXP, parv[3]);
    }
  } else if (!strcmp(parv[2], MARK_KILL)) {
    if(parc < 4)
      return protocol_violation(sptr, "MARK kill received too few parameters (%u)", parc);

    if ((acptr = FindUser(parv[1]))) {
      ircd_strncpy(cli_killmark(acptr), parv[3], BUFSIZE + 1);
      sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s :%s", cli_name(acptr), MARK_KILL, parv[3]);
    }
  } else if (!strcmp(parv[2], MARK_MARK) || !strcmp(parv[2], MARK_DNSBL_DATA)) {
    if(parc < 4)
      return protocol_violation(sptr, "MARK MARK (tag) received too few parameters (%u)", parc);

    if ((acptr = FindUser(parv[1]))) {
      add_mark(acptr, parv[3]);
      SetMarked(acptr);
      sendcmdto_serv_butone(sptr, CMD_MARK, cptr, "%s %s :%s", cli_name(acptr), MARK_MARK, parv[3]);
    }
  }

  return 0;
}

