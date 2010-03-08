/*
 * IRC - Internet Relay Chat, ircd/m_svsident.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
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
 * $Id: m_svsident.c 2480 2009-05-20 09:33:32Z sirvulcan $
 */

#include "channel.h"
#include "config.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_alloc.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"
#include "s_debug.h"
#include "userload.h"
#include "patchlevel.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>


/*
 * ms_svsident - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = Target numeric
 * parv[2] = New ident
 */
int ms_svsident(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char *s;
  char *newident = NULL;
  int legalident=1;

  if (parc < 3)
    return need_more_params(sptr, "SVSIDENT");

   /* Ignore SVSIDENT for a user that has quit */
  if (!(acptr = findNUser(parv[1])))
    return 0;

  if (IsChannelService(acptr))
    return 0;

  newident = strdup(parv[2]);

  if (strlen(newident) > USERLEN)
    return protocol_violation(sptr, "Ident too long in SVSIDENT command");

  for (s = newident; *s; s++)
  {
    if (!IsUserChar(*s))
    {
      legalident = 0;
      break;
    }
  }

  if (legalident == 0)
    return protocol_violation(sptr, "Illegal characters in SVSIDENT ident");

  ircd_strncpy(cli_user(acptr)->username, newident, USERLEN);
  ircd_strncpy(cli_username(acptr), newident, USERLEN);

  sendcmdto_serv_butone(sptr, CMD_SVSIDENT, cptr, "%C %s", acptr, cli_username(acptr));

  return 0;
}

