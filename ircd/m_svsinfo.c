/*
 * IRC - Internet Relay Chat, ircd/m_svsinfo.c
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
 * $Id: m_svsinfo.c 2418 2009-01-05 04:08:27Z sirvulcan $
 */
#include "config.h"

#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"
#include "s_conf.h"
#include "s_user.h"


/*
 * ms_svsinfo - server message handler
 *
 *   parv[0] = Sender prefix
 *   parv[1] = Numeric nick
 *   parv[parc-1] = New info line
 */
int ms_svsinfo(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;

  if (parc < 2)
    return need_more_params(sptr, "SVSINFO");

  if (!(acptr = findNUser(parv[1])))
    return 0; /* Ignore SVSINFO for a user that has quit */

  if (ircd_strcmp(acptr->cli_info, parv[parc-1]) == 0)
    return 0; /* New info already the same as current one */

  /* Set the info line, if the length is over REALLEN then it will
     be truncated */
  ircd_strncpy(acptr->cli_info, parv[2], REALLEN + 1);


  sendcmdto_serv_butone(sptr, CMD_SVSINFO, cptr, "%C :%s", acptr, acptr->cli_info);

  return 0;
}

