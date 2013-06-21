/*
 * IRC - Internet Relay Chat, ircd/m_watch.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
 * Copyright (C) 2002-2007 IRC-Dev Development Team <devel@irc-dev.net>
 * Copyright (C) 2002 Toni Garcia (zoltan) <zoltan@irc-dev.net>
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
 * $Id$
 */

#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "numeric.h"
#include "s_user.h"
#include "send.h"
#include "watch.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/*
 * m_watch - generic message handler
 *
 *   parv[0] = sender prefix
 *   parv[1] = parametres
 *
 * The parv[1] can be separated parameters with "," or " " or both.
 * If a parameter begins by '+', adds a nick.
 * And if a parameter begins by '-' deletes a nick.
 * If to a 'C' or 'c' is sent, deletes all the watch list.
 * A 'S' or 's' gives the notify status.
 * The parameter 'l' list nicks on-line and 'L' list nicks on-line and off-line.
 * 
 * By default, the parameter is a 'l'.
 *
 * 2002/05/20 zoltan <zoltan@irc-dev.net>
 */
int m_watch(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char *s, *p = 0;
  int i = 0;

  if (parc < 2)
  {
    /* Default parameter 'l' */
    parc = 2;
    parv[1] = "l";
  }

  /*
   * The parameters can be separated for " " or "," or both.
   */
  for (i = 0; i < parc; i++) {
	  for (s = ircd_strtok(&p, parv[i], ", "); s; s = ircd_strtok(&p, NULL, ", "))
	  {
	    /*
	     * Prefix: "+" (add) "-" (delete)
	     */
	    if (*s == '+' || *s == '-')
	    {
	      char *nick, *p2;
	      char c = *s;
	
	      *s++ = '\0';
	
	      /* If nick!user@host is received we truncated it */
	      if (!(nick = ircd_strtok(&p2, s, "!")))
		nick = s;
	
	      /* Do not admit servers, neither @, nor jockers */
	      if (strchr(nick, '*') || strchr(nick, '.') || strchr(nick, '@'))
		continue;
	
	      if (strlen(nick) > NICKLEN)
		nick[NICKLEN] = '\0';
	
	      if (!*nick)
		continue;
	
	      if (c == '+')		/* Add nick */
	      {
		if (cli_user(sptr)->watches >= feature_int(FEAT_MAXWATCHS))
		{
		  send_reply(sptr, ERR_TOOMANYWATCH, nick, feature_int(FEAT_MAXWATCHS));
		  continue;
		}
	
		add_nick_watch(sptr, nick);
		show_status_watch(sptr, nick, RPL_NOWON, RPL_NOWOFF);
	
	      }
	      else if (c == '-')	/* Deletes nick */
	      {
		del_nick_watch(sptr, nick);
		show_status_watch(sptr, nick, RPL_WATCHOFF, RPL_WATCHOFF);
	      }
	      continue;
	    }
	
	    /*
	     * Parameter C/c
	     *
	     * Deletes all the WATCH list.
	     */
	    if (*s == 'C' || *s == 'c')
	    {
	      del_list_watch(sptr);
	      continue;
	    }
	
	    /*
	     * Parametr S/s
	     *
	     * Status the WATCH List.
	     */
	    if (*s == 'S' || *s == 's')
	    {
	      struct Watch *wptr;
	      struct SLink *lp;
	      char line[BUFSIZE * 2];
	      int count = 0;
	
	      wptr = FindWatch(cli_name(sptr));
	
	      if (wptr)
		for (lp = wt_watch(wptr), count = 1; (lp = lp->next); count++);
	
	      send_reply(sptr, RPL_WATCHSTAT, cli_user(sptr)->watches, count);
	
	      lp = cli_user(sptr)->watch;
	      if (lp)
	      {
		*line = '\0';
		strcpy(line, lp->value.wptr->wt_nick);
		count = strlen(parv[0]) + strlen(cli_name(&me)) + 10 + strlen(line);
	
		while ((lp = lp->next))
		{
		  if ((count + strlen(lp->value.wptr->wt_nick) + 1) > 512)
		  {
		    send_reply(sptr, RPL_WATCHLIST, line);
		    *line = '\0';
		    count = strlen(cli_name(sptr)) + strlen(cli_name(&me)) + 10;
		  }
		  strcat(line, " ");
		  strcat(line, lp->value.wptr->wt_nick);
		  count += (strlen(lp->value.wptr->wt_nick) + 1);
		}
		send_reply(sptr, RPL_WATCHLIST, line);
	      }
	      send_reply(sptr, RPL_ENDOFWATCHLIST, *s);
	
	      continue;
	    }
	
	    /*
	     * Parameter L/l
	     *
	     * List users online and if we also especified "L" offline.
	     */
	    if (*s == 'L' || *s == 'l')
	    {
	      struct Client *acptr;
	      struct SLink *lp = cli_user(sptr)->watch;
	
	
	      while (lp)
	      {
		if ((acptr = FindUser(lp->value.wptr->wt_nick)))
		{
		  send_reply(sptr, RPL_NOWON, cli_name(acptr),
		      cli_user(acptr)->username,
		      !IsAnOper(sptr) ?
		      cli_user(acptr)->host : cli_user(acptr)->realhost,
		      cli_lastnick(acptr));
		}
		/*
		 * If it specifies "L" to also send off-line.
		 */
		else if (*s == 'L')
		{
		  send_reply(sptr, RPL_NOWOFF, lp->value.wptr->wt_nick,
		      "*", "*", lp->value.wptr->wt_lasttime);
		}
	
		lp = lp->next;
	      }
	
	      send_reply(sptr, RPL_ENDOFWATCHLIST, *s);
	      continue;
	    }
	
	    /* Unknown or not supported parameter.
	     * Ignored it :)
	     */
	  }
  }

  return 0;
}
