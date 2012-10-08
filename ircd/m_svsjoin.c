/*
 * IRC - Internet Relay Chat, ircd/m_svsjoin.c
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
 * $Id: m_join.c 1906 2009-02-09 03:39:42Z entrope $
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Searches for and handles a 0 in a join list.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] chanlist List of channels to join.
 * @return First token in \a chanlist after the final 0 entry, which
 * may be its nul terminator (if the final entry is a 0 entry).
 */
static char *
last0(struct Client *cptr, struct Client *sptr, char *chanlist)
{
  char *p;
  int join0 = 0;

  for (p = chanlist; p[0]; p++) /* find last "JOIN 0" */
    if (p[0] == '0' && (p[1] == ',' || p[1] == '\0')) {
      if (p[1] == ',')
        p++;
      chanlist = p + 1;
      join0 = 1;
    } else {
      while (p[0] != ',' && p[0] != '\0') /* skip past channel name */
	p++;

      if (!p[0]) /* hit the end */
	break;
    }

  if (join0) {
    struct JoinBuf part;
    struct Membership *member;

    joinbuf_init(&part, sptr, cptr, JOINBUF_TYPE_PARTALL,
                 "Left all channels", 0);

    joinbuf_join(&part, 0, 0);

    while ((member = cli_user(sptr)->channel))
      joinbuf_join(&part, member->channel,
                   IsZombie(member) ? CHFL_ZOMBIE :
                   IsDelayedJoin(member) ? CHFL_DELAYED :
                   0);

    joinbuf_flush(&part);
  }

  return chanlist;
}

/** Handle a JOIN message from a client connection.
 * See @ref m_functions for discussion of the arguments.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 */
int ms_svsjoin(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Client *acptr;
  struct Channel *chptr;
  struct JoinBuf join;
  struct JoinBuf create;
  char *p = 0;
  char *chanlist;
  char *name;

  if (parc < 3 || *parv[2] == '\0')
    return need_more_params(sptr, "SVSJOIN");

  if(!(acptr = findNUser(parv[1])))
    if (!(acptr = FindUser(parv[1])))
      return 0; /* Ignore SVSNICK for a user that has quit */

  if (!MyUser(acptr)) {
    sendcmdto_serv_butone(sptr, CMD_SVSJOIN, cptr, "%C %s", acptr, parv[2]);
    return 0;
  }

  joinbuf_init(&join, acptr, acptr, JOINBUF_TYPE_JOIN, 0, 0);
  joinbuf_init(&create, acptr, acptr, JOINBUF_TYPE_CREATE, 0, TStime());

  chanlist = last0(acptr, acptr, parv[2]); /* find last "JOIN 0" */

  for (name = ircd_strtok(&p, chanlist, ","); name;
       name = ircd_strtok(&p, 0, ",")) {

    if (!IsChannelName(name) || !strIsIrcCh(name))
    {
      /* bad channel name */
      send_reply(acptr, ERR_NOSUCHCHANNEL, name);
      continue;
    }

    if (!(chptr = FindChannel(name))) {
      if (((name[0] == '&') && !feature_bool(FEAT_LOCAL_CHANNELS))
          || strlen(name) > IRCD_MIN(CHANNELLEN, feature_int(FEAT_CHANNELLEN))) {
        send_reply(acptr, ERR_NOSUCHCHANNEL, name);
        continue;
      }

      if (!(chptr = get_channel(acptr, name, CGT_CREATE)))
        continue;

      /* Try to add the new channel as a recent target for the user. */
      if (check_target_limit(acptr, chptr, chptr->chname, 0)) {
        chptr->members = 0;
        destruct_channel(chptr);
        continue;
      }

      joinbuf_join(&create, chptr, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
    } else if (find_member_link(chptr, acptr)) {
      continue; /* already on channel */
    } else if (check_target_limit(acptr, chptr, chptr->chname, 0)) {
      continue;
    } else {
      int flags = CHFL_DEOPPED;

      if (chptr->users == 0 && !chptr->mode.apass[0] && !(chptr->mode.exmode & EXMODE_PERSIST)) {
        /* Joining a zombie channel (zannel): give ops and increment TS. */
        flags = CHFL_CHANOP;
        chptr->creationtime++;
      }

      joinbuf_join(&join, chptr, flags);
      if (flags & CHFL_CHANOP) {
        struct ModeBuf mbuf;
	/* Always let the server op him: this is needed on a net with older servers
	   because they 'destruct' channels immediately when they become empty without
	   sending out a DESTRUCT message. As a result, they would always bounce a mode
	   (as HACK(2)) when the user ops himself.
           (There is also no particularly good reason to have the user op himself.)
        */
	modebuf_init(&mbuf, &me, cptr, chptr, MODEBUF_DEST_SERVER);
	modebuf_mode_client(&mbuf, MODE_ADD | MODE_CHANOP, acptr,
                            chptr->mode.apass[0] ? ((flags & CHFL_CHANNEL_MANAGER) ? 0 : 1) : MAXOPLEVEL);
	modebuf_flush(&mbuf);
      }
    }

    del_invite(acptr, chptr);

    if (chptr->topic[0]) {
      send_reply(acptr, RPL_TOPIC, chptr->chname, chptr->topic);
      send_reply(acptr, RPL_TOPICWHOTIME, chptr->chname, chptr->topic_nick,
		 chptr->topic_time);
    }

    do_names(acptr, chptr, NAMES_ALL|NAMES_EON); /* send /names list */
  }

  joinbuf_flush(&join); /* must be first, if there's a JOIN 0 */
  joinbuf_flush(&create);

  return 0;
}

