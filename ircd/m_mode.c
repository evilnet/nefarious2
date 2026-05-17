/*
 * IRC - Internet Relay Chat, ircd/m_mode.c
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
 * $Id: m_mode.c 1818 2007-07-14 02:40:01Z isomer $
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

#include "handlers.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "match.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

int
m_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr = 0;
  struct ModeBuf mbuf;
  struct Membership *member;
  int hoflags = 0;
  int lb;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  if (!IsChannelName(parv[1]) || !(chptr = FindChannel(parv[1])))
  {
    struct Client *acptr;

    acptr = FindUser(parv[1]);
    if (!acptr)
    {
      send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
      return 0;
    }
    else if (sptr != acptr)
    {
      /* Aliases share their primary's session identity.  An alias
       * sending MODE for the primary's nick (which is the alias's
       * effective post-attach nick) is acting on its own user state.
       * set_user_mode has the matching carve-out at the parc < 3 and
       * parc >= 3 paths — but this earlier gate in m_mode also has to
       * let the alias through.  Pre-fix, MODE from an alias for the
       * primary's nick got ERR_USERSDONTMATCH here before ever
       * reaching set_user_mode. */
      if (!(cli_user(sptr) && cli_user(sptr)->alias_primary == acptr)) {
        send_reply(sptr, ERR_USERSDONTMATCH);
        return 0;
      }
    }

    if (!IsAnOper(sptr) && IsRestrictUMode(sptr))
      return 0;

    return set_user_mode(cptr, sptr, parc, parv, ALLOWMODES_ANY);
  }

  ClrFlag(sptr, FLAG_TS8);

  member = find_member_link(chptr, sptr);

  if (parc < 3) {
    char modebuf[MODEBUFLEN];
    char parabuf[MODEBUFLEN];

    lb = labeled_batch_start(sptr);
    *modebuf = *parabuf = '\0';
    modebuf[1] = '\0';
    channel_modes(sptr, modebuf, parabuf, sizeof(parabuf), chptr, member);
    send_reply(sptr, RPL_CHANNELMODEIS, chptr->chname, modebuf, parabuf);
    send_reply(sptr, RPL_CREATIONTIME, chptr->chname, chptr->creationtime);
    if (lb) labeled_batch_end(sptr);
    return 0;
  }

  if (!member || (!IsChanOp(member) && !IsHalfOp(member))) {
    if (IsLocalChannel(chptr->chname) && HasPriv(sptr, PRIV_MODE_LCHAN)) {
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to channel */
		    MODEBUF_DEST_HACK4));  /* Send HACK(4) notice */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
		 (MODE_PARSE_SET |    /* Set the mode */
		  MODE_PARSE_FORCE),  /* Force it to take */
		  member);
      return modebuf_flush(&mbuf);
    } else
      mode_parse(0, cptr, sptr, chptr, parc - 2, parv + 2,
		 (member ? MODE_PARSE_NOTOPER : MODE_PARSE_NOTMEMBER), member);
    return 0;
  }

  hoflags = MODE_PARSE_SET;
  if (member && !IsChanOp(member) && IsHalfOp(member))
    hoflags |= MODE_PARSE_ISHALFOP|MODE_PARSE_NOTOPER;

  modebuf_init(&mbuf, sptr, cptr, chptr,
	       (MODEBUF_DEST_CHANNEL | /* Send mode to channel */
		MODEBUF_DEST_SERVER)); /* Send mode to servers */
  mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2, hoflags, member);
  return modebuf_flush(&mbuf);
}

int
ms_mode(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr = 0;
  struct ModeBuf mbuf;
  struct Membership *member;

  if (parc < 3)
    return need_more_params(sptr, "MODE");

  if (IsLocalChannel(parv[1]))
    return 0;

  if (!(chptr = FindChannel(parv[1])))
  {
    struct Client *acptr;

    acptr = FindUser(parv[1]);
    if (!acptr)
    {
      return 0;
    }

    /* Alias→primary mode sync: when the alias's mode changes (e.g. from
     * OPER on the leaf), apply it to the primary on the hub.
     * For +o, do a proper oper-up via do_oper() so the primary gets
     * the right class, handler, snomask, privileges, etc.
     * For other modes, fall through to set_user_mode(). */
    if (IsBouncerAlias(sptr) && cli_user(sptr)
        && cli_user(sptr)->alias_primary == acptr) {
      /* Check if +o is being set */
      int setting_oper = 0;
      int mi;
      char *mm;
      int mwhat = MODE_ADD;
      for (mi = 2; mi < parc; mi++) {
        for (mm = parv[mi]; *mm; mm++) {
          if (*mm == '+') mwhat = MODE_ADD;
          else if (*mm == '-') mwhat = MODE_DEL;
          else if (*mm == 'o' && mwhat == MODE_ADD) setting_oper = 1;
        }
      }

      if (setting_oper && !IsOper(acptr)) {
        /* Find a matching Operator block on this server.
         * The leaf already validated name+password; we just need
         * a host-matching ConfItem for the class/privileges. */
        struct ConfItem *aconf;
        for (aconf = GlobalConfList; aconf; aconf = aconf->next) {
          if (!(aconf->status & CONF_OPERATOR))
            continue;
          if (aconf->username
              && match(aconf->username, cli_user(acptr)->username))
            continue;
          if (aconf->addrbits < 0) {
            if (match(aconf->host, cli_user(acptr)->realhost))
              continue;
          } else if (!ipmask_check(&cli_ip(acptr), &aconf->address.addr,
                                    aconf->addrbits))
            continue;
          break;
        }
        if (aconf) {
          do_oper(cli_from(acptr), acptr, aconf, OPER_FLAG_SILENT);
          return 0;  /* do_oper handles MODE propagation */
        }
      }

      /* Fallback for non-oper modes or no matching Operator block */
      return set_user_mode(cptr, cptr, parc, parv,
                           ALLOWMODES_ANY | ALLOWMODES_ALIAS_SYNC);
    }

    if ((sptr != acptr) && !IsServer(sptr))
    {
      sendwallto_group_butone(&me, WALL_WALLOPS, 0,
                              "MODE for User %s from %s!%s", parv[1],
                              cli_name(cptr), cli_name(sptr));
      return 0;
    }
    return set_user_mode(cptr, sptr, parc, parv, ALLOWMODES_ANY);
  }

  ClrFlag(sptr, FLAG_TS8);

  if (IsServer(sptr)) {
    if (find_conf_byhost(cli_confs(cptr), cli_name(sptr), CONF_UWORLD))
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER  | /* Send mode to servers */
		    MODEBUF_DEST_HACK4));  /* Send a HACK(4) message */
    else if (!feature_bool(FEAT_OPLEVELS))
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER  | /* Send mode to servers */
		    MODEBUF_DEST_HACK3));  /* Send a HACK(3) message */
    else
      /* Servers need to be able to op people who join using the Apass
       * or upass, as well as people joining a zannel, therefore we do
       * not generate HACK3 when oplevels are on. */
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER));   /* Send mode to servers */

    mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
	       (MODE_PARSE_SET    | /* Set the mode */
		MODE_PARSE_STRICT | /* Interpret it strictly */
		MODE_PARSE_FORCE),  /* And force it to be accepted */
	        NULL);
  } else {
    if (find_conf_byhost(cli_confs(cptr), cli_name(cli_user(sptr)->server), CONF_UWORLD) ||
        IsChannelService(sptr)) {
      modebuf_init(&mbuf, sptr, cptr, chptr,
                   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
                    MODEBUF_DEST_SERVER  | /* Send mode to servers */
                    MODEBUF_DEST_HACK4));  /* Send a HACK(4) message */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
                 (MODE_PARSE_SET    | /* Set the mode */
                  MODE_PARSE_STRICT | /* Interpret it strictly */
                  MODE_PARSE_FORCE),  /* And force it to be accepted */
                  NULL);
    } else if (!(member = find_member_link(chptr, sptr)) || (!IsChanOp(member) && !IsHalfOp(member))) {
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_SERVER |  /* Send mode to server */
		    MODEBUF_DEST_HACK2  |  /* Send a HACK(2) message */
		    MODEBUF_DEST_DEOP   |  /* Deop the source */
		    MODEBUF_DEST_BOUNCE)); /* And bounce the MODE */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
		 (MODE_PARSE_STRICT |  /* Interpret it strictly */
		  MODE_PARSE_BOUNCE),  /* And bounce the MODE */
		  member);
    } else {
      modebuf_init(&mbuf, sptr, cptr, chptr,
		   (MODEBUF_DEST_CHANNEL | /* Send mode to clients */
		    MODEBUF_DEST_SERVER)); /* Send mode to servers */
      mode_parse(&mbuf, cptr, sptr, chptr, parc - 2, parv + 2,
		 (MODE_PARSE_SET    | /* Set the mode */
		  MODE_PARSE_STRICT | /* Interpret it strictly */
		  MODE_PARSE_FORCE),  /* And force it to be accepted */
		  member);
    }
  }

  return modebuf_flush(&mbuf);
}
