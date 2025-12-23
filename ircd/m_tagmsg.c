/*
 * IRC - Internet Relay Chat, ircd/m_tagmsg.c
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
#include "send.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/*
 * m_tagmsg - local client message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target (channel or user)
 *
 * TAGMSG sends a message with only tags (no content).
 * Used for client-only tags like +typing.
 * IRCv3 specification: https://ircv3.net/specs/extensions/message-tags
 *
 * Note: Client-only tags (prefixed with +) are extracted by parse.c
 * and stored temporarily. This handler relays them to recipients.
 */
int m_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  struct Client* acptr;
  char* target;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "TAGMSG");

  target = parv[1];

  /* Check if target is a channel */
  if (IsChannelName(target)) {
    chptr = FindChannel(target);
    if (!chptr)
      return send_reply(sptr, ERR_NOSUCHCHANNEL, target);

    /* Check if user can send to channel */
    if (!client_can_send_to_channel(sptr, chptr, 0))
      return send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);

    /* Relay TAGMSG to channel members with message-tags capability */
    /* Note: For now, we only relay locally. S2S relay requires Phase 13b. */
    sendcmdto_channel_capab_butserv_butone(sptr, CMD_TAGMSG, chptr, sptr,
                                           SKIP_DEAF | SKIP_BURST,
                                           CAP_SERVERTIME, CAP_NONE,
                                           "%H", chptr);
  }
  else {
    /* Target is a user */
    acptr = FindUser(target);
    if (!acptr)
      return send_reply(sptr, ERR_NOSUCHNICK, target);

    /* Only send to local users with message-tags capability */
    if (MyConnect(acptr) && CapActive(acptr, CAP_SERVERTIME)) {
      sendcmdto_one_tags(sptr, CMD_TAGMSG, acptr, "%C", acptr);
    }
    /* Note: S2S relay for remote users requires Phase 13b */
  }

  return 0;
}

/*
 * ms_tagmsg - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = target (channel or user)
 *
 * Handle TAGMSG from other servers (P10: TM token).
 * Note: Full S2S tag propagation requires Phase 13.
 */
int ms_tagmsg(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel* chptr;
  struct Client* acptr;
  char* target;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Servers can't send TAGMSG */
  if (IsServer(sptr))
    return protocol_violation(sptr, "Server trying to send TAGMSG");

  if (parc < 2 || EmptyString(parv[1]))
    return 0;

  target = parv[1];

  /* Check if target is a channel */
  if (IsChannelName(target)) {
    chptr = FindChannel(target);
    if (!chptr)
      return 0;

    /* Relay to local channel members with message-tags capability */
    sendcmdto_channel_capab_butserv_butone(sptr, CMD_TAGMSG, chptr, cptr,
                                           SKIP_DEAF | SKIP_BURST,
                                           CAP_SERVERTIME, CAP_NONE,
                                           "%H", chptr);

    /* Propagate to other servers */
    sendcmdto_serv_butone(sptr, CMD_TAGMSG, cptr, "%s", target);
  }
  else {
    /* Target is a user */
    acptr = findNUser(target);
    if (!acptr)
      acptr = FindUser(target);
    if (!acptr)
      return 0;

    if (MyConnect(acptr)) {
      /* Local user - deliver if they have message-tags capability */
      if (CapActive(acptr, CAP_SERVERTIME)) {
        sendcmdto_one_tags(sptr, CMD_TAGMSG, acptr, "%C", acptr);
      }
    }
    else {
      /* Remote user - forward to their server */
      sendcmdto_one(sptr, CMD_TAGMSG, acptr, "%C", acptr);
    }
  }

  return 0;
}
