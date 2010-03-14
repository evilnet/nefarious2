/*
 * IRC - Internet Relay Chat, ircd/m_svsnick.c
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
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "sys.h"
#include "s_misc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * ms_svsnick - server message handler
 * parv[0] = sender prefix
 * parv[1] = Target numeric
 * parv[2] = New nickname
 */
int ms_svsnick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr = NULL;
  struct Client* acptr2 = NULL;
  char		 nick[NICKLEN + 2];
  char*		 arg;

  if (parc < 3)
    return need_more_params(sptr, "SVSNICK"); 

  if (!(acptr = findNUser(parv[1])))
    return 0; /* Ignore SVSNICK for a user that has quit */

  if (ircd_strcmp(cli_name(acptr), parv[2]) == 0)
    return 0; /* Nick already set to what SVSNICK wants, ignoring... */

  /*
   * Basic sanity checks
   */

  /*
   * Don't let them make us send back a really long string of
   * garbage
   */
  arg = parv[2];
  if (strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
    arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';

  strcpy(nick, arg);

  /*
   * If do_nick_name() returns a null name then reject it.
   */
  if (0 == do_nick_name(nick))
    return 0;

  /*
   * Check if this is a LOCAL user trying to use a reserved (Juped)
   * nick, if so tell him that it's a nick in use...
   */
  if (isNickJuped(nick))
    return 0;                        /* NICK message ignored */

  /*
   * Set acptr2 to the client pointer of any user with nick's name.
   * If the user is the same as the person being svsnick'ed, let it
   * through as it is probably a change in the nickname's case.
   */
  if ((acptr2 = FindClient(nick))) {
    /*
     * If acptr == acptr2, then we have a client doing a nick
     * change between *equivalent* nicknames as far as server
     * is concerned (user is changing the case of his/her
     * nickname or somesuch), so we let it through :)
     */
    if (acptr != acptr2) {
      /* Nick collision occured, kill user with specific reason */
      send_reply(acptr2, ERR_NICKCOLLISION, nick);
      ServerStats->is_kill++;
      SetFlag(acptr2, FLAG_KILLED);
      exit_client(cptr, acptr2, &me, "Killed (Nickname Enforcement)");
    }
  }

  set_nick_name(acptr, acptr, nick, parc, parv, 1);
  sendcmdto_serv_butone(sptr, CMD_SVSNICK, cptr, "%s %s", parv[1], nick);
  return 0;
}

