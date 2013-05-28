/*
 * IRC - Internet Relay Chat, ircd/m_notice.c
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
 * $Id: m_notice.c 1271 2004-12-11 05:14:07Z klmitch $
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
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_relay.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "mark.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "send.h"
#include "s_conf.h"
#include "s_misc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

#if !defined(XXX_BOGUS_TEMP_HACK)
#include "handlers.h"
#endif

/*
 * m_notice - generic message handler
 */
int m_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  int             found_g = 0;
  char*           vector[MAXTARGETS];
  char*           temp;
  char            cversion[VERSIONLEN + 1];
  struct Channel* chptr;

  assert(0 != cptr);
  assert(cptr == sptr);

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_NOTICE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (parv[1][0] == '@' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  } else if (parv[1][0] == '+' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '+' */
    return m_wallvoices(cptr, sptr, parc, parv);
  }

  if (feature_bool(FEAT_CTCP_VERSIONING) && MyConnect(sptr) &&
      !ircd_strcmp(parv[1], cli_name(&me))) {
    if ((ircd_strncmp("\x01VERSION", parv[2], 8) == 0) && (strlen(parv[2]) > 10)) {
      temp = parv[2] + 9;
      ircd_strncpy(cversion, temp, VERSIONLEN);
      if (cversion[strlen(cversion)-1] == '\x01')
        cversion[strlen(cversion)-1] = '\0';

      ircd_strncpy(cli_version(sptr), cversion, VERSIONLEN);
      sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s",
                            cli_name(sptr), MARK_CVERSION, cli_version(sptr));

      if (feature_bool(FEAT_CTCP_VERSIONING_CHAN)) {
        /* Announce to channel. */
        if ((chptr = FindChannel(feature_str(FEAT_CTCP_VERSIONING_CHANNAME)))) {
          if (feature_bool(FEAT_CTCP_VERSIONING_USEMSG))
            sendcmdto_channel_butone(&me, CMD_PRIVATE, chptr, &me, SKIP_DEAF | SKIP_BURST,
                                     '\0', "%H :%s has version \002%s\002", chptr,
                                     cli_name(sptr), cli_version(sptr));
          else
            sendcmdto_channel_butone(&me, CMD_NOTICE, chptr, &me, SKIP_DEAF | SKIP_BURST,
                                     '\0', "%H :%s has version \002%s\002", chptr,
                                     cli_name(sptr), cli_version(sptr));
        }
      }

      if (feature_bool(FEAT_CTCP_VERSIONING_KILL)) {
        if ((found_g = find_kill(sptr))) {
          sendto_opmask_butone(0, found_g == -2 ? SNO_GLINE : SNO_OPERKILL,
                               found_g == -2 ? "G-line active for %s%s" :
                               "K-line active for %s%s",
                               IsUnknown(sptr) ? "Unregistered Client ":"",
                               get_client_name(sptr, SHOW_IP));
          return exit_client_msg(cptr, sptr, &me, "Banned Client: %s", cli_version(sptr));
        }
      }
      return 0;
    }
  }

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name)) {
      relay_channel_notice(sptr, name, parv[parc - 1]);
    }
    /*
     * we have to check for the '@' at least once no matter what we do
     * handle it first so we don't have to do it twice
     */
    else if ((server = strchr(name, '@')))
      relay_directed_notice(sptr, name, server, parv[parc - 1]);
    else 
      relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/*
 * ms_notice - server message handler
 */
int ms_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* name;
  char* server;

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 3) {
    /*
     * we can't deliver it, sending an error back is pointless
     */
    return protocol_violation(sptr,"Not enough params for NOTICE");
  }
  name = parv[1];
  /*
   * channel msg?
   */
  if (IsChannelPrefix(*name)) {
    server_relay_channel_notice(sptr, name, parv[parc - 1]);
  }
  /*
   * coming from another server, we have to check this here
   */
  else if ('$' == *name && IsOper(sptr)) {
    server_relay_masked_notice(sptr, name, parv[parc - 1]);
  }
  else if ((server = strchr(name, '@'))) {
    /*
     * XXX - can't get away with not doing everything
     * relay_directed_notice has to do
     */
    relay_directed_notice(sptr, name, server, parv[parc - 1]);
  }
  else {
    server_relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}

/*
 * mo_notice - oper message handler
 */
int mo_notice(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char*           name;
  char*           server;
  int             i;
  int             count;
  char*           vector[MAXTARGETS];
  assert(0 != cptr);
  assert(cptr == sptr);

  ClrFlag(sptr, FLAG_TS8);

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NORECIPIENT, MSG_NOTICE);

  if (parc < 3 || EmptyString(parv[parc - 1]))
    return send_reply(sptr, ERR_NOTEXTTOSEND);

  if (parv[1][0] == '@' && IsChannelPrefix(parv[1][1])) {
    parv[1]++;                        /* Get rid of '@' */
    return m_wallchops(cptr, sptr, parc, parv);
  }

  count = unique_name_vector(parv[1], ',', vector, MAXTARGETS);

  for (i = 0; i < count; ++i) {
    name = vector[i];
    /*
     * channel msg?
     */
    if (IsChannelPrefix(*name))
      relay_channel_notice(sptr, name, parv[parc - 1]);

    else if (*name == '$')
      relay_masked_notice(sptr, name, parv[parc - 1]);

    else if ((server = strchr(name, '@')))
      relay_directed_notice(sptr, name, server, parv[parc - 1]);

    else 
      relay_private_notice(sptr, name, parv[parc - 1]);
  }
  return 0;
}
