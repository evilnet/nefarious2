/*
 * IRC - Internet Relay Chat, ircd/m_sethost.c
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
 * $Id: m_sethost.c 1271 2004-12-11 05:14:07Z klmitch $
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
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/* Check if a username is valid */
int valid_username(const char* name) {
  const char *c = NULL;

  for (c = name; *c; c++) {
    if (!IsUserChar(*c))
      return 0;
  }

  return 1;
}

/* Check if a hostname is valid */
int valid_hostname(const char* name) {
  const char *c = NULL;

  /* Empty strings are not valid hosts */
  if (EmptyString(name))
    return 0;
  /* Don't allow leading period */
  if (*name == '.')
    return 0;
  /* Don't allow trailing period */
  if (name[strlen(name)-1] == '.')
    return 0;

  for (c = name; *c; c++) {
    if (!IsHostChar(*c))
      return 0;
  }

  return 1;
}

/*
 * m_sethost - generic message handler
 */
int m_sethost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Flags setflags;
  struct SHostConf *sconf = NULL;
  int res = 0;

  if (!feature_bool(FEAT_SETHOST)) {
    send_reply(cptr, ERR_DISABLED, "SETHOST");
    return 0;
  }

  if (parc < 2)
    return need_more_params(sptr, "SETHOST");

  /* Back up the flags first */
  setflags = cli_flags(sptr);

  if (ircd_strcmp("undo", parv[1]) == 0) {
    ClearSetHost(sptr);
    cli_user(sptr)->sethost[0] = '\0';
  } else if (parc < 3) {
    return need_more_params(sptr, "SETHOST");
  } else {
    if (!valid_hostname(parv[1])) {
      send_reply(sptr, ERR_BADHOSTMASK, parv[1]);
    } else {
      sconf = find_shost_conf(sptr, parv[1], parv[2], &res);
      if ((res == 0) && (sconf != 0)) {
        if (strchr(parv[1], '@') != NULL)
          ircd_strncpy(cli_user(sptr)->sethost, parv[1], HOSTLEN + 1);
        else
          ircd_snprintf(0, cli_user(sptr)->sethost, USERLEN + HOSTLEN + 1, "%s@%s",
                      cli_user(sptr)->username, parv[1]);
        SetSetHost(sptr);
        SetHiddenHost(sptr);
      } else {
          if (res == 1)
            send_reply(sptr, ERR_PASSWDMISMATCH);
          else
            send_reply(sptr, ERR_HOSTUNAVAIL, parv[1]);
      }
    }
  }

  hide_hostmask(sptr);
  send_umode_out(cptr, sptr, &setflags, 0);

  return 0;
}

/*
 * mo_sethost - oper message handler
 */
int mo_sethost(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Flags setflags;
  struct SHostConf *sconf = NULL;
  char hostmask[USERLEN + HOSTLEN + 2];
  int res = 0;

  if (!feature_bool(FEAT_SETHOST)) {
    send_reply(cptr, ERR_DISABLED, "SETHOST");
    return 0;
  }

  if (parc < 2)
    return need_more_params(sptr, "SETHOST");

  /* Back up the flags first */
  setflags = cli_flags(sptr);

  if (ircd_strcmp("undo", parv[1]) == 0) {
    ClearSetHost(sptr);
    cli_user(sptr)->sethost[0] = '\0';
  } else if (parc < 3) {
    return need_more_params(sptr, "SETHOST");
  } else {
    ircd_snprintf(0, hostmask, USERLEN + HOSTLEN + 1, "%s@%s", parv[1], parv[2]);
    if (!valid_username(parv[1]) || !valid_hostname(parv[2])) {
      send_reply(sptr, ERR_BADHOSTMASK, hostmask);
    } else if (HasPriv(sptr, PRIV_FREEFORM)) {
      ircd_strncpy(cli_user(sptr)->sethost, hostmask, USERLEN + HOSTLEN + 1);
      SetSetHost(sptr);
      SetHiddenHost(sptr);
    } else {
      sconf = find_shost_conf(sptr, hostmask, NULL, &res);
      if ((res == 0) && (sconf != 0)) {
        ircd_strncpy(cli_user(sptr)->sethost, hostmask, USERLEN + HOSTLEN + 1);
        SetSetHost(sptr);
        SetHiddenHost(sptr);
      } else {
        send_reply(sptr, ERR_HOSTUNAVAIL, hostmask);
      }
    }
  }

  hide_hostmask(sptr);
  send_umode_out(cptr, sptr, &setflags, 0);

  return 0;
}

