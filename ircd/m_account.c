/*
 * IRC - Internet Relay Chat, ircd/m_account.c
 * Copyright (C) 2002 Kevin L. Mitchell <klmitch@mit.edu>
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
 * $Id: m_account.c 1271 2004-12-11 05:14:07Z klmitch $
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
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/*
 * decode the request id, as encoded in s_user.c (register_user):
 * request-id ::= <period> <fd> <period> <cookie>
 */
static struct Client *decode_auth_id(const char *id)
{
  const char *cookiestr;
  unsigned int fd, cookie;
  struct Client *cptr;

  if (!id)
    return NULL;
  if (id[0] != '.')
    return NULL;
  if (!(cookiestr = strchr(id + 1, '.')))
    return NULL;
  fd = atoi(id + 1);
  cookie = atoi(cookiestr + 1);
  Debug((DEBUG_DEBUG, "ACCOUNT auth id fd=%u cookie=%u", fd, cookie));

  if (!(cptr = LocalClientArray[fd]) || !cli_loc(cptr) || cli_loc(cptr)->cookie != cookie)
    return NULL;
  return cptr;
}

/*
 * ms_account - server message handler
 *
 * parv[0] = sender prefix
 * parv[1] = numeric of client to act on
 * parv[2] = account name (12 characters or less)
 */
int ms_account(struct Client* cptr, struct Client* sptr, int parc,
	       char* parv[])
{
  struct Client *acptr;
  char type;

  if (parc < 3)
    return need_more_params(sptr, "ACCOUNT");

  if (!IsServer(sptr))
    return protocol_violation(cptr, "ACCOUNT from non-server %s",
			      cli_name(sptr));

  if (feature_bool(FEAT_EXTENDED_ACCOUNTS)) {
    if (strlen(parv[2]) != 1)
      return protocol_violation(cptr, "ACCOUNT detected invalid subcommand token "
                                "'%s'. Old syntax maybe? See EXTENDED_ACCOUNTS F:line",
                                parv[2] ? parv[2] : "");

    type = parv[2][0];

    if (type == 'U' || type == 'M' || type == 'R') {
      /* General account changes (U=unregister, R=register, M=change account) */
      if (!(acptr = findNUser(parv[1])))
        return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

      if (type =='U') {
        if (!IsAccount(acptr))
          return protocol_violation(cptr, "User %s does not have an account set "
                                    "(ACCOUNT Removal)", cli_name(acptr));
        assert(0 != cli_user(acptr)->account[0]);

        ClearAccount(acptr);
        ircd_strncpy(cli_user(acptr)->account, "", ACCOUNTLEN);

        sendcmdto_common_channels_capab_butone(acptr, CMD_ACCOUNT, acptr, CAP_ACCNOTIFY, CAP_NONE,
                                               "*");

        sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr, "%C U", acptr);
      } else if (type == 'R' || type == 'M') {
        if (parc < 4)
          return need_more_params(sptr, "ACCOUNT");

        if (type == 'R') {
          if (IsAccount(acptr))
            return protocol_violation(cptr, "ACCOUNT for already registered user %s "
                                      "(%s -> %s)", cli_name(acptr),
                                      cli_user(acptr)->account, parv[3]);
          assert(0 == cli_user(acptr)->account[0]);
        }

        if (strlen(parv[3]) > ACCOUNTLEN)
          return protocol_violation(cptr,
                                    "Received account (%s) longer than %d for %s; "
                                    "ignoring.",
                                    parv[3], ACCOUNTLEN, cli_name(acptr));

        if (ircd_strncmp(cli_user(acptr)->account, parv[3], ACCOUNTLEN) == 0)
          return 0;

        ircd_strncpy(cli_user(acptr)->account, parv[3], ACCOUNTLEN);
        SetAccount(acptr);

        if (parc > 4) {
          cli_user(acptr)->acc_create = atoi(parv[4]);
          Debug((DEBUG_DEBUG, "Received timestamped account: account \"%s\", "
                 "timestamp %Tu", parv[3], cli_user(acptr)->acc_create));
        }

        sendcmdto_common_channels_capab_butone(acptr, CMD_ACCOUNT, acptr, CAP_ACCNOTIFY, CAP_NONE,
                                               "%s", cli_user(acptr)->account);

        if (parc > 4) {
          sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr, "%C %c %s %s",
                                acptr, type, parv[3], parv[4]);
        } else {
          sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr, "%C %c %s",
                                acptr, type, parv[3]);
        }
      }

      if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
           (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
          IsHiddenHost(acptr))
        hide_hostmask(acptr);
      return 0;
    } else if (type == 'C' || type == 'H' || type == 'S') {
      /* LOC requests, forward them and ignore them */
      if (((type == 'C') && (parc < 6)) || ((type == 'H') && (parc < 7)) ||
          ((type == 'S') && (parc < 8)))
        return need_more_params(sptr, "ACCOUNT");

      if (!(acptr = FindNServer(parv[1])) && !(acptr = findNUser(parv[1])))
        return 0; /* target not online, ignore */

      if (IsMe(acptr))
        return protocol_violation(cptr, "ACCOUNT check (%s %s %s%s%s)", parv[3],
                                  parv[4], parv[5], (parc>6 ? " ": ""),
                                  (parc>6 ? parv[6]: ""));
      if (parc>7)
        sendcmdto_one(sptr, CMD_ACCOUNT, acptr, "%s %s %s %s %s %s :%s",
                      parv[1], parv[2], parv[3], parv[4], parv[5], parv[6], parv[7]);
      else if (parc>6)
        sendcmdto_one(sptr, CMD_ACCOUNT, acptr, "%s %s %s %s %s :%s",
                      parv[1], parv[2], parv[3], parv[4], parv[5], parv[6]);
      else
        sendcmdto_one(sptr, CMD_ACCOUNT, acptr, "%s %s %s %s :%s",
                      parv[1], parv[2], parv[3], parv[4], parv[5]);
      return 0;
    } else if (type == 'A' || type == 'D') {
      /* LOC Replies (A=accept, D=deny) */
      if (parc < 4)
        return need_more_params(sptr, "ACCOUNT");

      if (!(acptr = FindNServer(parv[1])))
        return 0; /* target not online, ignore */

      if (!IsMe(acptr)) {
        /* in-transit message, forward it */
        sendcmdto_one(sptr, CMD_ACCOUNT, acptr, "%s %s %s", parv[1], parv[2],
                      parv[3]);
        return 0;
      }

      if (!(acptr = decode_auth_id(parv[3])))
        return 0; /* most probably, user disconnected */

      if (type == 'A') {
        SetAccount(acptr);
        ircd_strncpy(cli_user(acptr)->account, cli_loc(acptr)->account,
                        ACCOUNTLEN);

        if (parc > 4) {
          cli_user(acptr)->acc_create = atoi(parv[4]);
        }

        if ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
            (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) {
          SetHiddenHost(acptr);
          hide_hostmask(acptr);
        }
      }

      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :AUTHENTICATION %s as %s", acptr,
                    type == 'A' ? "SUCCESSFUL" : "FAILED", cli_loc(acptr)->account);
      MyFree(cli_loc(acptr));

      if (type == 'D') {
        sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Type \002/QUOTE PASS\002 "
                      "to connect anyway", acptr);
        return 0;
      }

      return register_user(acptr, acptr);
    } else {
      return protocol_violation(cptr, "ACCOUNT sub-type '%s' not implemented",
                                parv[2]);
    }

    return 0;
  } else {
    if (!(acptr = findNUser(parv[1])))
      return 0; /* Ignore ACCOUNT for a user that QUIT; probably crossed */

    if (IsAccount(acptr))
      return protocol_violation(cptr, "ACCOUNT for already registered user %s "
                                "(%s -> %s)", cli_name(acptr),
                                cli_user(acptr)->account, parv[2]);

    assert(0 == cli_user(acptr)->account[0]);

    if (strlen(parv[2]) > ACCOUNTLEN)
      return protocol_violation(cptr,
                                "Received account (%s) longer than %d for %s; "
                                "ignoring.",
                                parv[2], ACCOUNTLEN, cli_name(acptr));

    if (parc > 3) {
      cli_user(acptr)->acc_create = atoi(parv[3]);
      Debug((DEBUG_DEBUG, "Received timestamped account: account \"%s\", "
             "timestamp %Tu", parv[2], cli_user(acptr)->acc_create));
    }

    ircd_strncpy(cli_user(acptr)->account, parv[2], ACCOUNTLEN);
    SetAccount(acptr);

    sendcmdto_common_channels_capab_butone(acptr, CMD_ACCOUNT, acptr, CAP_ACCNOTIFY, CAP_NONE,
                                           "%s", cli_user(acptr)->account);

    if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
         (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
        IsHiddenHost(acptr))
      hide_hostmask(acptr);

    sendcmdto_serv_butone(sptr, CMD_ACCOUNT, cptr,
                          cli_user(acptr)->acc_create ? "%C %s %Tu" : "%C %s",
                          acptr, cli_user(acptr)->account,
                          cli_user(acptr)->acc_create);
  }

  return 0;
}
