/*
 * IRC - Internet Relay Chat, ircd/m_sasl.c
 * Copyright (C) 2013 Matthew Beeching (Jobe)
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
 * $Id:$
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
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"
#include "send.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

int ms_sasl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  const char* token;
  const char* reply;
  const char* data;
  const char* ext = NULL;
  char* fdstr;
  char* cookiestr;
  unsigned int fd, cookie;

  if (parc < 5) /* have enough parameters? */
    return need_more_params(sptr, "SASL");

  token = parv[2];
  reply = parv[3];
  data = parv[4];
  if (parc > 5)
    ext = parv[5];

  if (!strcmp(parv[1], "*")) {
    if (ext != NULL)
      sendcmdto_serv_butone(sptr, CMD_SASL, cptr, "* %s %s %s :%s",
                                   token, reply, data, ext);
    else
      sendcmdto_serv_butone(sptr, CMD_SASL, cptr, "* %s %s :%s",
                                   token, reply, data);
    return 0;
  } else {
    /* Look up the target */
    if (!(acptr = findNUser(parv[1])) && !(acptr = FindNServer(parv[1])))
      return send_reply(sptr, SND_EXPLICIT | ERR_NOSUCHSERVER,
                        "* :Server has disconnected");

    /* If it's not to us, forward the reply */
    if (!IsMe(acptr)) {
      if (ext != NULL)
        sendcmdto_one(sptr, CMD_SASL, acptr, "%C %s %s %s :%s", acptr, token,
                      reply, data, ext);
      else
        sendcmdto_one(sptr, CMD_SASL, acptr, "%C %s %s :%s", acptr, token,
                      reply, data);
      return 0;
    }
  }

  /* If token is not prefixed with my numnick then ignore */
  if (strncmp(cli_yxx(&me), token, 2))
    return 0;

  /* If there is no fd then it is an invalid token */
  if ((fdstr = strchr(token, '!')) == NULL)
    return 0;
  fdstr++;

  /* If there is no cookie then it is also an invalid token */
  if ((cookiestr = strchr(token, '.')) == NULL)
    return 0;
  *cookiestr++ = '\0';

  fd = atoi(fdstr);
  cookie = atoi(cookiestr);

  /* Could not find a matching client, ignore the message */
  if (!(acptr = LocalClientArray[fd]) || (cli_saslcookie(acptr) != cookie))
    return 0;

  /* OK we now know who the message is for, let's deal with it! */

  /* If we don't know who the agent is we do now, else check its the same agent */
  if (!cli_saslagent(acptr)) {
    cli_saslagent(acptr) = sptr;
    cli_saslagentref(sptr)++;
  } else if (cli_saslagent(acptr) != sptr)
    return 0;

  if (reply[0] == 'C') {
    sendrawto_one(acptr, MSG_AUTHENTICATE " %s", data);
    return 0;
  } else if (reply[0] == 'L') {
    if (parc > 5)
      cli_saslacccreate(acptr) = atoi(parv[5]);
    ircd_strncpy(cli_saslaccount(acptr), data, ACCOUNTLEN);
    send_reply(acptr, RPL_LOGGEDIN,
               BadPtr(cli_name(acptr)) ? "*" : cli_name(acptr),
               (!cli_user(acptr) || BadPtr(cli_user(acptr)->username)) ? "*" : cli_user(acptr)->username,
               (!cli_user(acptr) || BadPtr(cli_user(acptr)->host)) ? "*" : cli_user(acptr)->host,
               cli_saslaccount(acptr), cli_saslaccount(acptr));
    if (cli_auth(acptr))
      auth_set_account(cli_auth(acptr), cli_saslaccount(acptr));
  } else if (reply[0] == 'D') {
    if (data[0] == 'S') {
      SetSASLComplete(acptr);
      send_reply(acptr, RPL_SASLSUCCESS);
    } else if (data[0] == 'F') {
      send_reply(acptr, ERR_SASLFAIL, "");
    } else if (data[0] == 'A') {
      send_reply(acptr, ERR_SASLABORTED);
    }
    if ((cli_saslagent(acptr) != NULL) && cli_saslagentref(cli_saslagent(acptr)))
      cli_saslagentref(cli_saslagent(acptr))--;
    cli_saslagent(acptr) = NULL;
    cli_saslcookie(acptr) = 0;
    if (t_active(&cli_sasltimeout(cptr)))
      timer_del(&cli_sasltimeout(cptr));
  } else if (reply[0] == 'M')
    return send_reply(acptr, ERR_SASLMECHS, data);

  return 0;
}

int abort_sasl(struct Client* cptr, int timeout) {
  struct Client* acptr;

  if (t_active(&cli_sasltimeout(cptr)))
    timer_del(&cli_sasltimeout(cptr));

  if (!cli_saslcookie(cptr) || IsSASLComplete(cptr))
    return 0;

  /* Look up the target server */
  if (!(acptr = cli_saslagent(cptr))) {
    if (strcmp(feature_str(FEAT_SASL_SERVER), "*"))
      acptr = find_match_server((char *)feature_str(FEAT_SASL_SERVER));
    else
      acptr = NULL;
  }

  if (timeout)
    send_reply(cptr, ERR_SASLFAIL, ": request timed out");
  else
    send_reply(cptr, ERR_SASLABORTED);

  if (acptr)
    sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u D A", acptr,
                  &me, cli_fd(cptr), cli_saslcookie(cptr));
  else
    sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u D A",
                          &me, cli_fd(cptr), cli_saslcookie(cptr));

  if ((cli_saslagent(cptr)!= NULL) && cli_saslagentref(cli_saslagent(cptr)))
    cli_saslagentref(cli_saslagent(cptr))--;
  cli_saslagent(cptr) = NULL;
  cli_saslcookie(cptr) = 0;

  return 0;
}

