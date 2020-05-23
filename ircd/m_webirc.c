/*
 * IRC - Internet Relay Chat, ircd/m_webirc.c
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
#include "ircd_geoip.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "IPcheck.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * m_webirc
 *
 * parv[0] = sender prefix
 * parv[1] = password           (WEBIRC Password)
 * parv[2] = username           (ignored)
 * parv[3] = hostname           (Real host)
 * parv[4] = ip                 (Real IP in ASCII)
 */
int m_webirc(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct irc_in_addr addr;
  char* username = NULL;
  char* hostname = NULL;
  char* ipaddr = NULL;
  char* password = NULL;
  char* options = NULL;
  char* opt = NULL;
  char* optval = NULL;
  char *p = NULL;
  int res = 0;
  int ares = 0;
  struct WebIRCConf *wline;

  if (IsServerPort(cptr))
    return exit_client(cptr, sptr, &me, "Use a different port");

  if (parc < 5)
    return need_more_params(sptr, "WEBIRC");

  if (IsWebIRC(cptr))
    return 0;

  /* These shouldn't be empty, but just in case... */
  if (!EmptyString(parv[1]))
    password = parv[1];
  if (!EmptyString(parv[2]))
    username = parv[2];
  if (!EmptyString(parv[3]))
    hostname = parv[3];
  if (!EmptyString(parv[4]))
    ipaddr = parv[4];
  if ((parc > 5) && !EmptyString(parv[5]))
    options = parv[5];

  /* And to be extra sure... (should never occur) */
  if (!password || !username || !hostname || !ipaddr) {
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid parameters from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC parameters supplied are invalid");
  }

  wline = find_webirc_conf(cptr, password, &res);

  ares = -1;
  if (res && cli_auth(cptr))
      ares = auth_set_webirc(cli_auth(cptr), password, username, hostname, ipaddr);

  if (!ares)
    return 0;
  else
  {
    switch (res)
    {
      case 2:
        sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                    "WEBIRC Attempt unauthorized from %s [%s]",
                                    cli_sockhost(sptr), cli_sock_ip(sptr));
        return exit_client(cptr, sptr, &me, "WEBIRC Not authorized from your host");
        break;
      case 1:
        sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                    "WEBIRC Attempt with invalid password from %s [%s]",
                                    cli_sockhost(sptr), cli_sock_ip(sptr));
        return exit_client(cptr, sptr, &me, "WEBIRC Password invalid for your host");
        break;
    }
  }

  /* Send connection notice to inform opers of the change of IP and host. */
  if (feature_bool(FEAT_CONNEXIT_NOTICES))
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                         "WEBIRC Client host: from %s [%s] to %s [%s]",
                         cli_sockhost(sptr), cli_sock_ip(sptr), hostname, ipaddr);

  /* Copy old details to cli_connectip and cli_connecthost. */
  if (!IsIPSpoofed(sptr)) {
    memcpy(&cli_connectip(sptr), &cli_ip(sptr), sizeof(cli_ip(sptr)));
    ircd_strncpy(cli_connecthost(sptr), cli_sockhost(sptr), HOSTLEN);
    if (cli_auth(sptr))
      auth_set_originalip(cli_auth(sptr), cli_ip(sptr));
    SetIPSpoofed(sptr);
  }

  /* Undo original IP connection in IPcheck. */
  if (IsIPChecked(sptr)) {
    IPcheck_connect_fail(sptr, 1);
    ClearIPChecked(sptr);
  }

  /* Update the IP and charge them as a remote connect. */
  ircd_aton(&addr, ipaddr);
  memcpy(&cli_ip(sptr), &addr, sizeof(cli_ip(sptr)));
  if (!find_except_conf(sptr, EFLAG_IPCHECK))
    IPcheck_remote_connect(sptr, 0);

  /* Change cli_sock_ip() and cli_sockhost() to spoofed host and IP. */
  ircd_strncpy(cli_sock_ip(sptr), ircd_ntoa(&cli_ip(sptr)), SOCKIPLEN);
  ircd_strncpy(cli_sockhost(sptr), hostname, HOSTLEN);

  /* Update host names if already set. */
  if (cli_user(sptr)) {
    if (!IsHiddenHost(sptr))
      ircd_strncpy(cli_user(sptr)->host, hostname, HOSTLEN);
    ircd_strncpy(cli_user(sptr)->realhost, hostname, HOSTLEN);
  }

  /* Set client's GeoIP data */
  geoip_apply(cptr);

  /* From this point the user is a WEBIRC user. */
  SetWebIRC(cptr);

  if (FlagHas(&wline->flags, WFLAG_NOIDENT))
    ClrFlag(sptr, FLAG_GOTID);

  if (FlagHas(&wline->flags, WFLAG_USERIDENT))
    SetWebIRCUserIdent(cptr);

  if (FlagHas(&wline->flags, WFLAG_STRIPSSLFP))
    ircd_strncpy(cli_sslclifp(cptr), "", BUFSIZE + 1);

  if (FlagHas(&wline->flags, WFLAG_USEOPTIONS)) {
    /* Remove user mode +z and only add it if "secure" option is supplied. */
    ClearSSL(sptr);

    if (options != NULL) {
      for (opt = ircd_strtok(&p, options, " "); opt;
           opt = ircd_strtok(&p, 0, " ")) {
        optval = strchr(opt, '=');
        if (optval != NULL)
          *optval++ = '\0';
        else
          optval = "";
        Debug((DEBUG_DEBUG, "WEBIRC: Found option '%s' with value '%s'", opt, optval));

        /* handle "secure" option */
        if (!ircd_strcmp(opt, "secure"))
          SetSSL(sptr);
        /* handle "local-port" and "remote-port" options */
        else if (!ircd_strcmp(opt, "local-port") || !ircd_strcmp(opt, "remote-port"))
          Debug((DEBUG_DEBUG, "WEBIRC: Ignoring option '%s' as we don't use it", opt));
        /* handle "afternet.org/account" option */
        else if (!ircd_strcmp(opt, "afternet.org/account")) {
          if (FlagHas(&wline->flags, WFLAG_TRUSTACCOUNT)) {
            SetAccount(sptr);
            ircd_strncpy(cli_user(sptr)->account, optval, ACCOUNTLEN);

            if ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
                (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) {
              SetHiddenHost(sptr);
            }
          } else
            Debug((DEBUG_DEBUG, "WEBIRC: Ignoring untrusted %s value '%s'", opt, optval));
        }
        /* Log unrecognized options */
        else
          Debug((DEBUG_DEBUG, "WEBIRC: Unrecognized option '%s' supplied by client", opt));
      }
    }
  }

  if (!EmptyString(wline->description)) {
    ircd_strncpy(cli_webirc(cptr), wline->description, BUFSIZE);
  }

  /* Set users ident to WebIRC block specified ident. */
  if (!EmptyString(wline->ident)) {
    ircd_strncpy(cli_username(cptr), wline->ident, USERLEN);
    SetGotId(cptr);
  }

  auth_set_webirc_trusted(cli_auth(cptr), password, username, hostname, ipaddr);

  return 0;
}

