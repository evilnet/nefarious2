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
#include "ircd_alloc.h"
#include "ircd_crypt.h"
#include "ircd_features.h"
#include "ircd_geoip.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "IPcheck.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Context for async WEBIRC password verification */
struct webirc_verify_ctx {
  int fd;                           /**< Client fd for lookup */
  char username[USERLEN + 1];       /**< WEBIRC username */
  char hostname[HOSTLEN + 1];       /**< WEBIRC hostname */
  char ipaddr[SOCKIPLEN + 1];       /**< WEBIRC IP address */
  char options[256];                /**< WEBIRC options */
  struct irc_in_addr addr;          /**< Parsed IP address */
  struct WebIRCConf *wconf;         /**< Matched config block */
};

/**
 * Apply WEBIRC changes to a client after password verification succeeds.
 * This function contains the common code for applying WEBIRC IP/host changes.
 * @param[in] cptr Client to apply changes to
 * @param[in] wconf Matched WebIRC configuration
 * @param[in] hostname New hostname to set
 * @param[in] ipaddr New IP address string
 * @param[in] addr Parsed IP address
 * @param[in] options WEBIRC options string (may be NULL)
 */
static void apply_webirc_changes(struct Client *cptr, struct WebIRCConf *wconf,
                                  const char *hostname, const char *ipaddr,
                                  const struct irc_in_addr *addr, const char *options)
{
  char *optsdup = NULL;
  char *opt = NULL;
  char *optval = NULL;
  char *p = NULL;

  /* Send connection notice to inform opers of the change of IP and host. */
  if (feature_bool(FEAT_CONNEXIT_NOTICES))
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                         "WEBIRC Client host: from %s [%s] to %s [%s]",
                         cli_sockhost(cptr), cli_sock_ip(cptr), hostname, ipaddr);

  /* Copy old details to cli_connectip and cli_connecthost. */
  if (!IsIPSpoofed(cptr)) {
    memcpy(&cli_connectip(cptr), &cli_ip(cptr), sizeof(cli_ip(cptr)));
    ircd_strncpy(cli_connecthost(cptr), cli_sockhost(cptr), HOSTLEN + 1);
    if (cli_auth(cptr))
      auth_set_originalip(cli_auth(cptr), cli_ip(cptr));
    SetIPSpoofed(cptr);
  }

  /* Undo original IP connection in IPcheck. */
  if (IsIPChecked(cptr)) {
    IPcheck_connect_fail(cptr, 1);
    ClearIPChecked(cptr);
  }

  /* Update the IP and charge them as a remote connect. */
  memcpy(&cli_ip(cptr), addr, sizeof(cli_ip(cptr)));
  if (!find_except_conf(cptr, EFLAG_IPCHECK))
    IPcheck_remote_connect(cptr, 0);

  /* Change cli_sock_ip() and cli_sockhost() to spoofed host and IP. */
  ircd_strncpy(cli_sock_ip(cptr), ircd_ntoa(&cli_ip(cptr)), SOCKIPLEN + 1);
  ircd_strncpy(cli_sockhost(cptr), hostname, HOSTLEN + 1);

  /* Update host names if already set. */
  if (cli_user(cptr)) {
    if (!IsHiddenHost(cptr))
      ircd_strncpy(cli_user(cptr)->host, hostname, HOSTLEN + 1);
    ircd_strncpy(cli_user(cptr)->realhost, hostname, HOSTLEN + 1);
  }

  /* Set client's GeoIP data */
  geoip_apply(cptr);

  /* From this point the user is a WEBIRC user. */
  SetWebIRC(cptr);

  if (FlagHas(&wconf->flags, WFLAG_NOIDENT))
    ClrFlag(cptr, FLAG_GOTID);

  if (FlagHas(&wconf->flags, WFLAG_USERIDENT))
    SetWebIRCUserIdent(cptr);

  if (FlagHas(&wconf->flags, WFLAG_STRIPSSLFP))
    ircd_strncpy(cli_sslclifp(cptr), "", BUFSIZE + 1);

  if (FlagHas(&wconf->flags, WFLAG_USEOPTIONS)) {
    /* Remove user mode +z and only add it if "secure" option is supplied. */
    ClearSSL(cptr);

    if (options != NULL && options[0] != '\0') {
      DupString(optsdup, options);
      for (opt = ircd_strtok(&p, optsdup, " "); opt;
           opt = ircd_strtok(&p, 0, " ")) {
        optval = strchr(opt, '=');
        if (optval != NULL)
          *optval++ = '\0';
        else
          optval = "";
        Debug((DEBUG_DEBUG, "WEBIRC: Found option '%s' with value '%s'", opt, optval));

        /* handle "secure" option */
        if (!ircd_strcmp(opt, "secure"))
          SetSSL(cptr);
        /* handle "local-port" and "remote-port" options */
        else if (!ircd_strcmp(opt, "local-port") || !ircd_strcmp(opt, "remote-port"))
          Debug((DEBUG_DEBUG, "WEBIRC: Ignoring option '%s' as we don't use it", opt));
        /* handle "afternet.org/account" option */
        else if (!ircd_strcmp(opt, "afternet.org/account")) {
          if (FlagHas(&wconf->flags, WFLAG_TRUSTACCOUNT) && cli_user(cptr)) {
            SetAccount(cptr);
            ircd_strncpy(cli_user(cptr)->account, optval, ACCOUNTLEN + 1);

            if ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
                (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) {
              SetHiddenHost(cptr);
            }
          } else
            Debug((DEBUG_DEBUG, "WEBIRC: Ignoring untrusted %s value '%s'", opt, optval));
        }
        /* Log unrecognized options */
        else
          Debug((DEBUG_DEBUG, "WEBIRC: Unrecognized option '%s' supplied by client", opt));
      }
      MyFree(optsdup);
    }
  }

  if (!EmptyString(wconf->description)) {
    ircd_strncpy(cli_webirc(cptr), wconf->description, BUFSIZE + 1);
  }

  /* Set users ident to WebIRC block specified ident. */
  if (!EmptyString(wconf->ident)) {
    ircd_strncpy(cli_username(cptr), wconf->ident, USERLEN + 1);
    SetGotId(cptr);
  }
}

/**
 * Callback invoked when async WEBIRC password verification completes.
 * Called in main thread context via thread_pool_poll().
 */
static void webirc_password_verified(int result, void *arg)
{
  struct webirc_verify_ctx *ctx = arg;
  struct Client *cptr;

  /* Look up client by fd */
  if (ctx->fd < 0 || ctx->fd >= MAXCONNECTIONS) {
    MyFree(ctx);
    return;
  }

  cptr = LocalClientArray[ctx->fd];

  /* Verify client still exists and is pending verification */
  if (!cptr || IsDead(cptr) || !IsWebIRCPending(cptr)) {
    Debug((DEBUG_DEBUG, "webirc_password_verified: client gone or not pending "
           "(fd %d)", ctx->fd));
    MyFree(ctx);
    return;
  }

  /* Clear pending flag */
  ClearWebIRCPending(cptr);

  if (result == CRYPT_VERIFY_MATCH) {
    /* Password matched - apply WEBIRC changes */
    Debug((DEBUG_INFO, "webirc_password_verified: WEBIRC success for %s [%s]",
           cli_sockhost(cptr), cli_sock_ip(cptr)));

    apply_webirc_changes(cptr, ctx->wconf, ctx->hostname, ctx->ipaddr,
                         &ctx->addr, ctx->options[0] ? ctx->options : NULL);

    /* Forward to IAuth if configured */
    if (cli_auth(cptr)) {
      if (FlagHas(&ctx->wconf->flags, WFLAG_USEOPTIONS))
        auth_set_webirc_trusted(cli_auth(cptr), "", ctx->username, ctx->hostname,
                                ctx->ipaddr, ctx->options[0] ? ctx->options : NULL);
      else
        auth_set_webirc_trusted(cli_auth(cptr), "", ctx->username, ctx->hostname,
                                ctx->ipaddr, NULL);
    }
  } else {
    /* Password didn't match */
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid password from %s [%s]",
                                cli_sockhost(cptr), cli_sock_ip(cptr));
    exit_client(cptr, cptr, &me, "WEBIRC Password invalid for your host");
    Debug((DEBUG_INFO, "webirc_password_verified: WEBIRC failed for %s [%s]",
           cli_sockhost(cptr), cli_sock_ip(cptr)));
  }

  MyFree(ctx);
}

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
  int res = 0;
  int ares = 0;
  struct WebIRCConf *wconf;

  if (IsServerPort(cptr))
    return exit_client(cptr, sptr, &me, "Use a different port");

  if (parc < 5)
    return need_more_params(sptr, "WEBIRC");

  if (IsWebIRC(cptr))
    return 0;

  /* Already pending async verification? */
  if (IsWebIRCPending(cptr))
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

  /* Check supplied IP address is valid (do this early before async) */
  if (!ipmask_parse(ipaddr, &addr, NULL)) {
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid IP address from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC Invalid IP address");
  }

  /* Check supplied host name is valid (do this early before async) */
  if (!valid_hostname(hostname)) {
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid host name from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC Invalid host name");
  }

  /* Find matching WebIRC block by host (without password check) */
  wconf = find_webirc_conf_by_host(cptr);
  if (!wconf) {
    /* No matching host - check if IAuth can handle it */
    if (cli_auth(cptr)) {
      ares = auth_set_webirc(cli_auth(cptr), password, username, hostname, ipaddr, options);
      if (!ares)
        return 0;  /* IAuth is handling it */
    }
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt unauthorized from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC Not authorized from your host");
  }

  /* If IAuth handles WEBIRC, let it (it might use different password database) */
  if (cli_auth(cptr)) {
    ares = auth_set_webirc(cli_auth(cptr), password, username, hostname, ipaddr, options);
    if (!ares)
      return 0;  /* IAuth is handling it */
  }

  /* Check if password is required */
  if (EmptyString(wconf->passwd)) {
    /* No password required - apply WEBIRC changes immediately */
    apply_webirc_changes(cptr, wconf, hostname, ipaddr, &addr, options);

    /* Forward to IAuth if configured */
    if (cli_auth(cptr)) {
      if (FlagHas(&wconf->flags, WFLAG_USEOPTIONS))
        auth_set_webirc_trusted(cli_auth(cptr), password, username, hostname, ipaddr, options);
      else
        auth_set_webirc_trusted(cli_auth(cptr), password, username, hostname, ipaddr, NULL);
    }
    return 0;
  }

  /* Password required - try async verification if available */
  if (ircd_crypt_async_available()) {
    struct webirc_verify_ctx *ctx;

    ctx = (struct webirc_verify_ctx *)MyMalloc(sizeof(struct webirc_verify_ctx));
    ctx->fd = cli_fd(cptr);
    ctx->wconf = wconf;
    memcpy(&ctx->addr, &addr, sizeof(ctx->addr));
    ircd_strncpy(ctx->username, username, USERLEN);
    ircd_strncpy(ctx->hostname, hostname, HOSTLEN);
    ircd_strncpy(ctx->ipaddr, ipaddr, SOCKIPLEN);
    ircd_strncpy(ctx->options, options ? options : "", sizeof(ctx->options) - 1);

    if (ircd_crypt_verify_async(password, wconf->passwd,
                                 webirc_password_verified, ctx) == 0) {
      /* Async verification started */
      SetWebIRCPending(cptr);
      Debug((DEBUG_INFO, "m_webirc: started async verification for %s [%s]",
             cli_sockhost(cptr), cli_sock_ip(cptr)));
      return 0;
    }

    /* Async failed to start, fall back to sync */
    MyFree(ctx);
    Debug((DEBUG_DEBUG, "m_webirc: async failed, falling back to sync for %s [%s]",
           cli_sockhost(cptr), cli_sock_ip(cptr)));
  }

  /* Synchronous password verification (blocking if bcrypt) */
  res = 0;
  wconf = find_webirc_conf(cptr, password, &res);

  if (res == 1) {
    /* Password mismatch */
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid password from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC Password invalid for your host");
  }

  if (res == 2 || !wconf) {
    /* No matching config */
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt unauthorized from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC Not authorized from your host");
  }

  /* Password verified - apply changes */
  apply_webirc_changes(cptr, wconf, hostname, ipaddr, &addr, options);

  /* Forward to IAuth if configured */
  if (cli_auth(cptr)) {
    if (FlagHas(&wconf->flags, WFLAG_USEOPTIONS))
      auth_set_webirc_trusted(cli_auth(cptr), password, username, hostname, ipaddr, options);
    else
      auth_set_webirc_trusted(cli_auth(cptr), password, username, hostname, ipaddr, NULL);
  }

  return 0;
}
