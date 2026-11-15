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
#include "handlers.h"
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
#include "random.h"
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
  unsigned int cookie;              /**< cli_checkcookie() at WEBIRC time */
  char *passwd;                     /**< The password (hash) checked against.
                                         No pointer to the block: a rehash
                                         during the check frees it. */
  char *given;                      /**< The password the gateway gave: what
                                         IAuth is told in the w line, or
                                         handed in the W if the check fails
                                         (webirc_unmatched()) */
  char username[USERLEN + 1];       /**< WEBIRC username */
  char hostname[HOSTLEN + 1];       /**< WEBIRC hostname */
  char ipaddr[SOCKIPLEN + 1];       /**< WEBIRC IP address */
  char options[256];                /**< WEBIRC options */
  struct irc_in_addr addr;          /**< Parsed IP address */
};

/** Free a WEBIRC check's context, wiping the password the gateway gave. */
static void webirc_ctx_free(struct webirc_verify_ctx *ctx)
{
  volatile char *p;

  for (p = ctx->given; p && *p; p++)
    *p = '\0';
  MyFree(ctx->given);
  MyFree(ctx->passwd);
  MyFree(ctx);
}

/** A WEBIRC that no block here accepts: no block matches the gateway
 * (\a res 2), or the password is wrong (\a res 1).  When IAuth's policy
 * asks for WEBIRC lines (w), IAuth is handed it as an untrusted W -- it
 * may know the gateway by a password of its own, and apply the address
 * itself -- and the client is kept, with the gateway's address meanwhile;
 * else the client is refused.  A block that matches and accepts the
 * password is never handed over: IAuth is told the trusted w once the
 * address is applied.
 * @param[in] found For a check that finished after a rehash: what was
 *   found then ("no WebIRC block", "password changed"), for the notice;
 *   else NULL.
 * @return Zero if handed to IAuth, else exit_client()'s result.
 */
static int webirc_unmatched(struct Client *cptr, int res, const char *found,
                            const char *password, const char *username,
                            const char *hostname, const char *ipaddr,
                            const char *options)
{
  if (cli_auth(cptr)
      && !auth_set_webirc(cli_auth(cptr), password, username, hostname,
                          ipaddr, options)) {
    /* A wrong password kept the connection: it does not get another
     * guess at the block's (m_webirc()). */
    if (res == 1)
      SetWebIRCBadPass(cptr);
    return 0;
  }
  if (found) {
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt from %s [%s]: %s when the "
                                "password check finished",
                                cli_sockhost(cptr), cli_sock_ip(cptr), found);
    return exit_client(cptr, cptr, &me, res == 2 ? "WEBIRC Not authorized from your host"
                       : "WEBIRC Password invalid for your host");
  }
  if (res == 1) {
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid password from %s [%s]",
                                cli_sockhost(cptr), cli_sock_ip(cptr));
    return exit_client(cptr, cptr, &me, "WEBIRC Password invalid for your host");
  }
  sendto_opmask_butone_global(&me, SNO_WEBIRC,
                              "WEBIRC Attempt unauthorized from %s [%s]",
                              cli_sockhost(cptr), cli_sock_ip(cptr));
  return exit_client(cptr, cptr, &me, "WEBIRC Not authorized from your host");
}

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

  /* The native DNSBL lookup started at connect asked about the gateway's
   * address: ask about the client's. */
  if (cli_auth(cptr))
    auth_dnsbl_restart(cli_auth(cptr));
}

/**
 * Callback invoked when async WEBIRC password verification completes.
 * Called in main thread context via thread_pool_poll().
 */
static void webirc_password_verified(int result, void *arg)
{
  struct webirc_verify_ctx *ctx = arg;
  struct Client *cptr;
  struct WebIRCConf *wconf = NULL;
  int res = 1;                   /* refused: as find_webirc_conf()'s status */
  const char *found = NULL;

  /* Look up client by fd */
  if (ctx->fd < 0 || ctx->fd >= MAXCONNECTIONS) {
    webirc_ctx_free(ctx);
    return;
  }

  cptr = LocalClientArray[ctx->fd];

  /* Verify client still exists and is pending verification -- this one's:
   * the fd may have been reused since by a connection with a WEBIRC of
   * its own pending. */
  if (!cptr || IsDead(cptr) || !IsWebIRCPending(cptr)
      || cli_checkcookie(cptr) != ctx->cookie) {
    Debug((DEBUG_DEBUG, "webirc_password_verified: client gone or not pending "
           "(fd %d)", ctx->fd));
    webirc_ctx_free(ctx);
    return;
  }

  /* Clear pending flag */
  ClearWebIRCPending(cptr);
  cli_checkcookie(cptr) = 0;

  /* Judged by the configuration in force now (a rehash during the check
   * may have removed or re-passworded the block): the block that matches
   * the connection now, with the password that was checked. */
  if (result == CRYPT_VERIFY_MATCH) {
    wconf = find_webirc_conf_by_host(cptr);
    if (!wconf)
      res = 2, found = "no WebIRC block";
    else if (!wconf->passwd || strcmp(wconf->passwd, ctx->passwd))
      found = "password changed";
    else
      res = 0;
  }

  if (res) {
    /* Not accepted here (a wrong password, or the block gone or changed):
     * as a WEBIRC arriving now would be.  Handed to IAuth (policy w), the
     * client goes on with the gateway's address: the AUTHENTICATE lines
     * held for the check start their exchange (one may exit the client),
     * and registration is let go on.  Else it has been refused. */
    Debug((DEBUG_INFO, "webirc_password_verified: WEBIRC not accepted for %s [%s]",
           cli_sockhost(cptr), cli_sock_ip(cptr)));
    if (!webirc_unmatched(cptr, res, found, ctx->given, ctx->username,
                          ctx->hostname, ctx->ipaddr,
                          ctx->options[0] ? ctx->options : NULL)
        && authenticate_replay(cptr) != CPTR_KILLED)
      auth_webirc_release_later(cli_auth(cptr));
    webirc_ctx_free(ctx);
    return;
  }

  /* Password matched - apply WEBIRC changes */
  Debug((DEBUG_INFO, "webirc_password_verified: WEBIRC success for %s [%s]",
         cli_sockhost(cptr), cli_sock_ip(cptr)));

  apply_webirc_changes(cptr, wconf, ctx->hostname, ctx->ipaddr,
                       &ctx->addr, ctx->options[0] ? ctx->options : NULL);

  /* Forward to IAuth if configured: the line a check made at once sends
   * (the password given, and the options only if the block enables them) */
  if (cli_auth(cptr)) {
    if (FlagHas(&wconf->flags, WFLAG_USEOPTIONS))
      auth_set_webirc_trusted(cli_auth(cptr), ctx->given, ctx->username,
                              ctx->hostname, ctx->ipaddr,
                              ctx->options[0] ? ctx->options : NULL);
    else
      auth_set_webirc_trusted(cli_auth(cptr), ctx->given, ctx->username,
                              ctx->hostname, ctx->ipaddr, NULL);

    /* AUTHENTICATE lines held for the check (m_authenticate.c) start
     * their exchange now, on the real address; one may exit the client. */
    if (authenticate_replay(cptr) == CPTR_KILLED) {
      webirc_ctx_free(ctx);
      return;
    }

    /* Registration waited for this (auth_webirc_hold()): it goes on now,
     * with the real address in place. */
    auth_webirc_release_later(cli_auth(cptr));
  }

  webirc_ctx_free(ctx);
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

  /* One guess at a block's password per connection: a wrong one handed to
   * IAuth (webirc_unmatched()) left the connection up, and any later WEBIRC
   * on it is refused as a wrong password is without IAuth, unchecked. */
  if (IsWebIRCBadPass(cptr)) {
    sendto_opmask_butone_global(&me, SNO_WEBIRC,
                                "WEBIRC Attempt with invalid password from %s [%s]",
                                cli_sockhost(sptr), cli_sock_ip(sptr));
    return exit_client(cptr, sptr, &me, "WEBIRC Password invalid for your host");
  }

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

  /* Find matching WebIRC block by host (the password is checked below).
   * A block that matches is judged here, whatever IAuth's policy: IAuth
   * (w) is handed the WEBIRC only when no block accepts it
   * (webirc_unmatched()), and is told the trusted w when one does. */
  wconf = find_webirc_conf_by_host(cptr);
  if (!wconf)
    return webirc_unmatched(cptr, 2, NULL, password, username, hostname,
                            ipaddr, options);

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

  /* Password required - try async verification if available.  Only while
   * registration can still wait for it (the client has its auth request):
   * the check's result is the client's address, which registration must
   * not be decided without. */
  if (ircd_crypt_async_available() && cli_auth(cptr)) {
    struct webirc_verify_ctx *ctx;

    ctx = (struct webirc_verify_ctx *)MyMalloc(sizeof(struct webirc_verify_ctx));
    ctx->fd = cli_fd(cptr);
    ctx->cookie = (ircrandom() & 0x7fffffff) | 1;   /* never 0 */
    DupString(ctx->passwd, wconf->passwd);
    DupString(ctx->given, password);
    memcpy(&ctx->addr, &addr, sizeof(ctx->addr));
    ircd_strncpy(ctx->username, username, USERLEN + 1);
    ircd_strncpy(ctx->hostname, hostname, HOSTLEN + 1);
    ircd_strncpy(ctx->ipaddr, ipaddr, SOCKIPLEN + 1);
    ircd_strncpy(ctx->options, options ? options : "", sizeof(ctx->options) - 1);

    if (ircd_crypt_verify_async(password, wconf->passwd,
                                 webirc_password_verified, ctx) == 0) {
      /* Async verification started; registration waits for it */
      SetWebIRCPending(cptr);
      cli_checkcookie(cptr) = ctx->cookie;
      auth_webirc_hold(cli_auth(cptr));
      Debug((DEBUG_INFO, "m_webirc: started async verification for %s [%s]",
             cli_sockhost(cptr), cli_sock_ip(cptr)));
      return 0;
    }

    /* Async failed to start, fall back to sync */
    webirc_ctx_free(ctx);
    Debug((DEBUG_DEBUG, "m_webirc: async failed, falling back to sync for %s [%s]",
           cli_sockhost(cptr), cli_sock_ip(cptr)));
  }

  /* Synchronous password verification (blocking if bcrypt) */
  res = 0;
  wconf = find_webirc_conf(cptr, password, &res);

  if (res || !wconf)
    return webirc_unmatched(cptr, res == 1 ? 1 : 2, NULL, password, username,
                            hostname, ipaddr, options);

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
