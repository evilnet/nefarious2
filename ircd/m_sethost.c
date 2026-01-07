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
#include "ircd_alloc.h"
#include "ircd_crypt.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** Context for async SETHOST password verification */
struct sethost_verify_ctx {
  int fd;                               /**< Client fd for lookup */
  char hostmask[USERLEN + HOSTLEN + 2]; /**< Requested user@host mask */
  struct SHostConf *sconf;              /**< Matched config block */
  struct Flags setflags;                /**< Backed up client flags */
};

/**
 * Apply SETHOST changes to a client after password verification succeeds.
 * @param[in] sptr Client to apply changes to
 * @param[in] hostmask Hostmask to set (user@host or just host)
 * @param[in] sconf Matched SpoofHost configuration (may be NULL)
 * @param[in] setflags Backed up client flags for mode change notification
 */
static void apply_sethost_changes(struct Client *sptr, const char *hostmask,
                                   struct SHostConf *sconf, struct Flags *setflags)
{
  /* Apply the spoofhost */
  if (strchr(hostmask, '@') != NULL)
    ircd_strncpy(cli_user(sptr)->sethost, hostmask, HOSTLEN + 1);
  else
    ircd_snprintf(0, cli_user(sptr)->sethost, USERLEN + HOSTLEN + 1, "%s@%s",
                  cli_user(sptr)->username, hostmask);

  if (FlagHas(setflags, FLAG_SETHOST))
    FlagClr(setflags, FLAG_SETHOST);
  SetSetHost(sptr);
  SetHiddenHost(sptr);

  hide_hostmask(sptr);
  send_umode_out(sptr, sptr, setflags, 0);
}

/**
 * Callback invoked when async SETHOST password verification completes.
 * Called in main thread context via thread_pool_poll().
 */
static void sethost_password_verified(int result, void *arg)
{
  struct sethost_verify_ctx *ctx = arg;
  struct Client *sptr;

  /* Look up client by fd */
  if (ctx->fd < 0 || ctx->fd >= MAXCONNECTIONS) {
    MyFree(ctx);
    return;
  }

  sptr = LocalClientArray[ctx->fd];

  /* Verify client still exists and is pending verification */
  if (!sptr || IsDead(sptr) || !IsSetHostPending(sptr)) {
    Debug((DEBUG_DEBUG, "sethost_password_verified: client gone or not pending "
           "(fd %d)", ctx->fd));
    MyFree(ctx);
    return;
  }

  /* Clear pending flag */
  ClearSetHostPending(sptr);

  if (result == CRYPT_VERIFY_MATCH) {
    /* Password matched - apply SETHOST changes */
    Debug((DEBUG_INFO, "sethost_password_verified: SETHOST success for %s",
           cli_name(sptr)));
    apply_sethost_changes(sptr, ctx->hostmask, ctx->sconf, &ctx->setflags);
  } else {
    /* Password didn't match */
    send_reply(sptr, ERR_PASSWDMISMATCH);
    Debug((DEBUG_INFO, "sethost_password_verified: SETHOST failed for %s",
           cli_name(sptr)));
  }

  MyFree(ctx);
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

  /* Already pending async verification? */
  if (IsSetHostPending(sptr))
    return 0;

  /* Back up the flags first */
  setflags = cli_flags(sptr);

  if (ircd_strcmp("undo", parv[1]) == 0) {
    ClearSetHost(sptr);
    cli_user(sptr)->sethost[0] = '\0';
    hide_hostmask(sptr);
    send_umode_out(cptr, sptr, &setflags, 0);
    return 0;
  }

  if (parc < 3)
    return need_more_params(sptr, "SETHOST");

  if (!valid_hostname(parv[1])) {
    send_reply(sptr, ERR_BADHOSTMASK, parv[1]);
    return 0;
  }

  /* Find matching SHost block by host (without password check) */
  sconf = find_shost_conf_by_host(sptr, parv[1]);
  if (!sconf) {
    send_reply(sptr, ERR_HOSTUNAVAIL, parv[1]);
    return 0;
  }

  /* Check if password is required */
  if (!EmptyString(sconf->passwd)) {
    /* Password required - try async verification if available */
    if (ircd_crypt_async_available()) {
      struct sethost_verify_ctx *ctx;

      ctx = (struct sethost_verify_ctx *)MyMalloc(sizeof(struct sethost_verify_ctx));
      ctx->fd = cli_fd(sptr);
      ctx->sconf = sconf;
      ctx->setflags = setflags;
      ircd_strncpy(ctx->hostmask, parv[1], sizeof(ctx->hostmask) - 1);

      if (ircd_crypt_verify_async(parv[2], sconf->passwd,
                                   sethost_password_verified, ctx) == 0) {
        /* Async verification started */
        SetSetHostPending(sptr);
        Debug((DEBUG_INFO, "m_sethost: started async verification for %s",
               cli_name(sptr)));
        return 0;
      }

      /* Async failed to start, fall back to sync */
      MyFree(ctx);
      Debug((DEBUG_DEBUG, "m_sethost: async failed, falling back to sync for %s",
             cli_name(sptr)));
    }

    /* Synchronous password verification (blocking if bcrypt) */
    sconf = find_shost_conf(sptr, parv[1], parv[2], &res);
    if (res == 1) {
      send_reply(sptr, ERR_PASSWDMISMATCH);
      return 0;
    }
    if (res == 2 || !sconf) {
      send_reply(sptr, ERR_HOSTUNAVAIL, parv[1]);
      return 0;
    }
  }

  /* Password verified (or not required) - apply changes */
  apply_sethost_changes(sptr, parv[1], sconf, &setflags);

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

  /* Already pending async verification? */
  if (IsSetHostPending(sptr))
    return 0;

  /* Back up the flags first */
  setflags = cli_flags(sptr);

  if (ircd_strcmp("undo", parv[1]) == 0) {
    ClearSetHost(sptr);
    cli_user(sptr)->sethost[0] = '\0';
    hide_hostmask(sptr);
    send_umode_out(cptr, sptr, &setflags, 0);
    return 0;
  }

  if (parc < 3)
    return need_more_params(sptr, "SETHOST");

  ircd_snprintf(0, hostmask, USERLEN + HOSTLEN + 1, "%s@%s", parv[1], parv[2]);

  if (!valid_username(parv[1]) || !valid_hostname(parv[2])) {
    send_reply(sptr, ERR_BADHOSTMASK, hostmask);
    return 0;
  }

  /* If oper has PRIV_FREEFORM, allow any hostmask without password */
  if (HasPriv(sptr, PRIV_FREEFORM)) {
    ircd_strncpy(cli_user(sptr)->sethost, hostmask, USERLEN + HOSTLEN + 1);
    if (FlagHas(&setflags, FLAG_SETHOST))
      FlagClr(&setflags, FLAG_SETHOST);
    SetSetHost(sptr);
    SetHiddenHost(sptr);
    hide_hostmask(sptr);
    send_umode_out(cptr, sptr, &setflags, 0);
    return 0;
  }

  /* Find matching SHost block by host (without password check) */
  sconf = find_shost_conf_by_host(sptr, hostmask);
  if (!sconf) {
    send_reply(sptr, ERR_HOSTUNAVAIL, hostmask);
    return 0;
  }

  /* Check if password is required */
  if (!EmptyString(sconf->passwd)) {
    /* Oper needs password too (unless PRIV_FREEFORM which was handled above) */
    if (parc < 4) {
      send_reply(sptr, ERR_NEEDMOREPARAMS, "SETHOST");
      return 0;
    }

    /* Password required - try async verification if available */
    if (ircd_crypt_async_available()) {
      struct sethost_verify_ctx *ctx;

      ctx = (struct sethost_verify_ctx *)MyMalloc(sizeof(struct sethost_verify_ctx));
      ctx->fd = cli_fd(sptr);
      ctx->sconf = sconf;
      ctx->setflags = setflags;
      ircd_strncpy(ctx->hostmask, hostmask, sizeof(ctx->hostmask) - 1);

      if (ircd_crypt_verify_async(parv[3], sconf->passwd,
                                   sethost_password_verified, ctx) == 0) {
        /* Async verification started */
        SetSetHostPending(sptr);
        Debug((DEBUG_INFO, "mo_sethost: started async verification for %s",
               cli_name(sptr)));
        return 0;
      }

      /* Async failed to start, fall back to sync */
      MyFree(ctx);
      Debug((DEBUG_DEBUG, "mo_sethost: async failed, falling back to sync for %s",
             cli_name(sptr)));
    }

    /* Synchronous password verification (blocking if bcrypt) */
    sconf = find_shost_conf(sptr, hostmask, parv[3], &res);
    if (res != 0 || !sconf) {
      send_reply(sptr, ERR_HOSTUNAVAIL, hostmask);
      return 0;
    }
  }

  /* Password verified (or not required) - apply changes */
  ircd_strncpy(cli_user(sptr)->sethost, hostmask, USERLEN + HOSTLEN + 1);
  if (FlagHas(&setflags, FLAG_SETHOST))
    FlagClr(&setflags, FLAG_SETHOST);
  SetSetHost(sptr);
  SetHiddenHost(sptr);

  hide_hostmask(sptr);
  send_umode_out(cptr, sptr, &setflags, 0);

  return 0;
}
