/*
 * IRC - Internet Relay Chat, ircd/m_oper.c
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
 * $Id: m_oper.c 1327 2005-03-19 22:52:33Z entrope $
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

#include "channel.h"
#include "class.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_crypt.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "querycmds.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "s_misc.h"
#include "s_bsd.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/* Forward declarations */
void do_oper(struct Client* cptr, struct Client* sptr, struct ConfItem* aconf);

/**
 * Context for async OPER password verification.
 * This is passed to the thread pool callback.
 */
struct oper_verify_ctx {
  int fd;                         /**< Client file descriptor */
  unsigned int cookie;            /**< Unique cookie to verify client identity */
  char name[NICKLEN + 1];         /**< Oper name for logging */
  struct ConfItem *aconf;         /**< Oper config block */
};

/**
 * Callback invoked when async OPER password verification completes.
 * Called in main thread context via thread_pool_poll().
 */
static void oper_password_verified(int result, void *arg)
{
  struct oper_verify_ctx *ctx = arg;
  struct Client *sptr;

  /* Look up client by fd */
  if (ctx->fd < 0 || ctx->fd >= MAXCONNECTIONS) {
    MyFree(ctx);
    return;
  }

  sptr = LocalClientArray[ctx->fd];

  /* Verify client still exists and matches our cookie */
  if (!sptr || IsDead(sptr) || !IsOperPending(sptr)) {
    Debug((DEBUG_DEBUG, "oper_password_verified: client gone or not pending "
           "(fd %d)", ctx->fd));
    MyFree(ctx);
    return;
  }

  /* Clear pending flag */
  ClearOperPending(sptr);

  if (result == CRYPT_VERIFY_MATCH) {
    /* Password matched - complete OPER */
    if (MyUser(sptr)) {
      int attach_result = attach_conf(sptr, ctx->aconf);
      if ((ACR_OK != attach_result) && (ACR_ALREADY_AUTHORIZED != attach_result)) {
        send_reply(sptr, ERR_NOOPERHOST);
        sendto_opmask_butone_global(&me, SNO_OLDREALOP,
            "Failed OPER attempt by %s (%s@%s) (attach failed after async)",
            cli_name(sptr), cli_user(sptr)->username, cli_user(sptr)->realhost);
        MyFree(ctx);
        return;
      }
    }
    do_oper(sptr, sptr, ctx->aconf);
    SetOperedLocal(sptr);
    ClearOperedRemote(sptr);
    Debug((DEBUG_INFO, "oper_password_verified: OPER success for %s",
           cli_name(sptr)));
  } else {
    /* Password didn't match */
    send_reply(sptr, ERR_PASSWDMISMATCH);
    sendto_opmask_butone_global(&me, SNO_OLDREALOP,
        "Failed OPER attempt by %s (%s@%s) (password mismatch)",
        cli_name(sptr), cli_user(sptr)->username, cli_user(sptr)->realhost);
    Debug((DEBUG_INFO, "oper_password_verified: OPER failed for %s",
           cli_name(sptr)));
  }

  MyFree(ctx);
}

void do_oper(struct Client* cptr, struct Client* sptr, struct ConfItem* aconf)
{
  struct Flags old_mode = cli_flags(sptr);
  char*        modes;
  char*        parv[2];
  char*        join[3];
  char         chan[CHANNELLEN + 1];
  char*        ajoinchan;
  char*        ajoinnotice;
  unsigned int snomask = 0;

  parv[0] = cli_name(sptr);
  parv[1] = NULL;

  SetOper(sptr);
  client_set_privs(sptr, aconf);
  ClearOper(sptr);

  snomask = ConfSnoMask(aconf) & SNO_ALL;
  snomask |= aconf->snomask & SNO_ALL;

  ajoinchan = ConfAjoinChan(aconf);
  ajoinnotice = ConfAjoinNotice(aconf);

  if (MyUser(sptr)) {
    SetLocOp(sptr);
    if (HasPriv(sptr, PRIV_PROPAGATE))
    {
      ClearLocOp(sptr);
      SetOper(sptr);
      if (HasPriv(sptr, PRIV_ADMIN))
        SetAdmin(sptr);
      if (!IsHideOper(sptr) && !IsChannelService(sptr) && !IsBot(sptr))
        ++UserStats.opers;
    }
    cli_handler(sptr) = OPER_HANDLER;

    SetFlag(sptr, FLAG_WALLOP);
    SetFlag(sptr, FLAG_SERVNOTICE);
    SetFlag(sptr, FLAG_DEBUG);

    if (snomask)
      set_snomask(sptr, snomask, SNO_ADD);
    else
      set_snomask(sptr, feature_int(FEAT_SNOMASK_OPERDEFAULT), SNO_ADD);
    cli_max_sendq(sptr) = 0; /* Get the sendq from the oper's class */
    cli_max_recvq(sptr) = 0; /* Get the recvq from the oper's class */
    cli_lag_min(sptr) = -2; /* Get the fake lag minimum from the oper's class */
    cli_lag_factor(sptr) = -2; /* Get the fake lag factor from the oper's class */

    if (cli_user(sptr)->opername)
      MyFree(cli_user(sptr)->opername);
    DupString(cli_user(sptr)->opername, aconf->name);

    send_umode_out(sptr, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
  } else {
    client_send_privs(&me, sptr, sptr);

    if (HasPriv(sptr, PRIV_PROPAGATE)) {
      modes = (HasPriv(sptr, PRIV_ADMIN) ? "aowsg" : "owsg");
    } else {
      modes = "Owsg";
    }

    sendcmdto_one(&me, CMD_MODE, sptr, "%s %s", cli_name(sptr), modes);
  }

  modes = ConfUmode(aconf);
  if (modes) {
    if (MyUser(sptr)) {
      char *umodev[] = { NULL, NULL, NULL, NULL };
      umodev[1] = cli_name(sptr);
      umodev[2] = modes;
      old_mode = cli_flags(sptr);
      set_user_mode(sptr, sptr, 3, umodev, ALLOWMODES_ANY);
      send_umode(NULL, sptr, &old_mode, HasPriv(sptr, PRIV_PROPAGATE));
      if ((cli_snomask(sptr) != feature_int(FEAT_SNOMASK_OPERDEFAULT)) &&
          HasFlag(sptr, FLAG_SERVNOTICE))
        send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));
    } else {
      if (snomask)
        sendcmdto_one(&me, CMD_MODE, sptr, "%s %s+s +%d", cli_name(sptr), modes, snomask);
      else
        sendcmdto_one(&me, CMD_MODE, sptr, "%s %s", cli_name(sptr), modes);
    }
  }

  send_reply(sptr, RPL_YOUREOPER);

  if ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
      (feature_int(FEAT_HOST_HIDING_STYLE) == 3))
    hide_hostmask(sptr);

  if (!EmptyString(ajoinchan))
  {
    if (!EmptyString(ajoinnotice))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, ajoinnotice);

    if (!MyUser(sptr)) {
      sendcmdto_serv_butone(&me, CMD_SVSJOIN, NULL, "%C %s", sptr, ajoinchan);
    } else {
      ircd_strncpy(chan, ajoinchan, CHANNELLEN + 1);
      join[0] = cli_name(sptr);
      join[1] = chan;
      join[2] = NULL;
      m_join(sptr, sptr, 2, join);
    }
  }

  if (!EmptyString(aconf->autojoinchan))
  {
    if (!EmptyString(aconf->autojoinnotice))
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, aconf->autojoinnotice);

    if (!MyUser(sptr)) {
      sendcmdto_serv_butone(&me, CMD_SVSJOIN, NULL, "%C %s", sptr, aconf->autojoinchan);
    } else {
      ircd_strncpy(chan, aconf->autojoinchan, CHANNELLEN + 1);
      join[0] = cli_name(sptr);
      join[1] = chan;
      join[2] = NULL;
      m_join(sptr, sptr, 2, join);
    }
  }

  if (!EmptyString(aconf->swhois))
  {
    ircd_strncpy(cli_user(sptr)->swhois, aconf->swhois, BUFSIZE + 1);
    sendcmdto_serv_butone(&me, CMD_SWHOIS, NULL, "%C :%s", sptr, aconf->swhois);
  }

  sendto_opmask_butone_global((MyUser(sptr) ? &me : NULL), SNO_OLDSNO,
     "%s (%s@%s) is now a %s operator (%c)",
     cli_name(sptr), cli_user(sptr)->username, cli_user(sptr)->realhost,
     HasPriv(sptr, PRIV_PROPAGATE) ? "global" : "local",
     HasPriv(sptr, PRIV_PROPAGATE) ? 'O' : 'o');

  if (feature_bool(FEAT_OPERMOTD))
    m_opermotd(sptr, sptr, 1, parv);

  log_write(LS_OPER, L_INFO, 0, "OPER (%s) by (%#C)", aconf->name, sptr);
}

int can_oper(struct Client *cptr, struct Client *sptr, char *name,
             char *password, struct ConfItem **_aconf)
{
  struct ConfItem *aconf;

  aconf = find_conf_exact(name, sptr, CONF_OPERATOR);
  if (!aconf || IsIllegal(aconf))
  {
    send_reply(sptr, ERR_NOOPERHOST);
    sendto_opmask_butone_global(&me, SNO_OLDREALOP, "Failed %sOPER attempt by %s (%s@%s) "
                         "(no operator block)", (!MyUser(sptr) ? "remote " : ""),
                         cli_name(sptr), cli_user(sptr)->username, cli_user(sptr)->realhost);
    return 0;
  }
  assert(0 != (aconf->status & CONF_OPERATOR));

  if (!MyUser(sptr)) {
    if (FlagHas(&aconf->privs, PRIV_REMOTE)) {
    } else if (aconf->conn_class && FlagHas(&aconf->conn_class->privs, PRIV_REMOTE)) {
    } else {
      send_reply(sptr, ERR_NOOPERHOST);
      sendto_opmask_butone_global(&me, SNO_OLDREALOP, "Failed %sOPER attempt by %s (%s@%s) "
                           "(no remote oper priv)", (!MyUser(sptr) ? "remote " : ""),
                           cli_name(sptr), cli_user(sptr)->username, cli_user(sptr)->realhost);
      return 0;
    }
  }

  if (!verify_sslclifp(sptr, aconf))
  {
    send_reply(sptr, ERR_SSLCLIFP);
    sendto_opmask_butone_global(&me, SNO_OLDREALOP, "Failed %sOPER attempt by %s "
                                "(%s@%s) (SSL fingerprint mismatch)",
                                (!MyUser(sptr) ? "remote " : ""), cli_name(sptr),
                                cli_user(sptr)->username, cli_user(sptr)->realhost);
    return 0;
  }

  /*
   * Try async password verification if available.
   * This prevents blocking the event loop during bcrypt/PBKDF2 hashing.
   * Falls back to synchronous verification if async is not available.
   */
  if (MyUser(sptr) && ircd_crypt_async_available() && !IsOperPending(sptr)) {
    struct oper_verify_ctx *ctx;

    ctx = (struct oper_verify_ctx *)MyMalloc(sizeof(struct oper_verify_ctx));
    ctx->fd = cli_fd(sptr);
    ctx->aconf = aconf;
    ircd_strncpy(ctx->name, name, NICKLEN);

    if (ircd_crypt_verify_async(password, aconf->passwd,
                                 oper_password_verified, ctx) == 0) {
      /* Async verification started */
      SetOperPending(sptr);
      Debug((DEBUG_INFO, "can_oper: started async verification for %s",
             cli_name(sptr)));
      *_aconf = aconf;
      return 1; /* Return 1 = pending async */
    }

    /* Async failed to start, fall back to sync */
    MyFree(ctx);
    Debug((DEBUG_DEBUG, "can_oper: async failed, falling back to sync for %s",
           cli_name(sptr)));
  }

  /* Synchronous password verification (blocking) */
  if (oper_password_match(password, aconf->passwd))
  {
    if (MyUser(sptr))
    {
      int attach_result = attach_conf(sptr, aconf);
      if ((ACR_OK != attach_result) && (ACR_ALREADY_AUTHORIZED != attach_result)) {
        send_reply(sptr, ERR_NOOPERHOST);
        sendto_opmask_butone_global(&me, SNO_OLDREALOP, "Failed %sOPER attempt by %s "
                                    "(%s@%s) (no operator block)",
                                    (!MyUser(sptr) ? "remote " : ""), cli_name(sptr),
                                    cli_user(sptr)->username, cli_user(sptr)->realhost);
        return 0;
      }
    }
    *_aconf = aconf;
    return -1;
  }
  else
  {
    send_reply(sptr, ERR_PASSWDMISMATCH);
    sendto_opmask_butone_global(&me, SNO_OLDREALOP, "Failed %sOPER attempt by %s (%s@%s) "
                                 "(password mis-match)", (!MyUser(sptr) ? "remote " : ""),
                                 cli_name(sptr), cli_user(sptr)->username,
                                 cli_user(sptr)->realhost);
    return 0;
  }
}

/*
 * m_oper - generic message handler
 */
int m_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct ConfItem* aconf;
  char*            name;
  char*            password;

  assert(0 != cptr);
  assert(cptr == sptr);

  if ((parc > 3) && feature_bool(FEAT_REMOTE_OPER)) {
    struct Client *srv;

    if (!string_has_wildcards(parv[1]))
      srv = FindServer(parv[1]);
    else
      srv = find_match_server(parv[1]);

    if (!srv)
      return send_reply(sptr, ERR_NOOPERHOST);

    if (IsMe(srv)) {
      parv[1] = parv[2];
      parv[2] = parv[3];
    } else {
      sendcmdto_one(sptr, CMD_OPER, srv, "%C %s %s", srv, parv[2], parv[3]);
      SetOperedRemote(sptr);
      ClearOperedLocal(sptr);
      return 0;
    }
  }

  name     = parc > 1 ? parv[1] : 0;
  password = parc > 2 ? parv[2] : 0;

  if (EmptyString(name) || EmptyString(password))
    return need_more_params(sptr, "OPER");

  /* Reject if async verification already in progress */
  if (IsOperPending(sptr)) {
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :OPER authentication already in progress",
                  sptr);
    return 0;
  }

  {
    int result = can_oper(cptr, sptr, name, password, &aconf);
    if (result == -1) {
      /* Sync verification succeeded */
      do_oper(cptr, sptr, aconf);
      SetOperedLocal(sptr);
      ClearOperedRemote(sptr);
    }
    /* result == 1 means async pending, callback will handle it */
    /* result == 0 means failed, error already sent */
  }

  return 0;
}

/*
 * ms_oper - server message handler
 */
int ms_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  struct ConfItem *aconf;

  assert(0 != cptr);
  assert(IsServer(cptr));
  /*
   * if message arrived from server, trust it, and set to oper
   */

  if (!IsServer(sptr) && !IsOper(sptr)) {
    if (parc < 4)
      return send_reply(sptr, ERR_NOOPERHOST);

    if (!(acptr = FindNServer(parv[1])))
      return send_reply(sptr, ERR_NOOPERHOST);
    else if (!IsMe(acptr)) {
      sendcmdto_one(sptr, CMD_OPER, acptr, "%C %s %s", acptr, parv[2],
                    parv[3]);
      return 0;
    }

    if (can_oper(cptr, sptr, parv[2], parv[3], &aconf))
      do_oper(cptr, sptr, aconf);
  } else if (!IsServer(sptr))
    send_reply(sptr, RPL_YOUREOPER);

  return 0;
}

/*
 * mo_oper - oper message handler
 */
int mo_oper(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != cptr);
  assert(cptr == sptr);
  send_reply(sptr, RPL_YOUREOPER);
  return 0;
}

