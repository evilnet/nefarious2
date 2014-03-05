/*
 * IRC - Internet Relay Chat, ircd/client.c
 * Copyright (C) 1990 Darren Reed
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
 */
/** @file
 * @brief Implementation of functions for handling local clients.
 * @version $Id: client.c 1523 2005-10-12 23:52:12Z entrope $
 */
#include "config.h"

#include "client.h"
#include "class.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "send.h"
#include "struct.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/** Find the shortest non-zero ping time attached to a client.
 * If all attached ping times are zero, return the value for
 * FEAT_PINGFREQUENCY.
 * @param[in] acptr Client to find ping time for.
 * @return Ping time in seconds.
 */
int client_get_ping(const struct Client* acptr)
{
  int     ping = 0;
  struct ConfItem* aconf;
  struct SLink*    link;

  assert(cli_verify(acptr));

  for (link = cli_confs(acptr); link; link = link->next) {
    aconf = link->value.aconf;
    if (aconf->status & (CONF_CLIENT | CONF_SERVER)) {
      int tmp = get_conf_ping(aconf);
      if (0 < tmp && (ping > tmp || !ping))
        ping = tmp;
    }
  }
  if (0 == ping)
    ping = feature_int(FEAT_PINGFREQUENCY);

  Debug((DEBUG_DEBUG, "Client %s Ping %d", cli_name(acptr), ping));

  return ping;
}

/** Find the default usermode for a client.
 * @param[in] sptr Client to find default usermode for.
 * @return Pointer to usermode string (or NULL, if there is no default).
 */
const char* client_get_default_umode(const struct Client* sptr)
{
  struct ConfItem* aconf;
  struct SLink* link;

  assert(cli_verify(sptr));

  for (link = cli_confs(sptr); link; link = link->next) {
    aconf = link->value.aconf;
    if ((aconf->status & CONF_CLIENT) && ConfUmode(aconf))
      return ConfUmode(aconf);
  }
  return NULL;
}

/** Find the number of host componants to hide for a client.
 * @param[in] sptr Client to find the number of host componants to hide for.
 * @return The number of host componants to hide.
 */
int client_get_hidehostcomponants(const struct Client* sptr)
{
  struct ConfItem* aconf;
  struct SLink* link;

  assert(cli_verify(sptr));

  for (link = cli_confs(sptr); link; link = link->next) {
    aconf = link->value.aconf;
      if ((aconf->status & CONF_CLIENT) && (aconf->hidehostcomps > 0))
        return aconf->hidehostcomps;
  }

  return feature_int(FEAT_HOST_HIDING_COMPONANTS);
}

/** Remove a connection from the list of connections with queued data.
 * @param[in] con Connection with no queued data.
 */
void client_drop_sendq(struct Connection* con)
{
  if (con_prev_p(con)) { /* on the queued data list... */
    if (con_next(con))
      con_prev_p(con_next(con)) = con_prev_p(con);
    *(con_prev_p(con)) = con_next(con);

    con_next(con) = 0;
    con_prev_p(con) = 0;
  }
}

/** Add a connection to the list of connections with queued data.
 * @param[in] con Connection with queued data.
 * @param[in,out] con_p Previous pointer to next connection.
 */
void client_add_sendq(struct Connection* con, struct Connection** con_p)
{
  if (!con_prev_p(con)) { /* not on the queued data list yet... */
    con_prev_p(con) = con_p;
    con_next(con) = *con_p;

    if (*con_p)
      con_prev_p(*con_p) = &(con_next(con));
    *con_p = con;
  }
}

/** Default privilege set for global operators. */
static struct Privs privs_global;
/** Default privilege set for local operators. */
static struct Privs privs_local;
/** Non-zero if #privs_global and #privs_local have been initialized. */
static int privs_defaults_set;

/* client_set_privs(struct Client* client)
 *
 * Sets the privileges for opers.
 */
/** Set the privileges for a client.
 * @param[in] client Client who has become an operator.
 * @param[in] oper Configuration item describing oper's privileges.
 */
void
client_set_privs(struct Client *client, struct ConfItem *oper)
{
  struct Privs *source, *defaults;
  enum Priv priv;

  /* Clear out client's privileges. */
  memset(&cli_privs(client), 0, sizeof(struct Privs));

  if (!IsAnOper(client) || !oper)
      return;

  if (!privs_defaults_set)
  {
    memset(&privs_global, -1, sizeof(privs_global));
    FlagClr(&privs_global, PRIV_WALK_LCHAN);
    FlagClr(&privs_global, PRIV_UNLIMIT_QUERY);
    FlagClr(&privs_global, PRIV_SET);
    FlagClr(&privs_global, PRIV_BADCHAN);
    FlagClr(&privs_global, PRIV_LOCAL_BADCHAN);
    FlagClr(&privs_global, PRIV_APASS_OPMODE);
    FlagClr(&privs_global, PRIV_WHOIS_NOTICE);
    FlagClr(&privs_global, PRIV_HIDE_OPER);
    FlagClr(&privs_global, PRIV_HIDE_CHANNELS);
    FlagClr(&privs_global, PRIV_HIDE_IDLE);
    FlagClr(&privs_global, PRIV_ADMIN);
    FlagClr(&privs_global, PRIV_XTRAOP);
    FlagClr(&privs_global, PRIV_SERVICE);
    FlagClr(&privs_global, PRIV_REMOTE);
    FlagClr(&privs_global, PRIV_FREEFORM);
    FlagClr(&privs_global, PRIV_REMOVE);

    memset(&privs_local, 0, sizeof(privs_local));
    FlagSet(&privs_local, PRIV_CHAN_LIMIT);
    FlagSet(&privs_local, PRIV_MODE_LCHAN);
    FlagSet(&privs_local, PRIV_SHOW_INVIS);
    FlagSet(&privs_local, PRIV_SHOW_ALL_INVIS);
    FlagSet(&privs_local, PRIV_LOCAL_KILL);
    FlagSet(&privs_local, PRIV_REHASH);
    FlagSet(&privs_local, PRIV_LOCAL_GLINE);
    FlagSet(&privs_local, PRIV_LOCAL_JUPE);
    FlagSet(&privs_local, PRIV_LOCAL_OPMODE);
    FlagSet(&privs_local, PRIV_WHOX);
    FlagSet(&privs_local, PRIV_DISPLAY);
    FlagSet(&privs_local, PRIV_FORCE_LOCAL_OPMODE);
    FlagSet(&privs_local, PRIV_LOCAL_SHUN);
    FlagSet(&privs_local, PRIV_LOCAL_ZLINE);

    privs_defaults_set = 1;
  }

  /* Decide whether to use global or local oper defaults. */
  if (FlagHas(&oper->privs_dirty, PRIV_PROPAGATE))
    defaults = FlagHas(&oper->privs, PRIV_PROPAGATE) ? &privs_global : &privs_local;
  else if (FlagHas(&oper->conn_class->privs_dirty, PRIV_PROPAGATE))
    defaults = FlagHas(&oper->conn_class->privs, PRIV_PROPAGATE) ? &privs_global : &privs_local;
  else {
    assert(0 && "Oper has no propagation and neither does connection class");
    return;
  }

  /* For each feature, figure out whether it comes from the operator
   * conf, the connection class conf, or the defaults, then apply it.
   */
  for (priv = 0; priv < PRIV_LAST_PRIV; ++priv)
  {
    /* Figure out most applicable definition for the privilege. */
    if (FlagHas(&oper->privs_dirty, priv))
      source = &oper->privs;
    else if (FlagHas(&oper->conn_class->privs_dirty, priv))
      source = &oper->conn_class->privs;
    else
      source = defaults;

    /* Set it if necessary (privileges were already cleared). */
    if (FlagHas(source, priv))
      SetPriv(client, priv);
  }

  /* This should be handled in the config, but lets be sure... */
  if (HasPriv(client, PRIV_PROPAGATE))
  {
    /* force propagating opers to display */
    SetPriv(client, PRIV_DISPLAY);
  }
  else
  {
    /* if they don't propagate oper status, prevent desyncs */
    ClrPriv(client, PRIV_KILL);
    ClrPriv(client, PRIV_GLINE);
    ClrPriv(client, PRIV_JUPE);
    ClrPriv(client, PRIV_SHUN);
    ClrPriv(client, PRIV_ZLINE);
    ClrPriv(client, PRIV_OPMODE);
    ClrPriv(client, PRIV_BADCHAN);
  }

  if (MyUser(client))
    ClrPriv(client, PRIV_REMOTE);

  client_sendtoserv_privs(client);
}

/** Array mapping privilege values to names and vice versa. */
static struct {
  char        *name; /**< Name of privilege. */
  unsigned int priv; /**< Enumeration value of privilege */
} privtab[] = {
/** Helper macro to define an array entry for a privilege. */
#define P(priv)		{ #priv, PRIV_ ## priv }
  P(CHAN_LIMIT),     P(MODE_LCHAN),     P(WALK_LCHAN),    P(DEOP_LCHAN),
  P(SHOW_INVIS),     P(SHOW_ALL_INVIS), P(UNLIMIT_QUERY), P(KILL),
  P(LOCAL_KILL),     P(REHASH),         P(RESTART),       P(DIE),
  P(GLINE),          P(LOCAL_GLINE),    P(JUPE),          P(LOCAL_JUPE),
  P(OPMODE),         P(LOCAL_OPMODE),   P(SET),           P(WHOX),
  P(BADCHAN),        P(LOCAL_BADCHAN),  P(SEE_CHAN),      P(PROPAGATE),
  P(DISPLAY),        P(SEE_OPERS),      P(WIDE_GLINE),    P(LIST_CHAN),
  P(FORCE_OPMODE),   P(FORCE_LOCAL_OPMODE), P(APASS_OPMODE), P(CHECK),
  P(WHOIS_NOTICE),   P(HIDE_OPER),      P(HIDE_CHANNELS), P(HIDE_IDLE),
  P(ADMIN),          P(XTRAOP),         P(SERVICE),       P(REMOTE),
  P(SHUN),           P(LOCAL_SHUN),     P(WIDE_SHUN),     P(FREEFORM),
  P(REMOTEREHASH),   P(REMOVE),         P(LOCAL_ZLINE),   P(ZLINE),
  P(WIDE_ZLINE),
#undef P
  { 0, 0 }
};

/** Report privileges of \a client to \a to.
 * @param[in] to Client requesting privilege list.
 * @param[in] client Client whos privileges should be listed.
 * @return Zero.
 */
int
client_report_privs(struct Client *to, struct Client *client)
{
  struct MsgBuf *mb;
  int found1 = 0;
  int i;

  mb = msgq_make(to, rpl_str(RPL_PRIVS), cli_name(&me), cli_name(to),
		 cli_name(client));

  for (i = 0; privtab[i].name; i++)
    if (HasPriv(client, privtab[i].priv))
      msgq_append(0, mb, "%s%s", found1++ ? " " : "", privtab[i].name);

  send_buffer(to, mb, 0); /* send response */
  msgq_clean(mb);

  return 0;
}

void client_check_privs(struct Client *client, struct Client *replyto)
{
  char outbuf[BUFSIZE];
  int i = 0;
  static char privbufp[BUFSIZE] = "";

  memset(&privbufp, 0, BUFSIZE);

  for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
      if (strlen(privbufp) + strlen(privtab[i].name) + 2 > 70) {
        ircd_snprintf(0, outbuf, sizeof(outbuf), "     Privileges:: %s", privbufp);
        send_reply(replyto, RPL_DATASTR, outbuf);
        memset(&privbufp, 0, BUFSIZE);
      }
      strcat(privbufp, privtab[i].name);
      strcat(privbufp, " ");
    }
  }

  if (strlen(privbufp) > 0) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "     Privileges:: %s", privbufp);
    send_reply(replyto, RPL_DATASTR, outbuf);
  }
}

void client_send_privs(struct Client *from, struct Client *to, struct Client *client)
{
  int i;
  int mlen = NICKLEN + 5 + NICKLEN + 7;
  static char privbuf[BUFSIZE] = "";

  memset(&privbuf, 0, BUFSIZE);

  for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
      if (strlen(privbuf) + strlen(privtab[i].name) + 1 > BUFSIZE - mlen) {
        sendcmdto_one(from, CMD_PRIVS, to, "%C %s", client, privbuf);
        memset(&privbuf, 0, BUFSIZE);
      }
      strcat(privbuf, privtab[i].name);
      strcat(privbuf, " ");
    }
  }

  if (strlen(privbuf) > 0) {
    sendcmdto_one(from, CMD_PRIVS, to, "%C %s", client, privbuf);
  }    
}

void client_sendtoserv_privs(struct Client *client)
{
  int i;
  int mlen = NICKLEN + 5 + NICKLEN + 7;
  static char privbuf[BUFSIZE] = "";

  memset(&privbuf, 0, BUFSIZE);

  for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
      if (strlen(privbuf) + strlen(privtab[i].name) + 1 > BUFSIZE - mlen) {
        sendcmdto_serv_butone(&me, CMD_PRIVS, client, "%C %s", client, privbuf);
        memset(&privbuf, 0, BUFSIZE);
      }
      strcat(privbuf, privtab[i].name);
      strcat(privbuf, " ");
    }
  }

  if (strlen(privbuf) > 0) {
    sendcmdto_serv_butone(&me, CMD_PRIVS, client, "%C %s", client, privbuf);
  }
}

char *client_print_privs(struct Client *client)
{
  int i;
  static char privbufp[BUFSIZE] = "";

  privbufp[0] = '\0';
  for (i = 0; privtab[i].name; i++) {
    if (HasPriv(client, privtab[i].priv)) {
      strcat(privbufp, privtab[i].name);
      strcat(privbufp, " ");
    }
  }
  privbufp[strlen(privbufp)] = 0;

  return (char *)privbufp;
}

int client_modify_priv_by_name(struct Client *who, char *priv, int what) {
  int i = 0;
  assert(0 != priv);
  assert(0 != who);

  for (i = 0; privtab[i].name; i++)
  if (0 == ircd_strcmp(privtab[i].name, priv)) {
    if (what == PRIV_ADD) {
      SetPriv(who, privtab[i].priv);
    } else if (what == PRIV_DEL) {
      ClrPriv(who, privtab[i].priv);
    }
  }
  return 0;
}

int clear_privs(struct Client *who) {
  int i = 0;
  assert(0 != who);

  for (i = 0; privtab[i].name; i++)
    ClrPriv(who, privtab[i].priv);

  return 0;
}

void client_check_marks(struct Client *client, struct Client *replyto)
{
  char outbuf[BUFSIZE];
  static char markbufp[BUFSIZE] = "";
  struct SLink* dp;

  if (!IsMarked(client))
    return;

  memset(&markbufp, 0, BUFSIZE);

  for (dp = cli_marks(client); dp; dp = dp->next) {
    if (strlen(markbufp) + strlen(dp->value.cp) + 4 > 70) {
      ircd_snprintf(0, outbuf, sizeof(outbuf), "          Marks:: %s", markbufp);
      send_reply(replyto, RPL_DATASTR, outbuf);
      memset(&markbufp, 0, BUFSIZE);
    }

    if (markbufp[0])
      strcat(markbufp, ", ");
    strcat(markbufp, dp->value.cp);
  }

  if (markbufp[0]) {
    ircd_snprintf(0, outbuf, sizeof(outbuf), "          Marks:: %s", markbufp);
    send_reply(replyto, RPL_DATASTR, outbuf);
  }
}

