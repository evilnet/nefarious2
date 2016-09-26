/*
 * IRC - Internet Relay Chat, ircd/s_user.c (formerly ircd/s_msg.c)
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
 */
/** @file
 * @brief Miscellaneous user-related helper functions.
 * @version $Id: s_user.c 1919 2009-07-31 02:04:15Z entrope $
 */
#include "config.h"

#include "s_user.h"
#include "IPcheck.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_cloaking.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "mark.h"
#include "match.h"
#include "motd.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "random.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_serv.h" /* max_client_count */
#include "send.h"
#include "shun.h"
#include "ssl.h"
#include "struct.h"
#include "supported.h"
#include "sys.h"
#include "userload.h"
#include "version.h"
#include "watch.h"
#include "whowas.h"

#include "handlers.h" /* m_motd and m_lusers */

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/** Sends response \a m of length \a l to client \a c. */
#ifdef USE_SSL
#define sendheader(c, m, l) \
   ssl_send(c, m, l)
#else
#define sendheader(c, m, l) \
   send(cli_fd(c), m, l, 0)
#endif /* USE_SSL */

/** Count of allocated User structures. */
static int userCount = 0;

/** Makes sure that \a cptr has a User information block.
 * If cli_user(cptr) != NULL, does nothing.
 * @param[in] cptr Client to attach User struct to.
 * @return User struct associated with \a cptr.
 */
struct User *make_user(struct Client *cptr)
{
  assert(0 != cptr);

  if (!cli_user(cptr)) {
    cli_user(cptr) = (struct User*) MyMalloc(sizeof(struct User));
    assert(0 != cli_user(cptr));

    /* All variables are 0 by default */
    memset(cli_user(cptr), 0, sizeof(struct User));
    ++userCount;
    cli_user(cptr)->refcnt = 1;
  }
  return cli_user(cptr);
}

/** Dereference \a user.
 * User structures are reference-counted; if the refcount of \a user
 * becomes zero, free it.
 * @param[in] user User to dereference.
 */
void free_user(struct User* user)
{
  assert(0 != user);
  assert(0 < user->refcnt);

  if (--user->refcnt == 0) {
    if (user->away)
      MyFree(user->away);
    /*
     * sanity check
     */
    assert(0 == user->joined);
    assert(0 == user->invited);
    assert(0 == user->channel);

    MyFree(user);
    assert(userCount>0);
    --userCount;
  }
}

/** Find number of User structs allocated and memory used by them.
 * @param[out] count_out Receives number of User structs allocated.
 * @param[out] bytes_out Receives number of bytes used by User structs.
 */
void user_count_memory(size_t* count_out, size_t* bytes_out)
{
  assert(0 != count_out);
  assert(0 != bytes_out);
  *count_out = userCount;
  *bytes_out = userCount * sizeof(struct User);
}


/** Find the next client (starting at \a next) with a name that matches \a ch.
 * Normal usage loop is:
 * for (x = client; x = next_client(x,mask); x = x->next)
 *     HandleMatchingClient;
 *
 * @param[in] next First client to check.
 * @param[in] ch Name mask to check against.
 * @return Next matching client found, or NULL if none.
 */
struct Client *next_client(struct Client *next, const char* ch)
{
  struct Client *tmp = next;

  if (!tmp)
    return NULL;

  next = FindClient(ch);
  next = next ? next : tmp;
  if (cli_prev(tmp) == next)
    return NULL;
  if (next != tmp)
    return next;
  for (; next; next = cli_next(next))
    if (!match(ch, cli_name(next)))
      break;
  return next;
}

/** Find the destination server for a command, and forward it if that is not us.
 *
 * \a server may be a nickname, server name, server mask (if \a from
 * is a local user) or server numnick (if \a is a server or remote
 * user).
 *
 * @param[in] from Client that sent the command to us.
 * @param[in] cmd Long-form command text.
 * @param[in] tok Token-form command text.
 * @param[in] one Client that originated the command (ignored).
 * @param[in] MustBeOper If non-zero and \a from is not an operator, return HUNTED_NOSUCH.
 * @param[in] pattern Format string of arguments to command.
 * @param[in] server Index of target name or mask in \a parv.
 * @param[in] parc Number of valid elements in \a parv (must be less than 9).
 * @param[in] parv Array of arguments to command.
 * @return One of HUNTED_ISME, HUNTED_NOSUCH or HUNTED_PASS.
 */
int hunt_server_cmd(struct Client *from, const char *cmd, const char *tok,
                    struct Client *one, int MustBeOper, const char *pattern,
                    int server, int parc, char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from))
  {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to))) {
    send_reply(from, SND_EXPLICIT | ERR_NOSUCHSERVER, "* :Server has disconnected");
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */
  }

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* assert(!IsServer(from)); */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
                parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}

/** Find the destination server for a command, and forward it (as a
 * high-priority command) if that is not us.
 *
 * \a server may be a nickname, server name, server mask (if \a from
 * is a local user) or server numnick (if \a is a server or remote
 * user).
 * Unlike hunt_server_cmd(), this appends the message to the
 * high-priority message queue for the destination server.
 *
 * @param[in] from Client that sent the command to us.
 * @param[in] cmd Long-form command text.
 * @param[in] tok Token-form command text.
 * @param[in] one Client that originated the command (ignored).
 * @param[in] MustBeOper If non-zero and \a from is not an operator, return HUNTED_NOSUCH.
 * @param[in] pattern Format string of arguments to command.
 * @param[in] server Index of target name or mask in \a parv.
 * @param[in] parc Number of valid elements in \a parv (must be less than 9).
 * @param[in] parv Array of arguments to command.
 * @return One of HUNTED_ISME, HUNTED_NOSUCH or HUNTED_PASS.
 */
int hunt_server_prio_cmd(struct Client *from, const char *cmd, const char *tok,
			 struct Client *one, int MustBeOper,
			 const char *pattern, int server, int parc,
			 char *parv[])
{
  struct Client *acptr;
  char *to;

  /* Assume it's me, if no server or an unregistered client */
  if (parc <= server || EmptyString((to = parv[server])) || IsUnknown(from))
    return (HUNTED_ISME);

  /* Make sure it's a server */
  if (MyUser(from)) {
    /* Make sure it's a server */
    if (!strchr(to, '*')) {
      if (0 == (acptr = FindClient(to))) {
        send_reply(from, ERR_NOSUCHSERVER, to);
        return HUNTED_NOSUCH;
      }

      if (cli_user(acptr))
        acptr = cli_user(acptr)->server;
    } else if (!(acptr = find_match_server(to))) {
      send_reply(from, ERR_NOSUCHSERVER, to);
      return (HUNTED_NOSUCH);
    }
  } else if (!(acptr = FindNServer(to)))
    return (HUNTED_NOSUCH);        /* Server broke off in the meantime */

  if (IsMe(acptr))
    return (HUNTED_ISME);

  if (MustBeOper && !IsPrivileged(from)) {
    send_reply(from, ERR_NOPRIVILEGES);
    return HUNTED_NOSUCH;
  }

  /* assert(!IsServer(from)); SETTIME to particular destinations permitted */

  parv[server] = (char *) acptr; /* HACK! HACK! HACK! ARGH! */

  sendcmdto_prio_one(from, cmd, tok, acptr, pattern, parv[1], parv[2], parv[3],
		     parv[4], parv[5], parv[6], parv[7], parv[8]);

  return (HUNTED_PASS);
}


/*
 * register_user
 *
 * This function is called when both NICK and USER messages
 * have been accepted for the client, in whatever order. Only
 * after this the USER message is propagated.
 *
 * NICK's must be propagated at once when received, although
 * it would be better to delay them too until full info is
 * available. Doing it is not so simple though, would have
 * to implement the following:
 *
 * 1) user telnets in and gives only "NICK foobar" and waits
 * 2) another user far away logs in normally with the nick
 *    "foobar" (quite legal, as this server didn't propagate it).
 * 3) now this server gets nick "foobar" from outside, but
 *    has already the same defined locally. Current server
 *    would just issue "KILL foobar" to clean out dups. But,
 *    this is not fair. It should actually request another
 *    nick from local user or kill him/her...
 */
/** Finish registering a user who has sent both NICK and USER.
 * For local connections, possibly check IAuth; make sure there is a
 * matching Client config block; clean the username field; check
 * K/k-lines; check for "hacked" looking usernames; assign a numnick;
 * and send greeting (WELCOME, ISUPPORT, MOTD, etc).
 * For all connections, update the invisible user and operator counts;
 * run IPcheck against their address; and forward the NICK.
 *
 * @param[in] cptr Client who introduced the user.
 * @param[in,out] sptr Client who has been fully introduced.
 * @return Zero or CPTR_KILLED.
 */
int register_user(struct Client *cptr, struct Client *sptr)
{
  char*            parv[4];
  char*            tmpstr;
  char*            join[3];
  char             chan[CHANNELLEN-1];
  struct ConnectionClass* connclass = NULL;
  struct ConfItem* cliconf = NULL;
  struct User*     user = cli_user(sptr);
  char             ip_base64[25];
  struct Shun*     ashun = NULL;
  int              res = 0;
  struct SHostConf* sconf = NULL;

  user->last = CurrentTime;
  parv[0] = cli_name(sptr);
  parv[1] = parv[2] = NULL;

  if (MyConnect(sptr))
  {
    assert(cptr == sptr);

    Count_unknownbecomesclient(sptr, UserStats);

    /*
     * Ensure fake lag minimum and factor are retrived from the users class.
     */
    cli_lag_min(sptr) = -2;
    cli_lag_factor(sptr) = -2;

    /*
     * Set user's initial modes
     */
    tmpstr = (char*)client_get_default_umode(sptr);
    if (tmpstr) {
      char *umodev[] = { NULL, NULL, NULL, NULL };
      umodev[2] = tmpstr;
      set_user_mode(cptr, sptr, 3, umodev, ALLOWMODES_ANY);
    }

    SetUser(sptr);
    cli_handler(sptr) = CLIENT_HANDLER;
    SetLocalNumNick(sptr);

    if ((ashun = shun_lookup(sptr, 0))) {
       sendto_opmask_butone_global(&me, SNO_GLINE, "Shun active for %s%s",
                          IsUnknown(sptr) ? "Unregistered Client ":"",
                          get_client_name(sptr, SHOW_IP));
      if (!feature_bool(FEAT_HIS_SHUN_REASON))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :You are shunned: %s", sptr,
             ashun->sh_reason);
    }

    if (feature_bool(FEAT_CTCP_VERSIONING)) {
      if (feature_str(FEAT_CTCP_VERSIONING_NOTICE)) {
        char strver[BUFSIZE] = "";
        ircd_snprintf(0, strver, strlen(feature_str(FEAT_CTCP_VERSIONING_NOTICE)) + 16,
                      "NOTICE * :%s\r\n", feature_str(FEAT_CTCP_VERSIONING_NOTICE));
        sendheader(sptr, strver, strlen(strver));
      }

      sendcmdto_one(&me, CMD_PRIVATE, sptr, "%C :\001VERSION\001", sptr);
    }

    /* Look for an automatic Spoofhost to apply */
    sconf = find_shost_conf(sptr, NULL, NULL, &res);
    if ((res == 0) && (sconf != 0)) {
      if (strchr(sconf->spoofhost, '@') != NULL)
        ircd_strncpy(cli_user(sptr)->sethost, sconf->spoofhost, USERLEN + HOSTLEN + 1);
      else
        ircd_snprintf(0, cli_user(sptr)->sethost, USERLEN + HOSTLEN + 1, "%s@%s",
                      cli_user(sptr)->username, sconf->spoofhost);
      SetSetHost(sptr);
      SetHiddenHost(sptr);
    }

    send_reply(sptr,
               RPL_WELCOME,
               feature_str(FEAT_NETWORK),
               feature_str(FEAT_PROVIDER) ? " via " : "",
               feature_str(FEAT_PROVIDER) ? feature_str(FEAT_PROVIDER) : "",
               cli_name(sptr));
    /*
     * This is a duplicate of the NOTICE but see below...
     */
    send_reply(sptr, RPL_YOURHOST, cli_name(&me), version);
    send_reply(sptr, RPL_CREATED, creation);
    send_reply(sptr, RPL_MYINFO, cli_name(&me), version, infousermodes,
               infochanmodes, infochanmodeswithparams);
    send_supported(sptr);

#ifdef USE_SSL
    if (IsSSL(sptr))
    {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :You are connected to %s with %s", sptr,
                    cli_name(&me), ssl_get_cipher(cli_socket(sptr).ssl));
      if (!EmptyString(cli_sslclifp(sptr)))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Client certificate status: %s",
                      sptr, ssl_get_verify_result(cli_socket(sptr).ssl));
    }
#endif

    m_lusers(sptr, sptr, 1, parv);
    update_load();
    motd_signon(sptr);
    if (cli_snomask(sptr) & SNO_NOISY)
      set_snomask(sptr, cli_snomask(sptr) & SNO_NOISY, SNO_ADD);
    if (feature_bool(FEAT_CONNEXIT_NOTICES))
      sendto_opmask_butone_global(&me, SNO_CONNEXIT,
                           "Client connecting: %s (%s@%s) [%s] {%s} [%s] <%s%s>",
                           cli_name(sptr), user->username, user->realhost,
                           cli_sock_ip(sptr), get_client_class(sptr),
                           cli_info(sptr), NumNick(cptr) /* two %s's */);

    if (IsIPChecked(sptr))
      IPcheck_connect_succeeded(sptr);
  }
  else {
    struct Client *acptr = user->server;

    if (cli_from(acptr) != cli_from(sptr))
    {
      sendcmdto_one(&me, CMD_KILL, cptr, "%C :%s (%s != %s[%s])",
                    sptr, cli_name(&me), cli_name(user->server), cli_name(cli_from(acptr)),
                    cli_sockhost(cli_from(acptr)));
      SetFlag(sptr, FLAG_KILLED);
      return exit_client(cptr, sptr, &me, "NICK server wrong direction");
    }
    else if (HasFlag(acptr, FLAG_TS8))
      SetFlag(sptr, FLAG_TS8);

    /*
     * Check to see if this user is being propagated
     * as part of a net.burst, or is using protocol 9.
     * FIXME: This can be sped up - its stupid to check it for
     * every NICK message in a burst again  --Run.
     */
    for (; acptr != &me; acptr = cli_serv(acptr)->up)
    {
      if (IsBurst(acptr) || Protocol(acptr) < 10)
        break;
    }
    if (IsIPChecked(sptr) && !IPcheck_remote_connect(sptr, (acptr != &me)))
    {
      /*
       * We ran out of bits to count this
       */
      sendcmdto_one(&me, CMD_KILL, sptr, "%C :%s (Too many connections from your host -- Ghost)",
                    sptr, cli_name(&me));
      return exit_client(cptr, sptr, &me,"Too many connections from your host -- throttled");
    }
    SetUser(sptr);
  }

  /* Set the users cloaked host and IP fields. */
  user_setcloaked(sptr);

  /* If they get both +x and an account during registration, hide
   * their hostmask here.  Calling hide_hostmask() from IAuth's
   * account assignment causes a numeric reply during registration.
   */
  if (IsHiddenHost(sptr))
    hide_hostmask(sptr);
  if (IsInvisible(sptr))
    ++UserStats.inv_clients;
  if (IsOper(sptr) && !IsHideOper(sptr) && !IsChannelService(sptr) && !IsBot(sptr))
    ++UserStats.opers;

  tmpstr = umode_str(sptr);
  /* Send full IP address to IPv6-grokking servers. */
  sendcmdto_flag_serv_butone(user->server, CMD_NICK, cptr,
                             FLAG_IPV6, FLAG_LAST_FLAG,
                             "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                             cli_name(sptr), cli_hopcount(sptr) + 1,
                             cli_lastnick(sptr),
                             user->username, user->realhost,
                             *tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
                             iptobase64(ip_base64, &cli_ip(sptr), sizeof(ip_base64), 1),
                             NumNick(sptr), cli_info(sptr));
  /* Send fake IPv6 addresses to pre-IPv6 servers. */
  sendcmdto_flag_serv_butone(user->server, CMD_NICK, cptr,
                             FLAG_LAST_FLAG, FLAG_IPV6,
                             "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
                             cli_name(sptr), cli_hopcount(sptr) + 1,
                             cli_lastnick(sptr),
                             user->username, user->realhost,
                             *tmpstr ? "+" : "", tmpstr, *tmpstr ? " " : "",
                             iptobase64(ip_base64, &cli_ip(sptr), sizeof(ip_base64), 0),
                             NumNick(sptr), cli_info(sptr));

  clear_privs(sptr);

  /* Send user mode to client */
  if (MyUser(sptr))
  {
    static struct Flags flags; /* automatically initialized to zeros */
    struct SLink *lp;

    if (cli_webirc(sptr) && !EmptyString(cli_webirc(sptr)))
      sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s", cli_name(cptr), MARK_WEBIRC, cli_webirc(sptr));

    for (lp = cli_marks(cptr); lp; lp = lp->next) {
      sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s", cli_name(cptr), MARK_MARK, lp->value.cp);
    }

    if (cli_sslclifp(sptr) && !EmptyString(cli_sslclifp(sptr)))
      sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s", cli_name(cptr), MARK_SSLCLIFP, cli_sslclifp(sptr));

    if (cli_version(sptr) && !EmptyString(cli_version(sptr)))
      sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s", cli_name(cptr), MARK_CVERSION, cli_version(sptr));

    if (cli_killmark(sptr) && !EmptyString(cli_killmark(sptr)))
      sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s :%s", cli_name(cptr), MARK_KILL, cli_killmark(sptr));

    if (IsGeoIP(sptr)) {
      if (cli_countrycode(sptr) && !EmptyString(cli_countrycode(sptr)) &&
          cli_continentcode(sptr) && !EmptyString(cli_continentcode(sptr)))
        sendcmdto_serv_butone(&me, CMD_MARK, cptr, "%s %s %s %s",
                      cli_name(sptr), MARK_GEOIP, cli_countrycode(sptr),
                      cli_continentcode(sptr));
    }

    /* To avoid sending +r to the client due to auth-on-connect, set
     * the "old" FLAG_ACCOUNT bit to match the client's value.
     */
    if (IsAccount(cptr))
      FlagSet(&flags, FLAG_ACCOUNT);
    else
      FlagClr(&flags, FLAG_ACCOUNT);
    if (IsCloakHost(cptr))
      FlagSet(&flags, FLAG_CLOAKHOST);
    else
      FlagClr(&flags, FLAG_CLOAKHOST);
    if (IsCloakIP(cptr))
      FlagSet(&flags, FLAG_CLOAKIP);
    else
      FlagClr(&flags, FLAG_CLOAKIP);
    if (IsFakeHost(cptr))
      FlagSet(&flags, FLAG_FAKEHOST);
    else
      FlagClr(&flags, FLAG_FAKEHOST);
    if (IsSetHost(cptr))
      FlagSet(&flags, FLAG_SETHOST);
    else
      FlagClr(&flags, FLAG_SETHOST);
    client_set_privs(sptr, NULL);
    send_umode(cptr, sptr, &flags, ALL_UMODES);
    if ((cli_snomask(sptr) != feature_int(FEAT_SNOMASK_DEFAULT)) &&
        HasFlag(sptr, FLAG_SERVNOTICE))
      send_reply(sptr, RPL_SNOMASK, cli_snomask(sptr), cli_snomask(sptr));

    if ((connclass = get_client_class_conf(sptr)) != NULL)
    {
      if (!EmptyString(connclass->autojoinchan))
      {
        if (!EmptyString(connclass->autojoinnotice))
          sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, connclass->autojoinnotice);

        ircd_strncpy(chan, connclass->autojoinchan, CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        join[2] = NULL;
        m_join(sptr, sptr, 2, join);
      }
    }

    if ((cliconf = get_client_conf(sptr)) != NULL)
    {
      if (!EmptyString(cliconf->autojoinchan))
      {
        if (!EmptyString(cliconf->autojoinnotice))
          sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, cliconf->autojoinnotice);

        ircd_strncpy(chan, cliconf->autojoinchan, CHANNELLEN-1);
        join[0] = cli_name(sptr);
        join[1] = chan;
        join[2] = NULL;
        m_join(sptr, sptr, 2, join);
      }
    }

    if (connclass != NULL) {
      if (FlagHas(&connclass->restrictflags, CRFLAG_JOIN))
        SetRestrictJoin(sptr);
      if (FlagHas(&connclass->restrictflags, CRFLAG_PRIVMSG))
        SetRestrictPrivMsg(sptr);
      if (FlagHas(&connclass->restrictflags, CRFLAG_UMODE))
        SetRestrictUMode(sptr);
    }

  }

  /* Notify new local/remote user */
  check_status_watch(sptr, RPL_LOGON);

  return 0;
}

/** List of user mode characters. */
static const struct UserMode {
  unsigned int flag; /**< User mode constant. */
  char         c;    /**< Character corresponding to the mode. */
} userModeList[] = {
  { FLAG_OPER,         'o' },
  { FLAG_LOCOP,        'O' },
  { FLAG_INVISIBLE,    'i' },
  { FLAG_WALLOP,       'w' },
  { FLAG_SERVNOTICE,   's' },
  { FLAG_DEAF,         'd' },
  { FLAG_CHSERV,       'k' },
  { FLAG_DEBUG,        'g' },
  { FLAG_HIDDENHOST,   'x' },
  { FLAG_NOCHAN,       'n' },
  { FLAG_COMMONCHANSONLY, 'q' },
  { FLAG_BOT,          'B' },
  { FLAG_PRIVDEAF,     'D' },
  { FLAG_HIDE_OPER,    'H' },
  { FLAG_NOIDLE,       'I' },
  { FLAG_ACCOUNTONLY,  'R' },
  { FLAG_WHOIS_NOTICE, 'W' },
  { FLAG_ADMIN,        'a' },
  { FLAG_XTRAOP,       'X' },
  { FLAG_NOLINK,       'L' },
  { FLAG_SSL,          'z' },
  { FLAG_ACCOUNT,      'r' },
  { FLAG_SETHOST,      'h' },
  { FLAG_FAKEHOST,     'f' },
  { FLAG_CLOAKHOST,    'C' },
  { FLAG_CLOAKIP,      'c' }
};

/** Length of #userModeList. */
#define USERMODELIST_SIZE sizeof(userModeList) / sizeof(struct UserMode)

/*
 * XXX - find a way to get rid of this
 */
/** Nasty global buffer used for communications with umode_str() and others. */
static char umodeBuf[BUFSIZE];

/** Try to set a user's nickname.
 * If \a sptr is a server, the client is being introduced for the first time.
 * @param[in] cptr Client to set nickname.
 * @param[in] sptr Client sending the NICK.
 * @param[in] nick New nickname.
 * @param[in] parc Number of arguments to NICK.
 * @param[in] parv Argument list to NICK.
 * @return CPTR_KILLED if \a cptr was killed, else 0.
 */
int set_nick_name(struct Client* cptr, struct Client* sptr,
                  const char* nick, int parc, char* parv[],
                  int svsnick)
{
  if (IsServer(sptr)) {

    /*
     * A server introducing a new client, change source
     */
    struct Client* new_client = make_client(cptr, STAT_UNKNOWN);
    assert(0 != new_client);

    cli_hopcount(new_client) = atoi(parv[2]);
    cli_lastnick(new_client) = atoi(parv[3]);

    /*
     * Set new nick name.
     */
    strcpy(cli_name(new_client), nick);
    cli_user(new_client) = make_user(new_client);
    cli_user(new_client)->server = sptr;
    SetRemoteNumNick(new_client, parv[parc - 2]);
    /*
     * IP# of remote client
     */
    base64toip(parv[parc - 3], &cli_ip(new_client));

    add_client_to_list(new_client);
    hAddClient(new_client);

    cli_serv(sptr)->ghost = 0;        /* :server NICK means end of net.burst */
    ircd_strncpy(cli_username(new_client), parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->username, parv[4], USERLEN);
    ircd_strncpy(cli_user(new_client)->host, parv[5], HOSTLEN);
    ircd_strncpy(cli_user(new_client)->realhost, parv[5], HOSTLEN);
    ircd_strncpy(cli_info(new_client), parv[parc - 1], REALLEN);

    Count_newremoteclient(UserStats, sptr);

    if (parc > 7 && *parv[6] == '+') {
      /* (parc-4) -3 for the ip, numeric nick, realname */
      set_user_mode(cptr, new_client, parc-7, parv+4, ALLOWMODES_ANY);
    }

    return register_user(cptr, new_client);
  }
  else if ((cli_name(sptr))[0]) {
    /*
     * Client changing its nick
     *
     * If the client belongs to me, then check to see
     * if client is on any channels where it is currently
     * banned.  If so, do not allow the nick change to occur.
     */
    if (MyUser(sptr)) {
      const char* channel_name;
      struct Membership *member;
      if ((channel_name = find_no_nickchange_channel(sptr))
          && !IsXtraOp(sptr) && !svsnick) {
        return send_reply(cptr, ERR_BANNICKCHANGE, channel_name);
      }
      /*
       * Refuse nick change if the last nick change was less
       * then 30 seconds ago. This is intended to get rid of
       * clone bots doing NICK FLOOD. -SeKs
       * If someone didn't change their nick for more then 60 seconds
       * however, allow to do two nick changes immediately after another
       * before limiting the nick flood. -Run
       */
      if (CurrentTime < cli_nextnick(cptr))
      {
        cli_nextnick(cptr) += 2;
        send_reply(cptr, ERR_NICKTOOFAST, parv[1],
                   cli_nextnick(cptr) - CurrentTime);
        /* Send error message */
        sendcmdto_one(cptr, CMD_NICK, cptr, "%s", cli_name(cptr));
        /* bounce NICK to user */
        return 0;                /* ignore nick change! */
      }
      else {
        /* Limit total to 1 change per NICK_DELAY seconds: */
        cli_nextnick(cptr) += NICK_DELAY;
        /* However allow _maximal_ 1 extra consecutive nick change: */
        if (cli_nextnick(cptr) < CurrentTime)
          cli_nextnick(cptr) = CurrentTime;
      }
      /* Invalidate all bans against the user so we check them again */
      for (member = (cli_user(cptr))->channel; member;
	   member = member->next_channel) {
        ClearBanValid(member);
        ClearBanValidNick(member);
        ClearExceptValid(member);
        ClearExceptValidNick(member);
      }
    }
    /*
     * Also set 'lastnick' to current time, if changed.
     */
    if (0 != ircd_strcmp(parv[0], nick))
      cli_lastnick(sptr) = (sptr == cptr) ? TStime() : atoi(parv[2]);

    /*
     * Client just changing his/her nick. If he/she is
     * on a channel, send note of change to all clients
     * on that channel. Propagate notice to other servers.
     */
    if (IsUser(sptr)) {
      /* Notify exit user */
      check_status_watch(sptr, RPL_LOGOFF);

      sendcmdto_common_channels_butone(sptr, CMD_NICK, NULL, ":%s", nick);
      add_history(sptr, 1);
      sendcmdto_serv_butone(sptr, CMD_NICK, cptr, "%s %Tu", nick,
                            cli_lastnick(sptr));
    }
    else
      sendcmdto_one(sptr, CMD_NICK, sptr, ":%s", nick);

    /*
     * Send out a connexit notice for the nick change before
     * cli_name(sptr) is overwritten with the new nick. -reed
     */
    if (MyUser(sptr) && feature_bool(FEAT_CONNEXIT_NOTICES))
      sendto_opmask_butone_global(&me, SNO_NICKCHG,
                         "Nick change: From %s to %s [%s@%s] <%s%s>",
                         cli_name(sptr), nick,
                         cli_user(sptr)->username,
                         cli_user(sptr)->realhost,
                         NumNick(sptr) /* Two %'s */
                         );

    if ((cli_name(sptr))[0])
      hRemClient(sptr);
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);

    /* Notify change nick local/remote user */
    check_status_watch(sptr, RPL_LOGON);
  }
  else {
    /* Local client setting NICK the first time */
    strcpy(cli_name(sptr), nick);
    hAddClient(sptr);
    return auth_set_nick(cli_auth(sptr), nick);
  }
  return 0;
}

/** Calculate the hash value for a target.
 * @param[in] target Pointer to target, cast to unsigned int.
 * @return Hash value constructed from the pointer.
 */
static unsigned char hash_target(unsigned int target)
{
  return (unsigned char) (target >> 16) ^ (target >> 8);
}

/** Records \a target as a recent target for \a sptr.
 * @param[in] sptr User who has sent to a new target.
 * @param[in] target Target to add.
 */
void
add_target(struct Client *sptr, void *target)
{
  /* Ok, this shouldn't work esp on alpha
  */
  unsigned char  hash = hash_target((unsigned long) target);
  unsigned char* targets;
  int            i;
  assert(0 != sptr);
  assert(cli_local(sptr));

  targets = cli_targets(sptr);

  /* 
   * Already in table?
   */
  for (i = 0; i < MAXTARGETS; ++i) {
    if (targets[i] == hash)
      return;
  }
  /*
   * New target
   */
  memmove(&targets[RESERVEDTARGETS + 1],
          &targets[RESERVEDTARGETS], MAXTARGETS - RESERVEDTARGETS - 1);
  targets[RESERVEDTARGETS] = hash;
}

/** Check whether \a sptr can send to or join \a target yet.
 * @param[in] sptr User trying to join a channel or send a message.
 * @param[in] target Target of the join or message.
 * @param[in] name Name of the target.
 * @param[in] created If non-zero, trying to join a new channel.
 * @return Non-zero if too many target changes; zero if okay to send.
 */
int check_target_limit(struct Client *sptr, void *target, const char *name,
    int created)
{
  unsigned char hash = hash_target((unsigned long) target);
  int            i;
  unsigned char* targets;

  assert(0 != sptr);
  assert(cli_local(sptr));
  targets = cli_targets(sptr);

  /* Is target limiting even enabled? */
  if (!feature_bool(FEAT_TARGET_LIMITING))
    return 0;

  /* Is the client exempt from target limiting */
  if (find_except_conf(sptr, EFLAG_TARGLIMIT))
    return 0;

  /*
   * Same target as last time?
   */
  if (targets[0] == hash)
    return 0;
  for (i = 1; i < MAXTARGETS; ++i) {
    if (targets[i] == hash) {
      memmove(&targets[1], &targets[0], i);
      targets[0] = hash;
      return 0;
    }
  }
  /*
   * New target
   */
  if (!created) {
    if (CurrentTime < cli_nexttarget(sptr)) {
      /* If user is invited to channel, give him/her a free target */
      if (IsChannelName(name) && IsInvited(sptr, target))
        return 0;

      if (cli_nexttarget(sptr) - CurrentTime < TARGET_DELAY + 8) {
        /*
         * No server flooding
         */
        cli_nexttarget(sptr) += 2;
        send_reply(sptr, ERR_TARGETTOOFAST, name,
                   cli_nexttarget(sptr) - CurrentTime);
      }
      return 1;
    }
    else {
      cli_nexttarget(sptr) += TARGET_DELAY;
      if (cli_nexttarget(sptr) < CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1)))
        cli_nexttarget(sptr) = CurrentTime - (TARGET_DELAY * (MAXTARGETS - 1));
    }
  }
  memmove(&targets[1], &targets[0], MAXTARGETS - 1);
  targets[0] = hash;
  return 0;
}

/** Allows a channel operator to avoid target change checks when
 * sending messages to users on their channel.
 * @param[in] source User sending the message.
 * @param[in] nick Destination of the message.
 * @param[in] channel Name of channel being sent to.
 * @param[in] text Message to send.
 * @param[in] is_notice If non-zero, use CNOTICE instead of CPRIVMSG.
 */
/* Added 971023 by Run. */
int whisper(struct Client* source, const char* nick, const char* channel,
            const char* text, int is_notice)
{
  struct Client*     dest;
  struct Channel*    chptr;
  struct Membership* membership;

  assert(0 != source);
  assert(0 != nick);
  assert(0 != channel);
  assert(MyUser(source));

  if (!(dest = FindUser(nick))) {
    return send_reply(source, ERR_NOSUCHNICK, nick);
  }
  if (!(chptr = FindChannel(channel))) {
    return send_reply(source, ERR_NOSUCHCHANNEL, channel);
  }
  /*
   * compare both users channel lists, instead of the channels user list
   * since the link is the same, this should be a little faster for channels
   * with a lot of users
   */
  for (membership = cli_user(source)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership) {
    return send_reply(source, ERR_NOTONCHANNEL, chptr->chname);
  }
  if (!IsVoicedOrOpped(membership)) {
    return send_reply(source, ERR_VOICENEEDED, chptr->chname);
  }
  /*
   * lookup channel in destination
   */
  assert(0 != cli_user(dest));
  for (membership = cli_user(dest)->channel; membership; membership = membership->next_channel) {
    if (chptr == membership->channel)
      break;
  }
  if (0 == membership || IsZombie(membership)) {
    return send_reply(source, ERR_USERNOTINCHANNEL, cli_name(dest), chptr->chname);
  }
  if (is_silenced(source, dest, 0))
    return 0;

  if (IsAccountOnly(dest) && !IsAccount(source) && !IsOper(source) && (dest != source)) {
    send_reply(source, ERR_ACCOUNTONLY, cli_name(dest), (is_notice) ? "CNOTICE" : "CPRIVMSG", cli_name(dest));
    return 0;
  }

  if (IsPrivDeaf(dest) && !IsOper(source) && (dest != source)) {
    send_reply(source, ERR_PRIVDEAF, cli_name(dest), (is_notice) ? "CNOTICE" : "CPRIVMSG", cli_name(dest));
    return 0;
  }
          
  if (is_notice)
    sendcmdto_one(source, CMD_NOTICE, dest, "%C :%s", dest, text);
  else
  {
    if (cli_user(dest)->away)
      send_reply(source, RPL_AWAY, cli_name(dest), cli_user(dest)->away);
    sendcmdto_one(source, CMD_PRIVATE, dest, "%C :%s", dest, text);
  }
  return 0;
}


/** Send a user mode change for \a cptr to neighboring servers.
 * @param[in] cptr User whose mode is changing.
 * @param[in] sptr Client who sent us the mode change message.
 * @param[in] old Prior set of user flags.
 * @param[in] prop If non-zero, also include FLAG_OPER.
 */
void send_umode_out(struct Client *cptr, struct Client *sptr,
                    struct Flags *old, int prop)
{
  int i;
  struct Client *acptr;

  send_umode(NULL, sptr, old, prop ? SEND_UMODES : SEND_UMODES_BUT_OPER);

  for (i = HighestFd; i >= 0; i--)
  {
    if ((acptr = LocalClientArray[i]) && IsServer(acptr) &&
        (acptr != cptr) && (acptr != sptr) && *umodeBuf)
      sendcmdto_one(sptr, CMD_MODE, acptr, "%s %s", cli_name(sptr), umodeBuf);
  }
  if (cptr && MyUser(cptr))
    send_umode(cptr, sptr, old, ALL_UMODES);
}


/** Call \a fmt for each Client named in \a names.
 * @param[in] sptr Client requesting information.
 * @param[in] names Space-delimited list of nicknames.
 * @param[in] rpl Base reply string for messages.
 * @param[in] fmt Formatting callback function.
 */
void send_user_info(struct Client* sptr, char* names, int rpl, InfoFormatter fmt)
{
  char*          name;
  char*          p = 0;
  int            arg_count = 0;
  int            users_found = 0;
  struct Client* acptr;
  struct MsgBuf* mb;

  assert(0 != sptr);
  assert(0 != names);
  assert(0 != fmt);

  mb = msgq_make(sptr, rpl_str(rpl), cli_name(&me), cli_name(sptr));

  for (name = ircd_strtok(&p, names, " "); name; name = ircd_strtok(&p, 0, " ")) {
    if ((acptr = FindUser(name))) {
      if (users_found++)
	msgq_append(0, mb, " ");
      (*fmt)(acptr, sptr, mb);
    }
    if (5 == ++arg_count)
      break;
  }
  send_buffer(sptr, mb, 0);
  msgq_clean(mb);
}

/** Set \a flag on \a cptr and possibly hide the client's hostmask.
 * @param[in,out] cptr User who is getting a new flag.
 * @param[in] flag Some flag that affects host-hiding (FLAG_HIDDENHOST, FLAG_ACCOUNT).
 * @return Zero.
 */
int
hide_hostmask(struct Client *cptr)
{
  char newhost[HOSTLEN+1];
  char newuser[USERLEN+1];
  char* sethostat = NULL;
  char* userat = NULL;
  struct Membership *chan;

  newuser[0] = '\0';

  if (!IsHiddenHost(cptr))
    return 0;
  if (!IsFakeHost(cptr) && !IsSetHost(cptr)) {
    if ((feature_int(FEAT_HOST_HIDING_STYLE) < 0) ||
        (feature_int(FEAT_HOST_HIDING_STYLE) > 3))
      return 0;
    if ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) && !IsAccount(cptr))
      return 0;
  }

  if (!IsCloakHost(cptr) && ((feature_int(FEAT_HOST_HIDING_STYLE) == 2) ||
      (feature_int(FEAT_HOST_HIDING_STYLE) == 3)))
    user_setcloaked(cptr);

  /* Invalidate all bans against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan; chan = chan->next_channel) {
    ClearBanValid(chan);
    ClearBanValidNick(chan);
    ClearBanValidQuiet(chan);
    ClearExceptValid(chan);
    ClearExceptValidNick(chan);
    ClearExceptValidQuiet(chan);
  }

  /* Select the new host to change to. */
  if (IsSetHost(cptr)) {
    if ((sethostat = strstr(cli_user(cptr)->sethost, "@")) != NULL) {
      ircd_strncpy(newhost, sethostat+1, HOSTLEN);
      ircd_strncpy(newuser, cli_user(cptr)->sethost, USERLEN);
      if ((userat = strstr(newuser, "@")) != NULL)
        *userat = '\0';
    } else
      ircd_strncpy(newhost, cli_user(cptr)->sethost, HOSTLEN);
  } else if (IsFakeHost(cptr)) {
    ircd_strncpy(newhost, cli_user(cptr)->fakehost, HOSTLEN);
  } else if ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
      ((feature_int(FEAT_HOST_HIDING_STYLE) == 3) && IsAccount(cptr))) {
    if (IsAnOper(cptr) && feature_bool(FEAT_OPERHOST_HIDING))
      ircd_snprintf(0, newhost, HOSTLEN, "%s.%s",
                    cli_user(cptr)->account, feature_str(FEAT_HIDDEN_OPERHOST));
    else
      ircd_snprintf(0, newhost, HOSTLEN, "%s.%s",
                    cli_user(cptr)->account, feature_str(FEAT_HIDDEN_HOST));
  } else if (IsCloakHost(cptr) && ((feature_int(FEAT_HOST_HIDING_STYLE) == 2) ||
             (feature_int(FEAT_HOST_HIDING_STYLE) == 3))) {
    ircd_strncpy(newhost, cli_user(cptr)->cloakhost, HOSTLEN);
  } else {
    ircd_strncpy(newhost, cli_user(cptr)->realhost, HOSTLEN);
  }

  /* If the new host is the same as the current host return silently. */
  if (!ircd_strncmp(cli_user(cptr)->host, newhost, HOSTLEN))
    return 0;

  if (feature_bool(FEAT_HIDDEN_HOST_QUIT))
    sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":%s",
                  feature_str(FEAT_HIDDEN_HOST_SET_MESSAGE));

  /* Finally copy the new host to the users current host. */
  ircd_strncpy(cli_user(cptr)->host, newhost, HOSTLEN);
  if (newuser[0] != '\0')
    ircd_strncpy(cli_user(cptr)->username, newuser, USERLEN);

  /* ok, the client is now fully hidden, so let them know -- hikari */
  if (MyConnect(cptr))
   send_reply(cptr, RPL_HOSTHIDDEN, cli_user(cptr)->host, " hidden");

  if (!feature_bool(FEAT_HIDDEN_HOST_QUIT))
    return 0;

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel)
  {
    if (IsZombie(chan))
      continue;
    /* Send a JOIN unless the user's join has been delayed. */
    if (!IsDelayedJoin(chan)) {
      sendcmdto_channel_capab_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
                                         CAP_NONE, CAP_EXTJOIN, "%H", chan->channel);
      sendcmdto_channel_capab_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
                                         CAP_EXTJOIN, CAP_NONE, "%H %s :%s", chan->channel,
                                         IsAccount(cptr) ? cli_account(cptr) : "*",
                                         cli_info(cptr));
      if (cli_user(cptr)->away)
        sendcmdto_channel_capab_butserv_butone(cptr, CMD_AWAY, chan->channel, NULL, 0,
                                               CAP_AWAYNOTIFY, CAP_NONE, ":%s",
                                               cli_user(cptr)->away);
    }
    if (IsChanOp(chan) && IsHalfOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +ohv %C %C %C", chan->channel, cptr,
                                       cptr, cptr);
    else if (IsChanOp(chan) && IsHalfOp(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +oh %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsChanOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +ov %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsHalfOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +hv %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsChanOp(chan) || IsHalfOp(chan) || HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
        "%H +%c %C", chan->channel, IsChanOp(chan) ? 'o' : (IsHalfOp(chan) ? 'h' : 'v'), cptr);
  }
  return 0;
}

/** Unhide a client's hostmask.
 * @param[in,out] cptr User who is getting a new flag.
 * @param[in] flag Some flag that affects host-hiding (FLAG_HIDDENHOST, FLAG_ACCOUNT).
 * @return Zero.
 */
int
unhide_hostmask(struct Client *cptr)
{
  struct Membership *chan;

  if (IsHiddenHost(cptr))
    return 0;

  /* If the real host is the same as the current host return silently. */
  if (!ircd_strncmp(cli_user(cptr)->host, cli_user(cptr)->realhost, HOSTLEN))
    return 0;

  /* Invalidate all bans against the user so we check them again */
  for (chan = (cli_user(cptr))->channel; chan; chan = chan->next_channel) {
    ClearBanValid(chan);
    ClearBanValidQuiet(chan);
    ClearBanValidNick(chan);
    ClearExceptValid(chan);
    ClearExceptValidQuiet(chan);
    ClearExceptValidNick(chan);
  }

  if (feature_bool(FEAT_HIDDEN_HOST_QUIT))
    sendcmdto_common_channels_butone(cptr, CMD_QUIT, cptr, ":%s",
                  feature_str(FEAT_HIDDEN_HOST_UNSET_MESSAGE));
  ircd_strncpy(cli_user(cptr)->host, cli_user(cptr)->realhost, HOSTLEN);

  /* ok, the client is now fully unhidden, so let them know -- hikari */
  if (MyConnect(cptr))
   send_reply(cptr, RPL_HOSTHIDDEN, cli_user(cptr)->host, "");

  if (!feature_bool(FEAT_HIDDEN_HOST_QUIT))
    return 0;

  /*
   * Go through all channels the client was on, rejoin him
   * and set the modes, if any
   */
  for (chan = cli_user(cptr)->channel; chan; chan = chan->next_channel)
  {
    if (IsZombie(chan))
      continue;
    /* Send a JOIN unless the user's join has been delayed. */
    if (!IsDelayedJoin(chan)) {
      sendcmdto_channel_capab_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
                                         CAP_NONE, CAP_EXTJOIN, "%H", chan->channel);
      sendcmdto_channel_capab_butserv_butone(cptr, CMD_JOIN, chan->channel, cptr, 0,
                                         CAP_EXTJOIN, CAP_NONE, "%H %s :%s", chan->channel,
                                         IsAccount(cptr) ? cli_account(cptr) : "*",
                                         cli_info(cptr));
      if (cli_user(cptr)->away)
        sendcmdto_channel_capab_butserv_butone(cptr, CMD_AWAY, chan->channel, NULL, 0,
                                               CAP_AWAYNOTIFY, CAP_NONE, ":%s",
                                               cli_user(cptr)->away);
    }
    if (IsChanOp(chan) && IsHalfOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +ohv %C %C", chan->channel, cptr,
                                       cptr, cptr);
    else if (IsChanOp(chan) && IsHalfOp(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +oh %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsChanOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +ov %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsHalfOp(chan) && HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
                                       "%H +hv %C %C", chan->channel, cptr,
                                       cptr);
    else if (IsChanOp(chan) || IsHalfOp(chan) || HasVoice(chan))
      sendcmdto_channel_butserv_butone(&his, CMD_MODE, chan->channel, cptr, 0,
        "%H +%c %C", chan->channel, IsChanOp(chan) ? 'o' : (IsHalfOp(chan) ? 'h' : 'v'), cptr);
  }
  return 0;
}

/** Set a user's mode.  This function checks that \a cptr is trying to
 * set his own mode, prevents local users from setting inappropriate
 * modes through this function, and applies any other side effects of
 * a successful mode change.
 *
 * @param[in,out] cptr User setting someone's mode.
 * @param[in] sptr Client who sent the mode change message.
 * @param[in] parc Number of parameters in \a parv.
 * @param[in] parv Parameters to MODE.
 * @param[in] allow_modes ALLOWMODES_ANY for any mode, ALLOWMODES_DEFAULT for 
 *                        only permitting legitimate default user modes.
 * @return Zero.
 */
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc, 
		char *parv[], int allow_modes)
{
  char** p;
  char*  m;
  int what;
  int i;
  struct Flags setflags;
  unsigned int tmpmask = 0;
  int snomask_given = 0;
  char buf[BUFSIZE];
  int prop = 0;
  int do_host_hiding = 0;
  int force = 0;
  int is_svsmode = 0;
  char* account = NULL;
  char* cloakip = NULL;
  char* cloakhost = NULL;
  char* fakehost = NULL;
  char* sethost = NULL;
  struct Client *acptr = NULL;

  if (MyUser(sptr) && (allow_modes & ALLOWMODES_SVSMODE))
    is_svsmode = 1;

  what = MODE_ADD;

  if (parc < 2)
    return need_more_params(sptr, "MODE");

  if (IsServer(cptr))
    acptr = findNUser(parv[1]);

  if (!(parv[1]))
    acptr = sptr;

  if (!acptr && !(acptr = FindUser(parv[1])))
  {
    if (IsServer(cptr) && !MyConnect(sptr)) {
      acptr = sptr;
    } else {
      if (MyConnect(sptr))
        send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
      return 0;
    }
  }

  if (IsServer(sptr) || sptr != acptr)
  {
    if (IsServer(sptr)) {
      if (!MyConnect(acptr)) {
        /* Just propagate and ignore */
        char bufh[BUFSIZE] = "";
        for (i=1;i<parc;i++) {
          strcat(bufh, " ");
          strcat(bufh, parv[i]);
        }
        sendcmdto_serv_butone(sptr, CMD_MODE, cptr, "%s", bufh);
        return 0;
      }
      force = 1;
    }
    else {
      send_reply(sptr, ERR_USERSDONTMATCH);
      return 0;
    }
  }

  if (parc < 3)
  {
    m = buf;
    *m++ = '+';
    for (i = 0; i < USERMODELIST_SIZE; i++)
    {
      if (HasFlag(sptr, userModeList[i].flag) &&
          (userModeList[i].flag != FLAG_ACCOUNT) &&
          (userModeList[i].flag != FLAG_CLOAKIP) &&
          (userModeList[i].flag != FLAG_CLOAKHOST) &&
          (userModeList[i].flag != FLAG_FAKEHOST) &&
          (userModeList[i].flag != FLAG_SETHOST))
        *m++ = userModeList[i].c;
    }
    *m = '\0';
    send_reply(acptr, RPL_UMODEIS, buf);
    if (HasFlag(acptr, FLAG_SERVNOTICE) && MyConnect(acptr)
        && cli_snomask(acptr) !=
        (unsigned int)(IsOper(acptr) ? feature_int(FEAT_SNOMASK_OPERDEFAULT) :
         feature_int(FEAT_SNOMASK_DEFAULT)))
      send_reply(acptr, RPL_SNOMASK, cli_snomask(acptr), cli_snomask(acptr));
    return 0;
  }

  /*
   * find flags already set for user
   * why not just copy them?
   */
  setflags = cli_flags(acptr);

  if (MyConnect(acptr))
    tmpmask = cli_snomask(acptr);

  /*
   * parse mode change string(s)
   */
  for (p = &parv[2]; *p && p<&parv[parc]; p++) {       /* p is changed in loop too */
    for (m = *p; *m; m++) {
      switch (*m) {
      case '+':
        what = MODE_ADD;
        break;
      case '-':
        what = MODE_DEL;
        break;
      case 's':
        if (*(p + 1) && is_snomask(*(p + 1))) {
          snomask_given = 1;
          tmpmask = umode_make_snomask(tmpmask, *++p, what);
          tmpmask &= (IsAnOper(acptr) ? SNO_ALL : SNO_USER);
        }
        else
          tmpmask = (what == MODE_ADD) ?
              (IsAnOper(acptr) ? feature_int(FEAT_SNOMASK_OPERDEFAULT) :
               feature_int(FEAT_SNOMASK_DEFAULT)) : 0;
        if (tmpmask)
	  SetServNotice(acptr);
        else
	  ClearServNotice(acptr);
        break;
      case 'w':
        if (what == MODE_ADD)
          SetWallops(acptr);
        else
          ClearWallops(acptr);
        break;
      case 'o':
        if (what == MODE_ADD)
          SetOper(acptr);
        else {
          ClrFlag(acptr, FLAG_OPER);
          ClrFlag(acptr, FLAG_LOCOP);
          ClrFlag(acptr, FLAG_ADMIN);
          if (MyConnect(acptr))
          {
            tmpmask = cli_snomask(acptr) & ~SNO_OPER;
            if (MyUser(acptr))
              cli_handler(acptr) = CLIENT_HANDLER;
          }
        }
        break;
      case 'O':
        if (what == MODE_ADD)
          SetLocOp(acptr);
        else
        { 
          ClrFlag(acptr, FLAG_OPER);
          ClrFlag(acptr, FLAG_LOCOP);
          if (MyConnect(acptr))
          {
            tmpmask = cli_snomask(acptr) & ~SNO_OPER;
            if (MyUser(acptr))
              cli_handler(acptr) = CLIENT_HANDLER;
          }
        }
        break;
      case 'i':
        if (what == MODE_ADD)
          SetInvisible(acptr);
        else
          ClearInvisible(acptr);
        break;
      case 'd':
        if (what == MODE_ADD)
          SetDeaf(acptr);
        else
          ClearDeaf(acptr);
        break;
      case 'k':
        if (what == MODE_ADD)
          SetChannelService(acptr);
        else
          ClearChannelService(acptr);
        break;
      case 'g':
        if (what == MODE_ADD)
          SetDebug(acptr);
        else
          ClearDebug(acptr);
        break;
      case 'W':
        if (what == MODE_ADD)
          SetWhoisNotice(acptr);
        else
          ClearWhoisNotice(acptr);
        break;
      case 'H':
        if (what == MODE_ADD)
          SetHideOper(acptr);
        else
          ClearHideOper(acptr);
        break;
      case 'I':
        if (what == MODE_ADD)
          SetNoIdle(acptr);
        else
          ClearNoIdle(acptr);
        break;
      case 'n':
        if (what == MODE_ADD)
          SetNoChan(acptr);
        else
          ClearNoChan(acptr);
        break;
      case 'q':
        if (what == MODE_ADD)
          SetCommonChansOnly(acptr);
        else
          ClearCommonChansOnly(acptr);
        break;
      case 'R':
        if (what == MODE_ADD)
          SetAccountOnly(acptr);
        else
          ClearAccountOnly(acptr);
        break;
      case 'B':
        if (what == MODE_ADD)
          SetBot(acptr);
        else
          ClearBot(acptr);
        break;
      case 'D':
        if (what == MODE_ADD)
          SetPrivDeaf(acptr);
        else
          ClearPrivDeaf(acptr);
        break;
      case 'a':
        if (what == MODE_ADD)
          SetAdmin(acptr);
        else
          ClearAdmin(acptr);
        break;
      case 'X':
        if (what == MODE_ADD)
          SetXtraOp(acptr);
        else
          ClearXtraOp(acptr);
        break;
      case 'L':
        if (what == MODE_ADD)
          SetNoLink(acptr);
        else
          ClearNoLink(acptr);
        break;
      case 'x':
        if (what == MODE_ADD) {
          SetHiddenHost(acptr);
        } else {
          if (feature_bool(FEAT_ALLOWRMX) ||
              (feature_int(FEAT_HOST_HIDING_STYLE) == 2) ||
              (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) {
            ClearHiddenHost(acptr);
          }
        }
	break;
      case 'z':
        if (what == MODE_ADD)
          SetSSL(acptr);
        else
          ClearSSL(acptr);
        break;
      case 'r':
	if (*(p + 1) && (what == MODE_ADD)) {
	  account = *(++p);
	  SetAccount(acptr);
	}
	/* There is no -r */
	break;
      case 'C':
        if (*(p + 1) && (what == MODE_ADD)) {
          cloakhost = *(++p);
          SetCloakHost(acptr);
        }
        break;
      case 'c':
        if (*(p + 1) && (what == MODE_ADD)) {
          cloakip = *(++p);
          SetCloakIP(acptr);
        }
        break;
      case 'f':
        if (*(p + 1) && (what == MODE_ADD)) {
          fakehost = *(++p);
          SetFakeHost(acptr);
        }
        break;
      case 'h':
        if (what == MODE_ADD) {
          if (*(p + 1) && (what == MODE_ADD)) {
            sethost = *(++p);
            SetSetHost(acptr);
          }
        } else
          ClearSetHost(acptr);
        break;
      default:
        send_reply(acptr, ERR_UMODEUNKNOWNFLAG, *m);
        break;
      }
    }
  }
  /*
   * Evaluate rules for new user mode
   * Stop users making themselves operators too easily:
   */
  if (!IsServer(cptr) && !is_svsmode)
  {
    if (!FlagHas(&setflags, FLAG_OPER) && IsOper(acptr))
      ClearOper(acptr);
    if (!FlagHas(&setflags, FLAG_LOCOP) && IsLocOp(acptr))
      ClearLocOp(acptr);
    if (!HasPriv(acptr, PRIV_ADMIN) && !FlagHas(&setflags, FLAG_ADMIN) && IsAdmin(acptr))
      ClearAdmin(acptr);
    if (!FlagHas(&setflags, FLAG_ACCOUNT) && IsAccount(acptr))
      ClrFlag(acptr, FLAG_ACCOUNT);
    if (!FlagHas(&setflags, FLAG_CLOAKIP) && IsCloakIP(acptr))
      ClearCloakIP(acptr);
    if (!FlagHas(&setflags, FLAG_CLOAKHOST) && IsCloakHost(acptr))
      ClearCloakHost(acptr);
    if (!FlagHas(&setflags, FLAG_FAKEHOST) && IsFakeHost(acptr))
      ClearFakeHost(acptr);
    if (!FlagHas(&setflags, FLAG_SETHOST) && IsSetHost(acptr))
      ClearSetHost(acptr);
    if (FlagHas(&setflags, FLAG_SETHOST) && !IsSetHost(acptr))
      SetSetHost(acptr);
    if (!FlagHas(&setflags, FLAG_SSL) && IsSSL(acptr))
      ClearSSL(acptr);
    if (FlagHas(&setflags, FLAG_SSL) && !IsSSL(acptr))
      SetSSL(acptr);
    if (IsSetHost(acptr) && (sethost != NULL))
      sethost = NULL;
    /*
     * new umode; servers can set it, local users cannot;
     * prevents users from /kick'ing or /mode -o'ing
     */
    if (!FlagHas(&setflags, FLAG_CHSERV) && IsChannelService(acptr) &&
        !HasPriv(acptr, PRIV_SERVICE))
      ClearChannelService(acptr);
    /*
     * only send wallops to opers
     */
    if (feature_bool(FEAT_WALLOPS_OPER_ONLY) && !IsAnOper(acptr) &&
	SendWallops(acptr))
      ClearWallops(acptr);
    if (feature_bool(FEAT_HIS_SNOTICES_OPER_ONLY) && MyConnect(acptr) &&
        !IsAnOper(acptr) && !FlagHas(&setflags, FLAG_SERVNOTICE))
    {
      ClearServNotice(acptr);
      set_snomask(acptr, 0, SNO_SET);
    }
    if (feature_bool(FEAT_HIS_DEBUG_OPER_ONLY) &&
        !IsAnOper(acptr) && !FlagHas(&setflags, FLAG_DEBUG))
      ClearDebug(acptr);
    if (!(feature_bool(FEAT_OPER_WHOIS_PARANOIA) && HasPriv(acptr, PRIV_WHOIS_NOTICE)) &&
        IsWhoisNotice(acptr))
      ClearWhoisNotice(acptr);
    if (!(feature_bool(FEAT_OPER_HIDE) && HasPriv(acptr, PRIV_HIDE_OPER)) && IsHideOper(acptr))
      ClearHideOper(acptr);
    if (!HasPriv(acptr, PRIV_HIDE_CHANNELS) && IsNoChan(acptr))
      ClearNoChan(acptr);
    if (!HasPriv(acptr, PRIV_HIDE_IDLE) && IsNoIdle(acptr))
      ClearNoIdle(acptr);
    if (!(feature_bool(FEAT_OPER_XTRAOP) && HasPriv(acptr, PRIV_XTRAOP)) && IsXtraOp(acptr))
      ClearXtraOp(acptr);
    if (!FlagHas(&setflags, FLAG_HIDDENHOST) && IsHiddenHost(acptr) &&
        !(feature_bool(FEAT_HOST_HIDING) && (feature_int(FEAT_HOST_HIDING_STYLE) > 0)))
      ClearHiddenHost(acptr);
  }
  if (MyConnect(acptr))
  {
    /* remember propagate privilege setting */
    if (HasPriv(acptr, PRIV_PROPAGATE)) {
      prop = 1;
    }
    if ((FlagHas(&setflags, FLAG_OPER) || FlagHas(&setflags, FLAG_LOCOP)) &&
        !IsAnOper(acptr))
    {
      det_confs_butmask(acptr, CONF_CLIENT & ~CONF_OPERATOR);
      client_set_privs(acptr, NULL);
    }

    if (SendServNotice(acptr))
    {
      if (tmpmask != cli_snomask(acptr))
	set_snomask(acptr, tmpmask, SNO_SET);
      if (cli_snomask(acptr) && snomask_given)
	send_reply(acptr, RPL_SNOMASK, cli_snomask(acptr), cli_snomask(acptr));
    }
    else
      set_snomask(acptr, 0, SNO_SET);
  }
  /*
   * Compare new flags with old flags and send string which
   * will cause servers to update correctly.
   */
  if (!FlagHas(&setflags, FLAG_ACCOUNT) && IsAccount(acptr)) {
      int len = ACCOUNTLEN;
      char *ts;
      if ((ts = strchr(account, ':'))) {
	len = (ts++) - account;
	cli_user(acptr)->acc_create = atoi(ts);
	Debug((DEBUG_DEBUG, "Received timestamped account in user mode; "
	      "account \"%s\", timestamp %Tu", account,
	      cli_user(acptr)->acc_create));
      }
      ircd_strncpy(cli_user(acptr)->account, account, len);
  }

  if (!FlagHas(&setflags, FLAG_CLOAKIP) && IsCloakIP(acptr))
    ircd_strncpy(cli_user(acptr)->cloakip, cloakip, HOSTLEN);
  if (!FlagHas(&setflags, FLAG_CLOAKHOST) && IsCloakHost(acptr))
    ircd_strncpy(cli_user(acptr)->cloakhost, cloakhost, HOSTLEN);
  if (!FlagHas(&setflags, FLAG_FAKEHOST) && IsFakeHost(acptr))
    ircd_strncpy(cli_user(acptr)->fakehost, fakehost, HOSTLEN);
  if (IsSetHost(acptr) && (sethost != NULL)) {
    if (!FlagHas(&setflags, FLAG_SETHOST) ||
        (FlagHas(&setflags, FLAG_SETHOST) &&
         ircd_strncmp(cli_user(acptr)->sethost, sethost, HOSTLEN))) {
      /* Make sure we forward the sethost if its changed */
      FlagClr(&setflags, FLAG_SETHOST);
      ircd_strncpy(cli_user(acptr)->sethost, sethost, HOSTLEN);
      if (IsHiddenHost(acptr))
        do_host_hiding = 1;
    }
  }

  if (IsRegistered(acptr)) {
    if (!FlagHas(&setflags, FLAG_OPER) && IsOper(acptr)) {
      /* user now oper */
      if (!IsHideOper(acptr) && !IsChannelService(acptr) && !IsBot(acptr))
        ++UserStats.opers;
      if (IsHiddenHost(acptr))
        do_host_hiding = 1;
      if (MyUser(acptr))
        cli_handler(acptr) = OPER_HANDLER;
    }
    if (!FlagHas(&setflags, FLAG_LOCOP) && IsLocOp(acptr)) {
      if (IsHiddenHost(acptr))
        do_host_hiding = 1;
      if (MyUser(acptr))
        cli_handler(acptr) = OPER_HANDLER;
    }
    /* remember propagate privilege setting */
    if (HasPriv(acptr, PRIV_PROPAGATE)) {
      prop = 1;
    }
    if (FlagHas(&setflags, FLAG_OPER) && !IsOper(acptr)) {
      /* user no longer oper */
      if (!FlagHas(&setflags, FLAG_HIDE_OPER) && !FlagHas(&setflags, FLAG_CHSERV) && !FlagHas(&setflags, FLAG_BOT)) {
        assert(UserStats.opers > 0);
        --UserStats.opers;
      }
      if (IsHiddenHost(acptr))
        do_host_hiding = 1;
      client_set_privs(acptr, NULL); /* will clear propagate privilege */
      clear_privs(acptr);
      if (MyUser(acptr))
        cli_handler(acptr) = CLIENT_HANDLER;
    }
    if (FlagHas(&setflags, FLAG_LOCOP) && !IsLocOp(acptr)) {
      if (IsHiddenHost(acptr))
        do_host_hiding = 1;
      if (MyUser(acptr))
        cli_handler(acptr) = CLIENT_HANDLER;
    }
    if (!FlagHas(&setflags, FLAG_HIDE_OPER) &&
        !FlagHas(&setflags, FLAG_CHSERV) &&
        !FlagHas(&setflags, FLAG_BOT) &&
        (IsHideOper(acptr) || IsChannelService(acptr) || IsBot(acptr))) {
      if (FlagHas(&setflags, FLAG_OPER) && IsOper(acptr)) {
        --UserStats.opers;
      }
    }
    if ((FlagHas(&setflags, FLAG_HIDE_OPER) ||
         FlagHas(&setflags, FLAG_CHSERV) ||
         FlagHas(&setflags, FLAG_BOT)) &&
        !IsHideOper(acptr) && !IsChannelService(acptr) && !IsBot(acptr)) {
      if (FlagHas(&setflags, FLAG_OPER) && IsOper(acptr)) {
        ++UserStats.opers;
      }
    }
    if (FlagHas(&setflags, FLAG_INVISIBLE) && !IsInvisible(acptr)) {
      assert(UserStats.inv_clients > 0);
      --UserStats.inv_clients;
    }
    if (!FlagHas(&setflags, FLAG_INVISIBLE) && IsInvisible(acptr)) {
      ++UserStats.inv_clients;
    }
    if (FlagHas(&setflags, FLAG_SETHOST) && !IsSetHost(acptr)) {
      FlagClr(&setflags, FLAG_SETHOST); /* Dont let the user see -h */
      if (IsHiddenHost(acptr) && !IsFakeHost(acptr)) {
        if ((feature_int(FEAT_HOST_HIDING_STYLE) == 0) ||
            ((feature_int(FEAT_HOST_HIDING_STYLE) == 1) && !IsAccount(acptr)) ||
            (feature_int(FEAT_HOST_HIDING_STYLE) > 3))
          ClearHiddenHost(acptr);
        else
          do_host_hiding = 1;
      } else
        do_host_hiding = 1;
    }
    if (!FlagHas(&setflags, FLAG_HIDDENHOST) && IsHiddenHost(acptr)) {
      do_host_hiding = 1;
    }

    assert(UserStats.opers <= UserStats.clients + UserStats.unknowns);
    assert(UserStats.inv_clients <= UserStats.clients + UserStats.unknowns);
    send_umode_out(cptr, acptr, &setflags, prop);

    if (force) /* Let the user know */
      send_umode_out(acptr, acptr, &setflags, 1);

    if (FlagHas(&setflags, FLAG_HIDDENHOST) && !IsHiddenHost(acptr)) {
      unhide_hostmask(acptr);
    }
  }

  if (do_host_hiding) {
    if (IsHiddenHost(acptr))
      hide_hostmask(acptr);
  }

  return 0;
}

/** Build a mode string to describe modes for \a cptr.
 * @param[in] cptr Some user.
 * @return Pointer to a static buffer.
 */
char *umode_str(struct Client *cptr)
{
  /* Maximum string size: "owidgrx\0" */
  char *m = umodeBuf;
  int i;
  struct Flags c_flags = cli_flags(cptr);

  if (MyUser(cptr) && !HasPriv(cptr, PRIV_PROPAGATE))
    FlagClr(&c_flags, FLAG_OPER);

  for (i = 0; i < USERMODELIST_SIZE; ++i)
  {
    if (FlagHas(&c_flags, userModeList[i].flag) &&
        userModeList[i].flag >= FLAG_GLOBAL_UMODES)
      *m++ = userModeList[i].c;
  }

  if (IsAccount(cptr))
  {
    char* t = cli_user(cptr)->account;

    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
    m--; /* back up over nul-termination */

    if (cli_user(cptr)->acc_create) {
      char nbuf[20];
      Debug((DEBUG_DEBUG, "Sending timestamped account in user mode for "
	     "account \"%s\"; timestamp %Tu", cli_user(cptr)->account,
	     cli_user(cptr)->acc_create));
      ircd_snprintf(0, t = nbuf, sizeof(nbuf), ":%Tu",
		    cli_user(cptr)->acc_create);
      while ((*m++ = *t++))
	; /* Empty loop */
      m--; /* back up over nul-termination */
    }
  }

  if (IsSetHost(cptr))
  {
    char* t = cli_user(cptr)->sethost;
    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
    m--; /* back up over nul-termination */
  }

  if (IsFakeHost(cptr))
  {
    char* t = cli_user(cptr)->fakehost;
    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
    m--; /* back up over nul-termination */
  }

  if (IsCloakHost(cptr))
  {
    char* t = cli_user(cptr)->cloakhost;
    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
    m--; /* back up over nul-termination */
  }

  if (IsCloakIP(cptr))
  {
    char* t = cli_user(cptr)->cloakip;
    *m++ = ' ';
    while ((*m++ = *t++))
      ; /* Empty loop */
    m--; /* back up over nul-termination */
  }

  *(m) = '\0';

  return umodeBuf;                /* Note: static buffer, gets
                                   overwritten by send_umode() */
}

/** Send a mode change string for \a sptr to \a cptr.
 * @param[in] cptr Destination of mode change message.
 * @param[in] sptr User whose mode has changed.
 * @param[in] old Pre-change set of modes for \a sptr.
 * @param[in] sendset One of ALL_UMODES, SEND_UMODES_BUT_OPER,
 * SEND_UMODES, to select which changed user modes to send.
 */
void send_umode(struct Client *cptr, struct Client *sptr, struct Flags *old,
                int sendset)
{
  int i;
  int flag;
  char *m;
  int what = MODE_NULL;
  int needsethost = 0;

  /*
   * Build a string in umodeBuf to represent the change in the user's
   * mode between the new (cli_flags(sptr)) and 'old', but skipping
   * the modes indicated by sendset.
   */
  m = umodeBuf;
  *m = '\0';
  for (i = 0; i < USERMODELIST_SIZE; ++i)
  {
    flag = userModeList[i].flag;
    if (FlagHas(old, flag)
        == HasFlag(sptr, flag))
      continue;
    switch (sendset)
    {
    case ALL_UMODES:
      break;
    case SEND_UMODES_BUT_OPER:
      if (flag == FLAG_OPER)
        continue;
      /* and fall through */
    case SEND_UMODES:
      if (flag < FLAG_GLOBAL_UMODES)
        continue;
      break;      
    }
    if (cptr && MyUser(cptr)) {
      switch (flag)
      {
        case FLAG_CLOAKHOST:
        case FLAG_CLOAKIP:
        case FLAG_FAKEHOST:
        case FLAG_SETHOST:
          continue;
          break;
      }
    }
    if (FlagHas(old, flag))
    {
      if (what == MODE_DEL)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_DEL;
        *m++ = '-';
        *m++ = userModeList[i].c;
      }
    }
    else /* !FlagHas(old, flag) */
    {
      if (what == MODE_ADD)
        *m++ = userModeList[i].c;
      else
      {
        what = MODE_ADD;
        *m++ = '+';
        *m++ = userModeList[i].c;
      }
      if (flag == FLAG_SETHOST)
        needsethost++;
    }
  }

  if (needsethost)
    ircd_snprintf(0, m, USERLEN + HOSTLEN + 1, " %s", cli_user(sptr)->sethost);
  else
    *m = '\0';
  if (*umodeBuf && cptr)
    sendcmdto_one(sptr, CMD_MODE, cptr, "%s %s", cli_name(sptr), umodeBuf);
}

/**
 * Check to see if this resembles a sno_mask.  It is if 1) there is
 * at least one digit and 2) The first digit occurs before the first
 * alphabetic character.
 * @param[in] word Word to check for sno_mask-ness.
 * @return Non-zero if \a word looks like a server notice mask; zero if not.
 */
int is_snomask(char *word)
{
  if (word)
  {
    if (ircd_strcmp(word, "all") == 0)
      return 1;
    for (; *word; word++)
      if (IsDigit(*word))
        return 1;
      else if (IsAlpha(*word))
        return 0;
  }
  return 0;
}

/** Update snomask \a oldmask according to \a arg and \a what.
 * @param[in] oldmask Original user mask.
 * @param[in] arg Update string (either a number or '+'/'-' followed by a number).
 * @param[in] what MODE_ADD if adding the mask.
 * @return New value of service notice mask.
 */
unsigned int umode_make_snomask(unsigned int oldmask, char *arg, int what)
{
  unsigned int sno_what;
  unsigned int newmask;
  if (what == MODE_ADD)
    if (ircd_strcmp(arg, "all") == 0)
      return SNO_ALL;
  if (*arg == '+')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_ADD;
    else
      sno_what = SNO_DEL;
  }
  else if (*arg == '-')
  {
    arg++;
    if (what == MODE_ADD)
      sno_what = SNO_DEL;
    else
      sno_what = SNO_ADD;
  }
  else
    sno_what = (what == MODE_ADD) ? SNO_SET : SNO_DEL;
  /* pity we don't have strtoul everywhere */
  newmask = (unsigned int)atoi(arg);
  if (sno_what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (sno_what == SNO_ADD)
    newmask |= oldmask;
  return newmask;
}

/** Remove \a cptr from the singly linked list \a list.
 * @param[in] cptr Client to remove from list.
 * @param[in,out] list Pointer to head of list containing \a cptr.
 */
static void delfrom_list(struct Client *cptr, struct SLink **list)
{
  struct SLink* tmp;
  struct SLink* prv = NULL;

  for (tmp = *list; tmp; tmp = tmp->next) {
    if (tmp->value.cptr == cptr) {
      if (prv)
        prv->next = tmp->next;
      else
        *list = tmp->next;
      free_link(tmp);
      break;
    }
    prv = tmp;
  }
}

/** Set \a cptr's server notice mask, according to \a what.
 * @param[in,out] cptr Client whose snomask is updating.
 * @param[in] newmask Base value for new snomask.
 * @param[in] what One of SNO_ADD, SNO_DEL, SNO_SET, to choose operation.
 */
void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  unsigned int oldmask, diffmask;        /* unsigned please */
  int i;
  struct SLink *tmp;

  oldmask = cli_snomask(cptr);

  if (what == SNO_ADD)
    newmask |= oldmask;
  else if (what == SNO_DEL)
    newmask = oldmask & ~newmask;
  else if (what != SNO_SET)        /* absolute set, no math needed */
    sendto_opmask_butone(0, SNO_OLDSNO, "setsnomask called with %d ?!", what);

  newmask &= (IsAnOper(cptr) ? SNO_ALL : SNO_USER);

  diffmask = oldmask ^ newmask;

  for (i = 0; diffmask >> i; i++) {
    if (((diffmask >> i) & 1))
    {
      if (((newmask >> i) & 1))
      {
        tmp = make_link();
        tmp->next = opsarray[i];
        tmp->value.cptr = cptr;
        opsarray[i] = tmp;
      }
      else
        /* not real portable :( */
        delfrom_list(cptr, &opsarray[i]);
    }
  }
  cli_snomask(cptr) = newmask;
}

/** Check whether \a sptr is allowed to send a message to \a acptr.
 * If \a sptr is a remote user, it means some server has an outdated
 * SILENCE list for \a acptr, so send the missing SILENCE mask(s) back
 * in the direction of \a sptr.  Skip the check if \a sptr is a server.
 * @param[in] sptr Client trying to send a message.
 * @param[in] acptr Destination of message.
 * @return Non-zero if \a sptr is SILENCEd by \a acptr, zero if not.
 */
int is_silenced(struct Client *sptr, struct Client *acptr, int ischanmsg)
{
  struct Ban *found;
  struct User *user;
  size_t buf_used, slen;
  char buf[BUFSIZE];

  if (ischanmsg && !feature_bool(FEAT_SILENCE_CHANMSGS))
    return 0;

  if (IsServer(sptr) || IsMe(sptr) || !(user = cli_user(acptr))
      || !(found = find_ban(sptr, user->silence, EBAN_NONE, 0)))
    return 0;
  assert(!(found->flags & BAN_EXCEPTION));

  if (ischanmsg && feature_bool(FEAT_SILENCE_CHANMSGS))
    return 1;

  if (!MyConnect(sptr)) {
    /* Buffer positive silence to send back. */
    buf_used = strlen(found->banstr);
    memcpy(buf, found->banstr, buf_used);
    /* Add exceptions to buffer. */
    for (found = user->silence; found; found = found->next) {
      if (!(found->flags & BAN_EXCEPTION))
        continue;
      slen = strlen(found->banstr);
      if (buf_used + slen + 4 > 400) {
        buf[buf_used] = '\0';
        sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr, buf);
        buf_used = 0;
      }
      if (buf_used)
        buf[buf_used++] = ',';
      buf[buf_used++] = '+';
      buf[buf_used++] = '~';
      memcpy(buf + buf_used, found->banstr, slen);
      buf_used += slen;
    }
    /* Flush silence buffer. */
    if (buf_used) {
      buf[buf_used] = '\0';
      sendcmdto_one(acptr, CMD_SILENCE, cli_from(sptr), "%C %s", sptr, buf);
      buf_used = 0;
    }
  }
  return 1;
}

/** Set a users cloaked host and IP
 * @param[in/out] cptr Client to set cloaked host and IP for.
 */
void
user_setcloaked(struct Client *cptr)
{
  int components = 0;

  if ((feature_int(FEAT_HOST_HIDING_STYLE) != 2) &&
      (feature_int(FEAT_HOST_HIDING_STYLE) != 3))
    return;

  components = client_get_hidehostcomponents(cptr);

  if (!IsCloakIP(cptr)) {
    if (irc_in_addr_is_ipv4(&(cli_ip(cptr))))
      ircd_snprintf(0, cli_user(cptr)->cloakip, HOSTLEN+1, hidehost_ipv4(&(cli_ip(cptr))));
    else
      ircd_snprintf(0, cli_user(cptr)->cloakip, HOSTLEN+1, hidehost_ipv6(&(cli_ip(cptr))));
    SetCloakIP(cptr);
  }

  if (!IsCloakHost(cptr)) {
    if (!ircd_strncmp(cli_sock_ip(cptr), cli_user(cptr)->host, HOSTLEN+1))
      ircd_snprintf(0, cli_user(cptr)->cloakhost, HOSTLEN+1, cli_user(cptr)->cloakip);
    else
      ircd_snprintf(0, cli_user(cptr)->cloakhost, HOSTLEN+1,
                    hidehost_normalhost(cli_user(cptr)->realhost, components));
    SetCloakHost(cptr);
  }
}

/** Describes one element of the ISUPPORT list. */
struct ISupport {
    const char *is_name; /**< Name of supported feature. */
    enum {
        OPT_NONE,
        OPT_INT,
        OPT_STRING
    } is_type; /**< Type of the feature's value. */
    union {
        int iv;
        char *sv;
    } is_value; /**< Feature's value. */
    struct ISupport *is_next; /**< Pointer to next feature. */
};

static struct ISupport *isupport; /**< List of supported ISUPPORT features. */
static struct SLink *isupport_lines; /**< List of formatted ISUPPORT lines. */

/** Mark #isupport_lines as dirty and needing a rebuild. */
static void
touch_isupport()
{
  while (isupport_lines) {
    struct SLink *link = isupport_lines;
    isupport_lines = link->next;
    MyFree(link->value.cp);
    free_link(link);
  }
}

/** Get (or create) an ISupport element from #isupport with the
 * specified name and OPT_NONE type.
 * @param[in] name Name of ISUPPORT feature to describe.
 * @return Pre-existing or newly allocated ISupport structure.
 */
static struct ISupport *
get_clean_isupport(const char *name)
{
  struct ISupport *isv, *prev;

  for (isv = isupport, prev = 0; isv; prev = isv, isv = isv->is_next) {
    if (strcmp(isv->is_name, name))
      continue;
    if (isv->is_type == OPT_STRING)
      MyFree(isv->is_value.sv);
    break;
  }

  if (!isv) {
    isv = MyMalloc(sizeof(*isv));
    if (prev)
        prev->is_next = isv;
    else
        isupport = isv;
    isv->is_next = NULL;
  }

  isv->is_name = name;
  isv->is_type = OPT_NONE;
  touch_isupport();
  return isv;
}

/** Declare support for a feature with no parameter.
 * @param[in] name Name of ISUPPORT feature to announce.
 */
static
void add_isupport(const char *name)
{
  get_clean_isupport(name);
}

/** Declare support for a feature with an integer parameter.
 * @param[in] name Name of ISUPPORT feature to announce.
 * @param[in] value Value associated with the feature.
 */
void add_isupport_i(const char *name, int value)
{
  struct ISupport *isv = get_clean_isupport(name);
  isv->is_type = OPT_INT;
  isv->is_value.iv = value;
}

/** Declare support for a feature with a string parameter.
 * @param[in] name Name of ISUPPORT feature to announce.
 * @param[in] value Value associated with the feature.
 */
void add_isupport_s(const char *name, const char *value)
{
  struct ISupport *isv = get_clean_isupport(name);
  isv->is_type = OPT_STRING;
  DupString(isv->is_value.sv, value);
}

/** Stop announcing support for a feature.
 * @param[in] name Name of ISUPPORT feature to revoke.
 */
void del_isupport(const char *name)
{
  struct ISupport *isv, *prev;

  for (isv = isupport, prev = 0; isv; prev = isv, isv = isv->is_next) {
    if (strcmp(isv->is_name, name))
      continue;
    if (isv->is_type == OPT_STRING)
      MyFree(isv->is_value.sv);
    if (prev)
      prev->is_next = isv->is_next;
    else
      isupport = isv->is_next;
    break;
  }
  touch_isupport();
}

/** Populate #isupport_lines from #isupport. */
static void
build_isupport_lines()
{
  struct ISupport *is;
  struct SLink **plink;
  char buf[BUFSIZE];
  int used, len, usable, item = 0;

  /* Extra buffer space for :me.name 005 ClientNick <etc> */
  assert(isupport_lines == 0);
  usable = BUFSIZE - 10
      - strlen(cli_name(&me))
      - strlen(get_error_numeric(RPL_ISUPPORT)->format)
      - feature_int(FEAT_NICKLEN);
  plink = &isupport_lines;
  used = 0;

  /* For each ISUPPORT feature, */
  for (is = isupport; is; ) {
    /* Try to append it to the buffer. */
    switch (is->is_type) {
    case OPT_NONE:
      len = ircd_snprintf(NULL, buf + used, usable - used,
                          " %s", is->is_name);
      break;
    case OPT_INT:
      len = ircd_snprintf(NULL, buf + used, usable - used,
                          " %s=%d", is->is_name, is->is_value.iv);
      break;
    case OPT_STRING:
      len = ircd_snprintf(NULL, buf + used, usable - used,
                          " %s=%s", is->is_name, is->is_value.sv);
      break;
    default:
      assert(0 && "Unhandled ISUPPORT option type");
      len = 0;
      break;
    }

    item++;
    is = is->is_next;

    if (item < 13) {
      used += len;
    } else {
      assert(used > 0);
      *plink = make_link();
      DupString((*plink)->value.cp, buf + 1);
      (*plink)->next = 0;
      plink = &(*plink)->next;
      used = 0;
      item = 0;
    }
  }

  if (used > 0) {
    /* Terminate buffer and flush last bit of it out. */
    buf[used] = '\0';
    *plink = make_link();
    DupString((*plink)->value.cp, buf + 1);
    (*plink)->next = 0;
  }
}

/** Announce fixed-parameter and parameter-free ISUPPORT features
 * provided by ircu's core code.
 */
void init_isupport(void)
{
  char imaxlist[BUFSIZE] = "";
  char cmodebuf[BUFSIZE] = "";
  char extbanbuf[BUFSIZE] = "";

  strcat(imaxlist, "b:");
  strcat(imaxlist, itoa(feature_int(FEAT_MAXBANS)));
  if (feature_bool(FEAT_EXCEPTS)) {
    strcat(imaxlist, ",e:");
    strcat(imaxlist, itoa(feature_int(FEAT_MAXEXCEPTS)));
  }

  ircd_snprintf(0, cmodebuf, BUFSIZE, "b%s,%sk%s,Ll,aCcDdiMmNnOpQRrSsTtZz",
                feature_bool(FEAT_EXCEPTS) ? "e" : "",
                feature_bool(FEAT_OPLEVELS) ? "A" : "",
                feature_bool(FEAT_OPLEVELS) ? "U" : "");

  add_isupport("WHOX");
  add_isupport("WALLCHOPS");
  add_isupport("WALLHOPS");
  add_isupport("WALLVOICES");
  add_isupport("USERIP");
  add_isupport("CPRIVMSG");
  add_isupport("CNOTICE");
  add_isupport("NAMESX");
  add_isupport("UHNAMES");

  add_isupport_i("SILENCE", feature_int(FEAT_MAXSILES));
  add_isupport_i("WATCH", feature_int(FEAT_MAXWATCHS));
  add_isupport_i("MODES", MAXMODEPARAMS);
  add_isupport_i("MAXCHANNELS", feature_int(FEAT_MAXCHANNELSPERUSER));
  add_isupport_i("MAXBANS", feature_int(FEAT_MAXBANS));
  add_isupport_i("NICKLEN", feature_int(FEAT_NICKLEN));
  add_isupport_i("MAXNICKLEN", NICKLEN);
  add_isupport_i("TOPICLEN", TOPICLEN);
  add_isupport_i("AWAYLEN", AWAYLEN);
  add_isupport_i("KICKLEN", TOPICLEN);
  add_isupport_i("CHANNELLEN", feature_int(FEAT_CHANNELLEN));
  add_isupport_i("MAXCHANNELLEN", CHANNELLEN);
  add_isupport_s("CHANTYPES", feature_bool(FEAT_LOCAL_CHANNELS) ? "#&" : "#");
  add_isupport_s("PREFIX", feature_bool(FEAT_HALFOPS) ? "(ohv)@%+" : "(ov)@+");
  add_isupport_s("STATUSMSG", feature_bool(FEAT_HALFOPS) ? "@%+" : "@+");

  add_isupport_s("CHANMODES", cmodebuf);

  if (feature_bool(FEAT_EXCEPTS)) {
    add_isupport_s("EXCEPTS", "e");
    add_isupport_i("MAXEXCEPTS", feature_int(FEAT_MAXEXCEPTS));
  }

  if (feature_bool(FEAT_EXTBANS)) {
    strcat(extbanbuf, "~,");

    if (feature_bool(FEAT_EXTBAN_a))
      strcat(extbanbuf, "a");
    if (feature_bool(FEAT_EXTBAN_c))
      strcat(extbanbuf, "c");
    if (feature_bool(FEAT_EXTBAN_j))
      strcat(extbanbuf, "j");
    if (feature_bool(FEAT_EXTBAN_n))
      strcat(extbanbuf, "n");
    if (feature_bool(FEAT_EXTBAN_q))
      strcat(extbanbuf, "q");
    if (feature_bool(FEAT_EXTBAN_r))
      strcat(extbanbuf, "r");

    add_isupport_s("EXTBANS", extbanbuf);
  }

  add_isupport_s("CASEMAPPING", "rfc1459");
  add_isupport_s("NETWORK", feature_str(FEAT_NETWORK));
  add_isupport_s("MAXLIST", imaxlist);
  add_isupport_s("ELIST", "CT");
}

/** Send RPL_ISUPPORT lines to \a cptr.
 * @param[in] cptr Client to send ISUPPORT to.
 * @return Zero.
 */
int
send_supported(struct Client *cptr)
{
  struct SLink *line;

  if (isupport && !isupport_lines)
    build_isupport_lines();

  for (line = isupport_lines; line; line = line->next)
    send_reply(cptr, RPL_ISUPPORT, line->value.cp);

  return 0; /* convenience return, if it's ever needed */
}

/* vim: shiftwidth=2 
 */ 
