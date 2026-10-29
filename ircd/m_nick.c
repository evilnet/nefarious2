/*
 * IRC - Internet Relay Chat, ircd/m_nick.c
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
 * $Id: m_nick.c 1729 2006-11-04 21:42:00Z entrope $
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

#include "IPcheck.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "account_id.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "s_auth.h"
#include "bouncer_session.h"
#include "bouncer_converge.h"
#include "bouncer_rebind_auth.h"
#include "shun.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

 /*
* 'do_nick_name' ensures that the given parameter (nick) is really a proper
* string for a nickname (note, the 'nick' may be modified in the process...)
*
* RETURNS the length of the final NICKNAME (0, if nickname is invalid)
*
* Nickname characters are in range 'A'..'}', '_', '-', '0'..'9'
*  anything outside the above set will terminate nickname.
* In addition, the first character cannot be '-' or a Digit.
*
* Note:
*  The '~'-character should be allowed, but a change should be global,
*  some confusion would result if only few servers allowed it...
*/
int do_nick_name(char* nick)
{
  char* ch  = nick;
  char* end = ch + NICKLEN;
  assert(0 != ch);
  
  /* first character in [0..9-] */
  if (*ch == '-' || IsDigit(*ch))
    return 0;
  for ( ; (ch < end) && *ch; ++ch)
    if (!IsNickChar(*ch))
      break;

  *ch = '\0';

  return (ch - nick);
}

/*
 * m_nick - message handler for local clients
 * parv[0] = sender prefix
 * parv[1] = nickname
 */
int m_nick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  char           nick[NICKLEN + 2];
  char*          arg;
  char*          s;
  char           ts_buf[20];
  char*          rewrite_parv[3];

  assert(0 != cptr);
  assert(cptr == sptr);

  if (IsServerPort(cptr))
    return exit_client(cptr, cptr, &me, "Use a different port");

  if (*(cli_name(sptr)))
    if ((*parv[0] != '\0') && shun_lookup(sptr, 0))
      return 0;

  if (parc < 2) {
    send_reply(sptr, ERR_NONICKNAMEGIVEN);
    return 0;
  }

  /*
   * Don't let them send make us send back a really long string of
   * garbage
   */
  arg = parv[1];
  if (strlen(arg) > IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN)))
    arg[IRCD_MIN(NICKLEN, feature_int(FEAT_NICKLEN))] = '\0';

  if ((s = strchr(arg, '~')))
    *s = '\0';

  strcpy(nick, arg);

  /*
   * If do_nick_name() returns a null name then reject it.
   */
  if (0 == do_nick_name(nick)) {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, arg);
    return 0;
  }

  /* 
   * Check if this is a LOCAL user trying to use a reserved (Juped)
   * nick, if so tell him that it's a nick in use...
   */
  if (isNickJuped(nick)) {
    send_reply(sptr, ERR_NICKNAMEINUSE, nick);
    return 0;                        /* NICK message ignored */
  }

  if (!EmptyString(feature_str(FEAT_CTCP_VERSIONING_NICK))) {
    if (!ircd_strcmp(nick, feature_str(FEAT_CTCP_VERSIONING_NICK))) {
      send_reply(sptr, ERR_NICKNAMEINUSE, nick);
      return 0;
    }
  }

  /* Alias /nick — rewrite to primary so the rename hits the user's
   * canonical identity. Aliases mirror the primary; their nick must
   * follow the primary's, not diverge. set_nick_name then renames
   * primary on this server, broadcasts NICK from primary source, and
   * BX N (when sptr is local-MyUser) syncs aliases on other servers.
   * Local aliases on this server are renamed in set_nick_name's
   * local-alias rename pass.
   *
   * S2S routing: toward the primary's home server we must source the
   * NICK from the alias's numeric (so the home server processes the
   * rename request via standard alias→primary rewrite); away from the
   * primary we source from the primary's numeric (peers see the
   * canonical rename).  sendcmdto_set_alias_source() arms the upcoming
   * sendcmdto_serv_butone in set_nick_name to do the split delivery. */
  if (IsBouncerAlias(sptr) && cli_alias_primary(sptr)) {
    struct Client *alias_source = sptr;
    sptr = cli_alias_primary(sptr);
    /* Synthesize parv[2] timestamp so set_nick_name's
     * cli_lastnick(sptr) = (sptr == cptr) ? TStime() : atoi(parv[2])
     * path produces a sane lastnick when sptr is the (possibly remote)
     * primary rather than the original cptr. */
    ircd_snprintf(0, ts_buf, sizeof(ts_buf), "%Tu", TStime());
    rewrite_parv[0] = parv[0];
    rewrite_parv[1] = parv[1];
    rewrite_parv[2] = ts_buf;
    parv = rewrite_parv;
    parc = 3;
    sendcmdto_set_alias_source(alias_source);
  }

  if (!(acptr = SeekClient(nick))) {
    /*
     * No collisions, all clear...
     */
    return set_nick_name(cptr, sptr, nick, parc, parv, 0);
  }
  if (IsServer(acptr)) {
    /* Reply to cptr (the local connection) — sptr may have been
     * rewritten to a remote primary in the alias path above. */
    send_reply(cptr, ERR_NICKNAMEINUSE, nick);
    return 0;                        /* NICK message ignored */
  }
  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr) {
    /*
     * If acptr == sptr, then we have a client doing a nick
     * change between *equivalent* nicknames as far as server
     * is concerned (user is changing the case of his/her
     * nickname or somesuch)
     */
    if (0 != strcmp(cli_name(acptr), nick)) {
      /*
       * Allows change of case in his/her nick
       */
      return set_nick_name(cptr, sptr, nick, parc, parv, 0);
    }
    /*
     * This is just ':old NICK old' type thing.
     * Just forget the whole thing here. There is
     * no point forwarding it to anywhere,
     * especially since servers prior to this
     * version would treat it as nick collision.
     */
    return 0;
  }
  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  assert(acptr != sptr);
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   *
   * XXX - hmmm can this happen after one is registered?
   *
   * Yes, client 1 connects to IRC and registers, client 2 connects and
   * sends "NICK foo" but doesn't send anything more.  client 1 now does
   * /nick foo, they should succeed and client 2 gets disconnected with
   * the message below.
   */
  if (IsUnknown(acptr) && MyConnect(acptr)) {
    /* Mid-SASL bouncer-class client?  Defer rather than kill:
     * after SASL completes, if accounts match the new owner of the
     * nick, the bouncer alias path takes over.  Otherwise late 433. */
    if (cli_auth(acptr) && bounce_enabled_for(acptr)) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Bouncer: deferring mid-auth %C on local NICK "
                           "%s collision (awaiting SASL)",
                           acptr, nick);
      auth_defer_nick(cli_auth(acptr), nick);
      if (cli_name(acptr)[0]) {
        hRemClient(acptr);
        cli_name(acptr)[0] = '\0';
      }
      return set_nick_name(cptr, sptr, nick, parc, parv, 0);
    }
    /* A login whose registration the bouncer deferred (its auth is done,
     * it waits for the drain): not a dormant nick to override.  The local
     * NICK is refused (W3 12c-2b fix round 3, I-4). */
    if (bounce_is_pending_registration(acptr)) {
      log_write(LS_USER, L_INFO, 0,
                "Bouncer: a local NICK %s onto a deferred login's nick is "
                "refused (433); the login keeps it", nick);
      return send_reply(cptr, ERR_NICKNAMEINUSE, nick);
    }
    ServerStats->is_ref++;
    if (!find_except_conf(acptr, EFLAG_IPCHECK))
      IPcheck_connect_fail(acptr, 0);
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv, 0);
  }
  /* Defer collision with bouncer ghost or live bouncer session user.
   * After SASL, if accounts match, the bounce system handles it
   * (ghost revive or alias creation). Otherwise send late 433.
   * For remote ghosts, IsBouncerHold and bounce_get_session won't
   * match (flag isn't propagated via P10, hs_client is NULL on
   * replicas), so also check by account for any bouncer session. */
  if (!IsRegistered(sptr) && cli_auth(sptr)
      && (IsBouncerHold(acptr) || bounce_get_session(acptr)
          || (IsAccount(acptr) && bounce_has_sessions(cli_account(acptr))))) {
    return auth_defer_nick(cli_auth(sptr), nick);
  }
  /*
   * NICK is coming from local client connection. Just
   * send error reply and ignore the command.  Reply to cptr — sptr
   * may have been rewritten to a remote primary above.
   */
  send_reply(cptr, ERR_NICKNAMEINUSE, nick);
  return 0;                        /* NICK message ignored */
}


/*
 * ms_nick - server message handler for nicks
 * parv[0] = sender prefix
 * parv[1] = nickname
 *
 * If from server, source is client:
 *   parv[2] = timestamp
 *
 * Source is server:
 *   parv[2] = hopcount
 *   parv[3] = timestamp
 *   parv[4] = username
 *   parv[5] = hostname
 *   parv[6] = umode (optional)
 *   parv[parc-3] = IP#                 <- Only Protocol >= 10
 *   parv[parc-2] = YXX, numeric nick   <- Only Protocol >= 10
 *   parv[parc-1] = info
 *   parv[0] = server
 */
int ms_nick(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *acptr;
  char nick[NICKLEN + 2];
  time_t lastnick = 0;
  int differ = 1;
  const char *type;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(IsServer(cptr));

  if ((IsServer(sptr) && parc < 8) || parc < 3)
  {
    sendto_opmask_butone(0, SNO_OLDSNO, "bad NICK param count for %s from %C",
			 parv[1], cptr);
    return need_more_params(sptr, "NICK");
  }

  if (IsServer(sptr))
  {
    struct irc_in_addr ip;

    /* SetRemoteNumNick() and findNUser() index client_list[] from the
     * numnick, and the collision paths below decode the IP into a stack
     * irc_in_addr: refuse a malformed one before anything uses it. */
    if (!ValidUserNumNick(parv[parc - 2]))
      return protocol_violation(cptr, "Malformed numnick %s for %s",
                                parv[parc - 2], parv[1]);
    if (base64toip(parv[parc - 3], &ip))
    {
      protocol_violation(cptr, "Malformed IP %s for %s (%s)",
                         parv[parc - 3], parv[1], parv[parc - 2]);
      ++ServerStats->is_kill;
      sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (Malformed IP)",
                    parv[parc - 2], cli_name(&me));
      return 0;
    }
  }

  ircd_strncpy(nick, parv[1], NICKLEN + 1);
  nick[NICKLEN] = '\0';

  if (IsServer(sptr))
  {
    lastnick = atoi(parv[3]);
    if (lastnick > OLDEST_TS && !IsBurstOrBurstAck(sptr))
      cli_serv(sptr)->lag = TStime() - lastnick;
  }
  else
  {
    lastnick = atoi(parv[2]);
    if (lastnick > OLDEST_TS && !IsBurstOrBurstAck(sptr))
      cli_serv(cli_user(sptr)->server)->lag = TStime() - lastnick;
  }

  /* Alias-source NICK relay — rewrite to primary so receivers process
   * the rename as the user's canonical identity, not as the alias
   * diverging from primary. set_nick_name then renames primary on this
   * server (it may be local or remote, both paths handle correctly),
   * broadcasts NICK + (when primary is local-MyUser) BX N for sibling
   * alias sync. Local aliases are renamed in set_nick_name's local-alias
   * pass. */
  if (!IsServer(sptr) && IsBouncerAlias(sptr) && cli_alias_primary(sptr))
    sptr = cli_alias_primary(sptr);

  /*
   * If do_nick_name() returns a null name OR if the server sent a nick
   * name and do_nick_name() changed it in some way (due to rules of nick
   * creation) then reject it. If from a server and we reject it,
   * and KILL it. -avalon 4/4/92
   */
  if (!do_nick_name(nick) || strcmp(nick, parv[1]))
  {
    send_reply(sptr, ERR_ERRONEUSNICKNAME, parv[1]);
    
    ++ServerStats->is_kill;
    sendto_opmask_butone(0, SNO_OLDSNO, "Bad Nick: %s From: %s %C", parv[1],
			 parv[0], cptr);
    sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (%s <- %s[%s])",
		  IsServer(sptr) ? parv[parc - 2] : parv[0], cli_name(&me), parv[1],
		  nick, cli_name(cptr));
    if (!IsServer(sptr))
    {
      /*
       * bad nick _change_
       */
      sendcmdto_serv_butone(&me, CMD_KILL, 0, "%s :%s (%s <- %s!%s@%s)",
			    parv[0], cli_name(&me), cli_name(cptr), parv[0],
			    cli_user(sptr) ? cli_username(sptr) : "",
			    cli_user(sptr) ? cli_name(cli_user(sptr)->server) :
			    cli_name(cptr));
    }
    return 0;
  }
  /* The hold mark an introduction carries (,H) and whether the path from
   * its home server can be trusted to carry one; a same-nick meeting of
   * one account below decides on it. */
  if (IsServer(sptr) && sendcmdto_stash_is_current(cptr) && cli_s2s_held(cptr))
    Debug((DEBUG_INFO, "N %s (%s) from %s: hold mark %c, %s", nick,
           parv[parc - 2], cli_name(sptr), cli_s2s_held(cptr),
           bounce_hold_marks_trusted(sptr) ? "trusted" : "untrusted"));

  /* Check against nick name collisions. */
  if ((acptr = SeekClient(nick)) == NULL)
    /* No collisions, all clear... */
    return set_nick_name(cptr, sptr, nick, parc, parv, 0);

  /*
   * If acptr == sptr, then we have a client doing a nick
   * change between *equivalent* nicknames as far as server
   * is concerned (user is changing the case of his/her
   * nickname or somesuch)
   */
  if (acptr == sptr)
  {
    if (strcmp(cli_name(acptr), nick) != 0)
      /* Allows change of case in his/her nick */
      return set_nick_name(cptr, sptr, nick, parc, parv, 0);
    else
      /* Setting their nick to what it already is? Ignore it. */
      return 0;
  }
  /* now we know we have a real collision. */
  /*
   * Note: From this point forward it can be assumed that
   * acptr != sptr (point to different client structures).
   */
  assert(acptr != sptr);
  /*
   * Bouncer ghost-vs-primary revive.
   *
   * If acptr is a held bouncer ghost on this server and the incoming N
   * is from a server introducing the same logical user (account match),
   * rebind the ghost in place to represent the hub-introduced primary.
   * Standard collision logic would kill both because they share
   * user@host — they aren't independent clients, they're one user in
   * two representational states.
   */
  /* Extract account from incoming N (parv[6] umode flags + arg list).
   * Used by both the BouncerHold-ghost rebind and the live-primary
   * split-merge blocks below.  Empty if the incoming N has no +r. */
  const char *incoming_acct = NULL;
  char incoming_acct_buf[ACCOUNTLEN + 1];
  time_t incoming_acc_ts = 0;
  char incoming_kc_id[ACCOUNT_ID_LEN + 1] = "";
  if (IsServer(sptr) && parc > 7 && parv[6] && *parv[6] == '+') {
    /* Walk parv[6] flag string, counting arg-taking flags before 'r'.
     * Argument order in N matches umode_str() output order: r, h, f, C, c.
     * Args occupy parv[7..parc-4]; parv[parc-3..parc-1] are ip/numeric/info. */
    const char *m;
    int argi = 7;
    for (m = parv[6] + 1; *m; m++) {
      if (*m == 'r' || *m == 'h' || *m == 'f' || *m == 'C' || *m == 'c') {
        if (argi >= parc - 3)
          break;
        if (*m == 'r') {
          const char *a = parv[argi];
          const char *colon = strchr(a, ':');
          size_t alen = colon ? (size_t)(colon - a) : strlen(a);
          if (alen > ACCOUNTLEN)
            alen = ACCOUNTLEN;
          memcpy(incoming_acct_buf, a, alen);
          incoming_acct_buf[alen] = '\0';
          incoming_acct = incoming_acct_buf;
          /* +r value is "account[:ts]"; capture the TS for the bouncer
           * rebind gate's refusal log (it no longer authorizes; only the
           * session id does). */
          if (colon) {
            const char *idp = strchr(colon + 1, ':');
            incoming_acc_ts = (time_t)strtoll(colon + 1, NULL, 10);
            /* "account:ts:id": the Keycloak id vetoes a rebind of a
             * ghost that carries a different one. */
            if (idp && account_id_valid(idp + 1))
              ircd_strncpy(incoming_kc_id, idp + 1, sizeof(incoming_kc_id));
          }
          break;
        }
        argi++;
      }
    }
  }

  /* The incoming client's side of a meeting of two clients of one
   * account: its hold mark (,H) and session id (,S), read only from the
   * line being handled, and the mark's state only when every server from
   * its home to us announces SERVER flag H (bounce_hold_marks_trusted;
   * else the state is unknown, as before the mark existed). */
  struct bounce_nick_side theirs;
  memset(&theirs, 0, sizeof theirs);
  if (IsServer(sptr) && incoming_acct) {
    int stash = sendcmdto_stash_is_current(cptr);
    bounce_nick_side_from_mark(&theirs, bounce_hold_marks_trusted(sptr),
                               stash ? cli_s2s_held(cptr) : 0);
    theirs.lastnick = lastnick;
    theirs.sessid   = stash ? cli_s2s_sessid(cptr) : NULL;
    theirs.numeric  = parv[parc - 2];
  }

  /* Bouncer ghost rebind: incoming primary takes the place of our
   * held ghost (no kill, no normal N-forward -- this N resolves
   * locally instead of being relayed onward).  A legacy link that
   * may know the ghost's face still hears about it, with one BX P
   * each (bounce_legacy_face_change, inside the rebind).  Only when
   * acptr is a BouncerHold ghost on this server, and only when the
   * incoming client's state is unknown: a known state is decided by the
   * verdict below, which both servers compute (a held or outside
   * incoming client never takes our ghost's place, and one of our
   * session takes it only as the verdict's drop).  See bouncer/m_nick.c
   * history. */
  if (IsServer(sptr) && IsBouncerHold(acptr) && parc > 7
      && cli_user(acptr) && cli_user(acptr)->account[0]
      && incoming_acct && !theirs.state_known
      && 0 == ircd_strcmp(incoming_acct, cli_user(acptr)->account)) {
    struct irc_in_addr ip;
    int rebind_rc;
    base64toip(parv[parc - 3], &ip);
    rebind_rc = bounce_rebind_ghost_to_remote_primary(acptr, sptr,
                                                      parv[parc - 2],
                                                      lastnick, parv[4],
                                                      parv[5], &ip,
                                                      parv[parc - 1],
                                                      incoming_acc_ts,
                                                      incoming_kc_id);
    if (rebind_rc == 0) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Bouncer rebind: %C ghost rebound to %s on %C "
                           "(account %s)", acptr, parv[parc - 2], cptr,
                           incoming_acct);
      return 0;
    }
    /* rebind_rc == -1: not a rebind case, fall through.  (rc == -3
     * was the BX R-winner short-circuit, retired in Phase 5.) */
  }

  /* Same-nick convergence of two clients of one account (redesign D.1,
   * D.2): a client of ours -- live, or a held ghost -- and the one an
   * IRCv3-aware peer introduces.  Both servers see the same pair of N
   * lines and compute bounce_nick_verdict (bouncer_converge.h) from the
   * same facts, so one keeps exactly when the other yields; the
   * post-burst reconcile uses the same verdict.  No coordination
   * protocol.  Only a client of ours is decided here: a remote acptr is
   * its own server's to decide.
   *
   * Our side is the snapshot our own N to this link carried (its hold
   * mark), while the link's burst lasts: the peer decides from that, so
   * we do too, even if our client changed since (a socket that died, an
   * alias that left).  Otherwise our client as it is now.  The incoming
   * side is its mark (unknown without one).  Then the action is mapped
   * onto our client as it is now (bounce_nick_action): it never ends a
   * live device and never demotes a client with no socket.
   *
   *  - keep: the incoming N is refused silently; the peer yields.
   *  - retire: our held session ends -- its ghost leaves with a Q toward
   *    the legacy links (BX X toward the aware ones) -- before the
   *    incoming N is accepted and relayed (to the legacy links too).
   *  - drop: our session's ghost becomes the incoming client of the same
   *    session, its Client reused (no QUIT, no JOIN; one BX P per legacy
   *    link): its live primary (the session goes active) or its held
   *    ghost there (our record becomes a held replica).
   *  - demote: our live primary becomes the incoming one's alias (the
   *    merge below); our held ghost, which has no socket to keep, yields
   *    instead: it leaves, and its session's live connections follow the
   *    incoming primary under its session id.
   *  - classic: the collision rules below.
   *
   * Legacy peer gate: the symmetric contract only holds if the
   * introducing peer also runs this.  Against a legacy peer (no `v`
   * SERVER flag) our "we win" would refuse silently while the peer has
   * no equivalent code -- so skip it and let the classic rules decide
   * (TS-based, both sides KILL the loser).  A held ghost of ours meeting
   * a client nobody announced keeps today's rules too (the rebind above,
   * then classic): the verdict reads it as it always did. */
  if (IsServer(sptr) && incoming_acct && IsIRCv3Aware(sptr)
      && MyConnect(acptr) && IsUser(acptr)
      && !IsBouncerAlias(acptr) && IsAccount(acptr)
      && 0 == ircd_strcmp(incoming_acct, cli_user(acptr)->account)) {
    int held_now = 0, primary_now = 0, ours_primary = 0, snapshot;
    /* The one session object this decision reads and acts on: the
     * session acptr is the primary or held ghost of (the one its hold
     * mark and session id were stamped from); none when two sessions
     * name it. */
    struct BouncerSession *bsess =
      bounce_nick_side_lookup(acptr, &held_now, &primary_now);
    /* Can our live primary become an alias of the incoming one?  Decided
     * once, here, before anything is sent: the demote and its finish make
     * the same check at their own step, so a "yes" here means they run. */
    enum bounce_demote_bar bar =
      bsess ? bounce_demote_eligibility(BOUNCE_DEMOTE_PLAN, acptr, bsess,
                                        sptr, incoming_acct, incoming_kc_id)
            : BOUNCE_DEMOTE_NO_SESSION;
    /* Different Keycloak users, for the verdict: our session's id, else
     * acptr's own when it is in no session -- the check the peer makes
     * against our N, so both sides read the same two ids. */
    int kc_conflict =
      bounce_side_kc_conflict(bsess ? bounce_session_kc_id(bsess) : NULL,
                              cli_user(acptr)->kc_id, incoming_kc_id);
    struct bounce_nick_side ours;
    struct bounce_nick_now now;
    char our_full[6];
    enum bounce_nick_verdict verdict;
    enum bounce_nick_action action;

    /* The nick timestamps compared are cli_lastnick and the wire's
     * lastnick (parv[3]), never cli_firsttime: cli_lastnick is the field
     * both sides advertise to each other in the N, so the comparison is
     * like-for-like.  The full numeric is our client's home prefix (ours,
     * acptr being local) plus its own. */
    ircd_snprintf(0, our_full, sizeof(our_full), "%s%s",
                  cli_yxx(cli_user(acptr)->server), cli_yxx(acptr));
    memset(&ours, 0, sizeof ours);
    ours.state_known = 1;
    ours.lastnick    = cli_lastnick(acptr);
    ours.sessid      = bsess ? bsess->hs_sessid : cli_session_id(acptr);
    ours.numeric     = our_full;
    snapshot = bounce_nick_side_from_stamp(&ours, &ours_primary,
                                           bounce_burst_stamp_for(acptr, cptr));
    if (!snapshot) {
      ours.held    = held_now;
      ours_primary = primary_now;
    }

    if (!IsBouncerHold(acptr) || theirs.state_known || ours.held) {
      verdict = bounce_nick_verdict(&ours, &theirs, ours_primary,
                                    kc_conflict, IsBurstGated(cptr));

      memset(&now, 0, sizeof now);
      now.held_ghost  = IsBouncerHold(acptr);
      now.has_session = bsess != NULL;
      now.is_primary  = primary_now;
      now.live_alias  = bounce_session_has_live_alias(bsess);
      now.yield_ok    = !HasFlag(acptr, FLAG_KILLED);
      now.demote_bar  = bar;
      action = bounce_nick_action(verdict, &theirs, &now);

      /* One line per decision: the verdict, what it does here, both
       * numerics and the account -- to opers, and to the user log, the
       * record that stays. */
      {
        const char *ours_kind = ours.held ? "held"
                                : ours_primary ? "primary" : "outside";
        const char *theirs_kind = !theirs.state_known ? "unknown"
                                  : theirs.held ? "held"
                                  : theirs.non_member ? "outside" : "primary";
        sendto_opmask_butone(0, SNO_OLDSNO,
                             "Bouncer same-nick: %s (ours, %s%s) meets %s (%s) "
                             "from %C, account %s: %s, %s%s",
                             our_full, ours_kind,
                             snapshot ? " as stamped" : "",
                             parv[parc - 2], theirs_kind,
                             cptr, incoming_acct,
                             bounce_nick_verdict_name(verdict),
                             bounce_nick_action_name(action),
                             kc_conflict ? " (Keycloak ids differ)" : "");
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer same-nick: %s (ours, %s%s) meets %s (%s) from %s, "
                  "account %s: %s, %s%s",
                  our_full, ours_kind, snapshot ? " as stamped" : "",
                  parv[parc - 2], theirs_kind, cli_name(cptr), incoming_acct,
                  bounce_nick_verdict_name(verdict),
                  bounce_nick_action_name(action),
                  kc_conflict ? " (Keycloak ids differ)" : "");
      }

      switch (action) {
      case BNA_REFUSE:
        /* We keep: refuse the incoming N.  The peer reaches the
         * complementary verdict and yields on its side. */
        return 0;

      case BNA_RETIRE:
        /* Our held session ends, and its ghost leaves first: a legacy
         * link hears its Q before it hears the incoming N, which
         * set_nick_name relays.  A gate this restored session held up is
         * released after this line, never inside it. */
        log_write(LS_USER, L_INFO, 0,
                  "Bouncer retire: held session %s of %s ends, ghost %s "
                  "leaves for %s from %s",
                  bsess ? bsess->hs_sessid : "(none)", incoming_acct, our_full,
                  parv[parc - 2], cli_name(cptr));
        bounce_retire_held_session(bsess, acptr, cptr,
                                   "Bouncer session moved");
        bounce_schedule_gate_release();
        return set_nick_name(cptr, sptr, nick, parc, parv, 0);

      case BNA_REBIND_LIVE:
      case BNA_REBIND_HELD: {
        struct irc_in_addr ip;
        base64toip(parv[parc - 3], &ip);
        if (0 == bounce_drop_held_ghost(bsess, acptr, sptr, parv[parc - 2],
                                        lastnick, parv[4], parv[5], &ip,
                                        parv[parc - 1], incoming_kc_id,
                                        action == BNA_REBIND_HELD))
          return 0;
        /* The facts did not hold after all: the classic rules decide. */
        break;
      }

      case BNA_SWAP: {
        /* We lose and our primary can become the incoming one's alias.
         * Through the state-transition funnel (Phase 7): one call
         * combines demote + finish into one transition with invariant
         * assertions before/after.  set_nick_name runs first to install
         * the incoming N's Client struct.
         *
         * Legacy links know the user only as acptr's face, under the
         * same nick.  Relaying the incoming N to them would make them
         * collide the nick and KILL one side, and either KILL ends the
         * whole session.  So the N goes to IRCv3-aware links only, and
         * the legacy links renumber acptr's face to the new primary in
         * place (BX P: same nick, same channels).
         *
         * One session from here on, under one id, as for the yield: our
         * record takes the incoming id outside a burst (I-1), before the
         * BX P and the demote name it.  The id is copied off the line
         * first: it is the link's stash. */
        struct bounce_transition_params p;
        int rc;
        struct Client *new_primary;
        char their_sessid[S2S_SESSID_BUFSIZE];
        ircd_strncpy(their_sessid, theirs.sessid ? theirs.sessid : "",
                     sizeof(their_sessid));
        set_nick_relay_withhold_legacy();
        rc = set_nick_name(cptr, sptr, nick, parc, parv, 0);
        clear_nick_relay_withhold_legacy();
        new_primary = findNUser(parv[parc - 2]);
        if (new_primary) {
          bounce_swap_take_id(bsess, new_primary, their_sessid);
          /* While acptr still has the numeric the legacy links know.
           * Per-link sends: no S2S override is needed after them (the N
           * relay above has consumed its own). */
          bounce_legacy_face_change(acptr, bsess, cptr, parv[parc - 2], NULL);
          memset(&p, 0, sizeof p);
          p.demoted_alias = acptr;
          p.peer_primary  = new_primary;
          p.legacy_done   = 1;
          bounce_session_transition(bsess, BST_DEMOTE_TO_ALIAS, &p);
        }
        return rc;
      }

      case BNA_YIELD: {
        /* Our held ghost gives the session to the incoming primary.  As
         * for the merge: the incoming N is installed for the IRCv3-aware
         * links only, and the legacy links renumber the ghost's face to
         * it (inside the yield).  The session id is copied off the line
         * first: it is the link's stash. */
        int rc;
        struct Client *new_primary;
        char their_sessid[S2S_SESSID_BUFSIZE];
        ircd_strncpy(their_sessid, theirs.sessid ? theirs.sessid : "",
                     sizeof(their_sessid));
        set_nick_relay_withhold_legacy();
        rc = set_nick_name(cptr, sptr, nick, parc, parv, 0);
        clear_nick_relay_withhold_legacy();
        new_primary = findNUser(parv[parc - 2]);
        if (new_primary)
          bounce_yield_held_ghost(bsess, acptr, new_primary, cptr,
                                  their_sessid);
        return rc;
      }

      case BNA_CLASSIC:
        break;
      }
    }
    /* No merge: a meeting the verdict leaves to the classic rules, a
     * Keycloak-id veto, or a yield that cannot run.  The standard
     * collision logic below decides: for one account the older nick
     * wins (the same-account override), and an equal nick TS loses
     * both. */
  }
  /*
   * If the older one is "non-person", the new entry is just
   * allowed to overwrite it. Just silently drop non-person,
   * and proceed with the nick. This should take care of the
   * "dormant nick" way of generating collisions...
   */
  if (IsUnknown(acptr) && MyConnect(acptr))
  {
    /* Mid-SASL bouncer-class client?  Defer rather than kill —
     * remote N may turn out to be the same account we're SASLing
     * into, in which case the bouncer alias path takes over after
     * SASL completes.  Otherwise check_auth_finished sends late 433. */
    if (cli_auth(acptr) && bounce_enabled_for(acptr)) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Bouncer: deferring mid-auth %C on incoming "
                           "%s from %C (nick %s, awaiting SASL)",
                           acptr, parv[parc - 2], cptr, nick);
      auth_defer_nick(cli_auth(acptr), nick);
      if (cli_name(acptr)[0]) {
        hRemClient(acptr);
        cli_name(acptr)[0] = '\0';
      }
      return set_nick_name(cptr, sptr, nick, parc, parv, 0);
    }
    /* Post-SASL but pre-register_user: bounce_defer_registration
     * queued this client because a peer link was mid-burst at SASL
     * completion.  cli_auth has been destroyed but registration
     * hasn't run yet — the client is still IsUnknown.  An incoming
     * peer N reaching us before the EOB drain must NOT override-kill
     * this client; let the deferred registration settle and the
     * standard bouncer alias-attach path handle the same-account
     * collision when register_user runs. */
    if (bounce_is_pending_registration(acptr)) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Bouncer: deferring incoming %s from %C "
                           "while %C waits for burst-settle drain "
                           "(nick %s)",
                           parv[parc - 2], cptr, acptr, nick);
      if (cli_name(acptr)[0]) {
        /* Its queue entry keeps the nick: the drain resolves it, as
         * check_auth_finished() resolves a deferred nick (W3 12c-2b fix
         * round 3, I-2). */
        bounce_pending_registration_nick_taken(acptr);
        hRemClient(acptr);
        cli_name(acptr)[0] = '\0';
      }
      return set_nick_name(cptr, sptr, nick, parc, parv, 0);
    }
    ServerStats->is_ref++;
    if (!find_except_conf(acptr, EFLAG_IPCHECK))
      IPcheck_connect_fail(acptr, 0);
    exit_client(cptr, acptr, &me, "Overridden by other sign on");
    return set_nick_name(cptr, sptr, nick, parc, parv, 0);
  }
  /*
   * Decide, we really have a nick collision and deal with it
   */
  /*
   * NICK was coming from a server connection.
   * This means we have a race condition (two users signing on
   * at the same time), or two net fragments reconnecting with the same nick.
   * The latter can happen because two different users connected
   * or because one and the same user switched server during a net break.
   * If the TimeStamps are equal, we kill both (or only 'new'
   * if it was a ":server NICK new ...").
   * Otherwise we kill the youngest when user@host differ,
   * or the oldest when they are the same.
   * We treat user and ~user as different, because if it wasn't
   * a faked ~user the AUTH wouldn't have added the '~'.
   * --Run
   *
   */
  if (IsServer(sptr))
  {
    struct irc_in_addr ip;
    /*
     * A new NICK being introduced by a neighbouring
     * server (e.g. message type ":server NICK new ..." received)
     *
     * compare IP address and username
     */
    base64toip(parv[parc - 3], &ip);
    differ =  (0 != memcmp(&cli_ip(acptr), &ip, sizeof(cli_ip(acptr)))) ||
              (0 != ircd_strcmp(cli_user(acptr)->username, parv[4]));
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick collision on %C (%C %Tu <- "
			 "%C %Tu (%s user@host))", acptr, cli_from(acptr),
			 cli_lastnick(acptr), cptr, lastnick,
			 differ ? "Different" : "Same");
  }
  else
  {
    /*
     * A NICK change has collided (e.g. message type ":old NICK new").
     *
     * compare IP address and username
     */
    differ =  (0 != memcmp(&cli_ip(acptr), &cli_ip(sptr), sizeof(cli_ip(acptr)))) ||
              (0 != ircd_strcmp(cli_user(acptr)->username, cli_user(sptr)->username));
    sendto_opmask_butone(0, SNO_OLDSNO, "Nick change collision from %C to "
			 "%C (%C %Tu <- %C %Tu)", sptr, acptr, cli_from(acptr),
			 cli_lastnick(acptr), cptr, lastnick);
  }
  /* Account-asymmetry override: if our local acptr is account-authenticated
   * (e.g., a bouncer-managed alias or primary) and the incoming sptr is
   * not, the incoming has a weaker identity claim regardless of timestamp.
   * Same-IP/username (differ=0) is what makes them collide; same IP can
   * just mean two connection paths from the same person, and the
   * authenticated side is the canonical one.
   *
   * Prevents a legacy-server-introduced unauthenticated user from
   * KILLing our local account-bearing user via standard same-user@host
   * rules when timestamps disfavor us — the "held ghost nick collision"
   * symptom in chathistory replay (real local user killed because
   * upstream's nick claim arrived with a newer lastnick).
   *
   * Only applies for incoming server-introduced N's against a local
   * account-bearing acptr; doesn't change handling of other-account
   * collisions (different accounts → real collision, standard rules
   * apply via differ=1). */
  if (IsServer(sptr) && parc > 7
      && IsAccount(acptr) && IsUser(acptr)) {
    int incoming_has_account = 0;
    if (parv[6] && *parv[6] == '+') {
      const char *m;
      for (m = parv[6] + 1; *m; m++) {
        if (*m == 'r') { incoming_has_account = 1; break; }
        /* Skip past arg-taking flags' positions; we don't need their
         * values, just whether 'r' is set anywhere in the flag list. */
      }
    }
    /* Policy (2026-08-27): the account is same-person evidence, not a
     * license to kill a DIFFERENT older claimant.  Gate on !differ so the
     * protection only covers same-user@host (our own ghost/stale claim);
     * a different-person collision falls through to classic rules --
     * older wins, period, authenticated or not. */
    if (!incoming_has_account && !differ) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Account-asymmetry override: refusing to kill "
                           "account-bearing %C for unauth incoming %s on "
                           "%C (would be a hijack of an authenticated user)",
                           acptr, parv[parc - 2], cptr);
      /* Send KILL TO upstream — the server that owns the offending
       * unauth user.  Original code used sendcmdto_serv_butone with
       * butone=cptr, which excludes upstream from the broadcast and
       * leaves the offender alive there — upstream's own collision
       * logic then evicts our local user via the symmetric path.
       * sendcmdto_one targets cptr (the introducing link) directly,
       * matching the pattern used at m_nick.c:813 for the standard
       * server-introduced-new-client kill case. */
      log_write(LS_SERVKILL, L_INFO, 0,
                "collision KILL (asymmetry): killed incoming unauth %s "
                "(ts %Tu) toward %C; kept local authed %C (ts %Tu, differ=0)",
                parv[parc - 2], lastnick, cptr, acptr, cli_lastnick(acptr));
      sendcmdto_one(&me, CMD_KILL, cptr,
                    "%s :%s (Unauthenticated nick collides with "
                    "authenticated user)",
                    parv[parc - 2],
                    feature_str(FEAT_HIS_SERVERNAME));
      return 0;
    }

    /* Same-account override: both clients are authenticated and the
     * incoming N carries the same account as our local acptr.  We only
     * reach this point when D.2 did not merge them (a legacy source with
     * no symmetric alias-attach support, Keycloak ids that differ, or a
     * lost merge whose demote cannot run), so the natural answer "alias
     * them together" isn't available.  Default classic rule for
     * !differ (same user@host) kills the older as a reconnect ghost —
     * but here both are legitimate live sessions, and killing the
     * older invites the loser's bouncer to auto-reconnect with a fresh
     * (newer) TS, which then wins the next round and KILLs our local.
     * Thrash loop.  Promote to differ=1 (older-wins / stability) so the
     * established session keeps the nick; the legacy-side loser stays
     * killed and its bouncer's reconnect-with-newer-TS would still lose
     * the next round, giving a stable convergence signal. */
    if (incoming_has_account && incoming_acct
        && 0 == ircd_strcmp(incoming_acct, cli_user(acptr)->account)
        && !differ) {
      sendto_opmask_butone(0, SNO_OLDSNO,
                           "Same-account override: bouncer-account dual "
                           "session %C vs incoming %s on %C — applying "
                           "older-wins (stability) instead of newer-wins "
                           "(reconnect ghost)",
                           acptr, parv[parc - 2], cptr);
      differ = 1;
    }
  }

  type = differ ? "overruled by older nick" : "nick collision from same user@host";
  Debug((DEBUG_INFO, "m_nick collision: acptr=%C(numeric=%s,lastnick=%lu,user@host=%s@%s) "
         "incoming=%s lastnick=%lu user@host=%s@%s differ=%d cptr=%C sptr=%s",
         acptr, IsUser(acptr) ? cli_yxx(acptr) : "?",
         (unsigned long)cli_lastnick(acptr),
         IsUser(acptr) && cli_user(acptr) ? cli_user(acptr)->username : "?",
         IsUser(acptr) && cli_user(acptr) ? cli_user(acptr)->host : "?",
         IsServer(sptr) ? parv[parc - 2] : cli_name(sptr),
         (unsigned long)lastnick,
         IsServer(sptr) ? parv[4] : (cli_user(sptr) ? cli_username(sptr) : "?"),
         IsServer(sptr) ? parv[5] : (cli_user(sptr) ? cli_user(sptr)->host : "?"),
         differ, cptr, IsServer(sptr) ? cli_name(sptr) : cli_name(sptr)));
  /*
   * Now remove (kill) the nick on our side if it is the youngest.
   * If no timestamp was received, we ignore the incoming nick
   * (and expect a KILL for our legit nick soon ):
   * When the timestamps are equal we kill both nicks. --Run
   * acptr->from != cptr should *always* be true (?).
   *
   * This exits the client sending the NICK message
   */
  if ((differ && lastnick >= cli_lastnick(acptr)) ||
      (!differ && lastnick <= cli_lastnick(acptr)))
  {
    ServerStats->is_kill++;
    if (!IsServer(sptr))
    {
      /* If this was a nick change and not a nick introduction, we
       * need to ensure that we remove our record of the client, and
       * send a KILL to the whole network.
       */
      assert(!MyConnect(sptr));
      /* Inform the rest of the net... */
      log_write(LS_SERVKILL, L_INFO, 0,
                "collision KILL: killed remote %s (nick change to %s, ts %Tu) "
                "from %C; kept %C (ts %Tu, %s)",
                cli_name(sptr), nick, lastnick, cptr, acptr,
                cli_lastnick(acptr), type);
      sendcmdto_serv_butone(&me, CMD_KILL, 0, "%C :%s (%s)",
                            sptr, cli_name(&me), type);
      /* Don't go sending off a QUIT message... */
      SetFlag(sptr, FLAG_KILLED);
      /* Remove them locally. */
      exit_client_msg(cptr, sptr, &me,
                      "Killed (%s (%s))",
                      feature_str(FEAT_HIS_SERVERNAME), type);
    }
    else
    {
      /* If the origin is a server, this was a new client, so we only
       * send the KILL in the direction it came from.  We have no
       * client record that we would have to clean up.
       */
      log_write(LS_SERVKILL, L_INFO, 0,
                "collision KILL: killed incoming %s (ts %Tu) toward %C; "
                "kept %C (ts %Tu, %s)",
                parv[parc - 2], lastnick, cptr, acptr,
                cli_lastnick(acptr), type);
      sendcmdto_one(&me, CMD_KILL, cptr, "%s :%s (%s)",
                    parv[parc - 2], cli_name(&me), type);
    }
    /* If the timestamps differ and we just killed sptr, we don't need to kill
     * acptr as well.
     */
    if (lastnick != cli_lastnick(acptr))
      return 0;
  }
  log_write(LS_SERVKILL, L_INFO, 0,
            "collision KILL: killed local %C (ts %Tu) for incoming %s "
            "(ts %Tu) from %C (%s)",
            acptr, cli_lastnick(acptr), nick, lastnick, cptr, type);
  /* Tell acptr why we are killing it. */
  send_reply(acptr, ERR_NICKCOLLISION, nick);

  ServerStats->is_kill++;
  SetFlag(acptr, FLAG_KILLED);
  /*
   * This exits the client we had before getting the NICK message
   */
  sendcmdto_serv_butone(&me, CMD_KILL, NULL, "%C :%s (%s)",
                        acptr, feature_str(FEAT_HIS_SERVERNAME),
                        type);
  exit_client_msg(cptr, acptr, &me, "Killed (%s (%s))",
                  feature_str(FEAT_HIS_SERVERNAME), type);
  if (lastnick == cli_lastnick(acptr))
    return 0;
  if (sptr == NULL)
    return 0;
  return set_nick_name(cptr, sptr, nick, parc, parv, 0);
}
