/*
 * IRC - Internet Relay Chat, ircd/m_authenticate.c
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

#include "capab.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"
#include "send.h"
#include "s_auth.h"
#include "s_misc.h"
#include "s_user.h"
#include "sasl_auth.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

static void sasl_timeout_callback(struct Event* ev);

/** The most AUTHENTICATE lines held for one WEBIRC check (a mechanism and
 * its data: a long token takes a few 400-byte lines). */
#define SASL_HELD_MAX 16

/** Free the AUTHENTICATE lines held on @a con (its client is going, or
 * the client aborted them). */
void authenticate_held_free(struct Connection *con)
{
  struct SLink *lp;

  while ((lp = con_saslheld(con))) {
    con_saslheld(con) = lp->next;
    MyFree(lp->value.cp);
    free_link(lp);
  }
}

/** Hold an AUTHENTICATE line while a WEBIRC check is out (m_webirc.c).
 * Until it finishes, the client's address and host are the gateway's, and
 * every tier an exchange starts in is told them -- services in the SASL H
 * line, IAuth in its H line, Keycloak -- and services judge the login by
 * them (an account's allowed hostmasks).  So no exchange starts: the lines
 * are kept, in order, and replayed when the check has applied the real
 * address (authenticate_replay()).  A failed check exits the client, and
 * the lines go with it -- unless IAuth is handed the WEBIRC instead
 * (policy w, m_webirc.c), when they are replayed on the gateway's address,
 * which the client keeps; the registration timeout bounds the wait.
 * @return Zero.
 */
static int authenticate_hold(struct Client *cptr, const char *line)
{
  struct SLink **pp;
  struct SLink *lp;
  int n = 0;

  for (pp = &cli_saslheld(cptr); *pp; pp = &(*pp)->next)
    n++;
  if (n >= SASL_HELD_MAX) {
    /* More than any exchange's start: it fails as one would. */
    authenticate_held_free(cli_connect(cptr));
    return send_reply(cptr, ERR_SASLFAIL, "");
  }
  lp = make_link();
  DupString(lp->value.cp, line);
  lp->next = NULL;
  *pp = lp;
  return 0;
}

/** Replay the AUTHENTICATE lines held while @a cptr's WEBIRC check was out
 * (authenticate_hold()): the check has applied the real address, and the
 * exchange starts now, in whichever tier, with it.  Called from the
 * check's completion, before registration is let go on.
 * @return CPTR_KILLED if a line exited the client (nothing may touch it
 * then), else zero.
 */
int authenticate_replay(struct Client *cptr)
{
  struct SLink *lp;
  char *parv[3];
  int res;

  while ((lp = cli_saslheld(cptr))) {
    cli_saslheld(cptr) = lp->next;      /* off the list before it runs */
    parv[0] = cli_name(cptr);
    parv[1] = lp->value.cp;
    parv[2] = NULL;
    res = m_authenticate(cptr, cptr, 2, parv);
    MyFree(lp->value.cp);
    free_link(lp);
    if (res == CPTR_KILLED)
      return res;
  }
  return 0;
}

/** End @a cptr's SASL exchange in progress, in the tier that holds it --
 * the local Keycloak session, IAuth, or services over P10 -- and let
 * registration go on, as a failed exchange does: the next AUTHENTICATE
 * starts a new one.  @a client_abort: the client sent AUTHENTICATE *, and
 * gets 906 (904 after a local error challenge, RFC 7628 3.2.3); else the
 * caller has sent the failure numeric itself (905) and nothing more goes.
 * IAuth and services are told to drop their side (A X, SASL D A), as for
 * an abort.
 * @return What resuming registration did to @a cptr (CPTR_KILLED when it
 * exited or freed it): the handler's own result, nothing may touch
 * @a cptr after it.
 */
static int authenticate_end(struct Client *cptr, int client_abort)
{
  /* Only an exchange in progress: a cookie whose exchange has not
   * completed -- a REGISTER login meanwhile, or the completed login a
   * logged-in client's re-authentication keeps, completes no exchange
   * (IsSASLExchangeDone()).  A re-authentication ended here leaves that
   * login whole. */
  if (!cli_saslcookie(cptr) || IsSASLExchangeDone(cptr))
    return 0;

  /* The client abandons an exchange its credentials already went out for
   * (SASL_MAX_FAILURES; once per exchange).  A refused token's end is
   * counted below, and not at all when Keycloak could not be asked. */
  if (client_abort && !(cli_saslsession(cptr)
                        && cli_saslsession(cptr)->state == SASL_STATE_FAILED))
    sasl_exchange_abandoned(cptr, 0);

  /* Local SASL session takes priority */
  if (cli_saslsession(cptr)) {
    if (client_abort) {
      /* RFC 7628 §3.2.3: after an error challenge, client sends "*"
       * to acknowledge failure — reply with SASLFAIL, not SASLABORTED. */
      if (cli_saslsession(cptr)->state == SASL_STATE_FAILED) {
        /* The end of a refused token: counted, unless Keycloak could not
         * be asked (SASL_MAX_FAILURES). */
        if (!cli_saslsession(cptr)->fail_unavailable)
          sasl_failure_count(cptr);
        send_reply(cptr, ERR_SASLFAIL, "");
      }
      else
        send_reply(cptr, ERR_SASLABORTED);
    }
    /* Resumes registration; may exit cptr, so return its result. */
    return sasl_abort_local(cptr);
  }
  /* Notify IAuth if applicable */
  if (auth_iauth_handles_sasl())
    auth_send_sasl_abort(cptr);
  /* abort_sasl handles P10 notification and state cleanup; it only
   * drops the registration hold, so resume registration here.  This
   * may exit cptr, so return its result. */
  abort_sasl(cptr, client_abort ? SASL_ABORT_REPLY_ABORTED
                                : SASL_ABORT_REPLY_NONE);
  if (cli_auth(cptr))
    return auth_sasl_done(cli_auth(cptr));
  return 0;
}

int m_authenticate(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  int first = 0;
  char realhost[HOSTLEN + 3];
  char *hoststr = (cli_sockhost(cptr) ? cli_sockhost(cptr) : cli_sock_ip(cptr));

  /* SASL 3.1: AUTHENTICATE "MUST be used before registration is complete"
   * and is not specified in registered state; re-authentication after
   * registration is SASL 3.2's, which is SASL on CAP 302.  A connection
   * that never sent CAP LS with a version of 302 or more is a 3.1 client
   * (cap_version_after_ls(): a later CAP LS never lowers the version), and
   * once registered it gets stock master's answer -- whose command table
   * sends AUTHENTICATE from a registered client to m_registered() -- for
   * every line: 462, before anything else is looked at.  No tier is told,
   * nothing of the client changes, no exchange starts. */
  if (IsRegistered(cptr) && cli_capab_version(cptr) < CAP_VERSION_302)
    return m_registered(cptr, sptr, parc, parv);

  if (!CapActive(cptr, CAP_SASL))
    return 0;

  if (parc < 2) /* have enough parameters? */
    return need_more_params(cptr, "AUTHENTICATE");

  /* sasl-3.1: "If authentication fails, a 904 or 905 numeric will be
   * sent and the client MAY retry from the AUTHENTICATE <mechanism>
   * command."  905 fails the exchange in progress as 904 does: it ends
   * here, in its tier, or the client's next AUTHENTICATE <mechanism> would
   * be read as data of this one (and its QUIT answered 906). */
  if (strlen(parv[1]) > 400) {
    if (CapActive(cptr, CAP_STANDARDREPLIES))
      send_fail(cptr, "AUTHENTICATE", "TOO_LONG", NULL, "SASL message too long");
    /* The response of an exchange in flight: a failure (SASL_MAX_FAILURES).
     * A line with no exchange behind it ends none. */
    if (cli_saslcookie(cptr) && !IsSASLExchangeDone(cptr))
      sasl_failure_count(cptr);
    send_reply(cptr, ERR_SASLTOOLONG);
    return authenticate_end(cptr, 0);
  }

  /* Handle AUTHENTICATE * to abort SASL session (IRCv3 spec); only an
   * exchange in progress is aborted -- or lines held for a WEBIRC check
   * (authenticate_hold()), which are dropped: the exchange they would have
   * started is aborted. */
  if (parv[1][0] == '*' && parv[1][1] == '\0') {
    if (cli_saslheld(cptr)) {
      authenticate_held_free(cli_connect(cptr));
      return send_reply(cptr, ERR_SASLABORTED);
    }
    return authenticate_end(cptr, 1);
  }

  /* A WEBIRC check still out: no exchange starts on the gateway's address
   * (authenticate_hold()).  One begun before the WEBIRC goes on. */
  if (IsWebIRCPending(cptr) && !cli_saslsession(cptr) && !cli_saslcookie(cptr))
    return authenticate_hold(cptr, parv[1]);

  /* A client that already has an account or a completed login -- SASL
   * completed, or an account set by services, WEBIRC or a REGISTER -- gets
   * ERR_SASLALREADY (907) for any further AUTHENTICATE, as SASL 3.1 says,
   * unless it is a SASL 3.2 client (CAP LS 302; a 3.1 client after
   * registration got 462 above).  A 3.2 client may authenticate again as
   * SASL_REAUTH allows (sasl_auth.c): logged in (sasl_logged_in(): the ircd
   * has applied its account), with OAUTHBEARER only under refresh -- to
   * refresh a token about to expire -- and with any mechanism under same
   * and any; before registration has applied a login, likewise
   * (sasl_restart_mechanism_allowed()).  A registered 3.2 client with no
   * account may authenticate with any mechanism.  A failed or aborted
   * exchange completes nothing: the client may retry.  The rule applies
   * when an exchange starts, not to the data lines of one in progress (a
   * local session, or a cookie for the IAuth and P10 tiers; both are
   * cleared when the exchange completes or is aborted).
   *
   * What a logged-in client's re-authentication may prove is decided when
   * it completes, in every tier (sasl_reauth_refused(): sasl_login_apply()
   * step 0; a services or IAuth answer already at its L), SASL_REAUTH read
   * again then: its own account (a refresh), another one only under any
   * and never for a bouncer session's connection, the same name under
   * another Keycloak id never.  A refused one leaves the login exactly as
   * it was.  Before registration has applied a login, a 3.2 client that
   * may start again may log in as anyone -- and keeps the login it holds
   * until the new exchange succeeds (owner's ruling, 2026-11-15).
   */
  if (!cli_saslsession(cptr) && !cli_saslcookie(cptr)) {
    int limit = feature_int(FEAT_SASL_MAX_FAILURES);

    EndSASLExchange(cptr);    /* a new exchange: a re-authentication if set below */
    con_sasl_xflags(cli_connect(cptr)) = 0;   /* nothing sent, nothing counted */

    /* SASL_MAX_FAILURES, as it is now (a lowered value applies here too).
     * Before registration the connection is closed, as at the failure
     * that reached the limit (registration's check, sasl_failure_count()).
     * After it -- or once registration has applied a login -- no new
     * exchange starts: 904 and why, nothing reaches any tier, nothing else
     * changes.  A success resets the count and none can come now, so this
     * lasts until the client reconnects. */
    if (con_sasl_limited(cli_connect(cptr))
        || (limit > 0 && cli_sasl_failures(cptr) >= limit)) {
      /* The mark is final: a raised limit never revives the connection. */
      con_sasl_limited(cli_connect(cptr)) = 1;
      if (!IsRegistered(cptr) && cli_auth(cptr))
        return exit_client(cptr, cptr, &me, "Too many SASL failures");
      return send_reply(cptr, ERR_SASLFAIL,
                        ": too many failed attempts on this connection");
    }
  }
  if (!cli_saslsession(cptr) && !cli_saslcookie(cptr)
      && (IsSASLComplete(cptr) || IsAccount(cptr))) {
    int token = !ircd_strcmp(parv[1], "OAUTHBEARER");
    int allowed;

    if (cli_capab_version(cptr) < CAP_VERSION_302)
      allowed = 0;                            /* SASL 3.1 */
    else if (sasl_logged_in(cptr))
      allowed = sasl_reauth_mechanism_allowed(token);
    else
      allowed = sasl_restart_mechanism_allowed(token);
    if (!allowed) {
      if (CapActive(cptr, CAP_STANDARDREPLIES))
        send_fail(cptr, "AUTHENTICATE", "ALREADY_AUTHENTICATED", NULL,
                  "You have already completed SASL authentication");
      return send_reply(cptr, ERR_SASLALREADY);
    }
    /* The login stands -- after registration its account and record,
     * before it the identity registration will apply (sasl_identity_set():
     * name, timestamp, Keycloak id, id-confirmed), the SASL-complete flag,
     * FLAG_REGLOGIN, or an account from login-on-connect or WEBIRC --
     * until the new exchange SUCCEEDS: only a login that completes
     * replaces it, as a whole (sasl_login_apply() step 1, or IAuth's Z).
     * Every other end -- a mechanism the tier does not offer, a refusal, a
     * failure, an abort, the timeout, the agent or IAuth going away --
     * leaves it exactly as it is, and registration applies it
     * (auth_complete_sasl(), which also aborts an exchange still in
     * flight then).  The re-authentication mark tells every end of the
     * exchange that it is in flight beside a completed login
     * (IsSASLExchangeDone()), before registration as after it.  Whether
     * it began with a token mechanism is kept for a logged-in client's
     * completion, which reads SASL_REAUTH again (refresh: a token's
     * refresh only). */
    SetSASLReauth(cptr);
    if (token && sasl_logged_in(cptr))
      SetFlag(cptr, FLAG_SASLREAUTHTOKEN);
    /* Clear old SASL session state (no cookie here: the exchange's own
     * state was ended above) */
    if ((cli_saslagent(cptr) != NULL) && cli_saslagentref(cli_saslagent(cptr)))
      cli_saslagentref(cli_saslagent(cptr))--;
    cli_saslagent(cptr) = NULL;
    if (t_active(&cli_sasltimeout(cptr)))
      timer_del(&cli_sasltimeout(cptr));
  }

  /* Path 1: Local Keycloak-based SASL (highest priority) */
  if (sasl_local_available()) {
    if (cli_saslsession(cptr)) {
      /* Continuation of an existing local SASL session.  The exchange can
       * end in this call (a cached credential, a locally checked token,
       * the last step of SCRAM or ECDSA) and resume registration, which
       * may exit or free cptr: CPTR_KILLED then, returned as is. */
      return sasl_continue(cptr, parv[1]);
    }
    /* New session — sasl_start() returns 0 on success, -1 if mechanism
     * is unsupported (fall through to IAuth/P10 for unknown mechanisms).
     * Only when no exchange is in flight: a cookie with no local session is
     * an IAuth or services exchange (begun while Keycloak was unhealthy),
     * and this line is its data -- taken as a new local exchange it would
     * pass the mechanism check above (only a cookie-less line is checked). */
    if (!cli_saslcookie(cptr) && sasl_start(cptr, parv[1]) == 0)
      return 0;
    /* Fall through to IAuth/P10 if sasl_start returned -1 */
  }

  /* Path 2: IAuth SASL */
  if (auth_iauth_handles_sasl()) {
    /* Route SASL to IAuth */
    if (!cli_saslcookie(cptr)) {
      do {
        cli_saslcookie(cptr) = ircrandom() & 0x7fffffff;
      } while (!cli_saslcookie(cptr));
      cli_saslstart(cptr) = CurrentTime;
      cli_saslnamed(cptr)[0] = '\0';      /* nothing named for it yet */
      cli_saslnamedts(cptr) = 0;
      if (cli_auth(cptr))
        auth_sasl_start(cli_auth(cptr));
      first = 1;
    }

    if (strchr(hoststr, ':') != NULL)
      ircd_snprintf(0, realhost, sizeof(realhost), "[%s]", hoststr);
    else
      ircd_strncpy(realhost, hoststr, sizeof(realhost));

    /* A line that cannot be sent -- no program runs, or it is done with
     * this client -- will never be answered: the exchange fails now, not
     * at its timeout, and registration goes on.  This may exit cptr. */
    if (first) {
      if (*parv[1] == ':' || strchr(parv[1], ' '))
        return exit_client(cptr, sptr, sptr, "Malformed AUTHENTICATE");

      /* Send SASL start to IAuth */
      if (!auth_send_sasl_start(cptr, parv[1], cli_sslclifp(cptr))) {
        auth_iauth_sasl_fail(cptr);
        return cli_auth(cptr) ? auth_sasl_done(cli_auth(cptr)) : 0;
      }

      /* Send host info if configured */
      if (feature_bool(FEAT_SASL_SENDHOST))
        auth_send_sasl_host(cptr, cli_username(cptr), realhost, cli_sock_ip(cptr));
    } else if (!auth_send_sasl_data(cptr, parv[1])) {
      /* Send SASL continuation data to IAuth */
      auth_iauth_sasl_fail(cptr);
      return cli_auth(cptr) ? auth_sasl_done(cli_auth(cptr)) : 0;
    } else if (strcmp(parv[1], "*")) {
      /* The client's data went out to IAuth (SASL_MAX_FAILURES) */
      con_sasl_xflags(cli_connect(cptr)) |= SASLX_SENT;
      con_sasl_xflags(cli_connect(cptr)) &= ~SASLX_CLIENTTURN;
    }

    /* The program went away as the line was sent: the exchange has
     * failed already (iauth_disconnect()); no timer for it. */
    if (!cli_saslcookie(cptr))
      return 0;

    if (!t_active(&cli_sasltimeout(cptr))) {
      cli_freeflag(cptr) |= FREEFLAG_SASLTIMER;
      timer_add(&cli_sasltimeout(cptr), sasl_timeout_callback, cli_connect(cptr),
                TT_RELATIVE, feature_int(FEAT_SASL_TIMEOUT));
    }

    return 0;
  }

  /* Original code: route SASL to services via P10 */

  /* Look up the target server */
  if (!(acptr = cli_saslagent(cptr))) {
    if (strcmp(feature_str(FEAT_SASL_SERVER), "*"))
      acptr = find_match_server((char *)feature_str(FEAT_SASL_SERVER));
    else
      acptr = NULL;
  }

  /* Validate agent is still a valid, connected server */
  if (acptr && (IsDead(acptr) || !IsServer(acptr))) {
    /* Clear stale agent reference */
    if (cli_saslagent(cptr) == acptr) {
      if (cli_saslagentref(acptr))
        cli_saslagentref(acptr)--;
      cli_saslagent(cptr) = NULL;
    }
    /* Try to find a new agent */
    if (strcmp(feature_str(FEAT_SASL_SERVER), "*"))
      acptr = find_match_server((char *)feature_str(FEAT_SASL_SERVER));
    else
      acptr = NULL;
  }

  if (!acptr && strcmp(feature_str(FEAT_SASL_SERVER), "*")) {
    if (CapActive(cptr, CAP_STANDARDREPLIES))
      send_fail(cptr, "AUTHENTICATE", "SASL_FAIL", NULL, "SASL service unavailable");
    return send_reply(cptr, ERR_SASLFAIL, ": service unavailable");
  }

  /* If it's to us, do nothing; otherwise, forward the query */
  if (acptr && IsMe(acptr))
    return 0;

  /* Generate an SASL session cookie if not already generated */
  if (!cli_saslcookie(cptr)) {
    do {
      cli_saslcookie(cptr) = ircrandom() & 0x7fffffff;
    } while (!cli_saslcookie(cptr));
    cli_saslstart(cptr) = CurrentTime;
    cli_saslnamed(cptr)[0] = '\0';        /* nothing named for it yet */
    cli_saslnamedts(cptr) = 0;
    if (cli_auth(cptr))
      auth_sasl_start(cli_auth(cptr));
    first = 1;
  }

  if (strchr(hoststr, ':') != NULL)
    ircd_snprintf(0, realhost, sizeof(realhost), "[%s]", hoststr);
  else
    ircd_strncpy(realhost, hoststr, sizeof(realhost));

  if (acptr) {
    if (first) {
      if (*parv[1] == ':' || strchr(parv[1], ' '))
		return exit_client(cptr, sptr, sptr, "Malformed AUTHENTICATE");
      if (!EmptyString(cli_sslclifp(cptr)))
        sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u S %s :%s", acptr, &me,
                      cli_fd(cptr), cli_saslcookie(cptr),
                      parv[1], cli_sslclifp(cptr));
      else
        sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u S :%s", acptr, &me,
                      cli_fd(cptr), cli_saslcookie(cptr), parv[1]);
      if (feature_bool(FEAT_SASL_SENDHOST))
        sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u H :%s@%s:%s", acptr, &me,
                      cli_fd(cptr), cli_saslcookie(cptr), cli_username(cptr),
                      realhost, cli_sock_ip(cptr));
    } else {
      sendcmdto_one(&me, CMD_SASL, acptr, "%C %C!%u.%u C :%s", acptr, &me,
                    cli_fd(cptr), cli_saslcookie(cptr), parv[1]);
      con_sasl_xflags(cli_connect(cptr)) |= SASLX_SENT;   /* to services */
      con_sasl_xflags(cli_connect(cptr)) &= ~SASLX_CLIENTTURN;
    }
  } else {
    if (first) {
      if (*parv[1] == ':' || strchr(parv[1], ' '))
        return exit_client(cptr, sptr, sptr, "Malformed AUTHENTICATE");
      if (!EmptyString(cli_sslclifp(cptr)))
        sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u S %s :%s", &me,
                              cli_fd(cptr), cli_saslcookie(cptr),
                              parv[1], cli_sslclifp(cptr));
      else
        sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u S :%s", &me,
                              cli_fd(cptr), cli_saslcookie(cptr), parv[1]);
      if (feature_bool(FEAT_SASL_SENDHOST))
        sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u H :%s@%s:%s", &me,
                              cli_fd(cptr), cli_saslcookie(cptr), cli_username(cptr),
                              realhost, cli_sock_ip(cptr));
    } else {
      sendcmdto_serv_butone(&me, CMD_SASL, cptr, "* %C!%u.%u C :%s", &me,
                            cli_fd(cptr), cli_saslcookie(cptr), parv[1]);
      con_sasl_xflags(cli_connect(cptr)) |= SASLX_SENT;   /* to services */
      con_sasl_xflags(cli_connect(cptr)) &= ~SASLX_CLIENTTURN;
    }
  }

  if (!t_active(&cli_sasltimeout(cptr))) {
    cli_freeflag(cptr) |= FREEFLAG_SASLTIMER;
    timer_add(&cli_sasltimeout(cptr), sasl_timeout_callback, cli_connect(cptr),
              TT_RELATIVE, feature_int(FEAT_SASL_TIMEOUT));
  }

  return 0;
}

/** Timeout a given SASL auth request.
 * The timer lives in the client's Connection and keeps it allocated
 * (FREEFLAG_SASLTIMER) until the ET_DESTROY event, the same way the
 * process timer does: resuming registration from ET_EXPIRE may exit
 * the client, and timer_run() still touches the timer afterwards.
 * @param[in] ev A timer event whose associated data is the
 *   struct Connection.
 */
static void sasl_timeout_callback(struct Event* ev)
{
  struct Client *cptr;
  struct Connection *con;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));
  assert(ET_DESTROY == ev_type(ev) || ET_EXPIRE == ev_type(ev));

  con = (struct Connection*) t_data(ev_timer(ev));
  cptr = con_client(con);

  assert(0 == cptr || con == cli_connect(cptr));

  if (ev_type(ev) == ET_DESTROY) {
    con_freeflag(con) &= ~FREEFLAG_SASLTIMER;

    if (!con_freeflag(con) && !cptr)
      free_connection(con); /* client is being destroyed */
  } else if (cptr) {
    sasl_exchange_abandoned(cptr, 1);   /* counted only on the client's turn */
    abort_sasl(cptr, 1);
    /* SASL no longer holds registration; let it continue.  This may
     * exit cptr; nothing below touches it. */
    if (cli_auth(cptr))
      auth_sasl_done(cli_auth(cptr));
  }
}


