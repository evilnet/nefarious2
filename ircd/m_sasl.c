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

#include "capab.h"
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
#include "bouncer_session.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_user.h"
#include "metadata.h"
#include "sasl_auth.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/** End a relayed exchange that did not log \a acptr in (services failed
 * or aborted it, or its answer was refused): its agent, cookie and timer
 * go, and registration, if the exchange held it, goes on.  Its result
 * (whether acptr survived registration) is not for the caller: the line
 * came from a server link, which must not be told CPTR_KILLED, and nothing
 * may touch acptr afterwards. */
static void sasl_relay_end(struct Client *acptr)
{
  if ((cli_saslagent(acptr) != NULL) && cli_saslagentref(cli_saslagent(acptr)))
    cli_saslagentref(cli_saslagent(acptr))--;
  cli_saslagent(acptr) = NULL;
  EndSASLExchange(acptr);
  if (t_active(&cli_sasltimeout(acptr)))
    timer_del(&cli_sasltimeout(acptr));

  if (cli_auth(acptr))
    auth_sasl_done(cli_auth(acptr));
}

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
    /* Network-wide forms are relayed as-is.  (The old "SASL * * M
     * :<mechanisms>" list broadcast was emitted only by an abandoned X3
     * branch; the advertised sasl= value is per-node config, see
     * sasl_local_mechanisms() and the iauth mechanism cache.) */
    if (ext != NULL)
      sendcmdto_serv_butone(sptr, CMD_SASL, cptr, "* %s %s %s :%s",
                                   token, reply, data, ext);
    else
      sendcmdto_serv_butone(sptr, CMD_SASL, cptr, "* %s %s :%s",
                                   token, reply, data);
    return 0;
  } else {
    /* Look up the target */
    if (!(acptr = FindNServer(parv[1])))
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
  if (strncmp(cli_yxx(&me), token, 2)) {
    log_write(LS_DEBUG, L_DEBUG, 0, "SASL: Token prefix mismatch - expected %s, got %.2s (from %C)",
              cli_yxx(&me), token, sptr);
    return 0;
  }

  /* If there is no fd then it is an invalid token */
  if ((fdstr = strchr(token, '!')) == NULL) {
    protocol_violation(sptr, "SASL: Malformed token - missing fd separator '!' in '%s'", token);
    return 0;
  }
  fdstr++;

  /* If there is no cookie then it is also an invalid token */
  if ((cookiestr = strchr(token, '.')) == NULL) {
    protocol_violation(sptr, "SASL: Malformed token - missing cookie separator '.' in '%s'", token);
    return 0;
  }
  *cookiestr++ = '\0';

  fd = atoi(fdstr);
  cookie = atoi(cookiestr);

  /* This server never issues a cookie of 0 (m_authenticate(),
   * sasl_start() draw again until it is not); 0 is what a client with no
   * exchange in flight has -- never authenticated, done, aborted, a
   * server link -- so a reply saying 0 (or anything atoi() reads as 0)
   * names nobody. */
  if (!cookie) {
    log_write(LS_DEBUG, L_DEBUG, 0, "SASL: Reply with cookie 0 for fd %u "
              "ignored (from %C)", fd, sptr);
    return 0;
  }

  /* Bounds-check the wire-supplied fd before indexing.  LocalClientArray is
   * [MAXCONNECTIONS], indexed by raw socket fd; os_set_fdlimit() caps real
   * fds below MAXCONNECTIONS, so that is the structural bound (not HighestFd,
   * a mutable high-water mark).  fd is unsigned, so this single >= test also
   * rejects a negative atoi() result (wrapped to a huge value).  An in-bounds
   * but unused slot is still rejected by the NULL check that follows. */
  if (fd >= MAXCONNECTIONS || !(acptr = LocalClientArray[fd])) {
    log_write(LS_DEBUG, L_DEBUG, 0, "SASL: Client for fd %u not found (from %C, cookie %u)",
              fd, sptr, cookie);
    return 0;
  }
  if (cli_saslcookie(acptr) != cookie) {
    log_write(LS_DEBUG, L_DEBUG, 0, "SASL: Cookie mismatch for %C (fd %u) - expected %u, got %u (from %C)",
              acptr, fd, cli_saslcookie(acptr), cookie, sptr);
    return 0;
  }

  /* Check for stale SASL responses (FD reuse protection) */
  if (cli_saslstart(acptr) > 0) {
    int timeout = feature_int(FEAT_SASL_TIMEOUT);
    if (timeout > 0 && (CurrentTime - cli_saslstart(acptr)) > timeout) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL: Stale response for %C (fd %u) - session started %ld seconds ago (timeout %d)",
                acptr, fd, (long)(CurrentTime - cli_saslstart(acptr)), timeout);
      return 0;
    }
  }

  /* OK we now know who the message is for, let's deal with it! */

  /* Validate the sender is a valid server (not dead/disconnecting) */
  if (!IsServer(sptr) || IsDead(sptr)) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "SASL: Response from invalid/dead server %C, ignoring", sptr);
    return 0;
  }

  /* If we don't know who the agent is we do now, else check its the same agent */
  if (!cli_saslagent(acptr)) {
    cli_saslagent(acptr) = sptr;
    cli_saslagentref(sptr)++;
  } else if (cli_saslagent(acptr) != sptr) {
    /* Check if existing agent is dead - if so, accept new agent */
    if (IsDead(cli_saslagent(acptr)) || !IsServer(cli_saslagent(acptr))) {
      log_write(LS_DEBUG, L_DEBUG, 0,
                "SASL: Previous agent %C is dead, accepting new agent %C",
                cli_saslagent(acptr), sptr);
      if (cli_saslagentref(cli_saslagent(acptr)))
        cli_saslagentref(cli_saslagent(acptr))--;
      cli_saslagent(acptr) = sptr;
      cli_saslagentref(sptr)++;
    } else {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL: Agent mismatch for %C - expected %C, got %C (ignoring response)",
                acptr, cli_saslagent(acptr), sptr);
      return 0;
    }
  }

  if (reply[0] == 'C') {
    sendrawto_one(acptr, MSG_AUTHENTICATE " %s", data);
    return 0;
  } else if (reply[0] == 'L') {
    /* A logged-in client's re-authentication that services answer with
     * another account is refused here, as soon as the account is known and
     * before anything of it is kept: the client keeps its login and its
     * record (sasl_reauth_refused(), the rule sasl_login_apply() applies to
     * every tier).  The exchange ends; the D S that follows finds no
     * cookie and reaches nobody, and services announce nothing for it. */
    if (sasl_reauth_refused(acptr, data, NULL)) {
      sasl_relay_end(acptr);
      return 0;
    }
    /* The account (and creation time) services name for this exchange,
     * kept for its D S (sasl_complete_login()).  Not the login identity
     * yet: that is the success's to set, and a REGISTER login landing
     * before it (draft/account-registration: the two may overlap) writes
     * the identity meanwhile.  No timestamp in the reply: none, not an
     * earlier attempt's. */
    ircd_strncpy(cli_saslnamed(acptr), data, sizeof(cli_saslnamed(acptr)));
    cli_saslnamedts(acptr) = (parc > 5) ? atoi(parv[5]) : 0;
  } else if (reply[0] == 'D') {
    if (data[0] == 'S') {
      /* Success — use shared login completion function, as the account
       * services named in L (else, with no L, the identity as it stands,
       * as before).  Its result says whether acptr survived the
       * registration it resumed; cptr is the server link, so it must not
       * be returned from here, and nothing touches acptr after it. */
      char named[ACCOUNTLEN + 1];
      time_t named_ts = cli_saslnamedts(acptr);

      ircd_strncpy(named, cli_saslnamed(acptr)[0] ? cli_saslnamed(acptr)
                                                  : cli_saslaccount(acptr),
                   sizeof(named));
      if (!cli_saslnamed(acptr)[0])
        named_ts = cli_saslacccreate(acptr);
      cli_saslnamed(acptr)[0] = '\0';
      cli_saslnamedts(acptr) = 0;
      sasl_complete_login(acptr, named, named_ts, NULL, 0);   /* the wire from X3 carries no id */
      return 0;
    } else if (data[0] == 'F') {
      send_reply(acptr, ERR_SASLFAIL, "");
    } else if (data[0] == 'A') {
      send_reply(acptr, ERR_SASLABORTED);
    }
    /* Cleanup for failure/abort cases (success cleanup is in sasl_complete_login) */
    sasl_relay_end(acptr);
    return 0;
  } else if (reply[0] == 'M') {
    /* RPL_SASLMECHS lists what the sasl capability advertises, not the
     * services' own list: with the local Keycloak tier the two differ
     * (sasl=PLAIN,OAUTHBEARER,SCRAM-SHA-256 against services' PLAIN), and a
     * client that rebuilds its list from 908 would drop working
     * mechanisms.  Services' list only when the capability has none. */
    const char *mechs = cap_sasl_mechanisms();
    return send_reply(acptr, ERR_SASLMECHS, mechs ? mechs : data);
  }

  return 0;
}

int abort_sasl(struct Client* cptr, int timeout) {
  struct Client* acptr;

  if (t_active(&cli_sasltimeout(cptr)))
    timer_del(&cli_sasltimeout(cptr));

  /* Nothing in flight, or the exchange completed (a cookie left with the
   * flag: none since an IAuth success drops its own).  A REGISTER login meanwhile completes no exchange: one
   * still in flight is aborted, and its timeout fires (IsSASLExchangeDone). */
  if (!cli_saslcookie(cptr) || IsSASLExchangeDone(cptr))
    return 0;

  /* Look up the target server */
  if (!(acptr = cli_saslagent(cptr))) {
    if (strcmp(feature_str(FEAT_SASL_SERVER), "*"))
      acptr = find_match_server((char *)feature_str(FEAT_SASL_SERVER));
    else
      acptr = NULL;
  }

  /* Validate agent is still a valid, connected server */
  if (acptr && (IsDead(acptr) || !IsServer(acptr))) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "SASL abort: Agent %C is dead/invalid, broadcasting instead", acptr);
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
  EndSASLExchange(cptr);

  /* Drop the registration hold.  Do not resume registration from
   * here: auth_complete_sasl() calls this from inside
   * check_auth_finished(), and exit_client() calls it on a client
   * that is already closing.  The SASL timeout resumes explicitly. */
  if (cli_auth(cptr))
    auth_sasl_clear(cli_auth(cptr));

  return 0;
}

