/*
 * IRC - Internet Relay Chat, ircd/m_quit.c
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
 * $Id: m_quit.c 1271 2004-12-11 05:14:07Z klmitch $
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

#include "bouncer_session.h"
#include "channel.h"
#include "client.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "struct.h"
#include "s_misc.h"
#include "ircd_reply.h"
#include "send.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

/*
 * m_quit - client message handler 
 *
 * parv[0]        = sender prefix
 * parv[parc - 1] = comment
 */
int m_quit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  int stripquit = 0;
  int blockcolor = 0;
  int stripcolor = 0;
  const char* text;

  assert(0 != cptr);
  assert(0 != sptr);
  assert(cptr == sptr);

  /* Bouncer alias: skip all hold logic — just clean up.
   * exit_client() sends BX X to notify other servers. */
  if (IsBouncerAlias(sptr))
    return exit_client(cptr, sptr, sptr, "Quit");

  /* Fix #25: Check if client should enter bouncer HOLD mode instead of
   * quitting.  Clients routinely send QUIT on disconnect — the whole
   * purpose of hold is to survive that and keep channels alive.
   *
   * Immediate-promote (design intent: clean primary QUIT with alias
   * remaining → BX P numeric swap, NO HOLDING transition).  We only
   * promote inline if the chosen alias is on THIS server — same-server
   * alias state is synchronously authoritative, so the BX P broadcast
   * can't race a concurrent BX X from the alias's home server (we ARE
   * that server).  When every alias is on a remote server, fall
   * through to bounce_hold_client; the existing hold-expire path
   * still promotes, just with the safety of network-settled state.
   * (Cross-server immediate-promote without a race window is a v2.)
   *
   * On successful inline promote: the session continues under the new
   * primary, the old primary's channels are silently stripped by
   * bounce_promote_alias, and we fall through to normal exit_client
   * which produces no visible QUIT to channels (none left to send to).
   * Peers see BX P + BS T then the primary's clean Q. */
  if (IsUser(sptr) && bounce_should_hold(sptr)) {
    const char *comment = (parc > 1 && !BadPtr(parv[parc - 1]))
                          ? parv[parc - 1] : "Quit";
    struct BouncerSession *bsess = bounce_get_session(sptr);
    int promoted = -1;
    if (bsess && bsess->hs_client == sptr && bsess->hs_alias_count > 0)
      promoted = bounce_promote_alias(bsess, 1 /* local_only */);
    if (promoted == 0) {
      /* Inline local promote succeeded; fall through to exit_client.
       * Channels already stripped, BX P + BS T already broadcast. */
    } else if (bounce_hold_client(sptr, comment) == 0) {
      /* Entered HOLDING.  If a remote alias is available, schedule a
       * 0-tick deferred promote — any concurrent BX X for the chosen
       * winner has a chance to land during the intervening tick, and
       * the timer's re-evaluation picks a still-live alias.  See
       * bounce_schedule_cross_server_promote and Layer 2 of
       * .claude/plans/alias-promote-race-fix.md. */
      if (bsess && bsess->hs_alias_count > 0)
        bounce_schedule_cross_server_promote(bsess);
      return 0; /* Held (will promote at next tick or hold-expire) */
    }
    /* If hold failed too, fall through to normal quit */
  }

  if (cli_user(sptr)) {
    struct Membership* chan;
    for (chan = cli_user(sptr)->channel; chan; chan = chan->next_channel) {
        if (chan->channel->mode.exmode & EXMODE_NOQUITPARTS)
          stripquit = 1;
        if (chan->channel->mode.exmode & EXMODE_NOCOLOR)
          blockcolor = 1;
        if (chan->channel->mode.exmode & EXMODE_STRIPCOLOR)
          stripcolor = 1;
        if (!IsZombie(chan) && !IsDelayedJoin(chan) && !member_can_send_to_channel(chan, 0))
        return exit_client(cptr, sptr, sptr, "Signed off");
    }
  }

  /* UTF8ONLY enforcement on quit message */
  if (parc > 1 && !BadPtr(parv[parc - 1]) &&
      feature_bool(FEAT_UTF8ONLY) && !string_is_valid_utf8(parv[parc - 1])) {
    if (feature_bool(FEAT_UTF8ONLY_STRICT)) {
      /* Strict mode: use default quit message instead of rejecting */
      return exit_client(cptr, sptr, sptr, "Quit");
    }
    /* Warn mode: sanitize the quit message */
    string_sanitize_utf8(parv[parc - 1]);
  }

  if (parc > 1 && !BadPtr(parv[parc - 1]) && !stripquit)
    if (blockcolor && HasColor(parv[parc - 1]))
      return exit_client(cptr, sptr, sptr, "Quit");
    else if (stripcolor) {
      text = StripColor(parv[parc - 1]);
      if (EmptyString(text))
        return exit_client(cptr, sptr, sptr, "Quit");
      else
        return exit_client_msg(cptr, sptr, sptr, "Quit: %s", text);
    } else
      return exit_client_msg(cptr, sptr, sptr, "Quit: %s", parv[parc - 1]);
  else
    return exit_client(cptr, sptr, sptr, "Quit");
}


/*
 * ms_quit - server message handler
 *
 * parv[0] = sender prefix
 * parv[parc - 1] = comment
 */
int ms_quit(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  assert(0 != sptr);
  assert(parc > 0);
  if (IsServer(sptr)) {
  	protocol_violation(sptr,"Server QUIT, not SQUIT?");
  	return 0;
  }
  /*
   * ignore quit from servers
   */
  return exit_client(cptr, sptr, sptr, parv[parc - 1]);
}
