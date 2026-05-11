/*
 * IRC - Internet Relay Chat, ircd/m_end_of_burst.c
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
 * $Id: m_endburst.c 1411 2005-05-30 13:14:54Z entrope $
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
#include "capab.h"
#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "ircd_features.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */

/*
 * ms_end_of_burst - server message handler
 * - Added Xorath 6-14-96, rewritten by Run 24-7-96
 * - and fixed by record and Kev 8/1/96
 * - and really fixed by Run 15/8/96 :p
 * This the last message in a net.burst.
 * It clears a flag for the server sending the burst.
 *
 * As of 10.11, to fix a bug in the way BURST is processed, it also
 * makes sure empty channels are deleted
 *
 * parv[0] - sender prefix
 */
int ms_end_of_burst(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Channel *chan, *next_chan;

  assert(0 != cptr);
  assert(0 != sptr);

  sendto_opmask_butone(0, SNO_NETWORK, "Completed net.burst from %C.",
  	sptr);
  sendcmdto_serv_butone(sptr, CMD_END_OF_BURST, cptr, "");

  /* End IRCv3 netjoin batch for local clients */
  send_netjoin_batch_end(sptr);

  ClearBurst(sptr);
  SetBurstAck(sptr);

  /* (BX R retired in Phase 5; convergence is at-N-time per redesign
   * D.1 + D.3 — no EOB demote-retry pass.) */

  /* Drain any deferred local-user registrations.  These were queued by
   * check_auth_finished when SASL completed mid-burst — registering
   * immediately would have created a fresh standalone primary racing
   * peer's in-flight N for the same account.  Only drain when no peer
   * is still bursting; otherwise wait for the last EOB to fire. */
  if (!bounce_burst_in_progress())
    bounce_drain_pending_registrations();

  /* Prune stale alias entries from all sessions.  A peer's burst is
   * the authoritative source of which numerics it currently holds;
   * any alias entry pointing at an unknown numeric on this peer is
   * stale (peer restarted with a new numeric pool, BX X for the old
   * numeric was never received, or restore-from-DB seeded entries
   * that don't match post-restart state).  Without this prune /CHECK
   * shows "not found" entries forever and session state keeps
   * desyncing across reboot cycles. */
  bounce_prune_stale_aliases();

  if (MyConnect(sptr)) {
    sendcmdto_one(&me, CMD_END_OF_BURST_ACK, sptr, "");

    /* (BX R reconcile moved to pre-burst — see server_estab.  Post-
     * EOB is too late: by then peer's N for hold ghosts has already
     * been processed and any colliding ghosts have already been
     * killed by m_nick.) */

    /* Advertise chathistory storage capability (CH A S) to newly linked server.
     * Only advertise if we have CHATHISTORY_STORE enabled - this indicates we
     * actually store messages locally, not just handle queries.
     * The retention value tells the remote server how far back our history goes.
     *
     * Gate on IsIRCv3Aware(sptr) — legacy peers (X3, vanilla ircu) don't
     * implement the CH token and log "PARSE ERROR" on receipt. */
    if (feature_bool(FEAT_CHATHISTORY_STORE) && IsIRCv3Aware(sptr)) {
      int retention = feature_int(FEAT_CHATHISTORY_RETENTION);
      sendcmdto_one(&me, CMD_CHATHISTORY, sptr, "A S %d", retention);

      /* Layer 1: Also send channel advertisements (CH A F) */
      send_channel_advertisements(sptr);
    }

    /* Forward cached SASL mechanism list to newly linked server.
     * The SASL M broadcast from services only fires once when services
     * first links.  Servers that link later miss it, so we re-send
     * the cached mechanisms from the SASL server.
     */
    {
      const char *mechs = get_sasl_mechanisms();
      if (mechs) {
        const char *sasl_server_name = feature_str(FEAT_SASL_SERVER);
        struct Client *sasl_server = NULL;
        if (strcmp(sasl_server_name, "*"))
          sasl_server = find_match_server((char *)sasl_server_name);
        else
          sasl_server = &me;
        if (sasl_server)
          sendcmdto_one(sasl_server, CMD_SASL, sptr, "* * M :%s", mechs);
      }
    }
  }

  /* Check if the linking server is the SASL server (for legacy X3 support).
   * If SASL_DEFAULT_MECHANISMS is set and no dynamic mechanisms have been
   * received yet, enable SASL with the default mechanisms.
   * Only send CAP NEW if the advertised state actually changes.
   */
  {
    const char *sasl_server = feature_str(FEAT_SASL_SERVER);
    int is_sasl_server = (!strcmp(sasl_server, "*") ||
                          match(sasl_server, cli_name(sptr)) == 0);

    if (is_sasl_server && !get_sasl_mechanisms()) {
      const char *default_mechs = feature_str(FEAT_SASL_DEFAULT_MECHANISMS);
      if (default_mechs && *default_mechs) {
        /* In wildcard mode, SASL was already being advertised (UserStats.servers > 0
         * is always true due to local server), using these same default mechanisms.
         * In specific server mode, SASL wasn't advertised before, so send CAP NEW. */
        int was_already_advertised = !strcmp(sasl_server, "*");

        if (!was_already_advertised) {
          log_write(LS_SYSTEM, L_INFO, 0,
                    "SASL server linked (%C), enabling SASL with default mechanisms: %s",
                    sptr, default_mechs);
          send_cap_notify("sasl", 1, default_mechs);
        }
      }
    }
  }

  /* Count through channels... */
  for (chan = GlobalChannelList; chan; chan = next_chan) {
    next_chan = chan->next;
    if (!chan->members && (chan->mode.mode & MODE_BURSTADDED)) {
      /* Newly empty channel, schedule it for removal. */
      chan->mode.mode &= ~MODE_BURSTADDED;
      sub1_from_channel(chan);
   } else
      chan->mode.mode &= ~MODE_BURSTADDED;
  }

  return 0;
}

/*
 * ms_end_of_burst_ack - server message handler
 *
 * This the acknowledge message of the `END_OF_BURST' message.
 * It clears a flag for the server receiving the burst.
 *
 * parv[0] - sender prefix
 */
int ms_end_of_burst_ack(struct Client *cptr, struct Client *sptr, int parc, char **parv)
{
  if (!IsServer(sptr))
    return 0;

  sendto_opmask_butone(0, SNO_NETWORK, "%C acknowledged end of net.burst.",
		       sptr);
  sendcmdto_serv_butone(sptr, CMD_END_OF_BURST_ACK, cptr, "");
  ClearBurstAck(sptr);

  return 0;
}
