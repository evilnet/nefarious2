/*
 * IRC - Internet Relay Chat, ircd/s_serv.c (formerly ircd/s_msg.c)
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
 * @brief Miscellaneous server support functions.
 * @version $Id: s_serv.c 1438 2005-06-28 00:42:06Z entrope $
 */
#include "config.h"

#include "s_serv.h"
#include "IPcheck.h"
#include "channel.h"
#include "client.h"
#include "gline.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_crypt.h"
#include "jupe.h"
#include "list.h"
#include "mark.h"
#include "match.h"
#include "msg.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "querycmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "shun.h"
#include "struct.h"
#include "sys.h"
#include "userload.h"
#include "zline.h"
#include "metadata.h"
#include "bouncer_session.h"
#include "webpush.h"
#include "ircd_features.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdlib.h>
#include <string.h>

/** Maximum connection count since last restart. */
unsigned int max_connection_count = 0;
/** Maximum (local) client count since last restart. */
unsigned int max_client_count = 0;

/** Squit a new (pre-burst) server.
 * @param cptr Local client that tried to introduce the server.
 * @param sptr Server to disconnect.
 * @param host Name of server being disconnected.
 * @param timestamp Link time of server being disconnected.
 * @param pattern Format string for squit message.
 * @return CPTR_KILLED if cptr == sptr, else 0.
 */
int exit_new_server(struct Client *cptr, struct Client *sptr, const char *host,
                    time_t timestamp, const char *pattern, ...)
{
  struct VarData vd;
  int retval = 0;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  if (!IsServer(sptr))
    retval = vexit_client_msg(cptr, cptr, &me, pattern, vd.vd_args);
  else
    sendcmdto_one(&me, CMD_SQUIT, cptr, "%s %Tu :%v", host, timestamp, &vd);

  va_end(vd.vd_args);

  return retval;
}

/** Indicate whether \a a is between \a b and #me (that is, \a b would
 * be killed if \a a squits).
 * @param a A server that may be between us and \a b.
 * @param b A client that may be on the far side of \a a.
 * @return Non-zero if \a a is between \a b and #me.
 */
int a_kills_b_too(struct Client *a, struct Client *b)
{
  for (; b != a && b != &me; b = cli_serv(b)->up);
  return (a == b ? 1 : 0);
}

/** Handle a connection that has sent a valid PASS and SERVER.
 * @param cptr New peer server.
 * @param aconf Connect block for \a cptr.
 * @return Zero.
 */
int server_estab(struct Client *cptr, struct ConfItem *aconf)
{
  struct Client* acptr = 0;
  const char*    inpath;
  int            i;

  assert(0 != cptr);
  assert(0 != cli_local(cptr));

  inpath = cli_name(cptr);

  if (IsUnknown(cptr)) {
    if (aconf->passwd[0])
      sendrawto_one(cptr, MSG_PASS " :%s", aconf->passwd);
    /*
     *  Pass my info to the new server.
     *  Flag string: h=hub, 6=ipv6, o=oplevels, v=IRCv3-aware S2S extensions,
     *               F=BX F (reconcile-end) handshake supported.
     *  Legacy peers ignore unknown flag chars (set_server_flags has no
     *  default in its switch).
     */
    sendrawto_one(cptr, MSG_SERVER " %s 1 %Tu %Tu J%s %s%s +%s6%svF :%s",
		  cli_name(&me), cli_serv(&me)->timestamp,
		  cli_serv(cptr)->timestamp, MAJOR_PROTOCOL, NumServCap(&me),
		  feature_bool(FEAT_HUB) ? "h" : "",
                  feature_bool(FEAT_OPLEVELS) ? "o" : "",
		  *(cli_info(&me)) ? cli_info(&me) : "IRCers United");
  }

  det_confs_butmask(cptr, CONF_SERVER | CONF_UWORLD);

  if (!IsHandshake(cptr))
    hAddClient(cptr);
  SetServer(cptr);
  cli_handler(cptr) = SERVER_HANDLER;
  Count_unknownbecomesserver(UserStats);
  SetBurst(cptr);

/*    nextping = CurrentTime; */

  /*
   * NOTE: check for acptr->user == cptr->serv->user is necessary to insure
   * that we got the same one... bleah
   */
  if (cli_serv(cptr)->user && *(cli_serv(cptr))->by &&
      (acptr = findNUser(cli_serv(cptr)->by))) {
    if (cli_user(acptr) == cli_serv(cptr)->user) {
      sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :Link with %s established.",
                    acptr, inpath);
    }
    else {
      /*
       * if not the same client, set by to empty string
       */
      acptr = 0;
      *(cli_serv(cptr))->by = '\0';
    }
  }

  sendto_opmask_butone(acptr, SNO_OLDSNO, "Link with %s established.", inpath);
  cli_serv(cptr)->up = &me;
  cli_serv(cptr)->updown = add_dlink(&(cli_serv(&me))->down, cptr);
  sendto_opmask_butone(0, SNO_NETWORK, "Net junction: %s %s", cli_name(&me),
                       cli_name(cptr));
  SetJunction(cptr);
  /*
   * Old sendto_serv_but_one() call removed because we now
   * need to send different names to different servers
   * (domain name matching) Send new server to other servers.
   */
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(acptr = LocalClientArray[i]) || !IsServer(acptr) ||
        acptr == cptr || IsMe(acptr))
      continue;
    if (!match(cli_name(&me), cli_name(cptr)))
      continue;
    sendcmdto_one(&me, CMD_SERVER, acptr,
		  "%s 2 0 %Tu J%02u %s%s +%s%s%s%s%s%s :%s", cli_name(cptr),
		  cli_serv(cptr)->timestamp, Protocol(cptr), NumServCap(cptr),
		  IsHub(cptr) ? "h" : "", IsService(cptr) ? "s" : "",
		  IsIPv6(cptr) ? "6" : "", IsOpLevels(cptr) ? "o" : "",
		  IsIRCv3Aware(cptr) ? "v" : "",
		  IsBxfAware(cptr) ? "F" : "",
                  cli_info(cptr));
  }

  /* Send these as early as possible so that glined users/zlined users/juped servers can
   * be removed from the network while the remote server is still chewing
   * our burst.
   */
  gline_burst(cptr);
  shun_burst(cptr);
  jupe_burst(cptr);
  zline_burst(cptr);

  /* Burst webpush subscriptions to newly linked server */
  if (feature_bool(FEAT_CAP_draft_webpush))
    webpush_burst(cptr);

  /* Bouncer sessions are burst AFTER client introduction (below) so that
   * BS A can resolve ghost numerics via findNUser(). */

  /* Advertise multiline capability - legacy servers ignore, modern sets flag.
   * Also burst ML capability for all known ML-capable servers so that when
   * server C links to B after A already linked to B, C learns about A's
   * capability (not just B's).
   */
  if (feature_bool(FEAT_CAP_draft_multiline)) {
    struct Client *srv;
    sendcmdto_one(&me, CMD_MULTILINE, cptr, "%d %d",
                  feature_int(FEAT_MULTILINE_MAX_BYTES),
                  feature_int(FEAT_MULTILINE_MAX_LINES));
    for (srv = GlobalClientList; srv; srv = cli_next(srv)) {
      if (IsServer(srv) && !IsMe(srv) && srv != cptr && IsMultiline(srv))
        sendcmdto_one(srv, CMD_MULTILINE, cptr, "%u %u",
                      cli_serv(srv)->ml_max_bytes,
                      cli_serv(srv)->ml_max_lines);
    }
  }

  /*
   * Pass on my client information to the new server
   *
   * First, pass only servers (idea is that if the link gets
   * canceled because the server was already there,
   * there are no NICK's to be canceled...). Of course,
   * if cancellation occurs, all this info is sent anyway,
   * and I guess the link dies when a read is attempted...? --msa
   *
   * Note: Link cancellation to occur at this point means
   * that at least two servers from my fragment are building
   * up connection this other fragment at the same time, it's
   * a race condition, not the normal way of operation...
   */

  for (acptr = &me; acptr; acptr = cli_prev(acptr)) {
    /* acptr->from == acptr for acptr == cptr */
    if (cli_from(acptr) == cptr)
      continue;
    if (IsServer(acptr)) {
      const char* protocol_str;

      if (Protocol(acptr) > 9)
        protocol_str = IsBurst(acptr) ? "J" : "P";
      else
        protocol_str = IsBurst(acptr) ? "J0" : "P0";

      if (0 == match(cli_name(&me), cli_name(acptr)))
        continue;
      sendcmdto_one(cli_serv(acptr)->up, CMD_SERVER, cptr,
		    "%s %d 0 %Tu %s%u %s%s +%s%s%s%s%s%s :%s", cli_name(acptr),
		    cli_hopcount(acptr) + 1, cli_serv(acptr)->timestamp,
		    protocol_str, Protocol(acptr), NumServCap(acptr),
		    IsHub(acptr) ? "h" : "", IsService(acptr) ? "s" : "",
		    IsIPv6(acptr) ? "6" : "", IsOpLevels(acptr) ? "o" : "",
		    IsIRCv3Aware(acptr) ? "v" : "",
		    IsBxfAware(acptr) ? "F" : "",
                    cli_info(acptr));
    }
  }

  /* Per redesign D.3: no coordination protocol.  Convergence is
   * deterministic (m_nick at-N-time, sessid lex via cross-sessid BS C
   * rename), so we just need to defer N-emission long enough for
   * loser-side demotes to flip to IsBouncerAlias before our own
   * server_finish_burst's N loop fires.  The legacy-peer burst gate
   * does this with a timer fallback — no BX F handshake.
   *
   * The same gate applies regardless of peer flavor when we hold
   * local bouncer sessions: BX-aware peers will exchange their state
   * via BS C / BX C in their own server_finish_burst, and at-N-time
   * m_nick handles the symmetric election locally on each side.
   * Legacy peers see only the surviving face per design intent #135 +
   * #254 (alias-side N is filtered by IsBouncerAlias). */
  if (feature_bool(FEAT_BOUNCER_ENABLE) && bounce_have_local_sessions()) {
    SetBurstGated(cptr);
    cli_burst_gate_deadline(cptr) = CurrentTime + BOUNCE_LEGACY_GATE_SECS;
    Debug((DEBUG_INFO,
           "Bouncer: gating peer %s burst until %lld "
           "(local sessions present, deterministic convergence)",
           cli_name(cptr),
           (long long)cli_burst_gate_deadline(cptr)));
    return 0;
  }

  return server_finish_burst(cptr);
}

/** Send the deferred-able tail of the burst: N tokens for users,
 * BS for bouncer sessions, channel BURST modes, EB.
 *
 * For IRCv3-aware peers this runs from the BX F handler after both
 * sides' reconcile is complete; for legacy peers it runs inline at the
 * end of server_estab.  Either way, by the time we reach this point any
 * active-vs-active demote has flipped its loser to alias state, so the
 * IsBouncerAlias filter on the N loop (and on bounce_burst's session
 * iteration) keeps duplicate racing-nick N's off the wire.
 */
int server_finish_burst(struct Client *cptr)
{
  struct Client *acptr;
  struct SLink *lp;

  for (acptr = &me; acptr; acptr = cli_prev(acptr))
  {
    /* acptr->from == acptr for acptr == cptr */
    if (cli_from(acptr) == cptr)
      continue;
    /* Burst users.  Aliases (IsBouncerAlias) are filtered out — they
     * are introduced via BX C, not N, and never N-bursted to anyone.
     *
     * Held ghosts (IsBouncerHold) ARE bursted as standard N to all
     * peers, including non-IRCv3-aware ones.  Held ghosts represent
     * a real user in absentia (account-anchored, persisted across
     * restart) — legacy peers see them as regular users, and when
     * the ghost is destroyed without an alias to take over (no
     * promotion), exit_client emits a normal Q on legacy after
     * ClearBouncerHold (the IsBouncerHold suppression in exit_client
     * is dropped by the time Q broadcasts run, see bounce_hold_expire).
     * Routing PRIVMSGs to the held nick + chathistory storage works
     * naturally because legacy peers route by nick to its home server,
     * which has the ghost as a local Client struct with the bouncer
     * hold flag still set.
     *
     * Multi-bouncer collision (both peers have a hold ghost for the
     * same session) is resolved at-N-time by m_nick's deterministic
     * D.2 tiebreaker; the loser-side primary is flipped to alias
     * before any N-burst is filtered through IsBouncerAlias here. */
    if (IsUser(acptr) && !IsBouncerAlias(acptr))
    {
      char xxx_buf[25];
      char *s = umode_str(acptr);

      /* Legacy-face suppression: if cptr is a non-IRCv3-aware peer and
       * acptr's bouncer session has already had a face introduced toward
       * cptr (typically by an earlier walk-step on a different session
       * connection, or by an inbound burst that's already been forwarded
       * here), skip the entire user introduction block.  Per design:
       * legacy peers see exactly one N per session — BX-aware side may
       * juggle primary/alias state internally without disturbing
       * legacy's view.  The recorded face's local Client struct stays
       * alive (becomes IsBouncerAlias on demote) and routing back to
       * legacy resolves through it. */
      if (!IsIRCv3Aware(cptr) && IsAccount(acptr)) {
        if (bounce_account_legacy_face_for(cli_account(acptr),
                                            cli_yxx(cptr))) {
          Debug((DEBUG_INFO,
                 "Bouncer: burst-suppressing N for %s to legacy %s "
                 "— account already has a face there",
                 cli_name(acptr), cli_name(cptr)));
          continue;
        }
        {
          struct BouncerSession *bs = bounce_get_session(acptr);
          if (!bs)
            bs = bounce_find_any_session(cli_account(acptr));
          if (bs) {
            char face_buf[6];
            ircd_snprintf(0, face_buf, sizeof(face_buf), "%s%s",
                          cli_yxx(cli_user(acptr)->server), cli_yxx(acptr));
            bounce_session_record_legacy_intro(bs, cli_yxx(cptr), face_buf);
          }
        }
      }

      /* Per redesign A.2: stage the bouncer session-id hint for the
       * outgoing N's ,S compact-tag segment.  No-op for non-bouncer
       * clients.  Bouncer-aware peers parse it for at-N-time
       * convergence dispatch in m_nick. */
      bounce_set_n_sessid_hint(acptr);
      sendcmdto_one(cli_user(acptr)->server, CMD_NICK, cptr,
		    "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
		    cli_name(acptr), cli_hopcount(acptr) + 1, cli_lastnick(acptr),
		    cli_user(acptr)->username, cli_user(acptr)->realhost,
		    *s ? "+" : "", s, *s ? " " : "",
		    iptobase64(xxx_buf, &cli_ip(acptr), sizeof(xxx_buf), IsIPv6(cptr)),
		    NumNick(acptr), cli_info(acptr));

      if (cli_user(acptr) && !EmptyString(cli_user(acptr)->swhois))
        sendcmdto_one(cli_user(acptr)->server, CMD_SWHOIS, cptr, "%C :%s", acptr,
                      cli_user(acptr)->swhois);

      if (cli_version(acptr) && !EmptyString(cli_version(acptr)))
        sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%s",
                      cli_name(acptr), MARK_CVERSION, cli_version(acptr));

      if (cli_webirc(acptr) && !EmptyString(cli_webirc(acptr)))
        sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%s",
                      cli_name(acptr), MARK_WEBIRC, cli_webirc(acptr));

      for (lp = cli_marks(acptr); lp; lp = lp->next) {
        sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%s",
                      cli_name(acptr), MARK_MARK, lp->value.cp);
      }

      if (cli_sslclifp(acptr) && !EmptyString(cli_sslclifp(acptr))) {
        sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%s",
                      cli_name(acptr), MARK_SSLCLIFP, cli_sslclifp(acptr));
        if (feature_bool(FEAT_CERT_EXPIRY_TRACKING) && cli_sslcliexp(acptr) > 0)
          sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%lu",
                        cli_name(acptr), MARK_SSLCLIEXP, (unsigned long)cli_sslcliexp(acptr));
      }

      if (cli_killmark(acptr) && !EmptyString(cli_killmark(acptr)))
        sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%s",
                      cli_name(acptr), MARK_KILL, cli_killmark(acptr));

      if (IsGeoIP(acptr)) {
        if (cli_countrycode(acptr) && !EmptyString(cli_countrycode(acptr)) &&
            cli_continentcode(acptr) && !EmptyString(cli_continentcode(acptr)))
          sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s %s %s :%s",
                        cli_name(acptr), MARK_GEOIP, cli_countrycode(acptr),
                        cli_continentcode(acptr), cli_countryname(acptr));
      }

      if (feature_bool(FEAT_SILENCE_CHANMSGS)) {
        char buf[BUFSIZE];
        size_t buf_used = 0;
        size_t slen = 0;
        struct Ban *sile;

        for (sile = cli_user(acptr)->silence; sile; sile = sile->next) {
          slen = strlen(sile->banstr);

          if (buf_used + slen + 4 > 400) {
            buf[buf_used] = '\0';
            sendcmdto_one(acptr, CMD_SILENCE, cptr, "* %s", buf);
            buf_used = 0;
          }

          if (buf_used)
            buf[buf_used++] = ',';
          buf[buf_used++] = '+';
          if (sile->flags & BAN_EXCEPTION)
            buf[buf_used++] = '~';
          memcpy(buf + buf_used, sile->banstr, slen);
          buf_used += slen;
        }

        if (buf_used) {
          buf[buf_used] = '\0';
          sendcmdto_one(acptr, CMD_SILENCE, cptr, "* %s", buf);
          buf_used = 0;
        }
      }

      client_send_privs(cli_user(acptr)->server, cptr, acptr);

      /* Burst user metadata if enabled */
      if (feature_bool(FEAT_METADATA_BURST)) {
        struct MetadataEntry *entry;
        for (entry = cli_metadata(acptr); entry; entry = entry->next) {
          sendcmdto_one(cli_user(acptr)->server, CMD_METADATA, cptr, "%C %s %s :%s",
                        acptr, entry->key,
                        entry->visibility == METADATA_VIS_PRIVATE ? "P" : "*",
                        entry->value ? entry->value : "");
        }
      }
    }
  }

  /* Burst bouncer sessions AFTER client introduction so that BS A can
   * resolve ghost/primary numerics via findNUser().  If sent before N
   * tokens, the leaf can't link sessions to their clients. */
  if (feature_bool(FEAT_BOUNCER_ENABLE))
    bounce_burst(cptr);

  /*
   * Last, send the BURST.
   * (Or for 2.9 servers: pass all channels plus statuses)
   */
  {
    struct Channel *chptr;
    for (chptr = GlobalChannelList; chptr; chptr = chptr->next)
      send_channel_modes(cptr, chptr);
  }
  sendcmdto_one(&me, CMD_END_OF_BURST, cptr, "");
  /* Pair EA with EB so the EOB handshake completes symmetrically even
   * when our EB is delayed relative to peer's (e.g., legacy-peer burst
   * gate).  In normal symmetric flow, peer's m_endburst_ack on receiving
   * this trailing EA clears its FLAG_BURST_ACK on us — when EBs were
   * close in time the clear lines up with their set.  When our EB is
   * late, peer's BURST_ACK on us was set when our EB arrived; their
   * earlier EA (from their m_endburst processing our peer-EB-before-
   * gate) was sent before that set existed and so cleared nothing.
   * The trailing EA here is the correction that lands after peer's
   * BURST_ACK is set, clearing the ! marker in /MAP and /STATS u. */
  sendcmdto_one(&me, CMD_END_OF_BURST_ACK, cptr, "");
  return 0;
}

