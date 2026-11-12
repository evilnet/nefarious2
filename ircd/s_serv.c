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
#include "metadata_sync.h"
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

/** Send every network ban we hold (G-lines, shuns, jupes, Z-lines) to a
 * directly linked server, each with its lastmod.
 * @param cptr The link.
 */
static void server_ban_burst(struct Client *cptr)
{
  gline_burst(cptr);
  shun_burst(cptr);
  jupe_burst(cptr);
  zline_burst(cptr);
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
    int holdmark = feature_bool(FEAT_P10_MESSAGE_TAGS);

    if (aconf->passwd[0])
      sendrawto_one(cptr, MSG_PASS " :%s", aconf->passwd);
    /*
     *  Pass my info to the new server.
     *  Flag string: h=hub, 6=ipv6, o=oplevels, v=IRCv3-aware S2S extensions,
     *               F=BX F (reconcile-end) handshake supported,
     *               H=bouncer hold mark (,H) stamped and relayed -- only
     *                 while P10_MESSAGE_TAGS is on, as the mark rides the
     *                 compact tags.
     *  Legacy peers ignore unknown flag chars (set_server_flags has no
     *  default in its switch).
     */
    sendrawto_one(cptr, MSG_SERVER " %s 1 %Tu %Tu J%s %s%s +%s6%svF%s :%s",
		  cli_name(&me), cli_serv(&me)->timestamp,
		  cli_serv(cptr)->timestamp, MAJOR_PROTOCOL, NumServCap(&me),
		  feature_bool(FEAT_HUB) ? "h" : "",
                  feature_bool(FEAT_OPLEVELS) ? "o" : "",
                  holdmark ? "H" : "",
		  *(cli_info(&me)) ? cli_info(&me) : "IRCers United");
    if (holdmark)
      SetHoldMarkSent(cptr);
  }

  det_confs_butmask(cptr, CONF_SERVER | CONF_UWORLD);

  if (!IsHandshake(cptr))
    hAddClient(cptr);
  SetServer(cptr);
  cli_handler(cptr) = SERVER_HANDLER;
  Count_unknownbecomesserver(UserStats);
  SetBurst(cptr);
  /* This link's incarnation: a record keyed by the link's Client pointer
   * (which the Client freelist hands out again) also names the serial, so
   * it never reads as the next link's. */
  {
    static unsigned long link_serials;
    cli_serv(cptr)->link_serial = ++link_serials;
  }
  /* Its away merge window opens: until its barrier PONG, a session away
   * decision due on a line from it is decided once, at that PONG (W3 Task
   * 16 fix round 5). */
  bounce_away_merge_link_up(cptr);

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
		  "%s 2 0 %Tu J%02u %s%s +%s%s%s%s%s%s%s%s :%s", cli_name(cptr),
		  cli_serv(cptr)->timestamp, Protocol(cptr), NumServCap(cptr),
		  IsHub(cptr) ? "h" : "", IsService(cptr) ? "s" : "",
		  IsIPv6(cptr) ? "6" : "", IsOpLevels(cptr) ? "o" : "",
		  IsIRCv3Aware(cptr) ? "v" : "",
		  IsRenameCapable(cptr) ? "r" : "",
		  IsBxfAware(cptr) ? "F" : "",
		  IsHoldMark(cptr) ? "H" : "",
                  cli_info(cptr));
  }

  /* Send these as early as possible so that glined users/zlined users/juped servers can
   * be removed from the network while the remote server is still chewing
   * our burst.  A gated link gets them again at release
   * (server_release_burst_gate()).
   */
  server_ban_burst(cptr);

  /* Burst webpush subscriptions to newly linked server.  Gate on
   * IsIRCv3Aware like ML below — legacy peers (X3) error on unknown
   * tokens, and X3's snoop was echoing every WP B into its log channel. */
  if (feature_bool(FEAT_CAP_draft_webpush) && IsIRCv3Aware(cptr))
    webpush_burst(cptr);

  /* Bouncer sessions are burst AFTER client introduction (below) so that
   * BS A can resolve ghost numerics via findNUser(). */

  /* Advertise multiline capability — legacy servers (X3, vanilla ircu)
   * log PARSE ERROR on ML.  Gate on IsIRCv3Aware(cptr).  Comment about
   * "legacy servers ignore" was wrong: X3 explicitly errors on unknown
   * tokens.  The other ML-capable servers we know are announced below,
   * after the SERVER lines that introduce them.
   */
  if (feature_bool(FEAT_CAP_draft_multiline) && IsIRCv3Aware(cptr))
    sendcmdto_one(&me, CMD_MULTILINE, cptr, "%d %d",
                  feature_int(FEAT_MULTILINE_MAX_BYTES),
                  feature_int(FEAT_MULTILINE_MAX_LINES));

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
		    "%s %d 0 %Tu %s%u %s%s +%s%s%s%s%s%s%s%s :%s", cli_name(acptr),
		    cli_hopcount(acptr) + 1, cli_serv(acptr)->timestamp,
		    protocol_str, Protocol(acptr), NumServCap(acptr),
		    IsHub(acptr) ? "h" : "", IsService(acptr) ? "s" : "",
		    IsIPv6(acptr) ? "6" : "", IsOpLevels(acptr) ? "o" : "",
		    IsIRCv3Aware(acptr) ? "v" : "",
		    IsRenameCapable(acptr) ? "r" : "",
		    IsBxfAware(acptr) ? "F" : "",
		    IsHoldMark(acptr) ? "H" : "",
                    cli_info(acptr));
    }
  }

  /* Burst the ML capability of every other ML-capable server we know, so
   * that when server C links to B after A already linked to B, C learns
   * about A's capability (not just B's).  Only now, after the SERVER lines
   * above: an "<A> ML" sent before A's introduction has a prefix the new
   * server does not know yet, so it dropped the line and never knew A
   * takes ML -- and the originating server of a multiline batch decides by
   * the ML flag of every server on the way (ml_route_carries_multiline).
   * Exactly the servers whose SERVER line went out above. */
  if (feature_bool(FEAT_CAP_draft_multiline) && IsIRCv3Aware(cptr)) {
    struct Client *srv;
    for (srv = GlobalClientList; srv; srv = cli_next(srv)) {
      if (!IsServer(srv) || cli_from(srv) == cptr || !IsMultiline(srv)
          || 0 == match(cli_name(&me), cli_name(srv)))
        continue;
      sendcmdto_one(srv, CMD_MULTILINE, cptr, "%u %u",
                    cli_serv(srv)->ml_max_bytes,
                    cli_serv(srv)->ml_max_lines);
    }
  }

  /* Per redesign D.3: no coordination protocol.  Convergence is
   * deterministic (m_nick at-N-time, sessid lex via cross-sessid BS C
   * rename), so we just need to defer N-emission long enough for
   * loser-side demotes to flip to IsBouncerAlias before our own
   * server_finish_burst's N loop fires.
   *
   * Gate dynamically: only defer when bouncer convergence is actually
   * in flight (any session with hs_restore_pending, or another peer
   * currently IsBurst).  Stable state means our local primary/alias
   * decisions are final and burst-emit is safe to run immediately —
   * no point deferring 30s for no benefit.
   *
   * The 1-second timer (bounce_legacy_burst_gate_tick) plus the
   * event-driven release at convergence-completion sites
   * (bounce_release_idle_gates from hs_restore_pending=0 and
   * ClearBurst) together cover gated-peer release without coordination.
   * BOUNCE_LEGACY_GATE_SECS remains as the stall-fallback ceiling. */
  if (feature_bool(FEAT_BOUNCER_ENABLE) && bounce_have_local_sessions()
      && bounce_convergence_pending(cptr)) {
    SetBurstGated(cptr);
    cli_burst_gate_deadline(cptr) = CurrentTime + BOUNCE_LEGACY_GATE_SECS;
    Debug((DEBUG_INFO,
           "Bouncer: gating peer %s burst until %lld "
           "(convergence in flight: hs_restore_pending or peer IsBurst)",
           cli_name(cptr),
           (long long)cli_burst_gate_deadline(cptr)));
    return 0;
  }

  return server_finish_burst(cptr);
}

/** Send the deferred-able tail of the burst: N tokens for users,
 * BS for bouncer sessions, channel BURST modes, EB.
 *
 * For any peer, IRCv3-aware or legacy: it runs inline at the end of
 * server_estab (the peer's SERVER line) unless bouncer convergence is
 * in flight, in which case server_estab gates the peer and this runs at
 * release instead (server_release_burst_gate()) -- from
 * bounce_release_idle_gates at a convergence-completion site (a peer's
 * EB, an attach or revive) or from the 1-second
 * bounce_legacy_burst_gate_tick fallback.  Either
 * way, by the time we reach this point any active-vs-active demote has
 * flipped its loser to alias state, so the IsBouncerAlias filter on the
 * N loop (and on bounce_burst's session iteration) keeps duplicate
 * racing-nick N's off the wire.
 */
int server_finish_burst(struct Client *cptr)
{
  struct Client *acptr;
  struct SLink *lp;
  /* The burst can run while another link's line is handled (a gate
   * released at a peer's EB, an attach or a revive).  None of its lines
   * is that line's: while it runs no link's stash is the current line's,
   * so the tags a burst line carries are its own (the hint below), never
   * the handled line's msgid, time, session id or hold mark. */
  struct Client *inbound = sendcmdto_inbound_link();

  sendcmdto_set_inbound_link(NULL);

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
      char held_mark;

      /* A legacy peer gets every user of the walk, as it gets every N we
       * relay: aliases are not users of the walk (above), so a session
       * shows one face unless it has two primaries for the moment (two
       * copies of it met after a split and are not merged yet).  Then the
       * legacy peer holds both faces, as a relay would have given it,
       * and the merge retracts the one it converts (a QUIT); the survivor
       * stays known to it.  Holding back all but the first face of a
       * session here left the legacy peer with no face at all once the
       * merge retracted that first one, and its channel members unknown.
       *
       * The first face sent to the peer is noted for the session (CHECK
       * shows it; a later swap or retraction of that face updates it). */
      if (!IsIRCv3Aware(cptr) && IsAccount(acptr)) {
        struct BouncerSession *bs = bounce_get_session(acptr);
        if (bs) {
          char face_buf[6];
          ircd_snprintf(0, face_buf, sizeof(face_buf), "%s%s",
                        cli_yxx(cli_user(acptr)->server), cli_yxx(acptr));
          bounce_session_record_legacy_intro(bs, cli_yxx(cptr), face_buf);
        }
      }

      /* Per redesign A.2: stage the bouncer session-id hint for the
       * outgoing N's ,S compact-tag segment, so bouncer-aware peers
       * can dispatch at-N-time convergence in m_nick.  Only toward an
       * IRCv3-aware peer (a legacy one gets no tag region).
       *
       * The hint is cleared right after the send, not left to
       * format_s2s_tags_with_client, which consumes it only when it
       * uses it.  The burst runs from the burst-gate timer and from
       * callbacks, where no per-line reset follows: a leftover hint would
       * ride the next tagged line (a later burst line, the EB, any timer
       * send) with this user's sessid.  (No link's stash competes with
       * it here: the burst runs with no inbound line, above.)
       *
       * The hint also stages the hold mark (,H) of a user of ours: one
       * computation, so ",S names a session" and the mark agree.  It
       * stages none for a user of another server: only its home server
       * stamps one, and what it stamped then is not known now.  The mark
       * is cleared with the hint, for the same reasons. */
      held_mark = IsIRCv3Aware(cptr) ? bounce_set_n_sessid_hint(acptr) : 0;
      sendcmdto_one(cli_user(acptr)->server, CMD_NICK, cptr,
		    "%s %d %Tu %s %s %s%s%s%s %s%s :%s",
		    cli_name(acptr), cli_hopcount(acptr) + 1, cli_lastnick(acptr),
		    cli_user(acptr)->username, cli_user(acptr)->realhost,
		    *s ? "+" : "", s, *s ? " " : "",
		    iptobase64(xxx_buf, &cli_ip(acptr), sizeof(xxx_buf), IsIPv6(cptr)),
		    NumNick(acptr), cli_info(acptr));
      sendcmdto_set_s2s_sessid(NULL);
      sendcmdto_set_s2s_held(0);
      /* The mark this link's server will decide from, should one of its
       * own clients meet ours on this nick before its burst ends: kept
       * so we decide from the same snapshot (a socket that dies, or an
       * alias that leaves, in the meantime changes nothing). */
      if (held_mark && bounce_hold_marks_trusted(cptr))
        bounce_note_burst_stamp(acptr, cptr, held_mark);

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
        /* SSLCLIEXP and WEBSOCKET are fork-only MARK types; a legacy
         * next hop doesn't understand them, so skip them in the burst
         * to a non-IRCv3-aware peer (wire-hygiene rule). */
        if (feature_bool(FEAT_CERT_EXPIRY_TRACKING) && cli_sslcliexp(acptr) > 0 &&
            IsIRCv3Aware(cptr))
          sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%lu",
                        cli_name(acptr), MARK_SSLCLIEXP, (unsigned long)cli_sslcliexp(acptr));
      }

      if (!EmptyString(cli_wsorigin(acptr)) && IsIRCv3Aware(cptr))
        sendcmdto_one(cli_user(acptr)->server, CMD_MARK, cptr, "%s %s :%s",
                      cli_name(acptr), MARK_WEBSOCKET, cli_wsorigin(acptr));

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

      /* Burst user metadata if enabled.  MD is an IRCv3-aware extension —
       * legacy peers (X3, vanilla ircu) log PARSE ERROR on receipt.
       *
       * W4 Task 8: never by nick unless nothing else names the user.  A
       * logged-in user's keys go as the account's stamped rows
       * ("MD =account") under the stamp the store holds, so the peer
       * merges them by last-writer-wins instead of taking whatever it is
       * sent (a key the store has no row for -- no store, or a row never
       * written there -- goes under stamp 0.0.0, which any stamped row
       * beats).  Another user's keys go by its session id ("MD !sessid")
       * when the N above carried it (metadata_session_addressable),
       * else by nick.  Both forms keep the user's own server as the
       * line's origin: the receiver accepts a session- or nick-addressed
       * write only from there. */
      if (feature_bool(FEAT_METADATA_BURST) && IsIRCv3Aware(cptr)) {
        struct MetadataEntry *entry;
        const char *account = cli_user(acptr)->account;

        for (entry = cli_metadata(acptr); entry; entry = entry->next) {
          const char *vis_tok = entry->visibility == METADATA_VIS_PRIVATE ? "P" : "*";
          const char *value = entry->value ? entry->value : "";

          if (account[0]) {
            struct md_version v;
            char valbuf[METADATA_VALUE_LEN];

            /* An internal key (last_present, loaded into memory with the
             * account's rows; a key the wire validator refuses) is this
             * server's own: never a stamped row on the wire (push-2
             * final fix wave, M-2). */
            if (!md_key_replicable(entry->key))
              continue;
            if (!metadata_lmdb_is_available()
                || metadata_account_get_version(account, entry->key, &v,
                                                valbuf, sizeof(valbuf)) != 0) {
              memset(&v.st, 0, sizeof(v.st));
              v.tombstone = 0;
              v.vis = entry->visibility;
              v.value = value;
              v.vlen = strlen(value);
            }
            metadata_emit_versioned(cli_user(acptr)->server, cptr, NULL,
                                    account, entry->key, &v);
          } else if (metadata_session_addressable(acptr)) {
            sendcmdto_one(cli_user(acptr)->server, CMD_METADATA, cptr, "!%s %s %s :%s",
                          cli_session_id(acptr), entry->key, vis_tok, value);
          } else {
            sendcmdto_one(cli_user(acptr)->server, CMD_METADATA, cptr, "%s %s %s :%s",
                          cli_name(acptr), entry->key, vis_tok, value);
          }
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
    for (chptr = GlobalChannelList; chptr; chptr = chptr->next) {
      send_channel_modes(cptr, chptr);
      /* A relocation tombstone's BURST says only "+z, +L <target>"; its
       * record follows, so that the new link dissolves it on time too. */
      relocate_burst(cptr, chptr);
    }
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
  sendcmdto_set_inbound_link(inbound);
  return 0;
}

/** Release a link's burst gate: send the ban bursts again, then the
 * deferred tail of the burst (server_finish_burst()).
 *
 * While the link was gated, every ban change (GL, SU, JU, ZL) relayed
 * through the serv_butone senders was held back from it: an oper's
 * carries the oper's numeric, which the link does not know yet, and a
 * stock server drops a ban line from an unknown prefix
 * (bounce_burst_gate_passes()).  The burst tail carries no ban, so the
 * ban bursts go again here, ahead of it as in server_estab.  A ban the
 * link already has comes with the same lastmod and is a no-op there;
 * one it has newer is left alone while we are still bursting to it
 * (IsBurstOrBurstAck on its side until our EB, which ends the tail).
 * A ban removed with REMOVE while the link was gated is not in our
 * lists any more and cannot be carried this way.
 *
 * The two release paths call this: bounce_release_idle_gates (the wait
 * is over) and bounce_legacy_burst_gate_tick (the deadline passed).
 * @param cptr The gated link.
 * @return Zero.
 */
int server_release_burst_gate(struct Client *cptr)
{
  /* As in server_finish_burst: the release can run while another link's
   * line is handled, and none of these lines is that line's. */
  struct Client *inbound = sendcmdto_inbound_link();

  cli_burst_gate_deadline(cptr) = 0;
  ClearBurstGated(cptr);

  sendcmdto_set_inbound_link(NULL);
  server_ban_burst(cptr);
  sendcmdto_set_inbound_link(inbound);

  {
    int ret = server_finish_burst(cptr);

    /* Our burst is fully out now: when the link's own end of burst came
     * already (it waited behind the gate), the holder's away barrier PING
     * goes, and its PONG restates the sessions' away decisions to the link
     * (bounce_away_restate_to(); W3 Task 16 fix rounds 2 and 4). */
    if (!IsBurst(cptr))
      bounce_away_restate_to(cptr);
    return ret;
  }
}

