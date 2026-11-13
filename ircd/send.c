/*
 * IRC - Internet Relay Chat, common/send.c
 * Copyright (C) 1990 Jarkko Oikarinen and
 *                    University of Oulu, Computing Center
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
 * @brief Send messages to certain targets.
 * @version $Id: send.c 1909 2009-03-18 03:31:58Z entrope $
 */
#include "config.h"

#include "send.h"
#include "bouncer_session.h"
#include "bouncer_wire.h"
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "crdt_hlc.h"
#include "forwarded_label.h"
#include "client.h"
#include "hash.h"
#include "ircd_alloc.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "m_batch.h"
#include "match.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "parse.h"
#include "persistence_profile.h"
#include "replay.h"
#include "querycmds.h"
#include "s_bsd.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

/** Check if a client is from a U-lined (services) server.
 * @param[in] cptr Client to check.
 * @return Non-zero if client is from a U-lined server.
 */
static int is_from_uline(struct Client *cptr)
{
  struct Client *server;

  if (!cptr || !cli_user(cptr))
    return 0;

  server = cli_user(cptr)->server;
  if (!server)
    return 0;

  return find_conf_byhost(cli_confs(server), cli_name(server), CONF_UWORLD) != NULL;
}

/** Last used marker value. */
static int sentalong_marker;
/** Array of users with the corresponding server notice mask bit set. */
struct SLink *opsarray[32];     /* don't use highest bit unless you change
				   atoi to strtoul in sendto_op_mask() */
/** Linked list of all connections with data queued to send. */
static struct Connection *send_queues;

/** Active network batch ID for netjoin/netsplit batching.
 * When non-empty, all QUIT/JOIN messages to local clients with batch capability
 * will include @batch=<id> tag per IRCv3 netsplit/netjoin batch spec.
 */
static char active_network_batch_id[32] = "";
char *GlobalForwards[256];

/** Global tag context for per-connection CAP routing.
 * Set by channel send functions around their member loop, read by
 * send_buffer() for cap filtering and alias mirror suppression.
 */
struct CapRouteContext cap_route_ctx;


/** Override for S2S tag source connection.
 * When alias source rewriting substitutes a local primary for a remote alias,
 * the cptr computation (MyConnect(from) ? NULL : cli_from(from)) would yield
 * NULL, losing the incoming S2S tags. This preserves the alias's connection
 * so @time and ;msgid are correctly forwarded. Auto-cleared after use.
 */
static struct Client *s2s_cptr_override = NULL;

void sendcmdto_set_s2s_cptr(struct Client *cptr)
{
  s2s_cptr_override = cptr;
}

/** Override alias source for split S2S delivery in channel broadcasts.
 * When set, sendcmdto_channel_butone builds two S2S buffers:
 * - Primary numeric for all servers except the primary's direction
 * - Alias numeric for the primary's server direction (avoids fake direction)
 */
static struct Client *s2s_alias_source = NULL;

void sendcmdto_set_alias_source(struct Client *alias)
{
  s2s_alias_source = alias;
}

/** Override batch ID for forwarded label responses.
 * When non-empty, format_message_tags_for_ex() uses this instead of
 * cli_batch_id(to). Takes priority over use_batch. Auto-cleared after use.
 */
static char fwd_batch_id_override[16] = "";

/** Override S2S time for forwarded command compact tags.
 * When s2s_msgid_override is non-empty, sendcmdto_one uses these instead
 * of computing from cptr. Auto-cleared after use.
 */
static uint64_t s2s_time_override = 0;

/** Override S2S msgid for forwarded command compact tags. */
static char s2s_msgid_override[S2S_MSGID_BUFSIZE] = "";

/** Override S2S session-id hint (compact-tag ,S segment) for the next
 * S2S emit.  Used by N introduction sites to attach a bouncer session
 * UUID v7 to the outgoing message so receiving bouncer-aware peers can
 * dispatch m_nick's convergence rules at-N-time (per redesign A.2).
 * Auto-cleared after use. */
static char s2s_sessid_override[S2S_SESSID_BUFSIZE] = "";

/** Override bouncer hold mark (compact-tag ,H segment) for the next S2S
 * emit: BOUNCE_HOLD_MARK_* or 0.  The companion of s2s_sessid_override:
 * armed only beside an armed session id, disarmed whenever a session id
 * is armed, and consumed or cleared everywhere the session id is, so the
 * mark always describes the client the ,S beside it names. */
static char s2s_held_override = '\0';

/** The server link whose line is being handled right now, or NULL.
 *
 * A link's S2S stash (cli_s2s_msgid / cli_s2s_time_ms / cli_s2s_sessid
 * of the link) is cleared only when the NEXT line from that link is
 * parsed, so outside its own line it holds whatever that link sent
 * last: another event's msgid, time and session hint.  packet.c sets
 * this right before parse_server() and clears it right after, so the
 * stash is consulted only while it is the current line's own tags.
 * NULL outside server-line handling: client lines, timers, callbacks.
 * Only ever compared, never dereferenced. */
static struct Client *s2s_inbound_link = NULL;

void sendcmdto_set_inbound_link(struct Client *link)
{
  s2s_inbound_link = link;
}

struct Client *sendcmdto_inbound_link(void)
{
  return s2s_inbound_link;
}

/** Whether \a cptr's stash holds the tags of the line being handled:
 * \a cptr is the inbound link, or a client behind it (cli_connect of a
 * remote client is its link's connection, so their stash is the
 * link's).  The one gate for every reader of a link's stash. */
int sendcmdto_stash_is_current(struct Client *cptr)
{
  return cptr && s2s_inbound_link && cli_from(cptr) == s2s_inbound_link;
}

/** Multiline framing (compact-tag ,M segment: flag + batch reference)
 * for the next S2S emit that builds the tag region.  Armed by the ML
 * senders in m_batch.c (audit 0.1), consumed by
 * format_s2s_tags_with_client and cleared by
 * sendcmdto_one_tags_with_client whether or not it was used. */
static char s2s_ml_override[S2S_ML_BUFSIZE] = "";

/** Multiline fallback mark (compact-tag ,F<msgid> segment) for the next
 * S2S emit that builds the tag region: the line is one of the
 * single-line fallback lines of multiline message <msgid>.  Armed by
 * the originating server's DM fallback (m_batch.c) and by a relay
 * passing such a line on (server_relay_private_message); consumed by
 * format_s2s_tags_with_client and cleared by
 * sendcmdto_one_tags_with_client whether or not it was used. */
static char s2s_fallback_override[S2S_MSGID_BUFSIZE] = "";

/** Status-message PRIVMSG (#226), armed by sendcmdto_set_statusmsg_privmsg()
 * for the next channel send through
 * sendcmdto_channel_butone_with_client_tags() of a WALLCHOPS / WALLHOPS /
 * WALLVOICES line.  Two halves:
 *  - s2s_statusmsg_override: the compact-tag ,P segment, placed by the
 *    next format_s2s_tags_with_client() and consumed there, so the line
 *    toward IRCv3-aware links says "this is a PRIVMSG"; legacy links get
 *    the bare wall line, as for a NOTICE;
 *  - statusmsg_user_text: what local members are delivered instead of the
 *    wall command's NOTICE: ":<from> PRIVMSG <status><chan> :<text>",
 *    the text without the "<status> " lead the wall line carries.
 *    Consumed (cleared) by that channel send as it starts.
 * Cleared by sendcmdto_channel_butone(), by sendcmdto_one_tags_with_client()
 * and by the end-of-line reset, so neither half outlives its message. */
static int s2s_statusmsg_override = 0;
static const char *statusmsg_user_text = NULL;

/** Client-only tags (compact-tag ,C segment) for the next S2S emit
 * through sendcmdto_serv_butone_v3() (audit 0.1): a channel TAGMSG
 * with a large client tag used to ride the message body, which could
 * push an S2S line past the receiving peer's 512-byte cap and drop
 * the whole link. format_s2s_tags_with_client() already takes
 * client_tags as a direct parameter (used by
 * sendcmdto_one_tags_with_client for the DM path); this override
 * exists only to carry that value through sendcmdto_serv_butone_v3()'s
 * cmd/pattern/varargs forwarding, which has no slot for it.
 *
 * Unlike the other overrides, this stores the pointer itself, not a
 * copy: the caller's buffer (cli_client_tags(sptr) or
 * cli_s2s_client_tags(cptr)) must stay valid until the consuming call
 * runs, which is true for every current site (set immediately before
 * that call). Consumed and cleared by sendcmdto_serv_butone_v3();
 * cleared unconsumed by every other serv_butone variant, since
 * legacy/v1 peers have no ,C slot to put it in. */
static const char *s2s_client_tags_override = NULL;

/** Override msgid for client-side channel broadcasts.
 * When non-empty, format_message_tags_ex includes msgid for clients with
 * message-tags capability. Auto-cleared after channel broadcast completes.
 */
static char client_msgid_override[64] = "";

/** Override server-time for client-side tag formatting.
 * When non-empty, format_message_tags functions use this timestamp
 * instead of calling gettimeofday(). Used by multiline batch to ensure
 * consistent timestamps across all recipients. */
static char client_time_override[40] = "";

/** The event's ONE time, in epoch milliseconds, for client-facing @time
 * tags (2026-09-02).  Armed together with the client msgid (either by
 * sendcmdto_set_client_event or, for the sites that already stamp the
 * S2S tag, by sendcmdto_set_s2s_tags) and cleared with it.  Every
 * client composer used to stamp the wall clock at send time, so a
 * message's live @time drifted from the row the origin stored (the
 * HLC's lead over the wall clock, 1 ms in the echo case; tens of ms on
 * a receiving server whose PART broadcast never carried the tag).
 * Consumed only while a client msgid is armed, so a stray S2S-only
 * override can never stamp an unrelated later send. */
static uint64_t client_event_ms = 0;

/** Wall-clock replacement for client @time composition: the armed
 * event time when there is one, else the clock. */
static void client_tag_tv(struct timeval *tv)
{
  if (client_msgid_override[0] && client_event_ms) {
    tv->tv_sec = (time_t)(client_event_ms / 1000);
    tv->tv_usec = (suseconds_t)((client_event_ms % 1000) * 1000);
    return;
  }
  gettimeofday(tv, NULL);
}

void sendcmdto_set_client_time(const char *timestr)
{
  if (timestr)
    ircd_strncpy(client_time_override, timestr, sizeof(client_time_override));
  else
    client_time_override[0] = '\0';
}

void sendcmdto_set_client_msgid(const char *msgid)
{
  if (msgid)
    ircd_strncpy(client_msgid_override, msgid, sizeof(client_msgid_override));
  else {
    client_msgid_override[0] = '\0';
    client_event_ms = 0;
  }
}

void sendcmdto_set_client_event(const char *msgid, uint64_t event_ms)
{
  sendcmdto_set_client_msgid(msgid);
  client_event_ms = msgid ? event_ms : 0;
}

void sendcmdto_set_fwd_batch(const char *batch_id)
{
  if (batch_id)
    ircd_strncpy(fwd_batch_id_override, batch_id, sizeof(fwd_batch_id_override));
  else
    fwd_batch_id_override[0] = '\0';
}

void sendcmdto_set_s2s_tags(uint64_t time_ms, const char *msgid)
{
  s2s_time_override = time_ms;
  /* The same event time serves the client-facing @time (see
   * client_event_ms); only meaningful while a client msgid is armed. */
  if (time_ms)
    client_event_ms = time_ms;
  if (msgid)
    ircd_strncpy(s2s_msgid_override, msgid, sizeof(s2s_msgid_override));
  else
    s2s_msgid_override[0] = '\0';
}

/** Set the S2S session-id hint for the next S2S emit (per redesign A.2).
 * Bouncer-aware peers receive this as a `,S<sessid>` compact-tag segment;
 * legacy peers don't see it (they don't carry compact tags at all).
 * Auto-cleared after the next format_s2s_tags_with_client call. */
void sendcmdto_set_s2s_sessid(const char *sessid)
{
  if (sessid)
    ircd_strncpy(s2s_sessid_override, sessid, sizeof(s2s_sessid_override));
  else
    s2s_sessid_override[0] = '\0';
  /* A mark armed for another session id never rides this one. */
  s2s_held_override = '\0';
}

/** Set the bouncer hold mark (,H) for the next S2S emit, beside the
 * session id armed by sendcmdto_set_s2s_sessid().  Without an armed
 * session id there is nothing for the mark to describe: it is dropped.
 * The format emits ,H only beside ,S. */
void sendcmdto_set_s2s_held(char mark)
{
  s2s_held_override = s2s_sessid_override[0] ? mark : '\0';
}

/** Arm the multiline framing segment ,M<flag><batch_ref> for the next
 * S2S emit (audit 0.1).  \a flag is '+' (start), 'c' (concat), '-'
 * (end) or '.' (plain).  Only meaningful right before a
 * sendcmdto_one_tags_with_client() call toward a link for which
 * send_s2s_tags_on() holds: that call places ,M before ,C in the tag
 * region and clears the override either way.  A NULL or empty
 * \a batch_ref disarms. */
void sendcmdto_set_s2s_ml(char flag, const char *batch_ref)
{
  if (batch_ref && *batch_ref) {
    s2s_ml_override[0] = flag;
    ircd_strncpy(s2s_ml_override + 1, batch_ref, sizeof(s2s_ml_override) - 1);
  } else
    s2s_ml_override[0] = '\0';
}

/** Arm the multiline fallback mark ,F<msgid> for the next S2S emit
 * (see s2s_fallback_override).  NULL or empty disarms. */
void sendcmdto_set_s2s_fallback(const char *msgid)
{
  if (msgid && *msgid)
    ircd_strncpy(s2s_fallback_override, msgid, sizeof(s2s_fallback_override));
  else
    s2s_fallback_override[0] = '\0';
}

/** Arm a status-message PRIVMSG (#226) for the next
 * sendcmdto_channel_butone_with_client_tags() of a wall command (see
 * s2s_statusmsg_override): local members that pass the wall's status
 * filter get ":<from> PRIVMSG <status><chan> :<text>" -- the status from
 * the SKIP_NON* flag, as for the NOTICE form -- and the S2S line toward
 * IRCv3-aware links carries the ,P mark.  Stores \a text itself, not a
 * copy: the caller's buffer must outlive that send, which follows at
 * once.  NULL or "" disarms both halves.
 * @param[in] text The PRIVMSG form's text: the relayed text without its
 *            "<status> " lead. */
void sendcmdto_set_statusmsg_privmsg(const char *text)
{
  if (text && *text) {
    statusmsg_user_text = text;
    s2s_statusmsg_override = 1;
  } else {
    statusmsg_user_text = NULL;
    s2s_statusmsg_override = 0;
  }
}

/** Arm client-only tags (,C<client_tags>) for the next
 * sendcmdto_serv_butone_v3() call (audit 0.1).  Stores \a client_tags
 * itself rather than a copy: the caller's buffer must stay valid until
 * that call runs.  sendcmdto_serv_butone_v3() reads it, passes it
 * through to format_s2s_tags_with_client(), and clears it whether or
 * not it built a tagged variant; every other serv_butone variant
 * clears it unconsumed. A NULL or empty \a client_tags disarms. */
void sendcmdto_set_s2s_client_tags(const char *client_tags)
{
  s2s_client_tags_override = (client_tags && *client_tags) ? client_tags : NULL;
}

/** Whether a line sent toward \a to through
 * sendcmdto_one_tags_with_client() carries the S2S compact tag region:
 * the next hop is a server link (or &me) that speaks IRCv3 S2S tags,
 * and P10_MESSAGE_TAGS is on.  A caller that frames a line differently
 * with and without the tag region (ML, audit 0.1) decides with this,
 * and sendcmdto_one_tags_with_client() decides with it too, so the two
 * can never disagree. */
int send_s2s_tags_on(struct Client *to)
{
  to = cli_from(to);
  return (IsServer(to) || IsMe(to)) && IsIRCv3Aware(to)
         && feature_bool(FEAT_P10_MESSAGE_TAGS);
}

/** Whether the line "<from> <tok> <pattern...>" that a send toward a
 * server link builds (sendcmdto_one, the serv_butone family) fits whole
 * in the 510 bytes msgq_vmake keeps of an UNTAGGED S2S line.
 *
 * A body form that carries client tags AHEAD of its target -- a TAGMSG
 * ("@<tags> <target>") or a multiline start line ("+<ref> @<tags>
 * <target> :<text>"), sent this way when no tag region is built toward
 * that link (P10_MESSAGE_TAGS off) -- is not the same message once cut:
 * tags long enough to push the cut past them cut the target, so
 * "#ops-public" arrives as "#ops" and the receiver, which checks only
 * that a channel of that name exists, delivers there.  Such a sender
 * asks this first and sends another form (or nothing) when it says no.
 * The length is measured on the real line:  pattern and its arguments
 * are formatted exactly as the send would format them (numerics, since
 * the destination is a server).
 * @return 1 if the whole line fits, 0 if a send would cut it. */
int send_s2s_untagged_fits(struct Client *from, const char *tok,
                           const char *pattern, ...)
{
  struct VarData vd;
  char scratch[BUFSIZE];
  int len;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  len = ircd_snprintf(&me, scratch, sizeof(scratch), "%C %s %v", from, tok,
                      &vd);
  va_end(vd.vd_args);
  if (len <= BUFSIZE - 2)
    return 1;
  Debug((DEBUG_DEBUG, "untagged S2S %s line from %s is %d bytes, over the "
         "510-byte cut", tok, cli_name(from), len));
  return 0;
}

/** Pre-built S2S tag prefix for multi-msgid scenarios (e.g. batched CREATE/PART).
 * When non-empty, sendcmdto_serv_butone uses this directly instead of calling
 * format_s2s_tags(). Must include the trailing space. Auto-cleared after use.
 */
static char s2s_raw_tags[256] = "";

void sendcmdto_set_s2s_raw_tags(const char *tags)
{
  if (tags)
    ircd_strncpy(s2s_raw_tags, tags, sizeof(s2s_raw_tags));
  else
    s2s_raw_tags[0] = '\0';
}

/** Opt-in flag for S2S tags on the next sendcmdto_serv_butone() call.
 * Set to 1 before calling sendcmdto_serv_butone() to include compact S2S
 * tags on channel events (JOIN, PART, KICK, TOPIC). Auto-cleared after use.
 */
static int s2s_want_tags = 0;

void sendcmdto_want_s2s_tags(int want)
{
  s2s_want_tags = want;
}

/** End of the event: clear every S2S override (audit 0.4b).
 *
 * Each override is armed for one event's send(s) and consumed there,
 * but not every path consumes all of them -- a handler that arms and
 * then returns early (m_nick's alias source before a 433), a sender
 * that reads an override without clearing it, a tags-off or legacy
 * branch.  Whatever survives would stamp the next, unrelated
 * server-bound line with this event's msgid and time (a QUIT relay, a
 * forwarded command, even a PING), source it from an alias, or tag it
 * with another event's ,S/,M/,C.  packet.c calls this after every
 * parsed line, so no override outlives the line that armed it.
 *
 * The client-facing overrides (client msgid/time, the forwarded batch
 * id) are left alone: their senders clear them. */
void sendcmdto_reset_s2s_overrides(void)
{
  s2s_cptr_override = NULL;
  s2s_alias_source = NULL;
  s2s_msgid_override[0] = '\0';
  s2s_time_override = 0;
  s2s_sessid_override[0] = '\0';
  s2s_held_override = '\0';
  s2s_ml_override[0] = '\0';
  s2s_fallback_override[0] = '\0';
  s2s_statusmsg_override = 0;
  statusmsg_user_text = NULL;
  s2s_client_tags_override = NULL;
  s2s_raw_tags[0] = '\0';
  s2s_want_tags = 0;
}

/** Mint a fresh msgid into \a link's S2S stash for an event that
 * arrived from it with none (a legacy peer, or tags off), and stamp the
 * stash with that msgid's mint time.  The stash is what delivery,
 * storage and the onward relay read (cli_s2s_msgid/cli_s2s_time_ms of
 * the link), so they share one msgid and one time; a stash holding a
 * msgid but no time made the relay take its time from wherever it
 * could (audit 0.4b).  parse_server() clears the stash per line. */
void s2s_mint_link_event(struct Client *link)
{
  generate_msgid(cli_s2s_msgid(link), S2S_MSGID_BUFSIZE);
  /* Minting advanced the HLC: its physical time is the mint time. */
  cli_s2s_time_ms(link) = hlc_global()->physical_ms;
}



/** Format current time as ISO 8601 timestamp for server-time capability.
 * @param[out] buf Buffer to write timestamp to.
 * @param[in] buflen Size of buffer.
 * @return Pointer to buf.
 */
static char *format_server_time(char *buf, size_t buflen)
{
  struct timeval tv;
  struct tm tm;

  client_tag_tv(&tv);
  gmtime_r(&tv.tv_sec, &tm);
  snprintf(buf, buflen, "@time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           tv.tv_usec / 1000);
  return buf;
}

/** Set the active network batch ID for netjoin/netsplit batching.
 * When set, QUIT/JOIN messages to batch-capable clients will include @batch tag.
 * @param[in] batch_id Batch ID to set, or NULL/empty to clear.
 */
void set_active_network_batch(const char *batch_id)
{
  if (batch_id && *batch_id) {
    ircd_strncpy(active_network_batch_id, batch_id, sizeof(active_network_batch_id) - 1);
    active_network_batch_id[sizeof(active_network_batch_id) - 1] = '\0';
  } else {
    active_network_batch_id[0] = '\0';
  }
}

/** Get the active network batch ID.
 * @return Current batch ID, or empty string if none active.
 */
const char *get_active_network_batch(void)
{
  return active_network_batch_id;
}

/** Check if a client wants message tags.
 * Used for TAGMSG filtering - only clients with message-tags capability can receive TAGMSGs.
 * @param[in] to Recipient client.
 * @return Non-zero if client has message-tags capability active.
 */
static int wants_message_tags(struct Client *to)
{
  /* Primary check: message-tags capability */
  if (CapActive(to, CAP_MSGTAGS))
    return 1;

  /* Fallback: any capability that implies message tag support */
  return (feature_bool(FEAT_CAP_server_time) && CapActive(to, CAP_SERVERTIME)) ||
         (feature_bool(FEAT_CAP_account_tag) && CapActive(to, CAP_ACCOUNTTAG)) ||
         (feature_bool(FEAT_CAP_labeled_response) && MyConnect(to) &&
          LabeledResponseInUse(to) && cli_label(to)[0]);
}

/* draft/oper-tag (#494): a server-attached tag on every command sent
 * by an operator.  Attached only for DISPLAYED opers (PRIV_DISPLAY and
 * not +H) -- hidden opers are never disclosed by tag to anyone, which
 * is the visibility restriction the spec explicitly permits.  The tag
 * value discloses the opername only under FEAT_OPERTAG_VALUE. */
static int oper_tag_eligible(struct Client *from)
{
  return from && cli_user(from) && IsAnOper(from)
      && HasPriv(from, PRIV_DISPLAY) && !IsHideOper(from);
}

/** Append one tag to a tag region being built in @a buf: a ';' first
 * unless it is the region's first tag (@a pos 1, just past the '@'), then
 * the tag -- whole, or not at all.  Room is always left for the region's
 * trailing space and NUL, so a region built only with this stays inside
 * @a buf whatever its tags' lengths.
 * @param[in,out] buf The region ("@" and the tags so far).
 * @param[in] buflen Size of @a buf.
 * @param[in,out] pos Length of the region so far; advanced past the tag.
 * @param[in] fmt Format of the tag.
 * @return Non-zero if the tag went in. */
static int tag_put(char *buf, size_t buflen, int *pos, const char *fmt, ...)
{
  va_list vl;
  int sep = *pos > 1;
  int n;

  /* pos, a separator, the tag, then a space and the NUL */
  if (*pos < 1 || (size_t)*pos + sep + 2 >= buflen)
    return 0;
  if (sep)
    buf[*pos] = ';';
  va_start(vl, fmt);
  n = vsnprintf(buf + *pos + sep, buflen - *pos - sep - 1, fmt, vl);
  va_end(vl);
  if (n <= 0 || (size_t)(*pos + sep + n) >= buflen - 1) {
    buf[*pos] = '\0';   /* it did not fit: leave the region as it was */
    return 0;
  }
  *pos += sep + n;
  return 1;
}

static int append_oper_tag(char *buf, size_t buflen, int pos, struct Client *from)
{
  const char *name = feature_bool(FEAT_OPERTAG_VALUE)
      ? cli_user(from)->opername : NULL;
  /* The name as its value when it fits; the bare tag otherwise (a long
   * Operator block name), which still says the line is an oper's. */
  if (!(name && *name && !strpbrk(name, "; ")
        && tag_put(buf, buflen, &pos, "draft/oper=%s", name)))
    tag_put(buf, buflen, &pos, "draft/oper");
  return pos;
}

/** Flags for format_message_tags_ex() tag selection */
#define TAGS_TIME     0x01  /**< Include @time tag */
#define TAGS_ACCOUNT  0x02  /**< Include @account tag */
#define TAGS_BATCH    0x04  /**< Include @batch tag (network batch) */
#define TAGS_BOT      0x08  /**< Include @bot tag */
#define TAGS_MSGID    0x10  /**< Include @msgid tag from client_msgid_override */
#define TAGS_OPER     0x20  /**< Include @draft/oper tag (eligibility pre-checked) */
/** Size of per-flag-combination MsgBuf caches: one slot per possible
 * TAGS_* bitmask.  MUST cover every flag above -- an out-of-range
 * index reads an uninitialized stack slot as a MsgBuf* (SIGSEGV). */
#define TAGS_CACHE_SIZE (TAGS_OPER << 1)

/** Format message tags with explicit control over which tags to include.
 * @param[out] buf Buffer to write tags to.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client (for account tag and bot detection).
 * @param[in] flags TAGS_* flags indicating which tags to include.
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_ex(char *buf, size_t buflen, struct Client *from, int flags)
{
  int pos;
  int use_time = flags & TAGS_TIME;
  int use_account = flags & TAGS_ACCOUNT;
  int use_batch = (flags & TAGS_BATCH) && active_network_batch_id[0];
  int use_bot = (flags & TAGS_BOT) && from && IsBot(from);
  int use_msgid = (flags & TAGS_MSGID) && client_msgid_override[0];
  int use_oper = (flags & TAGS_OPER) != 0;

  if (!use_time && !use_account && !use_batch && !use_bot && !use_msgid && !use_oper)
    return NULL;
  if (buflen < 4)
    return NULL;

  /* Each tag goes in whole or not at all (tag_put()), in this order, so
   * the region never outgrows buf: the fan-outs build it into 128 bytes,
   * and the draft/oper value is an Operator block name of any length. */
  buf[0] = '@';
  buf[1] = '\0';
  pos = 1;

  /* @batch tag first (most important for batched messages) */
  if (use_batch)
    tag_put(buf, buflen, &pos, "batch=%s", active_network_batch_id);

  if (use_time) {
    struct timeval tv;
    struct tm tm;
    client_tag_tv(&tv);
    gmtime_r(&tv.tv_sec, &tm);
    tag_put(buf, buflen, &pos,
            "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec,
            (long)(tv.tv_usec / 1000));
  }

  if (use_msgid)
    tag_put(buf, buflen, &pos, "msgid=%s", client_msgid_override);

  if (use_account && from && cli_user(from) && IsAccount(from))
    tag_put(buf, buflen, &pos, "account=%s", cli_user(from)->account);

  if (use_oper)
    pos = append_oper_tag(buf, buflen, pos, from);

  /* Add @bot tag if sender has +B mode (IRCv3 bot-mode spec) */
  if (use_bot)
    tag_put(buf, buflen, &pos, "bot");

  /* No tag went in -- account-tag for a source with no account: "@ " is
   * no tag region, and the line goes without one. */
  if (pos == 1)
    return NULL;

  buf[pos++] = ' ';
  buf[pos] = '\0';
  return buf;
}

/** Get the tag flags appropriate for a client based on their capabilities.
 * @param[in] to Recipient client.
 * @param[in] from Source client (for bot detection).
 * @param[in] include_batch Whether to include batch tag if network batch is active.
 * @return TAGS_* flags for this client.
 */
static int get_client_tag_flags(struct Client *to, struct Client *from, int include_batch)
{
  int flags = 0;

  /* Use cli_active_own (per-connection caps) instead of cli_active (union).
   * For non-bouncer clients these are identical.  For bouncer primaries,
   * cli_active is the union of all session connections' caps — using it
   * here would add tags the primary's own connection didn't negotiate. */
  if (feature_bool(FEAT_CAP_server_time) && CapOwnHas(to, CAP_SERVERTIME))
    flags |= TAGS_TIME;
  if (feature_bool(FEAT_CAP_account_tag) && CapOwnHas(to, CAP_ACCOUNTTAG))
    flags |= TAGS_ACCOUNT;
  if (feature_bool(FEAT_CAP_oper_tag) && CapOwnHas(to, CAP_DRAFT_OPERTAG)
      && oper_tag_eligible(from))
    flags |= TAGS_OPER;
  if (include_batch && CapOwnHas(to, CAP_BATCH) && active_network_batch_id[0])
    flags |= TAGS_BATCH;
  /* Bot tag requires message-tags capability (server-generated tag per IRCv3) */
  if (CapOwnHas(to, CAP_MSGTAGS) && from && IsBot(from))
    flags |= TAGS_BOT;
  /* Include msgid when override is set and client has message-tags */
  if (client_msgid_override[0] && CapOwnHas(to, CAP_MSGTAGS))
    flags |= TAGS_MSGID;

  return flags;
}


/** Generate a unique message ID for IRCv3 message-ids.
 * HLC v1 format: <node_id_2><logical_b64_3><counter_b64_9> = 14 chars.
 * Advances the global HLC clock on each call.
 * @param[out] buf Buffer to write message ID to.
 * @param[in] buflen Size of buffer.
 * @return Pointer to buf.
 */
char *generate_msgid(char *buf, size_t buflen)
{
  /* Repacked 2026-09-01: <node_2><logical_3><time_ms_7><counter_2>.
   * The old layout wasted the counter's top chars on zero padding;
   * they now carry the HLC physical time, so ANY msgid resolves to
   * its mint time intrinsically (msgid_decode_time_ms) -- cursors and
   * refs keep working after the message ages out of storage.  12-bit
   * counter + per-event logical increments keep uniqueness. */
  struct HLC hlc = hlc_global_event();
  char logical_b64[4], time_b64[8], counter_b64[3];
  inttobase64_64(logical_b64, (uint64_t)hlc.logical, 3);
  inttobase64_64(time_b64, hlc.physical_ms, 7);
  inttobase64_64(counter_b64, (uint64_t)(++MsgIdCounter & 0xFFF), 2);
  snprintf(buf, buflen, "%s%s%s%s", cli_yxx(&me), logical_b64, time_b64,
           counter_b64);
  return buf;
}

/** Format message tags for S2S (server-to-server) relay.
 * Produces compact P10-native wire encoding: @A<time_b64_7><msgid_14>
 * The msgid and time are an armed override's, else -- while \a cptr's
 * link's own line is being handled -- the ones that line arrived with,
 * else freshly minted (see format_s2s_tags_with_client).
 * @param[out] buf Buffer for tag string (includes trailing space).
 * @param[in] buflen Size of buffer.
 * @param[in] cptr Server connection the message came from (for incoming tags).
 * @param[out] msgid_out Optional: buffer to store the msgid used (for echo-message).
 * @param[in] msgid_out_len Size of msgid_out buffer.
 * @return Pointer to buf, or NULL if P10_MESSAGE_TAGS is disabled.
 */
char *format_s2s_tags(char *buf, size_t buflen, struct Client *cptr,
                      char *msgid_out, size_t msgid_out_len)
{
  return format_s2s_tags_with_client(buf, buflen, cptr, NULL,
                                     msgid_out, msgid_out_len);
}

/** Format message tags for S2S relay including optional client-only tags.
 * Produces compact P10-native wire encoding:
 *   @A<time_b64_7><msgid_14>[,S<sessid>[,H<mark>]][,M<flag><batchref>][,F<msgid>][,P][,C<client_tags>]
 * The ,C<client_tags> segment is appended only when client_tags is non-NULL
 * and non-empty. Receivers parse it into cli_s2s_client_tags(cptr) for
 * forwarding to local recipients.  ,S, ,H, ,M, ,F and ,P come from their
 * armed overrides (sendcmdto_set_s2s_sessid, sendcmdto_set_s2s_held,
 * sendcmdto_set_s2s_ml, sendcmdto_set_s2s_fallback,
 * sendcmdto_set_statusmsg_privmsg), ,S and ,H also from cptr's stash.
 *
 * Precedence for the msgid and time (one source for both): an armed
 * override (s2s_msgid_override with s2s_time_override); else the stash
 * of \a cptr, but only while \a cptr's link is the one whose line is
 * being handled (sendcmdto_inbound_link()); else a fresh mint.  The ,S
 * hint follows the same gate: the stash, else the sessid override.  The
 * ,H hold mark comes from the same source as the ,S beside it, and only
 * with one: the mark describes the client that ,S names.
 *
 * Sized for callers that need to accommodate up to 4094 bytes of client
 * tags (IRCv3 cap) plus the compact prefix; recommend buf ≥ 4128 bytes
 * when client_tags may be present.
 *
 * @param[out] buf Buffer for tag string (includes trailing space).
 * @param[in] buflen Size of buffer.
 * @param[in] cptr Server connection the message came from, or a client
 *   behind it (for incoming tags); may be NULL.
 * @param[in] client_tags Optional client-only tags string ("+key=value;...").
 * @param[out] msgid_out Optional: buffer to store the msgid used.
 * @param[in] msgid_out_len Size of msgid_out buffer.
 * @return Pointer to buf, or NULL if P10_MESSAGE_TAGS is disabled.
 */
char *format_s2s_tags_with_client(char *buf, size_t buflen,
                                  struct Client *cptr,
                                  const char *client_tags,
                                  char *msgid_out, size_t msgid_out_len)
{
  char time_b64[8];
  char msgidbuf[S2S_MSGID_BUFSIZE];
  char sessidbuf[S2S_SESSID_BUFSIZE];
  char mlbuf[S2S_ML_BUFSIZE];
  char fbbuf[S2S_MSGID_BUFSIZE];
  char heldbuf[2] = "";
  char held = '\0';
  uint64_t epoch_ms;
  const char *msgid_tag = NULL;
  const char *sessid_tag = NULL;
  int has_ctags = (client_tags && *client_tags);
  int has_sessid;
  int has_ml;
  int has_fb;
  int has_sm;
  int stash;

  /* Check if P10 message tags are enabled */
  if (!feature_bool(FEAT_P10_MESSAGE_TAGS))
    return NULL;

  /* Multiline framing (audit 0.1): only ever the explicit override --
   * a relay re-arms it per line, so nothing is carried over from cptr. */
  has_ml = (s2s_ml_override[0] != '\0');
  if (has_ml) {
    ircd_strncpy(mlbuf, s2s_ml_override, sizeof(mlbuf));
    s2s_ml_override[0] = '\0';  /* auto-clear after consumption */
  }

  /* Multiline fallback mark: likewise only the explicit override (a
   * relay re-arms it, server_relay_private_message). */
  has_fb = (s2s_fallback_override[0] != '\0');
  if (has_fb) {
    ircd_strncpy(fbbuf, s2s_fallback_override, sizeof(fbbuf));
    s2s_fallback_override[0] = '\0';  /* auto-clear after consumption */
  }

  /* Status-message PRIVMSG mark (#226): only the explicit override (a
   * relay re-arms it, server_relay_channel_statusmsg). */
  has_sm = s2s_statusmsg_override;
  s2s_statusmsg_override = 0;       /* auto-clear after consumption */

  /* cptr's stash counts only while its link's line is being handled:
   * then it is the tags of the line this send relays.  Any other time
   * it holds whatever that link sent last -- another event, so reading
   * it gave, e.g., a bouncer alias's message on this server the msgid
   * of its primary's previous message on the primary's server. */
  stash = sendcmdto_stash_is_current(cptr);

  /* Sessid (,S): the current line's own hint, else the explicit
   * override.  Empty → no ,S segment.  Per redesign A.2: bouncer
   * session-identity hint for at-N-time recognition in m_nick.
   *
   * Hold mark (,H): taken with the ,S, from the same source -- the
   * current line's own mark (a relay copies what the N arrived with,
   * or nothing), else the override the home server's stamp armed
   * beside the sessid override.  Never with a ,S from another source,
   * never without a ,S. */
  if (stash && cli_s2s_sessid(cptr)[0]) {
    sessid_tag = cli_s2s_sessid(cptr);
    held = cli_s2s_held(cptr);
  } else if (s2s_sessid_override[0]) {
    ircd_strncpy(sessidbuf, s2s_sessid_override, sizeof(sessidbuf));
    sessid_tag = sessidbuf;
    held = s2s_held_override;
    s2s_sessid_override[0] = '\0';  /* auto-clear after consumption */
    s2s_held_override = '\0';
  }
  has_sessid = (sessid_tag && *sessid_tag);
  if (!has_sessid || !bounce_hold_mark_valid(held))
    held = '\0';

  /* Msgid and time, always from ONE source:
   *  1. an armed override -- this event's own id, minted here or
   *     restated by the caller; a local mint wins over any stash;
   *  2. the stash, under the gate above;
   *  3. a fresh mint, msgid FIRST so the HLC has advanced when its
   *     physical time is read.
   * A source without a time takes the HLC's physical time. */
  if (s2s_msgid_override[0]) {
    msgid_tag = s2s_msgid_override;
    epoch_ms = s2s_time_override;
  } else if (stash && cli_s2s_msgid(cptr)[0]) {
    msgid_tag = cli_s2s_msgid(cptr);
    epoch_ms = cli_s2s_time_ms(cptr);
  } else {
    generate_msgid(msgidbuf, sizeof(msgidbuf));
    msgid_tag = msgidbuf;
    epoch_ms = hlc_global()->physical_ms;
  }
  if (!epoch_ms)
    epoch_ms = hlc_global()->physical_ms;

  /* Store msgid for caller if requested (for echo-message) */
  if (msgid_out && msgid_out_len > 0) {
    ircd_strncpy(msgid_out, msgid_tag, msgid_out_len);
  }

  /* Compact format:
   *   @A<time_7><msgid_14>[,S<sessid>[,H<mark>]][,M<flag><batchref>][,F<msgid>][,P][,C<client_tags>]
   *
   * Segments are appended in order: ,S, then ,H, then ,M, then ,F, then
   * ,P (no data), then ,C.  ,C
   * is always the LAST segment and must never be followed by another
   * segment: a client-tag value may itself contain a comma, so
   * receivers read ,C to the end of the tag region rather than
   * stopping at the next comma (audit 0.1). Emit order otherwise is
   * conventional for readability in raw S2S logs.  A receiver that
   * does not know ,H skips it like any unknown segment. */
  heldbuf[0] = held;
  heldbuf[1] = '\0';
  inttobase64_64(time_b64, epoch_ms, 7);
  snprintf(buf, buflen, "@A%s%s%s%s%s%s%s%s%s%s%s%s%s ", time_b64, msgid_tag,
           has_sessid ? ",S" : "", has_sessid ? sessid_tag : "",
           held ? ",H" : "", heldbuf,
           has_ml ? ",M" : "", has_ml ? mlbuf : "",
           has_fb ? ",F" : "", has_fb ? fbbuf : "",
           has_sm ? ",P" : "",
           has_ctags ? ",C" : "", has_ctags ? client_tags : "");
  return buf;
}

/** Format the compact tag region of the line being handled, from
 * \a link's stash alone: @A<time_7><msgid_14>[,S<sessid>].
 *
 * For a reply that must echo the id of the line it answers (the
 * correlation a forwarded labeled command waits for): unlike
 * format_s2s_tags_with_client, no override is read or consumed, so an
 * id armed for some other send can never take the place of the one the
 * reply answers.
 * @param[out] buf Buffer for tag string (includes trailing space).
 * @param[in] buflen Size of buffer.
 * @param[in] link Server link the answered line arrived on.
 * @return Pointer to buf, or NULL if P10_MESSAGE_TAGS is off, \a link's
 *   line is not the one being handled, or its stash holds no msgid.
 */
char *format_s2s_tags_current(char *buf, size_t buflen, struct Client *link)
{
  char time_b64[8];
  uint64_t epoch_ms;
  int has_sessid;

  if (!feature_bool(FEAT_P10_MESSAGE_TAGS) || !sendcmdto_stash_is_current(link)
      || !cli_s2s_msgid(link)[0])
    return NULL;

  epoch_ms = cli_s2s_time_ms(link) ? cli_s2s_time_ms(link)
                                   : hlc_global()->physical_ms;
  has_sessid = (cli_s2s_sessid(link)[0] != '\0');
  inttobase64_64(time_b64, epoch_ms, 7);
  snprintf(buf, buflen, "@A%s%s%s%s ", time_b64, cli_s2s_msgid(link),
           has_sessid ? ",S" : "", has_sessid ? cli_s2s_sessid(link) : "");
  return buf;
}

/** Format message tags for a specific recipient, including label if applicable.
 * @param[out] buf Buffer for tag string.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client (for account tag).
 * @param[in] to Recipient client (for label tag).
 * @param[in] msgid Message ID to include, or NULL for none.
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_for_ex(char *buf, size_t buflen, struct Client *from,
                                        struct Client *to, const char *msgid)
{
  int use_time = feature_bool(FEAT_CAP_server_time) && CapOwnHas(to, CAP_SERVERTIME);
  int use_account = feature_bool(FEAT_CAP_account_tag) && CapOwnHas(to, CAP_ACCOUNTTAG);
  int use_oper = feature_bool(FEAT_CAP_oper_tag)
      && CapOwnHas(to, CAP_DRAFT_OPERTAG) && oper_tag_eligible(from);
  int use_label = feature_bool(FEAT_CAP_labeled_response) &&
                  to && LabeledResponseInUse(to) && MyConnect(to) && cli_label(to)[0] &&
                  !cli_label_responded(to);
  int use_batch = feature_bool(FEAT_CAP_batch) && CapOwnHas(to, CAP_BATCH) &&
                  to && MyConnect(to) && cli_batch_id(to)[0];
  int use_fwd_batch;
  int use_msgid = msgid && *msgid && CapOwnHas(to, CAP_MSGTAGS);
  int pos = 0;
  char fwd_batch[sizeof(fwd_batch_id_override)];

  /* The forwarded-label batch override is for the ONE line it was set
   * for: consumed here whether used or not.  Left set when the recipient
   * could not take it (no batch), it went onto the next line formatted
   * for ANY client with batch -- a batch that client never saw. */
  memcpy(fwd_batch, fwd_batch_id_override, sizeof(fwd_batch));
  fwd_batch_id_override[0] = '\0';
  use_fwd_batch = fwd_batch[0] && feature_bool(FEAT_CAP_batch) &&
                  CapOwnHas(to, CAP_BATCH);

  if (!use_time && !use_account && !use_label && !use_batch && !use_fwd_batch && !use_msgid
      && !use_oper)
    return NULL;

  buf[0] = '@';
  pos = 1;

  /* Forwarded label batch override takes priority over cli_batch_id.
   * This prevents forwarded numerics from leaking into LIST/chathistory batches.
   */
  if (use_fwd_batch) {
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", fwd_batch);
  } else if (use_batch) {
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", cli_batch_id(to));
  } else if (use_label) {
    pos += snprintf(buf + pos, buflen - pos, "label=%s", cli_label(to));
    /* Mark that we've sent a labeled response (for ACK mechanism) */
    cli_label_responded(to) = 1;
  }

  /* Add @msgid for message tracking (IRCv3 message-ids) */
  if (use_msgid) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "msgid=%s", msgid);
  }

  if (use_time) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    if (client_time_override[0]) {
      pos += snprintf(buf + pos, buflen - pos, "time=%s", client_time_override);
    } else {
      struct timeval tv;
      struct tm tm;
      client_tag_tv(&tv);
      gmtime_r(&tv.tv_sec, &tm);
      pos += snprintf(buf + pos, buflen - pos,
                      "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                      tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                      tm.tm_hour, tm.tm_min, tm.tm_sec,
                      tv.tv_usec / 1000);
    }
  }

  if (use_account && from && cli_user(from) && IsAccount(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "account=%s",
                    cli_user(from)->account);
  }

  if (use_oper)
    pos = append_oper_tag(buf, buflen, pos, from);

  /* Add @bot tag if sender has +B mode (IRCv3 bot-mode spec).
   * Per IRCv3, server-generated tags require message-tags capability. */
  if (from && IsBot(from) && CapOwnHas(to, CAP_MSGTAGS)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "bot");
  }

  if (pos < (int)buflen - 1) {
    buf[pos++] = ' ';
    buf[pos] = '\0';
  }

  return buf;
}

/** Format message tags for a specific recipient (wrapper without msgid).
 * @param[out] buf Buffer for tag string.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client (for account tag).
 * @param[in] to Recipient client (for label tag).
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_for(char *buf, size_t buflen, struct Client *from, struct Client *to)
{
  return format_message_tags_for_ex(buf, buflen, from, to, NULL);
}

/** Format message tags using an explicit CapSet for capability checks.
 *
 * Like format_message_tags_for_ex(), but checks capabilities against the
 * provided CapSet instead of the recipient's active caps. Used when the
 * recipient has a bouncer session with aliases — the union of all
 * connections' caps is passed so the MsgBuf includes all tags any
 * connection might need. send_buffer() then strips per-connection.
 *
 * Label and batch state still come from \a to (they are per-connection
 * state, not capability-dependent).
 *
 * @param[out] buf Buffer for tag string.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client (for account tag).
 * @param[in] to Recipient client (for label/batch state).
 * @param[in] msgid Message ID to include, or NULL for none.
 * @param[in] caps CapSet to check for tag capabilities.
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_for_caps(char *buf, size_t buflen,
                                           struct Client *from,
                                           struct Client *to,
                                           const char *msgid,
                                           struct CapSet *caps)
{
  int use_time = feature_bool(FEAT_CAP_server_time) && CapHas(caps, CAP_SERVERTIME);
  int use_account = feature_bool(FEAT_CAP_account_tag) && CapHas(caps, CAP_ACCOUNTTAG);
  int use_oper = feature_bool(FEAT_CAP_oper_tag)
      && CapHas(caps, CAP_DRAFT_OPERTAG) && oper_tag_eligible(from);
  int use_label = feature_bool(FEAT_CAP_labeled_response) &&
                  CapSetLabeledResponseInUse(caps) &&
                  to && MyConnect(to) && cli_label(to)[0] &&
                  !cli_label_responded(to);
  int use_batch = feature_bool(FEAT_CAP_batch) && CapHas(caps, CAP_BATCH) &&
                  to && MyConnect(to) && cli_batch_id(to)[0];
  int use_msgid = msgid && *msgid && CapHas(caps, CAP_MSGTAGS);
  int pos = 0;

  if (!use_time && !use_account && !use_label && !use_batch && !use_msgid && !use_oper)
    return NULL;

  buf[0] = '@';
  pos = 1;

  /* When in a batch, use @batch instead of @label */
  if (use_batch) {
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", cli_batch_id(to));
  } else if (use_label) {
    pos += snprintf(buf + pos, buflen - pos, "label=%s", cli_label(to));
    cli_label_responded(to) = 1;
  }

  if (use_msgid) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "msgid=%s", msgid);
  }

  if (use_time) {
    struct timeval tv;
    struct tm tm;
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    client_tag_tv(&tv);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(buf + pos, buflen - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    tv.tv_usec / 1000);
  }

  if (use_account && from && cli_user(from) && IsAccount(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "account=%s",
                    cli_user(from)->account);
  }

  if (use_oper)
    pos = append_oper_tag(buf, buflen, pos, from);

  if (from && IsBot(from) && CapHas(caps, CAP_MSGTAGS)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "bot");
  }

  if (pos < (int)buflen - 1) {
    buf[pos++] = ' ';
    buf[pos] = '\0';
  }

  return buf;
}

/** Format message tags including client-only tags for TAGMSG relay.
 * @param[out] buf Buffer for tag string.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client (for account tag and client tags).
 * @param[in] to Recipient client (for label tag).
 * @param[in] client_tags Client-only tags string (e.g., "+typing=active;+reply=msgid").
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_with_client(char *buf, size_t buflen, struct Client *from,
                                              struct Client *to, const char *client_tags)
{
  int use_time = feature_bool(FEAT_CAP_server_time) && CapOwnHas(to, CAP_SERVERTIME);
  int use_account = feature_bool(FEAT_CAP_account_tag) && CapOwnHas(to, CAP_ACCOUNTTAG);
  int use_oper = feature_bool(FEAT_CAP_oper_tag)
      && CapOwnHas(to, CAP_DRAFT_OPERTAG) && oper_tag_eligible(from);
  int use_label = feature_bool(FEAT_CAP_labeled_response) &&
                  to && LabeledResponseInUse(to) && MyConnect(to) && cli_label(to)[0] &&
                  !cli_label_responded(to);
  int use_batch = feature_bool(FEAT_CAP_batch) && CapOwnHas(to, CAP_BATCH) &&
                  to && MyConnect(to) && cli_batch_id(to)[0];
  int use_client_tags = client_tags && *client_tags && CapOwnHas(to, CAP_MSGTAGS);
  int pos = 0;

  /* TAGMSG is only useful if there are client-only tags to relay */
  if (!use_client_tags && !use_time && !use_account && !use_label && !use_batch
      && !use_oper)
    return NULL;

  buf[0] = '@';
  pos = 1;

  /* Client-only tags first (these are the primary content for TAGMSG) */
  if (use_client_tags) {
    pos += snprintf(buf + pos, buflen - pos, "%s", client_tags);
  }

  /* Include msgid from channel broadcast override */
  if (client_msgid_override[0] && CapOwnHas(to, CAP_MSGTAGS)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "msgid=%s", client_msgid_override);
  }

  /* When in a batch, use @batch instead of @label */
  if (use_batch) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", cli_batch_id(to));
  } else if (use_label) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "label=%s", cli_label(to));
    /* Mark that we've sent a labeled response (for ACK mechanism) */
    cli_label_responded(to) = 1;
  }

  if (use_time) {
    struct timeval tv;
    struct tm tm;
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    client_tag_tv(&tv);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(buf + pos, buflen - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    tv.tv_usec / 1000);
  }

  if (use_account && from && cli_user(from) && IsAccount(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "account=%s",
                    cli_user(from)->account);
  }

  if (use_oper)
    pos = append_oper_tag(buf, buflen, pos, from);

  /* Add @bot tag if sender has +B mode (IRCv3 bot-mode spec) */
  if (from && IsBot(from) && CapOwnHas(to, CAP_MSGTAGS)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "bot");
  }

  if (pos < (int)buflen - 1) {
    buf[pos++] = ' ';
    buf[pos] = '\0';
  }

  return buf;
}

/** Format message tags including client-only tags, using an explicit CapSet.
 * Like format_message_tags_with_client(), but checks capabilities against
 * the provided CapSet instead of the recipient's active caps. Used for
 * bouncer union caps.
 * @param[out] buf Buffer for tag string.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client.
 * @param[in] to Recipient client (for label/batch state).
 * @param[in] client_tags Client-only tags string.
 * @param[in] caps CapSet to check for tag capabilities.
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_with_client_caps(char *buf, size_t buflen,
                                                    struct Client *from,
                                                    struct Client *to,
                                                    const char *client_tags,
                                                    struct CapSet *caps)
{
  int use_time = feature_bool(FEAT_CAP_server_time) && CapHas(caps, CAP_SERVERTIME);
  int use_account = feature_bool(FEAT_CAP_account_tag) && CapHas(caps, CAP_ACCOUNTTAG);
  int use_oper = feature_bool(FEAT_CAP_oper_tag)
      && CapHas(caps, CAP_DRAFT_OPERTAG) && oper_tag_eligible(from);
  int use_label = feature_bool(FEAT_CAP_labeled_response) &&
                  CapSetLabeledResponseInUse(caps) &&
                  to && MyConnect(to) && cli_label(to)[0] &&
                  !cli_label_responded(to);
  int use_batch = feature_bool(FEAT_CAP_batch) && CapHas(caps, CAP_BATCH) &&
                  to && MyConnect(to) && cli_batch_id(to)[0];
  int use_client_tags = client_tags && *client_tags && CapHas(caps, CAP_MSGTAGS);
  int pos = 0;

  if (!use_client_tags && !use_time && !use_account && !use_label && !use_batch
      && !use_oper)
    return NULL;

  buf[0] = '@';
  pos = 1;

  if (use_client_tags) {
    pos += snprintf(buf + pos, buflen - pos, "%s", client_tags);
  }

  /* Include msgid from channel broadcast override */
  if (client_msgid_override[0] && CapHas(caps, CAP_MSGTAGS)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "msgid=%s", client_msgid_override);
  }

  if (use_batch) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", cli_batch_id(to));
  } else if (use_label) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "label=%s", cli_label(to));
    cli_label_responded(to) = 1;
  }

  if (use_time) {
    struct timeval tv;
    struct tm tm;
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    client_tag_tv(&tv);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(buf + pos, buflen - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    tv.tv_usec / 1000);
  }

  if (use_account && from && cli_user(from) && IsAccount(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "account=%s",
                    cli_user(from)->account);
  }

  if (use_oper)
    pos = append_oper_tag(buf, buflen, pos, from);

  if (from && IsBot(from) && CapHas(caps, CAP_MSGTAGS)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    pos += snprintf(buf + pos, buflen - pos, "bot");
  }

  if (pos < (int)buflen - 1) {
    buf[pos++] = ' ';
    buf[pos] = '\0';
  }

  return buf;
}

/*
 * dead_link
 *
 * An error has been detected. The link *must* be closed,
 * but *cannot* call ExitClient (m_bye) from here.
 * Instead, mark it with FLAG_DEADSOCKET. This should
 * generate ExitClient from the main loop.
 *
 * If 'notice' is not NULL, it is assumed to be a format
 * for a message to local opers. It can contain only one
 * '%s', which will be replaced by the sockhost field of
 * the failing link.
 *
 * Also, the notice is skipped for "uninteresting" cases,
 * like Persons and yet unknown connections...
 */
/** Mark a client as dead, even if they are not the current message source.
 * This is done by setting the DEADSOCKET flag on the user and letting the
 * main loop perform the actual exit logic.
 * @param[in,out] to Client being killed.
 * @param[in] notice Message for local opers.
 */
static void dead_link(struct Client *to, char *notice)
{
  SetFlag(to, FLAG_DEADSOCKET);
  /*
   * If because of BUFFERPOOL problem then clean dbuf's now so that
   * notices don't hurt operators below.
   */
  DBufClear(&(cli_recvQ(to)));
  MsgQClear(&(cli_sendQ(to)));
  client_drop_sendq(cli_connect(to));

  /*
   * Keep the reason for the exit message (exit_dead_client, the socket
   * callbacks).  Never in cli_info: that is the user's realname, which a
   * held session keeps, persists and replays.
   */
  ircd_strncpy(cli_exit_reason(to), notice, EXITREASONLEN + 1);

  if (!IsUser(to) && !IsUnknown(to) && !HasFlag(to, FLAG_CLOSING))
    sendto_opmask_butone(0, SNO_OLDSNO, "%s for %s", cli_exit_reason(to), cli_name(to));
  Debug((DEBUG_ERROR, "%s", cli_exit_reason(to)));
}

/** Test whether we can send to a client.
 * @param[in] to Client we want to send to.
 * @return Non-zero if we can send to the client.
 */
static int can_send(struct Client* to)
{
  assert(0 != to);
  return (IsDead(to) || IsMe(to) || -1 == cli_fd(to)) ? 0 : 1;
}

/** Close the connection with the highest sendq.
 * This should be called when we need to free buffer memory.
 * @param[in] servers_too If non-zero, consider killing servers, too.
 */
void
kill_highest_sendq(int servers_too)
{
  int i;
  unsigned int highest_sendq = 0;
  struct Client *highest_client = 0;

  for (i = HighestFd; i >= 0; i--)
  {
    if (!LocalClientArray[i] || (!servers_too && cli_serv(LocalClientArray[i])))
      continue; /* skip servers */
    
    /* If this sendq is higher than one we last saw, remember it */
    if (MsgQLength(&(cli_sendQ(LocalClientArray[i]))) > highest_sendq)
    {
      highest_client = LocalClientArray[i];
      highest_sendq = MsgQLength(&(cli_sendQ(highest_client)));
    }
  }

  if (highest_client)
    dead_link(highest_client, "Buffer allocation error");
}

/*
 * flush_connections
 *
 * Used to empty all output buffers for all connections. Should only
 * be called once per scan of connections. There should be a select in
 * here perhaps but that means either forcing a timeout or doing a poll.
 * When flushing, all we do is empty the obuffer array for each local
 * client and try to send it. if we cant send it, it goes into the sendQ
 * -avalon
 */
/** Flush data queued for one or all connections.
 * @param[in] cptr Client to flush (if NULL, do all).
 */
void flush_connections(struct Client* cptr)
{
  if (cptr) {
    send_queued(cptr);
  }
  else {
    struct Connection* con;
    for (con = send_queues; con; con = con_next(con)) {
      assert(0 < MsgQLength(&(con_sendQ(con))));
      send_queued(con_client(con));
    }
  }
}

/*
 * send_queued
 *
 * This function is called from the main select-loop (or whatever)
 * when there is a chance that some output would be possible. This
 * attempts to empty the send queue as far as possible...
 */
/** Attempt to send data queued for a client.
 * @param[in] to Client to send data to.
 */
void send_queued(struct Client *to)
{
  assert(0 != to);
  assert(0 != cli_local(to));

  if (IsBlocked(to) || !can_send(to))
    return;                     /* Don't bother */

  /* An out-of-band WebSocket frame (keepalive PING, PONG) can be left
   * pending with NOTHING queued behind it; the loop below would then
   * never reach deliver_it and the frame would wait for the next line.
   * Complete it now that the socket is writable. */
  if (IsWebSocket(to) && con_ws_txrem(cli_connect(to))
      && 0 == MsgQLength(&(cli_sendQ(to)))) {
    unsigned int wrote = 0;

    if (!ws_flush_txrem(to, &wrote)) {
      if (IsDead(to)) {
        char tmp[512];
        sprintf(tmp,"Write error: %s", ((cli_sslerror(to)) ? (cli_sslerror(to)) :
                ((strerror(cli_error(to))) ? (strerror(cli_error(to))) : "Unknown error")) );
        dead_link(to, tmp);
      }
      else
        update_write(to);
      return;
    }
    cli_sendB(to) += wrote;
    cli_sendB(&me) += wrote;
  }

  while (MsgQLength(&(cli_sendQ(to))) > 0) {
    unsigned int len;

    if ((len = deliver_it(to, &(cli_sendQ(to))))) {
      msgq_delete(&(cli_sendQ(to)), len);
      cli_lastsq(to) = MsgQLength(&(cli_sendQ(to))) / 1024;
      /* Only stay listed for the blocked retry while data remains: a
       * write that drains the queue exactly as the socket blocks must
       * fall through to the drop below, or the connection is left on
       * send_queues with an empty sendQ (the state free_client's linger
       * path can then orphan permanently — send.c:1019 assert class). */
      if (IsBlocked(to) && 0 < MsgQLength(&(cli_sendQ(to)))) {
	update_write(to);
        return;
      }
    }
    else {
      if (IsDead(to)) {
        char tmp[512];
        sprintf(tmp,"Write error: %s", ((cli_sslerror(to)) ? (cli_sslerror(to)) :
                ((strerror(cli_error(to))) ? (strerror(cli_error(to))) : "Unknown error")) );
        dead_link(to, tmp);
      }
      return;
    }
  }

  /* Ok, sendq is now empty... */
  client_drop_sendq(cli_connect(to));
  update_write(to);
}

/** Reconcile a connection's send_queues membership with its sendQ
 * contents after the queue was moved or cleared OUTSIDE the normal send
 * path (the bouncer socket transplant).  Lists the connection and arms
 * a write event when data is present; delists it otherwise.  Needed
 * because send_queues is static to this file.
 * @param[in] to Client whose connection should be reconciled.
 */
void client_reconcile_sendq(struct Client *to)
{
  assert(0 != to);
  assert(0 != cli_connect(to));

  if (0 < MsgQLength(&(cli_sendQ(to))))
    client_add_sendq(cli_connect(to), &send_queues);
  else
    client_drop_sendq(cli_connect(to));
  update_write(to);
}

static int batch_hold_take(struct Client *to, struct MsgBuf *mb);

/** Try to send a buffer to a client, queueing it if needed.
 * @param[in,out] to Client to send message to.
 * @param[in] buf Message to send.
 * @param[in] prio If non-zero, send as high priority.
 */
void send_buffer(struct Client* to, struct MsgBuf* buf, int prio)
{
  assert(0 != to);
  assert(0 != buf);

  if (cli_from(to))
    to = cli_from(to);

  if (!can_send(to))
    return;

  /* A blocked TLS socket has a record OpenSSL still holds pending, and
   * the retry must present that same record first.  msgq_mapiov maps the
   * priority queue ahead of the normal queue, so a priority line queued
   * now (the ping check's PING, a WALLOPS, a services line under
   * FLUSH_ULINE_IMMEDIATE) would reach SSL_write before the pending
   * record: SSL_ERROR_SSL "bad write retry", and the connection is killed
   * with "Write error: Internal OpenSSL error or protocol error".  It
   * cannot be flushed early anyway while the socket is blocked, so queue
   * it in order. */
#ifdef USE_SSL
  if (prio && IsBlocked(to) && cli_socket(to).ssl)
    prio = 0;
#endif

  if (MsgQLength(&(cli_sendQ(to))) > get_sendq(to)) {
    if (IsServer(to))
      sendto_opmask_butone(0, SNO_OLDSNO, "Max SendQ limit exceeded for %C: "
			   "%zu > %zu", to, MsgQLength(&(cli_sendQ(to))),
			   get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  Debug((DEBUG_SEND, "Sending [%p] to %s", buf, cli_name(to)));

  /* Per-connection cap routing for dual-call broadcasts.
   * When stc_withcap/skipcap are set and this is a bouncer primary,
   * check the primary's OWN caps (not union) to decide delivery. */
  {
    int suppress_primary = 0;
    if (cap_route_ctx.stc_active && MyUser(to) && !IsServer(to)
        && (cap_route_ctx.stc_withcap != CAP_NONE
            || cap_route_ctx.stc_skipcap != CAP_NONE)) {
      if (cap_route_ctx.stc_withcap != CAP_NONE
          && !CapOwnHas(to, cap_route_ctx.stc_withcap))
        suppress_primary = 1;
      if (cap_route_ctx.stc_skipcap != CAP_NONE
          && CapOwnHas(to, cap_route_ctx.stc_skipcap))
        suppress_primary = 1;
    }
    if (!suppress_primary && MyConnect(to) && con_batch_hold(cli_connect(to))
        && batch_hold_take(to, buf))
      return;   /* held for a deferred labeled batch (labeled_batch_defer()) */
    if (!suppress_primary) {
      msgq_add(&(cli_sendQ(to)), buf, prio);
      client_add_sendq(cli_connect(to), &send_queues);
      update_write(to);
      ++(cli_sendM(to));
      ++(cli_sendM(&me));
      if (prio || MsgQLength(&(cli_sendQ(to))) / 1024 > cli_lastsq(to))
        send_queued(to);
    }
  }

}

/*
 * Send a msg to all ppl on servers/hosts that match a specified mask
 * (used for enhanced PRIVMSGs)
 *
 *  addition -- Armin, 8jun90 (gruner@informatik.tu-muenchen.de)
 */

/** Check whether a client matches a target mask.
 * @param[in] from Client trying to send a message (ignored).
 * @param[in] one Client being considered as a target.
 * @param[in] mask Mask for matching against.
 * @param[in] what Type of match (either MATCH_HOST or MATCH_SERVER).
 * @return Non-zero if \a one matches, zero if not.
 */
static int match_it(struct Client *from, struct Client *one, const char *mask, int what)
{
  switch (what)
  {
    case MATCH_HOST:
      return (match(mask, cli_user(one)->host) == 0 ||
        (IsHiddenHost(one) && match(mask, cli_user(one)->realhost) == 0));
    case MATCH_SERVER:
    default:
      return (match(mask, cli_name(cli_user(one)->server)) == 0);
  }
}

/** Send an unprefixed line to a client.
 * @param[in] to Client receiving message.
 * @param[in] pattern Format string of message.
 */
void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  struct MsgBuf *mb;
  va_list vl;

  va_start(vl, pattern);
  mb = msgq_vmake(to, pattern, vl);
  va_end(vl);

  send_buffer(to, mb, 0);

  msgq_clean(mb);
}

/** Send a line without a source prefix to one local client, with the tags
 * its capabilities call for (format_message_tags_for_ex() as for a line
 * from this server: @label or the labeled-response @batch when answering
 * a labeled command, @time under server-time; nothing else applies to a
 * server source).  For server lines that have always been unprefixed --
 * draft/account-registration's "REGISTER SUCCESS <account> :..." -- so a
 * client that asked for no tags sees the line byte for byte as before.
 * @param[in] to Client to send to.
 * @param[in] pattern Format string for the line. */
void sendrawto_one_tags(struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[512];
  char *tags;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  tags = format_message_tags_for_ex(tagbuf, sizeof(tagbuf), &me, to, NULL);
  if (tags)
    mb = msgq_make(to, "%s%v", tags, &vd);
  else
    mb = msgq_make(to, "%v", &vd);
  va_end(vd.vd_args);

  send_buffer(to, mb, 0);
  msgq_clean(mb);
}

/** Send a raw line (@a pattern carries its own prefix, and no tags) to a
 * local client as part of the answer to the line it is handling: tagged
 * with the innermost batch open on that answer -- the labeled batch
 * (deferred or not: labeled_batch_defer()), or a typed batch nested in it
 * -- else with the line's label while it is still to be answered (this
 * line answers it), else bare.  A line sent outside any labeled answer
 * goes out byte for byte as sendrawto_one() would send it.
 * @param[in] to Client to send to.
 * @param[in] pattern Format string for the line. */
void sendrawto_one_answer(struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[128];

  tagbuf[0] = '\0';
  if (MyConnect(to) && batch_current_id(to)[0])
    ircd_snprintf(NULL, tagbuf, sizeof(tagbuf), "@batch=%s ", batch_current_id(to));
  else if (MyConnect(to) && cli_label(to)[0] && !cli_label_responded(to)
           && feature_bool(FEAT_CAP_labeled_response) && LabeledResponseInUse(to)) {
    ircd_snprintf(NULL, tagbuf, sizeof(tagbuf), "@label=%s ", cli_label(to));
    cli_label_responded(to) = 1;
  }
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  mb = msgq_make(cli_from(to), "%s%v", tagbuf, &vd);
  va_end(vd.vd_args);
  send_buffer(to, mb, 0);
  msgq_clean(mb);
}

/** Send a (prefixed) command to a single client.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Client *cptr;
  char s2s_tagbuf[128];
  char tagbuf[512];
  char *tags;
  int prio;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* For S2S messages, add compact tags.  Gate on FLAG_IRCV3AWARE so
   * legacy peers (which don't speak the @A compact format) don't pay
   * the prefix bytes against the 512-byte wire budget — they'd strip
   * the @-prefixed tags but the bytes still count, risking content
   * truncation on long messages.  Same gating discipline as 350769a
   * applied to the v3-only S2S tokens.
   *
   * A hold mark (s2s_held_override) needs no term of its own: it is
   * armed only beside a session id and emitted only with one, so the
   * sessid term covers it, and the else branch clears it with the
   * sessid. */
  if ((IsServer(to) || IsMe(to)) && feature_bool(FEAT_P10_MESSAGE_TAGS) &&
      IsIRCv3Aware(to) &&
      (s2s_msgid_override[0] || s2s_sessid_override[0] ||
       strcmp(tok, TOK_PRIVATE) == 0 || strcmp(tok, TOK_NOTICE) == 0 ||
       strcmp(tok, TOK_QUIT) == 0)) {
    if (s2s_msgid_override[0] && !s2s_sessid_override[0]) {
      /* Explicit tag override for forwarded commands / numeric relay
       * with no sessid component — fast path, builds tagbuf inline. */
      char time_b64[8];
      inttobase64_64(time_b64, s2s_time_override, 7);
      snprintf(s2s_tagbuf, sizeof(s2s_tagbuf), "@A%s%s ", time_b64, s2s_msgid_override);
      s2s_msgid_override[0] = '\0';
      s2s_time_override = 0;
      s2s_cptr_override = NULL;
      mb = msgq_make(to, "%s%:#C %s %v", s2s_tagbuf, from, tok, &vd);
    } else {
      /* General path: format_s2s_tags with cptr preservation.  Used
       * when sessid override is set (so the ,S segment gets emitted)
       * or for the channel-event tokens (PRIVMSG/NOTICE/QUIT) without
       * an msgid override.  format_s2s_tags consumes overrides. */
      cptr = s2s_cptr_override ? s2s_cptr_override
           : (MyConnect(from) ? NULL : cli_from(from));
      s2s_cptr_override = NULL;
      if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), cptr, NULL, 0)) {
        mb = msgq_make(to, "%s%:#C %s %v", s2s_tagbuf, from, tok, &vd);
      } else {
        mb = msgq_make(to, "%:#C %s %v", from, tok, &vd);
      }
    }
  } else {
    s2s_cptr_override = NULL;  /* Clear even if not used */
    s2s_msgid_override[0] = '\0';  /* Clear even if not used */
    s2s_sessid_override[0] = '\0';  /* Clear even if not used */
    s2s_held_override = '\0';
    s2s_time_override = 0;
    /* A line to a client inside the labeled-response batch its command
     * opened is part of that response: tag it the way send_reply() tags
     * the numerics around it (@batch, @time).  Untagged, it sits outside
     * the batch and a client collecting the response by batch id drops it
     * (the STATS help list, STATS w, VERSION's library notices).  Only the
     * synchronous batch labeled_batch_start() opened -- an async LIST
     * keeps cli_batch_id set across event-loop turns, and unrelated lines
     * must not join it. */
    tags = (MyConnect(to) && cli_labeled_batch(to))
         ? format_message_tags_for_ex(tagbuf, sizeof(tagbuf), from, to, NULL)
         : NULL;
    if (tags)
      mb = msgq_make(to, "%s%:#C %s %v", tags, from, cmd, &vd);
    else
      mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
                     &vd);
  }

  va_end(vd.vd_args);

  /* Flush immediately for messages from U-lined servers (services) */
  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;

  send_buffer(to, mb, prio);

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to a single client with message tags.
 * Includes @label, @time, and @account tags if the recipient supports them.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_tags(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[512];
  char msgidbuf[64];
  char *tags;
  const char *msgid = NULL;
  int prio;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* The event's msgid when the caller armed one (the JOIN/PART/NICK
   * echoes: the same id the other members got and history stored), else
   * a fresh one for PRIVMSG and NOTICE.  CMD_* expands to "MSG, TOK", so
   * compare the long name, and by content: identical literals in
   * different files need not share an address. */
  if (client_msgid_override[0])
    msgid = client_msgid_override;
  else if (feature_bool(FEAT_MSGID) &&
           (!strcmp(cmd, MSG_PRIVATE) || !strcmp(cmd, MSG_NOTICE))) {
    msgid = generate_msgid(msgidbuf, sizeof(msgidbuf));
  }

  tags = format_message_tags_for_ex(tagbuf, sizeof(tagbuf), from, to, msgid);

  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, IsServer(to) || IsMe(to) ? tok : cmd,
		   &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		   &vd);

  va_end(vd.vd_args);

  /* Flush immediately for messages from U-lined servers (services) */
  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;

  send_buffer(to, mb, prio);

  msgq_clean(mb);
}

/** Tag one event's line for one local client, as a channel fan-out tags
 * it: the msgid and @time the caller armed (sendcmdto_set_client_event),
 * @account, the oper and bot tags, each on the recipient's own caps --
 * never a batch the recipient has open nor its label.  With @a respond
 * the line answers the recipient's own command and leads with that
 * command's labeled-response @batch (the one labeled_batch_start()
 * opened), else its pending @label, which it consumes (no ACK follows).
 * @a client_tags, a delivered message's client-only tags, lead the
 * region for a recipient with message-tags.
 * @param[out] buf Buffer for the tag region, trailing space included.
 * @param[in] buflen Size of \a buf.
 * @param[in] from Client the event comes from.
 * @param[in] to Local client the line is for.
 * @param[in] respond Non-zero when the line answers \a to's own command.
 * @param[in] client_tags Client-only tags to lead with, or NULL.
 * @return \a buf, or NULL when the line carries no tags.
 */
static char *event_tags(char *buf, size_t buflen, struct Client *from,
                        struct Client *to, int respond, const char *client_tags)
{
  char head[96];
  char rest[256];
  int flags;
  int pos;

  if (!MyConnect(to))
    return NULL;

  head[0] = '\0';
  if (respond) {
    if (cli_labeled_batch(to) && cli_batch_id(to)[0]
        && feature_bool(FEAT_CAP_batch) && CapOwnHas(to, CAP_BATCH))
      snprintf(head, sizeof(head), "batch=%s", cli_batch_id(to));
    else if (feature_bool(FEAT_CAP_labeled_response) && LabeledResponseInUse(to)
             && cli_label(to)[0] && !cli_label_responded(to)) {
      snprintf(head, sizeof(head), "label=%s", cli_label(to));
      cli_label_responded(to) = 1;   /* answered: no ACK (send_labeled_ack) */
    }
  }

  /* format_message_tags_ex writes "@ " when its only flag found nothing
   * to say (account-tag, from no account): that is no tags. */
  flags = get_client_tag_flags(to, from, 0);
  if (!flags || !format_message_tags_ex(rest, sizeof(rest), from, flags)
      || rest[1] == ' ')
    rest[0] = '\0';
  if (!client_tags || !*client_tags || !CapOwnHas(to, CAP_MSGTAGS)
      || strlen(client_tags) + sizeof(head) + sizeof(rest) + 4 > buflen)
    client_tags = NULL;

  if (!client_tags && !head[0] && !rest[0])
    return NULL;

  /* Each part fits: head and rest by their sizes, client_tags by the
   * check above. */
  pos = snprintf(buf, buflen, "@%s", client_tags ? client_tags : "");
  if (head[0])
    pos += snprintf(buf + pos, buflen - pos, "%s%s", pos > 1 ? ";" : "", head);
  if (rest[0])   /* rest = "@...; " */
    snprintf(buf + pos, buflen - pos, "%s%s", pos > 1 ? ";" : "", rest + 1);
  else
    snprintf(buf + pos, buflen - pos, " ");
  return buf;
}

/** Send one event's line to a single local client, tagged as a channel
 * fan-out tags it: the msgid and @time the caller armed
 * (sendcmdto_set_client_event), @account, the oper and bot tags, each on
 * the recipient's own caps.  Unlike sendcmdto_one_tags, the line joins
 * no batch the recipient has open and takes none of its labels: an async
 * LIST keeps cli_batch_id set across event-loop turns (sendcmdto_one),
 * and a label left from the recipient's last command is not this line's.
 * Only when @a respond -- the line answers the recipient's own command
 * (its echo) -- does it carry that command's pending @label, or its
 * @batch inside the labeled batch the command opened
 * (labeled_batch_start), the same gate sendcmdto_one uses.
 * @param[in] from Client the event comes from.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] respond Non-zero when the line answers \a to's own command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_event(struct Client *from, const char *cmd, const char *tok,
                         struct Client *to, int respond, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[512];
  const char *tags;
  int prio;

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  tags = event_tags(tagbuf, sizeof(tagbuf), from, to, respond, NULL);

  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, IsServer(to) || IsMe(to) ? tok : cmd,
                   &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
                   &vd);

  va_end(vd.vd_args);

  /* Flush immediately for messages from U-lined servers (services) */
  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;

  send_buffer(to, mb, prio);

  msgq_clean(mb);
}

/** Deliver a message (PRIVMSG, NOTICE, TAGMSG) to a single local client
 * as the delivered message, not as the answer to that client's own
 * command: one it addressed to itself, or to its own bouncer session.
 * Tagged as
 * sendcmdto_one_event() tags an event (the msgid and @time the caller
 * armed, @account, the oper and bot tags), led by the sender's
 * client-only tags for a recipient with message-tags, and never with the
 * recipient's pending @label or inside a batch it has open.  Per
 * labeled-response, only the echo-message copy of a message to oneself
 * may carry the label; without one, the command is answered by ACK.
 * @param[in] from Client the message comes from.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (unused: \a to is a client).
 * @param[in] to Local client the message is delivered to.
 * @param[in] client_tags The sender's client-only tags, or NULL.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_delivery(struct Client *from, const char *cmd,
                            const char *tok, struct Client *to,
                            const char *client_tags, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[4608];
  const char *tags;
  int prio;

  (void)tok;
  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  tags = event_tags(tagbuf, sizeof(tagbuf), from, to, 0, client_tags);
  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, cmd, &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, cmd, &vd);

  va_end(vd.vd_args);

  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;
  send_buffer(to, mb, prio);
  msgq_clean(mb);
}

/** Send a (prefixed) command to a single client with message tags,
 * using a supplied msgid instead of generating one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] ext_msgid Message ID to include (may be NULL to skip).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_tags_ext(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, const char *ext_msgid,
		   const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[512];
  char *tags;
  int prio;

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  tags = format_message_tags_for_ex(tagbuf, sizeof(tagbuf), from, to, ext_msgid);

  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, IsServer(to) || IsMe(to) ? tok : cmd,
		   &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		   &vd);

  va_end(vd.vd_args);

  /* Flush immediately for messages from U-lined servers (services) */
  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;

  send_buffer(to, mb, prio);

  msgq_clean(mb);
}

/** Variant of sendcmdto_one_tags_ext() that includes client-only tags.
 *
 * For local-client destinations: uses format_message_tags_with_client
 * (existing per-recipient cap-aware tag formatting).
 *
 * For server-link destinations (= remote user delivery): uses
 * format_s2s_tags_with_client when the peer link is FLAG_IRCV3AWARE
 * to emit @A<time><msgid>,C<client_tags> prefix; non-IRCV3AWARE peers
 * get the bare command (matching pre-IRCV3-aware-framework behaviour
 * where direct PMs had no @A prefix at all).
 *
 * Used by relay_private_message and relay_private_notice for direct
 * user-to-user PMs/NOTICEs that may carry client-only tags
 * (+typing, +reply, +react, +channel-context).
 */
void sendcmdto_one_tags_with_client(struct Client *from,
                                    const char *cmd, const char *tok,
                                    struct Client *to,
                                    const char *ext_msgid,
                                    const char *client_tags,
                                    const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[4608];
  char s2s_tagbuf[4352];     /* fits @A prefix + ,S + ,H + ,M + ,F + ,C<4095-byte client_tags> */
  char *tags;
  int prio;
  int has_ctags = (client_tags && *client_tags);

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  if (IsServer(to) || IsMe(to)) {
    /* Server-link destination — use compact S2S tag prefix.
     * IRCV3AWARE peers get @A...,C<client_tags>; legacy peers get the
     * bare command (preserves pre-extension behaviour where direct
     * PMs to remote users had no @A prefix).
     *
     * The tag source is the ORIGIN, never `to`: passing the destination
     * link made format_s2s_tags_with_client read cli_s2s_msgid(to) -- the
     * last msgid PARSED off that link -- so a local PM sent right after a
     * services round-trip reused that message's id (2026-09-04).  For a
     * relayed message the origin link rides in s2s_cptr_override, and
     * format reads its stash only while that link's line is being
     * handled; for a locally-minted one the caller armed
     * s2s_msgid_override/time with this message's own id (ext_msgid),
     * which format takes ahead of any stash. */
    struct Client *tag_cptr = s2s_cptr_override;
    s2s_cptr_override = NULL;
    if (send_s2s_tags_on(to) &&
        format_s2s_tags_with_client(s2s_tagbuf, sizeof(s2s_tagbuf), tag_cptr,
                                    has_ctags ? client_tags : NULL,
                                    NULL, 0)) {
      mb = msgq_make(to, "%s%:#C %s %v", s2s_tagbuf, from, tok, &vd);
    } else {
      mb = msgq_make(to, "%:#C %s %v", from, tok, &vd);
    }
  } else {
    /* Local-client destination — use per-recipient cap-aware tag
     * formatting.  When client tags are present, format_message_tags_
     * with_client handles label + tags together.  When absent, fall
     * through to format_message_tags_for_ex so msgid lands properly
     * and the label isn't double-consumed: the _with_client path
     * side-effects cli_label_responded via its label branch even
     * when its return value gets discarded, so calling both eats
     * the label on the first send and emits it on neither (regression
     * caught by irctest testLabeledPrivmsgResponsesToSelf). */
    if (has_ctags)
      tags = format_message_tags_with_client(tagbuf, sizeof(tagbuf), from, to,
                                             client_tags);
    else
      tags = format_message_tags_for_ex(tagbuf, sizeof(tagbuf), from, to, ext_msgid);
    if (tags)
      mb = msgq_make(to, "%s%:#C %s %v", tags, from, cmd, &vd);
    else
      mb = msgq_make(to, "%:#C %s %v", from, cmd, &vd);
  }

  va_end(vd.vd_args);

  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;
  send_buffer(to, mb, prio);
  msgq_clean(mb);

  /* Consume any tag overrides the caller armed for this one send, so a
   * local-recipient path or a legacy (untagged) peer cannot leave them
   * to stamp the next server-bound emit. */
  s2s_cptr_override = NULL;
  s2s_msgid_override[0] = '\0';
  s2s_time_override = 0;
  s2s_ml_override[0] = '\0';
  s2s_fallback_override[0] = '\0';
  s2s_statusmsg_override = 0;
  statusmsg_user_text = NULL;
}

/** Send a line toward a server link with a stored row's client-only tags
 * in the compact tag region: @A<time_ms><msgid>,C<client_tags> (W5 Task
 * 2).  For the CH R line and the first CH B line a history responder
 * sends, and for a middle hop relaying them on (forward_fed_reply): the
 * row's own time and msgid stand in the @A part, so the receiver's stash
 * holds that row's, not an unrelated event's.
 *
 * With tags and a compact msgid (the 14 bytes parse_server copies), the
 * S2S msgid/time overrides are armed for one sendcmdto_one_tags_with_client
 * call, which builds the tag region only when send_s2s_tags_on(to) -- a
 * legacy link or P10_MESSAGE_TAGS off gets the bare line -- and clears
 * those overrides either way.  They are armed directly, not through
 * sendcmdto_set_s2s_tags: that also arms the client-facing event time
 * (client_event_ms), which no send here consumes and which would then
 * outlive this line.  Without tags, or with a msgid of another shape, the
 * plain sendcmdto_one line goes, as before.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (the one a server link gets).
 * @param[in] to Destination: a server link.
 * @param[in] time_ms The row's time (epoch ms; 0 = the HLC's).
 * @param[in] msgid The row's msgid.
 * @param[in] client_tags The row's client-only tags (NULL/empty = none).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_ctags(struct Client *from, const char *cmd, const char *tok,
                         struct Client *to, uint64_t time_ms, const char *msgid,
                         const char *client_tags, const char *pattern, ...)
{
  struct VarData vd;

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  if (client_tags && *client_tags && msgid && strlen(msgid) == 14) {
    s2s_time_override = time_ms;
    ircd_strncpy(s2s_msgid_override, msgid, sizeof(s2s_msgid_override));
    sendcmdto_one_tags_with_client(from, cmd, tok, to, msgid, client_tags, "%v", &vd);
  } else
    sendcmdto_one(from, cmd, tok, to, "%v", &vd);
  va_end(vd.vd_args);
}

/** Send a (prefixed) command to a single local client with message tags,
 * returning the generated msgid.
 * @param[in] from Client originating the message.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (used if \a to is a server or &me).
 * @param[in] to Destination of command.
 * @param[out] msgid_out Buffer to store generated msgid.
 * @param[in] msgid_out_len Size of msgid_out buffer.
 * @param[out] time_out Buffer to store generated timestamp.
 * @param[in] time_out_len Size of time_out buffer.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_tags_msgid(struct Client *from, const char *cmd, const char *tok,
		   struct Client *to, char *msgid_out, size_t msgid_out_len,
		   char *time_out, size_t time_out_len,
		   const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[512];
  char msgidbuf[64];
  char timebuf[32];
  char *tags;
  const char *msgid = NULL;
  struct timeval tv;
  struct tm tm;
  int prio;

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  /* Generate msgid for PRIVMSG and NOTICE if feature enabled */
  if (feature_bool(FEAT_MSGID) &&
      (strcmp(cmd, MSG_PRIVATE) == 0 || strcmp(cmd, MSG_NOTICE) == 0)) {
    msgid = generate_msgid(msgidbuf, sizeof(msgidbuf));
    if (msgid_out && msgid_out_len > 0) {
      ircd_strncpy(msgid_out, msgid, msgid_out_len - 1);
      msgid_out[msgid_out_len - 1] = '\0';
    }
  } else if (msgid_out && msgid_out_len > 0) {
    msgid_out[0] = '\0';
  }

  /* Generate timestamp - ISO for client @time= tag, Unix for storage */
  client_tag_tv(&tv);
  gmtime_r(&tv.tv_sec, &tm);
  snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           tv.tv_usec / 1000);
  /* Return Unix timestamp for internal storage/S2S */
  if (time_out && time_out_len > 0) {
    snprintf(time_out, time_out_len, "%lu.%03lu",
             (unsigned long)tv.tv_sec, (unsigned long)(tv.tv_usec / 1000));
  }

  tags = format_message_tags_for_ex(tagbuf, sizeof(tagbuf), from, to, msgid);

  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, IsServer(to) || IsMe(to) ? tok : cmd,
		   &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		   &vd);

  va_end(vd.vd_args);

  /* Flush immediately for messages from U-lined servers (services) */
  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;

  send_buffer(to, mb, prio);

  msgq_clean(mb);
}

/**
 * Send TAGMSG with client-only tags to a single local client.
 * Used for relaying +typing and other client-only tags.
 * @param[in] from Client sending the TAGMSG.
 * @param[in] cmd Long name of command (TAGMSG).
 * @param[in] to Destination of command.
 * @param[in] client_tags Client-only tags string from sender (e.g., "+typing=active").
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_one_client_tags(struct Client *from, const char *cmd,
                               struct Client *to, const char *client_tags,
                               const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  char tagbuf[4608];
  char *tags;
  int prio;

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  tags = format_message_tags_with_client(tagbuf, sizeof(tagbuf), from, to, client_tags);

  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, cmd, &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, cmd, &vd);

  va_end(vd.vd_args);

  /* Flush immediately for messages from U-lined servers (services) */
  prio = (feature_bool(FEAT_FLUSH_ULINE_IMMEDIATE) && is_from_uline(from)) ? 1 : 0;

  send_buffer(to, mb, prio);

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to a single client in the priority queue.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (used if \a to is a user).
 * @param[in] tok Short name of command (used if \a to is a server).
 * @param[in] to Destination of command.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_prio_one(struct Client *from, const char *cmd, const char *tok,
			struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
		 &vd);

  va_end(vd.vd_args);

  send_buffer(to, mb, 1);

  msgq_clean(mb);
}

/**
 * Send a (prefixed) command to all servers matching or not matching a
 * flag but one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] require Only send to servers with this Flag bit set.
 * @param[in] forbid Do not send to servers with this Flag bit set.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb = NULL;
  struct MsgBuf *mb_alias = NULL;
  struct DLink *lp;
  struct Client *alias_from = NULL;
  struct Client *primary_dir = NULL;

  /* Split S2S delivery for aliases (see sendcmdto_serv_butone) */
  if (s2s_alias_source) {
    alias_from = s2s_alias_source;
    s2s_alias_source = NULL;
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  } else if (IsBouncerAlias(from) && cli_alias_primary(from)) {
    alias_from = from;
    from = cli_alias_primary(from);
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  }

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  /* Two buffer variants per peer-class — see sendcmdto_serv_butone for
   * full rationale.  Tagged variant for IRCV3-aware peers, untagged
   * for legacy peers (so they don't pay @A bytes against the 512-byte
   * limit on tags they'll just strip). */
  {
    struct MsgBuf *mb_legacy = NULL;
    struct MsgBuf *mb_alias_legacy = NULL;
    int want_tags = s2s_want_tags;
    /* Sessid override (per redesign A.2) is also a tag-required signal:
     * if the caller staged a bouncer sessid for this emit, we must
     * generate the tagged variant so the ,S segment ships to
     * IRCv3-aware peers. */
    int has_sessid = (s2s_sessid_override[0] != '\0');
    s2s_want_tags = 0;

    if ((want_tags || has_sessid) && feature_bool(FEAT_P10_MESSAGE_TAGS)) {
      /* Check for pre-built raw tag string first */
      if (s2s_raw_tags[0]) {
        va_start(vd.vd_args, pattern);
        mb = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, from, tok, &vd);
        va_end(vd.vd_args);

        if (alias_from) {
          va_start(vd.vd_args, pattern);
          mb_alias = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, alias_from, tok, &vd);
          va_end(vd.vd_args);
        }
        s2s_raw_tags[0] = '\0';
        s2s_cptr_override = NULL;
        s2s_msgid_override[0] = '\0';
        s2s_sessid_override[0] = '\0';
        s2s_held_override = '\0';
        s2s_time_override = 0;
        s2s_client_tags_override = NULL;  /* no ,C slot on this path; clear unconsumed */
      } else {
        char s2s_tagbuf[128];
        struct Client *tag_cptr = s2s_cptr_override ? s2s_cptr_override
                                : (MyConnect(from) ? NULL : cli_from(from));
        s2s_cptr_override = NULL;

        if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), tag_cptr, NULL, 0)) {
          va_start(vd.vd_args, pattern);
          mb = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
          va_end(vd.vd_args);

          if (alias_from) {
            va_start(vd.vd_args, pattern);
            mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, alias_from, tok, &vd);
            va_end(vd.vd_args);
          }
        }
        /* Clear overrides consumed by format_s2s_tags */
        s2s_msgid_override[0] = '\0';
        s2s_time_override = 0;
        s2s_client_tags_override = NULL;  /* no ,C slot on this path; clear unconsumed */
      }
    } else {
      s2s_cptr_override = NULL;
      s2s_raw_tags[0] = '\0';
      s2s_msgid_override[0] = '\0';
      s2s_sessid_override[0] = '\0';
      s2s_held_override = '\0';
      s2s_time_override = 0;
      s2s_client_tags_override = NULL;  /* no tagged variant built; clear unconsumed */
    }

    /* Untagged variants for legacy peers — also serve as the only
     * variant when tags are disabled or format failed. */
    va_start(vd.vd_args, pattern);
    mb_legacy = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);

    if (alias_from) {
      va_start(vd.vd_args, pattern);
      mb_alias_legacy = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
      va_end(vd.vd_args);
    }

    /* If we never built a tagged variant, the legacy buffer is the
     * only buffer and gets used for everyone. */
    if (!mb) {
      mb = mb_legacy;
      mb_legacy = NULL;
      if (mb_alias_legacy) {
        if (mb_alias)
          msgq_clean(mb_alias);
        mb_alias = mb_alias_legacy;
        mb_alias_legacy = NULL;
      }
    }

    /* send it to our downlinks */
    for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
      struct MsgBuf *send_mb;
      struct MsgBuf *send_mb_alias;

      if (one && lp->value.cptr == cli_from(one))
        continue;
      if ((require < FLAG_LAST_FLAG) && !HasFlag(lp->value.cptr, require))
        continue;
      if ((forbid < FLAG_LAST_FLAG) && HasFlag(lp->value.cptr, forbid))
        continue;
      /* Burst-gate: peer is in convergence-defer window, holding our
       * burst-out to them.  Skip — the bulk burst at gate release
       * (server_finish_burst) will introduce this client to them as
       * part of its N loop.  Without this skip, in-flight relays from
       * other links during the gate window double-introduce users
       * (collision-kill on the gate-held peer).  A KILL, a SQUIT and
       * another server's EB/EA still go: each acts on what the peer
       * already has, and the burst never re-sends it
       * (bounce_burst_gate_passes()). */
      if (IsBurstGated(lp->value.cptr) && !bounce_burst_gate_passes(tok))
        continue;
      if (mb_legacy && !IsIRCv3Aware(lp->value.cptr)) {
        send_mb = mb_legacy;
        send_mb_alias = mb_alias_legacy;
      } else {
        send_mb = mb;
        send_mb_alias = mb_alias;
      }

      if (send_mb_alias && lp->value.cptr == primary_dir)
        send_buffer(lp->value.cptr, send_mb_alias, 0);
      else
        send_buffer(lp->value.cptr, send_mb, 0);
    }

    if (mb_legacy)
      msgq_clean(mb_legacy);
    if (mb_alias_legacy)
      msgq_clean(mb_alias_legacy);
  }

  msgq_clean(mb);
  if (mb_alias)
    msgq_clean(mb_alias);
}

/**
 * Send a (prefixed) command to all servers but one.
 * @param[in] from Client sending the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
			   const char *tok, struct Client *one,
			   const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb = NULL;
  struct MsgBuf *mb_alias = NULL;
  struct DLink *lp;
  struct Client *alias_from = NULL;
  struct Client *primary_dir = NULL;

  /* Split S2S delivery for aliases: two modes.
   * 1) Explicit: caller set s2s_alias_source (JOIN/PART via joinbuf)
   * 2) Automatic: from is an alias (MODE, KICK, TOPIC, etc.)
   * Send alias numeric to primary's server direction (avoids wrong-direction),
   * send primary numeric to all other servers. */
  if (s2s_alias_source) {
    alias_from = s2s_alias_source;
    s2s_alias_source = NULL;
    /* from is already the primary (caller rewrote it) */
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  } else if (IsBouncerAlias(from) && cli_alias_primary(from)) {
    alias_from = from;
    from = cli_alias_primary(from);
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  }

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  /* Two buffer variants: mb (with @A tag prefix, for IRCV3-aware peers)
   * and mb_legacy (no prefix, for legacy peers).  Legacy peers parse-
   * strip @-prefixed tags, but those bytes still count toward the
   * 512-byte wire budget — long PRIVMSG/NOTICE/JOIN-with-comment can
   * truncate.  Picking per-peer in the loop avoids the truncation
   * without losing tags for IRCV3-aware peers.  Same for alias
   * variant. */
  {
    struct MsgBuf *mb_legacy = NULL;
    struct MsgBuf *mb_alias_legacy = NULL;
    int want_tags = s2s_want_tags;
    /* Sessid override (per redesign A.2) is also a tag-required signal:
     * if the caller staged a bouncer sessid for this emit, we must
     * generate the tagged variant so the ,S segment ships to
     * IRCv3-aware peers. */
    int has_sessid = (s2s_sessid_override[0] != '\0');
    s2s_want_tags = 0;

    if ((want_tags || has_sessid) && feature_bool(FEAT_P10_MESSAGE_TAGS)) {
      /* Check for pre-built raw tag string (multi-msgid CREATE/PART) */
      if (s2s_raw_tags[0]) {
        va_start(vd.vd_args, pattern);
        mb = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, from, tok, &vd);
        va_end(vd.vd_args);

        if (alias_from) {
          va_start(vd.vd_args, pattern);
          mb_alias = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, alias_from, tok, &vd);
          va_end(vd.vd_args);
        }
        s2s_raw_tags[0] = '\0';
        s2s_cptr_override = NULL;
        s2s_msgid_override[0] = '\0';
        s2s_sessid_override[0] = '\0';
        s2s_held_override = '\0';
        s2s_time_override = 0;
        s2s_client_tags_override = NULL;  /* no ,C slot on this path; clear unconsumed */
      } else {
        char s2s_tagbuf[128];
        struct Client *tag_cptr = s2s_cptr_override ? s2s_cptr_override
                                : (MyConnect(from) ? NULL : cli_from(from));
        s2s_cptr_override = NULL;

        if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), tag_cptr, NULL, 0)) {
          va_start(vd.vd_args, pattern);
          mb = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
          va_end(vd.vd_args);

          /* Alias buffer also needs tag prefix */
          if (alias_from) {
            va_start(vd.vd_args, pattern);
            mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, alias_from, tok, &vd);
            va_end(vd.vd_args);
          }
        }
        /* Clear overrides consumed by format_s2s_tags */
        s2s_msgid_override[0] = '\0';
        s2s_time_override = 0;
        s2s_client_tags_override = NULL;  /* no ,C slot on this path; clear unconsumed */
      }
    } else {
      /* No tagged variant was built, so nothing consumed the overrides.
       * Clear them here or they ride the next server-bound emit: an
       * ACCOUNT/AWAY relay armed by sendcmdto_set_s2s_tags() without
       * sendcmdto_want_s2s_tags() stamped the next cross-server PRIVMSG
       * with the auth-time msgid and timestamp (2026-09-04). */
      s2s_cptr_override = NULL;
      s2s_raw_tags[0] = '\0';
      s2s_msgid_override[0] = '\0';
      s2s_sessid_override[0] = '\0';
      s2s_held_override = '\0';
      s2s_time_override = 0;
      s2s_client_tags_override = NULL;  /* no tagged variant built; clear unconsumed */
    }

    /* Untagged variants for legacy peers — also serve as the only
     * variant when tags are disabled or format failed. */
    va_start(vd.vd_args, pattern);
    mb_legacy = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);

    if (alias_from) {
      va_start(vd.vd_args, pattern);
      mb_alias_legacy = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
      va_end(vd.vd_args);
    }

    /* If we never built a tagged variant, the legacy buffer is the
     * only buffer and gets used for everyone. */
    if (!mb) {
      mb = mb_legacy;
      mb_legacy = NULL;
      if (mb_alias_legacy) {
        if (mb_alias)
          msgq_clean(mb_alias);
        mb_alias = mb_alias_legacy;
        mb_alias_legacy = NULL;
      }
    }

    /* send it to our downlinks */
    for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
      struct MsgBuf *send_mb;
      struct MsgBuf *send_mb_alias;

      if (one && lp->value.cptr == cli_from(one))
        continue;
      /* Burst-gate skip: peer is holding our burst; bulk server_finish_burst
       * at gate release provides the consistent state snapshot.  A KILL,
       * a SQUIT and another server's EB/EA still go.  See
       * sendcmdto_flag_serv_butone for the full rationale. */
      if (IsBurstGated(lp->value.cptr) && !bounce_burst_gate_passes(tok))
        continue;

      /* Pick tagged or legacy variant per-peer. */
      if (mb_legacy && !IsIRCv3Aware(lp->value.cptr)) {
        send_mb = mb_legacy;
        send_mb_alias = mb_alias_legacy;
      } else {
        send_mb = mb;
        send_mb_alias = mb_alias;
      }

      if (send_mb_alias && lp->value.cptr == primary_dir)
        send_buffer(lp->value.cptr, send_mb_alias, 0);
      else
        send_buffer(lp->value.cptr, send_mb, 0);
    }

    if (mb_legacy)
      msgq_clean(mb_legacy);
    if (mb_alias_legacy)
      msgq_clean(mb_alias_legacy);
  }

  msgq_clean(mb);
  if (mb_alias)
    msgq_clean(mb_alias);
}

/** Send a (prefixed) command to all IRCv3-aware servers but one.
 *
 * Identical to sendcmdto_serv_butone() except non-IRCv3-aware peers are
 * skipped during the downlink dispatch. Use this for fork-only P10 tokens
 * that legacy peers would silently drop (BT, BS, CH, MD, ML, RD, TM, etc.
 * — see ircv3aware-s2s-framework plan for the full list). Legacy peers
 * just don't receive the emission at all, saving wire bytes and avoiding
 * the 512-byte pre-strip line limit risk.
 *
 * BX (BOUNCER_TRANSFER) P is the explicit exception — only the P
 * subcommand (in-place numeric swap / membership transfer) must reach
 * legacy peers, which have been patched to handle it, and those emissions
 * go on the unconditional sendcmdto_serv_butone() path (a promote) or
 * per legacy link (bounce_legacy_face_change(), which renumbers or
 * retracts a face a legacy link knows). Every other BX subcommand (C, U,
 * X, N, V, and the unknown-subcommand relay) is fork-only noise to a
 * legacy peer — its m_bouncer_transfer.c processes only P and silently
 * relays the rest (bouncer design intent, invariant #7: "Legacy wire
 * vocabulary is BX P only") — so those sites use this function like any
 * other fork-only P10 token.
 *
 * Implementation note: this function duplicates the body of
 * sendcmdto_serv_butone() rather than calling it through a static gate
 * flag, because variadic forwarding without a vsendcmdto* helper would
 * require building the va_list twice. The duplication is shallow (mostly
 * msgq_make calls + the dispatch loop); refactor to a shared inner helper
 * if either function grows nontrivially.
 */
void sendcmdto_serv_butone_v3(struct Client *from, const char *cmd,
                              const char *tok, struct Client *one,
                              const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb = NULL;
  struct MsgBuf *mb_alias = NULL;
  struct DLink *lp;
  struct Client *alias_from = NULL;
  struct Client *primary_dir = NULL;

  if (s2s_alias_source) {
    alias_from = s2s_alias_source;
    s2s_alias_source = NULL;
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  } else if (IsBouncerAlias(from) && cli_alias_primary(from)) {
    alias_from = from;
    from = cli_alias_primary(from);
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  }

  vd.vd_format = pattern;

  {
    int want_tags = s2s_want_tags;
    s2s_want_tags = 0;

    if (want_tags && feature_bool(FEAT_P10_MESSAGE_TAGS)) {
      if (s2s_raw_tags[0]) {
        va_start(vd.vd_args, pattern);
        mb = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, from, tok, &vd);
        va_end(vd.vd_args);
        if (alias_from) {
          va_start(vd.vd_args, pattern);
          mb_alias = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, alias_from, tok, &vd);
          va_end(vd.vd_args);
        }
        s2s_raw_tags[0] = '\0';
        s2s_cptr_override = NULL;
        s2s_msgid_override[0] = '\0';
        s2s_sessid_override[0] = '\0';
        s2s_held_override = '\0';
        s2s_time_override = 0;
        s2s_client_tags_override = NULL;  /* no ,C slot on this path; clear unconsumed */
      } else {
        struct Client *tag_cptr = s2s_cptr_override ? s2s_cptr_override
                                : (MyConnect(from) ? NULL : cli_from(from));
        s2s_cptr_override = NULL;
        if (s2s_client_tags_override) {
          /* Client-only tags ride ,C instead of the message body
           * (audit 0.1): a channel TAGMSG with a large client tag no
           * longer risks the receiver's 512-byte S2S cap. Sized for
           * the IRCv3 4094-byte client-tag maximum plus the compact
           * prefix (,S/,M included). */
          char s2s_tagbuf_ctags[4200];
          const char *ctags = s2s_client_tags_override;
          s2s_client_tags_override = NULL;  /* consumed */
          if (format_s2s_tags_with_client(s2s_tagbuf_ctags, sizeof(s2s_tagbuf_ctags),
                                          tag_cptr, ctags, NULL, 0)) {
            va_start(vd.vd_args, pattern);
            mb = msgq_make(&me, "%s%C %s %v", s2s_tagbuf_ctags, from, tok, &vd);
            va_end(vd.vd_args);
            if (alias_from) {
              va_start(vd.vd_args, pattern);
              mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf_ctags, alias_from, tok, &vd);
              va_end(vd.vd_args);
            }
          }
        } else {
          char s2s_tagbuf[128];
          if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), tag_cptr, NULL, 0)) {
            va_start(vd.vd_args, pattern);
            mb = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
            va_end(vd.vd_args);
            if (alias_from) {
              va_start(vd.vd_args, pattern);
              mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, alias_from, tok, &vd);
              va_end(vd.vd_args);
            }
          }
        }
        s2s_msgid_override[0] = '\0';
        s2s_time_override = 0;
      }
    } else {
      /* No tagged variant was built, so nothing consumed the overrides.
       * Clear them here or they ride the next server-bound emit: an
       * ACCOUNT/AWAY relay armed by sendcmdto_set_s2s_tags() without
       * sendcmdto_want_s2s_tags() stamped the next cross-server PRIVMSG
       * with the auth-time msgid and timestamp (2026-09-04). */
      s2s_cptr_override = NULL;
      s2s_raw_tags[0] = '\0';
      s2s_msgid_override[0] = '\0';
      s2s_sessid_override[0] = '\0';
      s2s_held_override = '\0';
      s2s_time_override = 0;
      s2s_client_tags_override = NULL;  /* no tagged variant built; clear unconsumed */
    }
  }

  if (!mb) {
    va_start(vd.vd_args, pattern);
    mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
    if (alias_from) {
      va_start(vd.vd_args, pattern);
      mb_alias = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
      va_end(vd.vd_args);
    }
  }

  /* IRCv3-aware downlink dispatch: skip legacy peers entirely. */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    if (!IsIRCv3Aware(lp->value.cptr))
      continue;
    if (IsBurstGated(lp->value.cptr))
      continue;
    if (mb_alias && lp->value.cptr == primary_dir)
      send_buffer(lp->value.cptr, mb_alias, 0);
    else
      send_buffer(lp->value.cptr, mb, 0);
  }

  msgq_clean(mb);
  if (mb_alias)
    msgq_clean(mb_alias);
}

/** Send a (prefixed) command to all NON-IRCv3-aware (legacy) servers but one.
 *
 * Inverse of sendcmdto_serv_butone_v3 — the dispatch loop SKIPS peers that
 * advertise IRCv3 awareness, so only legacy peers receive the emission.
 *
 * NEVER builds a tagged variant, even if the caller armed S2S tags for a
 * paired sendcmdto_serv_butone_v3() / sendcmdto_serv_butone() call that
 * shares the same emit: a legacy peer cannot parse message tags, and every
 * other serv_butone variant already pays the @A bytes toward the 512-byte
 * wire budget only for peers that can use them.  Every S2S override
 * (raw tags, msgid, time, sessid, client-tags, cptr) is cleared
 * unconditionally here, the same as the untagged branch every other
 * serv_butone variant falls back to when no tagged variant is built —
 * nothing here ever consumes them, so a caller sharing tags with an
 * _v3/plain emit that runs first (e.g. away_send_to_servers()) is safe:
 * that first call drains the overrides, and this one clears whatever,
 * if anything, is left.
 *
 * Supported wire shapes through this helper (every one a legacy peer's
 * handler actually understands):
 *   - BX P (`CMD_BOUNCER_TRANSFER` subcommand 'P') — in-place numeric
 *     swap or membership transfer-and-kill via legacy m_bouncer_transfer.c.
 *   - SVSINFO (ghost realname sync).
 *   - PRIVS (oper-privilege sync, fork-only privileges stripped).
 *   - AWAY (the pre-away star, substituted to FEAT_AWAY_STAR_MSG).
 * The rule for adding a new one: only a line a legacy peer's own handler
 * parses and acts on correctly belongs here, and it must never carry
 * tags — everything else (BX C / X / A / K / U / M / E, and any other
 * fork-only token) is silently dropped by legacy peers and wastes the
 * emission; use sendcmdto_serv_butone_v3() for those instead.
 *
 * No BX C emission is paired with a BX P any more: an alias introduced by
 * BX C alone was never known to a legacy peer (the pair only ever relayed
 * through it), and a client a legacy peer knew by its N and a BX C then
 * converts leaves it with a QUIT (bounce_legacy_face_change()) -- a BX P
 * naming two numerics it knows made it drop the face without telling the
 * services behind it.
 *
 * Implementation note: the alias-source egress rewrite block
 * (s2s_alias_source / IsBouncerAlias preamble) is preserved verbatim —
 * invariant #10 from the bouncer-architecture skill applies to every S2S
 * helper that accepts arbitrary `from` clients.
 */
void sendcmdto_legacy_serv_butone(struct Client *from, const char *cmd,
                                  const char *tok, struct Client *one,
                                  const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb = NULL;
  struct MsgBuf *mb_alias = NULL;
  struct DLink *lp;
  struct Client *alias_from = NULL;
  struct Client *primary_dir = NULL;

  if (s2s_alias_source) {
    alias_from = s2s_alias_source;
    s2s_alias_source = NULL;
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  } else if (IsBouncerAlias(from) && cli_alias_primary(from)) {
    alias_from = from;
    from = cli_alias_primary(from);
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  }

  vd.vd_format = pattern;

  /* Never a tagged variant: a legacy peer can't parse message tags, so
   * this helper never stages one.  Clear every S2S override exactly like
   * the untagged branch every other serv_butone variant falls back to
   * when it built no tagged line -- an override left armed rides the
   * next server-bound emit. */
  s2s_want_tags = 0;
  s2s_cptr_override = NULL;
  s2s_raw_tags[0] = '\0';
  s2s_msgid_override[0] = '\0';
  s2s_sessid_override[0] = '\0';
  s2s_held_override = '\0';
  s2s_time_override = 0;
  s2s_client_tags_override = NULL;

  va_start(vd.vd_args, pattern);
  mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);
  if (alias_from) {
    va_start(vd.vd_args, pattern);
    mb_alias = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
    va_end(vd.vd_args);
  }

  /* Legacy-only downlink dispatch: skip IRCv3-aware peers entirely
   * (they get the fork form of the same event from the caller's paired
   * _v3 or unconditional send).  What goes here is only the legacy form
   * a legacy peer's own handler acts on -- BX P, SVSINFO, PRIVS, AWAY,
   * per the header above -- and it is never tagged. */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    if (IsIRCv3Aware(lp->value.cptr))
      continue;
    if (IsBurstGated(lp->value.cptr))
      continue;
    if (mb_alias && lp->value.cptr == primary_dir)
      send_buffer(lp->value.cptr, mb_alias, 0);
    else
      send_buffer(lp->value.cptr, mb, 0);
  }

  msgq_clean(mb);
  if (mb_alias)
    msgq_clean(mb_alias);
}

/** Safely increment the sentalong marker.
 * This increments the sentalong marker.  Since new connections will
 * have con_sentalong() == 0, and to avoid confusion when the counter
 * wraps, we reset all sentalong markers to zero when the sentalong
 * marker hits zero.
 * @param[in,out] one Client to mark with new sentalong marker (if any).
 */
static void
bump_sentalong(struct Client *one)
{
  if (!++sentalong_marker)
  {
    int ii;
    for (ii = 0; ii < HighestFd; ++ii)
      if (LocalClientArray[ii])
        cli_sentalong(LocalClientArray[ii]) = 0;
    ++sentalong_marker;
  }
  if (one)
    cli_sentalong(one) = sentalong_marker;
}

/** The body of sendcmdto_common_channels_butone() and
 * sendcmdto_common_channels_but_session(): @a from's line to the local
 * members of its channels, each once, except @a one (a client direction,
 * or NULL) and, with @a skip_devices, @a from's own bouncer aliases.
 * @a pattern's arguments come as @a ap, copied for each buffer built. */
static void
common_channels_vsend(struct Client *from, const char *cmd, struct Client *one,
                      int skip_devices, const char *pattern, va_list ap)
{
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[TAGS_CACHE_SIZE] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *chan;
  struct Membership *member;
  char tagbuf[128];
  int flags;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_copy(vd.vd_args, ap);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  bump_sentalong(from);

  /* Set tag context for per-connection CAP routing */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = CAP_NONE;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;
    for (member = chan->channel->members; member;
	 member = member->next_member)
      if (MyConnect(member->user)
          && member->user != one
          && !(skip_devices && IsBouncerAlias(member->user)
               && cli_alias_primary(member->user) == from)
          && cli_sentalong(member->user) != sentalong_marker) {
	cli_sentalong(member->user) = sentalong_marker;
	flags = get_client_tag_flags(member->user, from, 1);
	if (flags) {
	  /* Build cached message buffer for this flag combination if needed */
	  if (!mb_cache[flags]) {
	    if (format_message_tags_ex(tagbuf, sizeof(tagbuf), from, flags)) {
	      va_copy(vd.vd_args, ap);
	      mb_cache[flags] = msgq_make(0, "%s%:#C %s %v", tagbuf, from, cmd, &vd);
	      va_end(vd.vd_args);
	    }
	  }
	  if (mb_cache[flags])
	    send_buffer(member->user, mb_cache[flags], 0);
	  else
	    send_buffer(member->user, mb, 0);
	} else {
	  send_buffer(member->user, mb, 0);
	}
      }
  }

  if (MyConnect(from) && from != one) {
    flags = get_client_tag_flags(from, from, 1);
    if (flags && mb_cache[flags])
      send_buffer(from, mb_cache[flags], 0);
    else
      send_buffer(from, mb, 0);
  }

  /* Clear cap route context */
  cap_route_ctx.stc_active = 0;

  msgq_clean(mb);
  for (flags = 0; flags < TAGS_CACHE_SIZE; flags++) {
    if (mb_cache[flags])
      msgq_clean(mb_cache[flags]);
  }
}

/** Send a (prefixed) command to all channels that \a from is on.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_common_channels_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Client *one,
				      const char *pattern, ...)
{
  va_list ap;

  va_start(ap, pattern);
  common_channels_vsend(from, cmd, one, 0, pattern, ap);
  va_end(ap);
}

/** See include/send.h. */
void sendcmdto_common_channels_but_session(struct Client *from,
                                           const char *cmd, const char *tok,
                                           const char *pattern, ...)
{
  va_list ap;

  (void)tok;
  va_start(ap, pattern);
  common_channels_vsend(from, cmd, from, 1, pattern, ap);
  va_end(ap);
}

/** Send a (prefixed) command to all channels that \a from is on.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
/* An optional SECOND required capability for the next channel-capab send
 * (sendcmdto_common_channels_capab_butone / sendcmdto_channel_capab_butserv_butone),
 * consumed by that call.  Lets a caller split one event by two caps, e.g.
 * away-notify AND draft/pre-away versus away-notify WITHOUT it. */
static int sendcmdto_extra_withcap = CAP_NONE;

void sendcmdto_set_extra_withcap(int cap)
{
  sendcmdto_extra_withcap = cap;
}

/** Whether @a to, a connection the channel walk did not pick -- the
 * sender itself or one of its bouncer devices -- takes a channel-capab
 * send: the same three filters as the walk, read from the connection's
 * own caps (CapOwnHas(), as send_buffer()'s CapRouteContext check does).
 * Each connection, a bouncer device included, has its own caps; a local
 * client's cli_active mirrors them (bounce_recompute_session_caps()). */
static int capab_own_wants(struct Client *to, int withcap, int skipcap,
                           int extracap)
{
  if ((withcap != CAP_NONE) && !CapOwnHas(to, withcap))
    return 0;
  if ((skipcap != CAP_NONE) && CapOwnHas(to, skipcap))
    return 0;
  if ((extracap != CAP_NONE) && !CapOwnHas(to, extracap))
    return 0;
  return 1;
}

/** Queue one recipient's copy of a channel-capab send: the buffer with the
 * tags @a to negotiated (built on first use into @a mb_cache), else the
 * untagged @a mb. */
static void capab_send_tagged(struct Client *to, struct Client *from,
                              const char *cmd, struct MsgBuf *mb,
                              struct MsgBuf **mb_cache,
                              const char *pattern, va_list ap)
{
  struct VarData vd;
  char tagbuf[128];
  int flags = get_client_tag_flags(to, from, 0);

  if (flags && !mb_cache[flags]
      && format_message_tags_ex(tagbuf, sizeof(tagbuf), from, flags)) {
    vd.vd_format = pattern;
    va_copy(vd.vd_args, ap);
    mb_cache[flags] = msgq_make(0, "%s%:#C %s %v", tagbuf, from, cmd, &vd);
    va_end(vd.vd_args);
  }
  send_buffer(to, (flags && mb_cache[flags]) ? mb_cache[flags] : mb, 0);
}

/** The body of sendcmdto_common_channels_capab_butone() and
 * sendcmdto_common_channels_capab_session(): @a from's line to the local
 * members of its channels that pass the capability filters, each once,
 * except @a one; to @a from itself when it is ours and not @a one; and,
 * with @a devices, to every local bouncer device of @a from (an alias
 * whose primary it is), whether or not it shares a channel with it.
 * Every copy carries the tags its recipient negotiated -- @a from's own
 * too, which used to go untagged unless a member with the same tag set
 * had been sent one first. */
static void
common_channels_capab_vsend(struct Client *from, const char *cmd,
                            struct Client *one, int withcap, int skipcap,
                            int devices, const char *pattern, va_list ap)
{
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[TAGS_CACHE_SIZE] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *chan;
  struct Membership *member;
  int extracap = sendcmdto_extra_withcap;
  int flags;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_copy(vd.vd_args, ap);
  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Marks from itself: the walk never sends it a copy (it is a member of
   * its own channels); the step after the walk does. */
  bump_sentalong(from);

  /* Set tag context for per-connection CAP routing */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = withcap;
  cap_route_ctx.stc_skipcap = skipcap;

  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;
    for (member = chan->channel->members; member;
         member = member->next_member) {
      if (!MyConnect(member->user)
          || member->user == one
          || cli_sentalong(member->user) == sentalong_marker)
        continue;
      if ((withcap != CAP_NONE) && !CapActive(member->user, withcap))
        continue;
      if ((skipcap != CAP_NONE) && CapActive(member->user, skipcap))
        continue;
      if ((extracap != CAP_NONE) && !CapActive(member->user, extracap))
        continue;
      cli_sentalong(member->user) = sentalong_marker;
      capab_send_tagged(member->user, from, cmd, mb, mb_cache, pattern, ap);
    }
  }

  if (MyConnect(from) && from != one
      && capab_own_wants(from, withcap, skipcap, extracap))
    capab_send_tagged(from, from, cmd, mb, mb_cache, pattern, ap);

  /* The devices of from's bouncer session on this server, found by their
   * primary pointer rather than through the session record: the record is
   * filed under the account, which the callers of this form have just
   * changed (an account change) or whose sessions they have just ended (a
   * logout).  A device of another server is that server's: the same line
   * reaches it there.  A device sharing a channel with from was reached
   * by the walk already (sentalong).  The walk costs a pass over the
   * local clients, skipped when this server has no device at all
   * (UserStats.local_aliases, kept by the bouncer's count rule); a device
   * already leaving (FLAG_CLOSING) is skipped, as the session end's walk
   * skips it. */
  if (devices && UserStats.local_aliases) {
    int i;

    for (i = 0; i <= HighestFd; i++) {
      struct Client *dev = LocalClientArray[i];

      if (!dev || dev == from || dev == one || !IsUser(dev)
          || !IsBouncerAlias(dev) || HasFlag(dev, FLAG_CLOSING)
          || cli_alias_primary(dev) != from
          || cli_sentalong(dev) == sentalong_marker
          || !capab_own_wants(dev, withcap, skipcap, extracap))
        continue;
      cli_sentalong(dev) = sentalong_marker;
      capab_send_tagged(dev, from, cmd, mb, mb_cache, pattern, ap);
    }
  }

  /* Clear cap route context */
  cap_route_ctx.stc_active = 0;
  cap_route_ctx.stc_withcap = CAP_NONE;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  msgq_clean(mb);
  for (flags = 0; flags < TAGS_CACHE_SIZE; flags++) {
    if (mb_cache[flags])
      msgq_clean(mb_cache[flags]);
  }
  sendcmdto_extra_withcap = CAP_NONE;
}

void sendcmdto_common_channels_capab_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Client *one,
                                      int withcap, int skipcap,
                                      const char *pattern, ...)
{
  va_list ap;

  (void)tok;
  va_start(ap, pattern);
  common_channels_capab_vsend(from, cmd, one, withcap, skipcap, 0, pattern, ap);
  va_end(ap);
}

/** See include/send.h. */
void sendcmdto_common_channels_capab_session(struct Client *from,
                                             const char *cmd, const char *tok,
                                             int withcap,
                                             const char *pattern, ...)
{
  va_list ap;

  (void)tok;
  va_start(ap, pattern);
  common_channels_capab_vsend(from, cmd, NULL, withcap, CAP_NONE, 1, pattern, ap);
  va_end(ap);
}

/** The body of sendcmdto_channel_butserv_butone() and
 * sendcmdto_channel_butserv_respond(): @a from's line to the local
 * members of @a to, except @a one and those @a skip rules out.  The copy
 * to @a asker, when it is one of them, answers its command
 * (event_tags(): its labeled-response @batch or pending @label).
 * @a pattern's arguments come as @a ap, copied for each buffer built. */
static void
channel_butserv_vsend(struct Client *from, const char *cmd, struct Channel *to,
                      struct Client *one, struct Client *asker,
                      unsigned int skip, const char *pattern, va_list ap)
{
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[TAGS_CACHE_SIZE] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *member;
  char tagbuf[128];
  int flags;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_copy(vd.vd_args, ap);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Set tag context for per-connection CAP routing */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = CAP_NONE;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member)&& !HasVoice(member))
        || (skip & SKIP_CHGHOST && CapActive(member->user, CAP_CHGHOST))
        || !persistence_channel_visible(member->user, to->chname))
        continue;
    if (member->user == asker) {
      /* The asker's own copy: its tags for itself, never the cache's. */
      char atags[512];
      struct MsgBuf *amb;

      va_copy(vd.vd_args, ap);
      if (event_tags(atags, sizeof(atags), from, asker, 1, NULL))
        amb = msgq_make(0, "%s%:#C %s %v", atags, from, cmd, &vd);
      else
        amb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
      va_end(vd.vd_args);
      send_buffer(asker, amb, 0);
      msgq_clean(amb);
      continue;
    }
    flags = get_client_tag_flags(member->user, from, 0);
    if (flags) {
      /* Build cached message buffer for this flag combination if needed */
      if (!mb_cache[flags]) {
        if (format_message_tags_ex(tagbuf, sizeof(tagbuf), from, flags)) {
          va_copy(vd.vd_args, ap);
          mb_cache[flags] = msgq_make(0, "%s%:#C %s %v", tagbuf, from, cmd, &vd);
          va_end(vd.vd_args);
        }
      }
      if (mb_cache[flags])
        send_buffer(member->user, mb_cache[flags], 0);
      else
        send_buffer(member->user, mb, 0);
    } else {
      send_buffer(member->user, mb, 0);
    }
  }

  /* Clear cap route context */
  cap_route_ctx.stc_active = 0;

  msgq_clean(mb);
  for (flags = 0; flags < TAGS_CACHE_SIZE; flags++) {
    if (mb_cache[flags])
      msgq_clean(mb_cache[flags]);
  }
}

/** Send a (prefixed) command to all local users on a channel.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (ignored).
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_DEAF, SKIP_NONOPS, SKIP_NONVOICES indicating which clients to skip.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
				      const char *tok, struct Channel *to,
				      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  va_list ap;

  va_start(ap, pattern);
  channel_butserv_vsend(from, cmd, to, one, NULL, skip, pattern, ap);
  va_end(ap);
}

/** Send a channel event a client's own command caused to all local users
 * on the channel, as sendcmdto_channel_butserv_butone() does (skipping
 * nobody), the copy to @a asker answering that command: it carries the
 * command's labeled-response @batch, or its pending @label (consumed, so
 * no ACK follows).  The other members' copies, a bouncer sibling of
 * @a asker's included, are tagged as before.
 * @param[in] from Client originating the event.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (ignored).
 * @param[in] to Destination channel.
 * @param[in] asker The local connection whose command this answers, or
 *   NULL (then the same as sendcmdto_channel_butserv_butone()).
 * @param[in] skip Bitmask of SKIP_* flags, as for
 *   sendcmdto_channel_butserv_butone().
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butserv_respond(struct Client *from, const char *cmd,
                                       const char *tok, struct Channel *to,
                                       struct Client *asker, unsigned int skip,
                                       const char *pattern, ...)
{
  va_list ap;

  (void)tok;
  va_start(ap, pattern);
  channel_butserv_vsend(from, cmd, to, NULL,
                        (asker && MyConnect(asker)) ? asker : NULL, skip,
                        pattern, ap);
  va_end(ap);
}

/** Open a labeled-response batch for a command naming a comma-separated
 * list of targets, when it names two or more different ones: each gets
 * a line of its own.  For one target the single line carries the label
 * itself, and for none the command is answered by ACK (or its error).
 * @param[in] sptr Local client whose command it is.
 * @param[in] list The target list ("#a,#b").
 * @return Non-zero if a batch was opened (labeled_batch_start()).
 */
int labeled_batch_start_list(struct Client *sptr, const char *list)
{
  const char *first = NULL, *p;
  size_t first_len = 0;

  for (p = list; p && *p; ) {
    const char *end = strchr(p, ',');
    size_t len = end ? (size_t)(end - p) : strlen(p);

    if (len) {
      if (!first) {
        first = p;
        first_len = len;
      } else if (len != first_len || ircd_strncmp(p, first, len))
        return labeled_batch_start(sptr);
    }
    p = end ? end + 1 : NULL;
  }
  return 0;
}

/** Send a (prefixed) command to all local users on a channel with or without
 *  a client capability specified.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command (ignored).
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_DEAF, SKIP_NONOPS, SKIP_NONVOICES indicating which clients to skip.
 * @param[in] withcap CAP_* that the user must have active to receive the message.
 * @param[in] skipcap CAP_* that the user must not have active to receive the message.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_capab_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      int withcap, int skipcap,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[TAGS_CACHE_SIZE] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *member;
  char tagbuf[128];
  int flags;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Set tag context for per-connection CAP routing */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = withcap;
  cap_route_ctx.stc_skipcap = skipcap;

  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member)&& !HasVoice(member))
        || (skip & SKIP_CHGHOST && CapActive(member->user, CAP_CHGHOST))
        || !persistence_channel_visible(member->user, to->chname))
        continue;
    if ((withcap != CAP_NONE) && !CapActive(member->user, withcap))
        continue;
    if ((skipcap != CAP_NONE) && CapActive(member->user, skipcap))
        continue;
    if ((sendcmdto_extra_withcap != CAP_NONE)
        && !CapActive(member->user, sendcmdto_extra_withcap))
        continue;
    flags = get_client_tag_flags(member->user, from, 0);
    if (flags) {
      /* Build cached message buffer for this flag combination if needed */
      if (!mb_cache[flags]) {
        if (format_message_tags_ex(tagbuf, sizeof(tagbuf), from, flags)) {
          va_start(vd.vd_args, pattern);
          mb_cache[flags] = msgq_make(0, "%s%:#C %s %v", tagbuf, from, cmd, &vd);
          va_end(vd.vd_args);
        }
      }
      if (mb_cache[flags])
        send_buffer(member->user, mb_cache[flags], 0);
      else
        send_buffer(member->user, mb, 0);
    } else {
      send_buffer(member->user, mb, 0);
    }
  }

  /* Clear cap route context */
  cap_route_ctx.stc_active = 0;
  cap_route_ctx.stc_withcap = CAP_NONE;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  msgq_clean(mb);
  for (flags = 0; flags < TAGS_CACHE_SIZE; flags++) {
    if (mb_cache[flags])
      msgq_clean(mb_cache[flags]);
  }
  sendcmdto_extra_withcap = CAP_NONE;
}

/** Send TAGMSG with client-only tags to channel members with message-tags capability.
 * Used for relaying +typing and other client-only tags to channels.
 * @param[in] from Client originating the TAGMSG.
 * @param[in] cmd Long name of command (TAGMSG).
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_DEAF, SKIP_NONOPS, SKIP_NONVOICES indicating which clients to skip.
 * @param[in] client_tags Client-only tags string from sender (e.g., "+typing=active").
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_client_tags(struct Client *from, const char *cmd,
                                   struct Channel *to, struct Client *one,
                                   unsigned int skip, const char *client_tags,
                                   const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Membership *member;
  char tagbuf[4608];

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  /* Set tag context to filter out connections without message-tags capability.
   * TAGMSG is meaningless without tags, so connections that don't support
   * message-tags must not receive these messages. */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = CAP_MSGTAGS;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  /* Send to each local channel member with message-tags capability */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member) && !HasVoice(member))
        || !wants_message_tags(member->user)
        || !persistence_channel_visible(member->user, to->chname))
        continue;

    /* Build message with client-only tags for this recipient */
    if (format_message_tags_with_client(tagbuf, sizeof(tagbuf), from, member->user, client_tags)) {
      va_start(vd.vd_args, pattern);
      mb = msgq_make(0, "%s%:#C %s %v", tagbuf, from, cmd, &vd);
      va_end(vd.vd_args);
      send_buffer(member->user, mb, 0);
      msgq_clean(mb);
    }
  }

  /* Reset cap route context */
  cap_route_ctx.stc_active = 0;
  cap_route_ctx.stc_withcap = CAP_NONE;

  va_end(vd.vd_args);
}

/** Send a (prefixed) command to all servers with users on \a to.
 * Skip \a from and \a one plus those indicated in \a skip.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS and SKIP_NONVOICES indicating which clients to skip.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_servers_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *serv_mb;
  struct MsgBuf *serv_mb_alias = NULL;
  struct Membership *member;
  struct Client *alias_from = NULL;
  struct Client *primary_dir = NULL;

  /* Split S2S delivery for aliases (see sendcmdto_serv_butone) */
  if (s2s_alias_source) {
    alias_from = s2s_alias_source;
    s2s_alias_source = NULL;
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  } else if (IsBouncerAlias(from) && cli_alias_primary(from)) {
    alias_from = from;
    from = cli_alias_primary(from);
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  }

  /* build the buffer */
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%:#C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  if (alias_from) {
    va_start(vd.vd_args, pattern);
    serv_mb_alias = msgq_make(&me, "%:#C %s %v", alias_from, tok, &vd);
    va_end(vd.vd_args);
  }

  /* send the buffer to each server */
  bump_sentalong(one);
  cli_sentalong(from) = sentalong_marker;
  for (member = to->members; member; member = member->next_member) {
    if (MyConnect(member->user)
        || IsZombie(member)
        || cli_fd(cli_from(member->user)) < 0
        || cli_sentalong(member->user) == sentalong_marker
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member)&& !HasVoice(member)))
      continue;
    cli_sentalong(member->user) = sentalong_marker;
    if (serv_mb_alias && cli_from(member->user) == primary_dir)
      send_buffer(member->user, serv_mb_alias, 0);
    else
      send_buffer(member->user, serv_mb, 0);
  }
  msgq_clean(serv_mb);
  if (serv_mb_alias)
    msgq_clean(serv_mb_alias);
}

/** Send a fork-only channel line to every IRCv3-aware server link with a
 * member of \a to behind it (W5 Task 13), once per link.
 *
 * Who gets it: a direct server link is sent the line when some member of
 * \a to is not ours (MyConnect members are this server's to deliver), not
 * a zombie, reached through that link (whose fd is open), and -- with
 * SKIP_DEAF in \a skip -- not deaf (+d); never the link toward \a one
 * (bump_sentalong), never a legacy (!IsIRCv3Aware) link and never a link
 * whose burst is still gated.  No local client is sent anything.
 *
 * That is the receiving server's own delivery predicate for a channel
 * TAGMSG (sendcmdto_channel_client_tags skips deaf members and nothing
 * else a remote server can know), so every server whose local delivery
 * would reach a member is routed the line, and every server whose receive
 * window is open (channel_has_local_member: non-zombie, MyConnect, not
 * deaf, no positive SILENCE -- a subset) is too.  A bursting link is not
 * skipped: TAGMSG never skipped one.
 *
 * The lines are built exactly as sendcmdto_serv_butone_v3() builds them
 * (its alias preamble and tag block, verbatim): the tagged variant -- the
 * armed msgid/time, or the stash of the link \a one's line came on through
 * s2s_cptr_override, and ,C from sendcmdto_set_s2s_client_tags() -- when
 * sendcmdto_want_s2s_tags(1) was armed and P10_MESSAGE_TAGS is on, else
 * the plain line.  An alias \a from goes as its primary, and as itself
 * toward the primary's own direction (no fake direction there).  Every S2S
 * override it may read is cleared whether or not a link got the line.
 *
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command (ignored).
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip SKIP_DEAF, or 0.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_serv_butone_v3(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb = NULL;
  struct MsgBuf *mb_alias = NULL;
  struct Membership *member;
  struct Client *alias_from = NULL;
  struct Client *primary_dir = NULL;

  if (s2s_alias_source) {
    alias_from = s2s_alias_source;
    s2s_alias_source = NULL;
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  } else if (IsBouncerAlias(from) && cli_alias_primary(from)) {
    alias_from = from;
    from = cli_alias_primary(from);
    primary_dir = MyConnect(from) ? NULL : cli_from(from);
  }

  vd.vd_format = pattern;

  {
    int want_tags = s2s_want_tags;
    s2s_want_tags = 0;

    if (want_tags && feature_bool(FEAT_P10_MESSAGE_TAGS)) {
      if (s2s_raw_tags[0]) {
        va_start(vd.vd_args, pattern);
        mb = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, from, tok, &vd);
        va_end(vd.vd_args);
        if (alias_from) {
          va_start(vd.vd_args, pattern);
          mb_alias = msgq_make(&me, "%s%C %s %v", s2s_raw_tags, alias_from, tok, &vd);
          va_end(vd.vd_args);
        }
        s2s_raw_tags[0] = '\0';
        s2s_cptr_override = NULL;
        s2s_msgid_override[0] = '\0';
        s2s_sessid_override[0] = '\0';
        s2s_held_override = '\0';
        s2s_time_override = 0;
        s2s_client_tags_override = NULL;  /* no ,C slot on this path; clear unconsumed */
      } else {
        struct Client *tag_cptr = s2s_cptr_override ? s2s_cptr_override
                                : (MyConnect(from) ? NULL : cli_from(from));
        s2s_cptr_override = NULL;
        if (s2s_client_tags_override) {
          /* Client-only tags ride ,C (audit 0.1); sized as in
           * sendcmdto_serv_butone_v3(). */
          char s2s_tagbuf_ctags[4200];
          const char *ctags = s2s_client_tags_override;
          s2s_client_tags_override = NULL;  /* consumed */
          if (format_s2s_tags_with_client(s2s_tagbuf_ctags, sizeof(s2s_tagbuf_ctags),
                                          tag_cptr, ctags, NULL, 0)) {
            va_start(vd.vd_args, pattern);
            mb = msgq_make(&me, "%s%C %s %v", s2s_tagbuf_ctags, from, tok, &vd);
            va_end(vd.vd_args);
            if (alias_from) {
              va_start(vd.vd_args, pattern);
              mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf_ctags, alias_from, tok, &vd);
              va_end(vd.vd_args);
            }
          }
        } else {
          char s2s_tagbuf[128];
          if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), tag_cptr, NULL, 0)) {
            va_start(vd.vd_args, pattern);
            mb = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
            va_end(vd.vd_args);
            if (alias_from) {
              va_start(vd.vd_args, pattern);
              mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, alias_from, tok, &vd);
              va_end(vd.vd_args);
            }
          }
        }
        s2s_msgid_override[0] = '\0';
        s2s_time_override = 0;
      }
    } else {
      /* No tagged variant was built, so nothing consumed the overrides:
       * clear them, or they ride the next server-bound emit (see
       * sendcmdto_serv_butone_v3()). */
      s2s_cptr_override = NULL;
      s2s_raw_tags[0] = '\0';
      s2s_msgid_override[0] = '\0';
      s2s_sessid_override[0] = '\0';
      s2s_held_override = '\0';
      s2s_time_override = 0;
      s2s_client_tags_override = NULL;  /* no tagged variant built; clear unconsumed */
    }
  }

  if (!mb) {
    va_start(vd.vd_args, pattern);
    mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
    if (alias_from) {
      va_start(vd.vd_args, pattern);
      mb_alias = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
      va_end(vd.vd_args);
    }
  }

  /* Member-routed dispatch: each link once (a remote member's sentalong
   * is its link's), and only an IRCv3-aware, ungated link is sent it. */
  bump_sentalong(one);
  for (member = to->members; member; member = member->next_member) {
    struct Client *link;

    if (MyConnect(member->user) || IsZombie(member))
      continue;
    if ((skip & SKIP_DEAF) && IsDeaf(member->user))
      continue;
    link = cli_from(member->user);
    if (cli_fd(link) < 0 || cli_sentalong(member->user) == sentalong_marker)
      continue;
    cli_sentalong(member->user) = sentalong_marker;
    if (!IsIRCv3Aware(link) || IsBurstGated(link))
      continue;
    if (mb_alias && link == primary_dir)
      send_buffer(link, mb_alias, 0);
    else
      send_buffer(link, mb, 0);
  }

  msgq_clean(mb);
  if (mb_alias)
    msgq_clean(mb_alias);
}


/** Whether a channel message from \a from skips \a member: a zombie (no
 * longer a reader), a member the \a skip flags leave out (SKIP_DEAF: +d;
 * SKIP_BURST: behind a server still bursting; SKIP_NONOPS / NONHOPS /
 * NONVOICES), or one whose SILENCE list matches \a from when
 * SILENCE_CHANMSGS is on.  The member filter of sendcmdto_channel_butone()
 * and sendcmdto_channel_butone_with_client_tags(), the channel relay's
 * sends; multiline delivery (m_batch.c) uses it too, so a batch reaches
 * the members a single line reaches.
 * @param[in] from The message's source (the face: an alias's primary).
 * @param[in] member The channel member.
 * @param[in] skip Bitmask of SKIP_* flags.
 * @return Non-zero when the member does not get the message.
 */
int channel_member_skipped(struct Client *from, struct Membership *member,
                           unsigned int skip)
{
  return IsZombie(member) ||
         (skip & SKIP_DEAF && IsDeaf(member->user)) ||
         (skip & SKIP_NONOPS && !IsChanOp(member)) ||
         (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member)) ||
         (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member) && !HasVoice(member)) ||
         (skip & SKIP_BURST && IsBurstOrBurstAck(cli_from(member->user))) ||
         (is_silenced(from, member->user, 1));
}

/** Send a (prefixed) command to all users on this channel, except for
 * \a one and those matching \a skip.
 * @warning \a pattern must not contain %v.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS, SKIP_NONVOICES, SKIP_DEAF, SKIP_BURST.
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butone(struct Client *from, const char *cmd,
			      const char *tok, struct Channel *to,
			      struct Client *one, unsigned int skip,
			      unsigned char prefix, const char *pattern, ...)
{
  struct Membership *member;
  struct VarData vd;
  struct MsgBuf *user_mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *user_mb_cache[TAGS_CACHE_SIZE] = {0};  /* Indexed by TAGS_* flag combinations */
  struct MsgBuf *serv_mb;
  struct MsgBuf *serv_mb_tags = NULL;  /* S2S tagged version */
  struct MsgBuf *serv_mb_alias = NULL; /* Alias numeric for primary's server direction */
  struct MsgBuf *serv_mb_legacy = NULL; /* Untagged primary numeric for non-IRCv3-aware peers */
  struct Client *service;
  struct Client *cptr;  /* Server connection for incoming S2S tags */
  struct Client *alias_from;    /* Alias source for split S2S delivery */
  struct Client *primary_dir;   /* Primary's server direction (for split comparison) */
  const char *userfmt;
  const char *usercmd;
  char tagbuf[128];
  char s2s_tagbuf[128];
  char userfmt_tags[64];
  int tflags;

  vd.vd_format = pattern;

  /* A status-message PRIVMSG goes only through
   * sendcmdto_channel_butone_with_client_tags(): never mark this line ,P
   * nor deliver it as one (see s2s_statusmsg_override). */
  s2s_statusmsg_override = 0;
  statusmsg_user_text = NULL;

  /* Consume alias source override for split S2S delivery.
   * When set, we build two S2S buffers: primary numeric for most servers,
   * alias numeric for the primary's server direction (avoids fake direction). */
  alias_from = s2s_alias_source;
  primary_dir = alias_from ? cli_from(from) : NULL;
  s2s_alias_source = NULL;

  /* Get the server connection for S2S tag handling.
   * s2s_cptr_override is set by alias source rewriting — when the primary
   * is substituted for the alias as 'from', the cptr would be NULL (primary
   * is local), losing incoming S2S tags.  The override preserves them. */
  cptr = s2s_cptr_override ? s2s_cptr_override
       : (MyConnect(from) ? NULL : cli_from(from));
  s2s_cptr_override = NULL;

  /* Build buffer to send to users */
  usercmd = cmd;
  userfmt = "%:#C %s %v";
  if (skip & (SKIP_NONOPS | SKIP_NONHOPS | SKIP_NONVOICES)) {
    usercmd = MSG_NOTICE;
    if (skip & SKIP_NONVOICES)
      userfmt = "%:#C %s +%v";
    else if (skip & SKIP_NONHOPS)
      userfmt = "%:#C %s %%%v";
    else
      userfmt = "%:#C %s @%v";
  }

  va_start(vd.vd_args, pattern);
  user_mb = msgq_make(0, userfmt, from, usercmd, &vd);
  va_end(vd.vd_args);

  /* Prepare tagged format string for building cached buffers */
  ircd_snprintf(0, userfmt_tags, sizeof(userfmt_tags), "%%s%s", userfmt);

  /* Build buffer to send to servers - with S2S tags if enabled.  Legacy
   * (non-IRCv3-aware) peers never see the @A... prefix: they don't parse
   * it, and it eats bytes against their 512-byte limit that a client
   * line near the limit cannot spare (audit 1.5 -- live on prod: Fractal
   * sends @A-tagged channel lines to the stock legacy hub, which keeps
   * the tag and truncates the message's tail to fit). When tags are off
   * or format_s2s_tags fails, serv_mb is already untagged and doubles as
   * the legacy buffer, so there's nothing extra to build. */
  if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), cptr, NULL, 0)) {
    va_start(vd.vd_args, pattern);
    serv_mb_tags = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
    va_end(vd.vd_args);
    serv_mb = serv_mb_tags;  /* Use tagged version */

    va_start(vd.vd_args, pattern);
    serv_mb_legacy = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
  } else {
    va_start(vd.vd_args, pattern);
    serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
  }
  /* The msgid/time override was armed for this message alone (audit
   * 0.4b): consume it now that the prefix is built (or tags are off),
   * as the serv_butone family does.  Left armed, it stamped the next
   * server-bound line -- a QUIT relay, a forwarded command -- with this
   * message's msgid and time. */
  s2s_msgid_override[0] = '\0';
  s2s_time_override = 0;

  /* Build alias S2S buffer for the primary's server direction */
  if (alias_from) {
    va_start(vd.vd_args, pattern);
    if (serv_mb_tags)
      serv_mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, alias_from, tok, &vd);
    else
      serv_mb_alias = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
    va_end(vd.vd_args);
  }

  /* Set tag context for per-connection CAP routing */
  cap_route_ctx.stc_active = 1;
  cap_route_ctx.stc_withcap = CAP_NONE;
  cap_route_ctx.stc_skipcap = CAP_NONE;

  /* send buffer along! */
  bump_sentalong(one);
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (channel_member_skipped(from, member, skip) ||
        (cli_fd(cli_from(member->user)) < 0 && !MyConnect(member->user)) ||
        cli_sentalong(member->user) == sentalong_marker)
      continue;
    cli_sentalong(member->user) = sentalong_marker;

    if (MyConnect(member->user)) { /* pick right buffer to send */
      if (!persistence_channel_visible(member->user, to->chname))
        continue;
      tflags = get_client_tag_flags(member->user, from, 0);
      if (tflags) {
        /* Build cached message buffer for this flag combination if needed */
        if (!user_mb_cache[tflags]) {
          if (format_message_tags_ex(tagbuf, sizeof(tagbuf), from, tflags)) {
            va_start(vd.vd_args, pattern);
            user_mb_cache[tflags] = msgq_make(0, userfmt_tags, tagbuf, from, usercmd, &vd);
            va_end(vd.vd_args);
          }
        }
        if (user_mb_cache[tflags])
          send_buffer(member->user, user_mb_cache[tflags], 0);
        else
          send_buffer(member->user, user_mb, 0);
      } else {
        send_buffer(member->user, user_mb, 0);
      }
    } else {
      /* Legacy (non-IRCv3-aware) peers never get a tagged buffer, nor an
       * alias numeric -- aliases are introduced only via BX C, which
       * legacy peers never learn (invariant #10), so a routed command
       * sourced from the alias is an unknown source at the first legacy
       * hop.  Check the next hop's awareness first; otherwise fall back
       * to the existing alias-vs-primary choice. */
      struct Client *link = cli_from(member->user);
      if (serv_mb_legacy && !IsIRCv3Aware(link))
        send_buffer(member->user, serv_mb_legacy, 0);
      else if (serv_mb_alias && link == primary_dir)
        send_buffer(member->user, serv_mb_alias, 0);
      else
        send_buffer(member->user, serv_mb, 0);
    }
  }
  /* Consult service forwarding table. */
  if(GlobalForwards[prefix]
      && (service = FindServer(GlobalForwards[prefix]))
      && cli_sentalong(service) != sentalong_marker) {
      cli_sentalong(service) = sentalong_marker;
      if (serv_mb_legacy && !IsIRCv3Aware(cli_from(service)))
        send_buffer(service, serv_mb_legacy, 0);
      else
        send_buffer(service, serv_mb, 0);
  }

  /* Clear cap route context */
  cap_route_ctx.stc_active = 0;

  msgq_clean(user_mb);
  /* Walk the full 32-slot cache: TAGS_MSGID (0x10) bit means valid
   * tflags values reach 31.  A `< 16` bound here leaked every cached
   * MsgBuf whose tflags included TAGS_MSGID — fired on every
   * channel PRIVMSG to a recipient with CAP_MSGTAGS when the relay
   * had a msgid override staged. */
  for (tflags = 0; tflags < TAGS_CACHE_SIZE; tflags++) {
    if (user_mb_cache[tflags])
      msgq_clean(user_mb_cache[tflags]);
  }
  msgq_clean(serv_mb);
  if (serv_mb_alias)
    msgq_clean(serv_mb_alias);
  if (serv_mb_legacy)
    msgq_clean(serv_mb_legacy);
}

/** Send a (prefixed) command to all users on this channel, except for
 * \a one and those matching \a skip. Includes client-only tags for
 * clients with message-tags capability.
 * @warning \a pattern must not contain %v.
 * @param[in] from Client originating the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination channel.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] skip Bitmask of SKIP_NONOPS, SKIP_NONVOICES, SKIP_DEAF, SKIP_BURST.
 * @param[in] prefix Prefix character for statusmsg (@, %, +).
 * @param[in] client_tags Client-only tags string (e.g., "+typing=active;+reply=xxx").
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_channel_butone_with_client_tags(struct Client *from,
                              const char *cmd, const char *tok,
                              struct Channel *to, struct Client *one,
                              unsigned int skip, unsigned char prefix,
                              const char *client_tags,
                              const char *pattern, ...)
{
  struct Membership *member;
  struct VarData vd;
  struct MsgBuf *user_mb;
  struct MsgBuf *user_mb_tags = NULL;
  struct MsgBuf *serv_mb;
  struct MsgBuf *serv_mb_tags = NULL;
  struct MsgBuf *serv_mb_v3 = NULL;     /* @A...,C<client_tags> for IRCv3-aware peers */
  struct MsgBuf *serv_mb_alias = NULL; /* Alias numeric for primary's server direction */
  struct MsgBuf *serv_mb_alias_v3 = NULL; /* Alias numeric, IRCv3-aware variant */
  struct MsgBuf *serv_mb_legacy = NULL; /* Untagged primary numeric for non-IRCv3-aware peers */
  struct Client *service;
  struct Client *cptr;
  struct Client *alias_from;    /* Alias source for split S2S delivery */
  struct Client *primary_dir;   /* Primary's server direction */
  const char *userfmt;
  const char *usercmd;
  char tagbuf[4608];
  char s2s_tagbuf[128];
  char s2s_tagbuf_v3[4200];     /* fits @A prefix + ,C<4094-byte client_tags> */
  char userfmt_tags[64];
  int has_ctags = (client_tags && *client_tags);
  const char *sm_text = statusmsg_user_text;   /* #226, see below */
  char sm_status = '\0';

  vd.vd_format = pattern;
  statusmsg_user_text = NULL;

  /* Consume alias source override for split S2S delivery */
  alias_from = s2s_alias_source;
  primary_dir = alias_from ? cli_from(from) : NULL;
  s2s_alias_source = NULL;

  /* Get the server connection for S2S tag handling.
   * s2s_cptr_override is set by alias source rewriting — when the primary
   * is substituted for the alias as 'from', the cptr would be NULL (primary
   * is local), losing incoming S2S tags.  The override preserves them. */
  cptr = s2s_cptr_override ? s2s_cptr_override
       : (MyConnect(from) ? NULL : cli_from(from));
  s2s_cptr_override = NULL;

  /* Build buffer to send to users */
  usercmd = cmd;
  userfmt = "%:#C %s %v";
  if (skip & (SKIP_NONOPS | SKIP_NONHOPS | SKIP_NONVOICES)) {
    usercmd = MSG_NOTICE;
    if (skip & SKIP_NONVOICES) {
      userfmt = "%:#C %s +%v";
      sm_status = '+';
    } else if (skip & SKIP_NONHOPS) {
      userfmt = "%:#C %s %%%v";
      sm_status = '%';
    } else {
      userfmt = "%:#C %s @%v";
      sm_status = '@';
    }
  }
  /* A status-message PRIVMSG (#226): the wall line goes to servers as it
   * is (the "<status> " lead in its text, ,P toward IRCv3-aware links),
   * and local members get ":<from> PRIVMSG <status><chan> :<sm_text>"
   * instead of the NOTICE.  Only for a wall command's status filter. */
  if (!sm_status)
    sm_text = NULL;
  else if (sm_text)
    usercmd = MSG_PRIVATE;
  /* No status-message PRIVMSG here (no wall status filter, or nothing
   * armed): the S2S line must not carry its ,P mark either -- an arm
   * paired with an ordinary channel send would otherwise mark a P line. */
  if (!sm_text)
    s2s_statusmsg_override = 0;

  if (sm_text)
    user_mb = msgq_make(0, "%:#C %s %c%s :%s", from, usercmd, sm_status,
                        to->chname, sm_text);
  else {
    va_start(vd.vd_args, pattern);
    user_mb = msgq_make(0, userfmt, from, usercmd, &vd);
    va_end(vd.vd_args);
  }

  /* Prepare tagged format string */
  ircd_snprintf(0, userfmt_tags, sizeof(userfmt_tags), "%%s%s", userfmt);

  /* Build buffer to send to servers - with S2S tags if enabled.
   * When client_tags are present, additionally build a v3 buffer with
   * ,C<client_tags> in the compact-tag prefix; the dispatch loop picks
   * it for IRCv3-aware peers so they can forward the tags to their
   * local recipients. Legacy peers get a separate untagged buffer
   * (serv_mb_legacy, below) -- they don't parse the @A... prefix and
   * it eats bytes against their 512-byte limit (audit 1.5). When tags
   * are off or format_s2s_tags fails, serv_mb is already untagged and
   * doubles as the legacy buffer.
   *
   * The tag region is formatted ONCE (audit 0.4b).  Two format calls
   * minted two msgids when neither an override nor the link's stash
   * supplied one -- the ,C copy and the plain copy of one message went
   * out under different ids -- and the first call consumed the ,S
   * hint, so only the plain copy carried it.  With client tags, the
   * ,C prefix is built and the plain prefix is that string cut before
   * its ,C segment: the time and msgid are base64 and the ,S and ,M
   * data hold no comma, so the first ",C" after them starts the client
   * tags. */
  {
    int has_prefix = 0;

    if (has_ctags) {
      if (format_s2s_tags_with_client(s2s_tagbuf_v3, sizeof(s2s_tagbuf_v3),
                                      cptr, client_tags, NULL, 0)) {
        const char *head = s2s_tagbuf_v3 + 2;   /* past "@A" */
        const char *cseg = strstr(head + strcspn(head, ", "), ",C");
        size_t plen = cseg ? (size_t)(cseg - s2s_tagbuf_v3) : 0;

        if (cseg && plen + 2 <= sizeof(s2s_tagbuf)) {
          memcpy(s2s_tagbuf, s2s_tagbuf_v3, plen);
          s2s_tagbuf[plen] = ' ';
          s2s_tagbuf[plen + 1] = '\0';
          has_prefix = 1;
        }
      }
    } else if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), cptr, NULL, 0))
      has_prefix = 1;

    if (has_prefix) {
      va_start(vd.vd_args, pattern);
      serv_mb_tags = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
      va_end(vd.vd_args);
      serv_mb = serv_mb_tags;

      va_start(vd.vd_args, pattern);
      serv_mb_legacy = msgq_make(&me, "%C %s %v", from, tok, &vd);
      va_end(vd.vd_args);

      if (has_ctags) {
        va_start(vd.vd_args, pattern);
        serv_mb_v3 = msgq_make(&me, "%s%C %s %v", s2s_tagbuf_v3, from, tok, &vd);
        va_end(vd.vd_args);
      }
    } else {
      va_start(vd.vd_args, pattern);
      serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
      va_end(vd.vd_args);
    }
  }
  /* Consumed: armed for this message alone (see sendcmdto_channel_butone). */
  s2s_msgid_override[0] = '\0';
  s2s_time_override = 0;
  s2s_statusmsg_override = 0;   /* not consumed when tags are off */

  /* Build alias S2S buffer for the primary's server direction */
  if (alias_from) {
    va_start(vd.vd_args, pattern);
    if (serv_mb_tags)
      serv_mb_alias = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, alias_from, tok, &vd);
    else
      serv_mb_alias = msgq_make(&me, "%C %s %v", alias_from, tok, &vd);
    va_end(vd.vd_args);

    /* Alias variant also needs a v3 buffer when client_tags present and
     * the v3 prefix was successfully built above. */
    if (serv_mb_v3) {
      va_start(vd.vd_args, pattern);
      serv_mb_alias_v3 = msgq_make(&me, "%s%C %s %v", s2s_tagbuf_v3, alias_from, tok, &vd);
      va_end(vd.vd_args);
    }
  }

  /* send buffer along! */
  bump_sentalong(one);
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (channel_member_skipped(from, member, skip) ||
        (cli_fd(cli_from(member->user)) < 0 && !MyConnect(member->user)) ||
        cli_sentalong(member->user) == sentalong_marker)
      continue;
    cli_sentalong(member->user) = sentalong_marker;

    if (MyConnect(member->user)) {
      if (!persistence_channel_visible(member->user, to->chname))
        continue;
      /* For clients with message-tags cap, include client-only tags */
      if (CapOwnHas(member->user, CAP_MSGTAGS) && client_tags && *client_tags) {
        /* Build message with client-only tags + server tags for this recipient */
        if (format_message_tags_with_client(tagbuf, sizeof(tagbuf), from, member->user, client_tags)) {
          if (sm_text)
            user_mb_tags = msgq_make(0, "%s%:#C %s %c%s :%s", tagbuf, from, usercmd,
                                     sm_status, to->chname, sm_text);
          else {
            va_start(vd.vd_args, pattern);
            user_mb_tags = msgq_make(0, userfmt_tags, tagbuf, from, usercmd, &vd);
            va_end(vd.vd_args);
          }
          send_buffer(member->user, user_mb_tags, 0);
          msgq_clean(user_mb_tags);
        } else {
          send_buffer(member->user, user_mb, 0);
        }
      } else {
        /* No message-tags or no client tags - send plain or with server tags only */
        int tflags = get_client_tag_flags(member->user, from, 0);
        if (tflags) {
          if (format_message_tags_ex(tagbuf, sizeof(tagbuf), from, tflags)) {
            if (sm_text)
              user_mb_tags = msgq_make(0, "%s%:#C %s %c%s :%s", tagbuf, from, usercmd,
                                       sm_status, to->chname, sm_text);
            else {
              va_start(vd.vd_args, pattern);
              user_mb_tags = msgq_make(0, userfmt_tags, tagbuf, from, usercmd, &vd);
              va_end(vd.vd_args);
            }
            send_buffer(member->user, user_mb_tags, 0);
            msgq_clean(user_mb_tags);
          } else {
            send_buffer(member->user, user_mb, 0);
          }
        } else {
          send_buffer(member->user, user_mb, 0);
        }
      }
    } else {
      /* S2S delivery. Pick buffer based on:
       *   0. Legacy (non-IRCv3-aware) peers always get the untagged
       *      primary-numeric buffer -- never a tagged variant, and
       *      never an alias numeric either (invariant #10: aliases
       *      are introduced only via BX C, which legacy peers never
       *      learn).
       *   1. Primary-direction alias rewriting (serv_mb_alias variants)
       *   2. IRCv3-aware peers get the ,C<client_tags> variant when available
       *   3. Otherwise the standard prefix-only or no-prefix buffer
       */
      struct Client *peer_link = cli_from(member->user);
      int is_v3 = IsIRCv3Aware(peer_link);
      if (serv_mb_legacy && !is_v3) {
        send_buffer(member->user, serv_mb_legacy, 0);
      } else if (peer_link == primary_dir) {
        if (is_v3 && serv_mb_alias_v3)
          send_buffer(member->user, serv_mb_alias_v3, 0);
        else if (serv_mb_alias)
          send_buffer(member->user, serv_mb_alias, 0);
        else if (is_v3 && serv_mb_v3)
          send_buffer(member->user, serv_mb_v3, 0);
        else
          send_buffer(member->user, serv_mb, 0);
      } else {
        if (is_v3 && serv_mb_v3)
          send_buffer(member->user, serv_mb_v3, 0);
        else
          send_buffer(member->user, serv_mb, 0);
      }
    }
  }
  /* Consult service forwarding table. */
  if(GlobalForwards[prefix]
      && (service = FindServer(GlobalForwards[prefix]))
      && cli_sentalong(service) != sentalong_marker) {
      cli_sentalong(service) = sentalong_marker;
      /* Rule by the service's next hop (cli_from), not the service
       * entity itself -- IsIRCv3Aware(service) tested X3 itself, which
       * is never the thing parsing this buffer off the wire. */
      if (serv_mb_legacy && !IsIRCv3Aware(cli_from(service)))
        send_buffer(service, serv_mb_legacy, 0);
      else if (IsIRCv3Aware(cli_from(service)) && serv_mb_v3)
        send_buffer(service, serv_mb_v3, 0);
      else
        send_buffer(service, serv_mb, 0);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
  if (serv_mb_v3)
    msgq_clean(serv_mb_v3);
  if (serv_mb_alias)
    msgq_clean(serv_mb_alias);
  if (serv_mb_alias_v3)
    msgq_clean(serv_mb_alias_v3);
  if (serv_mb_legacy)
    msgq_clean(serv_mb_legacy);
}

/** Send a (prefixed) WALL of type \a type to all users except \a one.
 * @warning \a pattern must not contain %v.
 * @param[in] from Source of the command.
 * @param[in] type One of WALL_DESYNCH, WALL_WALLOPS or WALL_WALLUSERS.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] pattern Format string for command arguments.
 */
void sendwallto_group_butone(struct Client *from, int type, struct Client *one,
			     const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  struct MsgBuf *mb;
  struct DLink *lp;
  char *prefix=NULL;
  char *tok=NULL;
  int his_wallops;
  int i;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  switch (type) {
    	case WALL_DESYNCH:
	  	prefix="";
		tok=TOK_DESYNCH;
		break;
    	case WALL_WALLOPS:
	  	prefix="* ";
		tok=TOK_WALLOPS;
		break;
    	case WALL_WALLUSERS:
	  	prefix="$ ";
		tok=TOK_WALLUSERS;
		break;
	default:
		assert(0);
  }
  mb = msgq_make(0, "%:#C " MSG_WALLOPS " :%s%v", from, prefix,&vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  his_wallops = feature_bool(FEAT_HIS_WALLOPS);
  for (i = 0; i <= HighestFd; i++)
  {
    if (!(cptr = LocalClientArray[i]) ||
	(cli_fd(cli_from(cptr)) < 0) ||
	(type == WALL_DESYNCH && !SendDebug(cptr)) ||
	(type == WALL_WALLOPS &&
         (!SendWallops(cptr) || (his_wallops && !IsAnOper(cptr)))) ||
        (type == WALL_WALLUSERS && !SendWallops(cptr)))
      continue; /* skip it */
    send_buffer(cptr, mb, 1);
  }

  msgq_clean(mb);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  mb = msgq_make(&me, "%C %s :%v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along! */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    send_buffer(lp->value.cptr, mb, 1);
  }

  msgq_clean(mb);
}

/** Send a (prefixed) command to all users matching \a to as \a who.
 * @warning \a pattern must not contain %v.
 * @param[in] from Source of the command.
 * @param[in] cmd Long name of command.
 * @param[in] tok Short name of command.
 * @param[in] to Destination host/server mask.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] who Type of match for \a to (either MATCH_HOST or MATCH_SERVER).
 * @param[in] pattern Format string for command arguments.
 */
void sendcmdto_match_butone(struct Client *from, const char *cmd,
			    const char *tok, const char *to,
			    struct Client *one, unsigned int who,
			    const char *pattern, ...)
{
  struct VarData vd;
  struct Client *cptr;
  struct MsgBuf *user_mb;
  struct MsgBuf *serv_mb;

  vd.vd_format = pattern;

  /* Build buffer to send to users */
  va_start(vd.vd_args, pattern);
  user_mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* Build buffer to send to servers */
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send buffer along */
  bump_sentalong(one);
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!IsRegistered(cptr) || IsServer(cptr) || cli_fd(cli_from(cptr)) < 0 ||
        cli_sentalong(cptr) == sentalong_marker ||
        !match_it(from, cptr, to, who))
      continue; /* skip it */
    cli_sentalong(cptr) = sentalong_marker;

    if (MyConnect(cptr)) /* send right buffer */
      send_buffer(cptr, user_mb, 0);
    else
      send_buffer(cptr, serv_mb, 0);
  }

  msgq_clean(user_mb);
  msgq_clean(serv_mb);
}

/** Send a server notice out across the network before sending to all
 * users subscribing to the indicated \a mask except for \a one.
 * @param[in] from Client TOK_SNO is sent from.
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone_global(struct Client *one, unsigned int mask,
				 const char *pattern, ...)
{
  va_list vl;
  struct VarData vd;
  struct MsgBuf *mb;
  struct DLink *lp;

  va_start(vl, pattern);

  if (cli_serv(&me) && (lp = cli_serv(&me)->down)) {
    vd.vd_format = pattern;
    va_copy(vd.vd_args, vl);
    mb = msgq_make(&me, "%C " TOK_SNO " %d :%v", &me, mask, &vd);

    for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
      if (one && lp->value.cptr == cli_from(one))
        continue;
      send_buffer(lp->value.cptr, mb, 0);
    }

    msgq_clean(mb);
  }

  vsendto_opmask_butone(&me, one, mask, pattern, vl);
  va_end(vl);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone(struct Client *one, unsigned int mask,
			  const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_opmask_butone(&me, one, mask, pattern, vl);
  va_end(vl);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one from \a from.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone_from(struct Client *from, struct Client *one,
                          unsigned int mask, const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_opmask_butone(from, one, mask, pattern, vl);
  va_end(vl);
}

/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one, rate-limited to once per 30 seconds.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in,out] rate Pointer to the last time the message was sent.
 * @param[in] pattern Format string for server notice.
 */
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
				      time_t *rate, const char *pattern, ...)
{
  va_list vl;

  if ((CurrentTime - *rate) < 30)
    return;
  else
    *rate = CurrentTime;

  va_start(vl, pattern);
  vsendto_opmask_butone(&me, one, mask, pattern, vl);
  va_end(vl);
}


/** Send a server notice to all users subscribing to the indicated \a
 * mask except for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mask One of the SNO_* constants.
 * @param[in] pattern Format string for server notice.
 * @param[in] vl Argument list for format string.
 */
void vsendto_opmask_butone(struct Client *from, struct Client *one,
                           unsigned int mask, const char *pattern, va_list vl)
{
  struct VarData vd;
  struct MsgBuf *mb;
  int i = 0; /* so that 1 points to opsarray[0] */
  struct SLink *opslist;

  while ((mask >>= 1))
    i++;

  if (!(opslist = opsarray[i]))
    return;

  /*
   * build string; I don't want to bother with client nicknames, so I hope
   * this is ok...
   */
  vd.vd_format = pattern;
  va_copy(vd.vd_args, vl);
  mb = msgq_make(0, ":%s " MSG_NOTICE " * :*** Notice -- %v", cli_name(from),
		 &vd);

  for (; opslist; opslist = opslist->next)
    if (opslist->value.cptr != one)
      send_buffer(opslist->value.cptr, mb, 0);

  msgq_clean(mb);
}

/** Send a server notice to all users with the indicated \a mode except
 * for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mode One mode character.
 * @param[in] pattern Format string for server notice.
 */
void sendto_mode_butone(struct Client *one, struct Client *from, const char *mode,
                          const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsendto_mode_butone(one, from, mode, pattern, vl);
  va_end(vl);
}

/** Send a server notice to all users with the indicated \a mode except
 * for \a one.
 * @param[in] one Client direction to skip (or NULL).
 * @param[in] mode One mode character.
 * @param[in] pattern Format string for server notice.
 * @param[in] vl Argument list for format string.
 */
void vsendto_mode_butone(struct Client *one, struct Client *from, const char *mode,
                           const char *pattern, va_list vl)
{
  struct VarData vd;
  struct MsgBuf *mb;
  struct Client* acptr = 0;

  vd.vd_format = pattern;
  va_copy(vd.vd_args, vl);

  /* send to local users */
   mb = msgq_make(0, ":%s " MSG_NOTICE " * :*** Notice -- %v", cli_name(from),
              &vd);
  for (acptr = &me; acptr; acptr = cli_prev(acptr)) {
    if (IsUser(acptr))  {
      switch (*mode) {
        case 'O':
          if (IsLocOp(acptr))
            send_buffer(acptr, mb, 0);
          break;
        case 'o':
          if (IsOper(acptr))
            send_buffer(acptr, mb, 0);
          break;
        default:
          break; /* ignore, should only happen if incorrectly injected via raw */
      }
    }
  }
  msgq_clean(mb);
}

/** A batch reference for a client: "<numeric>-<seq>", both in lowercase
 * hex.  The batch spec: "Reference tag MUST contain only ASCII letters,
 * numbers, and/or hyphen" -- a P10 numeric's alphabet has '[' and ']'
 * (numnicks.c), so the numeric goes as its value (base64toint() of the
 * server part and the client part, the server's above the client's),
 * never as its characters.  @a seq is the receiving connection's
 * con_batch_seq, drawn by every reference made for that connection (its
 * own batches, generate_batch_id(), and the multiline batches it is sent),
 * so the references a connection gets are unique whatever numeric they
 * name.  At most 8 + 1 + 8 characters with a server part (BATCH_REF_SIZE
 * with the NUL), 5 + 1 + 8 without one (a BatchFrame's 16 bytes).
 * @param[out] buf Buffer for the reference.
 * @param[in] buflen Size of @a buf (BATCH_REF_SIZE is enough).
 * @param[in] server_yxx Server part of the numeric ("" or NULL for none).
 * @param[in] client_yxx Client part of the numeric ("" for none).
 * @param[in] seq The receiving connection's sequence number.
 * @return @a buf. */
char *batch_ref_make(char *buf, size_t buflen, const char *server_yxx,
                     const char *client_yxx, unsigned int seq)
{
  unsigned int value = 0;
  size_t clen = client_yxx ? strlen(client_yxx) : 0;

  /* 6 bits a character: a 2-character server and a 3-character client
   * numeric are 30 bits together. */
  if (server_yxx && server_yxx[0] && clen <= 3)
    value = base64toint(server_yxx) << (6 * clen);
  if (clen)
    value |= base64toint(client_yxx);
  ircd_snprintf(NULL, buf, buflen, "%x-%x", value, seq);
  return buf;
}

/**
 * Generate a unique batch reference ID for a batch on @a cptr's own
 * connection (batch_ref_make(): letters, digits and hyphen only; the
 * client's own numeric, "" before registration, and its sequence -- at
 * most 14 characters, a BatchFrame's id).
 * @param[in] cptr Local client to generate batch ID for.
 * @param[out] buf Buffer to store the generated ID.
 * @param[in] buflen Size of the buffer.
 * @return Pointer to the buffer.
 */
static char *generate_batch_id(struct Client *cptr, char *buf, size_t buflen)
{
  unsigned int seq = con_batch_seq(cli_connect(cptr))++;
  return batch_ref_make(buf, buflen, NULL, cli_yxx(cptr), seq);
}

/* ------------------------------------------------------------------ */
/* Batches on a client connection: the nesting model                    */
/* ------------------------------------------------------------------ */
/*
 * A connection keeps a small stack of the batches open on the answer it is
 * being sent (con_batch[], at most BATCH_NEST_MAX deep).  The batch spec
 * lets one batch nest in another: "Start and end messages of one batch MAY
 * refer to another batch.  If they do, they both MUST have batch tag, and
 * they MUST refer to the same batch."  So:
 *  - send_batch_start() opens a batch INSIDE the innermost one open: its
 *    "BATCH +<id>" line is tagged @batch=<parent> when there is one, the
 *    parent is recorded with it, and it becomes the innermost;
 *  - every line sent to the client meanwhile is tagged with the INNERMOST
 *    open batch (cli_batch_id(): reply_tags, the tag formatters, ...);
 *  - send_batch_end() ends the innermost: "BATCH -<id>" tagged with the
 *    SAME parent its start was, and the parent is innermost again.
 * The stack belongs to the line being answered: parse_client() ends
 * whatever that line left open, innermost first (batch_end_line()), so it
 * is empty between lines.  A batch that outlives its line -- an
 * asynchronous LIST's labeled batch -- is not on the stack then: its owner
 * takes it off when its line is done (batch_detach()) and puts it back only
 * while it sends into it (batch_resume() .. batch_suspend(), or
 * send_batch_end() for the last time).  So a later, unrelated line never
 * nests in it, and never disturbs it.  (Chathistory and replay pages, the
 * SEARCH batch and forwarded-label batches carry ids of their own, kept by
 * their owners; netjoin/netsplit use the server batch, send_s2s_batch_*.)
 * A client that does not hold batch gets frames with no id: nothing on the
 * wire, the pairing kept.  A start past BATCH_NEST_MAX opens nothing (its
 * lines stay in the innermost batch) and its end ends nothing
 * (con_batch_over).
 */

const char *batch_current_id(struct Client *cli)
{
  struct Connection *con;

  if (!cli || !MyConnect(cli))
    return "";
  con = cli_connect(cli);
  return con->con_batch_depth ? con->con_batch[con->con_batch_depth - 1].id : "";
}

/** Whether @a to can be sent batch lines now. */
static int batch_wire(struct Client *to)
{
  return feature_bool(FEAT_CAP_batch) && CapRecipientHas(to, CAP_BATCH);
}

/** Send one BATCH +/- line: @a sign '+' or '-', the batch @a id, tagged
 * @batch=<parent> when @a parent names one, plus @a label on a start and
 * any @a extra tags ("time=..." etc).  The one place a BATCH line of a
 * client's batches opened through this file is written (the connection's
 * stack, and a forwarded-label batch: forwarded_label.c). */
void send_batch_marker(struct Client *to, char sign, const char *id,
                       const char *parent, const char *type, const char *label,
                       const char *extra)
{
  struct MsgBuf *mb;
  char tagbuf[256];
  int pos = 0;

  tagbuf[0] = '\0';
  if (parent && parent[0])
    pos += ircd_snprintf(NULL, tagbuf + pos, sizeof(tagbuf) - pos, "@batch=%s", parent);
  if (label && label[0])
    pos += ircd_snprintf(NULL, tagbuf + pos, sizeof(tagbuf) - pos, "%slabel=%s",
                         pos ? ";" : "@", label);
  if (extra && extra[0])
    pos += ircd_snprintf(NULL, tagbuf + pos, sizeof(tagbuf) - pos, "%s%s",
                         pos ? ";" : "@", extra);
  if (pos && pos < (int)sizeof(tagbuf) - 1) {
    tagbuf[pos++] = ' ';
    tagbuf[pos] = '\0';
  }
  if (sign == '+')
    mb = msgq_make(cli_from(to), "%s:%s " MSG_BATCH_CMD " +%s %s",
                   tagbuf, cli_name(&me), id, type);
  else
    mb = msgq_make(cli_from(to), "%s:%s " MSG_BATCH_CMD " -%s",
                   tagbuf, cli_name(&me), id);
  send_buffer(to, mb, 0);
  msgq_clean(mb);
}

/* ------------------------------------------------------------------ */
/* A deferred labeled-response batch                                    */
/* ------------------------------------------------------------------ */
/*
 * "If a response consists of more than one message, a batch MUST be used
 * to group them into a single logical response" -- and a single message
 * carries the label itself, none is an ACK.  Some commands cannot count
 * their answer before sending it (PRIVMSG to several targets: an away
 * reply, an echo, a refusal per target, each decided as its target is
 * relayed).  For them labeled_batch_defer() opens the labeled batch's
 * frame WITHOUT its BATCH + line: every line of the answer is formatted
 * as inside it (tagged @batch=<id>, as any labeled batch's), and every
 * line sent to the connection meanwhile is held, in order
 * (batch_hold_take(), from send_buffer()).  The answer's logical messages
 * are counted as they come: a line tagged with the frame is one, a batch
 * nested in it is one (its BATCH + line; its BATCH - is not counted).
 *  - a second one: the batch is needed -- its BATCH + line (with the
 *    label) goes out, then the held lines, and the frame is an ordinary
 *    one from there on (batch_hold_materialize());
 *  - the frame ends with one: the held lines go out with the frame's tag
 *    taken off, the first line of that message carrying the label in its
 *    place -- a bare labeled line, or a nested batch whose BATCH + line
 *    carries the label, as if no batch had been asked for;
 *  - the frame ends with none: the held lines go out unchanged (lines that
 *    are not the answer: a message delivered to oneself) and the label is
 *    answered by ACK.
 * The hold is bounded (BATCH_HOLD_MAX lines; past it the batch is opened
 * -- a labeled batch around one message is legal).
 */
#define BATCH_HOLD_MAX 256

struct BatchHold {
  unsigned char depth;        /**< The deferred frame's depth (1-based) */
  int logical;                /**< The answer's logical messages held so far */
  int n;                      /**< Lines held */
  char label[64];             /**< The label the answer is for */
  char *lines[BATCH_HOLD_MAX];/**< The held lines, without their CR LF */
};

/** Where the tag region of @a line ends (its space), or NULL: no tags. */
static const char *hold_tags_end(const char *line)
{
  return line[0] == '@' ? strchr(line, ' ') : NULL;
}

/** Whether @a line's tags hold "batch=<id>". */
static int hold_tagged(const char *line, const char *id)
{
  const char *end = hold_tags_end(line), *p = line + 1;
  size_t n = strlen(id);

  if (!end)
    return 0;
  while (p < end) {
    const char *semi = memchr(p, ';', end - p);
    const char *tok_end = semi ? semi : end;

    if ((size_t)(tok_end - p) == 6 + n && !strncmp(p, "batch=", 6)
        && !strncmp(p + 6, id, n))
      return 1;
    p = tok_end + 1;
  }
  return 0;
}

/** Whether @a line is a BATCH - line. */
static int hold_is_batch_end(const char *line)
{
  const char *p = hold_tags_end(line);

  p = p ? p + 1 : line;
  if (*p == ':' && !(p = strchr(p, ' ')))
    return 0;
  if (*p == ' ')
    p++;
  return !strncmp(p, MSG_BATCH_CMD " -", sizeof(MSG_BATCH_CMD " -") - 1);
}

/** Send @a line (no CR LF) to @a to as it is. */
static void hold_send_line(struct Client *to, const char *line)
{
  struct MsgBuf *mb = msgq_make(cli_from(to), "%s", line);

  send_buffer(to, mb, 0);
  msgq_clean(mb);
}

/** Send @a line with its "batch=<id>" tag replaced by @a repl ("" or NULL:
 * dropped; a tag region left empty goes with it). */
static void hold_send_retagged(struct Client *to, const char *line,
                               const char *id, const char *repl)
{
  const char *end = hold_tags_end(line), *p = line + 1;
  size_t n = strlen(id);
  char tags[IRCV3_TAG_MAX + 1];
  int pos = 0;

  if (!end) {
    hold_send_line(to, line);
    return;
  }
  tags[0] = '\0';
  while (p < end) {
    const char *semi = memchr(p, ';', end - p);
    const char *tok_end = semi ? semi : end;
    int len = (int)(tok_end - p);

    if ((size_t)len == 6 + n && !strncmp(p, "batch=", 6) && !strncmp(p + 6, id, n)) {
      if (repl && repl[0])
        pos += ircd_snprintf(NULL, tags + pos, sizeof(tags) - pos, "%s%s",
                             pos ? ";" : "", repl);
    } else
      pos += ircd_snprintf(NULL, tags + pos, sizeof(tags) - pos, "%s%.*s",
                           pos ? ";" : "", len, p);
    if (pos >= (int)sizeof(tags) - 1)
      pos = (int)sizeof(tags) - 1;
    p = tok_end + 1;
  }
  {
    struct MsgBuf *mb = pos
        ? msgq_make(cli_from(to), "@%s %s", tags, end + 1)
        : msgq_make(cli_from(to), "%s", end + 1);
    send_buffer(to, mb, 0);
    msgq_clean(mb);
  }
}

/** Free what a deferred labeled batch holds (a connection freed with one,
 * list.c). */
void batch_hold_free(struct Connection *con)
{
  struct BatchHold *h;
  int i;

  if (!con || !(h = con_batch_hold(con)))
    return;
  con_batch_hold(con) = NULL;
  for (i = 0; i < h->n; i++)
    MyFree(h->lines[i]);
  MyFree(h);
}

/** The deferred labeled batch of @a to is needed: its BATCH + line (the
 * label on it), then every held line, and the frame is an ordinary one. */
static void batch_hold_materialize(struct Client *to)
{
  struct Connection *con = cli_connect(to);
  struct BatchHold *h = con_batch_hold(con);
  struct BatchFrame *f;
  int i;

  if (!h)
    return;
  con_batch_hold(con) = NULL;   /* the lines below go to the queue */
  f = &con->con_batch[h->depth - 1];
  send_batch_marker(to, '+', f->id, f->parent, "labeled-response", h->label,
                    NULL);
  for (i = 0; i < h->n; i++) {
    hold_send_line(to, h->lines[i]);
    MyFree(h->lines[i]);
  }
  MyFree(h);
}

/** send_buffer(): a line for @a to while its labeled batch is deferred --
 * held, in order, and the answer's messages counted.
 * @return 1 when the line was taken (held, or sent by the batch opening). */
static int batch_hold_take(struct Client *to, struct MsgBuf *mb)
{
  struct Connection *con = cli_connect(to);
  struct BatchHold *h = con_batch_hold(con);
  const char *data;
  unsigned int len;
  char *line;

  if (!h || h->depth > con->con_batch_depth)
    return 0;
  msgq_buf_data(mb, &data, &len);
  if (len >= 2 && data[len - 2] == '\r' && data[len - 1] == '\n')
    len -= 2;
  line = (char *)MyMalloc(len + 1);
  memcpy(line, data, len);
  line[len] = '\0';
  if (hold_tagged(line, con->con_batch[h->depth - 1].id) && !hold_is_batch_end(line))
    h->logical++;
  h->lines[h->n++] = line;
  if (h->logical >= 2 || h->n >= BATCH_HOLD_MAX)
    batch_hold_materialize(to);
  return 1;
}

/** The deferred frame of @a to ends with its batch never needed (one
 * logical message, or none): the held lines go out without the frame's
 * tag -- the first line of the one message carrying the label instead --
 * and an answer of none is ACKed.  Then the frame itself is popped with
 * nothing on the wire (batch_pop()). */
static void batch_hold_resolve(struct Client *to)
{
  struct Connection *con = cli_connect(to);
  struct BatchHold *h = con_batch_hold(con);
  struct BatchFrame *f;
  char labeled[IRCV3_TAG_MAX];
  int i, first = 1;

  if (!h)
    return;
  con_batch_hold(con) = NULL;
  f = &con->con_batch[h->depth - 1];
  /* The one message's first line: tagged as the frame's own start would
   * have been -- its parent, and the label. */
  if (f->parent[0])
    ircd_snprintf(NULL, labeled, sizeof(labeled), "batch=%s;label=%s",
                  f->parent, h->label);
  else
    ircd_snprintf(NULL, labeled, sizeof(labeled), "label=%s", h->label);
  for (i = 0; i < h->n; i++) {
    if (hold_tagged(h->lines[i], f->id)) {
      char parent[sizeof(f->parent) + 6];
      int opens = first && h->logical == 1 && !hold_is_batch_end(h->lines[i]);

      ircd_snprintf(NULL, parent, sizeof(parent), "batch=%s", f->parent);
      hold_send_retagged(to, h->lines[i], f->id,
                         opens ? labeled : (f->parent[0] ? parent : NULL));
      if (opens)
        first = 0;
    } else
      hold_send_line(to, h->lines[i]);
    MyFree(h->lines[i]);
  }
  if (!h->logical && LabeledResponseInUse(to)) {
    char saved[sizeof(con->con_label)];
    unsigned char responded = cli_label_responded(to);

    memcpy(saved, cli_label(to), sizeof(saved));
    ircd_strncpy(cli_label(to), h->label, sizeof(saved));
    cli_label_responded(to) = 0;
    send_labeled_ack(to);
    memcpy(cli_label(to), saved, sizeof(saved));
    cli_label_responded(to) = responded;
  }
  MyFree(h);
}

/**
 * Open a batch on @a to's current answer, nested in the innermost one open
 * (see the model above).  A pending, unanswered label of the line goes on
 * its BATCH + line and the label is answered.
 * @param[in] to Client to start batch for.
 * @param[in] type Batch type (e.g., "labeled-response", "metadata").
 * @return 1 if a BATCH + line was sent, else 0 (the client does not hold
 *   batch, or BATCH_NEST_MAX is reached); send_batch_end() is paired with
 *   every call either way.
 */
int send_batch_start(struct Client *to, const char *type)
{
  struct Connection *con;
  struct BatchFrame *f;
  const char *label = NULL;

  if (!to || !MyConnect(to))
    return 0;
  con = cli_connect(to);
  if (con->con_batch_depth >= BATCH_NEST_MAX) {
    con->con_batch_over++;
    return 0;
  }
  f = &con->con_batch[con->con_batch_depth];
  ircd_strncpy(f->parent, batch_current_id(to), sizeof(f->parent));
  f->id[0] = '\0';
  con->con_batch_depth++;
  if (!batch_wire(to))
    return 0;

  generate_batch_id(to, f->id, sizeof(f->id));
  if (feature_bool(FEAT_CAP_labeled_response) &&
      LabeledResponseInUse(to) && cli_label(to)[0] &&
      !cli_label_responded(to)) {   /* an answered label goes on no batch */
    label = cli_label(to);
    cli_label_responded(to) = 1;   /* the BATCH + line answers it: no ACK */
  }
  send_batch_marker(to, '+', f->id, f->parent, type, label, NULL);
  return 1;
}

/** End the innermost frame; with @a wire, send its BATCH - line (whatever
 * the client's capabilities are now: the caller decides). */
static void batch_pop(struct Client *to, int wire)
{
  struct Connection *con = cli_connect(to);
  struct BatchFrame *f;

  if (con->con_batch_over) {
    con->con_batch_over--;
    return;
  }
  if (!con->con_batch_depth)
    return;
  f = &con->con_batch[con->con_batch_depth - 1];
  if (con_batch_hold(con) && con_batch_hold(con)->depth == con->con_batch_depth)
    batch_hold_resolve(to);   /* a deferred labeled batch never opened */
  else if (wire && f->id[0])
    send_batch_marker(to, '-', f->id, f->parent, NULL, NULL, NULL);
  con->con_batch_depth--;
  if (con->con_labeled_batch > con->con_batch_depth)
    con->con_labeled_batch = 0;
}

/**
 * End the innermost batch open on @a to's answer: "BATCH -<id>", tagged
 * with the parent its start was, and the parent is the innermost again.
 * @param[in] to Client to end batch for.
 */
void send_batch_end(struct Client *to)
{
  if (!to || !MyConnect(to))
    return;
  batch_pop(to, batch_wire(to));
}

/** End every batch the line being answered left open, innermost first
 * (parse_client(), after each line). */
void batch_end_line(struct Client *to)
{
  if (!to || !MyConnect(to))
    return;
  while (cli_connect(to)->con_batch_over || cli_connect(to)->con_batch_depth)
    send_batch_end(to);
}

/** End every open batch innermost first, sending each BATCH - line while
 * @a wire (the client held batch until now: cap_dependents_drop(), before
 * the CAP ACK). */
void batch_end_all(struct Client *to, int wire)
{
  if (!to || !MyConnect(to))
    return;
  while (cli_connect(to)->con_batch_over || cli_connect(to)->con_batch_depth)
    batch_pop(to, wire);
}

/** The innermost batch outlives the line that opened it (an asynchronous
 * LIST): take it off the stack, nothing on the wire, and hand its id to
 * its owner (@a id, "" when nothing was opened).  Only a batch opened at
 * the top level is detached (its BATCH - will carry no parent). */
void batch_detach(struct Client *to, char *id, size_t idlen)
{
  struct Connection *con;

  id[0] = '\0';
  if (!to || !MyConnect(to))
    return;
  con = cli_connect(to);
  if (con->con_batch_over) {
    con->con_batch_over--;
    return;
  }
  if (!con->con_batch_depth)
    return;
  if (con_batch_hold(con))
    batch_hold_materialize(to);   /* it outlives the line: it must exist */
  if (!con->con_batch[con->con_batch_depth - 1].parent[0])
    ircd_strncpy(id, con->con_batch[con->con_batch_depth - 1].id, idlen);
  con->con_batch_depth--;
  if (con->con_labeled_batch > con->con_batch_depth)
    con->con_labeled_batch = 0;
}

/** The owner of a detached batch sends into it: put it back as the
 * innermost (nothing on the wire) until batch_suspend() -- or
 * send_batch_end(), which ends it.  An id of "" resumes a frame with
 * nothing on the wire, so the pairing holds either way. */
void batch_resume(struct Client *to, const char *id)
{
  struct Connection *con;
  struct BatchFrame *f;

  if (!to || !MyConnect(to))
    return;
  con = cli_connect(to);
  if (con->con_batch_depth >= BATCH_NEST_MAX) {
    con->con_batch_over++;
    return;
  }
  f = &con->con_batch[con->con_batch_depth++];
  ircd_strncpy(f->id, (id && batch_wire(to)) ? id : "", sizeof(f->id));
  f->parent[0] = '\0';
}

/** Take a resumed batch off again, nothing on the wire. */
void batch_suspend(struct Client *to)
{
  char dummy[16];

  batch_detach(to, dummy, sizeof(dummy));
}

/** Set aside every frame open on @a to (nothing on the wire) for an
 * answer that is not the current line's -- an asynchronous REGISTER or
 * OPER answer -- and put them back after with batch_restore(). */
void batch_save(struct Client *to, struct BatchSave *save)
{
  struct Connection *con = cli_connect(to);


  memcpy(save->frames, con->con_batch, sizeof(save->frames));
  save->depth = con->con_batch_depth;
  save->over = con->con_batch_over;
  save->labeled = con->con_labeled_batch;
  /* A deferred labeled batch (the line's, labeled_batch_defer()) is set
   * aside with its held lines, still undecided: the answer sent meanwhile
   * goes straight out, and the line's answer is resolved when its frame
   * ends, after batch_restore(). */
  save->hold = con_batch_hold(con);
  con_batch_hold(con) = NULL;
  con->con_batch_depth = 0;
  con->con_batch_over = 0;
  con->con_labeled_batch = 0;
}

void batch_restore(struct Client *to, const struct BatchSave *save)
{
  struct Connection *con = cli_connect(to);

  batch_end_line(to);   /* the answer's own batches end with it */
  memcpy(con->con_batch, save->frames, sizeof(con->con_batch));
  con->con_batch_depth = save->depth;
  con->con_batch_over = save->over;
  con->con_labeled_batch = save->labeled;
  if (save->hold) {
    batch_hold_free(con);   /* none: an answer opens no deferred batch */
    con_batch_hold(con) = save->hold;
  }
}

/** A connection's capabilities go from @a before to @a after (CAP REQ,
 * CAP ACK, CAP CLEAR).  labeled-response and draft/multiline are a no-op
 * without batch, and so is an open batch without batch: whatever they
 * left on the connection is undone here, AT the change -- not at the next
 * use.  The caller runs this before its CAP ACK (CAP ACK from the client
 * has none), so every batch the client was sent the start of is ended
 * while it still reads batches -- the BATCH - lines are sent whatever the
 * connection's set already is -- innermost first, each tagged with its
 * parent; nothing after the ACK carries a batch the client no longer has.
 *  - labeled-response going inert (it or batch dropped): the
 *    forwarded-label batches are ended and the pending forwarded labels
 *    forgotten (fwd_label_drop_all()); an asynchronous LIST's labeled
 *    batch is ended and the LIST goes on plain;
 *  - batch going away: every batch open on the answer being sent (the
 *    connection's stack) is ended, innermost first; every history batch
 *    a replay has open is ended (the page's, then the outer, then a
 *    suspended catch-up's) and the replay goes on unframed, its row types
 *    as decided (replay_batch_drop());
 *  - draft/multiline going inert: the open client batch is discarded
 *    (multiline_discard_batch()), nothing delivered; a labeled one is
 *    answered by a labeled ACK first when labeled-response stays in use
 *    (multiline_discard_answer()) -- else its label is inert with it.
 * Labels saved by requests still in flight are not cleared here: each is
 * used only under LabeledResponseInUse() when its answer is sent. */
void cap_dependents_drop(struct Client *cptr, const struct CapSet *before,
                         const struct CapSet *after)
{
  if (!cptr || !MyConnect(cptr))
    return;

  if (CapHas(before, CAP_BATCH) && !CapHas(after, CAP_BATCH))
    batch_end_all(cptr, 1);   /* the current line's batches, innermost first */

  if (CapSetLabeledResponseInUse(before) && !CapSetLabeledResponseInUse(after)) {
    fwd_label_drop_all(cptr, 1);   /* before: labels in use, so batch held */
    if (cli_listing(cptr) && cli_listing(cptr)->batch_id[0]) {
      send_batch_marker(cptr, '-', cli_listing(cptr)->batch_id, NULL, NULL,
                        NULL, NULL);
      cli_listing(cptr)->batch_id[0] = '\0';   /* LIST goes on plain */
    }
  }

  if (CapHas(before, CAP_BATCH) && !CapHas(after, CAP_BATCH))
    replay_batch_drop(cptr);

  if (CapHas(before, CAP_DRAFT_MULTILINE) && CapHas(before, CAP_BATCH)
      && !(CapHas(after, CAP_DRAFT_MULTILINE) && CapHas(after, CAP_BATCH))) {
    /* A labeled batch still answered while labels stay in use (only
     * draft/multiline dropped): its labeled ACK, before the CAP ACK. */
    if (CapSetLabeledResponseInUse(after))
      multiline_discard_answer(cptr);
    multiline_discard_batch(cptr);
  }
}

/**
 * Check if a client has a batch open on its current answer.
 * @param[in] cptr Client to check.
 * @return Non-zero if a batch is open (one with a reference), zero otherwise.
 */
int has_active_batch(struct Client *cptr)
{
  return batch_current_id(cptr)[0] != '\0';
}

/**
 * Start an S2S batch and send to all servers.
 * Used for netjoin/netsplit coordination across the network.
 * @param[in] sptr Server starting the batch.
 * @param[in] type Batch type (netjoin, netsplit).
 * @param[in] server1 First server in the split/join (optional).
 * @param[in] server2 Second server in the split/join (optional).
 */
void send_s2s_batch_start(struct Client *sptr, const char *type,
                          const char *server1, const char *server2)
{
  char batch_id[32];
  struct Client *acptr;

  if (!feature_bool(FEAT_P10_MESSAGE_TAGS))
    return;

  /* Generate unique batch ID: server numeric + counter.  An S2S id, kept
   * as it was (generate_batch_id() is for a client's own batches); no
   * caller sends one today. */
  ircd_snprintf(NULL, batch_id, sizeof(batch_id), "%s%u", cli_yxx(sptr),
                con_batch_seq(cli_connect(sptr))++);

  /* Send to all servers */
  if (server1 && server2) {
    sendcmdto_serv_butone_v3(sptr, CMD_BATCH_CMD, NULL, "+%s %s %s %s",
                          batch_id, type, server1, server2);
  }
  else if (server1) {
    sendcmdto_serv_butone_v3(sptr, CMD_BATCH_CMD, NULL, "+%s %s %s",
                          batch_id, type, server1);
  }
  else {
    sendcmdto_serv_butone_v3(sptr, CMD_BATCH_CMD, NULL, "+%s %s",
                          batch_id, type);
  }

  /* Store batch ID for later reference */
  ircd_strncpy(cli_s2s_batch_id(sptr), batch_id, sizeof(con_s2s_batch_id(cli_connect(sptr))) - 1);
  cli_s2s_batch_id(sptr)[sizeof(con_s2s_batch_id(cli_connect(sptr))) - 1] = '\0';
  ircd_strncpy(cli_s2s_batch_type(sptr), type, sizeof(con_s2s_batch_type(cli_connect(sptr))) - 1);
  cli_s2s_batch_type(sptr)[sizeof(con_s2s_batch_type(cli_connect(sptr))) - 1] = '\0';

  /* Send batch start to each connection that has batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    if (server1 && server2) {
      send_batch_perconn(acptr, "+%s %s %s %s",
                         batch_id, type, server1, server2);
    }
    else if (server1) {
      send_batch_perconn(acptr, "+%s %s %s",
                         batch_id, type, server1);
    }
    else {
      send_batch_perconn(acptr, "+%s %s",
                         batch_id, type);
    }
  }
}

/**
 * End an S2S batch and send to all servers.
 * @param[in] sptr Server ending the batch.
 * @param[in] batch_id Batch ID to end (or NULL to use stored ID).
 */
void send_s2s_batch_end(struct Client *sptr, const char *batch_id)
{
  struct Client *acptr;
  const char *id;

  if (!feature_bool(FEAT_P10_MESSAGE_TAGS))
    return;

  /* Use provided ID or the stored one */
  id = batch_id ? batch_id : cli_s2s_batch_id(sptr);
  if (!id || !*id)
    return;

  /* Send to all servers */
  sendcmdto_serv_butone_v3(sptr, CMD_BATCH_CMD, NULL, "-%s", id);

  /* Send batch end to each connection that has batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    send_batch_perconn(acptr, "-%s", id);
  }

  /* Clear stored batch ID */
  cli_s2s_batch_id(sptr)[0] = '\0';
  cli_s2s_batch_type(sptr)[0] = '\0';
}

/** Send a BATCH command to a client if it has CAP_BATCH.
 *
 * Checks per-connection caps (CapOwnHas) to decide delivery.
 *
 * @param[in] acptr  Local user client to consider.
 * @param[in] fmt    printf-style format string for the BATCH command body.
 */
void
send_batch_perconn(struct Client *acptr, const char *fmt, ...)
{
  struct MsgBuf *mb;
  struct VarData vd;
  va_list ap;

  va_start(ap, fmt);
  vd.vd_format = fmt;
  va_copy(vd.vd_args, ap);
  mb = msgq_make(acptr, "%:#C %s %v", &me, MSG_BATCH_CMD, &vd);
  va_end(vd.vd_args);
  va_end(ap);

  if (!mb)
    return;

  if (CapOwnHas(acptr, CAP_BATCH))
    send_buffer(acptr, mb, 0);

  msgq_clean(mb);
}

/**
 * Start a netjoin batch when a server reconnects.
 * Generates a batch ID and stores it on the server struct for later.
 * Sends BATCH +id netjoin server1 server2 to clients with batch cap.
 * @param[in] server Server that is reconnecting (junction server).
 * @param[in] uplink Server's uplink (server one hop closer to us).
 */
void send_netjoin_batch_start(struct Client *server, struct Client *uplink)
{
  struct Client *acptr;
  char batch_id[32];
  static unsigned long netjoin_seq = 0;

  if (!feature_bool(FEAT_CAP_batch))
    return;

  if (!server || !cli_serv(server))
    return;

  /* Generate unique batch ID: a reference for clients -- letters, digits
   * and hyphen only, so this server's numeric goes as its value in hex,
   * never as its characters ('[' and ']'); with it the reference is unique
   * on the network, not only here (a peer's relayed one cannot equal it). */
  ircd_snprintf(NULL, batch_id, sizeof(batch_id), "NJ%x-%lu",
                base64toint(cli_yxx(&me)), netjoin_seq++);

  /* Store on server struct */
  ircd_strncpy(cli_serv(server)->batch_id, batch_id,
               sizeof(cli_serv(server)->batch_id) - 1);
  cli_serv(server)->batch_id[sizeof(cli_serv(server)->batch_id) - 1] = '\0';

  /* Set active network batch so JOIN messages include @batch tag */
  set_active_network_batch(batch_id);

  /* Send batch start to each connection that has batch capability.
   * Uses send_batch_perconn to respect per-connection caps in bouncer
   * sessions — CapActive() would check the union, incorrectly sending
   * BATCH to connections that never negotiated it. */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    if (uplink) {
      send_batch_perconn(acptr, "+%s netjoin %s %s",
                         batch_id, cli_name(uplink), cli_name(server));
    } else {
      send_batch_perconn(acptr, "+%s netjoin %s",
                         batch_id, cli_name(server));
    }
  }
}

/**
 * End a netjoin batch when END_OF_BURST is received.
 * @param[in] server Server that finished bursting.
 */
void send_netjoin_batch_end(struct Client *server)
{
  struct Client *acptr;
  const char *batch_id;

  if (!feature_bool(FEAT_CAP_batch))
    return;

  if (!server || !cli_serv(server))
    return;

  batch_id = cli_serv(server)->batch_id;
  if (!batch_id || !*batch_id)
    return;

  /* Clear active network batch */
  set_active_network_batch(NULL);

  /* Send batch end to each connection that has batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    send_batch_perconn(acptr, "-%s", batch_id);
  }

  /* Clear stored batch ID */
  cli_serv(server)->batch_id[0] = '\0';
}

/**
 * Start a netsplit batch when a server disconnects.
 * @param[in] server Server that is disconnecting.
 * @param[in] uplink Server's uplink.
 * @param[out] batch_id_out Buffer to store generated batch ID (min 32 bytes).
 */
void send_netsplit_batch_start(struct Client *server, struct Client *uplink,
                                char *batch_id_out, size_t batch_id_len)
{
  struct Client *acptr;
  static unsigned long netsplit_seq = 0;

  if (!feature_bool(FEAT_CAP_batch))
    return;

  if (!batch_id_out || batch_id_len < 16)
    return;

  /* Generate unique batch ID: as the netjoin one (send_netjoin_batch_start()):
   * this server's numeric in hex, then the counter. */
  ircd_snprintf(NULL, batch_id_out, batch_id_len, "NS%x-%lu",
                base64toint(cli_yxx(&me)), netsplit_seq++);

  /* Send batch start to each connection that has batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    if (uplink && server) {
      send_batch_perconn(acptr, "+%s netsplit %s %s",
                         batch_id_out, cli_name(uplink), cli_name(server));
    } else if (server) {
      send_batch_perconn(acptr, "+%s netsplit %s",
                         batch_id_out, cli_name(server));
    }
  }
}

/**
 * End a netsplit batch.
 * @param[in] batch_id Batch ID from send_netsplit_batch_start.
 */
void send_netsplit_batch_end(const char *batch_id)
{
  struct Client *acptr;

  if (!feature_bool(FEAT_CAP_batch))
    return;

  if (!batch_id || !*batch_id)
    return;

  /* Send batch end to each connection that has batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    send_batch_perconn(acptr, "-%s", batch_id);
  }
}

/**
 * Send a standard reply (FAIL/WARN/NOTE) to a client with optional explicit label.
 * Internal helper function.
 * @param[in] to Client to send to.
 * @param[in] type Reply type (FAIL, WARN, or NOTE).
 * @param[in] command Command that generated this reply (or "*" for general).
 * @param[in] code Machine-readable code (e.g., "ACCOUNT_REQUIRED").
 * @param[in] context Optional context parameter (NULL if none).
 * @param[in] description Human-readable description.
 * @param[in] label Optional explicit label (NULL to use cli_label).
 */
static void send_standard_reply_ex(struct Client *to, const char *type,
                                    const char *command, const char *code,
                                    const char *context, const char *description,
                                    const char *label)
{
  struct MsgBuf *mb;
  char tagbuf[512];
  int pos = 0;
  int use_time, use_label, use_batch;

  if (!MyConnect(to))
    return;

  /* Always send FAIL/WARN/NOTE as actual IRC commands per IRCv3 standard-replies.
   * Draft extensions (metadata, redact, multiline, etc.) define FAIL as their
   * native error format — falling back to NOTICE breaks conformance tests.
   * Legacy clients will simply ignore unknown commands. */

  /* Format tags with explicit label override if provided.  Without one,
   * a standard reply answers the labeled command being handled: it goes in
   * that command's labeled-response batch when one is open
   * (labeled_batch_start(), the line's own -- never another batch open on
   * the connection: not a typed batch nested in the answer, like a
   * metadata batch, nor an asynchronous one), else it takes the label if
   * no line took it yet (a label answers one line or one batch).  A client
   * that sent no label gets its standard replies untagged, as before. */
  use_time = feature_bool(FEAT_CAP_server_time) && CapRecipientHas(to, CAP_SERVERTIME);
  use_batch = !(label && *label) && feature_bool(FEAT_CAP_batch) &&
              CapRecipientHas(to, CAP_BATCH) && cli_labeled_batch(to);
  use_label = !use_batch && feature_bool(FEAT_CAP_labeled_response) &&
              LabeledResponseInUse(to) &&
              ((label && *label) ||
               (cli_label(to)[0] && !cli_label_responded(to)));

  if (use_time || use_label || use_batch) {
    tagbuf[0] = '@';
    pos = 1;

    if (use_batch)
      pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "batch=%s",
                      cli_connect(to)->con_batch[cli_labeled_batch(to) - 1].id);
    else if (use_label) {
      /* Use explicit label if provided, otherwise use cli_label */
      const char *lbl = (label && *label) ? label : cli_label(to);
      pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "label=%s", lbl);
      /* Mark that we've sent a labeled response (for ACK mechanism) */
      cli_label_responded(to) = 1;
    }

    if (use_time) {
      if (pos > 1 && pos < (int)sizeof(tagbuf) - 1)
        tagbuf[pos++] = ';';
      if (client_time_override[0]) {
        pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "time=%s", client_time_override);
      } else {
        struct timeval tv;
        struct tm tm;
        client_tag_tv(&tv);
        gmtime_r(&tv.tv_sec, &tm);
        pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos,
                        "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                        tm.tm_hour, tm.tm_min, tm.tm_sec,
                        (long)(tv.tv_usec / 1000));
      }
    }

    tagbuf[pos++] = ' ';
    tagbuf[pos] = '\0';

    if (context && *context)
      mb = msgq_make(to, "%s%:#C %s %s %s %s :%s", tagbuf, &me, type, command, code, context, description);
    else
      mb = msgq_make(to, "%s%:#C %s %s %s :%s", tagbuf, &me, type, command, code, description);
  } else {
    if (context && *context)
      mb = msgq_make(to, "%:#C %s %s %s %s :%s", &me, type, command, code, context, description);
    else
      mb = msgq_make(to, "%:#C %s %s %s :%s", &me, type, command, code, description);
  }

  send_buffer(to, mb, 0);
  msgq_clean(mb);
}

/**
 * Send a standard reply (FAIL/WARN/NOTE) to a client.
 * Internal helper function.
 * @param[in] to Client to send to.
 * @param[in] type Reply type (FAIL, WARN, or NOTE).
 * @param[in] command Command that generated this reply (or "*" for general).
 * @param[in] code Machine-readable code (e.g., "ACCOUNT_REQUIRED").
 * @param[in] context Optional context parameter (NULL if none).
 * @param[in] description Human-readable description.
 */
static void send_standard_reply(struct Client *to, const char *type,
                                 const char *command, const char *code,
                                 const char *context, const char *description)
{
  send_standard_reply_ex(to, type, command, code, context, description, NULL);
}

/**
 * Send a FAIL reply to a client (IRCv3 standard-replies).
 * Indicates an error that prevented the command from executing.
 * @param[in] to Client to send to.
 * @param[in] command Command name (or "*" for general failure).
 * @param[in] code Machine-readable error code.
 * @param[in] context Optional context (NULL if none).
 * @param[in] description Human-readable error message.
 */
void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  send_standard_reply(to, "FAIL", command, code, context, description);
}

/**
 * Send a WARN reply to a client (IRCv3 standard-replies).
 * Indicates a warning that didn't prevent command execution.
 * @param[in] to Client to send to.
 * @param[in] command Command name (or "*" for general warning).
 * @param[in] code Machine-readable warning code.
 * @param[in] context Optional context (NULL if none).
 * @param[in] description Human-readable warning message.
 */
void send_warn(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  send_standard_reply(to, "WARN", command, code, context, description);
}

/**
 * Send a WARN reply with an explicit label (IRCv3 standard-replies + labeled-response).
 * Used when the warning relates to an earlier command whose label was saved.
 * @param[in] to Client to send to.
 * @param[in] command Command name (or "*" for general warning).
 * @param[in] code Machine-readable warning code.
 * @param[in] context Optional context (NULL if none).
 * @param[in] description Human-readable warning message.
 * @param[in] label Explicit label to include (NULL uses cli_label).
 */
void send_warn_with_label(struct Client *to, const char *command, const char *code,
                          const char *context, const char *description,
                          const char *label)
{
  send_standard_reply_ex(to, "WARN", command, code, context, description, label);
}

/**
 * Send a NOTE reply to a client (IRCv3 standard-replies).
 * Provides informational feedback about a command.
 * @param[in] to Client to send to.
 * @param[in] command Command name (or "*" for general note).
 * @param[in] code Machine-readable info code.
 * @param[in] context Optional context (NULL if none).
 * @param[in] description Human-readable info message.
 */
void send_note(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  send_standard_reply(to, "NOTE", command, code, context, description);
}

/**
 * Send a FAIL reply with printf-formatted context (IRCv3 standard-replies).
 * Supports multiple context parameters via format string, e.g.:
 *   send_fail_ctx(cli, "METADATA", "KEY_NO_PERMISSION",
 *                 "You don't have permission", "%s %s", target, key);
 * produces: FAIL METADATA KEY_NO_PERMISSION <target> <key> :You don't have permission
 */
void send_fail_ctx(struct Client *to, const char *command, const char *code,
                   const char *description, const char *context_fmt, ...)
{
  char ctx[512];
  if (context_fmt) {
    va_list ap;
    va_start(ap, context_fmt);
    ircd_vsnprintf(0, ctx, sizeof(ctx), context_fmt, ap);
    va_end(ap);
    send_standard_reply(to, "FAIL", command, code, ctx, description);
  } else {
    send_standard_reply(to, "FAIL", command, code, NULL, description);
  }
}

/**
 * Send a WARN reply with printf-formatted context (IRCv3 standard-replies).
 */
void send_warn_ctx(struct Client *to, const char *command, const char *code,
                   const char *description, const char *context_fmt, ...)
{
  char ctx[512];
  if (context_fmt) {
    va_list ap;
    va_start(ap, context_fmt);
    ircd_vsnprintf(0, ctx, sizeof(ctx), context_fmt, ap);
    va_end(ap);
    send_standard_reply(to, "WARN", command, code, ctx, description);
  } else {
    send_standard_reply(to, "WARN", command, code, NULL, description);
  }
}

/**
 * Send a NOTE reply with printf-formatted context (IRCv3 standard-replies).
 */
void send_note_ctx(struct Client *to, const char *command, const char *code,
                   const char *description, const char *context_fmt, ...)
{
  char ctx[512];
  if (context_fmt) {
    va_list ap;
    va_start(ap, context_fmt);
    ircd_vsnprintf(0, ctx, sizeof(ctx), context_fmt, ap);
    va_end(ap);
    send_standard_reply(to, "NOTE", command, code, ctx, description);
  } else {
    send_standard_reply(to, "NOTE", command, code, NULL, description);
  }
}

/**
 * Send an ACK message for labeled-response when a command produces no output.
 * Per IRCv3 labeled-response spec, server MUST send ACK if no response was sent.
 * @param[in] to Client to send ACK to.
 */
void send_labeled_ack(struct Client *to)
{
  struct MsgBuf *mb;
  char tagbuf[256];
  int pos = 0;
  int use_time;

  /* Only send ACK if client has labeled-response capability and a pending label */
  if (!to || !MyConnect(to))
    return;
  if (!feature_bool(FEAT_CAP_labeled_response) || !LabeledResponseInUse(to))
    return;
  if (!cli_label(to)[0])
    return;
  /* Don't send ACK if we already sent a labeled response */
  if (cli_label_responded(to))
    return;

  /* Build tags: @label=xxx;time=xxx */
  tagbuf[0] = '@';
  pos = 1;
  pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos, "label=%s", cli_label(to));

  use_time = feature_bool(FEAT_CAP_server_time) && CapRecipientHas(to, CAP_SERVERTIME);
  if (use_time) {
    struct timeval tv;
    struct tm tm;
    if (pos < (int)sizeof(tagbuf) - 1)
      tagbuf[pos++] = ';';
    client_tag_tv(&tv);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(tagbuf + pos, sizeof(tagbuf) - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    (long)(tv.tv_usec / 1000));
  }

  tagbuf[pos++] = ' ';
  tagbuf[pos] = '\0';

  /* Send: @label=xxx :server ACK */
  mb = msgq_make(to, "%s:%s ACK", tagbuf, cli_name(&me));
  send_buffer(to, mb, 0);
  msgq_clean(mb);

  /* Mark as responded so we don't send duplicate ACKs */
  cli_label_responded(to) = 1;
}

/** Start a labeled-response batch if client has pending label + batch cap.
 * Opens a labeled-response batch and sets cli_labeled_batch flag for
 * safety net tracking.
 * @param[in] sptr Local client to start batch for.
 * @return 1 if batch was started, 0 otherwise.
 */
int labeled_batch_start(struct Client *sptr)
{
  if (!MyConnect(sptr))
    return 0;
  /* Only for a label still waiting for its answer: one already answered
   * (or left by an earlier command) opens nothing. */
  if (!cli_label(sptr)[0] || cli_label_responded(sptr))
    return 0;
  if (!feature_bool(FEAT_CAP_labeled_response) || !LabeledResponseInUse(sptr))
    return 0;
  if (!feature_bool(FEAT_CAP_batch))
    return 0;

  if (!send_batch_start(sptr, "labeled-response")) {
    /* Nothing opened: BATCH_NEST_MAX batches are open already (the checks
     * above leave no other way).  The answer's lines will go out in the
     * innermost of them, which is not this label's: the label is answered
     * now, once, by a labeled ACK, and rides on none of them (left
     * pending, the first reply would carry it inside that unrelated
     * batch, or parse_client() would ACK after the lines).  No path opens
     * a labeled batch that deep today. */
    send_batch_end(sptr);   /* unpair it */
    send_labeled_ack(sptr);
    return 0;
  }
  cli_labeled_batch(sptr) = cli_connect(sptr)->con_batch_depth;
  return 1;
}

/** Open a DEFERRED labeled-response batch for an answer that cannot be
 * counted before it is sent (see "A deferred labeled-response batch"
 * above): its frame opens with nothing on the wire, the label is taken,
 * and the lines that follow are held until the answer needs the batch (a
 * second message) or ends (one message: it carries the label; none: ACK).
 * Ended as a labeled batch is (labeled_batch_end(), parse_client()).
 * @param[in] sptr Local client whose labeled line is being answered.
 * @return 1 if the frame was opened, 0 otherwise (no label pending, labels
 *   not in use, or the depth cap: labeled_batch_start()'s answer then). */
int labeled_batch_defer(struct Client *sptr)
{
  struct Connection *con;
  struct BatchFrame *f;
  struct BatchHold *h;

  if (!MyConnect(sptr))
    return 0;
  if (!cli_label(sptr)[0] || cli_label_responded(sptr))
    return 0;
  if (!feature_bool(FEAT_CAP_labeled_response) || !LabeledResponseInUse(sptr))
    return 0;
  if (!feature_bool(FEAT_CAP_batch) || !batch_wire(sptr))
    return 0;
  con = cli_connect(sptr);
  if (con_batch_hold(con) || con->con_batch_depth >= BATCH_NEST_MAX)
    return labeled_batch_start(sptr);

  f = &con->con_batch[con->con_batch_depth];
  ircd_strncpy(f->parent, batch_current_id(sptr), sizeof(f->parent));
  generate_batch_id(sptr, f->id, sizeof(f->id));
  con->con_batch_depth++;
  h = (struct BatchHold *)MyCalloc(1, sizeof(*h));
  h->depth = con->con_batch_depth;
  ircd_strncpy(h->label, cli_label(sptr), sizeof(h->label));
  con_batch_hold(con) = h;
  cli_label_responded(sptr) = 1;   /* the deferred batch has it */
  cli_labeled_batch(sptr) = con->con_batch_depth;
  return 1;
}

/** End a labeled-response batch started by labeled_batch_start().
 * Closes the batch and clears the cli_labeled_batch flag.
 * @param[in] sptr Local client to end batch for.
 */
void labeled_batch_end(struct Client *sptr)
{
  if (!MyConnect(sptr))
    return;
  if (!cli_labeled_batch(sptr))
    return;

  /* Batches still open inside it end first, innermost first. */
  {
    unsigned int at = cli_labeled_batch(sptr);
    while (cli_connect(sptr)->con_batch_over
           || cli_connect(sptr)->con_batch_depth >= at)
      send_batch_end(sptr);
  }
  cli_labeled_batch(sptr) = 0;
}

