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
#include "capab.h"
#include "channel.h"
#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numnicks.h"
#include "parse.h"
#include "s_bsd.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "struct.h"
#include "sys.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

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

/** Format current time as ISO 8601 timestamp for server-time capability.
 * @param[out] buf Buffer to write timestamp to.
 * @param[in] buflen Size of buffer.
 * @return Pointer to buf.
 */
static char *format_server_time(char *buf, size_t buflen)
{
  struct timeval tv;
  struct tm tm;

  gettimeofday(&tv, NULL);
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

/** Check if a client wants message tags (server-time, account-tag, or label).
 * Used for TAGMSG filtering - only clients with message-tags capability can receive TAGMSGs.
 * @param[in] to Recipient client.
 * @return Non-zero if client has any message tag capability active.
 */
static int wants_message_tags(struct Client *to)
{
  return (feature_bool(FEAT_CAP_server_time) && CapActive(to, CAP_SERVERTIME)) ||
         (feature_bool(FEAT_CAP_account_tag) && CapActive(to, CAP_ACCOUNTTAG)) ||
         (feature_bool(FEAT_CAP_labeled_response) && CapActive(to, CAP_LABELEDRESP) &&
          MyConnect(to) && cli_label(to)[0]);
}

/** Flags for format_message_tags_ex() tag selection */
#define TAGS_TIME     0x01  /**< Include @time tag */
#define TAGS_ACCOUNT  0x02  /**< Include @account tag */
#define TAGS_BATCH    0x04  /**< Include @batch tag (network batch) */
#define TAGS_BOT      0x08  /**< Include @bot tag */

/** Format message tags with explicit control over which tags to include.
 * @param[out] buf Buffer to write tags to.
 * @param[in] buflen Size of buffer.
 * @param[in] from Source client (for account tag and bot detection).
 * @param[in] flags TAGS_* flags indicating which tags to include.
 * @return Pointer to buf, or NULL if no tags to add.
 */
static char *format_message_tags_ex(char *buf, size_t buflen, struct Client *from, int flags)
{
  int pos = 0;
  int use_time = flags & TAGS_TIME;
  int use_account = flags & TAGS_ACCOUNT;
  int use_batch = (flags & TAGS_BATCH) && active_network_batch_id[0];
  int use_bot = (flags & TAGS_BOT) && from && IsBot(from);

  if (!use_time && !use_account && !use_batch && !use_bot)
    return NULL;

  buf[0] = '@';
  pos = 1;

  /* @batch tag first (most important for batched messages) */
  if (use_batch) {
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", active_network_batch_id);
  }

  if (use_time) {
    struct timeval tv;
    struct tm tm;
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(buf + pos, buflen - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    tv.tv_usec / 1000);
  }

  if (use_account && from && cli_user(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    if (IsAccount(from))
      pos += snprintf(buf + pos, buflen - pos, "account=%s", cli_user(from)->account);
    else
      pos += snprintf(buf + pos, buflen - pos, "account=*");
  }

  /* Add @bot tag if sender has +B mode (IRCv3 bot-mode spec) */
  if (use_bot) {
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

/** Get the tag flags appropriate for a client based on their capabilities.
 * @param[in] to Recipient client.
 * @param[in] from Source client (for bot detection).
 * @param[in] include_batch Whether to include batch tag if network batch is active.
 * @return TAGS_* flags for this client.
 */
static int get_client_tag_flags(struct Client *to, struct Client *from, int include_batch)
{
  int flags = 0;

  if (feature_bool(FEAT_CAP_server_time) && CapActive(to, CAP_SERVERTIME))
    flags |= TAGS_TIME;
  if (feature_bool(FEAT_CAP_account_tag) && CapActive(to, CAP_ACCOUNTTAG))
    flags |= TAGS_ACCOUNT;
  if (include_batch && CapActive(to, CAP_BATCH) && active_network_batch_id[0])
    flags |= TAGS_BATCH;
  /* Bot tag is sent to any client that gets any tags */
  if (flags && from && IsBot(from))
    flags |= TAGS_BOT;

  return flags;
}

/** Generate a unique message ID for IRCv3 message-ids.
 * Format: <server_numeric>-<startup_ts>-<counter>
 * @param[out] buf Buffer to write message ID to.
 * @param[in] buflen Size of buffer.
 * @return Pointer to buf.
 */
static char *generate_msgid(char *buf, size_t buflen)
{
  snprintf(buf, buflen, "%s-%lu-%lu",
           cli_yxx(&me),
           (unsigned long)cli_firsttime(&me),
           ++MsgIdCounter);
  return buf;
}

/** Format message tags for S2S (server-to-server) relay.
 * If the message came from another server with tags, preserve them.
 * Otherwise, generate new @time and @msgid tags.
 * @param[out] buf Buffer for tag string (includes trailing space).
 * @param[in] buflen Size of buffer.
 * @param[in] cptr Server connection the message came from (for incoming tags).
 * @param[out] msgid_out Optional: buffer to store the msgid used (for echo-message).
 * @param[in] msgid_out_len Size of msgid_out buffer.
 * @return Pointer to buf, or NULL if P10_MESSAGE_TAGS is disabled.
 */
static char *format_s2s_tags(char *buf, size_t buflen, struct Client *cptr,
                             char *msgid_out, size_t msgid_out_len)
{
  int pos = 0;
  char timebuf[32];
  char msgidbuf[64];
  const char *time_tag = NULL;
  const char *msgid_tag = NULL;

  /* Check if P10 message tags are enabled */
  if (!feature_bool(FEAT_P10_MESSAGE_TAGS))
    return NULL;

  /* Check for incoming S2S tags from cptr */
  if (cptr && cli_s2s_time(cptr)[0])
    time_tag = cli_s2s_time(cptr);
  if (cptr && cli_s2s_msgid(cptr)[0])
    msgid_tag = cli_s2s_msgid(cptr);

  /* Generate new tags if not present */
  if (!time_tag) {
    struct timeval tv;
    struct tm tm;
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    snprintf(timebuf, sizeof(timebuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec,
             tv.tv_usec / 1000);
    time_tag = timebuf;
  }

  if (!msgid_tag) {
    generate_msgid(msgidbuf, sizeof(msgidbuf));
    msgid_tag = msgidbuf;
  }

  /* Store msgid for caller if requested (for echo-message) */
  if (msgid_out && msgid_out_len > 0) {
    ircd_strncpy(msgid_out, msgid_tag, msgid_out_len - 1);
    msgid_out[msgid_out_len - 1] = '\0';
  }

  /* Format the tag string with trailing space */
  pos = snprintf(buf, buflen, "@time=%s;msgid=%s ", time_tag, msgid_tag);
  if (pos >= (int)buflen)
    buf[buflen - 1] = '\0';

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
  int use_time = feature_bool(FEAT_CAP_server_time) && CapActive(to, CAP_SERVERTIME);
  int use_account = feature_bool(FEAT_CAP_account_tag) && CapActive(to, CAP_ACCOUNTTAG);
  int use_label = feature_bool(FEAT_CAP_labeled_response) &&
                  CapActive(to, CAP_LABELEDRESP) &&
                  to && MyConnect(to) && cli_label(to)[0];
  int use_batch = feature_bool(FEAT_CAP_batch) && CapActive(to, CAP_BATCH) &&
                  to && MyConnect(to) && cli_batch_id(to)[0];
  int use_msgid = msgid && *msgid;
  int pos = 0;

  if (!use_time && !use_account && !use_label && !use_batch && !use_msgid)
    return NULL;

  buf[0] = '@';
  pos = 1;

  /* When in a batch, use @batch instead of @label */
  if (use_batch) {
    pos += snprintf(buf + pos, buflen - pos, "batch=%s", cli_batch_id(to));
  } else if (use_label) {
    pos += snprintf(buf + pos, buflen - pos, "label=%s", cli_label(to));
  }

  /* Add @msgid for message tracking (IRCv3 message-ids) */
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
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(buf + pos, buflen - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    tv.tv_usec / 1000);
  }

  if (use_account && from && cli_user(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    if (IsAccount(from)) {
      pos += snprintf(buf + pos, buflen - pos, "account=%s",
                      cli_user(from)->account);
    } else {
      pos += snprintf(buf + pos, buflen - pos, "account=*");
    }
  }

  /* Add @bot tag if sender has +B mode (IRCv3 bot-mode spec) */
  if (from && IsBot(from)) {
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
  int use_time = feature_bool(FEAT_CAP_server_time) && CapActive(to, CAP_SERVERTIME);
  int use_account = feature_bool(FEAT_CAP_account_tag) && CapActive(to, CAP_ACCOUNTTAG);
  int use_label = feature_bool(FEAT_CAP_labeled_response) &&
                  CapActive(to, CAP_LABELEDRESP) &&
                  to && MyConnect(to) && cli_label(to)[0];
  int use_batch = feature_bool(FEAT_CAP_batch) && CapActive(to, CAP_BATCH) &&
                  to && MyConnect(to) && cli_batch_id(to)[0];
  int use_client_tags = client_tags && *client_tags;
  int pos = 0;

  /* TAGMSG is only useful if there are client-only tags to relay */
  if (!use_client_tags && !use_time && !use_account && !use_label && !use_batch)
    return NULL;

  buf[0] = '@';
  pos = 1;

  /* Client-only tags first (these are the primary content for TAGMSG) */
  if (use_client_tags) {
    pos += snprintf(buf + pos, buflen - pos, "%s", client_tags);
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
  }

  if (use_time) {
    struct timeval tv;
    struct tm tm;
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    gettimeofday(&tv, NULL);
    gmtime_r(&tv.tv_sec, &tm);
    pos += snprintf(buf + pos, buflen - pos,
                    "time=%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                    tm.tm_hour, tm.tm_min, tm.tm_sec,
                    tv.tv_usec / 1000);
  }

  if (use_account && from && cli_user(from)) {
    if (pos > 1 && pos < (int)buflen - 1)
      buf[pos++] = ';';
    if (IsAccount(from)) {
      pos += snprintf(buf + pos, buflen - pos, "account=%s",
                      cli_user(from)->account);
    } else {
      pos += snprintf(buf + pos, buflen - pos, "account=*");
    }
  }

  /* Add @bot tag if sender has +B mode (IRCv3 bot-mode spec) */
  if (from && IsBot(from)) {
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
   * Keep a copy of the last comment, for later use...
   */
  ircd_strncpy(cli_info(to), notice, REALLEN + 1);

  if (!IsUser(to) && !IsUnknown(to) && !HasFlag(to, FLAG_CLOSING))
    sendto_opmask_butone(0, SNO_OLDSNO, "%s for %s", cli_info(to), cli_name(to));
  Debug((DEBUG_ERROR, cli_info(to)));
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

  while (MsgQLength(&(cli_sendQ(to))) > 0) {
    unsigned int len;

    if ((len = deliver_it(to, &(cli_sendQ(to))))) {
      msgq_delete(&(cli_sendQ(to)), len);
      cli_lastsq(to) = MsgQLength(&(cli_sendQ(to))) / 1024;
      if (IsBlocked(to)) {
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
    /*
     * This socket has already been marked as dead
     */
    return;

  if (MsgQLength(&(cli_sendQ(to))) > get_sendq(to)) {
    if (IsServer(to))
      sendto_opmask_butone(0, SNO_OLDSNO, "Max SendQ limit exceeded for %C: "
			   "%zu > %zu", to, MsgQLength(&(cli_sendQ(to))),
			   get_sendq(to));
    dead_link(to, "Max sendQ exceeded");
    return;
  }

  Debug((DEBUG_SEND, "Sending [%p] to %s", buf, cli_name(to)));

  msgq_add(&(cli_sendQ(to)), buf, prio);
  client_add_sendq(cli_connect(to), &send_queues);
  update_write(to);

  /*
   * Update statistics. The following is slightly incorrect
   * because it counts messages even if queued, but bytes
   * only really sent. Queued bytes get updated in SendQueued.
   */
  ++(cli_sendM(to));
  ++(cli_sendM(&me));
  /*
   * This little bit is to stop the sendQ from growing too large when
   * there is no need for it to. Thus we call send_queued() every time
   * 2k has been added to the queue since the last non-fatal write.
   * Also stops us from deliberately building a large sendQ and then
   * trying to flood that link with data (possible during the net
   * relinking done by servers with a large load).
   */
  if (MsgQLength(&(cli_sendQ(to))) / 1024 > cli_lastsq(to))
    send_queued(to);
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

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* For S2S messages (PRIVMSG/NOTICE to servers), add S2S tags */
  if ((IsServer(to) || IsMe(to)) &&
      (strcmp(tok, TOK_PRIVATE) == 0 || strcmp(tok, TOK_NOTICE) == 0) &&
      feature_bool(FEAT_P10_MESSAGE_TAGS)) {
    /* Get incoming server connection for tag preservation */
    cptr = MyConnect(from) ? NULL : cli_from(from);
    if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), cptr, NULL, 0)) {
      mb = msgq_make(to, "%s%:#C %s %v", s2s_tagbuf, from, tok, &vd);
    } else {
      mb = msgq_make(to, "%:#C %s %v", from, tok, &vd);
    }
  } else {
    mb = msgq_make(to, "%:#C %s %v", from, IsServer(to) || IsMe(to) ? tok : cmd,
                   &vd);
  }

  va_end(vd.vd_args);

  send_buffer(to, mb, 0);

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

  to = cli_from(to);

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* Generate msgid for PRIVMSG and NOTICE if feature enabled */
  if (feature_bool(FEAT_MSGID) &&
      (cmd == CMD_PRIVATE || cmd == CMD_NOTICE)) {
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

  send_buffer(to, mb, 0);

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
  char tagbuf[1024];
  char *tags;

  to = cli_from(to);

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  tags = format_message_tags_with_client(tagbuf, sizeof(tagbuf), from, to, client_tags);

  if (tags)
    mb = msgq_make(to, "%s%:#C %s %v", tags, from, cmd, &vd);
  else
    mb = msgq_make(to, "%:#C %s %v", from, cmd, &vd);

  va_end(vd.vd_args);

  send_buffer(to, mb, 0);

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
  struct MsgBuf *mb;
  struct DLink *lp;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* use token */
  mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send it to our downlinks */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    if ((require < FLAG_LAST_FLAG) && !HasFlag(lp->value.cptr, require))
      continue;
    if ((forbid < FLAG_LAST_FLAG) && HasFlag(lp->value.cptr, forbid))
      continue;
    send_buffer(lp->value.cptr, mb, 0);
  }

  msgq_clean(mb);
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
  struct MsgBuf *mb;
  struct DLink *lp;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* use token */
  mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

  /* send it to our downlinks */
  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    if (one && lp->value.cptr == cli_from(one))
      continue;
    send_buffer(lp->value.cptr, mb, 0);
  }

  msgq_clean(mb);
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
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[16] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *chan;
  struct Membership *member;
  char tagbuf[128];
  int flags;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_start(vd.vd_args, pattern);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  bump_sentalong(from);
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;
    for (member = chan->channel->members; member;
	 member = member->next_member)
      if (MyConnect(member->user)
          && -1 < cli_fd(cli_from(member->user))
          && member->user != one
          && cli_sentalong(member->user) != sentalong_marker) {
	cli_sentalong(member->user) = sentalong_marker;
	flags = get_client_tag_flags(member->user, from, 1);
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
  }

  if (MyConnect(from) && from != one) {
    flags = get_client_tag_flags(from, from, 1);
    if (flags && mb_cache[flags])
      send_buffer(from, mb_cache[flags], 0);
    else
      send_buffer(from, mb, 0);
  }

  msgq_clean(mb);
  for (flags = 0; flags < 16; flags++) {
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
void sendcmdto_common_channels_capab_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Client *one,
                                      int withcap, int skipcap,
                                      const char *pattern, ...)
{
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[16] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *chan;
  struct Membership *member;
  char tagbuf[128];
  int flags;

  assert(0 != from);
  assert(0 != cli_from(from));
  assert(0 != pattern);
  assert(!IsServer(from) && !IsMe(from));

  vd.vd_format = pattern; /* set up the struct VarData for %v */

  va_start(vd.vd_args, pattern);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  bump_sentalong(from);
  /*
   * loop through from's channels, and the members on their channels
   */
  for (chan = cli_user(from)->channel; chan; chan = chan->next_channel) {
    if (IsZombie(chan) || IsDelayedJoin(chan))
      continue;
    for (member = chan->channel->members; member;
         member = member->next_member)
      if (MyConnect(member->user)
          && -1 < cli_fd(cli_from(member->user))
          && member->user != one
          && cli_sentalong(member->user) != sentalong_marker
          && ((withcap == CAP_NONE) || CapActive(member->user, withcap))
          && ((skipcap == CAP_NONE) || !CapActive(member->user, skipcap))) {
        cli_sentalong(member->user) = sentalong_marker;
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
  }

  if (MyConnect(from) && from != one) {
    flags = get_client_tag_flags(from, from, 0);
    if (flags && mb_cache[flags])
      send_buffer(from, mb_cache[flags], 0);
    else
      send_buffer(from, mb, 0);
  }

  msgq_clean(mb);
  for (flags = 0; flags < 16; flags++) {
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
  struct VarData vd;
  struct MsgBuf *mb;
  /* Per-capability message buffers - only send tags client actually requested */
  struct MsgBuf *mb_cache[16] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *member;
  char tagbuf[128];
  int flags;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

  /* send the buffer to each local channel member */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member)&& !HasVoice(member))
        || (skip & SKIP_CHGHOST && CapActive(member->user, CAP_CHGHOST)))
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

  msgq_clean(mb);
  for (flags = 0; flags < 16; flags++) {
    if (mb_cache[flags])
      msgq_clean(mb_cache[flags]);
  }
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
  struct MsgBuf *mb_cache[16] = {0};  /* Indexed by TAGS_* flag combinations */
  struct Membership *member;
  char tagbuf[128];
  int flags;

  vd.vd_format = pattern; /* set up the struct VarData for %v */
  va_start(vd.vd_args, pattern);

  /* build the base buffer (no tags) */
  mb = msgq_make(0, "%:#C %s %v", from, cmd, &vd);
  va_end(vd.vd_args);

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
        || ((withcap != CAP_NONE) && !CapActive(member->user, withcap))
        || ((skipcap != CAP_NONE) && CapActive(member->user, skipcap)))
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

  msgq_clean(mb);
  for (flags = 0; flags < 16; flags++) {
    if (mb_cache[flags])
      msgq_clean(mb_cache[flags]);
  }
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
  char tagbuf[1024];

  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);

  /* Send to each local channel member with message-tags capability */
  for (member = to->members; member; member = member->next_member) {
    if (!MyConnect(member->user)
        || member->user == one
        || IsZombie(member)
        || (skip & SKIP_DEAF && IsDeaf(member->user))
        || (skip & SKIP_NONOPS && !IsChanOp(member))
        || (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member))
        || (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member) && !HasVoice(member))
        || !wants_message_tags(member->user))
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
  struct Membership *member;

  /* build the buffer */
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  serv_mb = msgq_make(&me, "%:#C %s %v", from, tok, &vd);
  va_end(vd.vd_args);

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
    send_buffer(member->user, serv_mb, 0);
  }
  msgq_clean(serv_mb);
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
  struct MsgBuf *user_mb_cache[16] = {0};  /* Indexed by TAGS_* flag combinations */
  struct MsgBuf *serv_mb;
  struct MsgBuf *serv_mb_tags = NULL;  /* S2S tagged version */
  struct Client *service;
  struct Client *cptr;  /* Server connection for incoming S2S tags */
  const char *userfmt;
  const char *usercmd;
  char tagbuf[128];
  char s2s_tagbuf[128];
  char userfmt_tags[64];
  int tflags;

  vd.vd_format = pattern;

  /* Get the server connection for S2S tag handling */
  cptr = MyConnect(from) ? NULL : cli_from(from);

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

  /* Build buffer to send to servers - with S2S tags if enabled */
  if (format_s2s_tags(s2s_tagbuf, sizeof(s2s_tagbuf), cptr, NULL, 0)) {
    va_start(vd.vd_args, pattern);
    serv_mb_tags = msgq_make(&me, "%s%C %s %v", s2s_tagbuf, from, tok, &vd);
    va_end(vd.vd_args);
    serv_mb = serv_mb_tags;  /* Use tagged version */
  } else {
    va_start(vd.vd_args, pattern);
    serv_mb = msgq_make(&me, "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
  }

  /* send buffer along! */
  bump_sentalong(one);
  for (member = to->members; member; member = member->next_member) {
    /* skip one, zombies, and deaf users... */
    if (IsZombie(member) ||
        (skip & SKIP_DEAF && IsDeaf(member->user)) ||
        (skip & SKIP_NONOPS && !IsChanOp(member)) ||
        (skip & SKIP_NONHOPS && !IsChanOp(member) && !IsHalfOp(member)) ||
        (skip & SKIP_NONVOICES && !IsChanOp(member) && !IsHalfOp(member) && !HasVoice(member)) ||
        (skip & SKIP_BURST && IsBurstOrBurstAck(cli_from(member->user))) ||
        (is_silenced(from, member->user, 1)) ||
        cli_fd(cli_from(member->user)) < 0 ||
        cli_sentalong(member->user) == sentalong_marker)
      continue;
    cli_sentalong(member->user) = sentalong_marker;

    if (MyConnect(member->user)) { /* pick right buffer to send */
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
    } else
      send_buffer(member->user, serv_mb, 0);
  }
  /* Consult service forwarding table. */
  if(GlobalForwards[prefix]
      && (service = FindServer(GlobalForwards[prefix]))
      && cli_sentalong(service) != sentalong_marker) {
      cli_sentalong(service) = sentalong_marker;
      send_buffer(service, serv_mb, 0);
  }

  msgq_clean(user_mb);
  for (tflags = 0; tflags < 16; tflags++) {
    if (user_mb_cache[tflags])
      msgq_clean(user_mb_cache[tflags]);
  }
  msgq_clean(serv_mb);
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

/**
 * Generate a unique batch reference ID.
 * @param[in] cptr Client to generate batch ID for.
 * @param[out] buf Buffer to store the generated ID.
 * @param[in] buflen Size of the buffer.
 * @return Pointer to the buffer.
 */
static char *generate_batch_id(struct Client *cptr, char *buf, size_t buflen)
{
  unsigned int seq = con_batch_seq(cli_connect(cptr))++;
  ircd_snprintf(NULL, buf, buflen, "%s%u", cli_yxx(cptr), seq);
  return buf;
}

/**
 * Start a batch for a client.
 * Sends BATCH +refid type to the client and stores the batch ID.
 * @param[in] to Client to start batch for.
 * @param[in] type Batch type (e.g., "labeled-response", "netjoin").
 */
void send_batch_start(struct Client *to, const char *type)
{
  struct MsgBuf *mb;
  char tagbuf[256];
  int pos = 0;

  if (!feature_bool(FEAT_CAP_batch) || !CapActive(to, CAP_BATCH) || !MyConnect(to))
    return;

  /* Generate a new batch ID */
  generate_batch_id(to, cli_batch_id(to), sizeof(con_batch_id(cli_connect(to))));

  /* Build message tags - include label if this is for labeled-response */
  tagbuf[0] = '\0';
  if (feature_bool(FEAT_CAP_labeled_response) &&
      CapActive(to, CAP_LABELEDRESP) && cli_label(to)[0]) {
    tagbuf[0] = '@';
    pos = 1;
    pos += ircd_snprintf(NULL, tagbuf + pos, sizeof(tagbuf) - pos, "label=%s", cli_label(to));
    if (pos < (int)sizeof(tagbuf) - 1) {
      tagbuf[pos++] = ' ';
      tagbuf[pos] = '\0';
    }
  }

  /* Send BATCH +refid type */
  if (tagbuf[0])
    mb = msgq_make(cli_from(to), "%s:%s " MSG_BATCH_CMD " +%s %s",
                   tagbuf, cli_name(&me), cli_batch_id(to), type);
  else
    mb = msgq_make(cli_from(to), ":%s " MSG_BATCH_CMD " +%s %s",
                   cli_name(&me), cli_batch_id(to), type);

  send_buffer(to, mb, 0);
  msgq_clean(mb);
}

/**
 * End the current batch for a client.
 * Sends BATCH -refid to the client and clears the batch ID.
 * @param[in] to Client to end batch for.
 */
void send_batch_end(struct Client *to)
{
  struct MsgBuf *mb;

  if (!feature_bool(FEAT_CAP_batch) || !CapActive(to, CAP_BATCH) || !MyConnect(to))
    return;

  /* Only end if there's an active batch */
  if (!cli_batch_id(to)[0])
    return;

  /* Send BATCH -refid */
  mb = msgq_make(cli_from(to), ":%s " MSG_BATCH_CMD " -%s",
                 cli_name(&me), cli_batch_id(to));

  send_buffer(to, mb, 0);
  msgq_clean(mb);

  /* Clear the batch ID */
  cli_batch_id(to)[0] = '\0';
}

/**
 * Check if a client has an active batch.
 * @param[in] cptr Client to check.
 * @return Non-zero if batch is active, zero otherwise.
 */
int has_active_batch(struct Client *cptr)
{
  if (!MyConnect(cptr))
    return 0;
  return cli_batch_id(cptr)[0] != '\0';
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

  /* Generate unique batch ID using server numeric + timestamp + counter */
  generate_batch_id(sptr, batch_id, sizeof(batch_id));

  /* Send to all servers */
  if (server1 && server2) {
    sendcmdto_serv_butone(sptr, CMD_BATCH_CMD, NULL, "+%s %s %s %s",
                          batch_id, type, server1, server2);
  }
  else if (server1) {
    sendcmdto_serv_butone(sptr, CMD_BATCH_CMD, NULL, "+%s %s %s",
                          batch_id, type, server1);
  }
  else {
    sendcmdto_serv_butone(sptr, CMD_BATCH_CMD, NULL, "+%s %s",
                          batch_id, type);
  }

  /* Store batch ID for later reference */
  ircd_strncpy(cli_s2s_batch_id(sptr), batch_id, sizeof(con_s2s_batch_id(cli_connect(sptr))) - 1);
  cli_s2s_batch_id(sptr)[sizeof(con_s2s_batch_id(cli_connect(sptr))) - 1] = '\0';
  ircd_strncpy(cli_s2s_batch_type(sptr), type, sizeof(con_s2s_batch_type(cli_connect(sptr))) - 1);
  cli_s2s_batch_type(sptr)[sizeof(con_s2s_batch_type(cli_connect(sptr))) - 1] = '\0';

  /* Send batch start to local clients with batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    if (server1 && server2) {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s %s %s %s",
                    batch_id, type, server1, server2);
    }
    else if (server1) {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s %s %s",
                    batch_id, type, server1);
    }
    else {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s %s",
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
  sendcmdto_serv_butone(sptr, CMD_BATCH_CMD, NULL, "-%s", id);

  /* Send batch end to local clients with batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", id);
  }

  /* Clear stored batch ID */
  cli_s2s_batch_id(sptr)[0] = '\0';
  cli_s2s_batch_type(sptr)[0] = '\0';
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

  /* Generate unique batch ID */
  ircd_snprintf(NULL, batch_id, sizeof(batch_id), "NJ%s%lu",
                cli_yxx(&me), netjoin_seq++);

  /* Store on server struct */
  ircd_strncpy(cli_serv(server)->batch_id, batch_id,
               sizeof(cli_serv(server)->batch_id) - 1);
  cli_serv(server)->batch_id[sizeof(cli_serv(server)->batch_id) - 1] = '\0';

  /* Set active network batch so JOIN messages include @batch tag */
  set_active_network_batch(batch_id);

  /* Send batch start to local clients with batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    if (uplink) {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s netjoin %s %s",
                    batch_id, cli_name(uplink), cli_name(server));
    } else {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s netjoin %s",
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

  /* Send batch end to local clients with batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", batch_id);
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

  /* Generate unique batch ID */
  ircd_snprintf(NULL, batch_id_out, batch_id_len, "NS%s%lu",
                cli_yxx(&me), netsplit_seq++);

  /* Send batch start to local clients with batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    if (uplink && server) {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s netsplit %s %s",
                    batch_id_out, cli_name(uplink), cli_name(server));
    } else if (server) {
      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s netsplit %s",
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

  /* Send batch end to local clients with batch capability */
  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (!MyConnect(acptr) || !IsUser(acptr))
      continue;
    if (!CapActive(acptr, CAP_BATCH))
      continue;

    sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", batch_id);
  }
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
  struct MsgBuf *mb;
  char tagbuf[512];

  if (!MyConnect(to))
    return;

  /* Only send to clients with standard-replies capability */
  if (!feature_bool(FEAT_CAP_standard_replies) || !CapActive(to, CAP_STANDARDREPLIES))
    return;

  /* Format tags (label, time) if applicable */
  if (format_message_tags_for(tagbuf, sizeof(tagbuf), NULL, to)) {
    if (context && *context)
      mb = msgq_make(to, "%s%s %s %s %s :%s", tagbuf, type, command, code, context, description);
    else
      mb = msgq_make(to, "%s%s %s %s :%s", tagbuf, type, command, code, description);
  } else {
    if (context && *context)
      mb = msgq_make(to, "%s %s %s %s :%s", type, command, code, context, description);
    else
      mb = msgq_make(to, "%s %s %s :%s", type, command, code, description);
  }

  send_buffer(to, mb, 0);
  msgq_clean(mb);
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

