/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
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
/*
 * ms_batch - server message handler for S2S BATCH coordination
 *
 * Handles BATCH commands from other servers for coordinating
 * netjoin/netsplit batches across the network.
 *
 * P10 Format:
 *   [SERVER_NUMERIC] BT +batchid type [params]   - Start batch
 *   [SERVER_NUMERIC] BT -batchid                  - End batch
 *
 * Batch Types:
 *   netjoin  - Server reconnecting, users rejoining channels
 *   netsplit - Server disconnecting, users quitting
 *
 * IRCv3 batch specification: https://ircv3.net/specs/extensions/batch
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_bsd.h"
#include "send.h"
#include "s_misc.h"
#include "s_user.h"
#include "msgq.h"
#include "class.h"
#include "ml_storage.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

/*
 * ms_batch - server message handler
 *
 * parv[0] = sender prefix (server numeric)
 * parv[1] = +batchid type [params] OR -batchid
 *
 * Handle BATCH from other servers (P10: BT token).
 * Format: SERVER BT +batchid netjoin server1 server2
 *         SERVER BT -batchid
 */
int ms_batch(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char* batch_ref;
  char* batch_type = NULL;
  int is_start;
  struct Client* acptr;
  struct DLink* lp;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Only servers can send S2S BATCH */
  if (!IsServer(sptr))
    return protocol_violation(sptr, "Non-server trying to send S2S BATCH");

  if (parc < 2 || EmptyString(parv[1]))
    return 0;

  batch_ref = parv[1];

  /* Determine if this is batch start (+) or end (-) */
  if (batch_ref[0] == '+') {
    is_start = 1;
    batch_ref++;  /* Skip the + prefix */
    if (parc >= 3 && !EmptyString(parv[2]))
      batch_type = parv[2];
    else
      return 0;  /* Start batch requires type */
  }
  else if (batch_ref[0] == '-') {
    is_start = 0;
    batch_ref++;  /* Skip the - prefix */
  }
  else {
    return 0;  /* Invalid format */
  }

  if (EmptyString(batch_ref))
    return 0;

  /* Store batch state for this server connection */
  if (is_start) {
    ircd_strncpy(cli_s2s_batch_id(cptr), batch_ref,
                 sizeof(con_s2s_batch_id(cli_connect(cptr))) - 1);
    cli_s2s_batch_id(cptr)[sizeof(con_s2s_batch_id(cli_connect(cptr))) - 1] = '\0';
    if (batch_type) {
      ircd_strncpy(cli_s2s_batch_type(cptr), batch_type,
                   sizeof(con_s2s_batch_type(cli_connect(cptr))) - 1);
      cli_s2s_batch_type(cptr)[sizeof(con_s2s_batch_type(cli_connect(cptr))) - 1] = '\0';
    }
  }
  else {
    /* Clear batch state on end */
    cli_s2s_batch_id(cptr)[0] = '\0';
    cli_s2s_batch_type(cptr)[0] = '\0';
  }

  /* Propagate to other servers */
  sendcmdto_serv_butone(sptr, CMD_BATCH_CMD, cptr, "%s%s%s%s",
                        is_start ? "+" : "-",
                        batch_ref,
                        batch_type ? " " : "",
                        batch_type ? batch_type : "");

  /* For netjoin/netsplit batches, notify local clients with batch capability */
  if (batch_type && (strcmp(batch_type, "netjoin") == 0 ||
                     strcmp(batch_type, "netsplit") == 0)) {
    /* Send batch markers to all local clients with batch capability */
    for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
      if (!MyConnect(acptr) || !IsUser(acptr))
        continue;
      if (!CapActive(acptr, CAP_BATCH))
        continue;

      if (is_start) {
        /* Start batch for this client */
        /* For netjoin: BATCH +refid netjoin server1 server2 */
        /* For netsplit: BATCH +refid netsplit server1 server2 */
        if (parc >= 5 && !EmptyString(parv[3]) && !EmptyString(parv[4])) {
          sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s %s %s %s",
                        batch_ref, batch_type, parv[3], parv[4]);
        }
        else if (parc >= 4 && !EmptyString(parv[3])) {
          sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s %s %s",
                        batch_ref, batch_type, parv[3]);
        }
        else {
          sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s %s",
                        batch_ref, batch_type);
        }
      }
      else {
        /* End batch for this client */
        sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", batch_ref);
      }
    }
  }

  return 0;
}

/*
 * Helper functions for multiline batch handling
 */

/** Clear the multiline batch state for a connection */
static void
clear_multiline_batch(struct Connection *con)
{
  struct SLink *lp, *next;

  /* Free all stored messages */
  for (lp = con_ml_messages(con); lp; lp = next) {
    next = lp->next;
    if (lp->value.cp)
      MyFree(lp->value.cp);
    free_link(lp);
  }

  /* Apply accumulated lag from the batch with a configurable discount.
   * Per IRCv3 multiline spec, we should be lenient for batched messages,
   * but we can't ignore lag entirely or malicious clients could abuse
   * multiline batches to flood channels (recipients who don't support
   * multiline still receive each line as a separate PRIVMSG).
   *
   * MULTILINE_LAG_DISCOUNT controls what percentage of lag is applied for DMs:
   *   100 = full lag (no benefit to multiline, like regular messages)
   *   50  = 50% lag (default - rewards multiline while preventing abuse)
   *   0   = no lag (dangerous - allows unlimited multiline flooding)
   *
   * MULTILINE_CHANNEL_LAG_DISCOUNT is used for channel messages (typically
   * higher than DM discount since channels affect more users).
   *
   * MULTILINE_RECIPIENT_DISCOUNT: When enabled, if ALL recipients support
   * draft/multiline (no fallback to individual PRIVMSGs was needed), we can
   * be more lenient since the batch was delivered as intended - halve the
   * lag discount percentage.
   */
  if (con_ml_lag_accum(con) > 0) {
    int discount;
    int discounted_lag;

    /* Use different discount for channels vs DMs */
    if (con_ml_target(con)[0] && IsChannelName(con_ml_target(con)))
      discount = feature_int(FEAT_MULTILINE_CHANNEL_LAG_DISCOUNT);
    else
      discount = feature_int(FEAT_MULTILINE_LAG_DISCOUNT);

    /* If all recipients supported multiline (no fallback), halve the discount */
    if (feature_bool(FEAT_MULTILINE_RECIPIENT_DISCOUNT) && !con_ml_had_fallback(con))
      discount = discount / 2;

    /* Clamp discount to valid range */
    if (discount < 0)
      discount = 0;
    else if (discount > 100)
      discount = 100;

    discounted_lag = (con_ml_lag_accum(con) * discount) / 100;
    if (discounted_lag < 2 && discount > 0)
      discounted_lag = 2;  /* Minimum one message worth (unless fully disabled) */
    con_since(con) += discounted_lag;
  }
  con_ml_lag_accum(con) = 0;

  con_ml_batch_id(con)[0] = '\0';
  con_ml_target(con)[0] = '\0';
  con_ml_messages(con) = NULL;
  con_ml_msg_count(con) = 0;
  con_ml_total_bytes(con) = 0;
  con_ml_batch_start(con) = 0;
}

/** Check for and handle client batch timeout.
 * Called periodically from check_pings().
 * @param[in] cptr Client to check.
 * @return 1 if batch was timed out, 0 otherwise.
 */
int
check_client_batch_timeout(struct Client *cptr)
{
  struct Connection *con;
  time_t timeout;

  if (!MyConnect(cptr))
    return 0;

  con = cli_connect(cptr);
  if (!con_ml_batch_id(con)[0])
    return 0; /* No active batch */

  timeout = feature_int(FEAT_CLIENT_BATCH_TIMEOUT);
  if (timeout <= 0)
    return 0; /* Timeout disabled */

  if (CurrentTime - con_ml_batch_start(con) < timeout)
    return 0; /* Not timed out yet */

  /* Batch has timed out - send FAIL and clear */
  send_fail(cptr, "BATCH", "TIMEOUT", con_ml_batch_id(con),
            "Batch timed out");
  clear_multiline_batch(con);
  return 1;
}

/** Add a message to the multiline batch */
int
multiline_add_message(struct Client *sptr, const char *text, int concat)
{
  struct Connection *con = cli_connect(sptr);
  struct SLink *lp;
  int len;
  char *msgcopy;

  if (!con_ml_batch_id(con)[0])
    return 0;  /* No active batch */

  len = strlen(text);

  /* Check limits */
  if (con_ml_msg_count(con) >= feature_int(FEAT_MULTILINE_MAX_LINES)) {
    send_fail(sptr, "BATCH", "MULTILINE_MAX_LINES",
              con_ml_batch_id(con), "Too many lines in batch");
    clear_multiline_batch(con);
    return -1;
  }

  if (con_ml_total_bytes(con) + len > feature_int(FEAT_MULTILINE_MAX_BYTES)) {
    send_fail(sptr, "BATCH", "MULTILINE_MAX_BYTES",
              con_ml_batch_id(con), "Total bytes exceeded");
    clear_multiline_batch(con);
    return -1;
  }

  /* Store the message with concat flag encoded in high bit of first char */
  msgcopy = (char *)MyMalloc(len + 2);
  msgcopy[0] = concat ? 1 : 0;  /* Flag byte */
  strcpy(msgcopy + 1, text);

  lp = make_link();
  lp->value.cp = msgcopy;
  lp->next = NULL;

  /* Append to end of list */
  if (!con_ml_messages(con)) {
    con_ml_messages(con) = lp;
  } else {
    struct SLink *tail;
    for (tail = con_ml_messages(con); tail->next; tail = tail->next)
      ;
    tail->next = lp;
  }

  con_ml_msg_count(con)++;
  con_ml_total_bytes(con) += len;

  return 0;
}

/** Helper to get user's displayed host */
static const char *
get_displayed_host(struct Client *sptr)
{
  if (IsHiddenHost(sptr))
    return cli_user(sptr)->host;
  return cli_user(sptr)->realhost;
}

/** Helper to format ISO 8601 timestamp for server-time tag */
static void
format_time_tag(char *buf, size_t buflen)
{
  struct timeval tv;
  struct tm tm;

  gettimeofday(&tv, NULL);
  gmtime_r(&tv.tv_sec, &tm);
  snprintf(buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           tv.tv_usec / 1000);
}

/** Process and deliver a completed multiline batch */
static int
process_multiline_batch(struct Client *sptr)
{
  struct Connection *con = cli_connect(sptr);
  struct Channel *chptr = NULL;
  struct Client *acptr = NULL;
  struct SLink *lp;
  struct Membership *member;
  int is_channel;
  int first;
  char batch_base_msgid[64];  /* Base msgid for entire batch */
  int msg_seq;  /* Sequence counter for submessage ordering */
  int fallback_count = 0;  /* Track recipients who got truncated fallback */

  if (!con_ml_batch_id(con)[0])
    return 0;  /* No active batch */

  if (!con_ml_messages(con)) {
    clear_multiline_batch(con);
    return 0;  /* Empty batch */
  }

  is_channel = IsChannelName(con_ml_target(con));

  /* Initialize fallback tracking for recipient-aware discounting */
  con_ml_had_fallback(con) = 0;

  /* Validate target */
  if (is_channel) {
    chptr = FindChannel(con_ml_target(con));
    if (!chptr) {
      send_reply(sptr, ERR_NOSUCHCHANNEL, con_ml_target(con));
      clear_multiline_batch(con);
      return 0;
    }
    /* Check if user can send to channel */
    member = find_member_link(chptr, sptr);
    if (!member && (chptr->mode.mode & MODE_NOPRIVMSGS)) {
      send_reply(sptr, ERR_CANNOTSENDTOCHAN, chptr->chname);
      clear_multiline_batch(con);
      return 0;
    }
  } else {
    acptr = FindUser(con_ml_target(con));
    if (!acptr) {
      send_reply(sptr, ERR_NOSUCHNICK, con_ml_target(con));
      clear_multiline_batch(con);
      return 0;
    }
  }

  /* Generate ONE base msgid for the entire multiline batch.
   * Each line will get this base msgid with a sequence suffix: base:00, base:01, etc.
   * This ensures all lines can be retrieved together via CHATHISTORY by msgid prefix.
   */
  generate_msgid(batch_base_msgid, sizeof(batch_base_msgid));

  /* Deliver to recipients */
  if (is_channel) {
    /* For each member of the channel */
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *to = member->user;

      if (to == sptr)
        continue;  /* Skip sender (handle echo-message separately) */

      if (CapActive(to, CAP_DRAFT_MULTILINE) && CapActive(to, CAP_BATCH)) {
        /* Send as batch to supporting clients */
        char batchid[16];
        char timebuf[32];
        char msgidbuf[64];
        int use_tags = CapActive(to, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        msg_seq = 0;  /* Reset sequence for each recipient's delivery */
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          /* Format msgid with sequence suffix for submessage ordering: base:00, base:01, etc. */
          if (use_tags) {
            format_time_tag(timebuf, sizeof(timebuf));
            ircd_snprintf(0, msgidbuf, sizeof(msgidbuf), "%s:%02d", batch_base_msgid, msg_seq);
          }
          msg_seq++;

          if (first && !concat) {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
            first = 0;
          } else if (concat) {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          } else {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          }
        }

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "-%s", batchid);
      } else {
        /* Fallback: send as individual messages
         * If recipient has +M (multiline expand), send full expansion
         * Otherwise use graduated truncation based on batch size
         */
        int total_lines = con_ml_msg_count(con);

        con_ml_had_fallback(con) = 1;  /* Track for recipient-aware discounting */
        fallback_count++;  /* Count for sender WARN notification */

        if (HasFlag(to, FLAG_MULTILINE_EXPAND)) {
          /* User opted in with +M: send all lines without truncation */
          for (lp = con_ml_messages(con); lp; lp = lp->next) {
            char *text = lp->value.cp + 1;
            sendcmdto_one(sptr, CMD_PRIVATE, to, "%H :%s", chptr, text);
          }
        } else {
          /* 3-tier truncation with retrieval hints:
           * - Small (1-5 lines): send all, no notice
           * - Medium (6-10 lines): send 4 lines + truncation notice
           * - Large (11+ lines): no preview, just retrieval notice
           */
          int lines_to_send;
          int send_notice;  /* 0=none, 1=medium (X more), 2=large (full msg) */

          if (total_lines <= 5) {
            /* Small batch: send all, no notice */
            lines_to_send = total_lines;
            send_notice = 0;
          } else if (total_lines <= 10) {
            /* Medium batch: send 4 lines + truncation notice */
            lines_to_send = 4;
            send_notice = 1;
          } else {
            /* Large batch: no preview, just retrieval notice */
            lines_to_send = 0;
            send_notice = 2;
          }

          int sent = 0;
          for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next, sent++) {
            char *text = lp->value.cp + 1;
            sendcmdto_one(sptr, CMD_PRIVATE, to, "%H :%s", chptr, text);
          }

          if (send_notice) {
            /* Store full content for retrieval */
            if (feature_bool(FEAT_MULTILINE_STORAGE_ENABLED)) {
              ml_storage_store(batch_base_msgid, cli_name(sptr), chptr->chname,
                               con_ml_messages(con), total_lines);
              if (send_notice == 1) {
                sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /join &ml-%s to view full message]",
                              chptr, total_lines - sent, batch_base_msgid);
              } else {
                sendcmdto_one(&me, CMD_NOTICE, to, "%H :[Multiline message (%d lines) - /join &ml-%s to view]",
                              chptr, total_lines, batch_base_msgid);
              }
            } else {
              if (send_notice == 1) {
                sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /msg HistServ FETCH %s %s]",
                              chptr, total_lines - sent, chptr->chname, batch_base_msgid);
              } else {
                sendcmdto_one(&me, CMD_NOTICE, to, "%H :[Multiline message (%d lines) - /msg HistServ FETCH %s %s]",
                              chptr, total_lines, chptr->chname, batch_base_msgid);
              }
            }
          }
        }
      }
    }

    /* Echo to sender if echo-message enabled
     * Bounded echo protection: allows echo to proceed even if SendQ is
     * near the limit, as long as we stay within an extended limit
     * (sendq_limit + input_bytes * ECHO_MAX_FACTOR). This prevents
     * "Max sendQ exceeded" disconnects from echo-message expansions
     * while still protecting against amplification attacks by bounding
     * the protection to a multiple of the input.
     *
     * Logic: Skip echo if adding echo bytes would exceed extended limit.
     * Without protection, skip if already over normal limit.
     */
    if (CapActive(sptr, CAP_ECHOMSG)) {
      int skip_echo = 0;

      if (MyConnect(sptr)) {
        unsigned int batch_input_bytes = con_ml_total_bytes(con);
        unsigned int current_sendq = MsgQLength(&(cli_sendQ(sptr)));
        unsigned int sendq_limit = get_sendq(sptr);

        if (feature_bool(FEAT_MULTILINE_ECHO_PROTECT)) {
          /* Protected: allow up to sendq_limit + bounded echo headroom */
          unsigned int max_echo_bytes = batch_input_bytes * feature_int(FEAT_MULTILINE_ECHO_MAX_FACTOR);
          unsigned int extended_limit = sendq_limit + max_echo_bytes;

          /* Skip if current SendQ already exceeds extended limit */
          if (current_sendq > extended_limit) {
            skip_echo = 1;
          }
        } else {
          /* Unprotected: skip echo if already at/over normal limit */
          if (current_sendq >= sendq_limit) {
            skip_echo = 1;
          }
        }
      }

      if (!skip_echo && CapActive(sptr, CAP_DRAFT_MULTILINE) && CapActive(sptr, CAP_BATCH)) {
        char batchid[16];
        char timebuf[32];
        char msgidbuf[64];
        int use_tags = CapActive(sptr, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(con)++);

        sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        msg_seq = 0;  /* Reset sequence for echo delivery */
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          /* Format msgid with sequence suffix for submessage ordering */
          if (use_tags) {
            format_time_tag(timebuf, sizeof(timebuf));
            ircd_snprintf(0, msgidbuf, sizeof(msgidbuf), "%s:%02d", batch_base_msgid, msg_seq);
          }
          msg_seq++;

          if (first && !concat) {
            if (use_tags) {
              sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
            first = 0;
          } else if (concat) {
            if (use_tags) {
              sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(sptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          } else {
            if (use_tags) {
              sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          }
        }

        sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
      } else if (!skip_echo) {
        /* Fallback echo for non-multiline-capable sender */
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          char *text = lp->value.cp + 1;
          sendcmdto_one(sptr, CMD_PRIVATE, sptr, "%H :%s", chptr, text);
        }
      }
    }
  } else {
    /* Private message to user */
    if (CapActive(acptr, CAP_DRAFT_MULTILINE) && CapActive(acptr, CAP_BATCH)) {
      char batchid[16];
      char timebuf[32];
      char msgidbuf[64];
      int use_tags = CapActive(acptr, CAP_MSGTAGS);

      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s draft/multiline %s",
                    batchid, cli_name(acptr));

      first = 1;
      msg_seq = 0;  /* Reset sequence for DM delivery */
      for (lp = con_ml_messages(con); lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        /* Format msgid with sequence suffix for submessage ordering */
        if (use_tags) {
          format_time_tag(timebuf, sizeof(timebuf));
          ircd_snprintf(0, msgidbuf, sizeof(msgidbuf), "%s:%02d", batch_base_msgid, msg_seq);
        }
        msg_seq++;

        if (first && !concat) {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
          first = 0;
        } else if (concat) {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
        } else {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
        }
      }

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", batchid);
    } else {
      /* Fallback for DM: send as individual messages
       * If recipient has +M (multiline expand), send full expansion
       * Otherwise use graduated truncation based on batch size
       */
      int total_lines = con_ml_msg_count(con);

      con_ml_had_fallback(con) = 1;
      fallback_count++;  /* Count for sender WARN notification */

      if (HasFlag(acptr, FLAG_MULTILINE_EXPAND)) {
        /* User opted in with +M: send all lines without truncation */
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          char *text = lp->value.cp + 1;
          sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
        }
      } else {
        /* 3-tier truncation with retrieval hints */
        int lines_to_send;
        int send_notice;  /* 0=none, 1=medium (X more), 2=large (full msg) */

        if (total_lines <= 5) {
          lines_to_send = total_lines;
          send_notice = 0;
        } else if (total_lines <= 10) {
          lines_to_send = 4;
          send_notice = 1;
        } else {
          lines_to_send = 0;
          send_notice = 2;
        }

        int sent = 0;
        for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next, sent++) {
          char *text = lp->value.cp + 1;
          sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
        }

        if (send_notice) {
          /* Store full content for retrieval */
          if (feature_bool(FEAT_MULTILINE_STORAGE_ENABLED)) {
            ml_storage_store(batch_base_msgid, cli_name(sptr), cli_name(acptr),
                             con_ml_messages(con), total_lines);
            if (send_notice == 1) {
              sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[%d more lines - /join &ml-%s to view full message]",
                            acptr, total_lines - sent, batch_base_msgid);
            } else {
              sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[Multiline message (%d lines) - /join &ml-%s to view]",
                            acptr, total_lines, batch_base_msgid);
            }
          } else {
            if (send_notice == 1) {
              sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[%d more lines - /msg HistServ FETCH %s %s]",
                            acptr, total_lines - sent, cli_name(acptr), batch_base_msgid);
            } else {
              sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[Multiline message (%d lines) - /msg HistServ FETCH %s %s]",
                            acptr, total_lines, cli_name(acptr), batch_base_msgid);
            }
          }
        }
      }
    }

    /* Echo to sender with bounded protection (same logic as channel echo) */
    if (CapActive(sptr, CAP_ECHOMSG)) {
      int skip_dm_echo = 0;

      if (MyConnect(sptr)) {
        unsigned int batch_input_bytes = con_ml_total_bytes(con);
        unsigned int current_sendq = MsgQLength(&(cli_sendQ(sptr)));
        unsigned int sendq_limit = get_sendq(sptr);

        if (feature_bool(FEAT_MULTILINE_ECHO_PROTECT)) {
          unsigned int max_echo_bytes = batch_input_bytes * feature_int(FEAT_MULTILINE_ECHO_MAX_FACTOR);
          unsigned int extended_limit = sendq_limit + max_echo_bytes;
          if (current_sendq > extended_limit) {
            skip_dm_echo = 1;
          }
        } else {
          if (current_sendq >= sendq_limit) {
            skip_dm_echo = 1;
          }
        }
      }

      if (!skip_dm_echo) {
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          char *text = lp->value.cp + 1;
          sendcmdto_one(sptr, CMD_PRIVATE, sptr, "%C :%s", acptr, text);
        }
      }
    }

    /* S2S relay for private messages to remote users */
    if (!MyConnect(acptr)) {
      char s2s_batch_id[16];
      ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                    cli_yxx(sptr), (unsigned long)CurrentTime);

      first = 1;
      for (lp = con_ml_messages(con); lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        if (first) {
          /* Start batch with first line */
          sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "+%s %s :%s",
                                s2s_batch_id, cli_name(acptr), text);
          first = 0;
        } else if (concat) {
          /* Concat line */
          sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "c%s %s :%s",
                                s2s_batch_id, cli_name(acptr), text);
        } else {
          /* Normal continuation */
          sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "%s %s :%s",
                                s2s_batch_id, cli_name(acptr), text);
        }
      }
      /* End batch */
      sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "-%s %s :",
                            s2s_batch_id, cli_name(acptr));
    }
  }

  /* S2S relay for channel messages */
  if (is_channel && chptr) {
    char s2s_batch_id[16];
    ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                  cli_yxx(sptr), (unsigned long)CurrentTime);

    first = 1;
    for (lp = con_ml_messages(con); lp; lp = lp->next) {
      int concat = lp->value.cp[0];
      char *text = lp->value.cp + 1;

      if (first) {
        /* Start batch with first line */
        sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "+%s %s :%s",
                              s2s_batch_id, chptr->chname, text);
        first = 0;
      } else if (concat) {
        /* Concat line */
        sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "c%s %s :%s",
                              s2s_batch_id, chptr->chname, text);
      } else {
        /* Normal continuation */
        sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "%s %s :%s",
                              s2s_batch_id, chptr->chname, text);
      }
    }
    /* End batch */
    sendcmdto_serv_butone(sptr, CMD_MULTILINE, NULL, "-%s %s :",
                          s2s_batch_id, chptr->chname);
  }

  /* Notify sender about fallback if they support standard-replies */
  if (fallback_count > 0 && feature_bool(FEAT_MULTILINE_FALLBACK_NOTIFY)
      && CapActive(sptr, CAP_STANDARDREPLIES)) {
    char desc[128];
    ircd_snprintf(0, desc, sizeof(desc), "Message truncated for %d legacy recipient%s",
                  fallback_count, fallback_count == 1 ? "" : "s");
    send_warn(sptr, "BATCH", "MULTILINE_FALLBACK",
              is_channel ? chptr->chname : cli_name(acptr), desc);
  }

  clear_multiline_batch(con);
  return 0;
}

/*
 * m_batch - client message handler for BATCH command
 *
 * Handles BATCH start/end for multiline messages from clients.
 *
 * parv[0] = sender prefix
 * parv[1] = +batchid type target OR -batchid
 *
 * For draft/multiline:
 *   BATCH +id draft/multiline #channel
 *   BATCH -id
 */
int m_batch(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Connection *con;
  char *batch_ref;
  char *batch_type = NULL;
  char *target = NULL;
  int is_start;

  assert(0 != cptr);
  assert(cptr == sptr);

  if (!IsUser(sptr))
    return 0;

  /* Require draft/multiline capability */
  if (!CapActive(sptr, CAP_DRAFT_MULTILINE))
    return 0;

  if (parc < 2 || EmptyString(parv[1]))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");

  con = cli_connect(sptr);
  batch_ref = parv[1];

  /* Determine if this is batch start (+) or end (-) */
  if (batch_ref[0] == '+') {
    is_start = 1;
    batch_ref++;  /* Skip the + prefix */

    if (parc < 3 || EmptyString(parv[2]))
      return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");
    batch_type = parv[2];

    if (parc < 4 || EmptyString(parv[3]))
      return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");
    target = parv[3];
  }
  else if (batch_ref[0] == '-') {
    is_start = 0;
    batch_ref++;  /* Skip the - prefix */
  }
  else {
    send_fail(sptr, "BATCH", "INVALID_FORMAT", NULL,
              "Invalid batch format, expected +id or -id");
    return 0;
  }

  if (EmptyString(batch_ref))
    return send_reply(sptr, ERR_NEEDMOREPARAMS, "BATCH");

  if (is_start) {
    /* Only support draft/multiline for now */
    if (ircd_strcmp(batch_type, "draft/multiline") != 0) {
      send_fail(sptr, "BATCH", "UNSUPPORTED_TYPE", batch_type,
                "Unsupported batch type");
      return 0;
    }

    /* Batch rate limiting (FEAT_BATCH_RATE_LIMIT) */
    {
      int rate_limit = feature_int(FEAT_BATCH_RATE_LIMIT);
      if (rate_limit > 0) {
        /* Reset counter if we're in a new minute */
        if (CurrentTime - con_batch_minute(con) >= 60) {
          con_batch_minute(con) = CurrentTime;
          con_batch_count(con) = 0;
        }
        /* Check rate limit */
        if (con_batch_count(con) >= rate_limit) {
          send_fail(sptr, "BATCH", "RATE_LIMIT_EXCEEDED", batch_ref,
                    "Too many batches per minute");
          return 0;
        }
        con_batch_count(con)++;
      }
    }

    /* Check if there's already an active batch */
    if (con_ml_batch_id(con)[0]) {
      /* Clear the old batch */
      clear_multiline_batch(con);
    }

    /* Start new multiline batch */
    ircd_strncpy(con_ml_batch_id(con), batch_ref,
                 sizeof(con->con_ml_batch_id) - 1);
    con_ml_batch_id(con)[sizeof(con->con_ml_batch_id) - 1] = '\0';

    ircd_strncpy(con_ml_target(con), target,
                 sizeof(con->con_ml_target) - 1);
    con_ml_target(con)[sizeof(con->con_ml_target) - 1] = '\0';

    con_ml_messages(con) = NULL;
    con_ml_msg_count(con) = 0;
    con_ml_total_bytes(con) = 0;
    con_ml_batch_start(con) = CurrentTime;
    con_ml_lag_accum(con) = 0;  /* Reset lag accumulator for new batch */
  }
  else {
    /* End batch */
    if (!con_ml_batch_id(con)[0]) {
      send_fail(sptr, "BATCH", "NO_ACTIVE_BATCH", batch_ref,
                "No active batch to end");
      return 0;
    }

    if (strcmp(con_ml_batch_id(con), batch_ref) != 0) {
      send_fail(sptr, "BATCH", "BATCH_ID_MISMATCH", batch_ref,
                "Batch ID does not match active batch");
      return 0;
    }

    /* Process and deliver the batch */
    process_multiline_batch(sptr);
  }

  return 0;
}

/*
 * S2S Multiline batch relay structures and functions
 */

/** Structure to hold a pending multiline batch from S2S */
struct S2SMultilineBatch {
  char batch_id[16];            /**< Batch ID */
  char target[CHANNELLEN + 1];  /**< Target channel or nick */
  struct Client *sender;        /**< Original sender client */
  struct SLink *messages;       /**< Linked list of messages */
  int msg_count;                /**< Number of messages */
  time_t start_time;            /**< When batch started */
};

/** Global array of pending S2S multiline batches (indexed by server connection) */
static struct S2SMultilineBatch *s2s_ml_batches[MAXCONNECTIONS];

/** Find an S2S multiline batch by batch ID */
static struct S2SMultilineBatch *
find_s2s_multiline_batch(const char *batch_id)
{
  int i;
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_ml_batches[i] && strcmp(s2s_ml_batches[i]->batch_id, batch_id) == 0)
      return s2s_ml_batches[i];
  }
  return NULL;
}

/** Create a new S2S multiline batch */
static struct S2SMultilineBatch *
create_s2s_multiline_batch(const char *batch_id, const char *target,
                           struct Client *sender)
{
  int i;
  struct S2SMultilineBatch *batch;

  /* Find an empty slot */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (!s2s_ml_batches[i])
      break;
  }
  if (i >= MAXCONNECTIONS)
    return NULL;  /* No available slot */

  batch = (struct S2SMultilineBatch *)MyMalloc(sizeof(struct S2SMultilineBatch));
  ircd_strncpy(batch->batch_id, batch_id, sizeof(batch->batch_id) - 1);
  batch->batch_id[sizeof(batch->batch_id) - 1] = '\0';
  ircd_strncpy(batch->target, target, sizeof(batch->target) - 1);
  batch->target[sizeof(batch->target) - 1] = '\0';
  batch->sender = sender;
  batch->messages = NULL;
  batch->msg_count = 0;
  batch->start_time = CurrentTime;

  s2s_ml_batches[i] = batch;
  return batch;
}

/** Free an S2S multiline batch */
static void
free_s2s_multiline_batch(struct S2SMultilineBatch *batch)
{
  struct SLink *lp, *next;
  int i;

  if (!batch)
    return;

  /* Free messages */
  for (lp = batch->messages; lp; lp = next) {
    next = lp->next;
    if (lp->value.cp)
      MyFree(lp->value.cp);
    free_link(lp);
  }

  /* Remove from array */
  for (i = 0; i < MAXCONNECTIONS; i++) {
    if (s2s_ml_batches[i] == batch) {
      s2s_ml_batches[i] = NULL;
      break;
    }
  }

  MyFree(batch);
}

/** Add a message to an S2S multiline batch */
static void
add_s2s_multiline_message(struct S2SMultilineBatch *batch, const char *text, int concat)
{
  struct SLink *lp;
  char *msgcopy;
  int len;

  if (!batch || !text)
    return;

  len = strlen(text);
  msgcopy = (char *)MyMalloc(len + 2);
  msgcopy[0] = concat ? 1 : 0;  /* Flag byte */
  strcpy(msgcopy + 1, text);

  lp = make_link();
  lp->value.cp = msgcopy;
  lp->next = NULL;

  /* Append to end of list */
  if (!batch->messages) {
    batch->messages = lp;
  } else {
    struct SLink *tail;
    for (tail = batch->messages; tail->next; tail = tail->next)
      ;
    tail->next = lp;
  }

  batch->msg_count++;
}

/** Deliver a completed S2S multiline batch to local clients */
static void
deliver_s2s_multiline_batch(struct S2SMultilineBatch *batch, struct Client *cptr)
{
  struct Channel *chptr = NULL;
  struct Client *acptr = NULL;
  struct SLink *lp;
  struct Membership *member;
  int is_channel;
  int first;
  struct Client *sptr = batch->sender;
  char batch_base_msgid[64];  /* Base msgid for entire batch */
  int msg_seq;  /* Sequence counter for submessage ordering */

  if (!batch || !batch->messages || !sptr)
    return;

  /* Generate ONE base msgid for the entire S2S multiline batch */
  generate_msgid(batch_base_msgid, sizeof(batch_base_msgid));

  is_channel = IsChannelName(batch->target);

  /* Validate target */
  if (is_channel) {
    chptr = FindChannel(batch->target);
    if (!chptr)
      return;  /* Channel doesn't exist locally */
  } else {
    acptr = FindUser(batch->target);
    if (!acptr || !MyConnect(acptr))
      return;  /* User doesn't exist or isn't local */
  }

  /* Deliver to local recipients */
  if (is_channel) {
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *to = member->user;

      if (!MyConnect(to))
        continue;  /* Only deliver to local users */

      if (to == sptr)
        continue;  /* Skip sender (they already got echo) */

      if (CapActive(to, CAP_DRAFT_MULTILINE) && CapActive(to, CAP_BATCH)) {
        /* Send as batch to supporting clients */
        char batchid[16];
        char timebuf[32];
        char msgidbuf[64];
        int use_tags = CapActive(to, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        msg_seq = 0;  /* Reset sequence for each recipient's delivery */
        for (lp = batch->messages; lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          /* Format msgid with sequence suffix for submessage ordering */
          if (use_tags) {
            format_time_tag(timebuf, sizeof(timebuf));
            ircd_snprintf(0, msgidbuf, sizeof(msgidbuf), "%s:%02d", batch_base_msgid, msg_seq);
          }
          msg_seq++;

          if (first && !concat) {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
            first = 0;
          } else if (concat) {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          } else {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          }
        }

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "-%s", batchid);
      } else {
        /* Fallback: 3-tier truncation for S2S channel delivery */
        int total_lines = batch->msg_count;
        int lines_to_send;
        int send_notice;  /* 0=none, 1=medium (X more), 2=large (full msg) */

        if (total_lines <= 5) {
          lines_to_send = total_lines;
          send_notice = 0;
        } else if (total_lines <= 10) {
          lines_to_send = 4;
          send_notice = 1;
        } else {
          lines_to_send = 0;
          send_notice = 2;
        }

        int sent = 0;
        for (lp = batch->messages; lp && sent < lines_to_send; lp = lp->next, sent++) {
          char *text = lp->value.cp + 1;
          sendcmdto_one(sptr, CMD_PRIVATE, to, "%H :%s", chptr, text);
        }

        if (send_notice) {
          /* Store full content for retrieval */
          if (feature_bool(FEAT_MULTILINE_STORAGE_ENABLED)) {
            ml_storage_store(batch_base_msgid, cli_name(sptr), chptr->chname,
                             batch->messages, total_lines);
            if (send_notice == 1) {
              sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /join &ml-%s to view full message]",
                            chptr, total_lines - sent, batch_base_msgid);
            } else {
              sendcmdto_one(&me, CMD_NOTICE, to, "%H :[Multiline message (%d lines) - /join &ml-%s to view]",
                            chptr, total_lines, batch_base_msgid);
            }
          } else {
            if (send_notice == 1) {
              sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /msg HistServ FETCH %s %s]",
                            chptr, total_lines - sent, chptr->chname, batch_base_msgid);
            } else {
              sendcmdto_one(&me, CMD_NOTICE, to, "%H :[Multiline message (%d lines) - /msg HistServ FETCH %s %s]",
                            chptr, total_lines, chptr->chname, batch_base_msgid);
            }
          }
        }
      }
    }
  } else if (acptr && MyConnect(acptr)) {
    /* Private message to local user */
    if (CapActive(acptr, CAP_DRAFT_MULTILINE) && CapActive(acptr, CAP_BATCH)) {
      char batchid[16];
      char timebuf[32];
      char msgidbuf[64];
      int use_tags = CapActive(acptr, CAP_MSGTAGS);

      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s draft/multiline %s",
                    batchid, cli_name(acptr));

      first = 1;
      msg_seq = 0;  /* Reset sequence for S2S DM delivery */
      for (lp = batch->messages; lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        /* Format msgid with sequence suffix for submessage ordering */
        if (use_tags) {
          format_time_tag(timebuf, sizeof(timebuf));
          ircd_snprintf(0, msgidbuf, sizeof(msgidbuf), "%s:%02d", batch_base_msgid, msg_seq);
        }
        msg_seq++;

        if (first && !concat) {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
          first = 0;
        } else if (concat) {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
        } else {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, msgidbuf, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
        }
      }

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", batchid);
    } else {
      /* Fallback: 3-tier truncation for S2S DM delivery */
      int total_lines = batch->msg_count;
      int lines_to_send;
      int send_notice;  /* 0=none, 1=medium (X more), 2=large (full msg) */

      if (total_lines <= 5) {
        lines_to_send = total_lines;
        send_notice = 0;
      } else if (total_lines <= 10) {
        lines_to_send = 4;
        send_notice = 1;
      } else {
        lines_to_send = 0;
        send_notice = 2;
      }

      int sent = 0;
      for (lp = batch->messages; lp && sent < lines_to_send; lp = lp->next, sent++) {
        char *text = lp->value.cp + 1;
        sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
      }

      if (send_notice) {
        /* Store full content for retrieval */
        if (feature_bool(FEAT_MULTILINE_STORAGE_ENABLED)) {
          ml_storage_store(batch_base_msgid, cli_name(sptr), cli_name(acptr),
                           batch->messages, total_lines);
          if (send_notice == 1) {
            sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[%d more lines - /join &ml-%s to view full message]",
                          acptr, total_lines - sent, batch_base_msgid);
          } else {
            sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[Multiline message (%d lines) - /join &ml-%s to view]",
                          acptr, total_lines, batch_base_msgid);
          }
        } else {
          if (send_notice == 1) {
            sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[%d more lines - /msg HistServ FETCH %s %s]",
                          acptr, total_lines - sent, cli_name(acptr), batch_base_msgid);
          } else {
            sendcmdto_one(&me, CMD_NOTICE, acptr, "%C :[Multiline message (%d lines) - /msg HistServ FETCH %s %s]",
                          acptr, total_lines, cli_name(acptr), batch_base_msgid);
          }
        }
      }
    }
  }

  /* Propagate to other servers (except where it came from) */
  /* Note: This happens in ms_multiline which already propagates */
}

/*
 * ms_multiline - server message handler for S2S multiline batch
 *
 * P10 Format:
 *   [USER_NUMERIC] ML +batchid target :first_line   (start batch + first line)
 *   [USER_NUMERIC] ML batchid target :line          (normal continuation)
 *   [USER_NUMERIC] ML cbatchid target :line         (concat continuation)
 *   [USER_NUMERIC] ML -batchid target :             (end batch)
 *
 * parv[0] = sender prefix
 * parv[1] = batch_id with modifier (+, c, or -)
 * parv[2] = target
 * parv[3] = text (may be empty for end)
 */
int ms_multiline(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  char *batch_ref;
  char *target;
  char *text;
  int is_start = 0, is_end = 0, is_concat = 0;
  struct S2SMultilineBatch *batch;

  assert(0 != cptr);
  assert(0 != sptr);

  /* Sender must be a user */
  if (!IsUser(sptr))
    return protocol_violation(cptr, "Non-user sending MULTILINE");

  if (parc < 3)
    return 0;

  batch_ref = parv[1];
  target = parv[2];
  text = (parc >= 4 && !EmptyString(parv[3])) ? parv[3] : "";

  /* Parse batch modifier */
  if (batch_ref[0] == '+') {
    is_start = 1;
    batch_ref++;
  } else if (batch_ref[0] == '-') {
    is_end = 1;
    batch_ref++;
  } else if (batch_ref[0] == 'c') {
    is_concat = 1;
    batch_ref++;
  }

  if (EmptyString(batch_ref))
    return 0;

  /* Propagate to other servers first */
  sendcmdto_serv_butone(sptr, CMD_MULTILINE, cptr, "%s%s %s :%s",
                        is_start ? "+" : (is_end ? "-" : (is_concat ? "c" : "")),
                        batch_ref, target, text);

  if (is_start) {
    /* Start new batch */
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch) {
      /* Batch ID collision - clear old one */
      free_s2s_multiline_batch(batch);
    }

    batch = create_s2s_multiline_batch(batch_ref, target, sptr);
    if (!batch)
      return 0;  /* No room for new batch */

    /* Add first line if present */
    if (!EmptyString(text))
      add_s2s_multiline_message(batch, text, 0);
  }
  else if (is_end) {
    /* End batch and deliver */
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch) {
      deliver_s2s_multiline_batch(batch, cptr);
      free_s2s_multiline_batch(batch);
    }
  }
  else {
    /* Continuation line */
    batch = find_s2s_multiline_batch(batch_ref);
    if (batch)
      add_s2s_multiline_message(batch, text, is_concat);
  }

  return 0;
}
