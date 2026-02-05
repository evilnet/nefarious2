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
#include "history.h"
#include "bouncer_session.h"
#include "paste_store.h"
#include "paste_listener.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <sys/time.h>

/*
 * generate_paste_url - Create a paste from message list and return URL
 *
 * Helper function to generate a paste URL for multiline fallback scenarios.
 * Called by all fallback paths (client, bouncer shadow, server relay).
 *
 * Parameters:
 *   msgid    - base msgid for the batch
 *   sender   - sender nick
 *   target   - target channel/nick
 *   messages - linked list of message lines (value.cp + 1 = text)
 *
 * Returns: paste URL string (static buffer, do not free) or NULL if unavailable
 */
static const char *generate_paste_url(const char *msgid, const char *sender,
                                       const char *target, struct SLink *messages)
{
  char secret[12];
  char paste_id[PASTE_ID_MAX];
  char filename[PASTE_FILENAME_MAX] = "";
  size_t total_len = 0;
  char *content = NULL;
  char *p;
  struct SLink *lp;
  const char *result = NULL;

  if (!feature_bool(FEAT_PASTE_ENABLED) || !paste_store_available())
    return NULL;

  /* Calculate total content length */
  for (lp = messages; lp; lp = lp->next) {
    if (lp->value.cp) {
      const char *text = lp->value.cp + 1;
      total_len += strlen(text) + 1;  /* +1 for newline */
    }
  }

  if (total_len == 0)
    return NULL;

  content = (char *)MyMalloc(total_len);
  if (!content)
    return NULL;

  /* Concatenate all lines */
  p = content;
  for (lp = messages; lp; lp = lp->next) {
    if (lp->value.cp) {
      const char *text = lp->value.cp + 1;
      size_t len = strlen(text);
      memcpy(p, text, len);
      p += len;
      if (lp->next)
        *p++ = '\n';
    }
  }
  *p = '\0';

  /* Generate secret and paste_id */
  paste_generate_secret(secret, sizeof(secret));
  ircd_snprintf(0, paste_id, sizeof(paste_id), "%s-%s", msgid, secret);

  /* Parse optional filename hint from first line */
  const char *store_content = content;
  size_t store_len = strlen(content);
  paste_parse_filename_hint(content, store_len, filename, sizeof(filename),
                            &store_content, &store_len);

  /* Store the paste */
  if (paste_store_add(paste_id, sender, target, filename,
                      store_content, store_len,
                      feature_int(FEAT_PASTE_TTL)) == 0) {
    result = paste_url(paste_id);
  }

  MyFree(content);
  return result;
}

/*
 * send_multiline_fallback - Send truncated multiline with retrieval hints
 *
 * Implements the graceful fallback chain for legacy clients:
 * 1. Native chathistory (client can retrieve via CHATHISTORY AROUND)
 * 2. HistServ available (client can /msg HistServ FETCH)
 * 3. Local &ml- storage (ultimate fallback, zero dependencies)
 *
 * Uses configurable preview budget (FEAT_MULTILINE_LEGACY_MAX_LINES):
 * - ≤max_preview lines: send all, no notice
 * - >max_preview lines: send max_preview lines + retrieval notice
 *
 * Parameters:
 *   sptr        - sender client
 *   to          - recipient client
 *   target      - channel name or nick (for retrieval hint)
 *   msgid       - base msgid for retrieval
 *   messages    - linked list of message lines
 *   total_lines - total line count
 *   is_channel  - 1 if channel, 0 if DM
 *   chptr       - channel pointer (NULL for DMs)
 */
static void send_multiline_fallback(struct Client *sptr, struct Client *to,
                                     const char *target, const char *msgid,
                                     struct SLink *messages, int total_lines,
                                     int is_channel, struct Channel *chptr)
{
  struct SLink *lp;
  int lines_to_send;
  int send_notice;
  int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
  const char *paste_url_str = NULL;

  /* Configurable preview budget */
  if (total_lines <= max_preview) {
    lines_to_send = total_lines;
    send_notice = 0;
  } else {
    lines_to_send = max_preview;
    send_notice = 1;
  }

  /* Send preview lines */
  int sent = 0;
  for (lp = messages; lp && sent < lines_to_send; lp = lp->next, sent++) {
    char *text = lp->value.cp + 1;
    if (*text == '\0')
      continue;  /* Skip blank lines in fallback per IRCv3 spec */
    if (is_channel) {
      sendcmdto_one(sptr, CMD_PRIVATE, to, "%H :%s", chptr, text);
    } else {
      sendcmdto_one(sptr, CMD_PRIVATE, to, "%C :%s", to, text);
    }
  }

  if (!send_notice)
    return;

  int remaining = total_lines - sent;

  /* Generate paste URL if service available */
  paste_url_str = generate_paste_url(msgid, cli_name(sptr), target, messages);

  /* History-based fallback (tiers 2+3) requires:
   * - Recipient is authenticated (only authed users can query history)
   * - Sender is NOT +Y (no-storage users produce gap markers, not content)
   * Otherwise fall through to virtual channel storage (tier 4). */
  int history_usable = IsAccount(to) && !IsNoStorage(sptr)
                       && !(is_channel && chptr &&
                            (chptr->mode.exmode & EXMODE_NOSTORAGE));

  /* Fallback chain: chathistory -> HistServ -> &ml- storage
   * Paste URL included as additional retrieval option when available */
  if (history_usable && CapActive(to, CAP_DRAFT_CHATHISTORY)) {
    /* Tier 2: Client has native chathistory capability + can use it */
    if (is_channel) {
      if (paste_url_str) {
        sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - CHATHISTORY AROUND %s msgid=%s %d or %s]",
                      chptr, remaining, target, msgid, remaining + sent, paste_url_str);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - CHATHISTORY AROUND %s msgid=%s %d]",
                      chptr, remaining, target, msgid, remaining + sent);
      }
    } else {
      if (paste_url_str) {
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :[%d more lines - CHATHISTORY AROUND %s msgid=%s %d or %s]",
                      to, remaining, target, msgid, remaining + sent, paste_url_str);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :[%d more lines - CHATHISTORY AROUND %s msgid=%s %d]",
                      to, remaining, target, msgid, remaining + sent);
      }
    }
  } else if (history_usable && FindClient("HistServ")) {
    /* Tier 3: HistServ available + recipient can use it */
    if (is_channel) {
      if (paste_url_str) {
        sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /msg HistServ FETCH %s %s or %s]",
                      chptr, remaining, target, msgid, paste_url_str);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /msg HistServ FETCH %s %s]",
                      chptr, remaining, target, msgid);
      }
    } else {
      if (paste_url_str) {
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :[%d more lines - /msg HistServ FETCH %s %s or %s]",
                      to, remaining, target, msgid, paste_url_str);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :[%d more lines - /msg HistServ FETCH %s %s]",
                      to, remaining, target, msgid);
      }
    }
  } else {
    /* Tier 4: Ultimate fallback - local &ml- storage (zero dependencies) */
    ml_storage_store(msgid, cli_name(sptr), target, messages, total_lines);
    if (is_channel) {
      if (paste_url_str) {
        sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /join &ml-%s or %s]",
                      chptr, remaining, msgid, paste_url_str);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, to, "%H :[%d more lines - /join &ml-%s to view full message]",
                      chptr, remaining, msgid);
      }
    } else {
      if (paste_url_str) {
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :[%d more lines - /join &ml-%s or %s]",
                      to, remaining, msgid, paste_url_str);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, to, "%C :[%d more lines - /join &ml-%s to view full message]",
                      to, remaining, msgid);
      }
    }
  }
}

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
  con_ml_label(con)[0] = '\0';
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

  /* IRCv3 multiline spec: concat flag on blank line is invalid */
  if (concat && len == 0) {
    send_fail(sptr, "BATCH", "INVALID_MULTILINE",
              con_ml_batch_id(con), "Cannot use concat tag on blank line");
    clear_multiline_batch(con);
    return -1;
  }

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
    /* Suppress automatic shadow duplication - we handle shadows explicitly
     * to send the appropriate format based on each shadow's capabilities. */
    suppress_shadow_dup = 1;

    /* For each member of the channel */
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *to = member->user;
      struct BouncerSession *mbsess;
      int member_has_shadows;

      if (to == sptr)
        continue;  /* Skip sender (handle echo-message separately) */

      if (!MyConnect(to))
        continue;  /* Skip remote users - handled by S2S relay */

      mbsess = bounce_get_session(to);
      member_has_shadows = (mbsess && mbsess->hs_shadow_count > 0);

      /* Send to PRIMARY based on its OWN capabilities (not union) */
      if (CapOwnHas(to, CAP_DRAFT_MULTILINE) && CapOwnHas(to, CAP_BATCH)) {
        /* Send as batch to supporting primary */
        char batchid[16];
        char timebuf[32];
        int use_tags = CapOwnHas(to, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          /* All lines in the batch share the same msgid per IRCv3 multiline spec */
          if (use_tags) {
            format_time_tag(timebuf, sizeof(timebuf));
          }

          if (first && !concat) {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
                            batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          } else {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
        /* Fallback: send as individual messages to primary
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
          /* Graceful fallback: chathistory -> HistServ -> &ml- storage */
          send_multiline_fallback(sptr, to, chptr->chname, batch_base_msgid,
                                   con_ml_messages(con), total_lines, 1, chptr);
        }
      }

      /* Send to each SHADOW based on its capabilities */
      if (member_has_shadows) {
        struct ShadowConnection *sh;
        for (sh = mbsess->hs_shadows; sh; sh = sh->sh_next) {
          if (sh->sh_flags & SHADOW_FLAGS_DEAD)
            continue;

          if (CapHas(&sh->sh_active, CAP_DRAFT_MULTILINE) && CapHas(&sh->sh_active, CAP_BATCH)) {
            /* Shadow has multiline - send batch */
            char batchid[16];
            char timebuf[32];
            int use_tags = CapHas(&sh->sh_active, CAP_MSGTAGS);
            struct MsgBuf *mb;

            ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                          NumNick(sptr), con_batch_seq(cli_connect(to))++);

            mb = msgq_make(to, ":%s BATCH +%s draft/multiline %s",
                           cli_name(&me), batchid, chptr->chname);
            if (mb) {
              msgq_add(&sh->sh_sendQ, mb, 0);
              socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
              msgq_clean(mb);
            }

            first = 1;
            for (lp = con_ml_messages(con); lp; lp = lp->next) {
              int concat = lp->value.cp[0];
              char *text = lp->value.cp + 1;

              if (use_tags) {
                format_time_tag(timebuf, sizeof(timebuf));
              }

              if (first && !concat) {
                if (use_tags) {
                  mb = msgq_make(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                                 batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                 get_displayed_host(sptr), chptr->chname, text);
                } else {
                  mb = msgq_make(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                                 batchid, cli_name(sptr), cli_user(sptr)->username,
                                 get_displayed_host(sptr), chptr->chname, text);
                }
                first = 0;
              } else if (concat) {
                if (use_tags) {
                  mb = msgq_make(to, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                                 batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                 get_displayed_host(sptr), chptr->chname, text);
                } else {
                  mb = msgq_make(to, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                                 batchid, cli_name(sptr), cli_user(sptr)->username,
                                 get_displayed_host(sptr), chptr->chname, text);
                }
              } else {
                if (use_tags) {
                  mb = msgq_make(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                                 batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                 get_displayed_host(sptr), chptr->chname, text);
                } else {
                  mb = msgq_make(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                                 batchid, cli_name(sptr), cli_user(sptr)->username,
                                 get_displayed_host(sptr), chptr->chname, text);
                }
              }
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }
            }

            mb = msgq_make(to, ":%s BATCH -%s", cli_name(&me), batchid);
            if (mb) {
              msgq_add(&sh->sh_sendQ, mb, 0);
              socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
              msgq_clean(mb);
            }
          } else {
            /* Shadow doesn't have multiline - send fallback */
            int total_lines = con_ml_msg_count(con);
            int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
            int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;
            int sent = 0;
            struct MsgBuf *mb;

            for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
              char *text = lp->value.cp + 1;
              if (*text == '\0')
                continue;  /* Skip blank lines */
              mb = msgq_make(to, ":%s!%s@%s PRIVMSG %s :%s",
                             cli_name(sptr), cli_user(sptr)->username,
                             get_displayed_host(sptr), chptr->chname, text);
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }
              sent++;
            }

            /* Send truncation notice if needed */
            if (total_lines > max_preview) {
              int remaining = total_lines - sent;
              const char *sh_paste_url = generate_paste_url(batch_base_msgid, cli_name(sptr),
                                                            chptr->chname, con_ml_messages(con));

              if (sh_paste_url) {
                mb = msgq_make(to, ":%s NOTICE %s :[%d more lines - %s]",
                               cli_name(&me), chptr->chname, remaining, sh_paste_url);
              } else {
                mb = msgq_make(to, ":%s NOTICE %s :[%d more lines - use a multiline-capable client to view]",
                               cli_name(&me), chptr->chname, remaining);
              }
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }
            }
          }
        }
      }
    }

    suppress_shadow_dup = 0;

    /* Echo to sender and bouncer shadows with per-connection capability awareness.
     *
     * Bouncer sessions may have multiple connections (primary + shadows) with
     * different capabilities. Each connection that has echo-message should
     * receive the echo, formatted according to its own multiline capability.
     *
     * Bounded echo protection: allows echo to proceed even if SendQ is
     * near the limit, as long as we stay within an extended limit
     * (sendq_limit + input_bytes * ECHO_MAX_FACTOR).
     */
    {
      int need_echo = feature_bool(FEAT_CAP_echo_message) && CapActive(sptr, CAP_ECHOMSG);
      struct BouncerSession *bsess = bounce_get_session(sptr);
      int has_shadows = bsess && bsess->hs_shadow_count > 0;
      int skip_echo = 0;

      /* SendQ protection check */
      if (MyConnect(sptr)) {
        unsigned int batch_input_bytes = con_ml_total_bytes(con);
        unsigned int current_sendq = MsgQLength(&(cli_sendQ(sptr)));
        unsigned int sendq_limit = get_sendq(sptr);

        if (feature_bool(FEAT_MULTILINE_ECHO_PROTECT)) {
          unsigned int max_echo_bytes = batch_input_bytes * feature_int(FEAT_MULTILINE_ECHO_MAX_FACTOR);
          unsigned int extended_limit = sendq_limit + max_echo_bytes;
          if (current_sendq > extended_limit) {
            skip_echo = 1;
          }
        } else {
          if (current_sendq >= sendq_limit) {
            skip_echo = 1;
          }
        }
      }

      if (!skip_echo && (need_echo || has_shadows)) {
        /* Suppress automatic shadow duplication - we handle shadows manually
         * to send the appropriate format based on each shadow's capabilities. */
        suppress_shadow_dup = 1;

        /* Send to primary if it has echo-message */
        if (need_echo) {
          if (CapActive(sptr, CAP_DRAFT_MULTILINE) && CapActive(sptr, CAP_BATCH)) {
            /* Primary has multiline - send batch echo */
            char batchid[16];
            char timebuf[32];
            int use_tags = CapActive(sptr, CAP_MSGTAGS);
            int use_label = con_ml_label(con)[0] && CapActive(sptr, CAP_LABELEDRESP);

            ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                          NumNick(sptr), con_batch_seq(con)++);

            if (use_label) {
              sendrawto_one(sptr, "@label=%s :%s BATCH +%s draft/multiline %s",
                            con_ml_label(con), cli_name(&me), batchid, chptr->chname);
            } else {
              sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s draft/multiline %s",
                            batchid, chptr->chname);
            }

            first = 1;
            for (lp = con_ml_messages(con); lp; lp = lp->next) {
              int concat = lp->value.cp[0];
              char *text = lp->value.cp + 1;

              if (use_tags) {
                format_time_tag(timebuf, sizeof(timebuf));
              }

              if (first && !concat) {
                if (use_tags) {
                  sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                                batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
                                batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                get_displayed_host(sptr), chptr->chname, text);
                } else {
                  sendrawto_one(sptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                                batchid, cli_name(sptr), cli_user(sptr)->username,
                                get_displayed_host(sptr), chptr->chname, text);
                }
              } else {
                if (use_tags) {
                  sendrawto_one(sptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                                batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                get_displayed_host(sptr), chptr->chname, text);
                } else {
                  sendrawto_one(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                                batchid, cli_name(sptr), cli_user(sptr)->username,
                                get_displayed_host(sptr), chptr->chname, text);
                }
              }
            }

            sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
          } else {
            /* Primary doesn't have multiline - send fallback echo */
            for (lp = con_ml_messages(con); lp; lp = lp->next) {
              char *text = lp->value.cp + 1;
              sendcmdto_one(sptr, CMD_PRIVATE, sptr, "%H :%s", chptr, text);
            }
          }
        }

        /* Send to each shadow based on its capabilities.
         * Unlike the primary, shadows ALWAYS receive the message regardless of
         * echo-message cap - they're mirrors of the session and need to see what
         * was sent. This matches single-line behavior where automatic shadow
         * duplication sends to all shadows. */
        if (has_shadows) {
          struct ShadowConnection *sh;
          for (sh = bsess->hs_shadows; sh; sh = sh->sh_next) {
            if (sh->sh_flags & SHADOW_FLAGS_DEAD)
              continue;

            if (CapHas(&sh->sh_active, CAP_DRAFT_MULTILINE) && CapHas(&sh->sh_active, CAP_BATCH)) {
              /* Shadow has multiline - send batch echo */
              char batchid[16];
              char timebuf[32];
              int use_tags = CapHas(&sh->sh_active, CAP_MSGTAGS);
              struct MsgBuf *mb;

              ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                            NumNick(sptr), con_batch_seq(con)++);

              mb = msgq_make(sptr, ":%s BATCH +%s draft/multiline %s",
                             cli_name(&me), batchid, chptr->chname);
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }

              first = 1;
              for (lp = con_ml_messages(con); lp; lp = lp->next) {
                int concat = lp->value.cp[0];
                char *text = lp->value.cp + 1;

                if (use_tags) {
                  format_time_tag(timebuf, sizeof(timebuf));
                }

                if (first && !concat) {
                  if (use_tags) {
                    mb = msgq_make(sptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                                   batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                   get_displayed_host(sptr), chptr->chname, text);
                  } else {
                    mb = msgq_make(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                                   batchid, cli_name(sptr), cli_user(sptr)->username,
                                   get_displayed_host(sptr), chptr->chname, text);
                  }
                  first = 0;
                } else if (concat) {
                  if (use_tags) {
                    mb = msgq_make(sptr, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                                   batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                   get_displayed_host(sptr), chptr->chname, text);
                  } else {
                    mb = msgq_make(sptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                                   batchid, cli_name(sptr), cli_user(sptr)->username,
                                   get_displayed_host(sptr), chptr->chname, text);
                  }
                } else {
                  if (use_tags) {
                    mb = msgq_make(sptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                                   batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                                   get_displayed_host(sptr), chptr->chname, text);
                  } else {
                    mb = msgq_make(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                                   batchid, cli_name(sptr), cli_user(sptr)->username,
                                   get_displayed_host(sptr), chptr->chname, text);
                  }
                }
                if (mb) {
                  msgq_add(&sh->sh_sendQ, mb, 0);
                  socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                  msgq_clean(mb);
                }
              }

              mb = msgq_make(sptr, ":%s BATCH -%s", cli_name(&me), batchid);
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }
            } else {
              /* Shadow doesn't have multiline - send truncated fallback echo.
               * Use the same max_preview limit as regular fallback to avoid
               * flooding the shadow with many lines. */
              struct MsgBuf *mb;
              int total_lines = con_ml_msg_count(con);
              int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
              int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;
              int sent = 0;

              for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
                char *text = lp->value.cp + 1;
                if (*text == '\0')
                  continue;  /* Skip blank lines */
                mb = msgq_make(sptr, ":%s!%s@%s PRIVMSG %s :%s",
                               cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), chptr->chname, text);
                if (mb) {
                  msgq_add(&sh->sh_sendQ, mb, 0);
                  socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                  msgq_clean(mb);
                }
                sent++;
              }

              /* Send truncation notice with retrieval hints if needed */
              if (total_lines > max_preview) {
                int remaining = total_lines - sent;
                /* Check retrieval options for this shadow */
                int history_usable = IsAccount(sptr) && !IsNoStorage(sptr)
                                     && !(chptr->mode.exmode & EXMODE_NOSTORAGE);

                if (history_usable && CapHas(&sh->sh_active, CAP_DRAFT_CHATHISTORY)) {
                  /* Shadow has chathistory - provide CHATHISTORY hint */
                  if (remaining <= 15) {
                    mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - CHATHISTORY AROUND %s msgid=%s %d]",
                                   cli_name(&me), chptr->chname, remaining, chptr->chname,
                                   batch_base_msgid, remaining + sent);
                  } else {
                    mb = msgq_make(sptr, ":%s NOTICE %s :[Message continues (%d lines total) - CHATHISTORY AROUND %s msgid=%s %d]",
                                   cli_name(&me), chptr->chname, total_lines, chptr->chname,
                                   batch_base_msgid, total_lines);
                  }
                } else if (history_usable && FindClient("HistServ")) {
                  /* HistServ available */
                  if (remaining <= 15) {
                    mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - /msg HistServ FETCH %s %s]",
                                   cli_name(&me), chptr->chname, remaining, chptr->chname, batch_base_msgid);
                  } else {
                    mb = msgq_make(sptr, ":%s NOTICE %s :[Message continues (%d lines total) - /msg HistServ FETCH %s %s]",
                                   cli_name(&me), chptr->chname, total_lines, chptr->chname, batch_base_msgid);
                  }
                } else {
                  /* Fallback: paste URL (preferred) or &ml- storage */
                  const char *echo_paste_url = generate_paste_url(batch_base_msgid, cli_name(sptr),
                                                                  chptr->chname, con_ml_messages(con));
                  if (echo_paste_url) {
                    mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - %s]",
                                   cli_name(&me), chptr->chname, remaining, echo_paste_url);
                  } else {
                    /* Paste unavailable - use &ml- storage */
                    ml_storage_store(batch_base_msgid, cli_name(sptr), chptr->chname,
                                     con_ml_messages(con), total_lines);
                    if (remaining <= 15) {
                      mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - /join &ml-%s to view full message]",
                                     cli_name(&me), chptr->chname, remaining, batch_base_msgid);
                    } else {
                      mb = msgq_make(sptr, ":%s NOTICE %s :[Message continues (%d lines total) - /join &ml-%s to view]",
                                     cli_name(&me), chptr->chname, total_lines, batch_base_msgid);
                    }
                  }
                }
                if (mb) {
                  msgq_add(&sh->sh_sendQ, mb, 0);
                  socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                  msgq_clean(mb);
                }
              }
            }
          }
        }

        suppress_shadow_dup = 0;
      }
    }
  } else {
    /* Private message to user */
    struct BouncerSession *dmbsess = bounce_get_session(acptr);
    int dm_has_shadows = (dmbsess && dmbsess->hs_shadow_count > 0);

    /* Suppress automatic shadow duplication - handle shadows explicitly */
    suppress_shadow_dup = 1;

    /* Send to PRIMARY based on its OWN capabilities */
    if (CapOwnHas(acptr, CAP_DRAFT_MULTILINE) && CapOwnHas(acptr, CAP_BATCH)) {
      char batchid[16];
      char timebuf[32];
      int use_tags = CapOwnHas(acptr, CAP_MSGTAGS);

      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s draft/multiline %s",
                    batchid, cli_name(acptr));

      first = 1;
      for (lp = con_ml_messages(con); lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        /* All lines in the batch share the same msgid per IRCv3 multiline spec */
        if (use_tags) {
          format_time_tag(timebuf, sizeof(timebuf));
        }

        if (first && !concat) {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
                          batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
        } else {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
      /* Fallback for DM: send as individual messages to primary
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
        /* Graceful fallback: chathistory -> HistServ -> &ml- storage */
        send_multiline_fallback(sptr, acptr, cli_name(acptr), batch_base_msgid,
                                 con_ml_messages(con), total_lines, 0, NULL);
      }
    }

    /* Send to each SHADOW of the recipient based on its capabilities */
    if (dm_has_shadows) {
      struct ShadowConnection *sh;
      for (sh = dmbsess->hs_shadows; sh; sh = sh->sh_next) {
        if (sh->sh_flags & SHADOW_FLAGS_DEAD)
          continue;

        if (CapHas(&sh->sh_active, CAP_DRAFT_MULTILINE) && CapHas(&sh->sh_active, CAP_BATCH)) {
          /* Shadow has multiline - send batch */
          char batchid[16];
          char timebuf[32];
          int use_tags = CapHas(&sh->sh_active, CAP_MSGTAGS);
          struct MsgBuf *mb;

          ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                        NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

          mb = msgq_make(acptr, ":%s BATCH +%s draft/multiline %s",
                         cli_name(&me), batchid, cli_name(acptr));
          if (mb) {
            msgq_add(&sh->sh_sendQ, mb, 0);
            socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
            msgq_clean(mb);
          }

          first = 1;
          for (lp = con_ml_messages(con); lp; lp = lp->next) {
            int concat = lp->value.cp[0];
            char *text = lp->value.cp + 1;

            if (use_tags) {
              format_time_tag(timebuf, sizeof(timebuf));
            }

            if (first && !concat) {
              if (use_tags) {
                mb = msgq_make(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                               batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), cli_name(acptr), text);
              } else {
                mb = msgq_make(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                               batchid, cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), cli_name(acptr), text);
              }
              first = 0;
            } else if (concat) {
              if (use_tags) {
                mb = msgq_make(acptr, "@batch=%s;time=%s;msgid=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                               batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), cli_name(acptr), text);
              } else {
                mb = msgq_make(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                               batchid, cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), cli_name(acptr), text);
              }
            } else {
              if (use_tags) {
                mb = msgq_make(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                               batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), cli_name(acptr), text);
              } else {
                mb = msgq_make(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                               batchid, cli_name(sptr), cli_user(sptr)->username,
                               get_displayed_host(sptr), cli_name(acptr), text);
              }
            }
            if (mb) {
              msgq_add(&sh->sh_sendQ, mb, 0);
              socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
              msgq_clean(mb);
            }
          }

          mb = msgq_make(acptr, ":%s BATCH -%s", cli_name(&me), batchid);
          if (mb) {
            msgq_add(&sh->sh_sendQ, mb, 0);
            socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
            msgq_clean(mb);
          }
        } else {
          /* Shadow doesn't have multiline - send fallback */
          int total_lines = con_ml_msg_count(con);
          int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
          int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;
          int sent = 0;
          struct MsgBuf *mb;

          for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
            char *text = lp->value.cp + 1;
            if (*text == '\0')
              continue;  /* Skip blank lines */
            mb = msgq_make(acptr, ":%s!%s@%s PRIVMSG %s :%s",
                           cli_name(sptr), cli_user(sptr)->username,
                           get_displayed_host(sptr), cli_name(acptr), text);
            if (mb) {
              msgq_add(&sh->sh_sendQ, mb, 0);
              socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
              msgq_clean(mb);
            }
            sent++;
          }

          /* Send truncation notice if needed */
          if (total_lines > max_preview) {
            int remaining = total_lines - sent;
            const char *sh_paste_url = generate_paste_url(batch_base_msgid, cli_name(sptr),
                                                          cli_name(acptr), con_ml_messages(con));

            if (sh_paste_url) {
              mb = msgq_make(acptr, ":%s NOTICE %s :[%d more lines - %s]",
                             cli_name(&me), cli_name(acptr), remaining, sh_paste_url);
            } else {
              mb = msgq_make(acptr, ":%s NOTICE %s :[%d more lines - use a multiline-capable client to view]",
                             cli_name(&me), cli_name(acptr), remaining);
            }
            if (mb) {
              msgq_add(&sh->sh_sendQ, mb, 0);
              socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
              msgq_clean(mb);
            }
          }
        }
      }
    }

    suppress_shadow_dup = 0;

    /* Echo to sender and bouncer shadows with per-connection capability awareness.
     * Same logic as channel echo above. */
    {
      int need_echo = feature_bool(FEAT_CAP_echo_message) && CapActive(sptr, CAP_ECHOMSG);
      struct BouncerSession *bsess = bounce_get_session(sptr);
      int has_shadows = bsess && bsess->hs_shadow_count > 0;
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

      if (!skip_dm_echo && (need_echo || has_shadows)) {
        suppress_shadow_dup = 1;

        /* Send to primary if it has echo-message */
        if (need_echo) {
          for (lp = con_ml_messages(con); lp; lp = lp->next) {
            char *text = lp->value.cp + 1;
            sendcmdto_one(sptr, CMD_PRIVATE, sptr, "%C :%s", acptr, text);
          }
        }

        /* Send to each shadow based on its capabilities.
         * Shadows ALWAYS receive the message regardless of echo-message cap -
         * they're mirrors of the session and need to see what was sent. */
        if (has_shadows) {
          struct ShadowConnection *sh;
          for (sh = bsess->hs_shadows; sh; sh = sh->sh_next) {
            struct MsgBuf *mb;

            if (sh->sh_flags & SHADOW_FLAGS_DEAD)
              continue;

            /* For DM echo, send truncated fallback to avoid flooding */
            int total_lines = con_ml_msg_count(con);
            int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
            int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;
            int sent = 0;

            for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
              char *text = lp->value.cp + 1;
              if (*text == '\0')
                continue;  /* Skip blank lines */
              mb = msgq_make(sptr, ":%s!%s@%s PRIVMSG %s :%s",
                             cli_name(sptr), cli_user(sptr)->username,
                             get_displayed_host(sptr), cli_name(acptr), text);
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }
              sent++;
            }

            /* Send truncation notice with retrieval hints if needed */
            if (total_lines > max_preview) {
              int remaining = total_lines - sent;
              /* For PM echo to sender's shadow, check if PM history is available */
              int history_usable = IsAccount(sptr);

              if (history_usable && CapHas(&sh->sh_active, CAP_DRAFT_CHATHISTORY)) {
                mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - CHATHISTORY AROUND %s msgid=%s %d]",
                               cli_name(&me), cli_name(acptr), remaining, cli_name(acptr),
                               batch_base_msgid, remaining + sent);
              } else if (history_usable && FindClient("HistServ")) {
                mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - /msg HistServ FETCH %s %s]",
                               cli_name(&me), cli_name(acptr), remaining, cli_name(acptr), batch_base_msgid);
              } else {
                /* Fallback: paste URL (preferred) or &ml- storage */
                const char *dm_echo_paste_url = generate_paste_url(batch_base_msgid, cli_name(sptr),
                                                                   cli_name(acptr), con_ml_messages(con));
                if (dm_echo_paste_url) {
                  mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - %s]",
                                 cli_name(&me), cli_name(acptr), remaining, dm_echo_paste_url);
                } else {
                  ml_storage_store(batch_base_msgid, cli_name(sptr), cli_name(acptr),
                                   con_ml_messages(con), total_lines);
                  mb = msgq_make(sptr, ":%s NOTICE %s :[%d more lines - /join &ml-%s to view full message]",
                                 cli_name(&me), cli_name(acptr), remaining, batch_base_msgid);
                }
              }
              if (mb) {
                msgq_add(&sh->sh_sendQ, mb, 0);
                socket_events(&sh->sh_socket, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
                msgq_clean(mb);
              }
            }
          }
        }

        suppress_shadow_dup = 0;
      }
    }

    /* Capability-aware S2S relay for private messages to remote users */
    if (!MyConnect(acptr)) {
      struct Client *target_server = cli_from(acptr);
      char s2s_batch_id[16];
      ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                    cli_yxx(sptr), (unsigned long)CurrentTime);

      if (IsServer(target_server) && IsMultiline(target_server)) {
        /* Send ML tokens to capable server */
        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (first) {
            sendcmdto_one(sptr, CMD_MULTILINE, target_server, "+%s %s :%s",
                          s2s_batch_id, cli_name(acptr), text);
            first = 0;
          } else if (concat) {
            sendcmdto_one(sptr, CMD_MULTILINE, target_server, "c%s %s :%s",
                          s2s_batch_id, cli_name(acptr), text);
          } else {
            sendcmdto_one(sptr, CMD_MULTILINE, target_server, "%s %s :%s",
                          s2s_batch_id, cli_name(acptr), text);
          }
        }
        sendcmdto_one(sptr, CMD_MULTILINE, target_server, "-%s %s :",
                      s2s_batch_id, cli_name(acptr));
      } else {
        /* Send fallback PRIVMSGs to legacy server */
        int sent = 0;
        int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
        int total_lines = con_ml_msg_count(con);
        int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;

        for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
          char *text = lp->value.cp + 1;
          if (*text == '\0')
            continue;
          sendcmdto_one(sptr, CMD_PRIVATE, target_server, "%C :%s", acptr, text);
          sent++;
        }

        /* Send truncation notice from user (consistent with preview PRIVMSGs) */
        if (total_lines > max_preview) {
          int remaining = total_lines - sent;
          const char *relay_paste_url = generate_paste_url(batch_base_msgid, cli_name(sptr),
                                                           cli_name(acptr), con_ml_messages(con));

          if (relay_paste_url) {
            sendcmdto_one(sptr, CMD_NOTICE, target_server,
                "%C :[%d more lines - %s]",
                acptr, remaining, relay_paste_url);
          } else {
            sendcmdto_one(sptr, CMD_NOTICE, target_server,
                "%C :[%d more lines - connect to a multiline-capable server to view]",
                acptr, remaining);
          }
        }
      }
    }
  }

  /* Capability-aware S2S relay for channel messages.
   * Send ML tokens to servers that support multiline, fallback PRIVMSGs to legacy.
   * This fixes N² duplication bug: previously we sent fallback per remote user,
   * now we send once per server with appropriate format.
   */
  if (is_channel && chptr) {
    static unsigned long s2s_relay_marker = 0;
    char s2s_batch_id[16];
    int max_preview = feature_int(FEAT_MULTILINE_LEGACY_MAX_LINES);
    int total_lines = con_ml_msg_count(con);

    ircd_snprintf(0, s2s_batch_id, sizeof(s2s_batch_id), "%s%lu",
                  cli_yxx(sptr), (unsigned long)CurrentTime);

    /* Increment marker for this send cycle */
    s2s_relay_marker++;

    /* Iterate channel members to find servers that need the message */
    for (member = chptr->members; member; member = member->next_member) {
      struct Client *server;

      if (MyConnect(member->user))
        continue;  /* Local users already handled above */

      server = cli_from(member->user);
      if (!IsServer(server) || cli_sentalong(server) == s2s_relay_marker)
        continue;  /* Already sent to this server */

      cli_sentalong(server) = s2s_relay_marker;

      if (IsMultiline(server)) {
        /* Send ML tokens to capable servers */
        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (first) {
            sendcmdto_one(sptr, CMD_MULTILINE, server, "+%s %s :%s",
                          s2s_batch_id, chptr->chname, text);
            first = 0;
          } else if (concat) {
            sendcmdto_one(sptr, CMD_MULTILINE, server, "c%s %s :%s",
                          s2s_batch_id, chptr->chname, text);
          } else {
            sendcmdto_one(sptr, CMD_MULTILINE, server, "%s %s :%s",
                          s2s_batch_id, chptr->chname, text);
          }
        }
        sendcmdto_one(sptr, CMD_MULTILINE, server, "-%s %s :",
                      s2s_batch_id, chptr->chname);
      } else {
        /* Send fallback PRIVMSGs to legacy servers (once per server, not per user) */
        int sent = 0;
        int lines_to_send = (total_lines <= max_preview) ? total_lines : max_preview;

        for (lp = con_ml_messages(con); lp && sent < lines_to_send; lp = lp->next) {
          char *text = lp->value.cp + 1;
          if (*text == '\0')
            continue;
          sendcmdto_one(sptr, CMD_PRIVATE, server, "%H :%s", chptr, text);
          sent++;
        }

        /* Send truncation notice if needed.
         * Use sptr (user) as source to be consistent with preview PRIVMSGs.
         * This also ensures legacy servers properly relay it to channel members,
         * as some may not handle server-originated channel messages correctly.
         */
        if (total_lines > max_preview) {
          int remaining = total_lines - sent;
          const char *relay_paste_url = generate_paste_url(batch_base_msgid, cli_name(sptr),
                                                           chptr->chname, con_ml_messages(con));

          if (relay_paste_url) {
            sendcmdto_one(sptr, CMD_NOTICE, server,
                "%H :[%d more lines - %s]",
                chptr, remaining, relay_paste_url);
          } else {
            sendcmdto_one(sptr, CMD_NOTICE, server,
                "%H :[%d more lines - connect to a multiline-capable server to view]",
                chptr, remaining);
          }
        }
      }
    }
  }

  /* Notify sender about fallback if they support standard-replies */
  if (fallback_count > 0 && feature_bool(FEAT_MULTILINE_FALLBACK_NOTIFY)
      && CapActive(sptr, CAP_STANDARDREPLIES)) {
    char desc[128];
    ircd_snprintf(0, desc, sizeof(desc), "Message truncated for %d legacy recipient%s",
                  fallback_count, fallback_count == 1 ? "" : "s");
    /* Use saved label from BATCH +id for labeled-response correlation */
    send_warn_with_label(sptr, "BATCH", "MULTILINE_FALLBACK",
                         is_channel ? chptr->chname : cli_name(acptr), desc,
                         con_ml_label(con)[0] ? con_ml_label(con) : NULL);
  }

  /* Store multiline batch to history with the base msgid.
   * Concatenate all lines (respecting concat flags) into a single message.
   * This allows CHATHISTORY retrieval by the base msgid.
   */
  log_write(LS_SYSTEM, L_INFO, 0, "multiline: history_is_available=%d, target=%s, msgid=%s",
            history_is_available(), is_channel ? chptr->chname : cli_name(acptr),
            batch_base_msgid);
  if (history_is_available()) {
    char history_content[4096];  /* Reasonable max for multiline concatenated */
    size_t content_len = 0;
    char sender_mask[256];
    char timestamp[HISTORY_TIMESTAMP_LEN];

    /* Build sender mask nick!user@host */
    ircd_snprintf(0, sender_mask, sizeof(sender_mask), "%s!%s@%s",
                  cli_name(sptr), cli_user(sptr)->username,
                  get_displayed_host(sptr));

    /* Build concatenated content, respecting concat flags */
    for (lp = con_ml_messages(con); lp; lp = lp->next) {
      int concat = lp->value.cp[0];
      char *text = lp->value.cp + 1;
      size_t text_len = strlen(text);

      /* Add Unit Separator (\x1F) if not concat and not first line.
       * Using \x1F instead of \n avoids base64 encoding overhead in P10 federation
       * while still allowing multiline content to be stored and retrieved.
       * HistServ/chathistory converts \x1F back to newlines when displaying.
       */
      if (content_len > 0 && !concat) {
        if (content_len < sizeof(history_content) - 1) {
          history_content[content_len++] = '\x1F';
        }
      }

      /* Append text (truncate if exceeds buffer) */
      if (content_len + text_len < sizeof(history_content) - 1) {
        memcpy(history_content + content_len, text, text_len);
        content_len += text_len;
      } else if (content_len < sizeof(history_content) - 1) {
        /* Partial fit - copy what we can */
        size_t remaining = sizeof(history_content) - 1 - content_len;
        memcpy(history_content + content_len, text, remaining);
        content_len += remaining;
      }
    }
    history_content[content_len] = '\0';

    /* Get timestamp for storage */
    history_format_timestamp(timestamp, sizeof(timestamp));

    /* Check if channel has +P (no storage) mode or sender has +Y */
    if ((is_channel && (chptr->mode.exmode & EXMODE_NOSTORAGE)) || IsNoStorage(sptr)) {
      /* Skip storage but still clear batch */
    } else {
      /* Store with base msgid (no sub-IDs) for retrieval */
      int store_result = history_store_message(batch_base_msgid, timestamp,
                          is_channel ? chptr->chname : cli_name(acptr),
                          sender_mask,
                          cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                          HISTORY_PRIVMSG,
                          history_content);
      log_write(LS_SYSTEM, L_INFO, 0, "multiline: history_store_message returned %d for msgid=%s target=%s",
                store_result, batch_base_msgid, is_channel ? chptr->chname : cli_name(acptr));
    }
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

    /* Save the label from BATCH +id for labeled-response on WARN */
    if (cli_label(sptr)[0]) {
      ircd_strncpy(con_ml_label(con), cli_label(sptr),
                   sizeof(con->con_ml_label) - 1);
      con_ml_label(con)[sizeof(con->con_ml_label) - 1] = '\0';
    } else {
      con_ml_label(con)[0] = '\0';
    }
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
        int use_tags = CapActive(to, CAP_MSGTAGS);

        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        for (lp = batch->messages; lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          /* All lines in the batch share the same msgid per IRCv3 multiline spec */
          if (use_tags) {
            format_time_tag(timebuf, sizeof(timebuf));
          }

          if (first && !concat) {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
                            batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            } else {
              sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                            batchid, cli_name(sptr), cli_user(sptr)->username,
                            get_displayed_host(sptr), chptr->chname, text);
            }
          } else {
            if (use_tags) {
              sendrawto_one(to, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                            batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
        /* Graceful fallback for S2S channel delivery */
        send_multiline_fallback(sptr, to, chptr->chname, batch_base_msgid,
                                 batch->messages, batch->msg_count, 1, chptr);
      }
    }
  } else if (acptr && MyConnect(acptr)) {
    /* Private message to local user */
    if (CapActive(acptr, CAP_DRAFT_MULTILINE) && CapActive(acptr, CAP_BATCH)) {
      char batchid[16];
      char timebuf[32];
      int use_tags = CapActive(acptr, CAP_MSGTAGS);

      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s draft/multiline %s",
                    batchid, cli_name(acptr));

      first = 1;
      for (lp = batch->messages; lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        /* All lines in the batch share the same msgid per IRCv3 multiline spec */
        if (use_tags) {
          format_time_tag(timebuf, sizeof(timebuf));
        }

        if (first && !concat) {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
                          batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          } else {
            sendrawto_one(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), cli_name(acptr), text);
          }
        } else {
          if (use_tags) {
            sendrawto_one(acptr, "@batch=%s;time=%s;msgid=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, timebuf, batch_base_msgid, cli_name(sptr), cli_user(sptr)->username,
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
      /* Graceful fallback for S2S DM delivery */
      send_multiline_fallback(sptr, acptr, cli_name(acptr), batch_base_msgid,
                               batch->messages, batch->msg_count, 0, NULL);
    }
  }

  /* Store S2S multiline batch to history.
   * The originating server may have stored it, but we store locally
   * to ensure history is available for local clients.
   */
  if (history_is_available() && sptr) {
    char history_content[4096];
    size_t content_len = 0;
    char sender_mask[256];
    char timestamp[HISTORY_TIMESTAMP_LEN];

    /* Build sender mask nick!user@host */
    ircd_snprintf(0, sender_mask, sizeof(sender_mask), "%s!%s@%s",
                  cli_name(sptr), cli_user(sptr)->username,
                  get_displayed_host(sptr));

    /* Build concatenated content, respecting concat flags */
    for (lp = batch->messages; lp; lp = lp->next) {
      int concat = lp->value.cp[0];
      char *text = lp->value.cp + 1;
      size_t text_len = strlen(text);

      /* Add Unit Separator (\x1F) if not concat and not first line.
       * Using \x1F instead of \n avoids base64 encoding overhead in P10 federation
       * while still allowing multiline content to be stored and retrieved.
       * HistServ/chathistory converts \x1F back to newlines when displaying.
       */
      if (content_len > 0 && !concat) {
        if (content_len < sizeof(history_content) - 1) {
          history_content[content_len++] = '\x1F';
        }
      }

      /* Append text (truncate if exceeds buffer) */
      if (content_len + text_len < sizeof(history_content) - 1) {
        memcpy(history_content + content_len, text, text_len);
        content_len += text_len;
      } else if (content_len < sizeof(history_content) - 1) {
        size_t remaining = sizeof(history_content) - 1 - content_len;
        memcpy(history_content + content_len, text, remaining);
        content_len += remaining;
      }
    }
    history_content[content_len] = '\0';

    /* Get timestamp for storage */
    history_format_timestamp(timestamp, sizeof(timestamp));

    /* Check if channel has +P (no storage) mode or sender has +Y */
    if (!((is_channel && (chptr->mode.exmode & EXMODE_NOSTORAGE)) || IsNoStorage(sptr))) {
      /* Store with base msgid for retrieval */
      history_store_message(batch_base_msgid, timestamp,
                            is_channel ? chptr->chname : cli_name(acptr),
                            sender_mask,
                            cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL,
                            HISTORY_PRIVMSG,
                            history_content);
    }
  }
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

  /* Empty ML from server = capability advertisement during BURST */
  if (IsServer(sptr) && (parc < 2 || EmptyString(parv[1]))) {
    SetMultiline(sptr);
    /* Propagate to other servers */
    sendcmdto_serv_butone(sptr, CMD_MULTILINE, cptr, "");
    return 0;
  }

  /* Sender must be a user for actual multiline messages */
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
