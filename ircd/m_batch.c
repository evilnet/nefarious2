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
#include "send.h"
#include "s_misc.h"
#include "s_user.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>

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

  if (!con_ml_batch_id(con)[0])
    return 0;  /* No active batch */

  if (!con_ml_messages(con)) {
    clear_multiline_batch(con);
    return 0;  /* Empty batch */
  }

  is_channel = IsChannelName(con_ml_target(con));

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
        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(cli_connect(to))++);

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (first && !concat) {
            sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), chptr->chname, text);
            first = 0;
          } else if (concat) {
            sendrawto_one(to, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), chptr->chname, text);
          } else {
            sendrawto_one(to, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), chptr->chname, text);
          }
        }

        sendcmdto_one(&me, CMD_BATCH_CMD, to, "-%s", batchid);
      } else {
        /* Fallback: send as individual messages */
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          char *text = lp->value.cp + 1;
          sendcmdto_one(sptr, CMD_PRIVATE, to, "%H :%s", chptr, text);
        }
      }
    }

    /* Echo to sender if echo-message enabled */
    if (CapActive(sptr, CAP_ECHOMSG)) {
      if (CapActive(sptr, CAP_DRAFT_MULTILINE) && CapActive(sptr, CAP_BATCH)) {
        char batchid[16];
        ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                      NumNick(sptr), con_batch_seq(con)++);

        sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "+%s draft/multiline %s",
                      batchid, chptr->chname);

        first = 1;
        for (lp = con_ml_messages(con); lp; lp = lp->next) {
          int concat = lp->value.cp[0];
          char *text = lp->value.cp + 1;

          if (first && !concat) {
            sendrawto_one(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), chptr->chname, text);
            first = 0;
          } else if (concat) {
            sendrawto_one(sptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), chptr->chname, text);
          } else {
            sendrawto_one(sptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                          batchid, cli_name(sptr), cli_user(sptr)->username,
                          get_displayed_host(sptr), chptr->chname, text);
          }
        }

        sendcmdto_one(&me, CMD_BATCH_CMD, sptr, "-%s", batchid);
      } else {
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
      ircd_snprintf(0, batchid, sizeof(batchid), "%s%u",
                    NumNick(sptr), con_batch_seq(cli_connect(acptr))++);

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "+%s draft/multiline %s",
                    batchid, cli_name(acptr));

      first = 1;
      for (lp = con_ml_messages(con); lp; lp = lp->next) {
        int concat = lp->value.cp[0];
        char *text = lp->value.cp + 1;

        if (first && !concat) {
          sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                        batchid, cli_name(sptr), cli_user(sptr)->username,
                        get_displayed_host(sptr), cli_name(acptr), text);
          first = 0;
        } else if (concat) {
          sendrawto_one(acptr, "@batch=%s;draft/multiline-concat :%s!%s@%s PRIVMSG %s :%s",
                        batchid, cli_name(sptr), cli_user(sptr)->username,
                        get_displayed_host(sptr), cli_name(acptr), text);
        } else {
          sendrawto_one(acptr, "@batch=%s :%s!%s@%s PRIVMSG %s :%s",
                        batchid, cli_name(sptr), cli_user(sptr)->username,
                        get_displayed_host(sptr), cli_name(acptr), text);
        }
      }

      sendcmdto_one(&me, CMD_BATCH_CMD, acptr, "-%s", batchid);
    } else {
      for (lp = con_ml_messages(con); lp; lp = lp->next) {
        char *text = lp->value.cp + 1;
        sendcmdto_one(sptr, CMD_PRIVATE, acptr, "%C :%s", acptr, text);
      }
    }

    /* Echo to sender */
    if (CapActive(sptr, CAP_ECHOMSG)) {
      for (lp = con_ml_messages(con); lp; lp = lp->next) {
        char *text = lp->value.cp + 1;
        sendcmdto_one(sptr, CMD_PRIVATE, sptr, "%C :%s", acptr, text);
      }
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
