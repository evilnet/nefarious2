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
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "send.h"
#include "s_misc.h"

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
