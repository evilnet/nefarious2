/*
 * IRC - Internet Relay Chat, ircd/m_linesync.c
 * Copyright (C) 2025 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Handlers for LINESYNC command.
 */
#include "config.h"

#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "s_user.h"
#include "send.h"

#ifdef USE_CURL
#include "linesync.h"
#endif

#include <stdlib.h>
#include <string.h>

/** Handle LINESYNC command from an operator.
 * parv[0] = sender prefix
 * parv[1] = action (force|status) or target server
 * parv[2] = action if parv[1] is target
 *
 * Usage:
 *   /LINESYNC force        - Trigger immediate sync on local server
 *   /LINESYNC status       - Show sync status on local server
 *   /LINESYNC server force - Trigger sync on remote server
 *   /LINESYNC * force      - Trigger sync on all servers
 */
int mo_linesync(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_CURL
  const char *action;
  const char *target = NULL;
  struct Client *acptr;
  int is_force = 0;
  int is_status = 0;

  /* Check privilege */
  if (!HasPriv(sptr, PRIV_LINESYNC))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  /* Parse arguments */
  if (parc < 2) {
    /* No args - show usage */
    send_reply(sptr, SND_EXPLICIT | RPL_STATSCONN,
               ":Usage: /LINESYNC [server] <force|status>");
    return 0;
  }

  /* Check if first arg is action or target */
  if (ircd_strcmp(parv[1], "force") == 0) {
    is_force = 1;
  } else if (ircd_strcmp(parv[1], "status") == 0) {
    is_status = 1;
  } else {
    /* First arg is target server */
    target = parv[1];
    if (parc > 2) {
      if (ircd_strcmp(parv[2], "force") == 0)
        is_force = 1;
      else if (ircd_strcmp(parv[2], "status") == 0)
        is_status = 1;
    }
    if (!is_force && !is_status) {
      send_reply(sptr, SND_EXPLICIT | RPL_STATSCONN,
                 ":Usage: /LINESYNC [server] <force|status>");
      return 0;
    }
  }

  action = is_force ? "force" : "status";

  /* Handle remote target */
  if (target) {
    if (strcmp(target, "*") == 0) {
      /* Broadcast to all servers */
      sendcmdto_serv_butone(sptr, CMD_LINESYNC, cptr, "* %s", action);
      /* Also do local */
    } else {
      /* Find target server */
      acptr = find_match_server(target);
      if (!acptr) {
        return send_reply(sptr, ERR_NOSUCHSERVER, target);
      }
      if (!IsMe(acptr)) {
        /* Forward to remote server */
        sendcmdto_one(sptr, CMD_LINESYNC, acptr, "%C %s", acptr, action);
        return 0;
      }
      /* Target is us, fall through to local handling */
    }
  }

  /* Handle local action */
  if (is_force) {
    enum LinesyncStatus status;

    if (!feature_bool(FEAT_LINESYNC_ENABLE)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync is disabled", sptr);
      return 0;
    }

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Triggering linesync...", sptr);
    status = linesync_trigger(sptr, 1);

    if (status == LINESYNC_OK) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync completed successfully", sptr);
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync failed: %s",
                    sptr, linesync_status_str(status));
    }
  } else if (is_status) {
    const struct LinesyncStats *stats = linesync_get_stats();
    char timebuf[64];

    if (feature_bool(FEAT_LINESYNC_ENABLE)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync Status: Enabled", sptr);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  URL: %s",
                    sptr, feature_str(FEAT_LINESYNC_URL));
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Interval: %d seconds",
                    sptr, feature_int(FEAT_LINESYNC_INTERVAL));
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync Status: Disabled", sptr);
    }

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Successful syncs: %lu",
                  sptr, stats->syncs);
    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Failed syncs: %lu",
                  sptr, stats->failures);

    if (stats->last_sync > 0) {
      struct tm *tm = localtime(&stats->last_sync);
      strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last sync: %s", sptr, timebuf);
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last sync: Never", sptr);
    }

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last status: %s",
                  sptr, linesync_status_str(stats->last_status));

    if (stats->last_error[0]) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last error: %s",
                    sptr, stats->last_error);
    }
  }

  return 0;
#else
  return send_reply(sptr, ERR_DISABLED, "LINESYNC");
#endif
}

/** Handle LINESYNC command from a server.
 * parv[0] = sender prefix (oper numnick)
 * parv[1] = target server or "*"
 * parv[2] = action (force|status)
 */
int ms_linesync(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_CURL
  const char *target;
  const char *action;
  struct Client *acptr;

  if (parc < 3)
    return 0;

  target = parv[1];
  action = parv[2];

  /* Check if this is for us */
  if (strcmp(target, "*") == 0) {
    /* Broadcast - forward to other servers and handle locally */
    sendcmdto_serv_butone(sptr, CMD_LINESYNC, cptr, "* %s", action);
  } else {
    acptr = FindNServer(target);
    if (!acptr)
      acptr = find_match_server(target);

    if (!acptr || !IsMe(acptr)) {
      /* Not for us, forward */
      if (acptr)
        sendcmdto_one(sptr, CMD_LINESYNC, acptr, "%C %s", acptr, action);
      return 0;
    }
    /* Fall through to handle locally */
  }

  /* Handle local action */
  if (ircd_strcmp(action, "force") == 0) {
    if (!feature_bool(FEAT_LINESYNC_ENABLE)) {
      if (IsOper(sptr))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync is disabled on %s",
                      sptr, cli_name(&me));
      return 0;
    }

    linesync_trigger(sptr, 1);

    if (IsOper(sptr)) {
      const struct LinesyncStats *stats = linesync_get_stats();
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Linesync on %s: %s",
                    sptr, cli_name(&me), linesync_status_str(stats->last_status));
    }
  } else if (ircd_strcmp(action, "status") == 0) {
    if (IsOper(sptr)) {
      const struct LinesyncStats *stats = linesync_get_stats();
      char timebuf[64];

      if (feature_bool(FEAT_LINESYNC_ENABLE)) {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s Linesync: Enabled, %lu syncs, %lu failures",
                      sptr, cli_name(&me), stats->syncs, stats->failures);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s Linesync: Disabled",
                      sptr, cli_name(&me));
      }

      if (stats->last_sync > 0) {
        struct tm *tm = localtime(&stats->last_sync);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s Last sync: %s (%s)",
                      sptr, cli_name(&me), timebuf,
                      linesync_status_str(stats->last_status));
      }
    }
  }

  return 0;
#else
  return 0;
#endif
}
