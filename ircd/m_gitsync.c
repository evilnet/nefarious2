/*
 * IRC - Internet Relay Chat, ircd/m_gitsync.c
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
 * @brief Handlers for GITSYNC command.
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

#ifdef USE_LIBGIT2
#include "gitsync.h"
#endif

#include <stdlib.h>
#include <string.h>

/** Handle GITSYNC command from an operator.
 * parv[0] = sender prefix
 * parv[1] = action (force|status) or target server
 * parv[2] = action if parv[1] is target
 *
 * Usage:
 *   /GITSYNC force        - Trigger immediate sync on local server
 *   /GITSYNC status       - Show sync status on local server
 *   /GITSYNC server force - Trigger sync on remote server
 *   /GITSYNC * force      - Trigger sync on all servers
 */
int mo_gitsync(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_LIBGIT2
  const char *action;
  const char *target = NULL;
  struct Client *acptr;
  int is_force = 0;
  int is_status = 0;
  int is_pubkey = 0;

  /* Check privilege */
  if (!HasPriv(sptr, PRIV_GITSYNC))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  /* Parse arguments */
  if (parc < 2) {
    /* No args - show usage */
    send_reply(sptr, SND_EXPLICIT | RPL_STATSCONN,
               ":Usage: /GITSYNC [server] <force|status|pubkey>");
    return 0;
  }

  /* Check if first arg is action or target */
  if (ircd_strcmp(parv[1], "force") == 0) {
    is_force = 1;
  } else if (ircd_strcmp(parv[1], "status") == 0) {
    is_status = 1;
  } else if (ircd_strcmp(parv[1], "pubkey") == 0) {
    is_pubkey = 1;
  } else {
    /* First arg is target server */
    target = parv[1];
    if (parc > 2) {
      if (ircd_strcmp(parv[2], "force") == 0)
        is_force = 1;
      else if (ircd_strcmp(parv[2], "status") == 0)
        is_status = 1;
      else if (ircd_strcmp(parv[2], "pubkey") == 0)
        is_pubkey = 1;
    }
    if (!is_force && !is_status && !is_pubkey) {
      send_reply(sptr, SND_EXPLICIT | RPL_STATSCONN,
                 ":Usage: /GITSYNC [server] <force|status|pubkey>");
      return 0;
    }
  }

  action = is_force ? "force" : (is_status ? "status" : "pubkey");

  /* Pubkey is local-only, don't forward */
  if (is_pubkey && target) {
    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :GITSYNC PUBKEY is local-only, cannot forward to server", sptr);
    return 0;
  }

  /* Handle remote target */
  if (target) {
    if (strcmp(target, "*") == 0) {
      /* Broadcast to all servers */
      sendcmdto_serv_butone(sptr, CMD_GITSYNC, cptr, "* %s", action);
      /* Also do local */
    } else {
      /* Find target server */
      acptr = find_match_server(target);
      if (!acptr) {
        return send_reply(sptr, ERR_NOSUCHSERVER, target);
      }
      if (!IsMe(acptr)) {
        /* Forward to remote server */
        sendcmdto_one(sptr, CMD_GITSYNC, acptr, "%C %s", acptr, action);
        return 0;
      }
      /* Target is us, fall through to local handling */
    }
  }

  /* Handle local action */
  if (is_force) {
    enum GitsyncStatus status;

    if (!feature_bool(FEAT_GITSYNC_ENABLE)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync is disabled", sptr);
      return 0;
    }

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Triggering GitSync...", sptr);
    status = gitsync_trigger(sptr, 1);

    if (status == GITSYNC_OK) {
      const struct GitsyncStats *stats = gitsync_get_stats();
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :GitSync completed successfully (commit %.8s)",
                    sptr, stats->last_commit);
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                    sptr, gitsync_status_str(status));
    }
  } else if (is_status) {
    const struct GitsyncStats *stats = gitsync_get_stats();
    char timebuf[64];

    if (feature_bool(FEAT_GITSYNC_ENABLE)) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync Status: Enabled", sptr);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Repository: %s",
                    sptr, feature_str(FEAT_GITSYNC_REPOSITORY));
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Branch: %s",
                    sptr, feature_str(FEAT_GITSYNC_BRANCH));
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Interval: %d seconds",
                    sptr, feature_int(FEAT_GITSYNC_INTERVAL));
    } else {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync Status: Disabled", sptr);
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

    if (stats->last_commit[0]) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last commit: %.8s",
                    sptr, stats->last_commit);
    }

    sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last status: %s",
                  sptr, gitsync_status_str(stats->last_status));

    if (stats->last_error[0]) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Last error: %s",
                    sptr, stats->last_error);
    }
  } else if (is_pubkey) {
    /* Show the public key for GitLab/GitHub setup */
    const char *ssh_key_path;
    char pubkey_path[512];
    char cmd[1024];
    FILE *fp;
    char line[1024];
    int from_file = 0;

    ssh_key_path = feature_str(FEAT_GITSYNC_SSH_KEY);
    if (!ssh_key_path || !*ssh_key_path) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :No SSH key configured (GITSYNC_SSH_KEY not set)", sptr);
      return 0;
    }

    /* Try to read existing .pub file first */
    ircd_snprintf(0, pubkey_path, sizeof(pubkey_path), "%s.pub", ssh_key_path);
    fp = fopen(pubkey_path, "r");
    if (fp) {
      from_file = 1;
    } else {
      /* Generate public key from private key using ssh-keygen */
      ircd_snprintf(0, cmd, sizeof(cmd), "ssh-keygen -y -f \"%s\" 2>/dev/null", ssh_key_path);
      fp = popen(cmd, "r");
      if (!fp) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Cannot read or generate public key from %s", sptr, ssh_key_path);
        return 0;
      }
    }

    sendcmdto_one(&me, CMD_NOTICE, sptr,
                  "%C :Public key for GitSync (add to GitLab/GitHub):", sptr);

    while (fgets(line, sizeof(line), fp)) {
      /* Remove trailing newline */
      size_t len = strlen(line);
      if (len > 0 && line[len-1] == '\n')
        line[len-1] = '\0';
      if (line[0])
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, line);
    }

    if (from_file)
      fclose(fp);
    else
      pclose(fp);
  }

  return 0;
#else
  return send_reply(sptr, ERR_DISABLED, "GITSYNC");
#endif
}

/** Handle GITSYNC command from a server.
 * parv[0] = sender prefix (oper numnick)
 * parv[1] = target server or "*"
 * parv[2] = action (force|status)
 */
int ms_gitsync(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_LIBGIT2
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
    sendcmdto_serv_butone(sptr, CMD_GITSYNC, cptr, "* %s", action);
  } else {
    acptr = FindNServer(target);
    if (!acptr)
      acptr = find_match_server(target);

    if (!acptr || !IsMe(acptr)) {
      /* Not for us, forward */
      if (acptr)
        sendcmdto_one(sptr, CMD_GITSYNC, acptr, "%C %s", acptr, action);
      return 0;
    }
    /* Fall through to handle locally */
  }

  /* Handle local action */
  if (ircd_strcmp(action, "force") == 0) {
    if (!feature_bool(FEAT_GITSYNC_ENABLE)) {
      if (IsOper(sptr))
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync is disabled on %s",
                      sptr, cli_name(&me));
      return 0;
    }

    gitsync_trigger(sptr, 1);

    if (IsOper(sptr)) {
      const struct GitsyncStats *stats = gitsync_get_stats();
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync on %s: %s (commit %.8s)",
                    sptr, cli_name(&me), gitsync_status_str(stats->last_status),
                    stats->last_commit);
    }
  } else if (ircd_strcmp(action, "status") == 0) {
    if (IsOper(sptr)) {
      const struct GitsyncStats *stats = gitsync_get_stats();
      char timebuf[64];

      if (feature_bool(FEAT_GITSYNC_ENABLE)) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :%s GitSync: Enabled, %lu syncs, %lu failures",
                      sptr, cli_name(&me), stats->syncs, stats->failures);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s GitSync: Disabled",
                      sptr, cli_name(&me));
      }

      if (stats->last_sync > 0) {
        struct tm *tm = localtime(&stats->last_sync);
        strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s Last sync: %s (%s, %.8s)",
                      sptr, cli_name(&me), timebuf,
                      gitsync_status_str(stats->last_status),
                      stats->last_commit);
      }
    }
  }

  return 0;
#else
  return 0;
#endif
}
