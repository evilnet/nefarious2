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
#include <unistd.h>

/** Handle GITSYNC command from an operator.
 * parv[0] = sender prefix
 * parv[1] = action (force|status|pubkey|hostkey) or target server
 * parv[2] = action if parv[1] is target, or "pem"/"reset" for pubkey/hostkey
 * parv[3] = "pem"/"reset" if parv[2] is pubkey/hostkey
 *
 * All subcommands are remotable (can target specific servers or broadcast).
 *
 * Usage:
 *   /GITSYNC force           - Trigger immediate sync
 *   /GITSYNC status          - Show sync status
 *   /GITSYNC pubkey          - Show SSH public key (from GITSYNC_SSH_KEY)
 *   /GITSYNC pubkey pem      - Extract SSH public key from SSL certificate
 *   /GITSYNC hostkey         - Show SSH host key fingerprint (TOFU)
 *   /GITSYNC hostkey reset   - Clear stored fingerprint for re-verification
 *   /GITSYNC server <cmd>    - Run command on specific server
 *   /GITSYNC * <cmd>         - Run command on all servers
 *
 * Examples:
 *   /GITSYNC * force         - Sync all servers
 *   /GITSYNC * pubkey        - Show public keys from all servers
 *   /GITSYNC server.name hostkey reset - Reset fingerprint on specific server
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
  int is_hostkey = 0;

  /* Check privilege */
  if (!HasPriv(sptr, PRIV_GITSYNC))
    return send_reply(sptr, ERR_NOPRIVILEGES);

  /* Parse arguments */
  if (parc < 2) {
    /* No args - show usage */
    send_reply(sptr, SND_EXPLICIT | RPL_STATSCONN,
               ":Usage: /GITSYNC [server] <force|status|pubkey [pem]|hostkey [reset]>");
    return 0;
  }

  /* Check if first arg is action or target */
  if (ircd_strcmp(parv[1], "force") == 0) {
    is_force = 1;
  } else if (ircd_strcmp(parv[1], "status") == 0) {
    is_status = 1;
  } else if (ircd_strcmp(parv[1], "pubkey") == 0) {
    is_pubkey = 1;
  } else if (ircd_strcmp(parv[1], "hostkey") == 0) {
    is_hostkey = 1;
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
      else if (ircd_strcmp(parv[2], "hostkey") == 0)
        is_hostkey = 1;
    }
    if (!is_force && !is_status && !is_pubkey && !is_hostkey) {
      send_reply(sptr, SND_EXPLICIT | RPL_STATSCONN,
                 ":Usage: /GITSYNC [server] <force|status|pubkey [pem]|hostkey [reset]>");
      return 0;
    }
  }

  action = is_force ? "force" : (is_status ? "status" : (is_pubkey ? "pubkey" : "hostkey"));

  /* Handle remote target */
  if (target) {
    const char *subarg = NULL;

    /* Determine sub-argument for pubkey/hostkey */
    if (is_pubkey && parc > 3 && ircd_strcmp(parv[3], "pem") == 0) {
      subarg = "pem";
    } else if (is_hostkey && parc > 3 && ircd_strcmp(parv[3], "reset") == 0) {
      subarg = "reset";
    }

    if (strcmp(target, "*") == 0) {
      /* Broadcast to all servers */
      if (subarg)
        sendcmdto_serv_butone(sptr, CMD_GITSYNC, cptr, "* %s %s", action, subarg);
      else
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
        if (subarg)
          sendcmdto_one(sptr, CMD_GITSYNC, acptr, "%C %s %s", acptr, action, subarg);
        else
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
    /* gitsync_trigger sends its own success/failure messages */
    gitsync_trigger(sptr, 1);
  } else if (is_status) {
    const struct GitsyncStats *stats = gitsync_get_stats();
    char timebuf[64];

    if (feature_bool(FEAT_GITSYNC_ENABLE)) {
      const char *fingerprint;
      char fphost[256];

      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync Status: Enabled", sptr);
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Repository: %s",
                    sptr, feature_str(FEAT_GITSYNC_REPOSITORY));
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Branch: %s",
                    sptr, feature_str(FEAT_GITSYNC_BRANCH));
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Interval: %d seconds",
                    sptr, feature_int(FEAT_GITSYNC_INTERVAL));

      /* Show host key fingerprint status */
      fingerprint = gitsync_get_host_fingerprint(fphost, sizeof(fphost));
      if (fingerprint) {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Host key: %s (%s)",
                      sptr, fingerprint, fphost);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :  Host key: (not established)",
                      sptr);
      }
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
    /* Show the public key for GitLab/GitHub setup
     * Usage:
     *   /GITSYNC pubkey     - Use configured SSH key (GITSYNC_SSH_KEY)
     *   /GITSYNC pubkey pem - Extract from PEM certificate (SSL_CERTFILE)
     */
    const char *ssh_key_path;
    const char *pem_path;
    char pubkey_path[512];
    char cmd[1024];
    char tmpfile[256];
    FILE *fp;
    char line[1024];
    int from_file = 0;
    int from_pem = 0;

    /* Check if user requested PEM mode */
    if (parc > 2 && ircd_strcmp(parv[2], "pem") == 0) {
      from_pem = 1;
    } else if (target && parc > 2 && ircd_strcmp(parv[2], "pubkey") == 0 &&
               parc > 3 && ircd_strcmp(parv[3], "pem") == 0) {
      from_pem = 1;
    }

    if (from_pem) {
      /* PEM mode: Extract SSH key from SSL certificate
       * This matches gitsync.sh -p option behavior:
       * 1. Extract private key from PEM
       * 2. Extract public key using openssl
       * 3. Convert to SSH format using ssh-keygen
       */
      int tmpfd;

      pem_path = feature_str(FEAT_SSL_CERTFILE);
      if (!pem_path || !*pem_path) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :No SSL certificate configured (SSL_CERTFILE not set)", sptr);
        return 0;
      }

      /* Create secure temp file using mkstemp */
      ircd_strncpy(tmpfile, "/tmp/gitsync_pem.XXXXXX", sizeof(tmpfile) - 1);
      tmpfd = mkstemp(tmpfile);
      if (tmpfd < 0) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Cannot create temp file", sptr);
        return 0;
      }
      close(tmpfd);  /* We just need the filename, shell will use it */

      /* Extract private key and public key from PEM, then convert to SSH format
       * This replicates gitsync.sh -p logic:
       * awk '/BEGIN .*PRIVATE KEY/,/END .*PRIVATE KEY/' "$kpath" > "$ipath"
       * openssl x509 -in "$kpath" -pubkey -noout >> "$ipath"
       * ssh-keygen -i -m PKCS8 -f "$tmp_path/ssh.pem"
       */
      ircd_snprintf(0, cmd, sizeof(cmd),
        "( "
        "awk '/BEGIN .*PRIVATE KEY/,/END .*PRIVATE KEY/' \"%s\" > \"%s\" && "
        "openssl x509 -in \"%s\" -pubkey -noout >> \"%s\" && "
        "ssh-keygen -i -m PKCS8 -f \"%s\" 2>/dev/null"
        ") ; rm -f \"%s\"",
        pem_path, tmpfile, pem_path, tmpfile, tmpfile, tmpfile);

      fp = popen(cmd, "r");
      if (!fp) {
        unlink(tmpfile);  /* Clean up on error */
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Cannot extract public key from PEM %s", sptr, pem_path);
        return 0;
      }

      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Public key extracted from PEM (add to GitLab/GitHub):", sptr);
    } else {
      /* Standard SSH key mode */
      ssh_key_path = feature_str(FEAT_GITSYNC_SSH_KEY);
      if (!ssh_key_path || !*ssh_key_path) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :No SSH key configured (GITSYNC_SSH_KEY not set)", sptr);
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Tip: Use '/GITSYNC pubkey pem' to extract from SSL certificate", sptr);
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
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :Tip: Use '/GITSYNC pubkey pem' to extract from SSL certificate", sptr);
          return 0;
        }
      }

      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Public key for GitSync (add to GitLab/GitHub):", sptr);
    }

    while (fgets(line, sizeof(line), fp)) {
      /* Remove trailing newline */
      size_t len = strlen(line);
      char *p;
      if (len > 0 && line[len-1] == '\n')
        line[len-1] = '\0';
      len = strlen(line);
      /* Split long lines to fit IRC message limits (~400 bytes content) */
      p = line;
      while (len > 0) {
        size_t chunk = (len > 400) ? 400 : len;
        char save = p[chunk];
        p[chunk] = '\0';
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s", sptr, p);
        p[chunk] = save;
        p += chunk;
        len -= chunk;
      }
    }

    if (from_file)
      fclose(fp);
    else
      pclose(fp);
  } else if (is_hostkey) {
    /* Show or reset SSH host key fingerprint */
    const char *fingerprint;
    char host[256];
    int do_reset = 0;

    /* Check for reset subcommand */
    if (parc > 2 && ircd_strcmp(parv[2], "reset") == 0) {
      do_reset = 1;
    }

    if (do_reset) {
      /* Clear the TOFU fingerprint */
      gitsync_clear_host_fingerprint();
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :GitSync host fingerprint cleared - next sync will TOFU", sptr);
    } else {
      /* Show current fingerprint */
      fingerprint = gitsync_get_host_fingerprint(host, sizeof(host));
      if (fingerprint) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :GitSync SSH Host Key:", sptr);
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :  Host: %s", sptr, host);
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :  Fingerprint: %s", sptr, fingerprint);
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Use '/GITSYNC hostkey reset' to clear and re-establish", sptr);
      } else {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :GitSync: No host fingerprint established yet", sptr);
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :  First sync will use TOFU (Trust On First Use)", sptr);
      }
    }
  }

  return 0;
#else
  return send_reply(sptr, ERR_DISABLED, "GITSYNC");
#endif
}

/** Handle GITSYNC command from a server.
 * parv[0] = sender prefix (oper numnick)
 * parv[1] = target server or "*"
 * parv[2] = action (force|status|pubkey|hostkey)
 * parv[3] = optional sub-argument (pem|reset)
 */
int ms_gitsync(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
#ifdef USE_LIBGIT2
  const char *target;
  const char *action;
  const char *subarg = NULL;
  struct Client *acptr;

  if (parc < 3)
    return 0;

  target = parv[1];
  action = parv[2];
  if (parc > 3)
    subarg = parv[3];

  /* Check if this is for us */
  if (strcmp(target, "*") == 0) {
    /* Broadcast - forward to other servers and handle locally */
    if (subarg)
      sendcmdto_serv_butone(sptr, CMD_GITSYNC, cptr, "* %s %s", action, subarg);
    else
      sendcmdto_serv_butone(sptr, CMD_GITSYNC, cptr, "* %s", action);
  } else {
    acptr = FindNServer(target);
    if (!acptr)
      acptr = find_match_server(target);

    if (!acptr || !IsMe(acptr)) {
      /* Not for us, forward */
      if (acptr) {
        if (subarg)
          sendcmdto_one(sptr, CMD_GITSYNC, acptr, "%C %s %s", acptr, action, subarg);
        else
          sendcmdto_one(sptr, CMD_GITSYNC, acptr, "%C %s", acptr, action);
      }
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
  } else if (ircd_strcmp(action, "hostkey") == 0) {
    if (IsOper(sptr)) {
      if (subarg && ircd_strcmp(subarg, "reset") == 0) {
        /* Reset the TOFU fingerprint */
        gitsync_clear_host_fingerprint();
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :%s GitSync: Host fingerprint cleared",
                      sptr, cli_name(&me));
      } else {
        /* Show current fingerprint */
        const char *fingerprint;
        char host[256];

        fingerprint = gitsync_get_host_fingerprint(host, sizeof(host));
        if (fingerprint) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync Host Key: %s (%s)",
                        sptr, cli_name(&me), fingerprint, host);
        } else {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: No host fingerprint established",
                        sptr, cli_name(&me));
        }
      }
    }
  } else if (ircd_strcmp(action, "pubkey") == 0) {
    if (IsOper(sptr)) {
      const char *ssh_key_path;
      const char *pem_path;
      char pubkey_path[512];
      char cmd[1024];
      char tmpfile[256];
      FILE *fp;
      char line[1024];
      int from_file = 0;
      int from_pem = (subarg && ircd_strcmp(subarg, "pem") == 0);

      if (from_pem) {
        /* PEM mode: Extract SSH key from SSL certificate */
        int tmpfd;

        pem_path = feature_str(FEAT_SSL_CERTFILE);
        if (!pem_path || !*pem_path) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: No SSL certificate configured",
                        sptr, cli_name(&me));
          return 0;
        }

        /* Create secure temp file using mkstemp */
        ircd_strncpy(tmpfile, "/tmp/gitsync_pem.XXXXXX", sizeof(tmpfile) - 1);
        tmpfd = mkstemp(tmpfile);
        if (tmpfd < 0) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: Cannot create temp file",
                        sptr, cli_name(&me));
          return 0;
        }
        close(tmpfd);

        ircd_snprintf(0, cmd, sizeof(cmd),
          "( "
          "awk '/BEGIN .*PRIVATE KEY/,/END .*PRIVATE KEY/' \"%s\" > \"%s\" && "
          "openssl x509 -in \"%s\" -pubkey -noout >> \"%s\" && "
          "ssh-keygen -i -m PKCS8 -f \"%s\" 2>/dev/null"
          ") ; rm -f \"%s\"",
          pem_path, tmpfile, pem_path, tmpfile, tmpfile, tmpfile);

        fp = popen(cmd, "r");
        if (!fp) {
          unlink(tmpfile);
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: Cannot extract public key from PEM",
                        sptr, cli_name(&me));
          return 0;
        }

        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :%s GitSync Public Key (from PEM):",
                      sptr, cli_name(&me));
      } else {
        /* Standard SSH key mode */
        ssh_key_path = feature_str(FEAT_GITSYNC_SSH_KEY);
        if (!ssh_key_path || !*ssh_key_path) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: No SSH key configured",
                        sptr, cli_name(&me));
          return 0;
        }

        ircd_snprintf(0, pubkey_path, sizeof(pubkey_path), "%s.pub", ssh_key_path);
        fp = fopen(pubkey_path, "r");
        if (fp) {
          from_file = 1;
        } else {
          ircd_snprintf(0, cmd, sizeof(cmd), "ssh-keygen -y -f \"%s\" 2>/dev/null", ssh_key_path);
          fp = popen(cmd, "r");
          if (!fp) {
            sendcmdto_one(&me, CMD_NOTICE, sptr,
                          "%C :%s GitSync: Cannot read public key",
                          sptr, cli_name(&me));
            return 0;
          }
        }

        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :%s GitSync Public Key:",
                      sptr, cli_name(&me));
      }

      while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        char *p;
        if (len > 0 && line[len-1] == '\n')
          line[len-1] = '\0';
        len = strlen(line);
        /* Split long lines to fit IRC message limits (~350 bytes with server prefix) */
        p = line;
        while (len > 0) {
          size_t chunk = (len > 350) ? 350 : len;
          char save = p[chunk];
          p[chunk] = '\0';
          sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :%s   %s",
                        sptr, cli_name(&me), p);
          p[chunk] = save;
          p += chunk;
          len -= chunk;
        }
      }

      if (from_file)
        fclose(fp);
      else
        pclose(fp);
    }
  }

  return 0;
#else
  return 0;
#endif
}
