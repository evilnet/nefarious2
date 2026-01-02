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

#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

/** Validate that a path contains only safe characters.
 * Allows alphanumeric, underscore, hyphen, dot, and forward slash.
 * Rejects paths containing ".." to prevent directory traversal.
 * @param path Path to validate
 * @return 1 if safe, 0 if unsafe
 */
static int
validate_safe_path(const char *path)
{
  const char *p;

  if (!path || !*path)
    return 0;

  for (p = path; *p; p++) {
    if (!isalnum((unsigned char)*p) &&
        *p != '_' && *p != '-' && *p != '.' && *p != '/') {
      return 0;
    }
  }

  /* Reject directory traversal attempts */
  if (strstr(path, ".."))
    return 0;

  return 1;
}

/** Run ssh-keygen -y to extract public key from private key file.
 * Uses fork/exec instead of popen for security.
 * @param key_path Path to private key file
 * @param output Buffer to store output
 * @param output_size Size of output buffer
 * @return Number of bytes read, or -1 on error
 */
static int
run_ssh_keygen_pubkey(const char *key_path, char *output, size_t output_size)
{
  pid_t pid;
  int pipefd[2];
  int status;
  ssize_t total = 0;

  if (!validate_safe_path(key_path))
    return -1;

  if (pipe(pipefd) < 0)
    return -1;

  pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }

  if (pid == 0) {
    /* Child process */
    int devnull;

    close(pipefd[0]);  /* Close read end */

    /* Redirect stdout to pipe */
    if (dup2(pipefd[1], STDOUT_FILENO) < 0)
      _exit(127);
    close(pipefd[1]);

    /* Redirect stderr to /dev/null */
    devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }

    /* Redirect stdin from /dev/null */
    devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      close(devnull);
    }

    execlp("ssh-keygen", "ssh-keygen", "-y", "-f", key_path, (char *)NULL);
    _exit(127);
  }

  /* Parent process */
  close(pipefd[1]);  /* Close write end */

  /* Read output */
  while (total < (ssize_t)(output_size - 1)) {
    ssize_t n = read(pipefd[0], output + total, output_size - 1 - total);
    if (n <= 0)
      break;
    total += n;
  }
  output[total] = '\0';

  close(pipefd[0]);

  /* Wait for child */
  waitpid(pid, &status, 0);

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    return -1;

  return total;
}

/** Extract public key from X509 certificate and convert to SSH format.
 * Uses OpenSSL library APIs to extract the public key, then fork/exec
 * ssh-keygen to convert to SSH format.
 * @param pem_path Path to PEM certificate file
 * @param output Buffer to store SSH public key
 * @param output_size Size of output buffer
 * @return Number of bytes read, or -1 on error
 */
static int
extract_pubkey_from_pem(const char *pem_path, char *output, size_t output_size)
{
  FILE *pem_fp = NULL;
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  BIO *bio = NULL;
  char *pubkey_pem = NULL;
  long pubkey_len;
  char tmpfile[256];
  int tmpfd = -1;
  pid_t pid;
  int pipefd[2];
  int status;
  ssize_t total = 0;
  int result = -1;

  if (!validate_safe_path(pem_path))
    return -1;

  /* Open and read the certificate */
  pem_fp = fopen(pem_path, "r");
  if (!pem_fp)
    goto cleanup;

  /* Read X509 certificate */
  cert = PEM_read_X509(pem_fp, NULL, NULL, NULL);
  if (!cert) {
    /* Try reading from start again in case file has private key first */
    rewind(pem_fp);
    /* Skip past any private key */
    while (fgets(output, output_size, pem_fp)) {
      if (strstr(output, "-----BEGIN CERTIFICATE-----") ||
          strstr(output, "-----BEGIN X509 CERTIFICATE-----")) {
        /* Found certificate start, seek back */
        fseek(pem_fp, -(long)strlen(output), SEEK_CUR);
        break;
      }
    }
    cert = PEM_read_X509(pem_fp, NULL, NULL, NULL);
  }
  fclose(pem_fp);
  pem_fp = NULL;

  if (!cert)
    goto cleanup;

  /* Extract public key from certificate */
  pkey = X509_get_pubkey(cert);
  if (!pkey)
    goto cleanup;

  /* Write public key to memory BIO in PEM format */
  bio = BIO_new(BIO_s_mem());
  if (!bio)
    goto cleanup;

  if (!PEM_write_bio_PUBKEY(bio, pkey))
    goto cleanup;

  pubkey_len = BIO_get_mem_data(bio, &pubkey_pem);
  if (pubkey_len <= 0)
    goto cleanup;

  /* Write public key to temp file for ssh-keygen */
  ircd_strncpy(tmpfile, "/tmp/gitsync_pubkey.XXXXXX", sizeof(tmpfile) - 1);
  tmpfd = mkstemp(tmpfile);
  if (tmpfd < 0)
    goto cleanup;

  if (write(tmpfd, pubkey_pem, pubkey_len) != pubkey_len) {
    close(tmpfd);
    unlink(tmpfile);
    goto cleanup;
  }
  close(tmpfd);
  tmpfd = -1;

  /* Run ssh-keygen to convert to SSH format */
  if (pipe(pipefd) < 0) {
    unlink(tmpfile);
    goto cleanup;
  }

  pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    unlink(tmpfile);
    goto cleanup;
  }

  if (pid == 0) {
    /* Child process */
    int devnull;

    close(pipefd[0]);

    if (dup2(pipefd[1], STDOUT_FILENO) < 0)
      _exit(127);
    close(pipefd[1]);

    devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }

    devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      close(devnull);
    }

    execlp("ssh-keygen", "ssh-keygen", "-i", "-m", "PKCS8", "-f", tmpfile, (char *)NULL);
    _exit(127);
  }

  /* Parent process */
  close(pipefd[1]);

  while (total < (ssize_t)(output_size - 1)) {
    ssize_t n = read(pipefd[0], output + total, output_size - 1 - total);
    if (n <= 0)
      break;
    total += n;
  }
  output[total] = '\0';

  close(pipefd[0]);
  waitpid(pid, &status, 0);

  unlink(tmpfile);

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && total > 0)
    result = total;

cleanup:
  if (pem_fp)
    fclose(pem_fp);
  if (cert)
    X509_free(cert);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (bio)
    BIO_free(bio);

  return result;
}

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
    FILE *fp;
    char output[2048];
    int from_pem = 0;
    int result;

    /* Check if user requested PEM mode */
    if (parc > 2 && ircd_strcmp(parv[2], "pem") == 0) {
      from_pem = 1;
    } else if (target && parc > 2 && ircd_strcmp(parv[2], "pubkey") == 0 &&
               parc > 3 && ircd_strcmp(parv[3], "pem") == 0) {
      from_pem = 1;
    }

    if (from_pem) {
      /* PEM mode: Extract SSH key from SSL certificate using OpenSSL APIs */
      pem_path = feature_str(FEAT_SSL_CERTFILE);
      if (!pem_path || !*pem_path) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :No SSL certificate configured (SSL_CERTFILE not set)", sptr);
        return 0;
      }

      result = extract_pubkey_from_pem(pem_path, output, sizeof(output));
      if (result < 0) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Cannot extract public key from PEM %s", sptr, pem_path);
        return 0;
      }

      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :Public key extracted from PEM (add to GitLab/GitHub):", sptr);

      /* Output the key, splitting long lines for IRC */
      {
        char *p = output;
        size_t len = strlen(output);
        /* Remove trailing newline */
        if (len > 0 && output[len-1] == '\n') {
          output[len-1] = '\0';
          len--;
        }
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

      /* Ensure SSH key exists (gitsync_generate_ssh_key handles both
       * generation and detection of existing key atomically to prevent TOCTOU) */
      if (!gitsync_generate_ssh_key(ssh_key_path)) {
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Failed to generate or validate SSH key", sptr);
        return 0;
      }

      /* Try to read existing .pub file first */
      ircd_snprintf(0, pubkey_path, sizeof(pubkey_path), "%s.pub", ssh_key_path);
      fp = fopen(pubkey_path, "r");
      if (fp) {
        char line[1024];
        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Public key for GitSync (add to GitLab/GitHub):", sptr);
        while (fgets(line, sizeof(line), fp)) {
          size_t len = strlen(line);
          char *p;
          if (len > 0 && line[len-1] == '\n')
            line[len-1] = '\0';
          len = strlen(line);
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
        fclose(fp);
      } else {
        /* Generate public key from private key using ssh-keygen (secure fork/exec) */
        result = run_ssh_keygen_pubkey(ssh_key_path, output, sizeof(output));
        if (result < 0) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :Cannot read or generate public key from %s", sptr, ssh_key_path);
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :Tip: Use '/GITSYNC pubkey pem' to extract from SSL certificate", sptr);
          return 0;
        }

        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :Public key for GitSync (add to GitLab/GitHub):", sptr);

        /* Output the key, splitting long lines for IRC */
        {
          char *p = output;
          size_t len = strlen(output);
          if (len > 0 && output[len-1] == '\n') {
            output[len-1] = '\0';
            len--;
          }
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
      }
    }
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
      FILE *fp;
      char output[2048];
      int from_pem = (subarg && ircd_strcmp(subarg, "pem") == 0);
      int result;

      if (from_pem) {
        /* PEM mode: Extract SSH key from SSL certificate using OpenSSL APIs */
        pem_path = feature_str(FEAT_SSL_CERTFILE);
        if (!pem_path || !*pem_path) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: No SSL certificate configured",
                        sptr, cli_name(&me));
          return 0;
        }

        result = extract_pubkey_from_pem(pem_path, output, sizeof(output));
        if (result < 0) {
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync: Cannot extract public key from PEM",
                        sptr, cli_name(&me));
          return 0;
        }

        sendcmdto_one(&me, CMD_NOTICE, sptr,
                      "%C :%s GitSync Public Key (from PEM):",
                      sptr, cli_name(&me));

        /* Output the key, splitting long lines for IRC */
        {
          char *p = output;
          size_t len = strlen(output);
          if (len > 0 && output[len-1] == '\n') {
            output[len-1] = '\0';
            len--;
          }
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
          char line[1024];
          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync Public Key:",
                        sptr, cli_name(&me));
          while (fgets(line, sizeof(line), fp)) {
            size_t len = strlen(line);
            char *p;
            if (len > 0 && line[len-1] == '\n')
              line[len-1] = '\0';
            len = strlen(line);
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
          fclose(fp);
        } else {
          /* Generate public key from private key using ssh-keygen (secure fork/exec) */
          result = run_ssh_keygen_pubkey(ssh_key_path, output, sizeof(output));
          if (result < 0) {
            sendcmdto_one(&me, CMD_NOTICE, sptr,
                          "%C :%s GitSync: Cannot read public key",
                          sptr, cli_name(&me));
            return 0;
          }

          sendcmdto_one(&me, CMD_NOTICE, sptr,
                        "%C :%s GitSync Public Key:",
                        sptr, cli_name(&me));

          /* Output the key, splitting long lines for IRC */
          {
            char *p = output;
            size_t len = strlen(output);
            if (len > 0 && output[len-1] == '\n') {
              output[len-1] = '\0';
              len--;
            }
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
        }
      }
    }
  }

  return 0;
#else
  return 0;
#endif
}
