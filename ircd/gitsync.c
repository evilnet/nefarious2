/*
 * IRC - Internet Relay Chat, ircd/gitsync.c
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
 * @brief GitSync - centralized config distribution via git.
 */
#include "config.h"

#ifdef USE_LIBGIT2

#include "gitsync.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_stats.h"
#include "send.h"
#ifdef USE_SSL
#include "ssl.h"
#endif

#include <git2.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

/** Maximum size of linesync.data file (1 MB) */
#define GITSYNC_MAX_SIZE (1024 * 1024)

/** Global gitsync statistics */
static struct GitsyncStats gitsync_stats;

/** Timer for periodic gitsync */
static struct Timer gitsync_timer;

/** libgit2 initialized flag */
static int git_initialized = 0;

/** Status code to string mapping */
static const char *status_strings[] = {
  "OK",
  "Disabled",
  "No repository configured",
  "Clone error",
  "Fetch error",
  "Checkout error",
  "SSH authentication error",
  "Validation error",
  "Apply error"
};

/** SSH credentials callback for libgit2
 * @param out Credential output
 * @param url URL being accessed
 * @param username_from_url Username from URL
 * @param allowed_types Allowed credential types
 * @param payload User payload (unused)
 * @return 0 on success, negative on error
 */
static int
gitsync_cred_callback(git_credential **out, const char *url,
                      const char *username_from_url,
                      unsigned int allowed_types, void *payload)
{
  const char *ssh_key;
  const char *pubkey_path;
  char pubkey_buf[512];

  (void)url;
  (void)payload;

  if (!(allowed_types & GIT_CREDENTIAL_SSH_KEY))
    return GIT_PASSTHROUGH;

  ssh_key = feature_str(FEAT_GITSYNC_SSH_KEY);
  if (!ssh_key || !*ssh_key) {
    /* Try default SSH key location */
    ssh_key = NULL;
  }

  /* Build public key path */
  if (ssh_key) {
    ircd_snprintf(0, pubkey_buf, sizeof(pubkey_buf), "%s.pub", ssh_key);
    pubkey_path = pubkey_buf;
  } else {
    pubkey_path = NULL;
  }

  return git_credential_ssh_key_new(out,
                                    username_from_url ? username_from_url : "git",
                                    pubkey_path,
                                    ssh_key,
                                    NULL);  /* No passphrase */
}

/** Certificate check callback (accept all for now)
 * @param cert Certificate
 * @param valid Validity flag
 * @param host Host being accessed
 * @param payload User payload
 * @return 0 to accept
 */
static int
gitsync_cert_callback(git_cert *cert, int valid, const char *host, void *payload)
{
  (void)cert;
  (void)valid;
  (void)host;
  (void)payload;
  return 0;  /* Accept certificate */
}

/** Get full path to local repository
 * @param buf Buffer to store path
 * @param bufsize Buffer size
 * @return Pointer to buf
 */
static char *
gitsync_get_repo_path(char *buf, size_t bufsize)
{
  const char *local_path = feature_str(FEAT_GITSYNC_LOCAL_PATH);

  if (!local_path || !*local_path)
    local_path = "gitsync";

  ircd_strncpy(buf, local_path, bufsize - 1);
  buf[bufsize - 1] = '\0';
  return buf;
}

/** Check if directory exists
 * @param path Path to check
 * @return 1 if exists and is directory, 0 otherwise
 */
static int
dir_exists(const char *path)
{
  struct stat st;
  return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
}

/** Clone repository if it doesn't exist
 * @param repo_url Repository URL
 * @param local_path Local path to clone to
 * @param[out] repo Opened repository
 * @return GITSYNC_OK on success, error code otherwise
 */
static enum GitsyncStatus
gitsync_clone(const char *repo_url, const char *local_path, git_repository **repo)
{
  git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
  int error;

  clone_opts.fetch_opts.callbacks.credentials = gitsync_cred_callback;
  clone_opts.fetch_opts.callbacks.certificate_check = gitsync_cert_callback;

  Debug((DEBUG_INFO, "GitSync: Cloning %s to %s", repo_url, local_path));

  error = git_clone(repo, repo_url, local_path, &clone_opts);
  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Clone failed: %s", e ? e->message : "unknown error");

    if (e && (strstr(e->message, "authentication") ||
              strstr(e->message, "SSH") ||
              strstr(e->message, "key"))) {
      return GITSYNC_SSH_ERROR;
    }
    return GITSYNC_CLONE_ERROR;
  }

  return GITSYNC_OK;
}

/** Fetch and reset to remote branch
 * @param repo Repository
 * @param branch Branch name
 * @return GITSYNC_OK on success, error code otherwise
 */
static enum GitsyncStatus
gitsync_fetch_and_reset(git_repository *repo, const char *branch)
{
  git_remote *remote = NULL;
  git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
  git_reference *ref = NULL;
  git_object *target = NULL;
  char refspec[256];
  int error;

  fetch_opts.callbacks.credentials = gitsync_cred_callback;
  fetch_opts.callbacks.certificate_check = gitsync_cert_callback;

  /* Get origin remote */
  error = git_remote_lookup(&remote, repo, "origin");
  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Remote lookup failed: %s", e ? e->message : "unknown error");
    return GITSYNC_FETCH_ERROR;
  }

  /* Fetch from origin */
  Debug((DEBUG_INFO, "GitSync: Fetching from origin"));
  error = git_remote_fetch(remote, NULL, &fetch_opts, "gitsync fetch");
  git_remote_free(remote);

  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Fetch failed: %s", e ? e->message : "unknown error");

    if (e && (strstr(e->message, "authentication") ||
              strstr(e->message, "SSH") ||
              strstr(e->message, "key"))) {
      return GITSYNC_SSH_ERROR;
    }
    return GITSYNC_FETCH_ERROR;
  }

  /* Get reference to origin/branch */
  ircd_snprintf(0, refspec, sizeof(refspec), "refs/remotes/origin/%s", branch);
  error = git_reference_lookup(&ref, repo, refspec);
  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Branch lookup failed: %s", e ? e->message : "unknown error");
    return GITSYNC_CHECKOUT_ERROR;
  }

  /* Get the commit object */
  error = git_reference_peel(&target, ref, GIT_OBJECT_COMMIT);
  git_reference_free(ref);

  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Peel failed: %s", e ? e->message : "unknown error");
    return GITSYNC_CHECKOUT_ERROR;
  }

  /* Store commit hash */
  git_oid_tostr(gitsync_stats.last_commit, sizeof(gitsync_stats.last_commit),
                git_object_id(target));

  /* Hard reset to origin/branch */
  Debug((DEBUG_INFO, "GitSync: Resetting to %s", gitsync_stats.last_commit));
  error = git_reset(repo, target, GIT_RESET_HARD, NULL);
  git_object_free(target);

  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Reset failed: %s", e ? e->message : "unknown error");
    return GITSYNC_CHECKOUT_ERROR;
  }

  return GITSYNC_OK;
}

/** Read linesync.data file from repository
 * @param repo_path Path to repository
 * @param[out] content Content buffer (caller must free)
 * @param[out] len Content length
 * @return GITSYNC_OK on success, error code otherwise
 */
static enum GitsyncStatus
gitsync_read_data(const char *repo_path, char **content, size_t *len)
{
  char filepath[512];
  FILE *fp;
  struct stat st;
  char *buf;

  ircd_snprintf(0, filepath, sizeof(filepath), "%s/linesync.data", repo_path);

  if (stat(filepath, &st) != 0) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "linesync.data not found in repository");
    return GITSYNC_VALIDATION_ERROR;
  }

  if (st.st_size > GITSYNC_MAX_SIZE) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "linesync.data too large (%ld bytes)", (long)st.st_size);
    return GITSYNC_VALIDATION_ERROR;
  }

  fp = fopen(filepath, "r");
  if (!fp) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot open linesync.data");
    return GITSYNC_VALIDATION_ERROR;
  }

  buf = (char *)MyMalloc(st.st_size + 1);
  if (!buf) {
    fclose(fp);
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Memory allocation failed");
    return GITSYNC_APPLY_ERROR;
  }

  *len = fread(buf, 1, st.st_size, fp);
  fclose(fp);

  buf[*len] = '\0';
  *content = buf;

  return GITSYNC_OK;
}

/** Validate downloaded content
 * @param content Downloaded content
 * @param len Length of content
 * @return 1 if valid, 0 if invalid
 */
static int
gitsync_validate_content(const char *content, size_t len)
{
  const char *p;
  int brace_depth = 0;

  if (!content || len == 0)
    return 0;

  /* Basic validation: check for balanced braces and no dangerous patterns */
  for (p = content; *p; p++) {
    if (*p == '{') {
      brace_depth++;
    } else if (*p == '}') {
      brace_depth--;
      if (brace_depth < 0)
        return 0; /* Unbalanced braces */
    }
  }

  if (brace_depth != 0)
    return 0; /* Unbalanced braces */

  /* Reject content with shell metacharacters that could be dangerous */
  if (strstr(content, "$(") || strstr(content, "`"))
    return 0;

  /* Reject attempts to include other files (path traversal) */
  if (strstr(content, "../") || strstr(content, "..\\"))
    return 0;

  return 1;
}

/** Apply downloaded configuration
 * Writes to gitsync.conf and triggers a rehash.
 * @param content Configuration content
 * @param len Content length
 * @return GITSYNC_OK on success, error code otherwise
 */
static enum GitsyncStatus
gitsync_apply(const char *content, size_t len)
{
  const char *conf_file;
  FILE *fp;
  size_t written;

  conf_file = feature_str(FEAT_GITSYNC_CONF_FILE);
  if (!conf_file || !*conf_file)
    conf_file = "gitsync.conf";

  Debug((DEBUG_INFO, "GitSync: Writing %zu bytes to %s", len, conf_file));

  /* Write content to config file */
  fp = fopen(conf_file, "w");
  if (!fp) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot open %s for writing: %s", conf_file, strerror(errno));
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: %s", gitsync_stats.last_error);
    return GITSYNC_APPLY_ERROR;
  }

  /* Write header comment */
  fprintf(fp, "# GitSync configuration - DO NOT EDIT\n");
  fprintf(fp, "# Auto-generated from git commit %.8s\n", gitsync_stats.last_commit);
  fprintf(fp, "# Last sync: %s\n\n", myctime(CurrentTime));

  /* Write the actual content */
  written = fwrite(content, 1, len, fp);
  fclose(fp);

  if (written != len) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Short write to %s: wrote %zu of %zu bytes",
                  conf_file, written, len);
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: %s", gitsync_stats.last_error);
    return GITSYNC_APPLY_ERROR;
  }

  sendto_opmask_butone(0, SNO_OLDSNO,
                       "GitSync: Wrote %zu bytes to %s (commit %.8s), rehashing",
                       len, conf_file, gitsync_stats.last_commit);

  /* Trigger a rehash to load the new configuration */
  rehash(&me, 0);

  return GITSYNC_OK;
}

#ifdef USE_SSL
/** Update TLS certificate from git tag
 * @param repo Repository
 * @param tag_name Name of tag containing certificate
 * @return 1 if certificate was updated, 0 otherwise
 */
static int
gitsync_update_cert(git_repository *repo, const char *tag_name)
{
  git_object *obj = NULL;
  const git_blob *blob = NULL;
  const char *cert_content;
  size_t cert_size;
  const char *cert_file;
  FILE *fp;
  char *old_content = NULL;
  size_t old_size = 0;
  struct stat st;
  int changed = 0;
  int error;
  char refspec[256];

  cert_file = feature_str(FEAT_GITSYNC_CERT_FILE);
  if (!cert_file || !*cert_file)
    cert_file = feature_str(FEAT_SSL_CERTFILE);  /* Use IRCd's SSL cert file */

  /* Look up the tag */
  ircd_snprintf(0, refspec, sizeof(refspec), "refs/tags/%s", tag_name);
  error = git_revparse_single(&obj, repo, refspec);
  if (error < 0) {
    /* Try without refs/tags prefix */
    error = git_revparse_single(&obj, repo, tag_name);
    if (error < 0) {
      Debug((DEBUG_INFO, "GitSync: Tag %s not found", tag_name));
      return 0;
    }
  }

  /* Peel to blob if it's an annotated tag */
  if (git_object_type(obj) == GIT_OBJECT_TAG) {
    git_object *target = NULL;
    error = git_tag_peel(&target, (git_tag *)obj);
    git_object_free(obj);
    if (error < 0) {
      Debug((DEBUG_INFO, "GitSync: Cannot peel tag %s", tag_name));
      return 0;
    }
    obj = target;
  }

  /* Check if it's a blob */
  if (git_object_type(obj) != GIT_OBJECT_BLOB) {
    Debug((DEBUG_INFO, "GitSync: Tag %s is not a blob (type %d)",
           tag_name, git_object_type(obj)));
    git_object_free(obj);
    return 0;
  }

  blob = (const git_blob *)obj;
  cert_content = (const char *)git_blob_rawcontent(blob);
  cert_size = git_blob_rawsize(blob);

  /* Read existing cert file for comparison */
  if (stat(cert_file, &st) == 0 && st.st_size > 0) {
    fp = fopen(cert_file, "r");
    if (fp) {
      old_content = (char *)MyMalloc(st.st_size + 1);
      if (old_content) {
        old_size = fread(old_content, 1, st.st_size, fp);
        old_content[old_size] = '\0';
      }
      fclose(fp);
    }
  }

  /* Check if content changed */
  if (old_content == NULL || old_size != cert_size ||
      memcmp(old_content, cert_content, cert_size) != 0) {
    /* Backup old cert */
    if (stat(cert_file, &st) == 0) {
      char backup_path[512];
      ircd_snprintf(0, backup_path, sizeof(backup_path), "%s.backup", cert_file);
      rename(cert_file, backup_path);
    }

    /* Write new cert */
    fp = fopen(cert_file, "w");
    if (fp) {
      if (fwrite(cert_content, 1, cert_size, fp) == cert_size) {
        changed = 1;
        sendto_opmask_butone(0, SNO_OLDSNO,
                             "GitSync: Updated TLS certificate from tag %s", tag_name);
        log_write(LS_SYSTEM, L_INFO, 0,
                  "GitSync: Updated TLS certificate from tag %s", tag_name);
      } else {
        log_write(LS_SYSTEM, L_ERROR, 0,
                  "GitSync: Failed to write certificate to %s", cert_file);
      }
      fclose(fp);

      /* Reload SSL certificates */
      if (changed) {
        ssl_reinit(1);
      }
    } else {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "GitSync: Cannot open %s for writing: %s",
                cert_file, strerror(errno));
    }
  }

  if (old_content)
    MyFree(old_content);
  git_object_free(obj);

  return changed;
}
#endif /* USE_SSL */

/** Timer callback for periodic gitsync
 * @param ev Timer event
 */
static void
gitsync_timer_callback(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE) {
    gitsync_trigger(NULL, 0);
  }
}

void
gitsync_init(void)
{
  memset(&gitsync_stats, 0, sizeof(gitsync_stats));

  if (!git_initialized) {
    git_libgit2_init();
    git_initialized = 1;
  }
}

void
gitsync_start_timer(void)
{
  int interval;
  const char *conf_file;
  struct stat st;
  FILE *fp;

  if (!feature_bool(FEAT_GITSYNC_ENABLE))
    return;

  /* Ensure gitsync.conf exists so include directive doesn't fail */
  conf_file = feature_str(FEAT_GITSYNC_CONF_FILE);
  if (!conf_file || !*conf_file)
    conf_file = "gitsync.conf";

  if (stat(conf_file, &st) != 0) {
    /* File doesn't exist, create empty placeholder */
    fp = fopen(conf_file, "w");
    if (fp) {
      fprintf(fp, "# GitSync configuration placeholder\n");
      fprintf(fp, "# This file will be populated when gitsync runs\n");
      fclose(fp);
      Debug((DEBUG_INFO, "GitSync: Created empty %s", conf_file));
    }
  }

  interval = feature_int(FEAT_GITSYNC_INTERVAL);
  if (interval < 60)
    interval = 60; /* Minimum 1 minute */

  timer_add(timer_init(&gitsync_timer), gitsync_timer_callback,
            NULL, TT_PERIODIC, interval);

  Debug((DEBUG_INFO, "GitSync: Timer started with interval %d seconds", interval));
}

enum GitsyncStatus
gitsync_trigger(struct Client *sptr, int force)
{
  const char *repo_url;
  const char *branch;
  char repo_path[512];
  git_repository *repo = NULL;
  char *content = NULL;
  size_t len = 0;
  enum GitsyncStatus status;
  time_t now = CurrentTime;
  int interval;
  int error;

  gitsync_stats.last_attempt = now;

  /* Check if enabled */
  if (!feature_bool(FEAT_GITSYNC_ENABLE)) {
    gitsync_stats.last_status = GITSYNC_DISABLED;
    return GITSYNC_DISABLED;
  }

  /* Check if repository is configured */
  repo_url = feature_str(FEAT_GITSYNC_REPOSITORY);
  if (!repo_url || !*repo_url) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "No repository configured");
    gitsync_stats.last_status = GITSYNC_NO_REPO;
    return GITSYNC_NO_REPO;
  }

  /* Check interval (unless forced) */
  if (!force) {
    interval = feature_int(FEAT_GITSYNC_INTERVAL);
    if (gitsync_stats.last_sync > 0 &&
        (now - gitsync_stats.last_sync) < interval) {
      /* Not time yet */
      return GITSYNC_OK;
    }
  }

  /* Notify if triggered by oper */
  if (sptr) {
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "GitSync triggered by %s", cli_name(sptr));
  }

  /* Get paths */
  gitsync_get_repo_path(repo_path, sizeof(repo_path));
  branch = feature_str(FEAT_GITSYNC_BRANCH);
  if (!branch || !*branch)
    branch = "master";

  /* Initialize libgit2 if needed */
  if (!git_initialized) {
    git_libgit2_init();
    git_initialized = 1;
  }

  /* Clone or open repository */
  if (!dir_exists(repo_path)) {
    /* Need to clone */
    status = gitsync_clone(repo_url, repo_path, &repo);
    if (status != GITSYNC_OK) {
      gitsync_stats.failures++;
      gitsync_stats.last_status = status;
      if (sptr) {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                      sptr, gitsync_stats.last_error);
      }
      return status;
    }
  } else {
    /* Open existing repository */
    error = git_repository_open(&repo, repo_path);
    if (error < 0) {
      const git_error *e = git_error_last();
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "Cannot open repository: %s", e ? e->message : "unknown error");
      gitsync_stats.failures++;
      gitsync_stats.last_status = GITSYNC_CLONE_ERROR;
      if (sptr) {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                      sptr, gitsync_stats.last_error);
      }
      return GITSYNC_CLONE_ERROR;
    }

    /* Fetch and reset */
    status = gitsync_fetch_and_reset(repo, branch);
    if (status != GITSYNC_OK) {
      git_repository_free(repo);
      gitsync_stats.failures++;
      gitsync_stats.last_status = status;
      if (sptr) {
        sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                      sptr, gitsync_stats.last_error);
      }
      return status;
    }
  }

  /* Check for certificate update from git tag */
#ifdef USE_SSL
  {
    const char *cert_tag = feature_str(FEAT_GITSYNC_CERT_TAG);
    if (cert_tag && *cert_tag) {
      gitsync_update_cert(repo, cert_tag);
    }
  }
#endif

  /* Read linesync.data */
  status = gitsync_read_data(repo_path, &content, &len);
  git_repository_free(repo);

  if (status != GITSYNC_OK) {
    gitsync_stats.failures++;
    gitsync_stats.last_status = status;
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                    sptr, gitsync_stats.last_error);
    }
    return status;
  }

  /* Validate content */
  if (!gitsync_validate_content(content, len)) {
    MyFree(content);
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Content validation failed");
    gitsync_stats.failures++;
    gitsync_stats.last_status = GITSYNC_VALIDATION_ERROR;
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: validation error",
                    sptr);
    }
    return GITSYNC_VALIDATION_ERROR;
  }

  /* Apply configuration */
  status = gitsync_apply(content, len);
  MyFree(content);

  if (status == GITSYNC_OK) {
    gitsync_stats.last_sync = now;
    gitsync_stats.syncs++;
    gitsync_stats.last_error[0] = '\0';
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr,
                    "%C :GitSync completed successfully (commit %.8s)",
                    sptr, gitsync_stats.last_commit);
    }
  } else {
    gitsync_stats.failures++;
    if (sptr) {
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                    sptr, gitsync_stats.last_error);
    }
  }

  gitsync_stats.last_status = status;
  return status;
}

const char *
gitsync_status_str(enum GitsyncStatus status)
{
  if (status >= 0 && status < sizeof(status_strings) / sizeof(status_strings[0]))
    return status_strings[status];
  return "Unknown";
}

const struct GitsyncStats *
gitsync_get_stats(void)
{
  return &gitsync_stats;
}

void
gitsync_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  const struct GitsyncStats *stats = &gitsync_stats;
  char timebuf[64];

  (void)sd;
  (void)param;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":GitSync Statistics:");

  if (feature_bool(FEAT_GITSYNC_ENABLE)) {
    const char *cert_tag;
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Status: Enabled");
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Repository: %s",
               feature_str(FEAT_GITSYNC_REPOSITORY));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Branch: %s",
               feature_str(FEAT_GITSYNC_BRANCH));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Interval: %d seconds",
               feature_int(FEAT_GITSYNC_INTERVAL));
    cert_tag = feature_str(FEAT_GITSYNC_CERT_TAG);
    if (cert_tag && *cert_tag) {
      const char *cert_file = feature_str(FEAT_GITSYNC_CERT_FILE);
      if (!cert_file || !*cert_file)
        cert_file = feature_str(FEAT_SSL_CERTFILE);
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Cert Tag: %s",
                 cert_tag);
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Cert File: %s",
                 cert_file);
    }
  } else {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Status: Disabled");
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Successful syncs: %lu",
             stats->syncs);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Failed syncs: %lu",
             stats->failures);

  if (stats->last_sync > 0) {
    struct tm *tm = localtime(&stats->last_sync);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last sync: %s", timebuf);
  } else {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last sync: Never");
  }

  if (stats->last_commit[0]) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last commit: %.8s",
               stats->last_commit);
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last status: %s",
             gitsync_status_str(stats->last_status));

  if (stats->last_error[0]) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, ":  Last error: %s",
               stats->last_error);
  }
}

#endif /* USE_LIBGIT2 */
