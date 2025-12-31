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

/** Runtime storage for TOFU host fingerprint */
static char gitsync_runtime_fingerprint[128];
static char gitsync_runtime_host[256];

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

/** Generate an Ed25519 SSH key for GitSync authentication using ssh-keygen
 * @param key_path Path to save the private key (OpenSSH format)
 * @return 1 on success, 0 on failure
 */
int
gitsync_generate_ssh_key(const char *key_path)
{
  char cmd[1024];
  char pubkey_path[512];
  char pubkey_line[512];
  FILE *fp;
  int ret;

  /* Use ssh-keygen to generate Ed25519 key in OpenSSH format */
  ircd_snprintf(0, cmd, sizeof(cmd),
                "ssh-keygen -t ed25519 -f '%s' -N '' -C 'gitsync@nefarious' -q",
                key_path);

  ret = system(cmd);
  if (ret != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: ssh-keygen failed with exit code %d", ret);
    return 0;
  }

  /* Log the public key for reference */
  ircd_snprintf(0, pubkey_path, sizeof(pubkey_path), "%s.pub", key_path);
  fp = fopen(pubkey_path, "r");
  if (fp) {
    if (fgets(pubkey_line, sizeof(pubkey_line), fp)) {
      /* Remove trailing newline */
      char *nl = strchr(pubkey_line, '\n');
      if (nl) *nl = '\0';

      log_write(LS_SYSTEM, L_INFO, 0,
        "GitSync: Generated SSH key at %s, public key: %s", key_path, pubkey_line);
    }
    fclose(fp);
  }

  return 1;
}

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
  struct stat st;

  (void)url;
  (void)payload;

  if (!(allowed_types & GIT_CREDENTIAL_SSH_KEY))
    return GIT_PASSTHROUGH;

  ssh_key = feature_str(FEAT_GITSYNC_SSH_KEY);
  if (ssh_key && *ssh_key) {
    /* GITSYNC_SSH_KEY is set - use dedicated gitsync key */
    if (stat(ssh_key, &st) != 0) {
      /* Key file doesn't exist - generate it using ssh-keygen */
      Debug((DEBUG_INFO, "GitSync: SSH key %s not found, generating...", ssh_key));
      if (!gitsync_generate_ssh_key(ssh_key)) {
        ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                      "Failed to generate SSH key at %s", ssh_key);
        return GIT_EAUTH;
      }
    }
  } else {
    /* Fall back to SSL certificate (contains private key) */
    ssh_key = feature_str(FEAT_SSL_CERTFILE);
    if (!ssh_key || !*ssh_key)
      ssh_key = "ssl/ircd.pem";  /* Default location */
  }

  /* For PEM files, we don't have a separate .pub file - libgit2 can extract it */
  pubkey_path = NULL;

  Debug((DEBUG_INFO, "GitSync: Using SSH key from %s", ssh_key));

  return git_credential_ssh_key_new(out,
                                    username_from_url ? username_from_url : "git",
                                    pubkey_path,
                                    ssh_key,
                                    NULL);  /* No passphrase */
}

/** Format SSH host key fingerprint as hex string
 * @param hash Raw hash bytes
 * @param hash_len Length of hash
 * @param buf Output buffer
 * @param buflen Buffer size
 */
static void
gitsync_format_fingerprint(const unsigned char *hash, size_t hash_len,
                           char *buf, size_t buflen)
{
  size_t i;
  size_t pos = 0;

  for (i = 0; i < hash_len && pos + 3 < buflen; i++) {
    if (i > 0)
      buf[pos++] = ':';
    ircd_snprintf(0, buf + pos, buflen - pos, "%02x", hash[i]);
    pos += 2;
  }
  buf[pos] = '\0';
}

/** Certificate check callback with TOFU (Trust On First Use)
 * @param cert Certificate
 * @param valid Validity flag from libgit2
 * @param host Host being accessed
 * @param payload User payload
 * @return 0 to accept, -1 to reject
 */
static int
gitsync_cert_callback(git_cert *cert, int valid, const char *host, void *payload)
{
  git_cert_hostkey *hostkey;
  char fingerprint[128];
  const char *configured_fp;
  const char *trusted_fp;

  (void)valid;
  (void)payload;

  /* Only handle SSH host keys */
  if (cert->cert_type != GIT_CERT_HOSTKEY_LIBSSH2) {
    Debug((DEBUG_INFO, "GitSync: Non-SSH certificate type %d", cert->cert_type));
    return 0;  /* Accept non-SSH certs (e.g., HTTPS) */
  }

  hostkey = (git_cert_hostkey *)cert;

  /* Format the fingerprint - prefer SHA256, fallback to SHA1 */
  if (hostkey->type & GIT_CERT_SSH_SHA256) {
    gitsync_format_fingerprint(hostkey->hash_sha256, 32, fingerprint, sizeof(fingerprint));
  } else if (hostkey->type & GIT_CERT_SSH_SHA1) {
    gitsync_format_fingerprint(hostkey->hash_sha1, 20, fingerprint, sizeof(fingerprint));
  } else if (hostkey->type & GIT_CERT_SSH_MD5) {
    gitsync_format_fingerprint(hostkey->hash_md5, 16, fingerprint, sizeof(fingerprint));
  } else {
    Debug((DEBUG_INFO, "GitSync: Unknown host key hash type"));
    return -1;  /* Reject unknown hash type */
  }

  /* Check configured fingerprint first */
  configured_fp = feature_str(FEAT_GITSYNC_HOST_FINGERPRINT);

  /* Determine which fingerprint to trust */
  if (configured_fp && *configured_fp) {
    trusted_fp = configured_fp;
  } else if (gitsync_runtime_fingerprint[0]) {
    trusted_fp = gitsync_runtime_fingerprint;
  } else {
    trusted_fp = NULL;
  }

  if (!trusted_fp) {
    /* TOFU: First connection, trust and store this fingerprint */
    ircd_strncpy(gitsync_runtime_fingerprint, fingerprint,
                 sizeof(gitsync_runtime_fingerprint) - 1);
    ircd_strncpy(gitsync_runtime_host, host,
                 sizeof(gitsync_runtime_host) - 1);

    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: TOFU - Trusting host %s with fingerprint %s", host, fingerprint);
    log_write(LS_SYSTEM, L_INFO, 0,
      "GitSync: TOFU - Trusting host %s with fingerprint %s", host, fingerprint);
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: To persist, add to config: Set GITSYNC_HOST_FINGERPRINT \"%s\"",
      fingerprint);

    return 0;  /* Accept */
  }

  /* Verify fingerprint matches */
  if (ircd_strcmp(fingerprint, trusted_fp) != 0) {
    /* FINGERPRINT MISMATCH - possible MITM attack! */
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: WARNING! Host key for %s has CHANGED!", host);
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: Expected: %s", trusted_fp);
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: Got:      %s", fingerprint);
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: Rejecting connection - possible MITM attack!");
    log_write(LS_SYSTEM, L_CRIT, 0,
      "GitSync: HOST KEY MISMATCH for %s! Expected %s, got %s",
      host, trusted_fp, fingerprint);

    return -1;  /* REJECT */
  }

  Debug((DEBUG_INFO, "GitSync: Host key verified for %s", host));
  return 0;  /* Accept - fingerprint matches */
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
  git_clone_options clone_opts;
  int error;

  /* Initialize clone options - use runtime init for ABI compatibility */
  git_clone_options_init(&clone_opts, GIT_CLONE_OPTIONS_VERSION);
  git_fetch_options_init(&clone_opts.fetch_opts, GIT_FETCH_OPTIONS_VERSION);

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
  git_fetch_options fetch_opts;
  git_reference *ref = NULL;
  git_object *target = NULL;
  char refspec[256];
  int error;

  /* Initialize fetch options - use runtime init for ABI compatibility */
  git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);

  fetch_opts.callbacks.credentials = gitsync_cred_callback;
  fetch_opts.callbacks.certificate_check = gitsync_cert_callback;
  /* Fetch all tags (equivalent to git fetch --tags) */
  fetch_opts.download_tags = GIT_REMOTE_DOWNLOAD_TAGS_ALL;

  /* Get origin remote */
  error = git_remote_lookup(&remote, repo, "origin");
  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Remote lookup failed: %s", e ? e->message : "unknown error");
    return GITSYNC_FETCH_ERROR;
  }

  /* Fetch from origin with tags */
  Debug((DEBUG_INFO, "GitSync: Fetching from origin (with tags)"));
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

/** Check for dangerous include directives
 * Allows relative includes (e.g., include "klines.conf";)
 * Blocks absolute paths and path traversal
 * @param content Content to search
 * @return 1 if dangerous include found, 0 if safe
 */
static int
gitsync_has_dangerous_include(const char *content)
{
  const char *p = content;

  while (*p) {
    /* Check for "include" keyword (case-insensitive) */
    if ((*p == 'i' || *p == 'I') &&
        (p[1] == 'n' || p[1] == 'N') &&
        (p[2] == 'c' || p[2] == 'C') &&
        (p[3] == 'l' || p[3] == 'L') &&
        (p[4] == 'u' || p[4] == 'U') &&
        (p[5] == 'd' || p[5] == 'D') &&
        (p[6] == 'e' || p[6] == 'E')) {
      /* Check it's at start of line or after whitespace */
      if (p == content || isspace((unsigned char)p[-1])) {
        const char *q = p + 7;
        /* Skip whitespace after "include" */
        while (*q && isspace((unsigned char)*q))
          q++;
        /* Check for quoted path */
        if (*q == '"') {
          q++;
          /* Check for absolute path */
          if (*q == '/') {
            return 1;  /* Absolute path - dangerous */
          }
          /* Check for path traversal */
          if (q[0] == '.' && q[1] == '.') {
            return 1;  /* Path traversal - dangerous */
          }
        }
      }
    }
    p++;
  }
  return 0;
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

  /* Reject dangerous include directives (absolute paths, path traversal) */
  if (gitsync_has_dangerous_include(content)) {
    ircd_strncpy(gitsync_stats.last_error,
                 "Content contains dangerous include (absolute path or ../)",
                 sizeof(gitsync_stats.last_error) - 1);
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: Rejected content with dangerous include directive");
    return 0;
  }

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

  /* Reject path traversal anywhere in content */
  if (strstr(content, "../") || strstr(content, "..\\"))
    return 0;

  return 1;
}

/** Check if content matches last applied content
 * We store a hash of the last applied content to detect changes.
 */
static char gitsync_last_content_hash[64];

/** Simple hash of content for change detection */
static void
gitsync_hash_content(const char *content, size_t len, char *hash, size_t hashlen)
{
  /* Simple checksum - just use first 8 bytes of content + length */
  unsigned long h = len;
  size_t i;
  for (i = 0; i < len && i < 1024; i++) {
    h = h * 31 + (unsigned char)content[i];
  }
  ircd_snprintf(0, hash, hashlen, "%08lx%08lx", (unsigned long)len, h);
}

/** Apply downloaded configuration
 * Writes to gitsync.conf and triggers a rehash only if content changed.
 * Uses safe write: writes to .new, backs up old to .bak, then renames.
 * If rehash fails, restores from backup.
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
  char content_hash[64];
  char new_file[512];
  char bak_file[512];
  struct stat st;
  int had_backup = 0;

  conf_file = feature_str(FEAT_GITSYNC_CONF_FILE);
  if (!conf_file || !*conf_file)
    conf_file = "gitsync.conf";

  /* Check if content has changed */
  gitsync_hash_content(content, len, content_hash, sizeof(content_hash));
  if (gitsync_last_content_hash[0] &&
      strcmp(content_hash, gitsync_last_content_hash) == 0) {
    Debug((DEBUG_INFO, "GitSync: Content unchanged, skipping write"));
    return GITSYNC_OK;
  }

  /* Build temp and backup filenames */
  ircd_snprintf(0, new_file, sizeof(new_file), "%s.new", conf_file);
  ircd_snprintf(0, bak_file, sizeof(bak_file), "%s.bak", conf_file);

  Debug((DEBUG_INFO, "GitSync: Writing %zu bytes to %s", len, conf_file));

  /* Write content to temp file first */
  fp = fopen(new_file, "w");
  if (!fp) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot open %s for writing: %s", new_file, strerror(errno));
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
                  new_file, written, len);
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: %s", gitsync_stats.last_error);
    unlink(new_file);
    return GITSYNC_APPLY_ERROR;
  }

  /* Backup existing config file if it exists */
  if (stat(conf_file, &st) == 0) {
    unlink(bak_file);  /* Remove old backup */
    if (rename(conf_file, bak_file) == 0) {
      had_backup = 1;
      Debug((DEBUG_INFO, "GitSync: Backed up %s to %s", conf_file, bak_file));
    }
  }

  /* Rename new file to config file (atomic on most filesystems) */
  if (rename(new_file, conf_file) != 0) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot rename %s to %s: %s", new_file, conf_file, strerror(errno));
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: %s", gitsync_stats.last_error);
    /* Try to restore backup */
    if (had_backup)
      rename(bak_file, conf_file);
    return GITSYNC_APPLY_ERROR;
  }

  sendto_opmask_butone(0, SNO_OLDSNO,
                       "GitSync: Wrote %zu bytes to %s (commit %.8s), rehashing",
                       len, conf_file, gitsync_stats.last_commit);

  /* Trigger a rehash to load the new configuration */
  rehash(&me, 0);

  /* Check if config parsing failed */
  if (conf_get_error_flag()) {
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "GitSync: Config parse error detected, restoring backup");
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Config parse error, restoring %s from backup", conf_file);

    if (had_backup && rename(bak_file, conf_file) == 0) {
      /* Rehash again with restored config */
      rehash(&me, 0);
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "Config parse error - restored from backup");
    } else {
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "Config parse error - no backup to restore");
    }
    return GITSYNC_VALIDATION_ERROR;
  }

  /* Success - remember hash and clean up backup */
  ircd_strncpy(gitsync_last_content_hash, content_hash,
               sizeof(gitsync_last_content_hash) - 1);

  /* Keep backup for safety, but could optionally delete it here */
  /* unlink(bak_file); */

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
    /* Get HEAD commit hash after clone */
    {
      git_reference *head_ref = NULL;
      git_object *head_obj = NULL;
      if (git_repository_head(&head_ref, repo) == 0 &&
          git_reference_peel(&head_obj, head_ref, GIT_OBJECT_COMMIT) == 0) {
        git_oid_tostr(gitsync_stats.last_commit, sizeof(gitsync_stats.last_commit),
                      git_object_id(head_obj));
        git_object_free(head_obj);
      }
      if (head_ref)
        git_reference_free(head_ref);
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

const char *
gitsync_get_host_fingerprint(char *host, size_t hostlen)
{
  const char *configured_fp;

  /* Return configured fingerprint if set */
  configured_fp = feature_str(FEAT_GITSYNC_HOST_FINGERPRINT);
  if (configured_fp && *configured_fp) {
    if (host && hostlen > 0)
      ircd_strncpy(host, "(configured)", hostlen - 1);
    return configured_fp;
  }

  /* Return runtime TOFU fingerprint if established */
  if (gitsync_runtime_fingerprint[0]) {
    if (host && hostlen > 0)
      ircd_strncpy(host, gitsync_runtime_host, hostlen - 1);
    return gitsync_runtime_fingerprint;
  }

  return NULL;
}

void
gitsync_clear_host_fingerprint(void)
{
  if (gitsync_runtime_fingerprint[0]) {
    sendto_opmask_butone(0, SNO_OLDSNO,
      "GitSync: Cleared TOFU host fingerprint for %s", gitsync_runtime_host);
    log_write(LS_SYSTEM, L_INFO, 0,
      "GitSync: Cleared TOFU host fingerprint for %s", gitsync_runtime_host);
  }
  gitsync_runtime_fingerprint[0] = '\0';
  gitsync_runtime_host[0] = '\0';
}

#endif /* USE_LIBGIT2 */
