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
#include "gitsync_content.h"
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
#include <openssl/err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

/** Maximum size of linesync.data file (1 MB) */
#define GITSYNC_MAX_SIZE (1024 * 1024)

/** Global gitsync statistics */
static struct GitsyncStats gitsync_stats;

/** The libgit2 version built against, as major * 100 + minor. */
#if defined(LIBGIT2_VERSION_MAJOR)
#define GITSYNC_GIT2_VERSION (LIBGIT2_VERSION_MAJOR * 100 + LIBGIT2_VERSION_MINOR)
#elif defined(LIBGIT2_VER_MAJOR)
#define GITSYNC_GIT2_VERSION (LIBGIT2_VER_MAJOR * 100 + LIBGIT2_VER_MINOR)
#else
#define GITSYNC_GIT2_VERSION 0
#endif

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
  "Apply error",
  "Content refused, waiting for a change"
};

/** Validate a file path contains only safe characters.
 * Allowed: alphanumeric, underscore, hyphen, dot, forward slash
 * @param path Path to validate
 * @return 1 if valid, 0 if contains unsafe characters
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
  /* Reject paths with .. to prevent directory traversal */
  if (strstr(path, ".."))
    return 0;
  return 1;
}

/** Find ssh-keygen on PATH, in the parent before a fork(): the child
 * then runs it with execv(), which is async-signal-safe (execlp()'s PATH
 * search is not).
 * @return Its path (a static buffer), or NULL if it is not on PATH.
 */
const char *
gitsync_ssh_keygen_path(void)
{
  static char path[1024];
  const char *env = getenv("PATH");
  const char *p, *q;

  if (!env || !*env)
    env = "/usr/bin:/bin";
  for (p = env; ; p = q + 1) {
    q = strchr(p, ':');
    if (!q)
      q = p + strlen(p);
    if (q > p) {
      ircd_snprintf(0, path, sizeof(path), "%.*s/ssh-keygen", (int)(q - p), p);
      if (0 == access(path, X_OK))
        return path;
    }
    if (!*q)
      return NULL;
  }
}

/** The descriptor limit, computed before a fork() for
 * gitsync_child_close_fds()'s fallback loop. */
int
gitsync_fd_limit(void)
{
  long n = sysconf(_SC_OPEN_MAX);

  return (n <= 0 || n > 1048576) ? 1048576 : (int) n;
}

/** In a child between fork() and exec(): close every descriptor above
 * stderr -- listeners, client sockets, database files, the log -- so
 * ssh-keygen gets none of the server's.  Async-signal-safe: closefrom()
 * where the C library has it, else close() on each up to \a limit.
 * @param limit gitsync_fd_limit(), from before the fork. */
void
gitsync_child_close_fds(int limit)
{
#ifdef HAVE_CLOSEFROM
  (void) limit;
  closefrom(STDERR_FILENO + 1);
#else
  int fd;

  for (fd = STDERR_FILENO + 1; fd < limit; fd++)
    close(fd);
#endif
}

/** Generate an Ed25519 SSH key for GitSync authentication using ssh-keygen
 * Uses fork/exec to avoid shell command injection vulnerabilities.
 * Uses atomic file creation to prevent TOCTOU race conditions.
 * @param key_path Path to save the private key (OpenSSH format)
 * @return 1 on success (including if key already exists), 0 on failure
 */
int
gitsync_generate_ssh_key(const char *key_path)
{
  char pubkey_path[512];
  char pubkey_line[512];
  FILE *fp;
  pid_t pid;
  int status;
  int fd;
  struct stat st;
  const char *keygen;
  int fd_limit;

  /* Validate path contains only safe characters */
  if (!validate_safe_path(key_path)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Invalid characters in key path: %s", key_path);
    return 0;
  }

  /* Atomic check: try to create the file with O_CREAT | O_EXCL | O_NOFOLLOW
   * This prevents TOCTOU race conditions and symlink attacks */
  fd = open(key_path, O_CREAT | O_EXCL | O_NOFOLLOW | O_WRONLY, 0600);
  if (fd < 0) {
    if (errno == EEXIST) {
      /* File already exists - check if it's a regular file (not a symlink) */
      if (lstat(key_path, &st) == 0) {
        if (S_ISLNK(st.st_mode)) {
          log_write(LS_SYSTEM, L_ERROR, 0,
                    "GitSync: SSH key path is a symlink (possible attack): %s", key_path);
          return 0;
        }
        if (S_ISREG(st.st_mode)) {
          /* Regular file exists - key already generated */
          return 1;
        }
      }
      log_write(LS_SYSTEM, L_ERROR, 0,
                "GitSync: SSH key path exists but is not a regular file: %s", key_path);
      return 0;
    }
#ifdef ELOOP
    if (errno == ELOOP) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "GitSync: SSH key path is a symlink (possible attack): %s", key_path);
      return 0;
    }
#endif
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Cannot create SSH key file: %s: %s", key_path, strerror(errno));
    return 0;
  }

  /* We successfully created a placeholder file atomically - remove it before ssh-keygen */
  close(fd);
  unlink(key_path);

  /* Use fork/exec to run ssh-keygen safely without shell.  Everything
   * the child needs is ready before the fork. */
  if (!(keygen = gitsync_ssh_keygen_path())) {
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: ssh-keygen not found on PATH");
    return 0;
  }
  fd_limit = gitsync_fd_limit();
  pid = fork();
  if (pid < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: fork() failed: %s", strerror(errno));
    return 0;
  }

  if (pid == 0) {
    /* Child process - exec ssh-keygen */
    /* Close stdin, redirect stdout/stderr to /dev/null for -q behavior */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
      dup2(devnull, STDIN_FILENO);
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      if (devnull > STDERR_FILENO)
        close(devnull);
    }

    gitsync_child_close_fds(fd_limit);
    execl(keygen, "ssh-keygen",
          "-t", "ed25519",
          "-f", key_path,
          "-N", "",
          "-C", "gitsync@nefarious",
          "-q",
          (char *)NULL);

    /* If exec fails, exit with error */
    _exit(127);
  }

  /* Parent process - wait for child */
  if (waitpid(pid, &status, 0) < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: waitpid() failed: %s", strerror(errno));
    return 0;
  }

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: ssh-keygen failed with exit code %d",
              WIFEXITED(status) ? WEXITSTATUS(status) : -1);
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
/** Track credential callback attempts to prevent infinite retry loops.
 * libgit2 calls the callback again after auth failure — if we already
 * provided credentials, there's no point retrying with the same key. */
static int gitsync_cred_attempts;

/** Why the credential callback gave up, for the failure it causes:
 * libgit2 reports a callback's refusal with no message of its own ("no
 * error").  Empty when it did not. */
static char gitsync_cred_failure[256];

/** The key and user the credential callback offered last. */
static char gitsync_cred_key[200];
static char gitsync_cred_user[64];

/** Write the failure of a libgit2 transfer into gitsync_stats.last_error:
 * the credential callback's reason when it gave up, else libgit2's
 * message, else its error code.
 * @param what "Clone" or "Fetch".
 * @param error The libgit2 return code.
 * @return Non-zero if it was an SSH authentication failure.
 */
static int
gitsync_transfer_error(const char *what, int error)
{
  const git_error *e = git_error_last();

  if (gitsync_cred_failure[0]) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "%s failed: %s", what, gitsync_cred_failure);
    return 1;
  }
  if (e && e->klass != GIT_ERROR_NONE && e->message && *e->message) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "%s failed: %s", what, e->message);
    return strstr(e->message, "authentication") || strstr(e->message, "SSH")
      || strstr(e->message, "key");
  }
  ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                "%s failed: libgit2 error %d, no message", what, error);
  return 0;
}

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

  /* If we already provided credentials and they failed, stop retrying */
  if (gitsync_cred_attempts > 0) {
    Debug((DEBUG_INFO, "GitSync: SSH auth failed, not retrying"));
    if (!gitsync_cred_failure[0])
      ircd_snprintf(0, gitsync_cred_failure, sizeof(gitsync_cred_failure),
                    "SSH authentication refused by the remote for user %s "
                    "with the key at %s", gitsync_cred_user,
                    gitsync_cred_key);
    return GIT_EUSER;
  }
  gitsync_cred_attempts++;

  ssh_key = feature_str(FEAT_GITSYNC_SSH_KEY);
  if (ssh_key && *ssh_key) {
    /* GITSYNC_SSH_KEY is set - use dedicated gitsync key */
    if (stat(ssh_key, &st) != 0) {
      /* Key file doesn't exist - generate it using ssh-keygen */
      Debug((DEBUG_INFO, "GitSync: SSH key %s not found, generating...", ssh_key));
      if (!gitsync_generate_ssh_key(ssh_key)) {
        ircd_snprintf(0, gitsync_cred_failure, sizeof(gitsync_cred_failure),
                      "cannot generate the SSH key at %s", ssh_key);
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
  /* Named if the remote refuses it (the callback is called again). */
  ircd_strncpy(gitsync_cred_key, ssh_key, sizeof(gitsync_cred_key));
  ircd_strncpy(gitsync_cred_user, username_from_url ? username_from_url
               : "git", sizeof(gitsync_cred_user));

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
 * @return 0 to accept an SSH host key, -1 to reject it; GIT_PASSTHROUGH
 *   (a negative code) for any other certificate, so that libgit2's own
 *   verification decides
 */
static int
gitsync_cert_callback(git_cert *cert, int valid, const char *host, void *payload)
{
  git_cert_hostkey *hostkey;
  char fingerprint[128];
  const char *configured_fp;
  const char *trusted_fp;

  (void)valid;   /* used by Debug() only */
  (void)payload;

  /* Only handle SSH host keys.  Any other certificate (an HTTPS remote's
   * X.509) is libgit2's to judge: GIT_PASSTHROUGH honours its own
   * verification.  (0 here meant "proceed" whatever that said: any
   * certificate was accepted.) */
  if (cert->cert_type != GIT_CERT_HOSTKEY_LIBSSH2) {
    Debug((DEBUG_INFO, "GitSync: Non-SSH certificate type %d (%s by libgit2)",
           cert->cert_type, valid ? "valid" : "not valid"));
    return GIT_PASSTHROUGH;
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
gitsync_clone(const char *repo_url, const char *local_path, const char *branch,
              git_repository **repo)
{
  git_clone_options clone_opts;
  int error;

  /* Initialize clone options - use runtime init for ABI compatibility */
  git_clone_options_init(&clone_opts, GIT_CLONE_OPTIONS_VERSION);
  git_fetch_options_init(&clone_opts.fetch_opts, GIT_FETCH_OPTIONS_VERSION);

  clone_opts.fetch_opts.callbacks.credentials = gitsync_cred_callback;
  clone_opts.fetch_opts.callbacks.certificate_check = gitsync_cert_callback;
  /* The configured branch, not the remote's default: the first sync
   * reads what a later fetch-and-reset would. */
  clone_opts.checkout_branch = branch;
  /* Nothing written to the working tree yet: the commit is checked first
   * (gitsync_first_clone()). */
  clone_opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_NONE;
  clone_opts.fetch_opts.proxy_opts.type = GIT_PROXY_NONE;

  Debug((DEBUG_INFO, "GitSync: Cloning %s to %s", repo_url, local_path));

  gitsync_cred_attempts = 0;
  gitsync_cred_failure[0] = '\0';
  error = git_clone(repo, repo_url, local_path, &clone_opts);
  if (error < 0)
    return gitsync_transfer_error("Clone", error) ? GITSYNC_SSH_ERROR
      : GITSYNC_CLONE_ERROR;

  return GITSYNC_OK;
}

/** The file inside a checkout that says GitSync cloned or adopted it and
 * may fetch into it and reset it; it holds the repository URL. */
#define GITSYNC_MARK ".git/gitsync-checkout"

/** Whether the checkout at \a path carries GitSync's mark: GitSync
 * cloned it, or adopted it with the configured origin, and may re-point
 * it when GITSYNC_REPOSITORY changes. */
static int
gitsync_checkout_marked(const char *path)
{
  char mark[1100];
  struct stat st;

  ircd_snprintf(0, mark, sizeof(mark), "%s/" GITSYNC_MARK, path);
  return 0 == lstat(mark, &st) && S_ISREG(st.st_mode);
}

/** Mark the checkout at \a path as GitSync's ("cloned <url>" for one its
 * clone made, "adopted <url>" for an existing checkout of the configured
 * repository it fetched into; the word is for the reader).
 * @return 0, or -1 (errno set). */
static int
gitsync_checkout_mark(const char *path, const char *word, const char *url)
{
  char mark[1100];
  int fd;
  ssize_t n = (ssize_t) strlen(url);
  ssize_t w = (ssize_t) strlen(word);

  ircd_snprintf(0, mark, sizeof(mark), "%s/" GITSYNC_MARK, path);
  fd = open(mark, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  if (fd < 0)
    return -1;
  if (write(fd, word, w) != w || write(fd, " ", 1) != 1
      || write(fd, url, n) != n || write(fd, "\n", 1) != 1) {
    close(fd);
    return -1;
  }
  return close(fd);
}

/** Make the checkout directory \a path 0700 -- the directory itself,
 * never what a link there points to.  It holds the configuration GitSync
 * pulls (and may hold the server's SSH key). */
static void
gitsync_checkout_private(const char *path)
{
  int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);

  if (fd < 0 || fchmod(fd, 0700) != 0)
    log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: cannot make the checkout "
              "%s 0700: %s", path, strerror(errno));
  if (fd >= 0)
    close(fd);
}

/** Remove \a path and, when it is a directory, what is in it: each entry
 * lstat()ed, a symbolic link unlinked, never followed.  A path that would
 * not fit the buffer stops the removal there (logged), never a cut one.
 * @return 0, or -1 if something stayed. */
static int
gitsync_remove_tree_at(const char *path)
{
  struct stat st;
  struct dirent *d;
  DIR *dir;
  char sub[1200];
  int ret = 0;

  if (lstat(path, &st) != 0)
    return errno == ENOENT ? 0 : -1;
  if (!S_ISDIR(st.st_mode))
    return unlink(path);
  if (!(dir = opendir(path)))
    return -1;
  while ((d = readdir(dir)))
    if (strcmp(d->d_name, ".") && strcmp(d->d_name, "..")) {
      if ((size_t) snprintf(sub, sizeof(sub), "%s/%s", path, d->d_name)
          >= sizeof(sub)) {
        log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: not removing %s/%s: "
                  "path too long", path, d->d_name);
        ret = -1;
        continue;
      }
      if (gitsync_remove_tree_at(sub) != 0)
        ret = -1;
    }
  closedir(dir);
  return rmdir(path) != 0 ? -1 : ret;
}

/** Remove the temporary directory a first clone made in THIS sync:
 * \a tmp_path, which mkdtemp() made as "<repo_path>.clone-XXXXXX" -- never
 * the checkout itself, nothing that existed before the sync. */
static void
gitsync_remove_clone_tmp(const char *repo_path, const char *tmp_path)
{
  size_t n = strlen(repo_path);

  assert(0 == strncmp(tmp_path, repo_path, n)
         && 0 == strncmp(tmp_path + n, ".clone-", 7));
  if (gitsync_remove_tree_at(tmp_path) != 0)
    log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: could not remove all of "
              "%s", tmp_path);
}

/** Whether directory \a path is empty. */
static int
gitsync_dir_empty(const char *path)
{
  struct dirent *d;
  DIR *dir = opendir(path);
  int empty = 1;

  if (!dir)
    return 0;
  while ((d = readdir(dir)))
    if (strcmp(d->d_name, ".") && strcmp(d->d_name, "..")) {
      empty = 0;
      break;
    }
  closedir(dir);
  return empty;
}

/** Payload of gitsync_mode_walk(). */
struct gitsync_mode_walk {
  char path[512];               /**< The first entry refused. */
  unsigned int mode;
};

/** git_tree_walk() callback: stop at the first entry that is not a
 * regular file or a tree. */
static int
gitsync_mode_walk(const char *root, const git_tree_entry *entry, void *payload)
{
  struct gitsync_mode_walk *w = payload;
  unsigned int mode = (unsigned int) git_tree_entry_filemode(entry);

  if (gitsync_filemode_allowed(mode))
    return 0;
  ircd_snprintf(0, w->path, sizeof(w->path), "%s%s", root,
                git_tree_entry_name(entry));
  w->mode = mode;
  return -1;
}

/** Refuse a commit whose tree holds anything but regular files
 * (100644/100755) and trees -- a symbolic link, a submodule: the
 * configuration repository needs none, and a link could make a checkout
 * write, or a read, go outside the tree.  The whole tree is walked.
 * @return 0, or -1 with gitsync_stats.last_error set. */
static int
gitsync_check_commit(git_object *commit)
{
  struct gitsync_mode_walk walk;
  git_tree *tree = NULL;

  if (git_commit_tree(&tree, (git_commit *) commit) < 0) {
    const git_error *e = git_error_last();

    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot read the commit's tree: %s",
                  e && e->message ? e->message : "unknown error");
    return -1;
  }
  walk.path[0] = '\0';
  git_tree_walk(tree, GIT_TREEWALK_PRE, gitsync_mode_walk, &walk);
  git_tree_free(tree);
  if (walk.path[0]) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "the repository contains %s at %s; not applied",
                  walk.mode == 0120000 ? "a symbolic link"
                  : walk.mode == 0160000 ? "a submodule"
                  : "an entry that is not a regular file", walk.path);
    return -1;
  }
  return 0;
}

/** Payload of gitsync_way_cb(). */
struct gitsync_in_the_way {
  int n;                        /**< Paths found. */
  char paths[300];              /**< The first few. */
  int nreplaced;                /**< Directories turned to files. */
  char replaced[16][512];
};

static void
gitsync_way_add(struct gitsync_in_the_way *w, const char *path)
{
  if (w->n < 3)
    ircd_snprintf(0, w->paths + strlen(w->paths),
                  sizeof(w->paths) - strlen(w->paths), "%s%s",
                  w->n ? ", " : "", path);
  w->n++;
}

/** Notify callback of the dry run.  libgit2 reports as a CONFLICT with no
 * baseline every untracked (and, with DONT_OVERWRITE_IGNORED, ignored)
 * path the commit would write over -- a directory where it needs a file,
 * or a file where it needs a directory, included.  A tracked directory
 * the commit turns into a file is reported UPDATED and untracked files in
 * it UNTRACKED: those are in the way too.  A CONFLICT with a baseline is a
 * tracked file modified locally: GitSync's own, reset as before. */
static int
gitsync_way_cb(git_checkout_notify_t why, const char *path,
               const git_diff_file *baseline, const git_diff_file *target,
               const git_diff_file *workdir, void *payload)
{
  struct gitsync_in_the_way *w = payload;
  int i;

  (void)workdir;
  if (why == GIT_CHECKOUT_NOTIFY_CONFLICT && !baseline)
    gitsync_way_add(w, path);
  else if (why == GIT_CHECKOUT_NOTIFY_UPDATED && baseline && target
           && baseline->mode == GIT_FILEMODE_TREE
           && target->mode != GIT_FILEMODE_TREE) {
    if (w->nreplaced < 16)
      ircd_strncpy(w->replaced[w->nreplaced], path, sizeof(w->replaced[0]));
    else
      gitsync_way_add(w, path);         /* too many to follow: refuse */
    w->nreplaced++;
  } else if (why == GIT_CHECKOUT_NOTIFY_UNTRACKED)
    for (i = 0; i < w->nreplaced && i < 16; i++)
      if (gitsync_path_under(path, w->replaced[i])) {
        gitsync_way_add(w, path);
        break;
      }
  return 0;
}

/** Dry-run a SAFE checkout of \a commit (GIT_CHECKOUT_SAFE |
 * GIT_CHECKOUT_DRY_RUN | GIT_CHECKOUT_DONT_OVERWRITE_IGNORED) and gather
 * what is in the way (gitsync_way_cb()) into \a w.
 * @return 0, or -1 with gitsync_stats.last_error set. */
static int
gitsync_dry_run(git_repository *repo, git_object *commit,
                struct gitsync_in_the_way *w)
{
  git_checkout_options opts;
  int error;

  memset(w, 0, sizeof(*w));
  git_checkout_options_init(&opts, GIT_CHECKOUT_OPTIONS_VERSION);
  opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_DRY_RUN
    | GIT_CHECKOUT_DONT_OVERWRITE_IGNORED;
  opts.notify_flags = GIT_CHECKOUT_NOTIFY_CONFLICT | GIT_CHECKOUT_NOTIFY_UPDATED
    | GIT_CHECKOUT_NOTIFY_UNTRACKED;
  opts.notify_cb = gitsync_way_cb;
  opts.notify_payload = w;
  error = git_checkout_tree(repo, commit, &opts);
  if (error < 0 && error != GIT_ECONFLICT && !w->n) {
    const git_error *e = git_error_last();

    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Checkout check failed: %s",
                  e && e->message ? e->message : "unknown error");
    return -1;
  }
  return 0;
}

/** git_stash_foreach() callback: the newest entry's id. */
static int
gitsync_stash_top_cb(size_t index, const char *message,
                     const git_oid *stash_id, void *payload)
{
  (void)message;
  if (index == 0)
    git_oid_cpy(payload, stash_id);
  return 1;                     /* the newest only */
}

/** A sync refused after it stashed the checkout's untracked files: put
 * them back (git_stash_pop() of entry 0, once it is checked to be the one
 * this sync made, \a stashed).  If they cannot be put back, the stash is
 * kept and the refusal says so, in the status and to the operators. */
static void
gitsync_unstash(git_repository *repo, const git_oid *stashed,
                const char *checkout)
{
  const git_error *e;
  const char *why = "it is no longer the newest stash entry";
  char reason[sizeof(gitsync_stats.last_error)];
  git_oid top;

  memset(&top, 0, sizeof(top));
  git_stash_foreach(repo, gitsync_stash_top_cb, &top);
  if (git_oid_equal(&top, stashed)) {
    if (git_stash_pop(repo, 0, NULL) == 0)
      return;
    e = git_error_last();
    why = (e && e->message) ? e->message : "unknown error";
  }
  /* What to do first, the refusal's own reason after it. */
  ircd_strncpy(reason, gitsync_stats.last_error, sizeof(reason));
  ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                "the update was not applied; the files moved to the stash "
                "could not be put back: run \"git -C %s stash pop\" (%s) -- %s",
                checkout, why, reason);
  log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: the update was not applied; "
            "the files moved to the stash could not be put back: run "
            "\"git -C %s stash pop\" (%s) -- %s", checkout, why, reason);
  sendto_opmask_butone(0, SNO_OLDSNO, "GitSync: the update was not applied; "
                       "the files moved to the stash of %s could not be put "
                       "back: run \"git -C %s stash pop\"", checkout, checkout);
}

/** A sync never destroys a file it did not put there: when a dry run finds
 * something untracked or ignored in the way of the update, the checkout's
 * untracked (and ignored) files -- all of them -- are moved to its git
 * stash (one entry, as "GitSync"), and the update proceeds.  If they
 * cannot be stashed, or something is still in the way afterwards (the
 * stash is then put back, gitsync_unstash()), the sync is refused and
 * nothing changes.  The hard reset that follows has only tracked files --
 * GitSync's -- to update.
 * @param[out] stashed The stash entry made, or all zero for none.
 * @return 0, or -1 with gitsync_stats.last_error set. */
static int
gitsync_clear_the_way(git_repository *repo, git_object *commit,
                      const char *checkout, git_oid *stashed)
{
  struct gitsync_in_the_way w;
  git_signature *sig = NULL;
  git_oid oid;
  char msg[200], when[32];
  time_t now = time(NULL);
  int error;

  memset(stashed, 0, sizeof(*stashed));
  if (gitsync_dry_run(repo, commit, &w))
    return -1;
  if (!w.n)
    return 0;                   /* a normal sync touches nothing untracked */

  strftime(when, sizeof(when), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
  ircd_snprintf(0, msg, sizeof(msg), "GitSync: files in the way of commit "
                "%.8s, %s", git_oid_tostr_s(git_object_id(commit)), when);
  error = git_signature_now(&sig, "GitSync", "gitsync@localhost");
  if (error == 0)
    error = git_stash_save(&oid, repo, sig, msg, GIT_STASH_INCLUDE_UNTRACKED
                           | GIT_STASH_INCLUDE_IGNORED);
  git_signature_free(sig);
  if (error < 0) {
    const git_error *e = git_error_last();

    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "commit %.8s would overwrite or remove %s%s in %s, which "
                  "GitSync did not put there, and the checkout cannot be "
                  "stashed (%s); not applied",
                  git_oid_tostr_s(git_object_id(commit)), w.paths,
                  w.n > 3 ? " and more" : "", checkout,
                  e && e->message ? e->message : "unknown error");
    return -1;
  }
  log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: %s%s (%d) in the way of commit "
            "%.8s: ALL untracked and ignored files in %s were moved to its "
            "git stash -- "
            "\"git -C %s stash list\" shows them, \"git -C %s stash pop\" "
            "puts them back", w.paths, w.n > 3 ? " ..." : "", w.n,
            git_oid_tostr_s(git_object_id(commit)), checkout, checkout,
            checkout);
  sendto_opmask_butone(0, SNO_OLDSNO, "GitSync: %s%s (%d) in the way of "
                       "commit %.8s: ALL untracked and ignored files in %s "
                       "were moved to its git stash -- \"git -C %s stash "
                       "pop\" puts them "
                       "back", w.paths, w.n > 3 ? " ..." : "", w.n,
                       git_oid_tostr_s(git_object_id(commit)), checkout,
                       checkout);

  git_oid_cpy(stashed, &oid);

  /* Still in the way (a case the stash does not clear): refuse, never
   * force -- with the stash put back. */
  if (gitsync_dry_run(repo, commit, &w) == 0) {
    if (!w.n)
      return 0;
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "commit %.8s would still overwrite or remove %s%s in %s "
                  "after stashing; not applied",
                  git_oid_tostr_s(git_object_id(commit)), w.paths,
                  w.n > 3 ? " and more" : "", checkout);
  }
  gitsync_unstash(repo, stashed, checkout);
  return -1;
}

/** git_stash_foreach() callback: count. */
static int
gitsync_stash_count_cb(size_t index, const char *message,
                       const git_oid *stash_id, void *payload)
{
  (void)index;
  (void)message;
  (void)stash_id;
  ++*(unsigned long *) payload;
  return 0;
}

/** The checkout's origin URL as its configuration spells it
 * (remote.origin.url, without url.<base>.insteadOf rewriting), copied
 * into \a buf ("" when it has none). */
static void
gitsync_origin_url(git_repository *repo, char *buf, size_t size)
{
  git_config *cfg = NULL;
  git_config *snap = NULL;
  const char *url = NULL;

  buf[0] = '\0';
  if (git_repository_config(&cfg, repo) < 0)
    return;
  if (git_config_snapshot(&snap, cfg) == 0
      && git_config_get_string(&url, snap, "remote.origin.url") == 0 && url)
    ircd_strncpy(buf, url, size);
  git_config_free(snap);
  git_config_free(cfg);
}

/** Note the checkout's HEAD commit as the commit synced. */
static void
gitsync_note_head(git_repository *repo)
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

/** First clone of \a repo_url for the checkout \a repo_path (resolved),
 * which does not exist or is an empty directory of the server's own:
 * into a fresh "<checkout>.clone-XXXXXX" (mkdtemp(), 0700) without
 * writing the working tree; the commit is checked (gitsync_check_commit())
 * and only then checked out (SAFE), the directory marked and renamed into
 * place (rename() replaces an empty directory).  A failed clone removes
 * only that temporary directory, made in this sync.
 * @param[out] repo The new checkout, open.
 * @return GITSYNC_OK, or an error (gitsync_stats.last_error set). */
static enum GitsyncStatus
gitsync_first_clone(const char *repo_url, const char *repo_path,
                    const char *branch, git_repository **repo)
{
  char tmp_path[1100];
  git_repository *fresh = NULL;
  git_object *head = NULL;
  git_checkout_options copts;
  enum GitsyncStatus status;
  int error;

  ircd_snprintf(0, tmp_path, sizeof(tmp_path), "%s.clone-XXXXXX", repo_path);
  if (!mkdtemp(tmp_path)) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot make a directory beside %s to clone into: %s",
                  repo_path, strerror(errno));
    return GITSYNC_CLONE_ERROR;
  }
  status = gitsync_clone(repo_url, tmp_path, branch, &fresh);
  if (status != GITSYNC_OK) {
    gitsync_remove_clone_tmp(repo_path, tmp_path);         /* made in this sync */
    return status;
  }
  if (git_revparse_single(&head, fresh, "HEAD") < 0
      || gitsync_check_commit(head) != 0) {
    if (!head)
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "The clone has no HEAD");
    git_object_free(head);
    git_repository_free(fresh);
    gitsync_remove_clone_tmp(repo_path, tmp_path);
    return GITSYNC_CHECKOUT_ERROR;
  }
  git_checkout_options_init(&copts, GIT_CHECKOUT_OPTIONS_VERSION);
  copts.checkout_strategy = GIT_CHECKOUT_SAFE;
  error = git_checkout_tree(fresh, head, &copts);
  git_object_free(head);
  git_repository_free(fresh);
  if (error < 0) {
    const git_error *e = git_error_last();

    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Checkout failed: %s", e && e->message ? e->message : "unknown error");
    gitsync_remove_clone_tmp(repo_path, tmp_path);
    return GITSYNC_CHECKOUT_ERROR;
  }
  gitsync_checkout_private(tmp_path);
  if (gitsync_checkout_mark(tmp_path, "cloned", repo_url) != 0
      || rename(tmp_path, repo_path) != 0) {      /* replaces an empty dir */
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot put the new checkout in place at %s: %s", repo_path,
                  strerror(errno));
    gitsync_remove_clone_tmp(repo_path, tmp_path);
    return GITSYNC_CLONE_ERROR;
  }
  error = git_repository_open(repo, repo_path);
  if (error < 0) {
    const git_error *e = git_error_last();

    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot open repository: %s", e ? e->message : "unknown error");
    return GITSYNC_CLONE_ERROR;
  }
  return GITSYNC_OK;
}

/** Fetch GITSYNC_REPOSITORY's branch into the checkout and reset to it.
 * The fetch goes to \a repo_url itself, through an anonymous remote made
 * without the checkout's url.<base>.insteadOf rewriting
 * (GIT_REMOTE_CREATE_SKIP_INSTEADOF) and without a proxy
 * (GIT_PROXY_NONE): whatever the checkout's .git/config says about
 * "origin", insteadOf or proxies does not redirect it.  The tip is what
 * this fetch wrote to refs/remotes/origin/<branch> (cleared first): a
 * repository without the branch fails the sync.  The commit is
 * checked (gitsync_check_commit()), and when something untracked is in
 * the way the checkout's untracked files go to its git stash
 * (gitsync_clear_the_way()); a refusal from either changes nothing.  Then a hard
 * reset: tracked files (GitSync's) are updated, other untracked ones stay
 * -- no clean ever runs; objects left behind stay in .git (no gc).
 * @param repo The checkout.
 * @param repo_url GITSYNC_REPOSITORY.
 * @param branch GITSYNC_BRANCH.
 * @param checkout Its directory, resolved.
 */
static enum GitsyncStatus
gitsync_fetch_and_reset(git_repository *repo, const char *repo_url,
                        const char *branch, const char *checkout)
{
  git_remote *remote = NULL;
  git_object *before = NULL;
  git_oid stashed;
  git_remote_create_options ropts;
  git_fetch_options fetch_opts;
  git_reference *ref = NULL;
  git_object *target = NULL;
  char refspec[1200], tracking[600];
  char *specs[1];
  git_strarray refspecs;
  int error;

  /* Initialize fetch options - use runtime init for ABI compatibility */
  git_fetch_options_init(&fetch_opts, GIT_FETCH_OPTIONS_VERSION);

  fetch_opts.callbacks.credentials = gitsync_cred_callback;
  fetch_opts.callbacks.certificate_check = gitsync_cert_callback;
  fetch_opts.proxy_opts.type = GIT_PROXY_NONE;
  /* Fetch all tags (equivalent to git fetch --tags) */
  fetch_opts.download_tags = GIT_REMOTE_DOWNLOAD_TAGS_ALL;

  git_remote_create_options_init(&ropts, GIT_REMOTE_CREATE_OPTIONS_VERSION);
  ropts.repository = repo;
  ropts.name = NULL;            /* anonymous: nothing read from the config */
  ropts.flags = GIT_REMOTE_CREATE_SKIP_INSTEADOF
    | GIT_REMOTE_CREATE_SKIP_DEFAULT_FETCHSPEC;
  error = git_remote_create_with_opts(&remote, repo_url, &ropts);
  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Remote setup failed: %s", e ? e->message : "unknown error");
    return GITSYNC_FETCH_ERROR;
  }

  /* The tip is what THIS fetch brings: a tracking ref left by an earlier
   * one (another repository, or a branch since deleted) goes first, so a
   * repository without the branch fails the sync instead of resetting to
   * a stale commit.  The checkout itself (HEAD) is not touched. */
  ircd_snprintf(0, tracking, sizeof(tracking), "refs/remotes/origin/%s", branch);
  if (git_reference_lookup(&ref, repo, tracking) == 0) {
    error = git_reference_delete(ref);
    git_reference_free(ref);
    ref = NULL;
    if (error < 0) {
      const git_error *e = git_error_last();
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "Cannot clear %s before the fetch: %s", tracking,
                    e ? e->message : "unknown error");
      git_remote_free(remote);
      return GITSYNC_FETCH_ERROR;
    }
  }

  ircd_snprintf(0, refspec, sizeof(refspec),
                "+refs/heads/%s:%s", branch, tracking);
  specs[0] = refspec;
  refspecs.strings = specs;
  refspecs.count = 1;

  Debug((DEBUG_INFO, "GitSync: Fetching %s (with tags)", branch));
  gitsync_cred_attempts = 0;
  gitsync_cred_failure[0] = '\0';
  error = git_remote_fetch(remote, &refspecs, &fetch_opts, "gitsync fetch");
  git_remote_free(remote);

  if (error < 0)
    return gitsync_transfer_error("Fetch", error) ? GITSYNC_SSH_ERROR
      : GITSYNC_FETCH_ERROR;

  /* Get reference to origin/branch, as this fetch wrote it */
  error = git_reference_lookup(&ref, repo, tracking);
  if (error == GIT_ENOTFOUND) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "branch %s not found in %s; not applied", branch, repo_url);
    return GITSYNC_FETCH_ERROR;
  }
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

  /* Nothing of the commit reaches the checkout before it is checked, and
   * a sync never overwrites a file it did not put there. */
  if (gitsync_check_commit(target)
      || gitsync_clear_the_way(repo, target, checkout, &stashed)) {
    git_object_free(target);
    return GITSYNC_CHECKOUT_ERROR;
  }

  /* Hard reset to origin/branch (unrelated histories too: no merge) */
  Debug((DEBUG_INFO, "GitSync: Resetting to %s", git_oid_tostr_s(git_object_id(target))));
  if (git_revparse_single(&before, repo, "HEAD") < 0)
    before = NULL;
  error = git_reset(repo, target, GIT_RESET_HARD, NULL);
  if (error >= 0)
    git_oid_tostr(gitsync_stats.last_commit, sizeof(gitsync_stats.last_commit),
                  git_object_id(target));
  git_object_free(target);

  if (error < 0) {
    const git_error *e = git_error_last();
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Reset failed: %s", e ? e->message : "unknown error");
    /* After a stash, the checkout as it was found: its tracked files back
     * from a reset that failed half way, then the stash on top of them. */
    if (!git_oid_is_zero(&stashed)) {
      if (before)
        git_reset(repo, before, GIT_RESET_HARD, NULL);
      gitsync_unstash(repo, &stashed, checkout);
    }
    git_object_free(before);
    return GITSYNC_CHECKOUT_ERROR;
  }

  git_object_free(before);
  return GITSYNC_OK;
}

/** Open the regular file \a rel of the checkout \a checkout (resolved)
 * for reading: it must resolve (realpath()) to a path inside the checkout
 * -- an untracked symbolic link put in place of a file or directory on the
 * way is not followed out of it -- and is opened with O_NOFOLLOW and
 * fstat()ed to be a regular file.
 * @param[out] st Its fstat().
 * @return The descriptor, or -1. */
static int
gitsync_open_in_checkout(const char *checkout, const char *rel,
                         struct stat *st)
{
  char path[1200], real[PATH_MAX];
  int fd;

  ircd_snprintf(0, path, sizeof(path), "%s/%s", checkout, rel);
  if (!realpath(path, real) || !gitsync_path_under(real, checkout)
      || !strcmp(real, checkout))
    return -1;
  if ((fd = open(real, O_RDONLY | O_NOFOLLOW)) < 0)
    return -1;
  if (fstat(fd, st) != 0 || !S_ISREG(st->st_mode)) {
    close(fd);
    return -1;
  }
  return fd;
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
  struct stat st;
  char *buf;
  ssize_t n;
  int fd;

  fd = gitsync_open_in_checkout(repo_path, "linesync.data", &st);
  if (fd < 0) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "linesync.data not found in repository (or not a regular "
                  "file there)");
    return GITSYNC_VALIDATION_ERROR;
  }

  if (st.st_size > GITSYNC_MAX_SIZE) {
    close(fd);
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "linesync.data too large (%ld bytes)", (long)st.st_size);
    return GITSYNC_VALIDATION_ERROR;
  }

  buf = (char *)MyMalloc(st.st_size + 1);
  n = read(fd, buf, st.st_size);
  close(fd);
  if (n < 0) {
    MyFree(buf);
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "Cannot read linesync.data: %s", strerror(errno));
    return GITSYNC_VALIDATION_ERROR;
  }

  *len = (size_t) n;
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
 * We store a hash of the last applied content (gitsync_content_hash():
 * every byte) to detect changes.
 */
static char gitsync_last_content_hash[GITSYNC_HASHLEN];

/** The hash of the content refused last (it did not parse and the backup
 * was restored): a periodic sync does not apply it again until it
 * changes; a forced one does. */
static char gitsync_refused_content_hash[GITSYNC_HASHLEN];

/** The file the content of gitsync_last_content_hash was written to. */
static char gitsync_last_content_file[512];

/** Set by gitsync_apply() when the sync in progress wrote new content
 * and rehashed with it. */
static int gitsync_applied;

/** Non-zero while gitsync_trigger() runs a sync. */
static int gitsync_running;

/** Open \a path for writing a file only the server's user may read:
 * created 0600, and an existing one truncated and made 0600 (fchmod, so
 * the umask does not matter and a looser file is tightened); a symbolic
 * link is not followed.
 * @return The open stream, or NULL (errno set).
 */
static FILE *
gitsync_open_private(const char *path)
{
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
  FILE *fp;

  if (fd < 0)
    return NULL;
  if (fchmod(fd, 0600) < 0 || !(fp = fdopen(fd, "w"))) {
    int err = errno;

    close(fd);
    errno = err;
    return NULL;
  }
  return fp;
}

/** Apply downloaded configuration
 * Writes to gitsync.conf and triggers a rehash only if content changed.
 * Uses safe write: writes to .new, backs up old to .bak, then renames.
 * If rehash fails, restores from backup.
 * @param content Configuration content
 * @param len Content length
 * @param force Non-zero to apply content refused before as well.
 * @param cptr The connection whose line asked for the sync (&me for the
 *   timer), handed to rehash() as m_rehash does: the new configuration
 *   can K-line it.
 * @param[out] killed Set to CPTR_KILLED when a rehash exited \a cptr;
 *   nothing may touch it then.
 * @return GITSYNC_OK on success (or unchanged content), GITSYNC_REFUSED
 *   for content refused before and not forced, an error code otherwise
 */
static enum GitsyncStatus
gitsync_apply(const char *content, size_t len, int force,
              struct Client *cptr, int *killed)
{
  const char *conf_file;
  FILE *fp;
  size_t written;
  char content_hash[GITSYNC_HASHLEN];
  char new_file[512];
  char bak_file[512];
  struct stat st;
  int had_backup = 0;

  conf_file = gitsync_conf_file();

  /* What was applied last counts only for the file it was written to,
   * and only while that file is there. */
  if (strcmp(conf_file, gitsync_last_content_file) || stat(conf_file, &st))
    gitsync_last_content_hash[0] = '\0';

  /* Check if content has changed */
  gitsync_content_hash(content, len, content_hash, sizeof(content_hash));
  switch (gitsync_content_verdict(content_hash, gitsync_last_content_hash,
                                  gitsync_refused_content_hash, force)) {
  case GITSYNC_CONTENT_UNCHANGED:
    Debug((DEBUG_INFO, "GitSync: Content unchanged, skipping write"));
    return GITSYNC_OK;
  case GITSYNC_CONTENT_REFUSED:
    /* Reported when it was refused; GITSYNC status still says so. */
    Debug((DEBUG_INFO, "GitSync: Content refused before, skipping write"));
    return GITSYNC_REFUSED;
  case GITSYNC_CONTENT_APPLY:
    break;
  }

  /* Build temp and backup filenames */
  ircd_snprintf(0, new_file, sizeof(new_file), "%s.new", conf_file);
  ircd_snprintf(0, bak_file, sizeof(bak_file), "%s.bak", conf_file);

  Debug((DEBUG_INFO, "GitSync: Writing %zu bytes to %s", len, conf_file));

  /* Write content to temp file first: the content holds link passwords,
   * so it (and the file it becomes) is the server's user's only. */
  fp = gitsync_open_private(new_file);
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
      chmod(bak_file, 0600);   /* whatever mode the old file had */
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

  /* Trigger a rehash to load the new configuration.  Its K-line pass can
   * exit the oper who asked (cptr): it says so only when told which
   * connection that is. */
  if (rehash(cptr, 0) == CPTR_KILLED)
    *killed = CPTR_KILLED;

  /* Check if config parsing failed */
  if (conf_get_error_flag()) {
    int abandoned = conf_rehash_abandoned();
    int clean = -1;
    const char *what = abandoned == CONF_ABANDON_OTHER
        ? "Rehash abandoned before the file was checked"
        : "Config parse error";

    sendto_opmask_butone(0, SNO_OLDSNO, "GitSync: %s, %s", what,
                         had_backup ? "restoring backup"
                         : "removing the new file (no previous file)");
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: %s, %s %s%s", what,
              had_backup ? "restoring" : "removing", conf_file,
              had_backup ? " from backup" : " (no previous file)");

    /* Back to the configuration as it was: the backup, or no file at all
     * when there was none (an include of it then reads as empty). */

    if (abandoned == CONF_ABANDON_OTHER) {
      /* The rehash read nothing of the file: it could not be read, or it
       * kept changing while it was checked.  Nothing is known of the
       * content, so it is put back as for any rehash that did not apply
       * and tried again at the next sync, never refused. */
      if (had_backup ? 0 == rename(bak_file, conf_file)
                     : 0 == unlink(conf_file))
        ircd_snprintf(0, gitsync_stats.last_error,
                      sizeof(gitsync_stats.last_error),
                      "Rehash with commit %.8s abandoned before the file was "
                      "checked (it could not be read, or kept changing); %s; "
                      "retried at the next sync", gitsync_stats.last_commit,
                      had_backup ? "restored from backup"
                      : "taken back (there was no previous file)");
      else
        ircd_snprintf(0, gitsync_stats.last_error,
                      sizeof(gitsync_stats.last_error),
                      "Rehash with commit %.8s abandoned - cannot %s %s: %s; "
                      "retried at the next sync", gitsync_stats.last_commit,
                      had_backup ? "restore the backup of" : "remove",
                      conf_file, strerror(errno));
    } else if (had_backup ? 0 == rename(bak_file, conf_file)
                          : 0 == unlink(conf_file)) {
      /* An abandoned rehash changed nothing: the running configuration
       * is the one from before it, so there is nothing to reload -- only
       * whether the configuration is clean without the content to learn,
       * which the check tells without a second full rehash. */
      if (abandoned)
        clean = conf_file_check();
      /* Otherwise, or if the check could not run, rehash again with the
       * restored config (never handing it a cptr the first one exited) */
      if (clean < 0) {
        if (rehash(*killed ? &me : cptr, 0) == CPTR_KILLED)
          *killed = CPTR_KILLED;
        clean = !conf_get_error_flag();
      }
      if (clean) {
        /* Clean without the content: the content is what failed.  Not
         * written and rehashed again by every periodic sync. */
        ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                      "Config parse error in commit %.8s - %s; not applied "
                      "again until the content changes",
                      gitsync_stats.last_commit, had_backup
                      ? "restored from backup"
                      : "taken back (there was no previous file; the include "
                        "now reads as empty)");
        ircd_strncpy(gitsync_refused_content_hash, content_hash,
                     sizeof(gitsync_refused_content_hash));
      } else {
        /* The configuration fails without the content too (a local
         * error, ircd.conf or another include): the content is not shown
         * to be at fault, and the next sync tries it again. */
        ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                      "Config parse error with commit %.8s, and with %s too: "
                      "the configuration has errors of its own; retried at "
                      "the next sync", gitsync_stats.last_commit, had_backup
                      ? "the backup restored"
                      : "it taken back (there was no previous file)");
      }
    } else {
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "Config parse error with commit %.8s - cannot %s %s: %s; "
                    "retried at the next sync", gitsync_stats.last_commit,
                    had_backup ? "restore the backup of" : "remove", conf_file,
                    strerror(errno));
    }
    return GITSYNC_VALIDATION_ERROR;
  }

  /* Success - remember hash and clean up backup */
  ircd_strncpy(gitsync_last_content_hash, content_hash,
               sizeof(gitsync_last_content_hash) - 1);
  ircd_strncpy(gitsync_last_content_file, conf_file,
               sizeof(gitsync_last_content_file));
  gitsync_refused_content_hash[0] = '\0';
  gitsync_applied = 1;

  /* Keep backup for safety, but could optionally delete it here */
  /* unlink(bak_file); */

  return GITSYNC_OK;
}

#ifdef USE_SSL
/** Whether PEM content holds a private key ("-----BEGIN ... PRIVATE KEY"). */
static int
gitsync_pem_has_key(const char *content, size_t size)
{
  static const char marker[] = "PRIVATE KEY-----";
  size_t n = sizeof(marker) - 1;
  size_t i;

  for (i = 0; i + n <= size; i++)
    if (content[i] == 'P' && !memcmp(content + i, marker, n))
      return 1;
  return 0;
}

/** Validate that content looks like a PEM certificate.
 * Checks for BEGIN/END markers and reasonable size.
 * Does NOT do full X.509 parsing — that's OpenSSL's job during ssl_reinit().
 * @param content Certificate content to validate
 * @param size Size of content in bytes
 * @return 1 if content appears to be valid PEM, 0 otherwise
 */
static int
gitsync_validate_pem(const char *content, size_t size)
{
  const char *p;

  if (!content || size < 100 || size > GITSYNC_MAX_SIZE)
    return 0;

  /* Skip leading whitespace */
  p = content;
  while (p < content + size && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
    p++;

  /* Must start with -----BEGIN */
  if (p + 10 > content + size || memcmp(p, "-----BEGIN", 10) != 0)
    return 0;

  /* Must contain at least one -----END marker */
  {
    size_t i;
    int found_end = 0;
    for (i = 0; i + 8 <= size; i++) {
      if (memcmp(content + i, "-----END", 8) == 0) {
        found_end = 1;
        break;
      }
    }
    if (!found_end)
      return 0;
  }

  return 1;
}

/** Install a certificate to disk atomically.
 * Writes to a temp file, preserves permissions, renames atomically.
 * Shared by both blob-tag and file-based cert update paths.
 * @param content Certificate PEM content
 * @param size Size of content in bytes
 * @param source_desc Human-readable description of cert source (for snomask)
 * @return 1 if certificate was updated, 0 if unchanged, -1 on error
 */
static int
gitsync_install_cert(const char *content, size_t size, const char *source_desc)
{
  const char *cert_file;
  char new_file[512];
  char bak_file[512];
  char *old_content = NULL;
  size_t old_size = 0;
  struct stat st;
  FILE *fp;
  int had_backup = 0;
  mode_t old_mode = 0600;

  /* Validate PEM content */
  if (!gitsync_validate_pem(content, size)) {
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "GitSync: Rejected invalid PEM certificate from %s", source_desc);
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Certificate from %s failed PEM validation", source_desc);
    return -1;
  }

  /* Resolve destination path */
  cert_file = feature_str(FEAT_GITSYNC_CERT_FILE);
  if (!cert_file || !*cert_file)
    cert_file = feature_str(FEAT_SSL_CERTFILE);

  /* Read existing cert for comparison */
  if (stat(cert_file, &st) == 0 && st.st_size > 0) {
    old_mode = st.st_mode & 0777;
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
  if (old_content && old_size == size &&
      memcmp(old_content, content, size) == 0) {
    MyFree(old_content);
    return 0;  /* Unchanged */
  }

  if (old_content)
    MyFree(old_content);

  /* Build temp and backup filenames */
  ircd_snprintf(0, new_file, sizeof(new_file), "%s.new", cert_file);
  ircd_snprintf(0, bak_file, sizeof(bak_file), "%s.backup", cert_file);

  /* Write to temp file (0600 until its mode is settled below) */
  fp = gitsync_open_private(new_file);
  if (!fp) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Cannot open %s for writing: %s", new_file, strerror(errno));
    return -1;
  }

  if (fwrite(content, 1, size, fp) != size) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Short write to %s", new_file);
    fclose(fp);
    unlink(new_file);
    return -1;
  }
  fclose(fp);

  /* Preserve permissions from existing cert (or 0600 default) -- but a
   * PEM with a private key in it is never group or world readable. */
  if (gitsync_pem_has_key(content, size))
    old_mode &= 0700;
  chmod(new_file, old_mode | 0600);

  /* Backup existing cert (it may hold the previous key: owner only) */
  if (stat(cert_file, &st) == 0) {
    unlink(bak_file);
    if (rename(cert_file, bak_file) == 0) {
      had_backup = 1;
      chmod(bak_file, 0600);
    }
  }

  /* Atomic rename */
  if (rename(new_file, cert_file) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Cannot rename %s to %s: %s", new_file, cert_file, strerror(errno));
    if (had_backup)
      rename(bak_file, cert_file);
    return -1;
  }

  sendto_opmask_butone(0, SNO_OLDSNO,
                       "GitSync: Updated TLS certificate from %s", source_desc);
  log_write(LS_SYSTEM, L_INFO, 0,
            "GitSync: Updated TLS certificate from %s", source_desc);

  /* Reload SSL certificates (0 = no extra snomask from ssl_reinit) */
  ssl_reinit(0);

  return 1;
}

/** Update TLS certificate from git blob tag (legacy mode).
 * Resolves a git tag to a blob object and installs the cert atomically.
 * @param repo Repository
 * @param tag_name Name of tag containing certificate blob
 * @return 1 if certificate was updated, 0 otherwise
 */
static int
gitsync_update_cert(git_repository *repo, const char *tag_name)
{
  git_object *obj = NULL;
  const git_blob *blob = NULL;
  const char *cert_content;
  size_t cert_size;
  int result;
  int error;
  char refspec[256];
  char source_desc[128];

  /* Look up the tag */
  ircd_snprintf(0, refspec, sizeof(refspec), "refs/tags/%s", tag_name);
  error = git_revparse_single(&obj, repo, refspec);
  if (error < 0) {
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

  /* Must be a blob */
  if (git_object_type(obj) != GIT_OBJECT_BLOB) {
    Debug((DEBUG_INFO, "GitSync: Tag %s is not a blob (type %d)",
           tag_name, git_object_type(obj)));
    git_object_free(obj);
    return 0;
  }

  blob = (const git_blob *)obj;
  cert_content = (const char *)git_blob_rawcontent(blob);
  cert_size = git_blob_rawsize(blob);

  ircd_snprintf(0, source_desc, sizeof(source_desc), "tag %s", tag_name);
  result = gitsync_install_cert(cert_content, cert_size, source_desc);

  git_object_free(obj);
  return (result > 0) ? 1 : 0;
}

/** Update TLS certificate from a file in the repository working tree.
 * Reads the cert from <repo_path>/<cert_path> after fetch+reset.
 * @param repo_path Path to the local git repository
 * @param cert_path Relative path to cert file within the repository
 * @return 1 if certificate was updated, 0 otherwise
 */
static int
gitsync_update_cert_from_file(const char *repo_path, const char *cert_path)
{
  struct stat st;
  char *content;
  ssize_t n;
  size_t nread;
  char source_desc[128];
  int result;
  int fd;

  fd = gitsync_open_in_checkout(repo_path, cert_path, &st);
  if (fd < 0 || st.st_size == 0) {
    if (fd >= 0)
      close(fd);
    Debug((DEBUG_INFO, "GitSync: Cert file %s not found in repo", cert_path));
    return 0;
  }

  if ((size_t)st.st_size > GITSYNC_MAX_SIZE) {
    close(fd);
    log_write(LS_SYSTEM, L_ERROR, 0,
              "GitSync: Cert file %s too large (%ld bytes)", cert_path, (long)st.st_size);
    return 0;
  }

  content = (char *)MyMalloc(st.st_size + 1);
  n = read(fd, content, st.st_size);
  close(fd);
  if (n < 0) {
    MyFree(content);
    log_write(LS_SYSTEM, L_ERROR, 0, "GitSync: Cannot read cert file %s: %s",
              cert_path, strerror(errno));
    return 0;
  }
  nread = (size_t) n;
  content[nread] = '\0';

  ircd_snprintf(0, source_desc, sizeof(source_desc), "file %s", cert_path);
  result = gitsync_install_cert(content, nread, source_desc);

  MyFree(content);
  return (result > 0) ? 1 : 0;
}
#endif /* USE_SSL */

/** The file GitSync writes the configuration it pulls into (and the
 * operator's ircd.conf includes): GITSYNC_CONF_FILE, or "gitsync.conf"
 * when that is empty.
 * @return The name, as configured.
 */
const char *
gitsync_conf_file(void)
{
  const char *conf_file = feature_str(FEAT_GITSYNC_CONF_FILE);

  return (conf_file && *conf_file) ? conf_file : "gitsync.conf";
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

/** Feature \a feat, in seconds, as libgit2's milliseconds: 0 (the system
 * default) for 0 or less, at most a day. */
static int
gitsync_timeout_ms(enum Feature feat)
{
  int secs = feature_int(feat);

  if (secs <= 0)
    return 0;
  if (secs > 86400)
    secs = 86400;
  return secs * 1000;
}

/** Bound what a sync may wait for the remote: GITSYNC_CONNECT_TIMEOUT
 * for a connection, GITSYNC_TIMEOUT for each read or write.  The sync
 * runs in the main loop; without them a remote that accepts and never
 * answers, or drops the connection attempt, holds the server for as long
 * as the system lets it (minutes) or for ever.  libgit2 1.7 and later
 * only; older libraries keep their defaults.
 *
 * Not bounded: an SSH server that accepts and never answers.  libgit2
 * (1.9, libssh2 transport) hands the I/O timeout to libssh2, whose
 * handshake gives up after it, but calls the handshake again while it
 * reports a timeout, so the sync waits for as long as the server holds
 * the connection.  Only running the sync outside the main loop bounds
 * that. */
static void
gitsync_set_timeouts(void)
{
#if GITSYNC_GIT2_VERSION >= 107
  git_libgit2_opts(GIT_OPT_SET_SERVER_CONNECT_TIMEOUT,
                   gitsync_timeout_ms(FEAT_GITSYNC_CONNECT_TIMEOUT));
  git_libgit2_opts(GIT_OPT_SET_SERVER_TIMEOUT,
                   gitsync_timeout_ms(FEAT_GITSYNC_TIMEOUT));
#endif
}

/** The CA file loaded into libgit2 last ("" for none). */
static char gitsync_ca_loaded[512];

/** Load GITSYNC_CA_FILE as the certificate authorities an HTTPS remote's
 * certificate may be signed by, when it is set and changed.  libgit2's
 * TLS backend decides what that means: with mbedTLS (Debian's build) the
 * file replaces the system's list (SSL_CERT_FILE and SSL_CERT_DIR are
 * not read), with OpenSSL it adds to it.  Emptying the feature again
 * keeps the file loaded until a restart. */
static void
gitsync_set_ca_file(void)
{
  const char *ca = feature_str(FEAT_GITSYNC_CA_FILE);

  if (!ca || !*ca || !strcmp(ca, gitsync_ca_loaded))
    return;
  if (git_libgit2_opts(GIT_OPT_SET_SSL_CERT_LOCATIONS, ca, NULL) < 0) {
    const git_error *e = git_error_last();

    log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: cannot load the CA file "
              "%s: %s", ca, e && e->message ? e->message : "unknown error");
    sendto_opmask_butone(0, SNO_OLDSNO, "GitSync: cannot load the CA file "
                         "%s: %s", ca, e && e->message ? e->message
                         : "unknown error");
    return;
  }
  ircd_strncpy(gitsync_ca_loaded, ca, sizeof(gitsync_ca_loaded));
}

/** Run a sync.
 * @param cptr The connection whose line asked for it (&me for the timer).
 * @param sptr The oper who asked (NULL for the timer), told how it went.
 * @param force Sync even if the interval has not elapsed.
 * @param[out] killed Set to CPTR_KILLED when the sync's rehash exited
 *   \a cptr; nothing may touch it (or \a sptr, the same client then).
 * @return The sync's status.
 */
static enum GitsyncStatus
gitsync_run(struct Client *cptr, struct Client *sptr, int force, int *killed)
{
  const char *repo_url;
  const char *branch;
  char repo_path[1024];
  git_repository *repo = NULL;
  char *content = NULL;
  size_t len = 0;
  enum GitsyncStatus status = GITSYNC_OK;
  time_t now = CurrentTime;
  char local_path[512];
  const char *why;
  int interval;
  int error;

  gitsync_stats.last_attempt = now;
  gitsync_applied = 0;

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

  /* Get paths: the checkout directory, resolved (symbolic links
   * followed) and judged before anything touches it; everything below
   * uses the resolved path.  (Between this check and libgit2's use of the
   * path, a component an attacker could write to could still be swapped
   * for a link: the parents of GITSYNC_LOCAL_PATH must be the server's.) */
  gitsync_get_repo_path(local_path, sizeof(local_path));
  if ((why = gitsync_local_path_check(local_path, repo_path,
                                      sizeof(repo_path)))) {
    ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                  "GITSYNC_LOCAL_PATH %s %s: refused", local_path, why);
    gitsync_stats.failures++;
    gitsync_stats.last_status = GITSYNC_CLONE_ERROR;
    if (sptr)
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync failed: %s",
                    sptr, gitsync_stats.last_error);
    return GITSYNC_CLONE_ERROR;
  }
  branch = feature_str(FEAT_GITSYNC_BRANCH);
  if (!branch || !*branch)
    branch = "master";

  /* Initialize libgit2 if needed */
  if (!git_initialized) {
    git_libgit2_init();
    git_initialized = 1;
  }

  gitsync_set_timeouts();
  gitsync_set_ca_file();

  /* The checkout.  GitSync never deletes or replaces an existing
   * directory: a missing or empty one gets a first clone; a git
   * repository is fetched into and reset (a changed GITSYNC_REPOSITORY
   * re-points it in place) when its origin is the configured repository
   * or it is marked as GitSync's, and is left alone otherwise; anything
   * else is refused.  (libgit2's owner validation, on by default, refuses
   * to open a repository another user owns.) */
  {
    struct stat st;
    int exists = (0 == lstat(repo_path, &st));

    if (exists && !S_ISDIR(st.st_mode)) {
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "%s exists and is not a directory; not touched", repo_path);
      status = GITSYNC_CLONE_ERROR;
    } else if (!exists || gitsync_dir_empty(repo_path)) {
      status = gitsync_first_clone(repo_url, repo_path, branch, &repo);
      if (status == GITSYNC_OK)
        gitsync_note_head(repo);
    } else if (git_repository_open_ext(&repo, repo_path,
                                       GIT_REPOSITORY_OPEN_NO_SEARCH,
                                       NULL) < 0) {
      const git_error *e = git_error_last();

      repo = NULL;
      ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                    "%s exists and is not a GitSync checkout (%s); not "
                    "touched", repo_path,
                    e && e->message ? e->message : "not a git repository");
      status = GITSYNC_CLONE_ERROR;
    } else {
      char old_url[512];

      gitsync_origin_url(repo, old_url, sizeof(old_url));
      switch (gitsync_checkout_action(0 == strcmp(old_url, repo_url),
                                      gitsync_checkout_marked(repo_path))) {
      case GITSYNC_CHECKOUT_FETCH:
        gitsync_checkout_private(repo_path);
        status = gitsync_fetch_and_reset(repo, repo_url, branch, repo_path);
        break;
      case GITSYNC_CHECKOUT_FETCH_ADOPT:
        status = gitsync_fetch_and_reset(repo, repo_url, branch, repo_path);
        if (status == GITSYNC_OK
            && gitsync_checkout_mark(repo_path, "adopted", repo_url) == 0)
          gitsync_checkout_private(repo_path);
        break;
      case GITSYNC_CHECKOUT_REPOINT:
        /* GITSYNC_REPOSITORY changed: point origin at it (for the record;
         * the fetch goes to the configured URL anyway), fetch, reset -- in
         * place; untracked files stay.  On any failure the old URL goes
         * back and the working tree is as it was. */
        if (git_remote_set_url(repo, "origin", repo_url) < 0) {
          const git_error *e = git_error_last();

          ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                        "Cannot set origin: %s", e ? e->message : "unknown error");
          status = GITSYNC_FETCH_ERROR;
          break;
        }
        status = gitsync_fetch_and_reset(repo, repo_url, branch, repo_path);
        if (status != GITSYNC_OK) {
          git_remote_set_url(repo, "origin", old_url);
          ircd_snprintf(0, gitsync_stats.last_error + strlen(gitsync_stats.last_error),
                        sizeof(gitsync_stats.last_error) - strlen(gitsync_stats.last_error),
                        " (GITSYNC_REPOSITORY changed: origin put back; the "
                        "checkout and the configuration in force are "
                        "unchanged)");
        } else {
          gitsync_checkout_mark(repo_path, "cloned", repo_url);
          gitsync_checkout_private(repo_path);
          log_write(LS_SYSTEM, L_NOTICE, 0, "GitSync: GITSYNC_REPOSITORY "
                    "changed: the checkout %s now follows it", repo_path);
          sendto_opmask_butone(0, SNO_OLDSNO, "GitSync: GITSYNC_REPOSITORY "
                               "changed: the checkout %s now follows it",
                               repo_path);
        }
        break;
      case GITSYNC_CHECKOUT_REFUSE_FOREIGN:
        ircd_snprintf(0, gitsync_stats.last_error, sizeof(gitsync_stats.last_error),
                      "%s is not a GitSync checkout (a repository of another "
                      "origin); not touched -- move it away or point "
                      "GITSYNC_LOCAL_PATH elsewhere", repo_path);
        status = GITSYNC_CLONE_ERROR;
        break;
      }
    }
    if (status != GITSYNC_OK) {
      if (repo)
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

  /* Check for certificate update */
#ifdef USE_SSL
  {
    const char *cert_tag = feature_str(FEAT_GITSYNC_CERT_TAG);
    const char *cert_path = feature_str(FEAT_GITSYNC_CERT_PATH);
    if (cert_tag && *cert_tag) {
      gitsync_update_cert(repo, cert_tag);           /* Legacy blob-tag mode */
    } else if (cert_path && *cert_path) {
      gitsync_update_cert_from_file(repo_path, cert_path);  /* File-based mode */
    }
  }
#endif

  /* Read linesync.data */
  status = gitsync_read_data(repo_path, &content, &len);
  gitsync_stats.stash_entries = 0;
  git_stash_foreach(repo, gitsync_stash_count_cb, &gitsync_stats.stash_entries);
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
  status = gitsync_apply(content, len, force, cptr, killed);
  MyFree(content);
  if (*killed && sptr == cptr)
    sptr = NULL;   /* its own ban exited it: nobody to tell */

  if (status == GITSYNC_REFUSED) {
    /* The content refused before, unchanged: not a new failure.  The
     * error that refused it stands in GITSYNC status. */
    if (sptr)
      sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :GitSync: %s", sptr,
                    gitsync_stats.last_error);
  } else if (status == GITSYNC_OK) {
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

int
gitsync_trigger(struct Client *cptr, struct Client *sptr, int force)
{
  int killed = 0;
  enum GitsyncStatus status;

  gitsync_running = 1;
  status = gitsync_run(cptr, sptr, force, &killed);
  gitsync_running = 0;

  /* A sync nobody asked for -- the immediate one when GitSync starts or
   * its file was replaced by a placeholder, or a periodic one -- says
   * what it did in the log: new content applied
   * (operators were told "Wrote ..., rehashing"), or a failure and why
   * (operators are told too, as the oper who asks for one is).  Nothing
   * for unchanged content, for content refused before, or when it was
   * not yet time. */
  if (!sptr) {
    const char *kind = force ? "Immediate sync" : "Periodic sync";

    if (status == GITSYNC_OK) {
      if (gitsync_applied)
        log_write(LS_SYSTEM, L_NOTICE, 0, "GitSync: %s applied commit "
                  "%.8s to %s", kind, gitsync_stats.last_commit,
                  gitsync_conf_file());
    } else if (status != GITSYNC_REFUSED && status != GITSYNC_DISABLED) {
      log_write(LS_SYSTEM, L_WARNING, 0, "GitSync: %s failed (%s): %s",
                kind, gitsync_status_str(status), gitsync_stats.last_error);
      sendto_opmask_butone(0, SNO_OLDSNO, "GitSync: %s failed (%s): %s",
                           kind, gitsync_status_str(status),
                           gitsync_stats.last_error);
    }
  }

  /* libssh2 runs on OpenSSL's libcrypto and leaves errors on this
   * thread's queue: it reads an OpenSSH-format key through OpenSSL's PEM
   * decoder first, which fails ("DECODER routines::unsupported").  A TLS
   * link's next would-block write then read it as its own SSL_ERROR_SSL
   * and the link dropped; the periodic sync shares its timer second with
   * the chathistory purge, whose stall makes that backlog
   * (ssl_clear_errors() in ssl.c).  Leave nothing behind. */
  ERR_clear_error();
  return killed;
}

/** Forget the content applied last: the next sync writes and rehashes
 * whatever it pulls (GitSync starting again, or its file replaced by a
 * placeholder). */
void
gitsync_forget_applied(void)
{
  gitsync_last_content_hash[0] = '\0';
}

/** @return Non-zero while a sync runs (its rehash among it). */
int
gitsync_busy(void)
{
  return gitsync_running;
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
