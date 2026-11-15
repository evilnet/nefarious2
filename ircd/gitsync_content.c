/*
 * IRC - Internet Relay Chat, ircd/gitsync_content.c
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
 * @brief GitSync - what a sync does with the content it pulled.
 *
 * No libgit2, no ircd state (path resolution reads the filesystem), so
 * the CMocka suite links it alone.
 */
#include "config.h"

#include "gitsync_content.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

/** Hash content for change detection: its length and the 64-bit FNV-1a
 * hash of every byte.  Not a defence against anyone choosing content (the
 * repository is trusted); it only has to change when the content does,
 * wherever the change is, and be cheap for a file of up to a megabyte.
 * @param[in] content The content.
 * @param[in] len Its length.
 * @param[out] hash Where to write the hash (GITSYNC_HASHLEN bytes).
 * @param[in] hashlen Size of \a hash.
 */
void
gitsync_content_hash(const char *content, size_t len, char *hash,
                     size_t hashlen)
{
  unsigned long long h = 14695981039346656037ULL;      /* FNV offset basis */
  size_t i;

  for (i = 0; i < len; i++) {
    h ^= (unsigned char) content[i];
    h *= 1099511628211ULL;                             /* FNV prime */
  }
  snprintf(hash, hashlen, "%lx-%016llx", (unsigned long) len, h);
}

/** What a sync does with the content it pulled.
 * @param[in] hash gitsync_content_hash() of the content.
 * @param[in] applied The hash of the content applied last ("" for none).
 * @param[in] refused The hash of the content refused last -- it did not
 *   parse and the backup was restored -- ("" for none).
 * @param[in] force Non-zero for a forced sync (an operator's GITSYNC
 *   force, or the first sync after GitSync starts).
 * @return GITSYNC_CONTENT_UNCHANGED for the content applied last, forced
 *   or not; GITSYNC_CONTENT_REFUSED for the content refused last, unless
 *   forced; GITSYNC_CONTENT_APPLY otherwise.
 */
enum GitsyncContentVerdict
gitsync_content_verdict(const char *hash, const char *applied,
                        const char *refused, int force)
{
  if (applied[0] && 0 == strcmp(hash, applied))
    return GITSYNC_CONTENT_UNCHANGED;
  if (!force && refused[0] && 0 == strcmp(hash, refused))
    return GITSYNC_CONTENT_REFUSED;
  return GITSYNC_CONTENT_APPLY;
}

/** Spell \a name as an absolute path: a relative name is taken against
 * \a cwd, "." components and repeated slashes are dropped.  ".." and
 * symbolic links are left as they are (a ".." name is refused before
 * anything relies on this).
 * @return 0, or -1 if it does not fit in \a size.
 */
int
gitsync_path_spell(const char *name, const char *cwd, char *buf, size_t size)
{
  const char *parts[2];
  size_t len = 0;
  int i;

  parts[0] = (name[0] == '/') ? "" : cwd;
  parts[1] = name;
  for (i = 0; i < 2; i++) {
    const char *p = parts[i];

    while (*p) {
      const char *q;
      size_t n;

      while (*p == '/')
        p++;
      for (q = p; *q && *q != '/'; q++)
        ;
      n = q - p;
      if (n && !(n == 1 && p[0] == '.')) {
        if (len + 1 + n + 1 > size)
          return -1;
        buf[len++] = '/';
        memcpy(buf + len, p, n);
        len += n;
      }
      p = q;
    }
  }
  if (len + 2 > size)
    return -1;
  if (len == 0)
    buf[len++] = '/';
  buf[len] = '\0';
  return 0;
}

/** Whether spelt path \a path is \a dir or lies below it (by whole
 * components: "/a/bc" is not below "/a/b"). */
int
gitsync_path_under(const char *path, const char *dir)
{
  size_t n = strlen(dir);

  if (n == 1 && dir[0] == '/')
    return 1;
  return 0 == strncmp(path, dir, n) && (path[n] == '\0' || path[n] == '/');
}

/** Resolve \a name as the filesystem has it now: realpath() of it when
 * it exists, else realpath() of its parent plus its last component.
 * @return 0; -1 when it (or its parent) cannot be resolved; -2 when its
 *   last component is itself a symbolic link (dangling or not): what it
 *   names could be changed after any check. */
int
gitsync_path_resolve(const char *name, char *out, size_t size)
{
  char buf[PATH_MAX], parent[PATH_MAX], rp[PATH_MAX];
  const char *last;
  struct stat st;
  size_t n;

  if (!name || !*name || strlen(name) >= sizeof(buf))
    return -1;
  strcpy(buf, name);
  n = strlen(buf);
  while (n > 1 && buf[n - 1] == '/')
    buf[--n] = '\0';
  if (0 == lstat(buf, &st) && S_ISLNK(st.st_mode))
    return -2;
  if (realpath(buf, rp)) {
    if (strlen(rp) + 1 > size)
      return -1;
    strcpy(out, rp);
    return 0;
  }
  if (errno != ENOENT)
    return -1;
  last = strrchr(buf, '/');
  if (last) {
    size_t pl = (size_t) (last - buf);

    memcpy(parent, buf, pl ? pl : 1);
    parent[pl ? pl : 1] = '\0';
    last++;
  } else {
    strcpy(parent, ".");
    last = buf;
  }
  if (!*last || !strcmp(last, ".") || !strcmp(last, "..")
      || !realpath(parent, rp))
    return -1;
  if (strlen(rp) + 1 + strlen(last) + 1 > size)
    return -1;
  if (!strcmp(rp, "/"))
    snprintf(out, size, "/%s", last);
  else
    snprintf(out, size, "%s/%s", rp, last);
  return 0;
}

/** Why GITSYNC_LOCAL_PATH must not be used for a checkout, or NULL when it
 * may.  A sync clones into it and makes it 0700: it must not be empty,
 * the root, or the server's working directory or one of its parents
 * (nothing is ever deleted; a directory holding ircd.conf, the SSH key or
 * other files of the server is fine).  Judged on \a resolved -- the path
 * the filesystem gives (gitsync_local_path_check()), so a symbolic link in
 * it counts as what it reaches.
 * @param local_path The feature's value.
 * @param resolved It, resolved and absolute (NULL: characters only).
 * @param cwd The server's working directory, resolved.
 * @return NULL, or the reason (for "GITSYNC_LOCAL_PATH <value> <reason>").
 */
const char *
gitsync_local_path_refusal(const char *local_path, const char *resolved,
                           const char *cwd)
{
  if (!local_path || !*local_path)
    return "is empty";
  if (!resolved)
    return NULL;
  if (!strcmp(resolved, "/"))
    return "is the root directory";
  if (gitsync_path_under(cwd, resolved))
    return "is the server's directory or one of its parents";
  return NULL;
}

/** Resolve GITSYNC_LOCAL_PATH and judge it (gitsync_local_path_refusal())
 * against the resolved working directory.  Its last component may not be
 * a symbolic link.
 * @param local_path The feature's value.
 * @param[out] resolved Where to write the resolved path, for every use.
 * @param size Its size.
 * @return NULL (use \a resolved), or the reason it is refused.
 */
const char *
gitsync_local_path_check(const char *local_path, char *resolved, size_t size)
{
  char cwd[PATH_MAX], here[PATH_MAX];
  const char *why;
  int r;

  if ((why = gitsync_local_path_refusal(local_path, NULL, NULL)))
    return why;                 /* empty */
  if (!getcwd(here, sizeof(here)) || !realpath(here, cwd))
    return "cannot be checked (the working directory cannot be resolved)";
  if ((r = gitsync_path_resolve(local_path, resolved, size)) == -2)
    return "is a symbolic link";
  if (r < 0)
    return "cannot be resolved (a missing or unreadable parent directory)";
  return gitsync_local_path_refusal(local_path, resolved, cwd);
}

/** What a sync does with an existing checkout (see enum
 * GitsyncCheckoutAction).
 * @param origin_matches Its origin URL is GITSYNC_REPOSITORY.
 * @param marked It carries GitSync's mark (GitSync cloned or adopted it).
 */
enum GitsyncCheckoutAction
gitsync_checkout_action(int origin_matches, int marked)
{
  if (origin_matches)
    return marked ? GITSYNC_CHECKOUT_FETCH : GITSYNC_CHECKOUT_FETCH_ADOPT;
  return marked ? GITSYNC_CHECKOUT_REPOINT : GITSYNC_CHECKOUT_REFUSE_FOREIGN;
}

/** Whether a tree entry mode is one a configuration repository may have:
 * a regular file (0100644, 0100755) or a tree (040000) -- not a symbolic
 * link (0120000), a submodule (0160000) or anything else. */
int
gitsync_filemode_allowed(unsigned int mode)
{
  return mode == 0100644 || mode == 0100755 || mode == 0040000;
}
