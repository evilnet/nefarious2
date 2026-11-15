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
 * Pure: no libgit2, no ircd state, so the CMocka suite links it alone.
 */
#include "config.h"

#include "gitsync_content.h"

#include <stdio.h>
#include <string.h>

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
