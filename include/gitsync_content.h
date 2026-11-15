/*
 * IRC - Internet Relay Chat, include/gitsync_content.h
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
 * @brief GitSync - what a sync does with the content it pulled (pure).
 */
#ifndef INCLUDED_gitsync_content_h
#define INCLUDED_gitsync_content_h

#include <stddef.h>

/** Size of a buffer for gitsync_content_hash(). */
#define GITSYNC_HASHLEN 64

/** What a sync does with content it pulled. */
enum GitsyncContentVerdict {
  GITSYNC_CONTENT_APPLY,       /**< Write it and rehash. */
  GITSYNC_CONTENT_UNCHANGED,   /**< It is what was applied last: nothing. */
  GITSYNC_CONTENT_REFUSED      /**< It is what was refused last: nothing. */
};

extern void gitsync_content_hash(const char *content, size_t len,
                                 char *hash, size_t hashlen);

extern enum GitsyncContentVerdict
gitsync_content_verdict(const char *hash, const char *applied,
                        const char *refused, int force);

/** What a sync does with an existing checkout (a git repository at
 * GITSYNC_LOCAL_PATH).  Nothing is ever deleted or replaced. */
enum GitsyncCheckoutAction {
  GITSYNC_CHECKOUT_FETCH,          /**< GitSync's, origin as configured:
                                        fetch and reset. */
  GITSYNC_CHECKOUT_FETCH_ADOPT,    /**< Unmarked, origin as configured (a
                                        checkout an older build or the
                                        operator made): fetch, reset, mark. */
  GITSYNC_CHECKOUT_REPOINT,        /**< GitSync's, another origin
                                        (GITSYNC_REPOSITORY changed): set
                                        origin, fetch, reset -- in place. */
  GITSYNC_CHECKOUT_REFUSE_FOREIGN  /**< Unmarked, another origin: someone
                                        else's repository; touch nothing. */
};

extern int gitsync_path_spell(const char *name, const char *cwd, char *buf,
                              size_t size);
extern int gitsync_path_under(const char *path, const char *dir);
extern int gitsync_path_resolve(const char *name, char *out, size_t size);
extern const char *gitsync_local_path_refusal(const char *local_path,
                                              const char *resolved,
                                              const char *cwd);
extern const char *gitsync_local_path_check(const char *local_path,
                                            char *resolved, size_t size);
extern enum GitsyncCheckoutAction
gitsync_checkout_action(int origin_matches, int marked);

extern int gitsync_filemode_allowed(unsigned int mode);

#endif /* INCLUDED_gitsync_content_h */
