/*
 * IRC - Internet Relay Chat, include/gitsync.h
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
 *
 * GitSync provides automated synchronization of network configuration
 * (K-lines, G-lines, Jupes, etc.) from a central git repository.
 * This replaces the older HTTP-based linesync with a more robust
 * git-based approach using libgit2.
 */
#ifndef INCLUDED_gitsync_h
#define INCLUDED_gitsync_h

#include "config.h"
#include <time.h>

#ifdef USE_LIBGIT2

struct Client;
struct StatDesc;

/** GitSync status codes */
enum GitsyncStatus {
  GITSYNC_OK,              /**< Success */
  GITSYNC_DISABLED,        /**< Feature disabled */
  GITSYNC_NO_REPO,         /**< No repository configured */
  GITSYNC_CLONE_ERROR,     /**< Git clone failed */
  GITSYNC_FETCH_ERROR,     /**< Git fetch failed */
  GITSYNC_CHECKOUT_ERROR,  /**< Git checkout failed */
  GITSYNC_SSH_ERROR,       /**< SSH authentication error */
  GITSYNC_VALIDATION_ERROR,/**< Content validation failed */
  GITSYNC_APPLY_ERROR      /**< Failed to apply config */
};

/** GitSync statistics */
struct GitsyncStats {
  time_t last_sync;         /**< Timestamp of last successful sync */
  time_t last_attempt;      /**< Timestamp of last sync attempt */
  unsigned long syncs;      /**< Total successful syncs */
  unsigned long failures;   /**< Total failed syncs */
  enum GitsyncStatus last_status; /**< Status of last sync */
  char last_error[256];     /**< Last error message */
  char last_commit[64];     /**< Last synced commit hash */
};

/** Initialize gitsync subsystem */
extern void gitsync_init(void);

/** Start the gitsync timer after config is loaded */
extern void gitsync_start_timer(void);

/** Trigger a gitsync
 * @param sptr Client triggering the sync (NULL for timer)
 * @param force Force sync even if interval not elapsed
 * @return GITSYNC_OK on success, error code otherwise
 */
extern enum GitsyncStatus gitsync_trigger(struct Client *sptr, int force);

/** Get gitsync status as string
 * @param status Status code
 * @return Human-readable status string
 */
extern const char *gitsync_status_str(enum GitsyncStatus status);

/** Get gitsync statistics */
extern const struct GitsyncStats *gitsync_get_stats(void);

/** Report gitsync statistics for /STATS
 * @param to Client requesting stats
 * @param sd Stats descriptor
 * @param param Extra parameter (unused)
 */
extern void gitsync_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

#endif /* USE_LIBGIT2 */

#endif /* INCLUDED_gitsync_h */
