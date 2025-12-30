/*
 * IRC - Internet Relay Chat, include/linesync.h
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
 * @brief Linesync - centralized config distribution via HTTPS.
 */
#ifndef INCLUDED_linesync_h
#define INCLUDED_linesync_h

#include "config.h"

#ifdef USE_CURL

struct Client;
struct StatDesc;

/** Linesync status codes */
enum LinesyncStatus {
  LINESYNC_OK,              /**< Success */
  LINESYNC_DISABLED,        /**< Feature disabled */
  LINESYNC_NO_URL,          /**< No URL configured */
  LINESYNC_CURL_ERROR,      /**< libcurl error */
  LINESYNC_HTTP_ERROR,      /**< HTTP error response */
  LINESYNC_VALIDATION_ERROR,/**< Content validation failed */
  LINESYNC_CHECKSUM_ERROR,  /**< Checksum verification failed */
  LINESYNC_APPLY_ERROR      /**< Failed to apply config */
};

/** Linesync statistics */
struct LinesyncStats {
  time_t last_sync;         /**< Timestamp of last successful sync */
  time_t last_attempt;      /**< Timestamp of last sync attempt */
  unsigned long syncs;      /**< Total successful syncs */
  unsigned long failures;   /**< Total failed syncs */
  enum LinesyncStatus last_status; /**< Status of last sync */
  char last_error[256];     /**< Last error message */
};

/** Initialize linesync subsystem */
extern void linesync_init(void);

/** Trigger a linesync
 * @param sptr Client triggering the sync (NULL for timer)
 * @param force Force sync even if interval not elapsed
 * @return LINESYNC_OK on success, error code otherwise
 */
extern enum LinesyncStatus linesync_trigger(struct Client *sptr, int force);

/** Get linesync status as string
 * @param status Status code
 * @return Human-readable status string
 */
extern const char *linesync_status_str(enum LinesyncStatus status);

/** Get linesync statistics */
extern const struct LinesyncStats *linesync_get_stats(void);

/** Report linesync statistics for /STATS
 * @param to Client requesting stats
 * @param sd Stats descriptor
 * @param param Extra parameter (unused)
 */
extern void linesync_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

#endif /* USE_CURL */

#endif /* INCLUDED_linesync_h */
