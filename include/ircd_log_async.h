/*
 * IRC - Internet Relay Chat, include/ircd_log_async.h
 * Copyright (C) 2025 AfterNET Development Team
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
/**
 * @file
 * @brief Async logging infrastructure.
 *
 * This module provides non-blocking logging by offloading file and syslog
 * writes to a dedicated writer thread. This prevents the main event loop
 * from blocking during log I/O operations.
 *
 * Usage:
 * 1. Call log_async_init() at startup (after feature_init)
 * 2. Use log_write_async() instead of direct writev/syslog calls
 * 3. Call log_async_flush() for critical messages or before shutdown
 * 4. Call log_async_shutdown() at exit
 */
#ifndef INCLUDED_ircd_log_async_h
#define INCLUDED_ircd_log_async_h

#ifndef INCLUDED_config_h
#include "config.h"
#endif

/** Maximum size of a single log entry */
#define LOG_ASYNC_MAX_ENTRY 2048

/** Default number of entries in the ring buffer */
#define LOG_ASYNC_BUFFER_SIZE_DEFAULT 4096

/** Log entry for async queue */
struct log_async_entry {
  int fd;                              /**< File descriptor to write to (-1 for syslog) */
  int syslog_priority;                 /**< Syslog priority (if fd == -1) */
  int len;                             /**< Length of message */
  char message[LOG_ASYNC_MAX_ENTRY];   /**< Pre-formatted log message */
};

#ifdef HAVE_PTHREAD

/**
 * Initialize the async logging system.
 * Creates the writer thread and allocates the ring buffer.
 * @param[in] buffer_size Number of entries in ring buffer (0 = use default)
 * @return 0 on success, -1 on failure
 */
int log_async_init(int buffer_size);

/**
 * Shut down the async logging system.
 * Flushes remaining entries and terminates the writer thread.
 */
void log_async_shutdown(void);

/**
 * Queue a log entry for async write.
 * If the buffer is full, this will block briefly or fall back to sync write.
 *
 * @param[in] fd File descriptor to write to (-1 for syslog only)
 * @param[in] syslog_priority Syslog priority (0 to skip syslog)
 * @param[in] message Pre-formatted log message
 * @param[in] len Length of message
 * @return 0 on success (queued), 1 if sync fallback was used, -1 on error
 */
int log_async_write(int fd, int syslog_priority, const char *message, int len);

/**
 * Flush all pending log entries.
 * Blocks until the writer thread has processed all queued entries.
 * Use this before shutdown or for critical log messages.
 */
void log_async_flush(void);

/**
 * Check if async logging is available and enabled.
 * @return 1 if async logging is active, 0 otherwise
 */
int log_async_available(void);

/**
 * Get async logging statistics.
 * @param[out] queued Current entries in queue
 * @param[out] written Total entries written since init
 * @param[out] dropped Total entries dropped due to full buffer
 */
void log_async_stats(unsigned long *queued, unsigned long *written,
                     unsigned long *dropped);

#else /* !HAVE_PTHREAD */

/* Stub implementations when pthreads is not available */
#define log_async_init(s)                       (0)
#define log_async_shutdown()                    do {} while (0)
#define log_async_write(fd, prio, msg, len)     (-1)
#define log_async_flush()                       do {} while (0)
#define log_async_available()                   (0)
#define log_async_stats(q, w, d)                do { if (q) *(q) = 0; if (w) *(w) = 0; if (d) *(d) = 0; } while (0)

#endif /* HAVE_PTHREAD */

#endif /* INCLUDED_ircd_log_async_h */
