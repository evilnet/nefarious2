/*
 * IRC - Internet Relay Chat, ircd/ircd_log_async.c
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
 * @brief Async logging implementation.
 *
 * Uses a ring buffer with a dedicated writer thread to offload log I/O
 * from the main event loop. The design prioritizes:
 *
 * 1. Minimal main thread impact - only atomic operations and memcpy
 * 2. Graceful degradation - falls back to sync if buffer full
 * 3. Reliable delivery - flush ensures all entries written
 * 4. Clean shutdown - drains buffer before exit
 */

#include "config.h"

#ifdef HAVE_PTHREAD

#include "ircd_log_async.h"
#include "ircd_alloc.h"
#include "s_debug.h"

#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

/** Ring buffer state */
static struct {
  struct log_async_entry *entries;  /**< Ring buffer of log entries */
  unsigned int size;                /**< Number of entries in buffer */
  unsigned int head;                /**< Next write position (producer) */
  unsigned int tail;                /**< Next read position (consumer) */

  pthread_t writer_thread;          /**< Writer thread handle */
  pthread_mutex_t mutex;            /**< Protects head/tail updates */
  pthread_cond_t not_empty;         /**< Signals data available */
  pthread_cond_t not_full;          /**< Signals space available */
  pthread_cond_t flushed;           /**< Signals flush complete */

  int running;                      /**< 1 if writer thread active */
  int flush_requested;              /**< 1 if flush in progress */

  /* Statistics */
  unsigned long written;            /**< Total entries written */
  unsigned long dropped;            /**< Entries dropped due to full buffer */
} log_async;

/**
 * Calculate number of entries in the buffer.
 * Must be called with mutex held.
 */
static inline unsigned int buffer_count(void)
{
  if (log_async.head >= log_async.tail)
    return log_async.head - log_async.tail;
  return log_async.size - log_async.tail + log_async.head;
}

/**
 * Check if buffer is full.
 * Must be called with mutex held.
 */
static inline int buffer_full(void)
{
  return ((log_async.head + 1) % log_async.size) == log_async.tail;
}

/**
 * Check if buffer is empty.
 * Must be called with mutex held.
 */
static inline int buffer_empty(void)
{
  return log_async.head == log_async.tail;
}

/**
 * Writer thread main loop.
 * Continuously drains the ring buffer to file/syslog.
 */
static void *log_writer_thread(void *arg)
{
  struct log_async_entry *entry;
  int was_empty_before_flush;

  (void)arg;  /* unused */

  pthread_mutex_lock(&log_async.mutex);

  while (log_async.running || !buffer_empty()) {
    /* Wait for data */
    while (buffer_empty() && log_async.running) {
      /* If flush requested and buffer is empty, signal completion */
      if (log_async.flush_requested) {
        log_async.flush_requested = 0;
        pthread_cond_signal(&log_async.flushed);
      }
      pthread_cond_wait(&log_async.not_empty, &log_async.mutex);
    }

    /* Check if we should exit */
    if (buffer_empty() && !log_async.running)
      break;

    /* Get entry from buffer */
    entry = &log_async.entries[log_async.tail];
    log_async.tail = (log_async.tail + 1) % log_async.size;
    was_empty_before_flush = buffer_empty();

    /* Signal that there's space now */
    pthread_cond_signal(&log_async.not_full);

    /* Release mutex during I/O */
    pthread_mutex_unlock(&log_async.mutex);

    /* Perform the actual I/O (blocking is OK here - we're in worker thread) */
    if (entry->fd >= 0 && entry->len > 0) {
      (void)!write(entry->fd, entry->message, entry->len);
    }

    if (entry->syslog_priority > 0) {
      syslog(entry->syslog_priority, "%.*s",
             entry->len > 0 ? entry->len : (int)strlen(entry->message),
             entry->message);
    }

    pthread_mutex_lock(&log_async.mutex);
    log_async.written++;

    /* Check if this completed a flush */
    if (was_empty_before_flush && log_async.flush_requested) {
      log_async.flush_requested = 0;
      pthread_cond_signal(&log_async.flushed);
    }
  }

  /* Final flush check before exit */
  if (log_async.flush_requested) {
    log_async.flush_requested = 0;
    pthread_cond_signal(&log_async.flushed);
  }

  pthread_mutex_unlock(&log_async.mutex);
  return NULL;
}

/**
 * Initialize the async logging system.
 */
int log_async_init(int buffer_size)
{
  pthread_attr_t attr;

  if (log_async.running)
    return 0;  /* Already initialized */

  /* Use default if not specified */
  if (buffer_size <= 0)
    buffer_size = LOG_ASYNC_BUFFER_SIZE_DEFAULT;

  /* Allocate ring buffer */
  log_async.entries = (struct log_async_entry *)
    MyCalloc(buffer_size, sizeof(struct log_async_entry));
  if (!log_async.entries) {
    Debug((DEBUG_ERROR, "log_async_init: failed to allocate buffer"));
    return -1;
  }

  log_async.size = buffer_size;
  log_async.head = 0;
  log_async.tail = 0;
  log_async.written = 0;
  log_async.dropped = 0;
  log_async.flush_requested = 0;

  /* Initialize synchronization primitives */
  if (pthread_mutex_init(&log_async.mutex, NULL) != 0) {
    Debug((DEBUG_ERROR, "log_async_init: mutex init failed"));
    MyFree(log_async.entries);
    log_async.entries = NULL;
    return -1;
  }

  if (pthread_cond_init(&log_async.not_empty, NULL) != 0 ||
      pthread_cond_init(&log_async.not_full, NULL) != 0 ||
      pthread_cond_init(&log_async.flushed, NULL) != 0) {
    Debug((DEBUG_ERROR, "log_async_init: cond init failed"));
    pthread_mutex_destroy(&log_async.mutex);
    MyFree(log_async.entries);
    log_async.entries = NULL;
    return -1;
  }

  /* Create writer thread */
  log_async.running = 1;

  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  if (pthread_create(&log_async.writer_thread, &attr,
                     log_writer_thread, NULL) != 0) {
    Debug((DEBUG_ERROR, "log_async_init: thread create failed: %s",
           strerror(errno)));
    log_async.running = 0;
    pthread_cond_destroy(&log_async.flushed);
    pthread_cond_destroy(&log_async.not_full);
    pthread_cond_destroy(&log_async.not_empty);
    pthread_mutex_destroy(&log_async.mutex);
    MyFree(log_async.entries);
    log_async.entries = NULL;
    pthread_attr_destroy(&attr);
    return -1;
  }

  pthread_attr_destroy(&attr);

  Debug((DEBUG_DEBUG, "log_async_init: initialized with buffer size %d",
         buffer_size));
  return 0;
}

/**
 * Shut down the async logging system.
 */
void log_async_shutdown(void)
{
  if (!log_async.running)
    return;

  Debug((DEBUG_DEBUG, "log_async_shutdown: flushing %u pending entries",
         buffer_count()));

  /* Signal writer thread to exit */
  pthread_mutex_lock(&log_async.mutex);
  log_async.running = 0;
  pthread_cond_signal(&log_async.not_empty);
  pthread_mutex_unlock(&log_async.mutex);

  /* Wait for writer thread to finish */
  pthread_join(log_async.writer_thread, NULL);

  /* Cleanup */
  pthread_cond_destroy(&log_async.flushed);
  pthread_cond_destroy(&log_async.not_full);
  pthread_cond_destroy(&log_async.not_empty);
  pthread_mutex_destroy(&log_async.mutex);
  MyFree(log_async.entries);
  log_async.entries = NULL;

  Debug((DEBUG_DEBUG, "log_async_shutdown: completed, %lu written, %lu dropped",
         log_async.written, log_async.dropped));
}

/**
 * Queue a log entry for async write.
 */
int log_async_write(int fd, int syslog_priority, const char *message, int len)
{
  struct log_async_entry *entry;
  int result = 0;

  if (!log_async.running || !message)
    return -1;

  /* Clamp length to max entry size */
  if (len > LOG_ASYNC_MAX_ENTRY - 1)
    len = LOG_ASYNC_MAX_ENTRY - 1;
  if (len < 0)
    len = strlen(message);
  if (len > LOG_ASYNC_MAX_ENTRY - 1)
    len = LOG_ASYNC_MAX_ENTRY - 1;

  pthread_mutex_lock(&log_async.mutex);

  /* Check if buffer is full */
  if (buffer_full()) {
    /* Try waiting briefly for space */
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_nsec += 1000000;  /* 1ms wait */
    if (timeout.tv_nsec >= 1000000000) {
      timeout.tv_sec++;
      timeout.tv_nsec -= 1000000000;
    }

    if (pthread_cond_timedwait(&log_async.not_full, &log_async.mutex,
                               &timeout) != 0) {
      /* Still full after wait - fall back to sync write */
      log_async.dropped++;
      pthread_mutex_unlock(&log_async.mutex);

      /* Sync fallback: write directly */
      if (fd >= 0 && len > 0)
        (void)!write(fd, message, len);
      if (syslog_priority > 0)
        syslog(syslog_priority, "%.*s", len, message);

      return 1;  /* Indicate sync fallback */
    }
  }

  /* Add entry to buffer */
  entry = &log_async.entries[log_async.head];
  entry->fd = fd;
  entry->syslog_priority = syslog_priority;
  entry->len = len;
  memcpy(entry->message, message, len);
  entry->message[len] = '\0';

  log_async.head = (log_async.head + 1) % log_async.size;

  /* Signal writer thread */
  pthread_cond_signal(&log_async.not_empty);
  pthread_mutex_unlock(&log_async.mutex);

  return result;
}

/**
 * Flush all pending log entries.
 */
void log_async_flush(void)
{
  if (!log_async.running)
    return;

  pthread_mutex_lock(&log_async.mutex);

  if (!buffer_empty()) {
    log_async.flush_requested = 1;
    pthread_cond_signal(&log_async.not_empty);

    /* Wait for flush to complete */
    while (log_async.flush_requested && log_async.running) {
      pthread_cond_wait(&log_async.flushed, &log_async.mutex);
    }
  }

  pthread_mutex_unlock(&log_async.mutex);
}

/**
 * Check if async logging is available and enabled.
 */
int log_async_available(void)
{
  return log_async.running;
}

/**
 * Get async logging statistics.
 */
void log_async_stats(unsigned long *queued, unsigned long *written,
                     unsigned long *dropped)
{
  pthread_mutex_lock(&log_async.mutex);
  if (queued)
    *queued = buffer_count();
  if (written)
    *written = log_async.written;
  if (dropped)
    *dropped = log_async.dropped;
  pthread_mutex_unlock(&log_async.mutex);
}

#endif /* HAVE_PTHREAD */
