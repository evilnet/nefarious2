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
#include <sys/uio.h>
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

  int running;                      /**< 1 if writer thread active; read
                                     *   and written only through
                                     *   RUNNING() / SET_RUNNING() */
  int accepting;                    /**< 1 while new entries are queued;
                                     *   0 after log_async_set_accepting(0)
                                     *   (mutex held) */
  int busy;                         /**< 1 while the writer is writing an
                                     *   entry it took off the buffer */

  /* Statistics */
  unsigned long written;            /**< Total entries written */
  unsigned long dropped;            /**< Entries dropped due to full buffer */
} log_async;

/* running is read without the mutex (log_async_write(), the
 * availability check), by thread-pool workers as well as the main
 * thread: an atomic acquire load sees everything log_async_init() set up
 * before its release store. */
#define RUNNING()        __atomic_load_n(&log_async.running, __ATOMIC_ACQUIRE)
#define SET_RUNNING(v)   __atomic_store_n(&log_async.running, (v), __ATOMIC_RELEASE)

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

/** Syslog @a message (a log file's line) as syslog wants it: from
 * @a off, without the file's timestamp, and without the line's newline.
 */
static void syslog_line(int priority, const char *message, int len, int off)
{
  if (off < 0 || off > len)
    off = 0;
  message += off;
  len -= off;
  if (len > 0 && message[len - 1] == '\n')
    len--;
  syslog(priority, "%.*s", len, message);
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
 *
 * An entry carries its log file's descriptor NUMBER.  The writer takes it
 * off the buffer and writes it with the mutex released, so the buffer is
 * empty while the last entry is still being written: \a busy covers that
 * write, and the writer signals \a flushed only when the buffer is empty
 * and nothing is in flight -- the one state in which the log may close a
 * descriptor (log_async_flush()).
 */
static void *log_writer_thread(void *arg)
{
  struct log_async_entry *entry;

  (void)arg;  /* unused */

  pthread_mutex_lock(&log_async.mutex);

  while (RUNNING() || !buffer_empty()) {
    /* Wait for data */
    while (buffer_empty() && RUNNING())
      pthread_cond_wait(&log_async.not_empty, &log_async.mutex);

    /* Check if we should exit */
    if (buffer_empty() && !RUNNING())
      break;

    /* Get entry from buffer */
    entry = &log_async.entries[log_async.tail];
    log_async.tail = (log_async.tail + 1) % log_async.size;
    log_async.busy = 1;

    /* Signal that there's space now.  The slot just taken is not reused
     * while it is written: the producer stops one short of the tail. */
    pthread_cond_signal(&log_async.not_full);

    /* Release mutex during I/O */
    pthread_mutex_unlock(&log_async.mutex);

    /* Perform the actual I/O (blocking is OK here - we're in worker thread) */
    if (entry->fd >= 0 && entry->len > 0) {
      (void)!write(entry->fd, entry->message, entry->len);
    }

    if (entry->syslog_priority > 0)
      syslog_line(entry->syslog_priority, entry->message,
                  entry->len > 0 ? entry->len : (int)strlen(entry->message),
                  entry->syslog_off);

    pthread_mutex_lock(&log_async.mutex);
    log_async.written++;
    log_async.busy = 0;

    /* Everything queued is written: wake any flush. */
    if (buffer_empty())
      pthread_cond_broadcast(&log_async.flushed);
  }

  /* Exiting: nothing more will be written. */
  pthread_cond_broadcast(&log_async.flushed);
  pthread_mutex_unlock(&log_async.mutex);
  return NULL;
}

/**
 * Initialize the async logging system.
 */
int log_async_init(int buffer_size)
{
  pthread_attr_t attr;
  int err;

  if (RUNNING())
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
  log_async.busy = 0;
  log_async.accepting = 1;

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

  /* Create the writer thread, and publish running only once it exists.
   * Other threads may be logging already (a REHASH turns ASYNC_LOGGING
   * on while thread-pool workers run): one that saw running set would
   * queue into this buffer, which a failed create frees.  The writer
   * starts by taking the mutex, so it sees running set. */
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

  pthread_mutex_lock(&log_async.mutex);
  if ((err = pthread_create(&log_async.writer_thread, &attr,
                            log_writer_thread, NULL)) != 0) {
    pthread_mutex_unlock(&log_async.mutex);
    Debug((DEBUG_ERROR, "log_async_init: thread create failed: %s",
           strerror(err)));
    pthread_cond_destroy(&log_async.flushed);
    pthread_cond_destroy(&log_async.not_full);
    pthread_cond_destroy(&log_async.not_empty);
    pthread_mutex_destroy(&log_async.mutex);
    MyFree(log_async.entries);
    log_async.entries = NULL;
    pthread_attr_destroy(&attr);
    return -1;
  }

  SET_RUNNING(1);
  pthread_mutex_unlock(&log_async.mutex);
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
  if (!RUNNING())
    return;

  Debug((DEBUG_DEBUG, "log_async_shutdown: flushing %u pending entries",
         buffer_count()));

  /* Signal writer thread to exit */
  pthread_mutex_lock(&log_async.mutex);
  SET_RUNNING(0);
  pthread_cond_signal(&log_async.not_empty);
  pthread_cond_broadcast(&log_async.flushed);
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
int log_async_write(int fd, int syslog_priority, const char *message, int len,
                    int syslog_off)
{
  struct log_async_entry *entry;
  int result = 0, cut = 0;

  if (!RUNNING() || !message)
    return -1;

  /* Clamp length to max entry size.  A line cut short still ends with
   * its newline, or the next one would run on from it. */
  if (len < 0)
    len = strlen(message);
  if (len > LOG_ASYNC_MAX_ENTRY - 1) {
    len = LOG_ASYNC_MAX_ENTRY - 1;
    cut = message[len] != '\0' && message[len - 1] != '\n';
  }

  pthread_mutex_lock(&log_async.mutex);

again:
  /* Not accepting (ASYNC_LOGGING turned off): the caller writes this
   * line itself, but only once every line queued before it is written,
   * so no thread's synchronous line lands ahead of an older queued one.
   * Queueing turned back on while it waits: queue the line instead. */
  if (!log_async.accepting) {
    while ((!buffer_empty() || log_async.busy) && RUNNING() &&
           !log_async.accepting) {
      pthread_cond_signal(&log_async.not_empty);
      pthread_cond_wait(&log_async.flushed, &log_async.mutex);
    }
    if (!log_async.accepting || !RUNNING()) {
      pthread_mutex_unlock(&log_async.mutex);
      return -1;
    }
  }

  /* Full: wait up to 1 ms for room.  Recheck after every wake -- a wake
   * may be spurious, or another producer may have taken the slot -- and
   * never write into a full ring: advancing head onto tail would make it
   * look empty and overwrite the entry the writer is on. */
  if (buffer_full()) {
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_nsec += 1000000;  /* 1ms wait */
    if (timeout.tv_nsec >= 1000000000) {
      timeout.tv_sec++;
      timeout.tv_nsec -= 1000000000;
    }

    while (buffer_full()) {
      int rc = pthread_cond_timedwait(&log_async.not_full, &log_async.mutex,
                                      &timeout);

      /* Turned off while it waited: the line goes after the queued ones,
       * as any thread's would (the drain wait above). */
      if (!log_async.accepting)
        goto again;
      if (rc != 0 && buffer_full()) {
        /* Still full after wait - fall back to sync write */
        log_async.dropped++;
        pthread_mutex_unlock(&log_async.mutex);

        /* Sync fallback: write directly.  The caller must not write it
         * again: it treats any return but -1 as written. */
        if (fd >= 0 && len > 0) {
          if (cut) {
            struct iovec iov[2];
            iov[0].iov_base = (void *)message;
            iov[0].iov_len = len - 1;
            iov[1].iov_base = (void *)"\n";
            iov[1].iov_len = 1;
            (void)!writev(fd, iov, 2);
          } else
            (void)!write(fd, message, len);
        }
        if (syslog_priority > 0)
          syslog_line(syslog_priority, message, cut ? len - 1 : len,
                      syslog_off);

        return 1;  /* Indicate sync fallback */
      }
    }
  }

  /* Add entry to buffer */
  entry = &log_async.entries[log_async.head];
  entry->fd = fd;
  entry->syslog_priority = syslog_priority;
  entry->syslog_off = syslog_off;
  entry->len = len;
  memcpy(entry->message, message, len);
  if (cut)
    entry->message[len - 1] = '\n';
  entry->message[len] = '\0';

  log_async.head = (log_async.head + 1) % log_async.size;

  /* Signal writer thread */
  pthread_cond_signal(&log_async.not_empty);
  pthread_mutex_unlock(&log_async.mutex);

  return result;
}

/**
 * Flush all pending log entries.
 *
 * Returns once every entry queued so far has been written, including the
 * one the writer may be writing right now (the buffer is already empty
 * then).  Call it before closing a descriptor the queue may name: an
 * entry left behind would be written to whatever file the number names
 * next.  Main thread only (the writer never logs through here).
 */
void log_async_flush(void)
{
  if (!RUNNING())
    return;

  pthread_mutex_lock(&log_async.mutex);
  while ((!buffer_empty() || log_async.busy) && RUNNING()) {
    pthread_cond_signal(&log_async.not_empty);
    pthread_cond_wait(&log_async.flushed, &log_async.mutex);
  }
  pthread_mutex_unlock(&log_async.mutex);
}

/**
 * Check if async logging is available and enabled.
 */
int log_async_available(void)
{
  return RUNNING();
}

/**
 * Start or stop queueing new entries (ASYNC_LOGGING turned on or off).
 * Stopping returns once every entry already queued is written; from
 * then on log_async_write() refuses, and its callers write themselves.
 * The writer thread stays.
 */
void log_async_set_accepting(int on)
{
  if (!RUNNING())
    return;

  pthread_mutex_lock(&log_async.mutex);
  log_async.accepting = on ? 1 : 0;
  /* Wake threads waiting to write past a drain, so they queue instead. */
  if (on)
    pthread_cond_broadcast(&log_async.flushed);
  pthread_mutex_unlock(&log_async.mutex);
  if (!on)
    log_async_flush();
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
