/*
 * IRC - Internet Relay Chat, include/thread_pool.h
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
/** @file
 * @brief Thread pool for CPU-bound operations.
 *
 * This module provides a lightweight thread pool for offloading CPU-bound
 * operations (like bcrypt/PBKDF2 password hashing) from the main event loop.
 * Results are delivered back to the main thread via callbacks.
 *
 * Usage:
 * 1. Call thread_pool_init() at startup
 * 2. Submit work with thread_pool_submit()
 * 3. Call thread_pool_poll() from event loop to process completions
 * 4. Call thread_pool_shutdown() at exit
 */
#ifndef INCLUDED_thread_pool_h
#define INCLUDED_thread_pool_h

#ifndef INCLUDED_config_h
#include "config.h"
#endif

/** Default number of worker threads */
#define THREAD_POOL_SIZE_DEFAULT 4

/** Maximum pending tasks before submit() blocks or fails */
#define THREAD_POOL_MAX_PENDING 256

/**
 * Callback invoked in main thread when async work completes.
 * @param[in] result Return value from work function
 * @param[in] ctx User-provided context pointer
 */
typedef void (*thread_pool_callback)(void *result, void *ctx);

/**
 * Work function to be executed in worker thread.
 * @param[in] arg Argument passed to thread_pool_submit()
 * @return Result pointer passed to callback
 */
typedef void *(*thread_pool_work_func)(void *arg);

#ifdef HAVE_PTHREAD

/**
 * Initialize the thread pool.
 * Creates worker threads and sets up the signal pipe for main thread wakeup.
 * @param[in] num_threads Number of worker threads (0 = use default)
 * @return 0 on success, -1 on failure
 */
int thread_pool_init(int num_threads);

/**
 * Shut down the thread pool.
 * Waits for pending tasks to complete, then terminates worker threads.
 * Any tasks submitted after this returns will fail.
 */
void thread_pool_shutdown(void);

/**
 * Submit work to the thread pool.
 * The work function runs in a worker thread. When it returns, the callback
 * is invoked in the main thread (via thread_pool_poll()) with the result.
 *
 * @param[in] work Function to execute in worker thread
 * @param[in] arg Argument passed to work function
 * @param[in] callback Function called in main thread with result (may be NULL)
 * @param[in] ctx Context pointer passed to callback
 * @return 0 on success, -1 on failure (pool not initialized or queue full)
 */
int thread_pool_submit(thread_pool_work_func work, void *arg,
                       thread_pool_callback callback, void *ctx);

/**
 * Process completed tasks.
 * Call this from the main event loop (after epoll_wait/kqueue/poll returns)
 * to invoke callbacks for completed async operations.
 *
 * This function is non-blocking - it only processes tasks that have already
 * completed.
 */
void thread_pool_poll(void);

/**
 * Get the signal pipe file descriptor.
 * This FD becomes readable when async tasks complete. Register it with
 * the event engine to wake up and call thread_pool_poll().
 * @return Read end of signal pipe, or -1 if not initialized
 */
int thread_pool_get_signal_fd(void);

/**
 * Check if thread pool is initialized and running.
 * @return 1 if running, 0 otherwise
 */
int thread_pool_is_running(void);

/**
 * Get thread pool statistics.
 * @param[out] pending Number of tasks waiting to be processed
 * @param[out] completed Total tasks completed since init
 * @param[out] active Number of tasks currently executing in workers
 */
void thread_pool_stats(unsigned int *pending, unsigned long *completed,
                       unsigned int *active);

#else /* !HAVE_PTHREAD */

/* Stub implementations when pthreads is not available */
#define thread_pool_init(n)                         (0)
#define thread_pool_shutdown()                      do {} while (0)
#define thread_pool_submit(w, a, cb, ctx)           (-1)
#define thread_pool_poll()                          do {} while (0)
#define thread_pool_get_signal_fd()                 (-1)
#define thread_pool_is_running()                    (0)
#define thread_pool_stats(p, c, a)                  do { if (p) *(p) = 0; if (c) *(c) = 0; if (a) *(a) = 0; } while (0)

#endif /* HAVE_PTHREAD */

#endif /* INCLUDED_thread_pool_h */
