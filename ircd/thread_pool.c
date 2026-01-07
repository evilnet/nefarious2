/*
 * IRC - Internet Relay Chat, ircd/thread_pool.c
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
 * @brief Thread pool for CPU-bound operations.
 *
 * Provides a lightweight thread pool to offload CPU-intensive operations
 * (like bcrypt/PBKDF2 password hashing) from the main event loop. Uses
 * the self-pipe trick to signal task completion to the main thread.
 */

#include "config.h"
#include "thread_pool.h"

#ifdef HAVE_PTHREAD

#include "ircd_alloc.h"
#include "ircd_log.h"
#include "s_debug.h"

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

/** Internal task structure */
struct thread_task {
  thread_pool_work_func work;      /**< Function to run in thread */
  void *arg;                        /**< Argument for work function */
  thread_pool_callback callback;   /**< Callback for main thread */
  void *ctx;                        /**< Context for callback */
  void *result;                     /**< Result from work function */
  struct thread_task *next;         /**< Next in queue */
};

/** Thread pool state */
static struct {
  pthread_t *workers;               /**< Worker thread handles */
  int num_workers;                  /**< Number of worker threads */
  int running;                      /**< Pool is accepting work */

  /* Task queue (pending work) */
  struct thread_task *task_head;    /**< Head of task queue */
  struct thread_task *task_tail;    /**< Tail of task queue */
  pthread_mutex_t task_mutex;       /**< Protects task queue */
  pthread_cond_t task_cond;         /**< Signals new work available */
  unsigned int pending_count;       /**< Tasks waiting for workers */

  /* Done queue (completed work) */
  struct thread_task *done_head;    /**< Head of done queue */
  struct thread_task *done_tail;    /**< Tail of done queue */
  pthread_mutex_t done_mutex;       /**< Protects done queue */

  /* Signal pipe for main thread wakeup */
  int signal_pipe[2];               /**< [0]=read, [1]=write */

  /* Statistics */
  unsigned long completed_count;    /**< Total tasks completed */
  unsigned int active_count;        /**< Tasks currently executing */
} pool;

/**
 * Set a file descriptor to non-blocking mode.
 */
static int set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Worker thread main loop.
 * Waits for tasks, executes them, and moves results to done queue.
 */
static void *worker_thread(void *arg)
{
  (void)arg; /* Unused */

  Debug((DEBUG_INFO, "thread_pool: worker thread started"));

  while (1) {
    struct thread_task *task;

    /* Wait for work */
    pthread_mutex_lock(&pool.task_mutex);
    while (!pool.task_head && pool.running) {
      pthread_cond_wait(&pool.task_cond, &pool.task_mutex);
    }

    /* Check for shutdown */
    if (!pool.running && !pool.task_head) {
      pthread_mutex_unlock(&pool.task_mutex);
      break;
    }

    /* Dequeue task */
    task = pool.task_head;
    if (task) {
      pool.task_head = task->next;
      if (!pool.task_head)
        pool.task_tail = NULL;
      pool.pending_count--;
      pool.active_count++;
    }
    pthread_mutex_unlock(&pool.task_mutex);

    if (!task)
      continue;

    /* Execute work function */
    task->result = task->work(task->arg);

    /* Decrement active count */
    pthread_mutex_lock(&pool.task_mutex);
    pool.active_count--;
    pthread_mutex_unlock(&pool.task_mutex);

    /* Move to done queue */
    task->next = NULL;
    pthread_mutex_lock(&pool.done_mutex);
    if (pool.done_tail) {
      pool.done_tail->next = task;
      pool.done_tail = task;
    } else {
      pool.done_head = pool.done_tail = task;
    }
    pthread_mutex_unlock(&pool.done_mutex);

    /* Signal main thread */
    {
      char c = 1;
      int ret;
      do {
        ret = write(pool.signal_pipe[1], &c, 1);
      } while (ret < 0 && errno == EINTR);
    }
  }

  Debug((DEBUG_INFO, "thread_pool: worker thread exiting"));
  return NULL;
}

/**
 * Initialize the thread pool.
 */
int thread_pool_init(int num_threads)
{
  int i;

  if (pool.running) {
    log_write(LS_SYSTEM, L_WARNING, 0, "thread_pool: already initialized");
    return -1;
  }

  /* Use default if not specified */
  if (num_threads <= 0)
    num_threads = THREAD_POOL_SIZE_DEFAULT;

  /* Create signal pipe */
  if (pipe(pool.signal_pipe) < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "thread_pool: pipe() failed: %s",
              strerror(errno));
    return -1;
  }

  /* Set non-blocking */
  if (set_nonblocking(pool.signal_pipe[0]) < 0 ||
      set_nonblocking(pool.signal_pipe[1]) < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "thread_pool: fcntl() failed: %s",
              strerror(errno));
    close(pool.signal_pipe[0]);
    close(pool.signal_pipe[1]);
    return -1;
  }

  /* Initialize mutexes and condition */
  pthread_mutex_init(&pool.task_mutex, NULL);
  pthread_mutex_init(&pool.done_mutex, NULL);
  pthread_cond_init(&pool.task_cond, NULL);

  /* Initialize queues */
  pool.task_head = pool.task_tail = NULL;
  pool.done_head = pool.done_tail = NULL;
  pool.pending_count = 0;
  pool.active_count = 0;
  pool.completed_count = 0;
  pool.running = 1;

  /* Allocate worker array */
  pool.workers = (pthread_t *)MyCalloc(num_threads, sizeof(pthread_t));
  pool.num_workers = num_threads;

  /* Create worker threads */
  for (i = 0; i < num_threads; i++) {
    if (pthread_create(&pool.workers[i], NULL, worker_thread, NULL) != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "thread_pool: pthread_create() failed: %s", strerror(errno));
      /* Shut down threads we did create */
      pool.running = 0;
      pthread_cond_broadcast(&pool.task_cond);
      while (--i >= 0) {
        pthread_join(pool.workers[i], NULL);
      }
      MyFree(pool.workers);
      pthread_mutex_destroy(&pool.task_mutex);
      pthread_mutex_destroy(&pool.done_mutex);
      pthread_cond_destroy(&pool.task_cond);
      close(pool.signal_pipe[0]);
      close(pool.signal_pipe[1]);
      return -1;
    }
  }

  log_write(LS_SYSTEM, L_INFO, 0, "thread_pool: initialized with %d workers",
            num_threads);
  return 0;
}

/**
 * Shut down the thread pool.
 */
void thread_pool_shutdown(void)
{
  int i;
  struct thread_task *task;

  if (!pool.running)
    return;

  log_write(LS_SYSTEM, L_INFO, 0, "thread_pool: shutting down");

  /* Signal workers to exit */
  pthread_mutex_lock(&pool.task_mutex);
  pool.running = 0;
  pthread_cond_broadcast(&pool.task_cond);
  pthread_mutex_unlock(&pool.task_mutex);

  /* Wait for workers */
  for (i = 0; i < pool.num_workers; i++) {
    pthread_join(pool.workers[i], NULL);
  }

  /* Process any remaining completed tasks */
  thread_pool_poll();

  /* Free pending tasks (shouldn't be any, but just in case) */
  pthread_mutex_lock(&pool.task_mutex);
  while ((task = pool.task_head)) {
    pool.task_head = task->next;
    /* Call callback with NULL result to indicate cancellation */
    if (task->callback)
      task->callback(NULL, task->ctx);
    MyFree(task);
  }
  pthread_mutex_unlock(&pool.task_mutex);

  /* Cleanup */
  MyFree(pool.workers);
  pool.workers = NULL;
  pool.num_workers = 0;

  pthread_mutex_destroy(&pool.task_mutex);
  pthread_mutex_destroy(&pool.done_mutex);
  pthread_cond_destroy(&pool.task_cond);

  close(pool.signal_pipe[0]);
  close(pool.signal_pipe[1]);
  pool.signal_pipe[0] = pool.signal_pipe[1] = -1;

  log_write(LS_SYSTEM, L_INFO, 0, "thread_pool: shutdown complete (%lu tasks)",
            pool.completed_count);
}

/**
 * Submit work to the thread pool.
 */
int thread_pool_submit(thread_pool_work_func work, void *arg,
                       thread_pool_callback callback, void *ctx)
{
  struct thread_task *task;

  if (!pool.running) {
    Debug((DEBUG_ERROR, "thread_pool_submit: pool not running"));
    return -1;
  }

  if (!work) {
    Debug((DEBUG_ERROR, "thread_pool_submit: NULL work function"));
    return -1;
  }

  /* Check queue limit */
  pthread_mutex_lock(&pool.task_mutex);
  if (pool.pending_count >= THREAD_POOL_MAX_PENDING) {
    pthread_mutex_unlock(&pool.task_mutex);
    log_write(LS_SYSTEM, L_WARNING, 0,
              "thread_pool: queue full (%u pending)", pool.pending_count);
    return -1;
  }
  pthread_mutex_unlock(&pool.task_mutex);

  /* Allocate task */
  task = (struct thread_task *)MyMalloc(sizeof(struct thread_task));
  task->work = work;
  task->arg = arg;
  task->callback = callback;
  task->ctx = ctx;
  task->result = NULL;
  task->next = NULL;

  /* Enqueue task */
  pthread_mutex_lock(&pool.task_mutex);
  if (pool.task_tail) {
    pool.task_tail->next = task;
    pool.task_tail = task;
  } else {
    pool.task_head = pool.task_tail = task;
  }
  pool.pending_count++;
  pthread_cond_signal(&pool.task_cond);
  pthread_mutex_unlock(&pool.task_mutex);

  Debug((DEBUG_DEBUG, "thread_pool_submit: queued task (pending=%u)",
         pool.pending_count));
  return 0;
}

/**
 * Process completed tasks.
 */
void thread_pool_poll(void)
{
  struct thread_task *task;
  char buf[64];
  int count = 0;

  if (!pool.running && pool.signal_pipe[0] < 0)
    return;

  /* Drain signal pipe */
  while (read(pool.signal_pipe[0], buf, sizeof(buf)) > 0)
    ;

  /* Process done queue */
  while (1) {
    pthread_mutex_lock(&pool.done_mutex);
    task = pool.done_head;
    if (task) {
      pool.done_head = task->next;
      if (!pool.done_head)
        pool.done_tail = NULL;
      pool.completed_count++;
    }
    pthread_mutex_unlock(&pool.done_mutex);

    if (!task)
      break;

    /* Invoke callback in main thread context */
    if (task->callback)
      task->callback(task->result, task->ctx);

    MyFree(task);
    count++;
  }

  if (count > 0) {
    Debug((DEBUG_DEBUG, "thread_pool_poll: processed %d tasks", count));
  }
}

/**
 * Get the signal pipe file descriptor.
 */
int thread_pool_get_signal_fd(void)
{
  return pool.running ? pool.signal_pipe[0] : -1;
}

/**
 * Check if thread pool is running.
 */
int thread_pool_is_running(void)
{
  return pool.running;
}

/**
 * Get thread pool statistics.
 */
void thread_pool_stats(unsigned int *pending, unsigned long *completed,
                       unsigned int *active)
{
  pthread_mutex_lock(&pool.task_mutex);
  if (pending)
    *pending = pool.pending_count;
  if (active)
    *active = pool.active_count;
  pthread_mutex_unlock(&pool.task_mutex);

  if (completed)
    *completed = pool.completed_count;
}

#endif /* HAVE_PTHREAD */
