/*
 * IRC - Internet Relay Chat, ircd/store_job.c
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
 * @brief A read of a store, run on the thread pool (store_job.h).
 *
 * Who owns what.  The two lists and the link of every job belong to the
 * main thread.  A job's state is the one thing a worker and the main
 * thread both write, under job_mutex:
 *
 *   NEW -> WAITING -> QUEUED -> RUNNING -> RAN        (worker ran it)
 *                     QUEUED -> CANCELLED             (main thread)
 *   NEW / WAITING -> run on the main thread, or abandoned there
 *
 * The thread pool cannot take a queued task back, so a job that is
 * cancelled stays in the pool; the worker that reaches it sees CANCELLED
 * under the mutex and returns without touching the job or the store.
 * QUEUED -> RUNNING and QUEUED -> CANCELLED exclude each other under the
 * mutex, which is what lets the main thread give a cancelled job's store
 * handles back itself (abandon()), and what store_jobs_quiesce() waits
 * on: once no job is RUNNING and none is QUEUED, no worker will read the
 * store again.
 */
#include "config.h"

#include "store_job.h"
#include "ircd_log.h"
#include "thread_pool.h"

#include <stddef.h>

enum {
  SJ_NEW = 0,     /**< not started */
  SJ_WAITING,     /**< waiting here for a place in the pool */
  SJ_QUEUED,      /**< in the pool, no worker has started it */
  SJ_RUNNING,     /**< a worker is in run() */
  SJ_RAN,         /**< run() returned; done() comes with the pool's callback */
  SJ_CANCELLED    /**< in the pool, never to run; abandoned already */
};

/* Memory-debug builds keep one unlocked list of every block: a worker
 * that allocates beside the main thread would tear it, so there every
 * job runs on the main thread. */
#if defined(HAVE_PTHREAD) && !defined(MDEBUG)
#define STORE_JOBS_POOLED 1
#include <pthread.h>
#endif

/** The jobs in the pool, in no order (main thread). */
static struct StoreJob *pool_jobs;
static unsigned int pool_count;
/** The jobs waiting for a place in the pool, oldest first (main thread). */
static struct StoreJob *wait_head, *wait_tail;
static unsigned int wait_count;

/** Append @a job to the waiting list. */
static void wait_push(struct StoreJob *job)
{
  job->sj_next = NULL;
  job->sj_prev = wait_tail;
  if (wait_tail)
    wait_tail->sj_next = job;
  else
    wait_head = job;
  wait_tail = job;
  wait_count++;
}

/** Take @a job off the waiting list. */
static void wait_del(struct StoreJob *job)
{
  if (job->sj_prev)
    job->sj_prev->sj_next = job->sj_next;
  else
    wait_head = job->sj_next;
  if (job->sj_next)
    job->sj_next->sj_prev = job->sj_prev;
  else
    wait_tail = job->sj_prev;
  job->sj_next = job->sj_prev = NULL;
  wait_count--;
}

/** Add @a job to the jobs in the pool. */
static void pool_add(struct StoreJob *job)
{
  job->sj_prev = NULL;
  job->sj_next = pool_jobs;
  if (pool_jobs)
    pool_jobs->sj_prev = job;
  pool_jobs = job;
  pool_count++;
}

/** Take @a job off the jobs in the pool. */
static void pool_del(struct StoreJob *job)
{
  if (job->sj_prev)
    job->sj_prev->sj_next = job->sj_next;
  else
    pool_jobs = job->sj_next;
  if (job->sj_next)
    job->sj_next->sj_prev = job->sj_prev;
  job->sj_next = job->sj_prev = NULL;
  pool_count--;
}

/** Run @a job here, on the main thread, and answer it. */
static void run_here(struct StoreJob *job)
{
  job->ops->run(job);
  job->ops->done(job, 1);
}

/** Give back the store handles of @a job, which will not run. */
static void abandon(struct StoreJob *job)
{
  if (job->ops->abandon)
    job->ops->abandon(job);
}

void store_jobs_count(unsigned int *in_pool, unsigned int *waiting)
{
  if (in_pool)
    *in_pool = pool_count;
  if (waiting)
    *waiting = wait_count;
}

#ifdef STORE_JOBS_POOLED

static pthread_mutex_t job_mutex = PTHREAD_MUTEX_INITIALIZER;
/** A worker left run(). */
static pthread_cond_t job_cond = PTHREAD_COND_INITIALIZER;
/** Jobs in SJ_RUNNING (job_mutex). */
static unsigned int running_count;

unsigned int store_jobs_cap(void)
{
  int workers = thread_pool_is_running() ? thread_pool_workers() : 0;

  if (workers <= 0)
    return 0;
  if (workers > 1)
    workers--;      /* one worker stays free of reads */
  return workers > STORE_JOBS_POOL_MAX ? STORE_JOBS_POOL_MAX
                                       : (unsigned int)workers;
}

/** The pool's work function: a worker thread. */
static void *job_work(void *arg)
{
  struct StoreJob *job = (struct StoreJob *)arg;
  int muted;

  pthread_mutex_lock(&job_mutex);
  if (job->sj_state != SJ_QUEUED) {
    /* Cancelled while it waited in the pool: the main thread has
     * abandoned it, and the store may be closed. */
    pthread_mutex_unlock(&job_mutex);
    return job;
  }
  job->sj_state = SJ_RUNNING;
  running_count++;
  pthread_mutex_unlock(&job_mutex);

  /* The store code run() calls logs as it goes, and logging is the main
   * thread's.  The worker goes back to the pool as it came. */
  muted = log_thread_muted();
  log_thread_mute(1);
  job->ops->run(job);
  log_thread_mute(muted);

  pthread_mutex_lock(&job_mutex);
  job->sj_state = SJ_RAN;
  running_count--;
  pthread_cond_broadcast(&job_cond);
  pthread_mutex_unlock(&job_mutex);
  return job;
}

static void job_delivered(void *result, void *ctx);

/** Put @a job in the pool.
 * @return 0, or -1 when the pool refused it (@a job is as it was). */
static int job_submit(struct StoreJob *job)
{
  int was = job->sj_state;

  /* QUEUED before the submit: a worker may take the job at once.  No
   * worker knows the job before the submit, so no lock for this write
   * (the pool's own queue lock orders it before the worker's read). */
  job->sj_state = SJ_QUEUED;
  if (thread_pool_submit(job_work, job, job_delivered, job) < 0) {
    job->sj_state = was;
    return -1;
  }
  pool_add(job);
  return 0;
}

/** Fill the pool's free places from the waiting list.  A job the pool
 * will not take runs here: the pool has stopped, or its queue is full. */
static void pump(void)
{
  struct StoreJob *job;

  while ((job = wait_head)) {
    unsigned int cap = store_jobs_cap();

    if (cap && pool_count >= cap)
      break;
    wait_del(job);
    job->sj_state = SJ_NEW;
    if (!cap || job_submit(job) < 0)
      run_here(job);
  }
}

/** The pool's callback: the main thread, once per submitted job.  A NULL
 * @a result is a job the pool discarded at its shutdown without calling
 * job_work(). */
static void job_delivered(void *result, void *ctx)
{
  struct StoreJob *job = (struct StoreJob *)ctx;
  int state;

  /* The worker is done with the job (or never had it), but its last
   * write of the state was under the mutex: read it there. */
  pthread_mutex_lock(&job_mutex);
  state = job->sj_state;
  pthread_mutex_unlock(&job_mutex);

  pool_del(job);

  if (!result && state == SJ_QUEUED)
    abandon(job);   /* discarded with the store still open, uncancelled */
  job->ops->done(job, state == SJ_RAN);

  /* A stopping pool takes nothing more: what still waits runs here. */
  pump();
}

void store_job_start(struct StoreJob *job)
{
  job->sj_next = job->sj_prev = NULL;
  job->sj_state = SJ_NEW;

  if (store_jobs_cap() == 0) {
    run_here(job);
    return;
  }
  /* Behind the jobs already waiting, never past them. */
  if (!wait_head && pool_count < store_jobs_cap()) {
    if (job_submit(job) < 0)
      run_here(job);
    return;
  }
  if (wait_count >= STORE_JOBS_WAIT_MAX) {
    run_here(job);
    return;
  }
  job->sj_state = SJ_WAITING;
  wait_push(job);
}

/** Cancel @a job if no worker has started it.
 * @return 1 when it was cancelled: it will never run, and the caller
 * abandons it. */
static int cancel_queued(struct StoreJob *job)
{
  int cancelled = 0;

  pthread_mutex_lock(&job_mutex);
  if (job->sj_state == SJ_QUEUED) {
    job->sj_state = SJ_CANCELLED;
    cancelled = 1;
  }
  pthread_mutex_unlock(&job_mutex);
  return cancelled;
}

void store_jobs_link_gone(const void *link)
{
  struct StoreJob *job, *next;

  if (!link)
    return;
  for (job = wait_head; job; job = next) {
    next = job->sj_next;
    if (job->link != link)
      continue;
    wait_del(job);
    job->link = NULL;
    abandon(job);
    job->ops->done(job, 0);
  }
  for (job = pool_jobs; job; job = job->sj_next) {
    if (job->link != link)
      continue;
    job->link = NULL;       /* done() sends nothing */
    if (cancel_queued(job))
      abandon(job);         /* and the read is not worth running */
  }
}

void store_jobs_quiesce(void)
{
  struct StoreJob *job;

  while ((job = wait_head)) {
    wait_del(job);
    abandon(job);
    job->ops->done(job, 0);
  }
  for (job = pool_jobs; job; job = job->sj_next)
    if (cancel_queued(job))
      abandon(job);

  /* Every job in the pool is now CANCELLED, RUNNING or RAN, and the main
   * thread (here) is the only one that queues more: wait out the ones
   * running.  A read is bounded (the search scan by its row budget), so
   * this is a fraction of a second per running job. */
  pthread_mutex_lock(&job_mutex);
  while (running_count > 0)
    pthread_cond_wait(&job_cond, &job_mutex);
  pthread_mutex_unlock(&job_mutex);
}

#else /* !STORE_JOBS_POOLED: every job runs in store_job_start() */

unsigned int store_jobs_cap(void)
{
  return 0;
}

void store_job_start(struct StoreJob *job)
{
  job->sj_next = job->sj_prev = NULL;
  job->sj_state = SJ_NEW;
  run_here(job);
}

void store_jobs_link_gone(const void *link)
{
  (void)link;
}

void store_jobs_quiesce(void)
{
}

#endif /* STORE_JOBS_POOLED */
