/*
 * IRC - Internet Relay Chat, include/store_job.h
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
 * @brief A read of a store, run on the thread pool.
 *
 * A long read (the federated SEARCH responder's scan) leaves the main
 * loop: the main thread fills a job with everything the read needs,
 * store_job_start() hands it to a thread pool worker, and the answer is
 * sent from the main thread when the worker is done.  Everything else
 * stays as it was on the main thread, so a job has three rules:
 *
 *  - run() reads nothing but the job and the store.  No client, channel,
 *    feature, clock or other ircd state: the main thread copies what the
 *    read needs into the job before it starts it.  run() may be on a
 *    worker, with that thread's logging muted (log_thread_mute), or on
 *    the main thread (the fallback).  It gives back every store handle
 *    the job holds before it returns.
 *  - abandon() is run() for a job that will never run: it gives back the
 *    store handles the job holds, on the main thread, while the store is
 *    still open.  Exactly one of run() and abandon() is called.
 *  - done() is called on the main thread, exactly once, after one of the
 *    two, and frees the job.  It may come after the store has closed (a
 *    DIE), so it touches memory and the link only.  @a ran says whether
 *    run() was called; the job's link is NULL when the server the answer
 *    was for has left (store_jobs_link_gone): nothing is sent then.
 *
 * A job runs on the main thread, inside store_job_start(), when there is
 * no thread pool, the pool is not running or refuses the job, or more
 * jobs are waiting than STORE_JOBS_WAIT_MAX: the read as it was before,
 * done() called before store_job_start() returns.
 *
 * The pool is shared with the password checks (OPER, SASL, WEBIRC): at
 * most store_jobs_cap() jobs are in the pool at once, one worker fewer
 * than it has.  That bounds a password check's wait; it does not keep a
 * worker free for it.  The pool's queue is first in, first out, so a
 * check waits behind the checks already there and behind at most
 * store_jobs_cap() reads -- with every other worker hashing, behind
 * both -- and never behind the reads over the cap: those wait here, in
 * order, and enter the pool as the ones before them finish.
 */
#ifndef INCLUDED_store_job_h
#define INCLUDED_store_job_h

struct StoreJob;

/** What a job is made of; see the file comment for who calls what. */
struct StoreJobOps {
  /** The read.  A worker or the main thread. */
  void (*run)(struct StoreJob *job);
  /** Give back the store handles of a job that will not run.  The main
   * thread, the store still open.  May be NULL (the job holds none). */
  void (*abandon)(struct StoreJob *job);
  /** Answer and free.  The main thread, exactly once, last. */
  void (*done)(struct StoreJob *job, int ran);
};

/** One job: the head of the caller's own struct.  The caller sets
 * @a ops and @a link and leaves the rest alone. */
struct StoreJob {
  const struct StoreJobOps *ops;
  /** The server the answer is for; NULL once it has left.  The main
   * thread's: run() must not read it. */
  const void *link;
  struct StoreJob *sj_next;   /**< private: the pool or waiting list */
  struct StoreJob *sj_prev;   /**< private */
  int sj_state;               /**< private; the job mutex guards it */
};

/** The most jobs that wait for a place in the pool; the next one runs on
 * the main thread. */
#define STORE_JOBS_WAIT_MAX 64
/** The most jobs in the pool at once, whatever its size. */
#define STORE_JOBS_POOL_MAX 8

/** Start @a job (main thread).  It may have run, and been freed by its
 * done(), when this returns. */
extern void store_job_start(struct StoreJob *job);

/** The server @a link has left (main thread): the jobs whose answer was
 * for it lose their link.  One no worker has started is cancelled. */
extern void store_jobs_link_gone(const void *link);

/** The store is about to close (main thread): cancel every job no worker
 * has started and wait for the ones a worker is running.  When this
 * returns no job holds a store handle and none will touch the store; the
 * jobs that ran are still answered (done()) when the pool delivers
 * them. */
extern void store_jobs_quiesce(void);

/** The most jobs store_job_start() puts in the pool at once: one worker
 * fewer than the pool has (a pool of one: one), at most
 * STORE_JOBS_POOL_MAX; 0 when jobs cannot leave the main thread. */
extern unsigned int store_jobs_cap(void);

/** The jobs in the pool (queued, running, or run and not yet answered)
 * and the ones waiting for a place there. */
extern void store_jobs_count(unsigned int *in_pool, unsigned int *waiting);

#endif /* INCLUDED_store_job_h */
