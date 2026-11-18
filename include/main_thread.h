/*
 * IRC - Internet Relay Chat, include/main_thread.h
 *
 * assert_main_thread(): the caller is not a thread pool worker.
 *
 * A worker may touch its job, the job's store snapshot and the store's
 * handles, and nothing of the main thread's: no feature value, no hash
 * table, no send, no timer.  Code that breaks that compiles, passes
 * every single-threaded test and races.  The pool mutes each worker's
 * logging (log_thread_mute()), which marks the thread: the functions a
 * worker must never reach assert on it, in builds with assertions.
 *
 * The reference is weak, so a test that links one of those objects
 * without ircd_log.o still links; nothing is checked there.
 */
#ifndef INCLUDED_main_thread_h
#define INCLUDED_main_thread_h

#include "ircd_log.h"   /* assert() */

extern int log_thread_muted(void) __attribute__((weak));

/* Not in a leak-detection build (MDEBUG): its allocator reports leaks
 * through a server notice from whichever thread allocates, a worker
 * hashing a password included. */
#ifdef MDEBUG
#define assert_main_thread() ((void)0)
#else
#define assert_main_thread() \
  assert(!log_thread_muted || !log_thread_muted())
#endif

#endif /* INCLUDED_main_thread_h */
