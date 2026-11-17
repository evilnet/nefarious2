/************************************************************************
 *   IRC - Internet Relay Chat, ircd/ircd_alloc.c
 *   Copyright (C) 1999 Thomas Helvey (BleepSoft)
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief IRC daemon memory allocation functions.
 * @version $Id: ircd_alloc.c 1306 2005-01-27 04:07:46Z entrope $
 */
#include "config.h"

#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "s_debug.h"

/* #include <assert.h> -- Now using assert in ircd_log.h */
#include <string.h>
#include <unistd.h>
#ifdef HAVE_PTHREAD
#include <pthread.h>
#endif

static void nomem_handler(void);

/** Variable holding out-of-memory callback. */
static OutOfMemoryHandler noMemHandler = nomem_handler;

/** Default handler for out-of-memory conditions. */
static void
nomem_handler(void)
{
#ifdef MDEBUG
  assert(0);
#else
  Debug((DEBUG_FATAL, "Out of memory, exiting"));
  exit(2);
#endif
}

#ifdef HAVE_PTHREAD
/** The thread that set the handler, once @a nomem_thread_known: the
 * main thread. */
static pthread_t nomem_thread;
static int nomem_thread_known;
#endif

/** Set callback function for out-of-memory conditions.  The handler
 * belongs to the calling thread, the main thread: no other thread ever
 * runs it (alloc_failed). */
void
set_nomem_handler(OutOfMemoryHandler handler)
{
  noMemHandler = handler;
#ifdef HAVE_PTHREAD
  nomem_thread = pthread_self();
  nomem_thread_known = 1;
#endif
}

/** An allocation failed.
 *
 * On the main thread: the handler (ircd.c restarts the server).  On any
 * other thread -- a thread pool worker hashing a password or scanning
 * the history store, a store's init thread -- the handler is not called
 * and the process exits at once, as server_panic() does and for its
 * reasons.  The handler's restart is main-thread work from end to end:
 * it sends notices, stops the listeners, persists the bouncer sessions
 * and closes the stores while the main thread is still running the same
 * structures, and history_shutdown() would then wait for the store jobs
 * under way, one of which is the caller: a hang with the listeners
 * closed, and one that every later DIE, SIGTERM or RESTART joined.  Nor
 * can the allocation be failed back to the caller instead: MyMalloc()
 * promises its callers a block, and the store code under a scan does
 * not check.  The line goes to stderr with write(), past the log (a
 * worker's log lines are dropped, log_thread_mute).  _exit() runs no
 * destructor and closes nothing by number, so no descriptor is reused
 * under a live thread; every committed write is in the WAL.  The server
 * does not re-exec itself on this path: whatever supervises it restarts
 * it. */
static void
alloc_failed(void)
{
#ifdef HAVE_PTHREAD
  if (nomem_thread_known && !pthread_equal(pthread_self(), nomem_thread)) {
    static const char msg[] = "ircd: out of memory off the main thread, exiting\n";

    if (write(2, msg, sizeof(msg) - 1) < 0) {
      /* nowhere left to say it */
    }
    _exit(1);
  }
#endif
  (*noMemHandler)();
}

#ifndef MDEBUG
/** Allocate memory.
 * @param[in] size Number of bytes to allocate.
 * @param[in] x Type of allocation (ignored).
 * @param[in] y Name of file doing allocation (ignored).
 * @param[in] z Line number doing allocation (ignored).
 * @return Newly allocated block of memory.
 */
void* DoMalloc(size_t size, const char* x, const char* y, int z)
{
  void* t = malloc(size);
  if (!t)
    alloc_failed();
  return t;
}

/** Allocate zero-initialized memory.
 * @param[in] size Number of bytes to allocate.
 * @param[in] x Type of allocation (ignored).
 * @param[in] y Name of file doing allocation (ignored).
 * @param[in] z Line number doing allocation (ignored).
 * @return Newly allocated block of memory.
 */
void* DoMallocZero(size_t size, const char* x, const char* y, int z)
{
  void* t = malloc(size);
  if (!t)
    alloc_failed();
  memset(t, 0, size);
  return t;
}

/** Resize an allocated block of memory.
 * @param[in] orig Original block to resize.
 * @param[in] size Minimum size for new block.
 * @param[in] file Name of file doing reallocation (ignored).
 * @param[in] line Line number doing reallocation (ignored).
 */
void* DoRealloc(void *orig, size_t size, const char *file, int line)
{
  void* t = realloc(orig, size);
  if (!t)
    alloc_failed();
  return t;
}
#endif
