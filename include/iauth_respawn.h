/*
 * IRC - Internet Relay Chat, include/iauth_respawn.h
 *
 * When to start an IAuth program again after it went away on its own (it
 * exited, or it could not be started at all).  The first exit after a good
 * run starts it again at once.  Otherwise the next start waits 5 seconds,
 * doubling with each further failure up to 300 seconds, so a program that
 * fails at start (missing, not executable, a broken configuration) is
 * retried slowly instead of in a tight loop.  A program that has run 60
 * seconds is healthy again and ends the streak.
 */
#ifndef INCLUDED_iauth_respawn_h
#define INCLUDED_iauth_respawn_h

#include <time.h>

/** A program that exits sooner than this after its start failed at start. */
#define IAUTH_RESPAWN_FAST   5
/** Delay before the first retry of a failing program, in seconds. */
#define IAUTH_RESPAWN_MIN    5
/** Longest delay between retries, in seconds. */
#define IAUTH_RESPAWN_MAX    300
/** A program that has run this many seconds ends the failure streak. */
#define IAUTH_RESPAWN_STABLE 60

/** Failure streak of an IAuth program. */
struct IAuthRespawn {
  unsigned int failures;  /**< exits or failed starts since it was last healthy */
  unsigned int delay;     /**< delay before the last retry; 0 for none */
};

/** The program went away on its own after running \a uptime seconds (0
 * when it could not be started).
 * @param[in,out] r Failure streak.
 * @param[in] uptime Seconds since the program was started.
 * @return Seconds to wait before starting it again; 0 to start it now.
 */
static inline unsigned int iauth_respawn_exited(struct IAuthRespawn *r,
                                                time_t uptime)
{
  if (uptime >= IAUTH_RESPAWN_STABLE)
    r->failures = r->delay = 0;
  if (r->failures++ == 0 && uptime >= IAUTH_RESPAWN_FAST)
    return 0;
  if (r->delay == 0)
    r->delay = IAUTH_RESPAWN_MIN;
  else if (r->delay >= IAUTH_RESPAWN_MAX / 2)
    r->delay = IAUTH_RESPAWN_MAX;
  else
    r->delay *= 2;
  return r->delay;
}

/** The program has run #IAUTH_RESPAWN_STABLE seconds: the streak ends.
 * @param[in,out] r Failure streak.
 * @return The number of failures it recovered from; 0 for none.
 */
static inline unsigned int iauth_respawn_stable(struct IAuthRespawn *r)
{
  unsigned int failures = r->failures;

  r->failures = r->delay = 0;
  return failures;
}

#endif /* INCLUDED_iauth_respawn_h */
