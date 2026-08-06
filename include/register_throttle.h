/* include/register_throttle.h
 * Cross-connection throttle for the IRCv3 REGISTER command.
 *
 * Deliberately pure: the caller supplies the clock and the limits, the
 * module owns all state.  No struct Client, no feature reads, no timers,
 * no logging -- which is what lets the CMocka suite gate the arithmetic
 * without a running ircd.  See ircd/register_throttle.c.
 */
#ifndef INCLUDED_register_throttle_h
#define INCLUDED_register_throttle_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>      /* time_t */
#define INCLUDED_sys_types_h
#endif

struct irc_in_addr;

enum reg_throttle_result {
  REG_THROTTLE_OK = 0,
  REG_THROTTLE_IP,        /* per-IP window exhausted */
  REG_THROTTLE_GLOBAL     /* server-wide cap reached */
};

/* Test-and-count in one call: on OK the attempt is recorded against both
 * limiters.  A refusal by EITHER limiter records nothing in EITHER
 * limiter -- an attempt refused by the global cap does not slide or
 * consume the caller IP's per-IP window, and vice versa -- so a refused
 * client must get back in once the window since its last COUNTED
 * attempt elapses.
 * limit <= 0 disables the per-IP limiter, global_limit <= 0 the global
 * one, period <= 0 both. */
extern enum reg_throttle_result reg_throttle_check(const struct irc_in_addr *ip,
                                                   time_t now, int limit,
                                                   int period, int global_limit);
/* Aging sweep: frees entries whose `period`-second window has elapsed
 * (period <= 0 frees everything).  Nothing schedules this -- expiry is
 * lazy (on contact); it exists for tests and any future caller that
 * wants to reclaim memory eagerly. */
extern void reg_throttle_expire(time_t now, int period);
/* Full reset (tests). */
extern void reg_throttle_clear(void);

#endif /* INCLUDED_register_throttle_h */
