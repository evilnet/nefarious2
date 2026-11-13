/*
 * IRC - Internet Relay Chat, include/nick_delay.h
 *
 * NICKDELAY: the nick-change flood limit of one connection.  The primary's
 * server applies it to the session user's own Connection (every device's
 * request is a change of that one user there); a device's own server
 * applies it to the device's Connection for a primary on another server.
 * Never to another server's client: its Connection is its link's.
 */
#ifndef INCLUDED_nick_delay_h
#define INCLUDED_nick_delay_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

/** Whether a connection's nick change is refused by NICKDELAY: at most
 * one change per @a delay seconds, and one extra change straight after a
 * quiet spell (-SeKs, -Run).
 * @param[in,out] next The connection's next-allowed time (con_nextnick).
 * @param[in] now The current time.
 * @param[in] delay FEAT_NICKDELAY; 0 or less allows every change.
 * @return 1 when refused (@a next moves on 2 seconds, the flood penalty),
 * 0 when allowed (@a next moves on @a delay, never to before @a now).
 */
static inline int nick_delay_refuses(time_t *next, time_t now, int delay)
{
  if (delay <= 0)
    return 0;
  if (now < *next) {
    *next += 2;
    return 1;
  }
  *next += delay;
  if (*next < now)
    *next = now;
  return 0;
}

#endif /* INCLUDED_nick_delay_h */
