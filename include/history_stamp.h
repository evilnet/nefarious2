/*
 * IRC - Internet Relay Chat, include/history_stamp.h
 *
 * Ordering of history timestamps as the store writes them: fixed-width
 * "sec.mmm", so a byte compare orders them.  Pure, for the TARGETS index's
 * max() rule and its unit test.
 */
#ifndef INCLUDED_history_stamp_h
#define INCLUDED_history_stamp_h

#include <string.h>

/** Whether stamp \a a is later than stamp \a b.  A longer stamp with an
 * equal prefix is later (more seconds digits).
 * @param[in] a Candidate stamp.
 * @param[in] al Its length.
 * @param[in] b Stamp currently held.
 * @param[in] bl Its length.
 * @return Non-zero when \a a should replace \a b.
 */
static inline int history_stamp_newer(const char *a, size_t al,
                                      const char *b, size_t bl)
{
  int c = memcmp(a, b, al < bl ? al : bl);
  return (c > 0) || (c == 0 && al > bl);
}

#endif /* INCLUDED_history_stamp_h */
