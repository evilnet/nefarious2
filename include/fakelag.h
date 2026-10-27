/*
 * IRC - Internet Relay Chat, include/fakelag.h
 *
 * Fake-lag credit: a registration-time allowance of seconds that absorbs
 * the first charges to the connection's lag clock (cli_since) instead of
 * being subtracted from the clock.  A clock set below "now" does not
 * survive: read_packet() pulls cli_since up to the last read time on
 * every read, which erased the old POSTREG_GRACE on the first command
 * after 001.  Spending the credit at charge time keeps it one-shot and
 * bounded, and the read-time floor can no longer touch it.
 */
#ifndef INCLUDED_fakelag_h
#define INCLUDED_fakelag_h

/** Apply a fake-lag charge against a credit.
 * @param[in,out] credit Unspent credit in seconds; reduced by what it absorbs.
 * @param[in] lag Seconds this command would add to the clock.
 * @return The seconds the clock is actually charged.
 */
static inline int fakelag_charge(int *credit, int lag)
{
  if (lag <= 0)
    return 0;
  if (*credit > 0) {
    int absorbed = *credit < lag ? *credit : lag;
    *credit -= absorbed;
    lag -= absorbed;
  }
  return lag;
}

#endif /* INCLUDED_fakelag_h */
