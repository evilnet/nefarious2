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
 *
 * Fake-lag pool (ircd/fakelag.c): a server-wide budget of lag-seconds,
 * FAKELAG_POOL, refilled over a minute, that a logged-in connection may
 * draw on for FAKELAG_BORROW_TIME seconds after registration once its own
 * credit is spent, for the connect-time commands fakelag_borrows() names.
 * A connection class may reserve a guaranteed share of it (fakelagshare
 * in its Class block); what is not reserved is shared by every class.  An
 * account draws at most FAKELAG_BORROW per FAKELAG_ACCOUNT_TIME seconds.
 * A lone reconnecting client gets a much bigger connect burst, and under
 * a reconnect storm the pool runs dry and everyone falls back to the
 * credit alone.  See doc/design/fakelag-htb.md.
 */
#ifndef INCLUDED_fakelag_h
#define INCLUDED_fakelag_h

#include <sys/types.h>

struct Client;
struct ConnectionClass;

/** A token bucket of lag-seconds that refills to its cap over a minute. */
struct FakelagBucket {
  int    level;   /**< Lag-seconds available. */
  int    rem;     /**< Refill carried over, in 1/60 s. */
  time_t last;    /**< When it was last settled; 0 = never. */
};

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

/** Spend a fake-lag charge: the connection's own credit first, then the
 * shared pool while the connection's allowance is live, and whatever is
 * left goes to the clock.  Pure, so the order is testable.
 * @param[in,out] credit The connection's own credit (POSTREG_GRACE).
 * @param[in] until Last second the allowance is live; 0 = none.
 * @param[in] now The current time.
 * @param[in] take Draws up to the given seconds from the pool for @a ctx,
 *   returns what it got; NULL when this line may not borrow.
 * @param[in] ctx Passed to @a take.
 * @param[in] lag Seconds this command would add to the clock.
 * @return The seconds the clock is actually charged.
 */
static inline int fakelag_spend(int *credit, time_t until, time_t now,
                                int (*take)(void *ctx, int want), void *ctx,
                                int lag)
{
  lag = fakelag_charge(credit, lag);
  if (lag > 0 && take && now <= until)
    lag -= take(ctx, lag);
  return lag;
}

extern int fakelag_borrows(const char *cmd);
extern int fakelag_pool_take(struct ConnectionClass *cl, int want);
extern int fakelag_charge_client(struct Client *cptr, const char *cmd,
                                 int lag);
extern void fakelag_grant(struct Client *cptr);
#ifdef CMOCKA_TEST
extern void fakelag_test_reset(void);
#endif

#endif /* INCLUDED_fakelag_h */
