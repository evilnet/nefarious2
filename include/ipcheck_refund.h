/* include/ipcheck_refund.h
 * Per-account cap on IPcheck connection refunds (IPcheck_login_refund).
 *
 * A connection that logs in with SASL and registers gets the attempt
 * IPcheck charged it at the accept back, so an account holder whose
 * device reconnects often is not throttled for it.  This module bounds
 * how many such refunds one account may draw in a period, so a login
 * loop cannot turn the refund into an unlimited connection budget.
 *
 * Deliberately pure, like register_throttle.c: the caller supplies the
 * clock and the limits, the module owns all state.  No struct Client, no
 * feature reads, no timers, no logging -- which is what lets the CMocka
 * suite gate the arithmetic without a running ircd.
 */
#ifndef INCLUDED_ipcheck_refund_h
#define INCLUDED_ipcheck_refund_h
#ifndef INCLUDED_sys_types_h
#include <sys/types.h>      /* time_t */
#define INCLUDED_sys_types_h
#endif

/* Test-and-count in one call: non-zero when `account` may draw one more
 * refund in its current window (the refund is then counted), zero when
 * its cap is reached or the table has no slot for it -- every slot of its
 * bucket holding another account's live window (nothing is recorded).  The window is `period`
 * seconds from the account's first counted refund -- a fixed window, so
 * up to 2 * limit refunds can fall within `period` across its edge.
 * limit <= 0 or period <= 0 grants nothing.  Account names are compared
 * ASCII case-insensitively, over their first ACCOUNTLEN bytes. */
extern int ipcheck_refund_take(const char *account, time_t now, int limit,
                               int period);
/* Full reset (tests). */
extern void ipcheck_refund_clear(void);

#endif /* INCLUDED_ipcheck_refund_h */
