#ifndef INCLUDED_bouncer_rebind_auth_h
#define INCLUDED_bouncer_rebind_auth_h
/*
 * Rebind authorization decision, isolated from the ircd so it can be
 * unit-tested. Real rebinds are rare (about four per five months in
 * production), so this decision is pinned by tests rather than observed.
 */

/** Which signal authorized a ghost rebind, in descending strength. */
enum BounceRebindAuth {
  BRA_NONE = 0,   /**< no signal; the rebind must be refused */
  BRA_ORIGIN,     /**< introducing server matches the session's recorded origin */
  BRA_SESSID,     /**< introducing message carried a matching ,S sessid tag */
  BRA_ACC_TS      /**< incoming account TS matched the ghost's (weakest) */
};

/** Decide which signal authorizes this rebind, strongest first.
 * Returns BRA_NONE when none apply. */
extern enum BounceRebindAuth bounce_rebind_auth(int origin_match,
                                                int sessid_match,
                                                int acc_ts_match);

/** Stable name for logging. Never NULL. */
extern const char *bounce_rebind_auth_name(enum BounceRebindAuth auth);

#endif /* INCLUDED_bouncer_rebind_auth_h */
