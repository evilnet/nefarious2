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
  BRA_ACC_TS      /**< retired 2026-09; never returned. Kept so log lines
                       written before the retirement remain interpretable. */
};

/** Decide which signal authorizes this rebind, strongest first.
 * Returns BRA_NONE when none apply. */
extern enum BounceRebindAuth bounce_rebind_auth(int origin_match,
                                                int sessid_match,
                                                int acc_ts_match);

/** Do the held ghost and the incoming introduction carry Keycloak ids that
 * differ?  Then they are different users and the rebind is refused,
 * whatever authorized it: a VETO only -- the id is account-level, it
 * cannot say which session, so it never authorizes; and a missing id
 * (a legacy hop strips it, a restored ghost may lack it) never vetoes. */
extern int bounce_rebind_kc_conflict(const char *ghost_id,
                                     const char *incoming_id);

/** What a login does with an existing session of its account, by their
 * Keycloak ids (user, 2026-10-23: a new id never attaches to an old
 * session, and an old session is never tied to a new id). */
enum BounceKcJoin {
  BKJ_JOIN,       /**< Same id, or one side has none (the transition). */
  BKJ_END_STALE,  /**< Different ids, and the session is the previous user's
                   *   leftover with nothing connected: end it. */
  BKJ_REFUSE      /**< Different ids, and the session is in use: refuse the
                   *   login (registering beside it collides). */
};

/** Decide whether a login with @a login_id may join a session that belongs
 * to @a session_id.
 * @param[in] session_unused Non-zero when the session may be ended: held
 *            here with nothing connected anywhere (no aliases), and the
 *            login's id confirmed by Keycloak itself during this login
 *            (user, 2026-10-23).
 */
extern enum BounceKcJoin bounce_kc_join(const char *session_id,
                                        const char *login_id,
                                        int session_unused);

/** Stable name for logging. Never NULL. */
extern const char *bounce_rebind_auth_name(enum BounceRebindAuth auth);

#endif /* INCLUDED_bouncer_rebind_auth_h */
