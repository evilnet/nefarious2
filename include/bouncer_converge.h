/*
 * IRC - Internet Relay Chat, include/bouncer_converge.h
 *
 * Cross-server bouncer session convergence: which of two session records
 * for ONE account survives when both sides announce a different session
 * id.  Pure (no ircd dependencies) so it can be unit tested; both peers
 * run the same function on the same wire-visible inputs and reach the
 * same answer without a coordination protocol (redesign D.3).
 */
#ifndef INCLUDED_bouncer_converge_h
#define INCLUDED_bouncer_converge_h

/** Does the peer's session win over ours?
 *
 * A session with a live primary (active) beats one that is merely held
 * or is a clientless replica (holding), whatever their ages: "an account
 * has one bouncer identity" and the live one is it.  Between equals the
 * lexicographically lower session id (the older UUID v7) wins, the
 * historical tie-break.
 *
 * @param[in] local_holding  1 if our record is HOLDING, 0 if ACTIVE.
 * @param[in] local_sessid   Our session id.
 * @param[in] peer_holding   1 if the peer announced "holding", 0 "active".
 * @param[in] peer_sessid    The peer's session id.
 * @return 1 when the peer's session should survive and ours be retired,
 *         0 when ours survives and the peer's replica is skipped.
 */
extern int bounce_converge_peer_wins(int local_holding, const char *local_sessid,
                                     int peer_holding, const char *peer_sessid);

#endif /* INCLUDED_bouncer_converge_h */
