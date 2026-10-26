/*
 * IRC - Internet Relay Chat, include/bouncer_converge.h
 *
 * Cross-server bouncer session convergence: which of two session records
 * for ONE account survives when both sides announce a different session
 * id, and what happens when two clients of one account meet on one nick.
 * Pure (no ircd dependencies) so it can be unit tested; both peers
 * run the same function on the same wire-visible inputs and reach the
 * same answer without a coordination protocol (redesign D.3).
 */
#ifndef INCLUDED_bouncer_converge_h
#define INCLUDED_bouncer_converge_h

#include <time.h>   /* time_t */

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

/** One side of a same-nick meeting of two clients of one account: ours,
 * or the one an incoming N introduces. */
struct bounce_nick_side {
  int held;              /**< a held ghost whose session has no live
                          *   connection left; a held ghost with a live
                          *   alias counts as live, since ending its
                          *   session would exit that device */
  int state_known;       /**< incoming side: its hold state is known
                          *   (every server on its path announces it);
                          *   ours always is */
  int non_member;        /**< incoming side: known to be a live login in
                          *   no session of the account (for ours,
                          *   local_is_session_primary says it); 0 when
                          *   it is a member or nobody knows */
  time_t lastnick;       /**< its nick timestamp */
  const char *sessid;    /**< its session id; NULL reads as "" */
  const char *numeric;   /**< its full YYXXX numeric; NULL reads as "" */
};

/** What a same-nick meeting does on the side that receives the N. */
enum bounce_nick_verdict {
  BNV_CLASSIC,           /**< not a bouncer case: classic P10 collision */
  BNV_KEEP_LOCAL,        /**< ours stays; refuse the incoming N silently */
  BNV_RETIRE_LOCAL,      /**< our held session ends (BS X + Q); accept the
                          *   incoming N */
  BNV_DROP_LOCAL_GHOST,  /**< our ghost leaves, the shared session record
                          *   stays; accept */
  BNV_DEMOTE_LOCAL       /**< our live primary becomes the incoming one's
                          *   alias */
};

/** What happens when an incoming N names the nick one of our clients
 * holds, both clients of one account.
 *
 * Both servers compute it from the same facts (each side's hold state,
 * nick timestamp, session id and full numeric), so for every pair one
 * side keeps exactly when the other yields, and both fall back to the
 * classic collision together.  Rules, in order:
 *
 *  1. Different Keycloak users: classic (sessions of different ids are
 *     never merged).
 *  2. A live login known to be in no session meets a held ghost, either
 *     way round: classic, as it has always been.  Whether the live login
 *     should win instead (the held session ending) is not decided; this
 *     is the one place that answers it.
 *  3. Ours held:
 *     - the incoming one known live: ours ends;
 *     - known held: the lower session id keeps (strcmp); equal ids, the
 *       lower numeric keeps; the other ends;
 *     - state unknown: ours ends when our burst to the link is still
 *       gated (the peer never saw our ghost), else classic.
 *     Ending is BNV_RETIRE_LOCAL when the session ids differ and
 *     BNV_DROP_LOCAL_GHOST when they are equal: the incoming client is
 *     in our session, so only the ghost goes.
 *  4. Ours live:
 *     - the incoming one known held: ours keeps;
 *     - ours not its session's primary, or the incoming one known to be
 *       in no session: classic;
 *     - else the older nick timestamp keeps; equal, the lower numeric;
 *       the newer is demoted to the other's alias.
 *
 * Held against live and held against held agree with BS C's session
 * convergence (bounce_converge_peer_wins): live beats held, and between
 * two held sessions the older id wins.
 *
 * @param[in] local    Our client; NULL gives BNV_CLASSIC.
 * @param[in] incoming The client the N introduces; NULL gives BNV_CLASSIC.
 * @param[in] local_is_session_primary Nonzero if ours is the live primary
 *                     of its session (read only while ours is live).
 * @param[in] kc_conflict Nonzero if the two carry different Keycloak ids.
 * @param[in] link_gated  Nonzero if our burst to the link the N came on
 *                     is still gated.
 * @return The verdict for our side.
 */
extern enum bounce_nick_verdict
bounce_nick_verdict(const struct bounce_nick_side *local,
                    const struct bounce_nick_side *incoming,
                    int local_is_session_primary, int kc_conflict,
                    int link_gated);

#endif /* INCLUDED_bouncer_converge_h */
