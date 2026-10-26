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
#ifndef INCLUDED_bouncer_wire_h
#include "bouncer_wire.h"  /* enum bounce_demote_bar */
#endif

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

/** What BS C's convergence does with our session when a peer announces
 * another session of the same account (session ids differ). */
enum bounce_session_outcome {
  BSO_KEEP,          /**< ours stays under its id; the peer's copy is not
                      *   mirrored here (the peer takes our id, or keeps
                      *   its own and skips ours) */
  BSO_RENAME,        /**< ours stays, every connection with it, and takes
                      *   the peer's session id */
  BSO_RETIRE,        /**< ours ends (bounce_kill_session, its held ghost
                      *   leaves with a Q); the peer's copy is mirrored */
  BSO_DROP_REPLICA   /**< our clientless replica is dropped (nothing here
                      *   exits); the peer's copy is mirrored */
};

/** BS C's convergence of two sessions of one account.
 *
 * The states are the announced ones ("holding" or "active", which is
 * hs_state on both ends), so both servers compute from the same facts:
 * a live session beats a holding one; between equal states the older
 * (lexicographically lower) id wins (bounce_converge_peer_wins).  The
 * session that loses takes the winner's id, except a holding one beaten
 * by a live one, which ends: retired when it is held here, dropped when
 * it is a replica of another server's session.
 *
 * A holding session still with a live connection here (a live alias, or
 * a live primary under a holding record) is never retired: ending it
 * would exit that device.  Nor is it merged: it keeps its id and the
 * peer's copy is not mirrored here, while the peer, reading our
 * announced "holding", keeps its own id and skips ours.  The two stay
 * apart, each server holding only its own, as sessions of different
 * Keycloak users are kept apart, and an alias of either is never filed
 * into the other (bounce_alias_filing, bouncer_wire.h).  Nothing here
 * merges them while both stay as they are.  They meet again at a later
 * link burst, where the rules above may rename one into the other's id,
 * with whatever a rename of a session held here brings; and a session
 * made fresh on either server after one of them ends meets the other
 * when its BS C arrives, which does not merge them either (registered).
 *
 * @param[in] local_holding  1 if our record is HOLDING (we announce
 *                           "holding"), 0 if ACTIVE.
 * @param[in] local_holder   1 if a connection of our session is on this
 *                           server (its primary or held ghost, or an
 *                           alias), 0 for a replica.
 * @param[in] local_live     1 if a connection of our session is live (a
 *                           held ghost with no live alias is not).
 * @param[in] local_sessid   Our session id.
 * @param[in] peer_holding   1 if the peer announced "holding".
 * @param[in] peer_sessid    The peer's session id.
 * @return What to do with ours.
 */
extern enum bounce_session_outcome
bounce_session_converge(int local_holding, int local_holder, int local_live,
                        const char *local_sessid, int peer_holding,
                        const char *peer_sessid);

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
  int non_member;        /**< incoming side: known to be live and not
                          *   the primary of one session of the account
                          *   (its home server stamped the outsider mark:
                          *   in no session, only on a session's alias
                          *   roster, or named as primary by two
                          *   sessions); for ours, local_is_session_primary
                          *   says it.  0 when it is a session's primary
                          *   or held ghost, or nobody knows */
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

/** Does a live login meet a held ghost of its account by the live login
 * winning (the held session ending)?  Not decided: 0 keeps the classic
 * rules for it, as they have always decided it.  This constant and the
 * one branch of bounce_nick_verdict_ex() that reads it are the whole
 * switch; 1 answers as if that branch were deleted. */
#define BOUNCE_LIVE_LOGIN_WINS 0

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
 *  2. The open case (BOUNCE_LIVE_LOGIN_WINS), the one switch: classic,
 *     as it has always been, when
 *     - a live login known to be in no session meets a held ghost,
 *       either way round; or
 *     - our held ghost meets a client whose state is unknown while our
 *       burst to its link is still gated: it may be a login in no
 *       session as well.
 *     Whether the live login should win instead (the held session
 *     ending) is not decided; with the switch off, the rules below
 *     answer both cases that way.
 *  3. Ours held:
 *     - the incoming one known to be in no session: ours ends, as
 *       BNV_RETIRE_LOCAL whatever session id it carries (a login in no
 *       session carries its own id, or a stale one; never ours);
 *     - known live otherwise: ours ends;
 *     - known held: the lower session id keeps (strcmp); equal ids, the
 *       lower numeric keeps; the other ends;
 *     - state unknown: ours ends when our burst to the link is still
 *       gated (the peer never saw our ghost), else classic.
 *     Ending (other than for a login in no session) is BNV_RETIRE_LOCAL
 *     when the session ids differ and BNV_DROP_LOCAL_GHOST when they are
 *     equal: the incoming client is in our session, so only the ghost
 *     goes.
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

/** bounce_nick_verdict() with the open case answered by @a
 * live_login_wins instead of BOUNCE_LIVE_LOGIN_WINS.  The server calls
 * bounce_nick_verdict(); this form lets the unit tests check both
 * answers against the one implementation.
 *
 * @param[in] live_login_wins Nonzero answers rule 2's cases by the rules
 *                     below it (the live login wins), 0 by the classic
 *                     rules.
 */
extern enum bounce_nick_verdict
bounce_nick_verdict_ex(const struct bounce_nick_side *local,
                       const struct bounce_nick_side *incoming,
                       int local_is_session_primary, int kc_conflict,
                       int link_gated, int live_login_wins);

/** Set the incoming side's hold state from the hold mark its N carried
 * (bouncer_wire.h: BOUNCE_HOLD_MARK_*).
 *
 * The state is known only when the mark can be trusted -- every server
 * on the path from the client's home server to us, both ends included,
 * announces SERVER flag H (bounce_hold_marks_trusted; two servers then
 * trust each other's marks or neither does, exact for a direct link;
 * multi-hop and runtime-toggle residuals are registered) -- AND the N
 * carries a valid mark.  Then:
 * held mark -> held; primary mark -> a live session member; outsider
 * mark -> live, in no session (non_member).  Otherwise the state is
 * unknown (state_known, held and non_member all 0), as for an N from a
 * server that stamps no mark.  Only those three fields are written.
 *
 * @param[out] side    The incoming side; NULL is ignored.
 * @param[in] trusted  Nonzero if every server on the path announces H.
 * @param[in] mark     The N's mark, or 0 when it carried none.
 */
extern void bounce_nick_side_from_mark(struct bounce_nick_side *side,
                                       int trusted, char mark);

/** Set our side of a meeting from the hold mark we stamped on our own
 * client's N toward the link the incoming N came on: the facts the peer
 * read about our client, so both verdicts are computed from the same
 * snapshot even when our client changed since (a socket that died, a
 * live alias that left).  Held mark -> held; primary mark -> a live
 * session primary; outsider mark -> live and not its session's primary.
 * A held ghost is its session's primary slot too, as the stamp has it.
 * Writes held, state_known (1) and non_member (0) only, and only for a
 * valid mark.
 *
 * @param[out] side    Our side; NULL is ignored.
 * @param[out] primary Set to local_is_session_primary for the verdict;
 *                     may be NULL.
 * @param[in]  stamp   The mark we stamped (bouncer_wire.h), or 0.
 * @return 1 when @a stamp is a valid mark and was applied, else 0
 *         (the caller then reads its client as it is now).
 */
extern int bounce_nick_side_from_stamp(struct bounce_nick_side *side,
                                       int *primary, char stamp);

/** What our side does about a same-nick verdict, given what our client
 * is when the verdict is acted on.  The verdict may come from the
 * snapshot our N carried (bounce_nick_side_from_stamp); this maps it onto
 * the client as it is now, so the action never ends a device the verdict
 * did not know about and never demotes a client with no socket. */
enum bounce_nick_action {
  BNA_CLASSIC,        /**< the classic collision rules decide */
  BNA_REFUSE,         /**< ours stays: the incoming N is refused silently */
  BNA_RETIRE,         /**< our held session ends (a ghost no session names
                       *   just exits), then the incoming N is accepted */
  BNA_REBIND_LIVE,    /**< our held ghost becomes the incoming live
                       *   primary of our own session (its Client is
                       *   reused; the session goes active) */
  BNA_REBIND_HELD,    /**< our held ghost becomes our record of the
                       *   incoming held ghost of our own session (the
                       *   session stays held, a replica here) */
  BNA_SWAP,           /**< our live primary becomes the incoming
                       *   primary's alias; legacy links swap the face */
  BNA_YIELD           /**< our held ghost leaves; its session's live
                       *   connections follow the incoming primary, whose
                       *   session id the session takes */
};

/** Our client as it is now (each 0 or 1, except the bar). */
struct bounce_nick_now {
  int held_ghost;      /**< a held ghost (it has no socket) */
  int has_session;     /**< the decision's one lookup found a session */
  int is_primary;      /**< that session's primary slot is our client */
  int live_alias;      /**< that session has a live alias */
  int yield_ok;        /**< a held ghost may hand its session to the
                        *   incoming primary: that primary's home is
                        *   IRCv3-aware and ours is not being killed */
  enum bounce_demote_bar demote_bar; /**< a live primary's demote
                        *   eligibility (BOUNCE_DEMOTE_PLAN) */
};

/** Map a verdict onto our client as it is now.
 *
 *  - CLASSIC: classic.
 *  - KEEP: refuse the N (a live primary goes through
 *    bounce_merge_choose(), which answers classic for a Keycloak-id
 *    conflict).
 *  - RETIRE: retire a held ghost that is its session's primary, or one
 *    no session names.  If its session has a live alias now, ending it
 *    would exit that device: yield to an incoming live session primary
 *    instead, else classic.  A client that is not a held ghost now:
 *    classic.
 *  - DROP: only for our session's own held ghost and an incoming client
 *    whose state is known: held -> rebind as held, live member -> rebind
 *    as live.  Never without a session, never for an unknown state or a
 *    login in no session: classic.
 *  - DEMOTE: a live primary swaps when its demote can run
 *    (bounce_merge_choose()), else classic.  A held ghost is never
 *    demoted (it has no socket to keep): it yields to an incoming live
 *    session primary when it is its session's primary and may yield,
 *    else classic.
 *
 * KEEP is the only verdict that refuses; every other action but classic
 * makes our side yield, so two servers acting on complementary verdicts
 * take complementary actions.
 *
 * @param[in] verdict  The verdict for our side.
 * @param[in] incoming The incoming side the verdict read; NULL is classic.
 * @param[in] now      Our client now; NULL is classic.
 * @return The action.
 */
extern enum bounce_nick_action
bounce_nick_action(enum bounce_nick_verdict verdict,
                   const struct bounce_nick_side *incoming,
                   const struct bounce_nick_now *now);

/** Short names for logs: "classic", "keep", ... */
extern const char *bounce_nick_verdict_name(enum bounce_nick_verdict v);
extern const char *bounce_nick_action_name(enum bounce_nick_action a);

#endif /* INCLUDED_bouncer_converge_h */
