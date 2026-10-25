/*
 * IRC - Internet Relay Chat, include/bouncer_wire.h
 *
 * Pure wire decisions for the bouncer: which direct server link may hold
 * a given client "face".  No ircd dependencies, so the cmocka suite
 * (ircd/test/bouncer_wire_cmocka.c) compiles it standalone; the callers
 * in bouncer_session.c read the link and client state and pass it in.
 */
#ifndef INCLUDED_bouncer_wire_h
#define INCLUDED_bouncer_wire_h

/** May a direct server link know a face as a user it learned by N from
 * us?
 *
 * A legacy (non-IRCv3-aware) server knows a bouncer session only by the
 * faces it was introduced to by N.  When a face is retired or renumbered
 * on our side, every legacy link that may know it must be told (a Q, or
 * a BX P swap).  A link does NOT know the face when:
 *  - it is IRCv3-aware: it follows the session through BX/BS itself;
 *  - it is still burst-gated: we have sent it no N yet, and the burst it
 *    gets at release carries the final state once;
 *  - the face lives behind it: it introduced the face to us, so it is
 *    that link's own news, never ours to retract.
 * Any other link may know it, whatever face the session's burst records
 * name: a face also reaches a legacy link by the ordinary N relay, which
 * records nothing, and a record can be stale.  Telling a link that never
 * knew the face costs nothing: a stock server drops a Q from an unknown
 * numeric, and leaves a BX P whose old numeric it does not know alone.
 *
 * @param[in] link_aware       Nonzero if the link is IRCv3-aware.
 * @param[in] link_gated       Nonzero if the link's burst is still gated.
 * @param[in] face_behind_link Nonzero if the face is a remote client whose
 *                             direction is this link.
 * @return 1 if the link may know the face, else 0.
 */
extern int bounce_legacy_link_knows(int link_aware, int link_gated,
                                    int face_behind_link);

#endif /* INCLUDED_bouncer_wire_h */
