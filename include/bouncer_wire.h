/*
 * IRC - Internet Relay Chat, include/bouncer_wire.h
 *
 * Pure wire decisions for the bouncer: which direct server link already
 * holds a given client "face".  No ircd dependencies, so the cmocka
 * suite (ircd/test/bouncer_wire_cmocka.c) compiles it standalone; the
 * callers in bouncer_session.c read the link and client state and pass
 * it in.
 */
#ifndef INCLUDED_bouncer_wire_h
#define INCLUDED_bouncer_wire_h

/** Does a direct server link know `face_numeric` as a user it learned
 * by N from us?
 *
 * A legacy (non-IRCv3-aware) server knows a bouncer session only by the
 * faces it was introduced to by N.  When a face is retired or renumbered
 * on our side, every legacy link that knows it must be told (a Q, or a
 * BX P swap), and no other link may be.  A link does NOT know the face
 * when:
 *  - it is IRCv3-aware: it follows the session through BX/BS itself;
 *  - it is still burst-gated: we have sent it no N yet, and the burst it
 *    gets at release carries the final state once;
 *  - the face lives behind it: it introduced the face to us, so it is
 *    that link's own news, never ours to retract;
 *  - the session recorded a different face toward it: the burst sent it
 *    that other face and suppressed this one.
 * Otherwise it does: either it holds exactly this recorded face, or
 * nothing was recorded and the face reached it by the ordinary N relay.
 *
 * @param[in] link_aware       Nonzero if the link is IRCv3-aware.
 * @param[in] link_gated       Nonzero if the link's burst is still gated.
 * @param[in] face_behind_link Nonzero if the face is a remote client whose
 *                             direction is this link.
 * @param[in] recorded_face    The full YYXXX the session recorded toward
 *                             this link, or NULL / "" for none.
 * @param[in] face_numeric     The face's full YYXXX.
 * @return 1 if the link knows the face, else 0.
 */
extern int bounce_legacy_link_knows(int link_aware, int link_gated,
                                    int face_behind_link,
                                    const char *recorded_face,
                                    const char *face_numeric);

#endif /* INCLUDED_bouncer_wire_h */
