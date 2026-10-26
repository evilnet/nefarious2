/*
 * IRC - Internet Relay Chat, include/bouncer_wire.h
 *
 * Pure wire decisions for the bouncer: which direct server link may hold
 * a given client "face", whether a live primary may be demoted into an
 * alias of a new primary, which way a same-nick merge goes, and the hold
 * mark a home server stamps on its client's N.  No ircd
 * dependencies, so the cmocka suite
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

/** Where a live primary's demote into an alias of a new primary stands.
 *
 * The demote runs in two steps on one session: the demote proper (the
 * face, still the session's live primary, becomes an alias and the
 * primary slot is emptied), then the finish once the new primary's
 * Client exists (the slot takes the new primary).  Every caller asks the
 * same question at the stage it stands at, so a "yes" before the demote
 * means both steps succeed.
 */
enum bounce_demote_stage {
  BOUNCE_DEMOTE_PLAN,   /**< before the demote: the face is the live primary */
  BOUNCE_DEMOTE_FINISH  /**< after it: the face is an alias, the slot empty */
};

/** What the slot of the face's session holds. */
enum bounce_demote_slot {
  BOUNCE_SLOT_FACE,     /**< the face itself */
  BOUNCE_SLOT_EMPTY,    /**< nothing (between the demote and its finish) */
  BOUNCE_SLOT_OTHER     /**< another client */
};

/** The facts a demote rests on, read by the caller (each 0 or 1). */
struct bounce_demote_facts {
  /* The face: our client that becomes (or became) the alias. */
  int face_account_user;   /**< a registered user with an account */
  int face_alias;          /**< flagged as an alias */
  int face_held;           /**< a held ghost */
  int face_dying;          /**< its socket is dead, or it was killed */
  /* Its session. */
  int session_found;       /**< there is a session */
  int session_account;     /**< the session's account is the face's */
  enum bounce_demote_slot session_slot; /**< what its primary slot holds */
  /* The new primary. */
  int new_home_known;      /**< its home server is known */
  int new_home_aware;      /**< that home server is IRCv3-aware */
  int new_account;         /**< it carries the face's account */
  int kc_id_conflict;      /**< it and the session carry different Keycloak
                            *   ids (a missing id is no conflict) */
};

/** Why a demote cannot run (BOUNCE_DEMOTE_OK: it can). */
enum bounce_demote_bar {
  BOUNCE_DEMOTE_OK = 0,
  BOUNCE_DEMOTE_NO_NEW_HOME,      /**< the new primary or its home is unknown */
  BOUNCE_DEMOTE_LEGACY_HOME,      /**< the new primary is homed on a legacy server */
  BOUNCE_DEMOTE_NOT_ACCOUNT_USER, /**< the face is not a user with an account */
  BOUNCE_DEMOTE_FACE_ALIAS,       /**< plan: already an alias; finish: not demoted */
  BOUNCE_DEMOTE_FACE_HELD,        /**< the face is a held ghost */
  BOUNCE_DEMOTE_FACE_DYING,       /**< the face is on its way out */
  BOUNCE_DEMOTE_NO_SESSION,       /**< no session */
  BOUNCE_DEMOTE_SESSION_SLOT,     /**< plan: face not the primary; finish: slot taken */
  BOUNCE_DEMOTE_NEW_ACCOUNT,      /**< the new primary has no account, or another */
  BOUNCE_DEMOTE_SESSION_ACCOUNT,  /**< the session is another account's */
  BOUNCE_DEMOTE_KC_CONFLICT       /**< another Keycloak user (never merged) */
};

/** May a live primary be demoted into an alias of a new primary?
 *
 * A different Keycloak user under the same account name (the account was
 * recreated) is refused before anything else: sessions of different ids
 * are never merged, and both sides of a merge read the same two ids.  A
 * legacy home is refused: a legacy server has no sessions (the new
 * primary is not a session member) and BX C never reaches it, so it
 * could not carry the session's aliases.  A dying face is refused: an
 * alias exit broadcasts BX X and would end the session everywhere,
 * while the primary's own exit holds it.  At PLAN the face must be the
 * session's live primary; at FINISH it must be the alias the demote made
 * and the slot empty.  The account rules are the finish's, checked at
 * PLAN too, so a PLAN "yes" carries through the finish.
 *
 * @param[in] stage The step the caller stands at.
 * @param[in] f     The facts; NULL is refused.
 * @return BOUNCE_DEMOTE_OK, or the first bar that applies.
 */
extern enum bounce_demote_bar
bounce_demote_check(enum bounce_demote_stage stage,
                    const struct bounce_demote_facts *f);

/** A short name for a bar, for logs ("ok", "legacy home", ...). */
extern const char *bounce_demote_bar_name(enum bounce_demote_bar bar);

/** What a same-nick merge of two live primaries of one account does on
 * the side that receives the other primary's N. */
enum bounce_merge_choice {
  BOUNCE_MERGE_REFUSE,  /**< ours wins: refuse the N, the peer demotes */
  BOUNCE_MERGE_SWAP,    /**< ours loses and can be demoted: install the
                         *   incoming primary for IRCv3-aware links only,
                         *   swap the legacy face to it (BX P), demote */
  BOUNCE_MERGE_CLASSIC  /**< no merge: the classic nick-collision rules */
};

/** The merge's branch, from who wins and the demote's eligibility.
 *
 * Different Keycloak users are never merged, whichever side would win:
 * classic collision on both sides.  Otherwise the winner refuses the N.
 * The loser merges only when its demote can run (BOUNCE_DEMOTE_PLAN
 * said OK); a demote that cannot run leaves its primary live under the
 * nick the incoming N claims, so the classic rules decide (for one
 * account, the older nick wins).
 *
 * @param[in] we_lose Nonzero if our primary is the newer one.
 * @param[in] bar     bounce_demote_check(BOUNCE_DEMOTE_PLAN, ...) for our
 *                    primary and the incoming one.
 */
extern enum bounce_merge_choice bounce_merge_choose(int we_lose,
                                                    enum bounce_demote_bar bar);

/* The hold mark: the compact-tag ,H<x> segment a client's home server
 * puts on the client's N, after its ,S session id.  It tells the server
 * receiving the N what a same-nick verdict (bouncer_converge.h) needs to
 * know about the client and cannot learn any other way before the burst
 * ends: is it a held ghost, a live session primary, or a live login that
 * is not its session's primary.  Only servers that announce SERVER flag
 * H stamp and relay it; a server relaying someone else's N copies the
 * mark it received or sends none. */
#define BOUNCE_HOLD_MARK_HELD     'h'  /**< a held ghost with no live alias */
#define BOUNCE_HOLD_MARK_PRIMARY  'p'  /**< live, its session's primary */
#define BOUNCE_HOLD_MARK_OUTSIDER 'n'  /**< live, and not the primary of
                                        *   one session: in no session,
                                        *   only on a session's alias
                                        *   roster, or named as primary
                                        *   by two sessions */

/** The mark a home server stamps on its own client's N.
 *
 * The inputs are the predicates the same-nick verdict reads for the
 * client on its own server, so the server receiving the N decides from
 * the facts the home server would decide from:
 *  - held:    bounce_nick_side_held() -- a held ghost whose session has
 *             no live alias (a held ghost with one counts as live; one
 *             two sessions name is not held);
 *  - primary: the client is the hs_client of the session the session-id
 *             hint names (the verdict's local_is_session_primary); 0 for
 *             a client only on a roster or named by two sessions.
 * Both come from one bounce_nick_side_lookup() call.  A held ghost is
 * its session's hs_client too: held wins.
 *
 * @param[in] held    Nonzero if the client is held (see above).
 * @param[in] primary Nonzero if it is its session's primary.
 * @return BOUNCE_HOLD_MARK_HELD, _PRIMARY or _OUTSIDER.
 */
extern char bounce_hold_stamp(int held, int primary);

/** Is @a mark one of the three hold marks?  A receiver keeps only these;
 * anything else on the wire reads as no mark. */
extern int bounce_hold_mark_valid(char mark);

/** May the hold marks of a client's N be trusted, given what the walk
 * from the client's home server toward us found?
 *
 * Trusted when we send marks ourselves (P10_MESSAGE_TAGS on), the walk
 * reached our own link, every server on it (home and our direct link
 * included) announced SERVER flag H, and our SERVER line to that link
 * announced H: the far end judges our marks by that announcement, so we
 * trust its marks only if it trusts ours.  For a direct link this is the
 * same fact on both ends; through more hops, and across a runtime switch
 * of the tags, the two ends can differ (registered).
 *
 * @param[in] hops        Servers on the path, home to our link inclusive.
 * @param[in] hops_with_h How many of them announced SERVER flag H.
 * @param[in] reached_us  Nonzero if the walk ended at our link.
 * @param[in] sent_h      Nonzero if our SERVER line to that link
 *                        announced H.
 * @param[in] tags_on     Nonzero if P10_MESSAGE_TAGS is on.
 * @return 1 if trusted, else 0.
 */
extern int bounce_hold_marks_trusted_path(int hops, int hops_with_h,
                                          int reached_us, int sent_h,
                                          int tags_on);

/** Which of our sessions a BX C files its alias into. */
enum bounce_alias_filing {
  BOUNCE_FILE_EXACT,    /**< the session of the id the BX C names */
  BOUNCE_FILE_PRIMARY,  /**< the session whose primary (hs_client) is the
                         *   primary the BX C names */
  BOUNCE_FILE_ACCOUNT,  /**< our session of the account: the BX C was sent
                         *   before its server took our id in a rename */
  BOUNCE_FILE_NONE      /**< none: the alias is tracked in no session */
};

/** Where a BX C's alias is filed, from what the lookups found.
 *
 * The id the BX C names first; else the session whose primary is the
 * BX C's primary (it follows a merge that left the ids apart); else our
 * session of the account, which covers a BX C sent before its server
 * took our id -- but never for an id BS C left unmirrored here: that
 * session was kept apart from ours (or loses to ours and is about to
 * end), and an alias of it is not one of ours.  A session of another
 * Keycloak user is refused by the caller, whichever is chosen.
 *
 * @param[in] exact      Nonzero if a session of the named id exists here.
 * @param[in] by_primary Nonzero if a session here has the named primary
 *                       as its hs_client.
 * @param[in] by_account Nonzero if the account has a session here that
 *                       the fallback may use (same Keycloak user).
 * @param[in] unmirrored Nonzero if BS C left the named id unmirrored here.
 */
extern enum bounce_alias_filing bounce_alias_filing(int exact, int by_primary,
                                                    int by_account,
                                                    int unmirrored);

#endif /* INCLUDED_bouncer_wire_h */
