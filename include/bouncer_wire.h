/*
 * IRC - Internet Relay Chat, include/bouncer_wire.h
 *
 * Pure wire decisions for the bouncer: which direct server link may hold
 * a given client "face", and whether a live primary may be demoted into
 * an alias of a new primary.  No ircd dependencies, so the cmocka suite
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
  BOUNCE_DEMOTE_SESSION_ACCOUNT   /**< the session is another account's */
};

/** May a live primary be demoted into an alias of a new primary?
 *
 * A legacy home is refused: a legacy server has no sessions (the new
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

#endif /* INCLUDED_bouncer_wire_h */
