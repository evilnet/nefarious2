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

/** Which of our sessions a BX P (a promote: <old primary> <new primary>
 * <session id>) updates. */
enum bounce_promote_session {
  BOUNCE_PROMOTE_EXACT,    /**< the session of the id the BX P names */
  BOUNCE_PROMOTE_PRIMARY,  /**< the session whose primary is the old one
                            *   and which lists the new one as its alias */
  BOUNCE_PROMOTE_NONE      /**< none: no session here is updated */
};

/** Where a BX P's promote lands, from what the lookups found.
 *
 * The id the BX P names first.  Else -- a merge left the two servers'
 * records of one session under two ids -- our session whose primary
 * (hs_client) is the BX P's old primary, but only when exactly one
 * session claims that primary and it lists the new primary on its alias
 * roster: the promote is then of our record's own alias.  A BX P whose
 * new primary is on no roster here (a swap of a face) updates nothing.
 *
 * @param[in] exact          Nonzero if a session of the named id exists.
 * @param[in] by_old_primary Nonzero if a session here has the old primary
 *                           as its hs_client.
 * @param[in] ambiguous      Nonzero if two or more sessions do.
 * @param[in] new_on_roster  Nonzero if that session lists the new primary
 *                           on its alias roster.
 */
extern enum bounce_promote_session
bounce_promote_session(int exact, int by_old_primary, int ambiguous,
                       int new_on_roster);

/** Deepest server tree a walk toward the root follows (P10 numbers at
 * most 4096 servers); a longer walk is a broken tree and answers "no". */
#define BOUNCE_MAX_SERVER_DEPTH 4096

/** Is @a srv the server @a departing, or a server behind it?
 *
 * Walks from @a srv toward the root of our server tree, one uplink at a
 * time (@a up), until it meets @a departing (yes) or the root, whose
 * uplink is itself or NULL (no).  The callers pass server Clients and
 * their cli_serv()->up; the walk only compares the pointers.
 *
 * @param[in] srv       Where to start (a client's server).
 * @param[in] departing The server leaving the network.
 * @param[in] up        The uplink of a server.
 * @return 1 when @a srv is at or behind @a departing, else 0.
 */
extern int bounce_server_at_or_behind(const void *srv, const void *departing,
                                      const void *(*up)(const void *));

/** Does a split ready a session for promotion, by where its primary is?
 *
 * A session whose primary is a client of another server is readied when
 * that server is the departing one or behind it: its primary leaves with
 * the split, and a surviving alias takes its place.  A session whose
 * primary is ours (live, or a held ghost) is never readied: the split
 * took nothing of it but aliases, and those leave by their own exits.  A
 * session with no primary at all (a replica BS C made whose primary
 * never resolved) has only the origin it recorded to go by.
 *
 * @param[in] has_primary    Nonzero if the session has a primary (hs_client).
 * @param[in] primary_local  Nonzero if that primary is our client.
 * @param[in] primary_behind Nonzero if its server is at or behind the
 *                           departing server.
 * @param[in] origin_behind  Nonzero if the server the session recorded
 *                           as its origin is at or behind the departing
 *                           server (read only when there is no primary).
 * @return 1 to ready the session, else 0.
 */
extern int bounce_squit_prepares(int has_primary, int primary_local,
                                 int primary_behind, int origin_behind);

/** What a session's hold timer does when the hold has run out. */
enum bounce_hold_expiry {
  BOUNCE_HOLD_END,      /**< our held ghost, no alias: the session ends
                         *   everywhere (BS X), the ghost leaves */
  BOUNCE_HOLD_PROMOTE,  /**< a live alias takes the primary's place */
  BOUNCE_HOLD_KEEP,     /**< the primary is not a ghost we hold (a client
                         *   of another server, or live): its holder
                         *   decides, nothing ends here */
  BOUNCE_HOLD_DROP      /**< no primary and no alias: our record goes,
                         *   nothing is sent */
};

/** The hold timer's action, from what the session is when it fires.
 *
 * Only the holder ends a session: a server ends one (BS X) only when the
 * primary is a ghost it holds.  A session whose primary is a client of
 * another server, or a live one, has moved since the timer was armed:
 * ending it from here would end it under that primary (a peer destroys
 * its record on BS X), and promoting an alias here would make a second
 * primary.
 *
 * @param[in] has_primary       Nonzero if the session has a primary.
 * @param[in] primary_ours_held Nonzero if it is a held ghost of ours.
 * @param[in] alias_count       Aliases on the session's roster.
 */
extern enum bounce_hold_expiry bounce_hold_expiry_action(int has_primary,
                                                         int primary_ours_held,
                                                         int alias_count);

/** Does our held copy of a session yield to a peer's live copy of it?
 *
 * One session (one id) can be held here while the peer has it live: a
 * restart restored our ghost, or our primary's socket dropped during a
 * split while the peer promoted an alias.  The live copy wins (user,
 * 2026-10-24), whichever server either record names as the session's
 * origin: our ghost leaves and our record follows the peer's primary.
 * It yields only to a primary we can see -- one the peer introduced to us
 * under the session's id -- so a primary refused at N time (a same-nick
 * meeting this server kept) never takes the session from our ghost
 * afterwards; and never across Keycloak users.
 *
 * @param[in] ours_holding     Nonzero if our record is HOLDING and we hold
 *                             something of it here (its ghost, or an alias).
 * @param[in] ours_live        Nonzero if its primary is a live client of
 *                             ours (a record that only says HOLDING).
 * @param[in] theirs_active    Nonzero if the peer announces it active.
 * @param[in] their_primary    Nonzero if the peer's primary of it is known
 *                             here.
 * @param[in] kc_conflict      Nonzero if the Keycloak ids differ.
 * @return 1 when ours yields, else 0.
 */
extern int bounce_same_session_yields(int ours_holding, int ours_live,
                                      int theirs_active, int their_primary,
                                      int kc_conflict);

/** Does a BS X naming one of our records leave it in place?
 *
 * Only the server holding a session ends it.  A record whose primary is a
 * client of ours -- live, or a held ghost -- is held here: the BS X ends
 * the sender's own copy (its held copy's hold ran out, a client of a
 * session sharing the id lost a collision, a member there ended it) and
 * nothing of ours.  Our KILL path, our hold timer and our own users' commands
 * end it.  A primary being killed is on its way out: its exit ends the
 * session anyway.
 *
 * @param[in] has_primary    Nonzero if the record has a primary (hs_client).
 * @param[in] primary_ours   Nonzero if it is a user of ours (a live client
 *                           or a held ghost, not an alias).
 * @param[in] primary_killed Nonzero if it carries FLAG_KILLED.
 * @return 1 to keep the record (and not relay the BS X), else 0.
 */
extern int bounce_bsx_keeps(int has_primary, int primary_ours,
                            int primary_killed);

/** What a BS A line does to our record of the session it names. */
enum bounce_bsa_action {
  BOUNCE_BSA_INSTALL,  /**< the client it names is the session's primary:
                        *   it takes the primary slot, its numeric is kept */
  BOUNCE_BSA_NUMERIC,  /**< the client it names is not known here and the
                        *   slot is not ours: only its numeric is kept (a
                        *   holder that restarted renumbered its ghost) */
  BOUNCE_BSA_IGNORE    /**< the slot and the kept numeric stay as they are */
};

/** What a BS A does to the primary slot (hs_client) of our record.
 *
 * A BS A names one connection of the session by its sender's numeric:
 * the sender's primary or held ghost, or -- in a link burst -- each of
 * the sender's own aliases, for their activity.  It never puts in the
 * slot:
 *  - an alias, or a client our record lists on its alias roster: the
 *    line is that connection's own, and updates only its roster entry;
 *  - a client of ours: the sender cannot speak for it;
 *  - anything at all while the slot holds a client of ours, our live
 *    primary or our held ghost: only we decide what our own client is
 *    (the yield at BS C, the same-nick decisions, the post-burst
 *    reconcile), and a peer's burst announces its copy of the session,
 *    not ours.
 * When it puts nothing in, it also leaves the numeric our record keeps
 * alone.
 *
 * @param[in] resolved       Nonzero if the named numeric is a user here.
 * @param[in] cand_alias     Nonzero if that user is a bouncer alias.
 * @param[in] cand_on_roster Nonzero if our record lists it as an alias.
 * @param[in] cand_ours      Nonzero if it is a client of ours.
 * @param[in] slot_ours      Nonzero if our record's primary is a user of
 *                           ours (live, or a held ghost), not an alias.
 */
extern enum bounce_bsa_action bounce_bsa_action(int resolved, int cand_alias,
                                                int cand_on_roster,
                                                int cand_ours, int slot_ours);

/** Does a BS A our held copy of a session ignored make that copy yield?
 *
 * Outside a burst a BS A announces that a connection attached to the
 * sender's copy of the session: a revive of its held ghost, or a login
 * reclaiming it.  When our own held ghost holds the slot, the line
 * changes nothing (bounce_bsa_action), yet the session is now live
 * there and only held here: the live copy wins, as at BS C
 * (bounce_same_session_yields), and our copy yields to the client the
 * line names -- only to a live member of the session we can see.
 *
 * @param[in] in_burst        Nonzero if the sender is still bursting.
 * @param[in] slot_ours_held  Nonzero if the slot holds our held ghost.
 * @param[in] cand_member     Nonzero if the named client resolves, is
 *                            neither an alias nor on our roster nor ours,
 *                            is behind the link the line came over, and
 *                            carries this session's id.
 * @param[in] ours_holding    Nonzero if our record is HOLDING and we hold
 *                            something of it here.
 * @param[in] kc_conflict     Nonzero if the Keycloak ids differ.
 * @return 1 when our copy yields, else 0.
 */
extern int bounce_bsa_yields(int in_burst, int slot_ours_held,
                             int cand_member, int ours_holding,
                             int kc_conflict);

/** What a BS D (the sender's primary of a session went held) does to our
 * record of that session. */
enum bounce_bsd_action {
  BOUNCE_BSD_APPLY,    /**< our record follows: HOLDING, the sender's ghost
                        *   in the slot, its numeric, time and channels */
  BOUNCE_BSD_NOTE,     /**< our own client holds the slot: nothing of our
                        *   record changes; the sender holds its copy */
  BOUNCE_BSD_FORWARD   /**< a session of another Keycloak user: nothing
                        *   here, the line is only passed on */
};

/** What a BS D does, from the same facts BS A reads.
 *
 * A session of another Keycloak user that shares the id is kept apart:
 * nothing of ours changes.  A slot our own live primary or held ghost
 * holds is ours to decide: the line announces the sender's copy only,
 * and our record, its state, numeric, disconnect time and channels stay.
 *
 * @param[in] kc_conflict Nonzero if the named ghost's Keycloak id is not
 *                        the session's.
 * @param[in] slot_ours   Nonzero if our record's primary is a user of
 *                        ours (live, or a held ghost), not an alias.
 */
extern enum bounce_bsd_action bounce_bsd_action(int kc_conflict, int slot_ours);

#endif /* INCLUDED_bouncer_wire_h */
