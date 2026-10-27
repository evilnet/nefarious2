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

/** What a BX C does with an alias this server knows already. */
enum bounce_bxc_known {
  BOUNCE_BXC_KNOWN_IGNORE,  /**< not the line's to change: a connection of
                             *   ours, or one behind another link */
  BOUNCE_BXC_KNOWN_KEEP,    /**< already as the line says: nothing changes */
  BOUNCE_BXC_KNOWN_REFILE   /**< it follows the line: its primary, its
                             *   record, its nick and its session id */
};

/** A BX C for an alias we know already: its server announces it again (a
 * link burst after an announcement we had, a session announced again), or
 * under another primary or session (its held copy yielded to another
 * server's live one, its session took another id).  Only the alias's own
 * server speaks for it, over the link it is behind.  The line then says
 * what the alias is now, as a BX C for a new one does: whose alias, filed
 * in which record (bounce_alias_filing()), under which nick (its
 * primary's: the line carries none) and which session id.
 *
 * @param[in] behind_link    The alias is behind the link the line came
 *                           over.
 * @param[in] same_primary   Its primary here is the one the line names.
 * @param[in] filed_as_named Our rosters list it where the filing order
 *                           puts it: in the record chosen and in no other,
 *                           or in none when the order chooses none.
 * @param[in] same_nick      It carries the named primary's nick.
 * @param[in] same_sessid    It carries the line's session id.
 */
extern enum bounce_bxc_known bounce_bxc_known_alias(int behind_link,
                                                    int same_primary,
                                                    int filed_as_named,
                                                    int same_nick,
                                                    int same_sessid);

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
 * Only the session's own live devices count (bounce_alias_is_own()): a
 * ghost whose roster lists only another copy's devices ends its own copy.
 *
 * @param[in] has_primary       Nonzero if the session has a primary.
 * @param[in] primary_ours_held Nonzero if it is a held ghost of ours.
 * @param[in] alias_count       The session's own live aliases on its
 *                              roster.
 */
extern enum bounce_hold_expiry bounce_hold_expiry_action(int has_primary,
                                                         int primary_ours_held,
                                                         int alias_count);

/** Is an alias on a record's roster a device of that record's own copy of
 * the session -- one a promote may make its primary, and one that keeps
 * its held ghost from reading as held?
 *
 * Two servers can each hold a copy of one session (both held after a
 * split, under two nicks), and a burst files the other copy's live device
 * on our record's roster by the session id.  That device follows the
 * other copy's primary: a user, not an alias, that is not our record's
 * primary.  Promoting it would make our server decide for the other copy
 * (its holder does), and move the session onto that device under our
 * nick.  Every other alias is the record's own: one that follows our
 * primary, one whose primary is unknown or itself an alias, and every
 * alias of a record with no primary (a promote at a split).
 *
 * @param[in] has_slot             The record has a primary (hs_client).
 * @param[in] primary_set          The alias has a primary (alias_primary).
 * @param[in] primary_is_slot      That primary is the record's.
 * @param[in] primary_is_user      That primary is a user that is not an
 *                                 alias.
 * @return 1 if the alias is the record's own, else 0.
 */
extern int bounce_alias_is_own(int has_slot, int primary_set,
                               int primary_is_slot, int primary_is_user);

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

/** After a BS D that left our record as it was (BOUNCE_BSD_NOTE), do we
 * announce our primary to the sender's link again?
 *
 * Only over our own LIVE primary: the sender's copy of the session just
 * went held while ours is live, and the live copy wins -- but a BS D says
 * nothing of ours, so the sender's held ghost would keep the nick until
 * its hold ran out.  Our primary's BS A, sent outside a burst, is what
 * makes a held copy yield (bounce_bsa_yields()).  Over our own held ghost
 * neither copy is live: nothing.  Only toward a link that announces the
 * hold mark: a build without the BS A install guard would install our
 * primary over its held ghost instead of yielding it.
 *
 * @param[in] action         What the BS D did (bounce_bsd_action()).
 * @param[in] slot_live      Our record's primary is our own live client
 *                           (not a held ghost, not an alias).
 * @param[in] link_hold_mark The link announced the hold mark (H).
 */
extern int bounce_bsd_reannounces(enum bounce_bsd_action action, int slot_live,
                                  int link_hold_mark);

/** What a BX P (a promote, or a face swap, on another server) does to our
 * record of the session it names. */
enum bounce_bxp_session_action {
  BOUNCE_BXP_APPLY,   /**< the record follows: the new client is its primary */
  BOUNCE_BXP_KEEP,    /**< our own live primary holds the slot: unchanged */
  BOUNCE_BXP_YIELD    /**< our own held ghost holds the slot: our held copy
                       *   yields to the sender's live one */
};

/** The BX P receiver's rule for our record, as at BS A and BS D: a record
 * whose primary slot holds our own client (live or a held ghost) is ours
 * to decide.  A BX P whose old client IS that slot renumbers it (a swap of
 * our face): applied.  A BX P whose new client is that slot names our own
 * client as the face: the record holds it already, and a held ghost stays
 * held (never a yield, which would exit the very client the line names).
 * Any other BX P names another server's copy of the session: over our live
 * primary nothing changes; over our held ghost the live copy wins
 * (bounce_same_session_yields()), as at BS A.
 *
 * @param[in] slot_ours      Our record's primary is a user of ours (live
 *                           or a held ghost), not an alias.
 * @param[in] slot_held      That user is a held ghost.
 * @param[in] old_is_slot    The BX P's old client is that user.
 * @param[in] new_is_slot    The BX P's new client is that user.
 * @param[in] ours_holding   Our record is HOLDING and held here.
 * @param[in] kc_conflict    The new client's Keycloak id is not the
 *                           session's.
 */
extern enum bounce_bxp_session_action
bounce_bxp_session_action(int slot_ours, int slot_held, int old_is_slot,
                          int new_is_slot, int ours_holding, int kc_conflict);

/** What a session primary's disconnect does.  One rule for every way a
 * primary goes: a QUIT, a socket that died (EOF, a read or write error, a
 * sendQ overflow) and a WebSocket close. */
enum bounce_disconnect {
  BOUNCE_DISCONNECT_EXIT,          /**< nothing of the session to keep: the
                                    *   client exits as it would in none */
  BOUNCE_DISCONNECT_PROMOTE_LOCAL, /**< try a live device of the session on
                                    *   this server: it takes the primary's
                                    *   place now, and the client exits */
  BOUNCE_DISCONNECT_HOLD_PROMOTE,  /**< held, and a live device on another
                                    *   server is promoted at the next tick;
                                    *   with none left then, still held */
  BOUNCE_DISCONNECT_BRIEF_PROMOTE, /**< held only until a live device on
                                    *   another server is promoted at the
                                    *   next tick; with none left then, the
                                    *   session ends */
  BOUNCE_DISCONNECT_HOLD           /**< held for the session's hold */
};

/** What bounce_disconnect_action() decides from. */
struct bounce_disconnect_facts {
  int killed;          /**< the client was KILLed: the KILL ends the whole
                        *   session, devices included */
  int logged_in;       /**< the client is still logged in: a session
                        *   outlives no logout */
  int bouncer_on;      /**< the bouncer is on for the client's class or for
                        *   the network */
  int local_user;      /**< the client is a registered user of ours */
  int active_primary;  /**< it is the primary of an ACTIVE session */
  int wants_hold;      /**< that session's hold preference */
  int own_aliases;     /**< live devices of the session's own copy on its
                        *   roster (bounce_alias_is_own()) */
  int local_tried;     /**< a promote of one of them on this server was
                        *   tried and found none */
};

/** The disconnect rule.  A live device of the session takes over before
 * anything is held: one on this server at once (its state here is the
 * truth, so the promote cannot cross that device's own exit), one on
 * another server after a hold, at the next tick.  The tick only lets a
 * BX X for that device that this server has already read land first; one
 * still on the wire can cross the BX P (the cross is narrowed, not
 * closed).  The hold preference
 * decides only when no device is left: hold, or exit.  So a session with
 * hold off still moves to a live device rather than leaving it without a
 * primary; its hold lasts until the next tick.  Every other guard is the
 * hold's own and stands for a promote too: a KILLed client, a client no
 * longer logged in, a bouncer that is off, a client not ours or not the
 * primary of an ACTIVE session keep nothing.
 *
 * @param[in] f The facts (NULL: EXIT).
 * @return The action.  After a PROMOTE_LOCAL that found no device here,
 *         ask again with local_tried set and own_aliases counted again.
 */
extern enum bounce_disconnect
bounce_disconnect_action(const struct bounce_disconnect_facts *f);

/** What the orphan sweep does with an alias that has lost its primary. */
enum bounce_orphan_action {
  BOUNCE_ORPHAN_KEEP,     /**< not ours to act on, or not an orphan */
  BOUNCE_ORPHAN_REPOINT,  /**< it follows its session's primary again */
  BOUNCE_ORPHAN_EXIT      /**< its session has no primary: it leaves
                           *   ("Bouncer session ended") */
};

/** The orphan sweep's rule: a backstop for an alias whose primary went
 * with no session end reaching it (an exit that took no device with it,
 * a split whose promote found none).  An alias has no nick of its own on
 * the network: left without a primary it is connected but invisible.
 *
 * Only an alias of ours is acted on: another server's alias is that
 * server's (exiting a remote client here splits the network).  An alias
 * that still follows a primary is no orphan, whether or not a record
 * files it.  An orphan its session's record still has a primary for
 * follows that primary again; any other orphan leaves.
 *
 * @param[in] local         The alias is a client of ours.
 * @param[in] has_primary   It still follows a primary.
 * @param[in] filed         A record of its session was found (the one
 *                          that lists it, else the one of its id).
 * @param[in] primary_live  That record has a primary: a user, not an
 *                          alias, not being killed.
 * @param[in] kc_conflict   That record is another Keycloak user's.
 */
extern enum bounce_orphan_action
bounce_orphan_alias_action(int local, int has_primary, int filed,
                           int primary_live, int kc_conflict);

/** Does a BS X that ends our record of a session end a device of ours
 * with it?
 *
 * The session's holder decided: every device of the session ends with it
 * (a device has no nick of its own; left behind it would be connected
 * but invisible).  Only a device of the session the holder ended: one of
 * our record's own copy, under the BS X's session id, of the session's
 * Keycloak user, following the sender's face (or no face), on a record
 * whose primary is the sender's (or that has none).
 *
 * @param[in] sender_holds   Our record's primary is a client of the
 *                           BS X's sender, or the record has none.
 * @param[in] own            The device is our record's own copy's
 *                           (bounce_alias_is_own()).
 * @param[in] follows_sender The device follows no primary, or a client
 *                           of the sender.
 * @param[in] same_id        The device carries the BS X's session id.
 * @param[in] kc_conflict    The device's Keycloak id is not the
 *                           session's.
 */
extern int bounce_bsx_ends_device(int sender_holds, int own,
                                  int follows_sender, int same_id,
                                  int kc_conflict);

/** How a session is ended for the devices on its roster. */
enum bounce_session_end {
  BOUNCE_END_KILL,    /**< a KILL or other enforcement: the whole session */
  BOUNCE_END_RETIRE   /**< our held copy gives way to another copy */
};

/** Does ending a session exit a device on its roster?  A KILL ends the
 * whole session: every device, another copy's included (#12).  A retire
 * ends our own copy only: another copy's device follows that copy's
 * primary, which carries on.
 *
 * @param[in] how The kind of end.
 * @param[in] own The device is the record's own copy's
 *                (bounce_alias_is_own()).
 */
extern int bounce_session_end_exits(enum bounce_session_end how, int own);

/** Why a connection is forced off. */
enum bounce_forced_exit {
  BOUNCE_FORCED_FLOOD,      /**< Excess Flood, in any of its forms */
  BOUNCE_FORCED_WEBSOCKET,  /**< a WebSocket frame, size, fragment or
                             *   UTF-8 error */
  BOUNCE_FORCED_BUFFER,     /**< the receive buffer took no more data */
  BOUNCE_FORCED_BAN,        /**< a G-, K- or Z-line, a banned client
                             *   version */
  BOUNCE_FORCED_SERVICES    /**< a quit services forced (SVSQUIT) */
};

/** Is a forced exit punitive (an oper's or services' enforcement) rather
 * than a fault of the connection? */
extern int bounce_forced_exit_punitive(enum bounce_forced_exit why);

/** What a forced exit does to the session its victim carries. */
enum bounce_forced_action {
  BOUNCE_FORCED_PLAIN,       /**< nothing of a session to act on: the
                              *   victim exits as it would in none */
  BOUNCE_FORCED_DISCONNECT,  /**< a fault: the disconnect rule
                              *   (bounce_disconnect_action()) -- another
                              *   device takes over, else hold or exit */
  BOUNCE_FORCED_END_SESSION, /**< enforcement on the session's primary:
                              *   the whole session ends first (every
                              *   device, everywhere), then its exit
                              *   sends the usual QUIT */
  BOUNCE_FORCED_END_BY_PRIMARY /**< enforcement on a device whose primary
                              *   is ours: the session ends first and its
                              *   primary exits with the same reason */
};

/** Bans end the session; faults promote (user, 2026-10-27).  Enforcement
 * on any connection of a session ends the whole session like a KILL
 * (#12) -- but a primary on another server is that server's to exit, so
 * enforcement on a device here whose primary is elsewhere ends that
 * device only.  A fault on a primary goes through the disconnect rule; a
 * device's exit is always its own.
 *
 * @param[in] why             Why the victim is forced off.
 * @param[in] is_alias        The victim is an alias.
 * @param[in] session_primary The victim is the primary of a session.
 * @param[in] primary_ours    The victim is an alias whose session primary
 *                            is a user of ours.
 */
extern enum bounce_forced_action
bounce_forced_exit_action(enum bounce_forced_exit why, int is_alias,
                          int session_primary, int primary_ours);

#endif /* INCLUDED_bouncer_wire_h */
