/** @file chathistory_presence.h
 * @brief Per-anchor channel presence tracking for strict-mode chathistory.
 *
 * Phase B of the strict-presence design (see
 * project_chathistory_design_intent.md).  Records when each presence
 * anchor (account or session_id) was a channel member, so the
 * chathistory replay path can filter messages to "you saw it live."
 *
 * Two storage backings, one filter interface:
 *   - Account anchors: persisted on the shared chathistory storage env
 *     in a "presence" column family, key = "account\0channel".
 *   - Session anchors: in-memory hash, purged on ephemeral client exit.
 *
 * Hooks live in channel.c at add_user_to_channel / remove_user_from_channel,
 * which between them cover JOIN, PART, KICK, QUIT, SQUIT, and burst-rejoin
 * uniformly without per-message-type plumbing.
 *
 * Storage shape (see chathistory_presence.c): per (anchor, channel),
 * a hard-capped list of closed (start,end) intervals plus an
 * open_since marker.  When the cap is exceeded the oldest closed
 * interval is dropped — fail-safe: you may lose visibility into your
 * oldest presence span, but you never gain visibility into a span you
 * weren't present for.
 */
#ifndef INCLUDED_chathistory_presence_h
#define INCLUDED_chathistory_presence_h

#ifndef INCLUDED_sys_types_h
#include <sys/types.h>
#define INCLUDED_sys_types_h
#endif

struct Client;
struct Channel;
struct HistoryMessage;

/** Open the "presence" column family on the chathistory storage env
 * for the account-anchored side, and zero the in-memory session
 * tables.  Called from history_init() after the env is up; safe to
 * call again (idempotent).  Returns 0 on success, -1 if the env is
 * not available or the CF open fails — session-anchored presence
 * keeps working in-memory either way; only account persistence is
 * lost in the failure case.
 */
extern int presence_init(void);

/** Drop persistent handles and free in-memory state.  Called from
 * history_shutdown().  Safe to call without a prior init. */
extern void presence_shutdown(void);

/** Record that @a anchor entered @a channel at @a when.  Idempotent
 * if an interval is already open for this anchor in this channel.
 * Hooked from add_user_to_channel(); not normally called directly.
 *
 * @param anchor             Account name or session_id (NUL-terminated).
 * @param anchor_is_session  Nonzero iff @a anchor is a session_id
 *                           (in-memory storage); zero for account
 *                           (persistent storage).
 * @param channel            Channel name (case-insensitive).
 * @param when               Event timestamp (epoch seconds).
 */
extern void presence_record_join(const char *anchor, int anchor_is_session,
                                  const char *channel, time_t when);

/** Close the open presence interval for @a anchor in @a channel.
 * No-op if no interval is open.  Hooked from remove_user_from_channel(). */
extern void presence_record_part(const char *anchor, int anchor_is_session,
                                  const char *channel, time_t when);

/** Was @a anchor present in @a channel at @a msg_time?  Returns nonzero
 * iff any open or closed interval contains @a msg_time. */
extern int presence_was_present(const char *anchor, int anchor_is_session,
                                 const char *channel, time_t msg_time);

/** Resolve the canonical presence anchor for @a cli: account name if
 * the client is authed, else cli_session_id.  Returns the anchor
 * string (pointer into the Client struct; do not free) and sets
 * *@a is_session_out nonzero iff the session_id was used.  Returns
 * NULL if neither is populated (which shouldn't happen after Phase A
 * but is handled defensively). */
extern const char *presence_anchor_for(const struct Client *cli,
                                        int *is_session_out);

/** Purge all in-memory presence records for a session anchor.  Called
 * from ephemeral_purge_session() during exit_one_client(). */
extern void presence_purge_session(const char *session_id);

/** Hook for add_user_to_channel().  Records a presence-join for the
 * client's anchor in @a chptr unless another connection of the same
 * anchor is already a channel member (the bouncer-aliases case —
 * presence is per-anchor, not per-connection, so the first sibling
 * opens the interval and subsequent siblings are no-ops).  Cheap
 * early-out if FEAT_CHATHISTORY_STRICT_PRESENCE is disabled. */
extern void presence_on_channel_add(struct Client *who, struct Channel *chptr);

/** Hook for remove_user_from_channel().  Must be called BEFORE the
 * underlying remove_member_from_channel() because the implementation
 * walks @a chptr's member list (with @a who excluded) to decide
 * whether any sibling connection of the same anchor remains.  Records
 * a presence-part only when the last sibling leaves.  Cheap early-out
 * if FEAT_CHATHISTORY_STRICT_PRESENCE is disabled. */
extern void presence_on_channel_remove(struct Client *who, struct Channel *chptr);

/** Sweep presence records: prune intervals fully older than the
 * configured chathistory retention; truncate the leading edge of any
 * interval that straddles the retention boundary.  Drops in-memory
 * records that become empty.  Intended to be called from the
 * existing chathistory maintenance timer. */
extern void presence_retention_sweep(void);

/** Filter a chathistory result list down to messages @a requestor was
 * present for in @a target.  Mutates *@a head, unlinking and freeing
 * messages that fail the presence check.  Returns the new message
 * count.  No-op (returns @a count_in unchanged) when:
 *   - FEAT_CHATHISTORY_STRICT_PRESENCE is disabled;
 *   - @a target is not a channel name (PMs are gated by participant
 *     check elsewhere);
 *   - the channel has EXMODE_PUBLICHISTORY (+H) set; or
 *   - @a ops_override is non-zero (validated by the caller as a real
 *     ops privilege, not just a parameter echo).
 *
 * Phase B baseline filters by message timestamp only; the redaction-
 * inheritance pass (visibility of a child = visibility of its target)
 * lands in the follow-up commit.
 *
 * @param requestor    The client whose presence anchor drives filtering.
 * @param target       Channel name (or PM target — no-op for PMs).
 * @param head         Address of the message-list head pointer.
 * @param count_in     Current list length.
 * @param ops_override Non-zero if the caller has authorized a full
 *                     unfiltered replay (validated up-stack).
 * @return The number of messages remaining in the list.
 */
extern int presence_filter_messages(struct Client *requestor,
                                     const char *target,
                                     struct HistoryMessage **head,
                                     int count_in,
                                     int ops_override);

#endif /* INCLUDED_chathistory_presence_h */
