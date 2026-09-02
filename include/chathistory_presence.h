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
#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif

struct Client;
struct Channel;
struct HistoryMessage;
struct HistoryRowFilter;

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

/* Presence time (2026-09-02) is the event's HLC stamp packed into an
 * int64: (epoch milliseconds << 16) | logical counter.  Rows carry
 * millisecond stamps, but two events processed inside the same
 * millisecond are still totally ordered by the HLC's logical counter,
 * which every msgid embeds -- so "a message sent right before the JOIN"
 * is hidden even when both land in one millisecond, and a member's own
 * JOIN/PART rows (same stamp as the interval edge) stay visible.
 * Whole-second intervals with inclusive edges used to count a message
 * sent in the same second as the JOIN -- but before it -- as seen.
 * Older stamps migrate on read by magnitude (presence_norm_time). */

#define PRESENCE_TIME_PACK(ms, logical) \
  ((((int64_t)(ms)) << 16) | ((int64_t)((logical) & 0xFFFF)))
#define PRESENCE_TIME_FROM_MS(ms) PRESENCE_TIME_PACK((ms), 0)
/** An ms-only stamp read as the END of its millisecond.  For a listing
 * (TARGETS' last-activity stamp has no msgid to order it inside its
 * millisecond) "activity at or after the join" should include activity
 * in the join's own millisecond; rows keep the start-of-millisecond
 * reading (hidden when unorderable -- the fail-safe direction). */
#define PRESENCE_TIME_FROM_MS_LATE(ms) PRESENCE_TIME_PACK((ms), 0xFFFF)
#define PRESENCE_TIME_MS(t) ((int64_t)(t) >> 16)

/** Reconnect-churn coalescing window: a part/rejoin gap at or below
 * this merges into the previous interval (30 s). */
#define PRESENCE_COALESCE_TIME PRESENCE_TIME_FROM_MS(30000)

/** Normalize a stored/wire stamp to presence time by magnitude: an
 * epoch in seconds (~1.7e9) is below 1e11, one in milliseconds
 * (~1.7e12) below 1e15, a packed stamp (~1.1e17) above. */
extern int64_t presence_norm_time(int64_t v);

/** The presence time of an event: its msgid's HLC stamp when the msgid
 * decodes and its millisecond agrees with @a event_ms (the row's stamp),
 * else (@a event_ms, logical 0). */
extern int64_t presence_event_time(const char *msgid, uint64_t event_ms);

/** Arm the event time the next membership hooks should stamp with --
 * the same event the row is stored for.  Callers set it around the
 * add/remove that fires the hooks and clear it with 0; an unarmed hook
 * stamps the HLC's current time. */
extern void presence_set_event_time(int64_t t);

/** Record that @a anchor entered @a channel at @a when_ms.  Idempotent
 * if an interval is already open for this anchor in this channel.
 * Hooked from add_user_to_channel(); not normally called directly.
 *
 * @param anchor             Account name or session_id (NUL-terminated).
 * @param anchor_is_session  Nonzero iff @a anchor is a session_id
 *                           (in-memory storage); zero for account
 *                           (persistent storage).
 * @param channel            Channel name (case-insensitive).
 * @param when               Event time (presence time, see PRESENCE_TIME_PACK).
 */
extern void presence_record_join(const char *anchor, int anchor_is_session,
                                  const char *channel, int64_t when);

/** Close the open presence interval for @a anchor in @a channel.
 * No-op if no interval is open.  Hooked from remove_user_from_channel(). */
extern void presence_record_part(const char *anchor, int anchor_is_session,
                                  const char *channel, int64_t when);

/** Was @a anchor present in @a channel at presence time @a t?  Returns
 * nonzero iff any open or closed interval contains @a t (inclusive
 * edges, HLC resolution). */
extern int presence_was_present(const char *anchor, int anchor_is_session,
                                 const char *channel, int64_t t);

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


/* Strict-presence hardening (2026-08-30 audit wave) */
extern void presence_touch_last_alive(void);
extern void presence_backfill_now(void);
extern void presence_burst_sync(struct Client *cptr);
extern void presence_apply_close(const char *anchor, int anchor_is_session,
                                 const char *channel, int64_t start,
                                 int64_t end);
extern void presence_anchor_transfer(struct Client *cptr,
                                     const char *old_anchor,
                                     int old_is_session,
                                     const char *new_anchor,
                                     int new_is_session);

/* Presence-aware paging (2026-09-02).  The store walk consults the
 * caller's presence PER ROW instead of the page being filtered after
 * it was filled: rows outside presence are skipped without counting
 * against the limit, and the walk seeks straight to the next presence
 * boundary instead of stepping through an invisible run.  A full raw
 * page that filtered to nothing used to leave the client with an empty,
 * incomplete batch and no cursor. */

/** Nearest presence time at/after (reverse=0) or at/before (reverse=1)
 * @a t at which @a anchor is present in @a channel.  Returns @a t itself
 * when it is already inside a presence window, -1 when nothing is
 * visible in that direction. */
extern int64_t presence_next_visible(const char *anchor, int anchor_is_session,
                                     const char *channel, int64_t t,
                                     int reverse);

/** Opaque per-query presence filter: one snapshot of the requester's
 * presence record plus the history row hook that consults it. */
struct PresenceQueryFilter;

/** Build the query-time presence filter for @a requestor on @a target.
 * *@a rc_out (may be NULL) receives 0 when no filtering applies (feature
 * off, PM target, +H channel, or @a effective_override set) and NULL is
 * returned; 1 when a filter was armed (returned); -1 when the request
 * must fail CLOSED (no resolvable anchor) and NULL is returned -- the
 * caller answers an empty, complete page. */
extern struct PresenceQueryFilter *presence_query_filter_open(
    struct Client *requestor, const char *target, int effective_override,
    int *rc_out);

/** The row hook to hand to history_query_*(); NULL for a NULL filter. */
extern struct HistoryRowFilter *presence_query_filter_hook(
    struct PresenceQueryFilter *pf);

/** Release a filter from presence_query_filter_open (NULL-safe). */
extern void presence_query_filter_close(struct PresenceQueryFilter *pf);

#endif /* INCLUDED_chathistory_presence_h */
