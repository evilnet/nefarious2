/*
 * IRC - Internet Relay Chat, include/chathistory_merge.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Merging a federated chathistory page: the local rows and the
 *   rows peers sent, deduplicated, in store-key order.
 */
#ifndef INCLUDED_chathistory_merge_h
#define INCLUDED_chathistory_merge_h

#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif
#include "history.h"   /* HISTORY_MSGID_LEN: the page leg's declaration table */

/** The row in @a list that is the same message as @a check: the same
 * msgid, else the same timestamp, sender, type and content (one message
 * stored on two servers under different msgids).
 * @return That row, or NULL. */
extern struct HistoryMessage *hm_find_dup(struct HistoryMessage *list,
                                          const struct HistoryMessage *check);

/** Merge two time-ordered row lists into a new one.  Ties on the
 * millisecond go in msgid order; a row that duplicates one already kept
 * (hm_find_dup) is dropped, and the kept row takes the dropped one's
 * client-only tags when it has none of its own.  Each kept row is a copy
 * that takes over its source's heap content (dyn_content, raw_content):
 * the source rows stay in @a a and @a b for their owner to free.  The
 * result is then cut to @a limit rows: the oldest when @a keep_oldest,
 * else the newest.
 * @return The merged list (the caller frees it with history_free_messages). */
extern struct HistoryMessage *hm_merge(struct HistoryMessage *a,
                                       struct HistoryMessage *b,
                                       int limit, int keep_oldest);

/** Cut a time-ordered row list to @a limit rows centred on an AROUND
 * page's reference, as a local AROUND page is cut (history_query_around):
 * the newest limit/2 rows before the reference, then the reference row and
 * the rows after it, oldest first, up to @a limit.  The before side is not
 * topped up when the after side runs short (nor is a local page's).  A row
 * is before the reference when its time is earlier than @a ref_ms, or, in
 * that millisecond, when @a ref_msgid is set and the row's msgid sorts
 * before it (a timestamp reference: every row of its millisecond is after).
 * The rows cut are freed (history_free_messages); call it on a list the
 * caller owns, such as hm_merge's result.
 * @return The cut list. */
extern struct HistoryMessage *hm_trim_around(struct HistoryMessage *list,
                                             int limit, uint64_t ref_ms,
                                             const char *ref_msgid);

/** The msgid of the row @a m hangs on as context, by the reply index's own
 * rule (history.c's store path): a TAGMSG's +reply tag (else its legacy
 * +draft/reply), a REDACT's first content word.  Any other row -- a reply
 * PRIVMSG included, a message in its own right -- hangs on nothing.
 * @return @a buf holding the msgid, or NULL. */
extern const char *hm_context_parent(const struct HistoryMessage *m,
                                     char *buf, size_t buflen);

/** Splice each context child of @a ctx_list (is_context, ctx_parent set)
 * into @a merged after its parent's existing context run.  Ownership of
 * @a ctx_list moves here: a child joins @a merged, or is freed when
 * hm_find_dup finds it in @a merged already (a local copy attached by
 * history_attach_context, an earlier splice, or the same message as a
 * row) or when its parent is not a non-context row of @a merged.  Moved
 * unchanged from m_chathistory.c's splice_fed_context (W5 Task 14). */
extern void hm_splice_context(struct HistoryMessage *merged,
                              struct HistoryMessage *ctx_list);

/** The msgids of the rows of @a rows (time order) whose children a peer may
 * hold and this store lacks (the children request, CH Q K; W5 Task 14):
 * every non-context row at or before the newest one whose context range
 * [its time, now] @a received rejects.  received(ms, ctx) is 1 when that
 * range was received here and no storage peer's absence overlaps it.
 * Monotone (a later start is a sub-range): every row up to the newest
 * rejected one is rejected, so the oldest row is checked first (it passes:
 * nothing is wanted), then the newest (it is rejected: everything is), and
 * a bisection finds the cut between them -- received() runs at most
 * ceil(log2 n) + 2 times for n rows.  A context row is never a parent (no
 * context of context).  The ids point into @a rows.
 * @return msgids written to @a ids, in time order, at most @a max (the
 *   oldest ones when more are wanted). */
extern int hm_children_wanted(const struct HistoryMessage *rows,
                              int (*received)(uint64_t ms, void *ctx), void *ctx,
                              const char **ids, int max);

/** Pack ids[from..n) space-separated into @a out while the text stays
 * within @a room bytes (and fits @a outsz with its NUL).
 * @return how many were packed (0 when ids[from] alone does not fit). */
extern int hm_pack_ids(const char *const *ids, int n, int from, size_t room,
                       char *out, size_t outsz);

/** Split a CH Q K msgid list in place: at most @a max space-separated
 * tokens of 1..HISTORY_MSGID_LEN-1 characters (a longer one is skipped);
 * runs of spaces separate.  NULL-safe.
 * @return the count. */
extern int hm_parse_ids(char *list, const char **ids, int max);

/** Is the context row @a m redacted, as this server's store knows it (W5
 * Task 15, F-2)?  1 yes, 0 no, -1 unknown (a read error, no store). */
typedef int (*hm_redacted_fn)(const struct HistoryMessage *m, void *arg);

/** The most distinct targets an hm_idset keeps (64 bytes each);
 * duplicates are never kept twice, so never count toward it. */
#define HM_IDSET_MAX 2048
/** An hm_idset is re-sorted when this many targets were added unsorted. */
#define HM_IDSET_TAIL 64

/** The targets of the REDACTs a federated request had to drop for budget
 * (W5 Task 15 fix round 1): a REDACT is never lost to a cap -- its target
 * goes here and hm_redact_filter still hides it.  Grown on demand up to
 * HM_IDSET_MAX.  Zeroed = empty. */
struct hm_idset {
  char (*ids)[HISTORY_MSGID_LEN];
  int n, cap;
  int nsorted;   /**< ids[0..nsorted) are sorted and distinct */
  int lost;   /**< a REDACT's target could not be kept (the set was full,
               *   or the REDACT was lost before its content was read): the
               *   page's peer rows fail closed (hm_fail_closed) */
};

/** Add @a id to @a s (a target already kept is not added again).
 * @return 1 kept, 0 not (full of distinct targets: @a s->lost is set). */
extern int hm_idset_add(struct hm_idset *s, const char *id);

/** A row of @a type and @a content dropped for budget: when it is a REDACT,
 * keep its target (its first content word) in @a s. */
extern void hm_idset_note_redact(struct hm_idset *s, int type, const char *content);

/** Keep in @a s the target of every REDACT in @a list (fix round 2, I-B:
 * the merge's limit may cut a peer's REDACT while the row it names stays
 * on the page).  NULL-safe. */
extern void hm_idset_note_list(struct hm_idset *s, const struct HistoryMessage *list);

/** Free @a s's storage and empty it. */
extern void hm_idset_free(struct hm_idset *s);

/** The reply-side redaction filter of a history page (W5 Task 15; it was
 * m_chathistory.c's redact_filter_messages, which kept 100 targets and
 * showed the redacted originals past them).  @a *head is a page: rows in
 * time order, each followed by its context run (history_attach_context and
 * hm_splice_context put a row's context right after it).  The redacted set
 * is the targets the page's REDACT entries name (their first content word)
 * and those of @a extra (REDACTs dropped for budget; NULL for none).
 *   - F-6: every PRIVMSG/NOTICE/TAGMSG/MULTILINE entry, context or not,
 *     in the redacted set is dropped.  The set is sized from the list, with
 *     no cap; when it cannot be allocated the filter fails closed
 *     (hm_redact_filter_closed).
 *   - A row one of whose children history_attach_context could not read
 *     (ctx_unread), and that a REDACT could name, is dropped: it may be
 *     redacted (fail closed).
 *   - F-7: the context run of a row dropped that way goes with it, except
 *     its REDACT entries (kept as before); so does any TAGMSG, row or
 *     context, whose own parent (hm_context_parent) is in the redacted set.
 *   - F-2: each context entry that survives and could be a REDACT target
 *     is looked up once with @a redacted (NULL: none is), and dropped
 *     unless the answer is 0: a read error, or no store, hides it (fail
 *     closed).  No context of context is ever attached, so a reaction's
 *     own REDACT is on the page only when its time is.
 * REDACT entries and events are never dropped.
 * @return @a count when nothing was dropped, else the entries left. */
extern int hm_redact_filter(struct HistoryMessage **head, int count,
                            const struct hm_idset *extra,
                            hm_redacted_fn redacted, void *arg);

/** hm_redact_filter's fail-closed form, for a set it could not allocate:
 * every entry a REDACT could name (PRIVMSG/NOTICE/TAGMSG/MULTILINE) is
 * dropped, context or not; REDACT entries and events stay.
 * @return @a count when nothing was dropped, else the entries left. */
extern int hm_redact_filter_closed(struct HistoryMessage **head, int count);

/** hm_redact_filter_closed on a list of a peer's rows or context (W5 Task
 * 15 fix round 1: a REDACT this request could not keep may name any of
 * them).  @return how many entries were dropped. */
extern int hm_fail_closed(struct HistoryMessage **list);

/** The parent a page-leg row of a federated page hangs on as context,
 * when that parent is on the page (W5 Task 15, F-3: a declaration the full
 * CH C table dropped never comes; hm_leg_add uses this only then).  @a m's
 * own parent
 * (hm_context_parent: a TAGMSG's +reply, a REDACT's target) must be a
 * non-context row of @a local, or a non-context row of @a peer, other than
 * @a m, that hangs on nothing itself: a row that is itself a child may be
 * made context, and its own children would then have no row to follow, so
 * they stay rows.  A duplicate of a local row (hm_find_dup) stays a row:
 * the merge keeps one copy and lends it the other's tags.
 * @return @a buf holding the parent, or NULL. */
extern const char *hm_page_parent(const struct HistoryMessage *m,
                                  const struct HistoryMessage *local,
                                  const struct HistoryMessage *peer,
                                  char *buf, size_t buflen);

/** Move every non-context row of *@a peer that hm_page_parent places on the
 * page (parents among @a local and *@a peer) onto the end of *@a ctx_list,
 * marked is_context with ctx_parent set (W5 Task 15, F-3).  Order does not
 * matter: a moved row is never a parent (it hangs on something).
 * @return how many moved. */
extern int hm_derive_context(struct HistoryMessage **peer,
                             const struct HistoryMessage *local,
                             struct HistoryMessage **ctx_list);

/** How a federated request takes one row of a peer's reply (W5 Task 15,
 * F-4): rows and context children have budgets of their own. */
enum hm_admit {
  HM_ADMIT_ROW,      /**< a row, counted against the row cap */
  HM_ADMIT_CONTEXT,  /**< a context child, counted against its own cap */
  HM_DROP_CONTEXT,   /**< a context child past its cap: dropped; context
                      *   loss is never partial */
  HM_DROP_ROW        /**< a row past the row cap: dropped, the page is cut */
};

/** Take one row (@a is_context: a declared or derived context child) against
 * *@a rows < @a row_max or *@a ctx < @a ctx_max, counting it when admitted.
 * A context child never counts against, or is refused by, the row cap. */
extern enum hm_admit hm_fed_admit(int is_context, int *rows, int *ctx,
                                  int row_max, int ctx_max);

/** The page leg's CH C declarations in flight (W5 Task 15 fix round 1).
 * A responder sends each declaration right before its row (send_ch_rows),
 * and the row takes it out (remove-on-match), so a table this size fills
 * only if 64 rows never come. */
#define HM_DECL_MAX 64

/** A CH C declaration: @a child is a context child of @a parent. */
struct hm_decl {
  char child[HISTORY_MSGID_LEN];
  char parent[HISTORY_MSGID_LEN];
  char tags[512];   /**< the child's client-only tags (CH R never carried them) */
};

/** A federated request's page leg (W5 Task 15): what the peers sent as rows
 * of their pages, the context they declared, and the budgets.  Zeroed =
 * empty; hm_leg_free empties it. */
struct hm_page_leg {
  struct HistoryMessage *msgs;   /**< rows and context children, arrival order */
  int rows;                      /**< rows held (the row cap) */
  int ctx;                       /**< context children held (their own cap, F-4) */
  int derive;                    /**< a history page: once a declaration was
                                  *   lost, a row whose own parent is on the
                                  *   page is context (F-3's fallback) */
  struct hm_decl decl[HM_DECL_MAX];
  int ndecl;
  int decl_lost;                 /**< a declaration came with the table full */
  struct hm_idset side;          /**< targets of REDACTs dropped for budget */
};

/** Take a peer's row into @a leg.  It is a context child when a declaration
 * names it (taken out of the table), else -- only when @a leg->derive and a
 * declaration was lost -- when hm_page_parent places it on the page (parents
 * among @a local and the leg's rows).  A peer's in-span reaction, never
 * declared, stays a row, as on a local page.  It then counts against
 * @a ctx_max or @a row_max (hm_fed_admit); dropped, it is freed, and a
 * REDACT dropped leaves its target in @a leg->side.
 * @return the admission (HM_DROP_ROW: the caller cuts the page). */
extern enum hm_admit hm_leg_add(struct hm_page_leg *leg, struct HistoryMessage *msg,
                                const struct HistoryMessage *local,
                                int row_max, int ctx_max);

/** A CH C declaration for @a leg.  A row already here under @a child, not
 * yet context (it came first; with three or more stores a second
 * responder may declare a child the first already sent), becomes the
 * context child, moving from the row budget to
 * the context budget (dropped when that is full, a REDACT's target kept);
 * else the declaration waits in the table, or, the table full, is lost
 * (@a leg->decl_lost). */
extern void hm_leg_declare(struct hm_page_leg *leg, const char *parent,
                           const char *child, const char *tags, int ctx_max);

/** A row @a leg will never get (lost before it was read): take its
 * declaration out of the table, its parent (for a REDACT: its target)
 * copied to @a parent when @a parent is not NULL.  @return 1 when it was
 * declared (context: its loss is never partial), else 0. */
extern int hm_leg_forget_decl(struct hm_page_leg *leg, const char *child,
                              char *parent, size_t plen);

/** When @a leg lost a REDACT whose target it cannot know (@a
 * leg->side.lost), withhold every entry of the finished @a page a REDACT
 * could name -- local rows included (fix round 2, I-A: a children-leg
 * REDACT always names a local row, a peer row's local copy is the one the
 * merge keeps, a context-only page is all local rows).  Never partial.
 * @return how many entries were withheld (0 when nothing was lost). */
extern int hm_leg_close_page(const struct hm_page_leg *leg, struct HistoryMessage **page);

/** A responder's rows and their attached context, before it sends them
 * (W5 Task 15 fix rounds 1-3): every context reaction (non-REDACT context)
 * that @a redacted does not clear (anything but 0) is unlinked and freed.
 * With @a skip_unread_rows (the page leg, whose rows are sent), a row its
 * attach could not fully read (ctx_unread) that a REDACT could name goes
 * too, with its non-REDACT context.  A REDACT entry is never dropped: it
 * may be all that hides the requester's own copy of its target.  The
 * children leg passes 0: its stub rows are never sent, and each child is
 * checked by itself. */
extern void hm_responder_skip(struct HistoryMessage **head, int skip_unread_rows,
                              hm_redacted_fn redacted, void *arg);

/** Does the CH B reassembly key @a key ("<reqid>:<msgid>", or
 * "<reqid>K:<msgid>" on the children leg) belong to request @a reqid?  A
 * request freed mid-row frees its entries (fix round 2). */
extern int hm_chunk_of_request(const char *key, const char *reqid);

/** Unlink @a leg's context children (they splice after their parents,
 * uncounted, #526) and return them; @a leg keeps its rows. */
extern struct HistoryMessage *hm_leg_extract_context(struct hm_page_leg *leg);

/** At completion, once a declaration was lost: hm_derive_context over
 * @a leg's rows (a parent that came after its child, from another
 * responder), appended to *@a ctx_list.  Nothing when none was lost.
 * @return how many rows became context. */
extern int hm_leg_derive(struct hm_page_leg *leg, const struct HistoryMessage *local,
                         struct HistoryMessage **ctx_list);

/** Does @a leg hold a row (not only context)?  The federated auto-replay
 * delivers a channel only then. */
extern int hm_leg_has_rows(const struct hm_page_leg *leg);

/** Free @a leg's rows and side set and empty it. */
extern void hm_leg_free(struct hm_page_leg *leg);

/* ------------------------------------------------------------------ */
/* CHATHISTORY TARGETS (W5 Task 11)                                    */
/*                                                                    */
/* TARGETS has BETWEEN's semantics (chathistory.md :111, :119): both   */
/* bounds exclusive, the limit counted from the FIRST argument, and    */
/* the argument order is the direction.  Rows go ascending (:126),     */
/* ties by folded name (:128).  Every time below is epoch ms: bounds   */
/* and stamps compare as integers, never as "sec.mmm" strings (a       */
/* variable-width seconds field made a start before 2001-09-09 or an   */
/* end after 2286 list nothing).                                       */
/* ------------------------------------------------------------------ */

/** Epoch ms of a TARGETS bound: ISO 8601 "YYYY-MM-DDThh:mm:ss[.fff]Z"
 * (what a client sends after "timestamp="), or "sec[.mmm]".
 * @return 0, or -1 when @a ref is neither. */
extern int hm_targets_ref_ms(const char *ref, uint64_t *ms);

/** Epoch ms of a stored "sec[.mmm]" stamp. */
extern uint64_t hm_targets_stamp_ms(const char *stamp);

/** One row per target from @a a and @a b (consumed; names compared under
 * the casemapping), at its latest stamp: the network-wide latest is the
 * maximum over whoever answered.
 * @return The merged list, in no particular order (caller frees). */
extern struct HistoryTarget *hm_targets_merge(struct HistoryTarget *a,
                                              struct HistoryTarget *b);

/** Whether the requester may be shown @a t (access, presence, a name to
 * show it under).  Called only for rows the page considers. */
typedef int (*hm_target_ok_fn)(const struct HistoryTarget *t, void *ctx);

/** Cut @a *list to a TARGETS page: the rows strictly between @a first_ms
 * and @a second_ms, counted from @a first_ms (forwards when it is the
 * older bound, else backwards), at most @a limit -- more only to finish a
 * group of equal stamps at the page's far edge, so the next page from
 * that stamp starts exactly after the group (never fewer).  A row @a ok
 * rejects (when given) is dropped and not counted.  The page is left in
 * @a *list ascending by (stamp, folded name); everything else is freed.
 * @param[out] more 1 when an eligible row lies beyond the page in its
 *   direction (the end tag must then not be set), else 0.
 * @return The rows on the page. */
extern int hm_targets_page(struct HistoryTarget **list, uint64_t first_ms,
                           uint64_t second_ms, int limit, hm_target_ok_fn ok,
                           void *ctx, int *more);

/** Order a storage peer's CH T answer: the rows strictly above the lower
 * bound, the in-window ones first (nearest @a first_ms first, ties by
 * folded name), then the veto rows (at or past the upper bound, which can
 * only disqualify a target), cut to @a cap -- past it only to finish a
 * group of equal in-window stamps -- so a cut drops veto rows (a duplicate
 * at worst) before any in-window row (a hole).
 * @param[out] cut 1 when rows were dropped at the cap.
 * @return The rows kept in @a *list, in that order. */
extern int hm_targets_responder(struct HistoryTarget **list, uint64_t first_ms,
                                uint64_t second_ms, int cap, int *cut);

#endif /* INCLUDED_chathistory_merge_h */
