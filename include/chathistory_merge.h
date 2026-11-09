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
 * Task 15, F-2)?  1 yes, 0 no, -1 unknown (a read error). */
typedef int (*hm_redacted_fn)(const struct HistoryMessage *m, void *arg);

/** The most targets an hm_idset keeps (64 bytes each). */
#define HM_IDSET_MAX 2048

/** The targets of the REDACTs a federated request had to drop for budget
 * (W5 Task 15 fix round 1): a REDACT is never lost to a cap -- its target
 * goes here and hm_redact_filter still hides it.  Grown on demand up to
 * HM_IDSET_MAX.  Zeroed = empty. */
struct hm_idset {
  char (*ids)[HISTORY_MSGID_LEN];
  int n, cap;
  int lost;   /**< a REDACT's target could not be kept (the set was full,
               *   or the REDACT was lost before its content was read): the
               *   page's peer rows fail closed (hm_fail_closed) */
};

/** Add @a id to @a s.  @return 1 kept, 0 not (full: @a s->lost is set). */
extern int hm_idset_add(struct hm_idset *s, const char *id);

/** A row of @a type and @a content dropped for budget: when it is a REDACT,
 * keep its target (its first content word) in @a s. */
extern void hm_idset_note_redact(struct hm_idset *s, int type, const char *content);

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
 *   - F-7: the context run of a row dropped that way goes with it, except
 *     its REDACT entries (kept as before).
 *   - F-2: each context entry that survives and could be a REDACT target
 *     is looked up once with @a redacted (NULL: none is), and dropped
 *     unless the answer is 0: a read error hides it (fail closed).  No context of context is ever attached, so a reaction's
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

/** A CH C declaration for @a leg.  A row already here under @a child (it
 * came first) becomes the context child, moving from the row budget to
 * the context budget (dropped when that is full, a REDACT's target kept);
 * else the declaration waits in the table, or, the table full, is lost
 * (@a leg->decl_lost). */
extern void hm_leg_declare(struct hm_page_leg *leg, const char *parent,
                           const char *child, const char *tags, int ctx_max);

/** A row @a leg will never get (lost before it was read): take its
 * declaration out of the table.  @return 1 when it was declared (context:
 * its loss is never partial), else 0. */
extern int hm_leg_forget_decl(struct hm_page_leg *leg, const char *child);

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

#endif /* INCLUDED_chathistory_merge_h */
