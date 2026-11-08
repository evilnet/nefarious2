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

struct HistoryMessage;

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

#endif /* INCLUDED_chathistory_merge_h */
