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

#endif /* INCLUDED_chathistory_merge_h */
