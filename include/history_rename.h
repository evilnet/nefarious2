/*
 * IRC - Internet Relay Chat, include/history_rename.h
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
 * @brief Chathistory follows a channel RENAME: the renames column family
 *   of the history env, and the walk over a channel's rows under every
 *   name it has had.
 *
 * A RENAME (classic, or the relocation form) moves a channel to another
 * name and keeps its creation timestamp.  Its stored rows stay where they
 * are, keyed by the name the channel had when each was stored; nothing is
 * rewritten.  The decision for what a client sees (ircv3-specifications
 * #532): "this channel has always been this name" -- CHATHISTORY of the
 * current name returns the rows stored under the earlier names as its
 * own, in one time order.
 *
 * What says which rows those are is one record per CURRENT name:
 *
 *   key   the name, folded through db_casefold_bytes (as every name key);
 *   value a version byte, then one entry per earlier name:
 *           be64 incarnation   the channel's creation timestamp
 *           be64 until_ms      when it left that name
 *           be64 since_ms      when it took it (0: at its creation)
 *           u8   length, the earlier name (folded)
 *
 * An entry is a SEGMENT: the rows under that earlier name which carry
 * that incarnation (history.h: every stored row is stamped with its
 * channel's creationtime) and are stamped no later than until_ms.  A
 * channel a stranger makes under the old name later has another creation
 * timestamp: its rows are in no segment, and the renamed channel's rows
 * under that name are not its history either (history.c's incarnation
 * test, as before).  Rows a relocation's tombstone stores under the old
 * name after the move are later than until_ms and stay the tombstone's.
 *
 * Records are FLAT.  A rename of #b to #c moves #b's entries of that
 * incarnation to #c's record and adds #b itself: nothing follows a chain
 * at read time, so there is no chain to bound and no loop to detect.  An
 * entry that would name the record's own channel is dropped (#a -> #b ->
 * #a: #a's own rows are its own already), one name appears once per
 * incarnation (its later stay: the later until_ms), an incarnation keeps at most
 * HREN_MAX_SEGS entries (the earliest leave first: hren_note says how
 * many went), and an entry whose
 * until_ms is behind the retention floor is dropped wherever a record is
 * read or written: every row it could name has aged out.
 *
 * Every server writes the record on its own when it executes the RENAME
 * (rename_channel() / relocate_execute(), local or from a server), so a
 * federated query needs nothing new on the wire: it names the current
 * name, and each store answers with what its own record says.
 *
 * ARRIVING at a name.  The channel's own entries are all in the record of
 * the name it leaves, so whatever the record of the name it arrives at
 * holds for its incarnation is another channel's: a dead one created in
 * the same second (the incarnation is a creation time in seconds) that
 * was renamed into that name before.  Those entries are dropped at the
 * arrival, never inherited; other incarnations' stay (no read of the
 * arriving channel returns them).
 *
 * What the stamp cannot tell apart, here as before this file: rows the
 * dead channel stored under the destination name ITSELF carry the same
 * incarnation as the arriving channel's own rows there, and are shown
 * with them.  It is the limit history.c already has for a channel that
 * is destroyed and made again within one second; a rename widens it to
 * "a dead channel of that name with the arriving channel's creation
 * second".  Only the arrival time could separate them, and a floor there
 * would hide the channel's own rows whenever a relayed message is
 * stamped by a server whose clock is behind (the same reason until_ms is
 * raised to the old name's newest stamp), so none is applied.
 *
 * CROSSING RELOCATIONS.  When two relocations of one channel cross, a
 * server may execute the losing one first: the loser's name gets the
 * record, and the server then makes the winner's channel.  hren_handover
 * moves what the loser took -- the old name with the time it was left,
 * and everything from before it -- to the winner, so both orders end
 * with the same record and the loser with none of it.
 *
 * BOUNDS.  HREN_MAX_SEGS earlier names per incarnation: the price of a
 * read (below) is linear in it, and anyone who may rename the channel
 * sets it.  One rename more inside the retention window and the earliest
 * name is no longer followed -- its rows stay where they are until they
 * age out, unreachable through the current name -- which history.c logs
 * (a warning naming the channel).  A read of a renamed channel opens one
 * bounded iterator per name (1 + HREN_MAX_SEGS at most), and each row of
 * a page has its redaction and its context looked for under each name
 * (one bounded prefix seek each).
 *
 * FAILURES fail towards showing less.  A record that cannot be read
 * fails the query that needed it (hren_lookup's -1: history.c answers as
 * for any failed read, and a redaction lookup answers "unknown", which
 * hides the row) instead of serving the page without the earlier names.
 * A record that cannot be written leaves the channel without earlier
 * names, and history.c deletes or stops reading whatever stale record
 * the name had.
 *
 * REDACTIONS AND TRIMMING.  A REDACT sent after a rename for a message
 * from before it is stored under the new name, its original under the
 * old one.  The redaction must not depend on a record joining the two:
 * the record keeps HREN_MAX_SEGS names, so enough later renames would
 * make the REDACT row's name one that is no longer read and show the
 * message again, and a relocation's old channel reads its own name
 * only.  So when history.c stores a REDACT row it looks for the original
 * (hren_find_parent: the names that hold the msgid, narrowed to rows of
 * the same incarnation that a record joins with the REDACT row,
 * hren_same_channel) and, when it is under another name, writes a second
 * reply-index entry under THAT name (redact_index.h).  A redaction is
 * read off the index under the name the original is stored under, which
 * is the name the original is read through whatever the channel is
 * called by then.  The REDACT row's own entry carries the other name:
 * the trim engine deletes a redacted original together with its REDACT
 * row (a redaction lives only in that row), and finds the original and
 * the second entry there with no record to consult.  A REDACT row from
 * before this (its entry names nothing) is still joined by the reads
 * that walk the earlier names, and by hren_find_parent at trim.
 *   The link runs one way.  What a relocation's old channel stores after
 * the move is its own, REDACT rows included: one sent there for a
 * message from before the move hides it in the old channel and not in
 * the new one.
 *
 * PRESENCE.  With CHATHISTORY_STRICT_PRESENCE a row is checked against
 * the presence recorded under the name it is STORED under: a RENAME
 * closes each member's open interval under the old name and opens one
 * under the new (chathistory_presence.h, presence_on_channel_rename);
 * nothing is copied.  An account's two records change in one write, so
 * a failed read or write leaves its interval where it was (logged),
 * never open under both names.
 *
 * KNOWN GAPS.
 *  - A server that did not execute the rename (down, or split from the
 *    network at that moment) has no record: its rows under the old name
 *    are not returned for the new one, by it or through it, and nothing
 *    repairs that later.  The burst names a channel's current name only;
 *    carrying its former names needs a wire change.
 *  - Rows from before incarnations were stamped (2026-09-08) carry none
 *    and belong to no segment.
 *  - Read markers and channel metadata are keyed by name and do not
 *    follow a rename.
 *  - Two renames whose times are equal to the millisecond are ordered by
 *    name when the cap chooses which entry to drop.
 *  - A REDACT stored while its original is not on this store (it arrives
 *    later, from another store) gets no second entry: it holds through
 *    the names the record keeps, as before, and no further.
 *
 * No ircd dependency beyond the db_* API, db_casefold and the key codec
 * (history_trim_codec.h): unit-tested on the in-memory store and on
 * RocksDB (ircd/test/history_rename_cmocka.c); history.c's use of it in
 * ircd/test/history_read_cmocka.c.
 */
#ifndef INCLUDED_history_rename_h
#define INCLUDED_history_rename_h

#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif
#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif

struct db_env;
struct db_cf;
struct db_snapshot;

/** Earlier names kept per channel incarnation: a read of the channel
 * opens one iterator for its own name and one for each of these, and
 * looks for a row's redaction and context under each, so this bounds
 * what a chanop can make every page of the channel cost by renaming it
 * over and over.  A channel renamed more often than this inside the
 * retention window loses the reach to its earliest names: the rows stay
 * (and age out) under them, the record's entries for them go, and
 * history.c logs each name dropped. */
#define HREN_MAX_SEGS 4

/** Entries one record holds, every incarnation of the name together. */
#define HREN_REC_MAX 64

/** One earlier name of a channel, and which rows under it are the
 * channel's. */
struct hren_seg {
  char name[CHANNELLEN + 1];   /**< The earlier name, folded */
  uint64_t incarnation;        /**< The channel's creation timestamp */
  uint64_t until_ms;           /**< Rows stamped up to here count */
  /** When the channel took the name -- the time it left the one before
   * -- or 0: it was made under it.  Of its LATEST stay, for a name it
   * had more than once (one entry per name).  Not a bound on the rows
   * (a relayed row may be stamped by a clock that is behind, so a
   * segment starts at the incarnation's creation): it says which name
   * the channel had at a given time, for a caller that has a time and no
   * row -- strict presence, for a row another server stored.  A time in
   * no entry's [since_ms, until_ms] and not after the last until_ms is
   * in an earlier stay under some name, which one is not known. */
  uint64_t since_ms;
};

/** A channel's earlier names, the one it left last first. */
struct hren_span {
  int count;
  struct hren_seg seg[HREN_MAX_SEGS];
};

/** The channel of @a incarnation, until now @a oldname, is @a newname
 * from @a until_ms on: write @a newname's record (and take what
 * @a oldname's held for this incarnation), in one batch.  Entries behind
 * @a floor_ms (0 = none) are dropped from both.  Two spellings of one
 * name are one key: nothing to write.
 *
 * The channel ARRIVES at @a newname: whatever that name's record held
 * for this incarnation is not this channel's (its own entries are all in
 * @a oldname's record) but a dead channel's with the same creation
 * second, and is dropped, never inherited.  So this is called ONCE per
 * rename.
 *
 * It fails towards showing less.  A record of @a newname that cannot be
 * read is replaced, not kept; when @a oldname's cannot be read, the
 * channel keeps only the name it just left, and @a oldname's record goes
 * (the return is 1).
 * @param[out] dropped Entries of this channel the caps removed (the
 *   earliest names, whose rows no read returns any more); may be NULL.
 * @return 0, 1 (written, the earlier names lost: see above), or -1 (a
 *   bad name, no incarnation, or the write failed: nothing changed). */
extern int hren_note(struct db_env *env, struct db_cf *cf,
                     const char *oldname, const char *newname,
                     uint64_t incarnation, uint64_t until_ms,
                     uint64_t floor_ms, int *dropped);

/** Two relocations of the channel @a oldname crossed, this store recorded
 * the losing one first (hren_note to @a losername), and the channel is at
 * @a winnername after all: move what the loser's record took from
 * @a oldname -- the entry for @a oldname, with the time it was left, and
 * every entry of the incarnation no later than it -- to @a winnername's
 * record.  The loser keeps what it gained since (a rename of its own).
 * @a winnername is arrived at as in hren_note.  The end state is the one
 * a store reaches that recorded the winning relocation first.
 * @param[out] dropped As hren_note's.
 * @return 1 moved; 0 the loser's record has no entry for @a oldname
 *   (nothing written: the caller records the rename as a first one); -1
 *   a bad name, a read or the write failed (nothing changed). */
extern int hren_handover(struct db_env *env, struct db_cf *cf,
                         const char *oldname, const char *losername,
                         const char *winnername, uint64_t incarnation,
                         uint64_t floor_ms, int *dropped);

/** Delete @a name's record without reading it: what is left to do when
 * its rewrite failed (the channel then has no earlier names, which shows
 * less, never another channel's rows).
 * @return 0, or -1. */
extern int hren_drop(struct db_env *env, struct db_cf *cf, const char *name);

/** Are a row under @a aname stamped @a a_ms and one under @a bname
 * stamped @a b_ms, both carrying @a incarnation, rows of ONE channel --
 * is there a record (of any name: the channel may have moved on since)
 * that takes in both, each as the record's own name or as an entry of
 * the incarnation that reaches its stamp?  The trim engine asks this
 * before a REDACT row it evicts takes with it an original stored under
 * another name (hren_find_parent).
 * @return 1 yes, 0 no, -1 on a read error. */
extern int hren_same_channel(struct db_env *env, struct db_cf *cf,
                             const char *aname, uint64_t a_ms,
                             const char *bname, uint64_t b_ms,
                             uint64_t incarnation);

/** The earlier names of the channel @a name of @a incarnation (0: of
 * every incarnation the name has a record for -- a name with no live
 * channel, whose own rows are all shown too), without the entries behind
 * @a floor_ms (0 = none).
 * @return The count (@a out filled, also when 0), or -1 on a read error
 *         (@a out empty). */
extern int hren_lookup(struct db_env *env, struct db_cf *cf,
                       struct db_snapshot *snap, const char *name,
                       uint64_t incarnation, uint64_t floor_ms,
                       struct hren_span *out);

/** Drop the entries of @a name's @a incarnation: its rows were pruned
 * (the incarnation lost a burst).
 * @return 0, or -1. */
extern int hren_forget(struct db_env *env, struct db_cf *cf,
                       const char *name, uint64_t incarnation);

/** Drop every entry behind @a floor_ms, and every record that leaves
 * empty: the maintenance pass's walk of the whole column family.
 * @return The entries dropped, or -1. */
extern int hren_sweep(struct db_env *env, struct db_cf *cf, uint64_t floor_ms);

/** The incarnation a stored messages row carries (history_record.h), or
 * 0 for a row that carries none or cannot be decoded. */
typedef uint64_t (*hren_row_inc_fn)(const void *val, size_t vlen);

/** The original a REDACT row redacts, when it is not stored under the
 * REDACT row's own name: the REDACT row is under @a child_name, stamped
 * @a child_ms, of @a incarnation, and names @a parent_msgid.  A REDACT
 * sent in a renamed channel for a message from before the rename is
 * stored under the new name, the message under the old one; the read
 * side joins them (history.c walks every earlier name), and the trim
 * engine, which deletes a redacted original with its REDACT row, must
 * find it too or evicting the REDACT row would show the message again.
 *
 * Looked for through @a msgid_index (key: msgid \0 fold(name), value:
 * the row's timestamp; htc_msgid_key): every other name that holds
 * @a parent_msgid, whose @a messages row carries @a incarnation
 * (@a inc_fn) and is of the same channel (hren_same_channel).
 * @param[out] name The name it is stored under, folded (CHANNELLEN + 1).
 * @param[out] ts Its key timestamp (@a tssz bytes).
 * @return 1 found, 0 none, -1 on a read error. */
extern int hren_find_parent(struct db_env *env, struct db_cf *cf,
                            struct db_cf *msgid_index, struct db_cf *messages,
                            hren_row_inc_fn inc_fn,
                            const char *child_name, uint64_t child_ms,
                            uint64_t incarnation, const char *parent_msgid,
                            char *name, char *ts, size_t tssz);

/** A walk over one channel's messages rows under its own name and every
 * segment of @a span, merged in key order (time, then msgid) -- what a
 * db_iter over the target's own prefix was, and used as one.
 *
 * Every key it takes and gives is the CANONICAL one: the row's key as if
 * it were stored under @a target (htc_msg_key).  Callers build seek keys,
 * floors and window ends for the target and compare what comes back with
 * them, as before; a row of a segment is presented under the current
 * name.
 *
 * The target's own rows are all given (the caller's incarnation test
 * stands).  A segment gives only rows from its incarnation's creation up
 * to its until_ms -- its iterator is bounded to that range -- that carry
 * its incarnation (@a inc_fn).
 *
 * Seeks and steps return DB_OK when the walk stands on a row, else
 * DB_NOTFOUND, or the backend's error.  A step may follow a seek in
 * either direction. */
struct hren_iter;

extern struct hren_iter *hren_iter_open(struct db_env *env,
                                        struct db_cf *messages,
                                        struct db_snapshot *snap,
                                        const char *target,
                                        const struct hren_span *span,
                                        hren_row_inc_fn inc_fn);
extern void hren_iter_close(struct hren_iter *it);
/** The first row at or after @a key, a canonical key. */
extern int hren_iter_seek(struct hren_iter *it, const void *key, size_t klen);
extern int hren_iter_seek_first(struct hren_iter *it);
extern int hren_iter_seek_last(struct hren_iter *it);
extern int hren_iter_next(struct hren_iter *it);
extern int hren_iter_prev(struct hren_iter *it);
extern int hren_iter_valid(const struct hren_iter *it);
/** The current row's canonical key; valid until the next seek or step. */
extern const void *hren_iter_key(struct hren_iter *it, size_t *klen);
extern const void *hren_iter_value(const struct hren_iter *it, size_t *vlen);
/** The segment the current row is of, or NULL: the target's own row. */
extern const struct hren_seg *hren_iter_seg(const struct hren_iter *it);

#endif /* INCLUDED_history_rename_h */
