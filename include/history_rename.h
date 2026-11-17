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
 * incarnation (the later until_ms), an incarnation keeps at most
 * HREN_MAX_SEGS entries (the earliest leave first), and an entry whose
 * until_ms is behind the retention floor is dropped wherever a record is
 * read or written: every row it could name has aged out.
 *
 * Every server writes the record on its own when it executes the RENAME
 * (rename_channel() / relocate_execute(), local or from a server), so a
 * federated query needs nothing new on the wire: it names the current
 * name, and each store answers with what its own record says.
 *
 * No ircd dependency beyond the db_* API, db_casefold and the key codec
 * (history_trim_codec.h): unit-tested on the in-memory store and on
 * RocksDB (ircd/test/history_rename_cmocka.c).
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

/** Earlier names kept per channel incarnation. */
#define HREN_MAX_SEGS 16

/** Entries one record holds, every incarnation of the name together. */
#define HREN_REC_MAX 64

/** One earlier name of a channel, and which rows under it are the
 * channel's. */
struct hren_seg {
  char name[CHANNELLEN + 1];   /**< The earlier name, folded */
  uint64_t incarnation;        /**< The channel's creation timestamp */
  uint64_t until_ms;           /**< Rows stamped up to here count */
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
 * @return 0, or -1 (a bad name, no incarnation, or the store failed). */
extern int hren_note(struct db_env *env, struct db_cf *cf,
                     const char *oldname, const char *newname,
                     uint64_t incarnation, uint64_t until_ms,
                     uint64_t floor_ms);

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
