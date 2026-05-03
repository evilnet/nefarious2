/** @file db_cursor.h
 * @brief Iterator/cursor primitives for range scans.
 *
 * The iterator is the most-used part of the abstraction (~66 sites
 * across history.c alone).  It directly mirrors the libmdbx cursor
 * API and the RocksDB iterator API, both of which expose the same
 * mental model: positionable cursor, step forward/backward, peek at
 * current key/value.
 *
 * Lifetime invariants:
 *   - Pointers from db_iter_key / db_iter_value are valid until the
 *     next operation on this iterator (next, prev, seek*, close).
 *     This is true on both backends — libmdbx returns mmap pointers
 *     valid for the read txn; RocksDB iterators own a small scratch
 *     that is overwritten on each step.
 *   - Iterators are tied to the snapshot they were opened against (or
 *     to an implicit snapshot if @a snap was NULL at open time).  The
 *     snapshot must outlive the iterator.
 *   - Iterators are tied to the env; close before db_env_close.
 *
 * Typical pattern:
 *
 *   struct db_iter *it = db_iter_open(env, cf, NULL);
 *   if (!it) goto err;
 *   if (db_iter_seek(it, prefix, prefix_len) != DB_OK)
 *     goto done;
 *   while (db_iter_valid(it)) {
 *     size_t klen, vlen;
 *     const void *k = db_iter_key(it, &klen);
 *     const void *v = db_iter_value(it, &vlen);
 *     if (klen < prefix_len ||
 *         memcmp(k, prefix, prefix_len) != 0)
 *       break;
 *     ...consume k/v (copy out anything you need to keep)...
 *     db_iter_next(it);
 *   }
 *  done:
 *   db_iter_close(it);
 */
#ifndef INCLUDED_db_cursor_h
#define INCLUDED_db_cursor_h

#ifndef INCLUDED_db_types_h
#include "db_types.h"
#endif

/** Open a new iterator on @a cf within @a env.  If @a snap is non-NULL,
 * the iterator reads through that snapshot.  Otherwise it reads the
 * env's current state (acquiring an implicit snapshot for the
 * iterator's lifetime).
 *
 * The newly-opened iterator is *not positioned* — call db_iter_seek*
 * before any key/value access.  db_iter_valid returns 0 on an
 * unpositioned iterator.
 *
 * Returns NULL on failure (allocation, bad CF, etc.). */
extern struct db_iter *db_iter_open(struct db_env *env,
                                    struct db_cf *cf,
                                    struct db_snapshot *snap);

/** Close an iterator and release its resources.  Safe on NULL. */
extern void db_iter_close(struct db_iter *it);

/** Position the iterator at the smallest key >= @a key.
 * Equivalent to libmdbx MDBX_SET_RANGE / RocksDB Seek.
 * Returns DB_OK if the iterator is now positioned at a valid key,
 * DB_NOTFOUND if no such key exists (iterator becomes invalid),
 * DB_ERR_* on backend error. */
extern int db_iter_seek(struct db_iter *it,
                        const void *key, size_t klen);

/** Position at the smallest key in the CF.  RocksDB SeekToFirst /
 * libmdbx MDBX_FIRST.  Returns DB_OK or DB_NOTFOUND (empty CF). */
extern int db_iter_seek_first(struct db_iter *it);

/** Position at the largest key in the CF.  RocksDB SeekToLast /
 * libmdbx MDBX_LAST. */
extern int db_iter_seek_last(struct db_iter *it);

/** Step forward one key.  After return, db_iter_valid tells you
 * whether the iterator is still positioned. */
extern int db_iter_next(struct db_iter *it);

/** Step backward one key. */
extern int db_iter_prev(struct db_iter *it);

/** Returns nonzero if the iterator is currently positioned at a valid
 * key.  Use this in `while (db_iter_valid(it))` loops; do not rely on
 * the return code of db_iter_next/prev (which is the libmdbx-style
 * DB_NOTFOUND-when-stepped-off-end). */
extern int db_iter_valid(const struct db_iter *it);

/** Borrow the current key.  Pointer is valid until the next iter op.
 * NULL if iterator is not valid. */
extern const void *db_iter_key(const struct db_iter *it, size_t *klen);

/** Borrow the current value.  Pointer is valid until the next iter op.
 * NULL if iterator is not valid. */
extern const void *db_iter_value(const struct db_iter *it, size_t *vlen);

#endif /* INCLUDED_db_cursor_h */
