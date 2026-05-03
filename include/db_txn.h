/** @file db_txn.h
 * @brief Read snapshots and write batches.
 *
 * Nefarious's IRCd is single-threaded event-driven; the event loop
 * serializes writes.  We don't need MVCC / TransactionDB conflict
 * resolution — a write batch (atomic group of put/del that commits
 * with optional fsync) is sufficient.  Reads that need a stable view
 * across multiple operations use a snapshot.
 *
 * Write batch lifecycle:
 *   wb = db_writebatch_new(env);
 *   db_writebatch_put(wb, cf, k, kl, v, vl);
 *   db_writebatch_del(wb, cf, k, kl);
 *   ... more ops ...
 *   rc = db_writebatch_commit(wb, sync_durably);
 *   db_writebatch_destroy(wb);
 *
 * Snapshot lifecycle:
 *   s = db_snapshot_new(env);
 *   db_get(env, cf, key, klen, s, &val);
 *   it = db_iter_open(env, cf, s);
 *   ... use iterator ...
 *   db_iter_close(it);
 *   db_snapshot_destroy(s);
 */
#ifndef INCLUDED_db_txn_h
#define INCLUDED_db_txn_h

#ifndef INCLUDED_db_types_h
#include "db_types.h"
#endif

/* -------------------------------------------------------------------- */
/* Write batches                                                        */
/* -------------------------------------------------------------------- */

/** Create a new write batch in @a env.  Operations queue up in memory
 * until commit.  Returns NULL on allocation failure. */
extern struct db_writebatch *db_writebatch_new(struct db_env *env);

/** Discard a write batch without committing.  Safe to call after a
 * successful commit (no-op) or on a NULL pointer. */
extern void db_writebatch_destroy(struct db_writebatch *wb);

/** Stage a put.  Key and value memory only needs to live for the
 * duration of this call (the batch copies it internally).
 * Returns DB_OK or DB_ERR_*. */
extern int db_writebatch_put(struct db_writebatch *wb,
                             struct db_cf *cf,
                             const void *key, size_t klen,
                             const void *val, size_t vlen);

/** Stage a put with an APPEND hint.  Use only when keys are inserted
 * in strictly monotonically-increasing order (chathistory hot path).
 * libmdbx backend translates to MDBX_APPEND for the underlying put.
 * RocksDB ignores the hint — its memtable handles ordered inserts
 * efficiently regardless. */
extern int db_writebatch_put_append(struct db_writebatch *wb,
                                    struct db_cf *cf,
                                    const void *key, size_t klen,
                                    const void *val, size_t vlen);

/** Stage a delete.  Idempotent: deleting a non-existent key is DB_OK. */
extern int db_writebatch_del(struct db_writebatch *wb,
                             struct db_cf *cf,
                             const void *key, size_t klen);

/** Commit all staged operations atomically.
 * @param sync_durably  Nonzero: fsync before returning (slower, durable).
 *                      Zero: rely on the env's configured sync policy
 *                      (libmdbx MDBX_SAFE_NOSYNC + sync_period; RocksDB
 *                      WAL with manual_wal_flush + flush timer).
 * Returns DB_OK on success, DB_ERR_FULL if storage exhausted, or
 * DB_ERR_* otherwise.  On failure the batch state is undefined; caller
 * should destroy and start over.
 *
 * After a successful commit the batch is empty and may be reused. */
extern int db_writebatch_commit(struct db_writebatch *wb, int sync_durably);

/** Number of staged operations in the batch.  Useful for "did I
 * actually queue anything" checks before committing. */
extern unsigned int db_writebatch_count(const struct db_writebatch *wb);

/* -------------------------------------------------------------------- */
/* Read snapshots                                                       */
/* -------------------------------------------------------------------- */

/** Create a snapshot of the current env state.  Subsequent reads
 * passing this snapshot see exactly this point-in-time view, even if
 * other code commits writes in between.  Internally cheap on both
 * backends: libmdbx opens a read-only txn, RocksDB pins the LSM
 * sequence number.  Returns NULL on failure. */
extern struct db_snapshot *db_snapshot_new(struct db_env *env);

/** Release a snapshot.  Safe on NULL.  After release, any iterator or
 * pending get that referenced this snapshot must not be used. */
extern void db_snapshot_destroy(struct db_snapshot *s);

/* -------------------------------------------------------------------- */
/* Single-shot get                                                      */
/* -------------------------------------------------------------------- */

/** Look up @a key in @a cf.  Returns:
 *   DB_OK         — key found, *out populated, caller frees with
 *                    db_val_free
 *   DB_NOTFOUND   — key absent, *out untouched
 *   DB_ERR_*      — backend error
 *
 * If @a snap is non-NULL, reads through that snapshot.  Otherwise
 * reads the env's current state (small implicit snapshot).
 *
 * The returned value buffer is owned by the caller; call db_val_free
 * when done.  The buffer's lifetime is independent of @a snap (the
 * snapshot may be destroyed before the value is freed).
 *
 * The libmdbx backend pays a memcpy here; RocksDB returns its
 * heap-allocated buffer directly. */
extern int db_get(struct db_env *env,
                  struct db_cf *cf,
                  const void *key, size_t klen,
                  struct db_snapshot *snap,    /* may be NULL */
                  struct db_val *out);

/** Convenience: check whether a key exists, without copying its value.
 * Returns DB_OK if present, DB_NOTFOUND if absent, DB_ERR_* on error. */
extern int db_exists(struct db_env *env,
                     struct db_cf *cf,
                     const void *key, size_t klen,
                     struct db_snapshot *snap);

#endif /* INCLUDED_db_txn_h */
