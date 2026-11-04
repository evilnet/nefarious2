/** @file fake_db.h
 * @brief In-memory fake backend for the storage API (db_env.h /
 *        db_txn.h / db_cursor.h / db_types.h), for CMocka tests.
 *
 * Implements the full db_* ABI: sorted rows per column family,
 * iterators that read a copy taken at open (snapshot semantics, as
 * ircd/test/db_casefold_cmocka.c's own narrower fake), write batches
 * applied in order at commit.  No RocksDB, no libmdbx.
 *
 * db_env_open/close/sync/compact/stats/warmup are not meaningful for
 * this fake (there is no on-disk env to open) and return DB_ERR_OTHER;
 * build the fake's env with fake_db_new() instead and free it with
 * fake_db_free().
 */
#ifndef INCLUDED_fake_db_h
#define INCLUDED_fake_db_h

#ifndef INCLUDED_db_types_h
#include "db_types.h"
#endif

/** Create a fake env.  Call db_cf_open on it to open column families,
 * same as a real env.  Free with fake_db_free. */
extern struct db_env *fake_db_new(void);

/** Free a fake env and every row in every CF it holds. */
extern void fake_db_free(struct db_env *env);

/** Make the NEXT db_writebatch_commit on this env fail: it returns
 * DB_ERR_IO and applies none of its staged ops.  One-shot -- clears
 * itself whether or not a batch is actually committed. */
extern void fake_db_fail_next_commit(struct db_env *env);

/** Make the @a n-th db_writebatch_commit from now on this env fail the
 * same way (1 = the next one; 0 cancels).  One-shot. */
extern void fake_db_fail_commit_at(struct db_env *env, unsigned int n);

/** Make the NEXT staging op (db_writebatch_put / _put_append / _del) on
 * any batch of this env return DB_ERR_MEMORY and stage nothing.
 * One-shot. */
extern void fake_db_fail_next_batch_op(struct db_env *env);

/** Make the NEXT db_iter_open / db_iter_open_bounded on this env return
 * NULL.  One-shot. */
extern void fake_db_fail_next_iter_open(struct db_env *env);

/** Make the @a n-th db_get from now on this env return DB_ERR_IO (1 =
 * the next one; 0 cancels).  One-shot. */
extern void fake_db_fail_get_at(struct db_env *env, unsigned int n);

/** Number of db_iter_open + db_iter_open_bounded calls made on @a cf
 * since it was opened. */
extern unsigned int fake_db_iter_opens(const struct db_cf *cf);

/** Number of db_iter_seek_first / db_iter_seek_last calls made on
 * iterators over @a cf since it was opened. */
extern unsigned int fake_db_seek_firsts(const struct db_cf *cf);
extern unsigned int fake_db_seek_lasts(const struct db_cf *cf);

/** Number of db_suggest_compact calls made on @a cf since it was
 * opened. */
extern unsigned int fake_db_suggest_calls(const struct db_cf *cf);

/** The bounds of the most recent db_suggest_compact call on @a cf.
 * The out params are NULL/0 for a bound that call passed as NULL.
 * Pointers are owned by @a cf; valid until the next db_suggest_compact
 * call on it.  Returns DB_OK, or DB_NOTFOUND if db_suggest_compact has
 * never been called on this cf. */
extern int fake_db_last_suggest(const struct db_cf *cf,
                                const void **start, size_t *slen,
                                const void **end, size_t *elen);

/** The lower bound of the most recent db_iter_open_bounded on @a cf
 * (NULL/0 when that open had none, or before any).  Owned by @a cf; valid
 * until the next bounded open on it.  On RocksDB a seek from a lower
 * bound skips every tombstone before it; from no bound it walks them. */
extern void fake_db_last_iter_lower(const struct db_cf *cf,
                                    const void **lower, size_t *llen);

/** Current row count of @a cf. */
extern size_t fake_db_rows(const struct db_cf *cf);

#endif /* INCLUDED_fake_db_h */
