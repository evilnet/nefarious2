/** @file db_env.h
 * @brief Storage environment lifecycle, column families, sync, compact, stats.
 *
 * An "env" is a single on-disk database directory hosting one or more
 * named column families (CFs).  libmdbx maps env→MDBX_env, CF→MDBX_dbi.
 * RocksDB maps env→rocksdb_t*, CF→rocksdb_column_family_handle_t*.
 *
 * Nefarious uses three logical envs: history, metadata, webpush.
 * Each is opened independently with its own tuning parameters.
 */
#ifndef INCLUDED_db_env_h
#define INCLUDED_db_env_h

#ifndef INCLUDED_db_types_h
#include "db_types.h"
#endif

/** Per-env tuning hints.  Not every backend respects every field; the
 * libmdbx backend uses size_floor/size_max for mdbx_env_set_geometry,
 * the RocksDB backend uses block_cache_bytes/write_buffer_bytes for
 * Options.  Fields with value 0 mean "use backend default." */
struct db_env_opts {
  size_t size_floor;          /**< libmdbx: lower bound for autoshrink */
  size_t size_max;            /**< libmdbx: upper bound for autogrow */
  size_t block_cache_bytes;   /**< RocksDB: shared block cache size */
  size_t write_buffer_bytes;  /**< RocksDB: per-CF memtable size */
  unsigned int sync_period_seconds;  /**< periodic durable-sync interval (libmdbx
                                          MDBX_opt_sync_period; RocksDB WAL flush) */
  int compress;               /**< nonzero: enable native block compression
                                    (RocksDB only — libmdbx ignores) */
  int random_access;          /**< nonzero: random-access workload hint
                                    (libmdbx MDBX_NORDAHEAD; RocksDB advise_random_on_open) */
};

/** Per-CF tuning at open time.  RocksDB uses these for column-family
 * Options; libmdbx ignores most of these (a DBI is just a B-tree). */
struct db_cf_opts {
  int dupsort;                /**< nonzero: backend supports multi-value-per-key.
                                    libmdbx: MDBX_DUPSORT.  RocksDB: caller MUST
                                    encode the dup discriminator into the key
                                    instead — flag is advisory only. */
  int append_optimised;       /**< nonzero: workload inserts at growing key.
                                    libmdbx: caller may pass MDBX_APPEND on put.
                                    RocksDB: hint only (memtable handles it). */
  int compress;               /**< nonzero: per-CF compression override */
};

/** Open (or create) an environment at @a path.  Caller closes with
 * db_env_close.  Returns DB_OK on success; on failure *out is NULL and
 * an error string is available via db_env_last_error after a failed
 * call (which is awkward when env creation itself failed — see also
 * db_strerror for static messages by code).
 *
 * @param path    Directory path for the env's files (created if absent).
 * @param opts    Tuning options.  May be NULL for backend defaults.
 * @param max_cfs Max number of column families that will be opened in
 *                this env.  libmdbx needs this up front (mdbx_env_set_maxdbs);
 *                RocksDB does not but accepts the hint.
 * @param[out] out  Receives the opened env handle.
 */
extern int db_env_open(const char *path,
                       const struct db_env_opts *opts,
                       unsigned int max_cfs,
                       struct db_env **out);

/** Close an environment.  All CFs, iterators, snapshots, and writebatches
 * derived from this env must be closed/freed first. */
extern void db_env_close(struct db_env *env);

/** Open a named column family in @a env.  CFs are opened by name; the
 * first opener creates the CF, subsequent opens return the same handle
 * (backends may keep an internal name→handle table).
 *
 * @param env  Env handle.
 * @param name CF name (NULL or "" for the default CF — libmdbx's main DBI).
 * @param opts CF tuning options.  May be NULL for defaults.
 * @param[out] out  Receives the opened CF handle.
 */
extern int db_cf_open(struct db_env *env,
                      const char *name,
                      const struct db_cf_opts *opts,
                      struct db_cf **out);

/** Close a CF handle.  Optional; db_env_close closes all open CFs. */
extern void db_cf_close(struct db_env *env, struct db_cf *cf);

/** Force a durable sync of pending writes.  Both backends honour this
 * regardless of the configured sync mode.  Returns DB_OK or an error. */
extern int db_env_sync(struct db_env *env);

/** Compact / defragment the env.  libmdbx: mdbx_env_defrag.  RocksDB:
 * rocksdb_compact_range_cf over each CF.  May be slow; intended for
 * the operator-issued /MDBX DEFRAG command, not regular maintenance.
 * @param cf  If non-NULL, compact only this CF.  If NULL, compact all
 *            CFs in @a env. */
extern int db_env_compact(struct db_env *env, struct db_cf *cf);

/** Backend-agnostic stats record returned by db_env_stats.  Numbers
 * are approximate on RocksDB (estimate-num-keys is not exact) and
 * exact on libmdbx (B-tree leaf count).  Empty fields are zero. */
struct db_env_stats {
  size_t   on_disk_bytes;        /**< total file size of all CFs in env */
  size_t   approx_keys_total;    /**< sum of estimate-num-keys across CFs */
  size_t   pending_compaction;   /**< RocksDB: pending compaction bytes; libmdbx: 0 */
  unsigned int level0_files;     /**< RocksDB only; libmdbx: 0 */
  unsigned int active_readers;   /**< libmdbx reader-table count; RocksDB: 0 */
};
extern int db_env_stats(struct db_env *env, struct db_env_stats *out);

/** Per-CF stats variant of the above.  Useful for per-CF /STATS output. */
struct db_cf_stats {
  size_t   on_disk_bytes;
  size_t   approx_keys;
  unsigned int depth;            /**< libmdbx B-tree depth; RocksDB: max LSM level */
};
extern int db_cf_stats(struct db_env *env, struct db_cf *cf,
                       struct db_cf_stats *out);

/** Reap stale reader-table slots after an unclean shutdown.  libmdbx-
 * specific; RocksDB no-op.  Called from history.c startup recovery. */
extern int db_env_reap_dead_readers(struct db_env *env);

/** Hint the OS to prefault pages.  libmdbx: mdbx_env_warmup.  RocksDB:
 * trivial first-block read of each CF.  Optional; both backends are
 * fine without it. */
extern int db_env_warmup(struct db_env *env);

/** Static, thread-safe message for a result code.  Returns a pointer
 * to a static string ("not found", "I/O error", etc.).  For backend-
 * specific detail use db_env_last_error. */
extern const char *db_strerror(int rc);

/** Most recent backend-specific error string for this env.  May be
 * NULL if no error has occurred or the backend doesn't track it.
 * Pointer is owned by the env; do not free.  Valid until the next
 * call on @a env. */
extern const char *db_env_last_error(struct db_env *env);

/* -------------------------------------------------------------------- *
 * Transitional escape hatches for incremental Phase 0 conversion.
 *
 * These let modules that haven't yet been fully ported to the abstraction
 * reach into the libmdbx backend for advanced features (stats, defrag,
 * GC info) that the abstraction doesn't surface.  They exist only when
 * USE_MDBX is the active backend; once Phase 4 (RocksDB migration)
 * deletes the libmdbx-specific code paths, these helpers retire.
 * -------------------------------------------------------------------- */
#ifdef USE_MDBX
struct MDBX_env;
struct MDBX_txn;
struct db_writebatch;
struct db_snapshot;
/** Return the underlying MDBX_env* for an env opened via db_env_open.
 * Caller must NOT close the returned env; ownership stays with @a env. */
extern struct MDBX_env *db_mdbx_unwrap_env(struct db_env *env);

/** Return the underlying MDBX_dbi for a CF opened via db_cf_open.
 * Returns 0 if @a cf is NULL (libmdbx valid DBIs are positive). */
extern unsigned int db_mdbx_unwrap_dbi(struct db_cf *cf);

/** Return the underlying MDBX_txn* for a writebatch.  libmdbx's
 * writebatch IS an open mdbx txn; this lets transitional code that
 * still calls raw mdbx_* (e.g. DUPSORT puts on reply_index, libmdbx's
 * MAP_FULL retry loop) interleave with the abstraction's writebatch.
 * The txn is begun lazily on the first put/del; calling this on an
 * empty writebatch returns NULL. */
extern struct MDBX_txn *db_mdbx_unwrap_writebatch_txn(struct db_writebatch *wb);

/** Return the underlying MDBX_txn* for a snapshot.  libmdbx's snapshot
 * is a read-only txn; this lets transitional read-side code (still raw
 * mdbx, e.g. ml_content_resolve) read through the same point-in-time
 * view as a sibling db_iter.  Returns NULL if the snapshot is NULL. */
extern struct MDBX_txn *db_mdbx_unwrap_snapshot_txn(struct db_snapshot *snap);
#endif

#endif /* INCLUDED_db_env_h */
