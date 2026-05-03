/** @file db_types.h
 * @brief Common types and error codes for the storage abstraction.
 *
 * The abstraction lives between Nefarious's persistent-storage call
 * sites (history.c, metadata.c, webpush_store.c, ml_content.c,
 * bouncer_session.c) and the actual key-value engine (libmdbx today,
 * RocksDB after migration).  See `.claude/plans/rocksdb-migration.md`
 * for context.
 *
 * Lifetime model:
 *   - Iterator key/value pointers (returned by db_iter_key /
 *     db_iter_value) are *borrowed*; valid only until the next
 *     operation on that iterator (next, prev, seek, close).
 *   - Single-get values (returned via `struct db_val` from db_get) are
 *     *owned*; caller frees with db_val_free.  This matches RocksDB's
 *     C-API contract; libmdbx backend pays a memcpy on get.
 *   - Input keys and values are passed as raw `const void* + size_t`
 *     and only need to live for the duration of the call.
 */
#ifndef INCLUDED_db_types_h
#define INCLUDED_db_types_h

#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif

/* Opaque handles.  Forward-declared here, defined per-backend. */
struct db_env;
struct db_cf;
struct db_iter;
struct db_writebatch;
struct db_snapshot;

/** An owned heap buffer returned from db_get.  Caller frees with
 * db_val_free.  Both fields are NULL/0 for a freshly-zeroed instance
 * or after free.  base is allocated by the backend; do not free it
 * directly. */
struct db_val {
  void  *base;
  size_t len;
};

/** Free a db_val previously populated by db_get.  Safe to call on a
 * zero-initialised db_val (no-op). */
extern void db_val_free(struct db_val *v);

/** Result codes.  All db_* functions returning int use these. */
enum {
  DB_OK         = 0,
  DB_NOTFOUND   = 1,   /**< key not present (db_get, iterator seek) */
  DB_ERR_IO     = -1,  /**< disk error, file open failure, etc. */
  DB_ERR_MEMORY = -2,  /**< allocation failure */
  DB_ERR_CORRUPT= -3,  /**< on-disk corruption / checksum mismatch */
  DB_ERR_FULL   = -4,  /**< storage exhausted (libmdbx MAP_FULL); on
                            RocksDB this is mapped from filesystem
                            ENOSPC.  Callers in history.c handle this
                            by triggering emergency_evict. */
  DB_ERR_OTHER  = -99
};

/** Iteration directions for db_iter_seek_first/last and stepping. */
enum db_dir {
  DB_DIR_FORWARD = 0,
  DB_DIR_BACKWARD = 1
};

#endif /* INCLUDED_db_types_h */
