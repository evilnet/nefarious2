/** @file db_rocksdb.c
 * @brief RocksDB backend for the storage abstraction (db_env.h /
 *        db_txn.h / db_cursor.h / db_types.h).
 *
 * Mirrors db_mdbx.c structurally.  Uses the librocksdb C API
 * (rocksdb/c.h) so the entire codebase stays C even though RocksDB
 * itself is C++.  See `.claude/plans/rocksdb-migration.md` Phase 2.
 *
 * Concept mapping:
 *   db_env           ↔ rocksdb_t* + shared options/block-cache + CF list
 *   db_cf            ↔ rocksdb_column_family_handle_t* keyed by name
 *   db_snapshot      ↔ const rocksdb_snapshot_t* pinned by readoptions
 *   db_writebatch    ↔ rocksdb_writebatch_t* committed via rocksdb_write
 *   db_iter          ↔ rocksdb_iterator_t* (with snapshot/readoptions)
 *
 * Lifetime (matches the abstraction):
 *   - Iterator key/value pointers are borrowed; valid until the next
 *     op on that iterator.  RocksDB's iterator owns scratch buffers
 *     overwritten by Next/Prev/Seek.
 *   - db_get returns an *owned* db_val whose base is the heap buffer
 *     returned by rocksdb_get_cf.  Caller frees with db_val_free.
 *
 * RocksDB quirks handled:
 *   - All existing CFs must be passed at rocksdb_open_column_families
 *     time.  We list them first via rocksdb_list_column_families and
 *     open the full set.  db_cf_open returns the handle for an
 *     already-open CF, or rocksdb_create_column_family for a new one.
 *   - errptr-style errors: every fallible call returns a malloc'd
 *     error string into a `char**`.  We copy/log it and rocksdb_free
 *     it.
 *   - Mode hint MDBX_APPEND has no equivalent — RocksDB's memtable
 *     handles ordered inserts efficiently.  put_append degrades to
 *     a normal put.
 *   - Sync mode: WriteOptions::sync controls per-write durability;
 *     manual_wal_flush + a periodic flush approximates libmdbx's
 *     SAFE_NOSYNC + sync_period.  For Phase 2 we honor sync_durably
 *     on commit and otherwise let the WAL accumulate.
 */
#include "config.h"

#ifdef USE_ROCKSDB

#include "client.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"

#include <rocksdb/c.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/* Internal struct definitions                                          */
/* -------------------------------------------------------------------- */

struct db_cf {
  struct db_env  *env;
  rocksdb_column_family_handle_t *handle;
  rocksdb_options_t *cf_opts;       /* per-CF options (compression, etc.) */
  char           *name;             /* heap-owned */
  struct db_cf   *next;             /* linked list within env */
};

struct db_env {
  rocksdb_t      *db;
  rocksdb_options_t *db_opts;
  rocksdb_cache_t   *block_cache;   /* shared LRU across all CFs */
  rocksdb_writeoptions_t *wopts_normal;  /* sync=false */
  rocksdb_writeoptions_t *wopts_sync;    /* sync=true */
  rocksdb_readoptions_t  *ropts_default; /* no snapshot */
  struct db_cf   *cfs;              /* head of CF list, includes default */
  char           *path;
  char            last_error[256];
};

struct db_snapshot {
  struct db_env *env;
  const rocksdb_snapshot_t *snap;
  rocksdb_readoptions_t    *ropts;  /* readoptions with snapshot pinned */
};

struct db_writebatch {
  struct db_env *env;
  rocksdb_writebatch_t *wb;
  unsigned int   count;
};

struct db_iter {
  struct db_env *env;
  struct db_cf  *cf;
  rocksdb_iterator_t    *iter;
  rocksdb_readoptions_t *ropts;     /* may be borrowed from snapshot */
  int            owns_ropts;
  int            positioned;        /* cached rocksdb_iter_valid result */
};

/* -------------------------------------------------------------------- */
/* Error tracking                                                       */
/* -------------------------------------------------------------------- */

static void env_record_error(struct db_env *env, const char *where, const char *errptr)
{
  if (!env)
    return;
  ircd_snprintf(NULL, env->last_error, sizeof env->last_error,
                "%s: %s", where, errptr ? errptr : "(unknown)");
}

const char *db_strerror(int rc)
{
  switch (rc) {
  case DB_OK:          return "ok";
  case DB_NOTFOUND:    return "not found";
  case DB_ERR_IO:      return "I/O error";
  case DB_ERR_MEMORY:  return "out of memory";
  case DB_ERR_CORRUPT: return "data corruption";
  case DB_ERR_FULL:    return "storage full";
  case DB_ERR_OTHER:   return "backend error";
  default:             return "unknown error";
  }
}

const char *db_env_last_error(struct db_env *env)
{
  return (env && env->last_error[0]) ? env->last_error : NULL;
}

/* RocksDB's errptr strings are loosely categorised — we map a few common
 * substrings to specific DB_ERR codes; everything else falls through to
 * DB_ERR_OTHER. */
static int translate_errptr(const char *errptr)
{
  if (!errptr)
    return DB_ERR_OTHER;
  if (strstr(errptr, "NotFound") || strstr(errptr, "not found"))
    return DB_NOTFOUND;
  if (strstr(errptr, "Corruption"))
    return DB_ERR_CORRUPT;
  if (strstr(errptr, "IOError") || strstr(errptr, "No space"))
    return DB_ERR_IO;
  if (strstr(errptr, "MemoryAllocation"))
    return DB_ERR_MEMORY;
  return DB_ERR_OTHER;
}

/* -------------------------------------------------------------------- */
/* db_val                                                               */
/* -------------------------------------------------------------------- */

void db_val_free(struct db_val *v)
{
  if (v && v->base) {
    /* db_val.base for RocksDB-returned values is a heap buffer
     * allocated by rocksdb_get_cf.  RocksDB requires rocksdb_free
     * (which is just free internally on most platforms, but the
     * library is the canonical owner). */
    rocksdb_free(v->base);
    v->base = NULL;
    v->len  = 0;
  }
}

/* -------------------------------------------------------------------- */
/* CF helpers                                                           */
/* -------------------------------------------------------------------- */

static struct db_cf *env_find_cf(struct db_env *env, const char *name)
{
  struct db_cf *cf;
  const char *want = (name && *name) ? name : "default";
  for (cf = env->cfs; cf; cf = cf->next) {
    if (cf->name && 0 == strcmp(cf->name, want))
      return cf;
  }
  return NULL;
}

static struct db_cf *env_alloc_cf(struct db_env *env, const char *name,
                                  rocksdb_column_family_handle_t *handle,
                                  rocksdb_options_t *cf_opts)
{
  struct db_cf *cf = MyCalloc(1, sizeof *cf);
  if (!cf)
    return NULL;
  cf->env = env;
  cf->handle = handle;
  cf->cf_opts = cf_opts;
  if (name && *name) {
    cf->name = MyMalloc(strlen(name) + 1);
    if (!cf->name) {
      MyFree(cf);
      return NULL;
    }
    strcpy(cf->name, name);
  } else {
    cf->name = MyMalloc(strlen("default") + 1);
    if (!cf->name) {
      MyFree(cf);
      return NULL;
    }
    strcpy(cf->name, "default");
  }
  cf->next = env->cfs;
  env->cfs = cf;
  return cf;
}

static rocksdb_options_t *make_cf_options(int compress)
{
  rocksdb_options_t *o = rocksdb_options_create();
  if (!o)
    return NULL;
  if (compress)
    rocksdb_options_set_compression(o, rocksdb_zstd_compression);
  return o;
}

/* -------------------------------------------------------------------- */
/* Env lifecycle                                                        */
/* -------------------------------------------------------------------- */

int db_env_open(const char *path,
                const struct db_env_opts *opts,
                unsigned int max_cfs,
                struct db_env **out)
{
  struct db_env *env;
  char *err = NULL;
  size_t existing_count = 0;
  char **existing_names = NULL;

  (void)max_cfs;
  assert(path);
  assert(out);
  *out = NULL;

  env = MyCalloc(1, sizeof *env);
  if (!env)
    return DB_ERR_MEMORY;

  env->path = MyMalloc(strlen(path) + 1);
  if (!env->path) {
    MyFree(env);
    return DB_ERR_MEMORY;
  }
  strcpy(env->path, path);

  /* Block cache shared across CFs.  Sized from opts or a sensible
   * default (64 MB).  */
  {
    size_t sz = (opts && opts->block_cache_bytes) ? opts->block_cache_bytes
                                                  : (64UL * 1024 * 1024);
    env->block_cache = rocksdb_cache_create_lru(sz);
  }

  env->db_opts = rocksdb_options_create();
  rocksdb_options_set_create_if_missing(env->db_opts, 1);
  rocksdb_options_set_create_missing_column_families(env->db_opts, 1);
  if (opts && opts->write_buffer_bytes)
    rocksdb_options_set_write_buffer_size(env->db_opts, opts->write_buffer_bytes);
  if (opts && opts->random_access)
    rocksdb_options_set_advise_random_on_open(env->db_opts, 1);

  env->wopts_normal = rocksdb_writeoptions_create();
  rocksdb_writeoptions_set_sync(env->wopts_normal, 0);
  env->wopts_sync = rocksdb_writeoptions_create();
  rocksdb_writeoptions_set_sync(env->wopts_sync, 1);
  env->ropts_default = rocksdb_readoptions_create();

  /* List existing column families.  If the DB doesn't exist yet
   * rocksdb_list_column_families fails; that's fine — we'll open
   * with just the default CF and the create_if_missing flag does
   * the rest. */
  existing_names = rocksdb_list_column_families(env->db_opts, path,
                                                &existing_count, &err);
  if (err) {
    /* Treat a missing-DB error as empty CF list.  Other errors
     * surface to the caller. */
    if (strstr(err, "No such file") || strstr(err, "does not exist")) {
      rocksdb_free(err);
      err = NULL;
      existing_names = NULL;
      existing_count = 0;
    } else {
      env_record_error(env, "list_column_families", err);
      log_write(LS_SYSTEM, L_ERROR, 0, "db_rocksdb: %s", env->last_error);
      rocksdb_free(err);
      rocksdb_options_destroy(env->db_opts);
      rocksdb_writeoptions_destroy(env->wopts_normal);
      rocksdb_writeoptions_destroy(env->wopts_sync);
      rocksdb_readoptions_destroy(env->ropts_default);
      rocksdb_cache_destroy(env->block_cache);
      MyFree(env->path);
      MyFree(env);
      return DB_ERR_IO;
    }
  }

  /* Build per-CF options array.  All existing CFs share the same
   * default options for now; per-CF tuning happens later if needed. */
  {
    size_t n = (existing_count > 0) ? existing_count : 1;
    const char **cf_names = MyCalloc(n, sizeof *cf_names);
    rocksdb_options_t **cf_opts = MyCalloc(n, sizeof *cf_opts);
    rocksdb_column_family_handle_t **cf_handles = MyCalloc(n, sizeof *cf_handles);
    size_t i;

    if (!cf_names || !cf_opts || !cf_handles) {
      if (cf_names) MyFree(cf_names);
      if (cf_opts)  MyFree(cf_opts);
      if (cf_handles) MyFree(cf_handles);
      if (existing_names) {
        for (i = 0; i < existing_count; i++) rocksdb_free(existing_names[i]);
        rocksdb_free(existing_names);
      }
      rocksdb_options_destroy(env->db_opts);
      rocksdb_writeoptions_destroy(env->wopts_normal);
      rocksdb_writeoptions_destroy(env->wopts_sync);
      rocksdb_readoptions_destroy(env->ropts_default);
      rocksdb_cache_destroy(env->block_cache);
      MyFree(env->path);
      MyFree(env);
      return DB_ERR_MEMORY;
    }

    if (existing_count > 0) {
      for (i = 0; i < existing_count; i++) {
        cf_names[i] = existing_names[i];
        cf_opts[i]  = make_cf_options(opts && opts->compress);
      }
    } else {
      /* Fresh DB: open with just "default". */
      cf_names[0] = "default";
      cf_opts[0]  = make_cf_options(opts && opts->compress);
    }

    env->db = rocksdb_open_column_families(env->db_opts, path,
                                           (int)n, cf_names, (const rocksdb_options_t **)cf_opts,
                                           cf_handles, &err);
    if (err) {
      env_record_error(env, "open_column_families", err);
      log_write(LS_SYSTEM, L_ERROR, 0, "db_rocksdb: %s", env->last_error);
      rocksdb_free(err);
      for (i = 0; i < n; i++) rocksdb_options_destroy(cf_opts[i]);
      MyFree(cf_names);
      MyFree(cf_opts);
      MyFree(cf_handles);
      if (existing_names) {
        for (i = 0; i < existing_count; i++) rocksdb_free(existing_names[i]);
        rocksdb_free(existing_names);
      }
      rocksdb_options_destroy(env->db_opts);
      rocksdb_writeoptions_destroy(env->wopts_normal);
      rocksdb_writeoptions_destroy(env->wopts_sync);
      rocksdb_readoptions_destroy(env->ropts_default);
      rocksdb_cache_destroy(env->block_cache);
      MyFree(env->path);
      MyFree(env);
      return DB_ERR_IO;
    }

    /* Populate db_cf list with the opened handles. */
    for (i = 0; i < n; i++) {
      const char *nm = cf_names[i];
      if (!env_alloc_cf(env, nm, cf_handles[i], cf_opts[i])) {
        /* Out of memory: caller will see partial CF list; cleanup
         * via db_env_close.  Drop the handle to avoid leak. */
        rocksdb_column_family_handle_destroy(cf_handles[i]);
        rocksdb_options_destroy(cf_opts[i]);
      }
    }

    if (existing_names) {
      for (i = 0; i < existing_count; i++) rocksdb_free(existing_names[i]);
      rocksdb_free(existing_names);
    }
    MyFree(cf_names);
    MyFree(cf_opts);
    MyFree(cf_handles);
  }

  *out = env;
  return DB_OK;
}

void db_env_close(struct db_env *env)
{
  struct db_cf *cf, *next;
  if (!env)
    return;

  cf = env->cfs;
  while (cf) {
    next = cf->next;
    if (cf->handle)  rocksdb_column_family_handle_destroy(cf->handle);
    if (cf->cf_opts) rocksdb_options_destroy(cf->cf_opts);
    if (cf->name)    MyFree(cf->name);
    MyFree(cf);
    cf = next;
  }

  if (env->db)            rocksdb_close(env->db);
  if (env->db_opts)       rocksdb_options_destroy(env->db_opts);
  if (env->wopts_normal)  rocksdb_writeoptions_destroy(env->wopts_normal);
  if (env->wopts_sync)    rocksdb_writeoptions_destroy(env->wopts_sync);
  if (env->ropts_default) rocksdb_readoptions_destroy(env->ropts_default);
  if (env->block_cache)   rocksdb_cache_destroy(env->block_cache);
  if (env->path)          MyFree(env->path);
  MyFree(env);
}

int db_env_sync(struct db_env *env)
{
  char *err = NULL;
  rocksdb_flushoptions_t *fopts;
  if (!env || !env->db)
    return DB_ERR_OTHER;
  fopts = rocksdb_flushoptions_create();
  rocksdb_flushoptions_set_wait(fopts, 1);
  rocksdb_flush(env->db, fopts, &err);
  rocksdb_flushoptions_destroy(fopts);
  if (err) {
    env_record_error(env, "flush", err);
    rocksdb_free(err);
    return DB_ERR_IO;
  }
  return DB_OK;
}

int db_env_compact(struct db_env *env, struct db_cf *cf)
{
  if (!env || !env->db)
    return DB_ERR_OTHER;
  if (cf) {
    rocksdb_compact_range_cf(env->db, cf->handle, NULL, 0, NULL, 0);
  } else {
    /* Compact every CF */
    struct db_cf *c;
    for (c = env->cfs; c; c = c->next)
      rocksdb_compact_range_cf(env->db, c->handle, NULL, 0, NULL, 0);
  }
  return DB_OK;
}

int db_env_warmup(struct db_env *env)
{
  /* RocksDB warms the block cache on demand; nothing to do here. */
  (void)env;
  return DB_OK;
}

int db_env_reap_dead_readers(struct db_env *env)
{
  /* RocksDB has no reader table to reap. */
  (void)env;
  return DB_OK;
}

int db_env_stats(struct db_env *env, struct db_env_stats *out)
{
  struct db_cf *c;
  if (!env || !env->db || !out)
    return DB_ERR_OTHER;
  memset(out, 0, sizeof *out);

  /* Sum per-CF estimate-num-keys for the env-wide approximation. */
  for (c = env->cfs; c; c = c->next) {
    char *v = rocksdb_property_value_cf(env->db, c->handle, "rocksdb.estimate-num-keys");
    if (v) {
      out->approx_keys_total += (size_t)strtoull(v, NULL, 10);
      rocksdb_free(v);
    }
  }
  /* on_disk_bytes: sum of total-sst-files-size if available */
  for (c = env->cfs; c; c = c->next) {
    char *v = rocksdb_property_value_cf(env->db, c->handle, "rocksdb.total-sst-files-size");
    if (v) {
      out->on_disk_bytes += (size_t)strtoull(v, NULL, 10);
      rocksdb_free(v);
    }
  }
  /* pending_compaction across CFs */
  for (c = env->cfs; c; c = c->next) {
    char *v = rocksdb_property_value_cf(env->db, c->handle, "rocksdb.estimate-pending-compaction-bytes");
    if (v) {
      out->pending_compaction += (size_t)strtoull(v, NULL, 10);
      rocksdb_free(v);
    }
  }
  return DB_OK;
}

int db_cf_stats(struct db_env *env, struct db_cf *cf, struct db_cf_stats *out)
{
  char *v;
  if (!env || !env->db || !cf || !out)
    return DB_ERR_OTHER;
  memset(out, 0, sizeof *out);
  v = rocksdb_property_value_cf(env->db, cf->handle, "rocksdb.estimate-num-keys");
  if (v) { out->approx_keys = (size_t)strtoull(v, NULL, 10); rocksdb_free(v); }
  v = rocksdb_property_value_cf(env->db, cf->handle, "rocksdb.total-sst-files-size");
  if (v) { out->on_disk_bytes = (size_t)strtoull(v, NULL, 10); rocksdb_free(v); }
  /* depth maps to LSM levels */
  v = rocksdb_property_value_cf(env->db, cf->handle, "rocksdb.num-files-at-level0");
  if (v) { out->depth = (unsigned int)strtoul(v, NULL, 10); rocksdb_free(v); }
  return DB_OK;
}

/* -------------------------------------------------------------------- */
/* Column family lifecycle                                              */
/* -------------------------------------------------------------------- */

int db_cf_open(struct db_env *env,
               const char *name,
               const struct db_cf_opts *opts,
               struct db_cf **out)
{
  struct db_cf *cf;
  rocksdb_options_t *cf_opts;
  rocksdb_column_family_handle_t *handle;
  char *err = NULL;
  const char *want = (name && *name) ? name : "default";

  assert(out);
  *out = NULL;
  if (!env || !env->db)
    return DB_ERR_OTHER;

  /* If already open, return the existing handle. */
  cf = env_find_cf(env, want);
  if (cf) {
    *out = cf;
    return DB_OK;
  }

  /* Otherwise create.  RocksDB errors if the CF already exists; the
   * env_find_cf check above protects against that for handles we
   * already track. */
  cf_opts = make_cf_options(opts && opts->compress);
  if (!cf_opts)
    return DB_ERR_MEMORY;

  handle = rocksdb_create_column_family(env->db, cf_opts, want, &err);
  if (err) {
    env_record_error(env, "create_column_family", err);
    rocksdb_free(err);
    rocksdb_options_destroy(cf_opts);
    return DB_ERR_OTHER;
  }

  cf = env_alloc_cf(env, want, handle, cf_opts);
  if (!cf) {
    rocksdb_column_family_handle_destroy(handle);
    rocksdb_options_destroy(cf_opts);
    return DB_ERR_MEMORY;
  }
  *out = cf;
  return DB_OK;
}

void db_cf_close(struct db_env *env, struct db_cf *cf)
{
  /* No-op: CF handles are owned by the env and torn down at
   * db_env_close.  Closing an individual CF would require unlinking
   * from the env list and dropping the handle, but the abstraction
   * doesn't require that — and the libmdbx backend doesn't actually
   * tear DBIs down per-call either. */
  (void)env;
  (void)cf;
}

/* -------------------------------------------------------------------- */
/* Snapshots                                                            */
/* -------------------------------------------------------------------- */

struct db_snapshot *db_snapshot_new(struct db_env *env)
{
  struct db_snapshot *s;
  if (!env || !env->db)
    return NULL;
  s = MyCalloc(1, sizeof *s);
  if (!s)
    return NULL;
  s->env = env;
  s->snap = rocksdb_create_snapshot(env->db);
  s->ropts = rocksdb_readoptions_create();
  rocksdb_readoptions_set_snapshot(s->ropts, s->snap);
  return s;
}

void db_snapshot_destroy(struct db_snapshot *s)
{
  if (!s)
    return;
  if (s->snap)
    rocksdb_release_snapshot(s->env->db, s->snap);
  if (s->ropts)
    rocksdb_readoptions_destroy(s->ropts);
  MyFree(s);
}

/* -------------------------------------------------------------------- */
/* Single-shot get                                                      */
/* -------------------------------------------------------------------- */

int db_get(struct db_env *env,
           struct db_cf *cf,
           const void *key, size_t klen,
           struct db_snapshot *snap,
           struct db_val *out)
{
  rocksdb_readoptions_t *ropts;
  char *err = NULL;
  size_t vlen = 0;
  char *vbuf;

  if (!env || !env->db || !cf || !out)
    return DB_ERR_OTHER;
  out->base = NULL;
  out->len  = 0;

  ropts = snap ? snap->ropts : env->ropts_default;
  vbuf = rocksdb_get_cf(env->db, ropts, cf->handle,
                        (const char *)key, klen, &vlen, &err);
  if (err) {
    env_record_error(env, "get", err);
    rocksdb_free(err);
    return DB_ERR_OTHER;
  }
  if (!vbuf)
    return DB_NOTFOUND;
  out->base = vbuf;
  out->len  = vlen;
  return DB_OK;
}

int db_exists(struct db_env *env,
              struct db_cf *cf,
              const void *key, size_t klen,
              struct db_snapshot *snap)
{
  struct db_val v = { NULL, 0 };
  int rc = db_get(env, cf, key, klen, snap, &v);
  if (rc == DB_OK) {
    db_val_free(&v);
    return DB_OK;
  }
  return rc;
}

/* -------------------------------------------------------------------- */
/* Write batches                                                        */
/* -------------------------------------------------------------------- */

struct db_writebatch *db_writebatch_new(struct db_env *env)
{
  struct db_writebatch *wb;
  if (!env || !env->db)
    return NULL;
  wb = MyCalloc(1, sizeof *wb);
  if (!wb)
    return NULL;
  wb->env = env;
  wb->wb = rocksdb_writebatch_create();
  return wb;
}

void db_writebatch_destroy(struct db_writebatch *wb)
{
  if (!wb)
    return;
  if (wb->wb)
    rocksdb_writebatch_destroy(wb->wb);
  MyFree(wb);
}

int db_writebatch_put(struct db_writebatch *wb,
                      struct db_cf *cf,
                      const void *key, size_t klen,
                      const void *val, size_t vlen)
{
  if (!wb || !cf)
    return DB_ERR_OTHER;
  rocksdb_writebatch_put_cf(wb->wb, cf->handle,
                            (const char *)key, klen,
                            (const char *)val, vlen);
  wb->count++;
  return DB_OK;
}

int db_writebatch_put_append(struct db_writebatch *wb,
                             struct db_cf *cf,
                             const void *key, size_t klen,
                             const void *val, size_t vlen)
{
  /* APPEND is a libmdbx hint; RocksDB's memtable handles ordered
   * inserts efficiently without it.  Forward to put. */
  return db_writebatch_put(wb, cf, key, klen, val, vlen);
}

int db_writebatch_del(struct db_writebatch *wb,
                      struct db_cf *cf,
                      const void *key, size_t klen)
{
  if (!wb || !cf)
    return DB_ERR_OTHER;
  rocksdb_writebatch_delete_cf(wb->wb, cf->handle, (const char *)key, klen);
  wb->count++;
  return DB_OK;
}

int db_writebatch_commit(struct db_writebatch *wb, int sync_durably)
{
  char *err = NULL;
  rocksdb_writeoptions_t *wopts;
  if (!wb || !wb->env || !wb->env->db)
    return DB_ERR_OTHER;
  if (wb->count == 0)
    return DB_OK;

  wopts = sync_durably ? wb->env->wopts_sync : wb->env->wopts_normal;
  rocksdb_write(wb->env->db, wopts, wb->wb, &err);
  if (err) {
    env_record_error(wb->env, "write", err);
    rocksdb_free(err);
    return DB_ERR_IO;
  }
  /* WriteBatch is usable after a successful write but contains all
   * its previous ops.  Clear it to match libmdbx's commit-clears
   * semantics so the same batch can be reused. */
  rocksdb_writebatch_clear(wb->wb);
  wb->count = 0;
  return DB_OK;
}

unsigned int db_writebatch_count(const struct db_writebatch *wb)
{
  return wb ? wb->count : 0;
}

/* -------------------------------------------------------------------- */
/* Iterators                                                            */
/* -------------------------------------------------------------------- */

struct db_iter *db_iter_open(struct db_env *env,
                             struct db_cf *cf,
                             struct db_snapshot *snap)
{
  struct db_iter *it;
  if (!env || !env->db || !cf)
    return NULL;
  it = MyCalloc(1, sizeof *it);
  if (!it)
    return NULL;
  it->env = env;
  it->cf  = cf;
  if (snap) {
    it->ropts = snap->ropts;
    it->owns_ropts = 0;
  } else {
    it->ropts = rocksdb_readoptions_create();
    it->owns_ropts = 1;
  }
  it->iter = rocksdb_create_iterator_cf(env->db, it->ropts, cf->handle);
  if (!it->iter) {
    if (it->owns_ropts) rocksdb_readoptions_destroy(it->ropts);
    MyFree(it);
    return NULL;
  }
  return it;
}

void db_iter_close(struct db_iter *it)
{
  if (!it)
    return;
  if (it->iter)
    rocksdb_iter_destroy(it->iter);
  if (it->owns_ropts && it->ropts)
    rocksdb_readoptions_destroy(it->ropts);
  MyFree(it);
}

static int iter_observe(struct db_iter *it)
{
  char *err = NULL;
  it->positioned = rocksdb_iter_valid(it->iter);
  rocksdb_iter_get_error(it->iter, &err);
  if (err) {
    env_record_error(it->env, "iter", err);
    rocksdb_free(err);
    it->positioned = 0;
    return DB_ERR_OTHER;
  }
  return it->positioned ? DB_OK : DB_NOTFOUND;
}

int db_iter_seek(struct db_iter *it, const void *key, size_t klen)
{
  if (!it) return DB_ERR_OTHER;
  rocksdb_iter_seek(it->iter, (const char *)key, klen);
  return iter_observe(it);
}

int db_iter_seek_first(struct db_iter *it)
{
  if (!it) return DB_ERR_OTHER;
  rocksdb_iter_seek_to_first(it->iter);
  return iter_observe(it);
}

int db_iter_seek_last(struct db_iter *it)
{
  if (!it) return DB_ERR_OTHER;
  rocksdb_iter_seek_to_last(it->iter);
  return iter_observe(it);
}

int db_iter_next(struct db_iter *it)
{
  if (!it) return DB_ERR_OTHER;
  rocksdb_iter_next(it->iter);
  return iter_observe(it);
}

int db_iter_prev(struct db_iter *it)
{
  if (!it) return DB_ERR_OTHER;
  rocksdb_iter_prev(it->iter);
  return iter_observe(it);
}

int db_iter_valid(const struct db_iter *it)
{
  return it ? it->positioned : 0;
}

const void *db_iter_key(const struct db_iter *it, size_t *klen)
{
  size_t l = 0;
  const char *k;
  if (!it || !it->positioned) {
    if (klen) *klen = 0;
    return NULL;
  }
  k = rocksdb_iter_key(it->iter, &l);
  if (klen) *klen = l;
  return k;
}

const void *db_iter_value(const struct db_iter *it, size_t *vlen)
{
  size_t l = 0;
  const char *v;
  if (!it || !it->positioned) {
    if (vlen) *vlen = 0;
    return NULL;
  }
  v = rocksdb_iter_value(it->iter, &l);
  if (vlen) *vlen = l;
  return v;
}

#endif /* USE_ROCKSDB */
