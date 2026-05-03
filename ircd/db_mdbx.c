/** @file db_mdbx.c
 * @brief libmdbx backend for the storage abstraction (db_env.h / db_txn.h /
 *        db_cursor.h / db_types.h).
 *
 * This is the only source-of-truth backend until phase 2 of the
 * RocksDB migration adds db_rocksdb.c.  See
 * `.claude/plans/rocksdb-migration.md`.
 *
 * Design notes:
 *  - libmdbx's MDBX_dbi handle is bound to the env, not to a txn — once
 *    opened, it stays valid for the env's lifetime.  We open it
 *    inside a one-shot txn at db_cf_open time and commit immediately.
 *  - libmdbx returns mmap pointers from cursor_get.  The iterator
 *    abstraction matches that: db_iter_key/value return pointers
 *    valid until the next iter op.  No copy.
 *  - libmdbx's mdbx_get returns mmap pointers valid until the txn
 *    commits/aborts.  db_get's contract is owned-buffer (to match
 *    RocksDB), so we memcpy out into a malloc'd buffer.  One alloc
 *    per get; acceptable.
 *  - libmdbx requires a txn for both reads and writes.  A db_writebatch
 *    lazily begins a write txn on first put/del, commits on
 *    db_writebatch_commit.  A db_snapshot begins a read txn, holds it
 *    until destroy.
 */
#include "config.h"

#include "client.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"

#include <mdbx.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/* Internal struct definitions                                          */
/* -------------------------------------------------------------------- */

struct db_env {
  MDBX_env *env;
  char     *path;
  unsigned int max_cfs;
  /* last_error is populated by helper macros on every failing call;
   * db_env_last_error returns a pointer into this buffer. */
  char     last_error[256];
};

struct db_cf {
  struct db_env *env;
  MDBX_dbi dbi;
  char    *name;
  unsigned int put_flags; /* MDBX_APPEND when append-optimised, etc. */
  int      dupsort;       /* 1 if MDBX_DUPSORT was requested */
};

struct db_snapshot {
  struct db_env *env;
  MDBX_txn      *txn;     /* read-only */
};

struct db_writebatch {
  struct db_env *env;
  MDBX_txn      *txn;     /* lazily begun on first op */
  unsigned int   count;
};

struct db_iter {
  struct db_env  *env;
  struct db_cf   *cf;
  MDBX_txn       *txn;
  MDBX_cursor    *cursor;
  int             owns_txn; /* 1: own txn, must abort on close.
                                0: borrowed from snapshot */
  /* Current position state — refreshed on every step. */
  MDBX_val        cur_key;
  MDBX_val        cur_val;
  int             positioned;
};

/* -------------------------------------------------------------------- */
/* Error tracking                                                       */
/* -------------------------------------------------------------------- */

static void env_record_error(struct db_env *env, const char *where, int rc)
{
  if (!env)
    return;
  ircd_snprintf(NULL, env->last_error, sizeof env->last_error,
                "%s: %s", where, mdbx_strerror(rc));
}

/** Map an MDBX errno to a DB_* result. */
static int translate_mdbx_rc(int rc)
{
  switch (rc) {
  case MDBX_SUCCESS:    return DB_OK;
  case MDBX_NOTFOUND:   return DB_NOTFOUND;
  case MDBX_MAP_FULL:   return DB_ERR_FULL;
  case MDBX_DBS_FULL:   return DB_ERR_FULL;
  case MDBX_TXN_FULL:   return DB_ERR_FULL;
  case MDBX_ENOMEM:     return DB_ERR_MEMORY;
  case MDBX_CORRUPTED:  return DB_ERR_CORRUPT;
  case MDBX_PAGE_CHECKSUM:
  case MDBX_PROBLEM:    return DB_ERR_CORRUPT;
  case MDBX_EIO:        return DB_ERR_IO;
  default:
    if (rc == ENOMEM) return DB_ERR_MEMORY;
    if (rc == ENOSPC) return DB_ERR_FULL;
    if (rc == EIO)    return DB_ERR_IO;
    return DB_ERR_OTHER;
  }
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

/* -------------------------------------------------------------------- */
/* db_val                                                               */
/* -------------------------------------------------------------------- */

void db_val_free(struct db_val *v)
{
  if (v && v->base) {
    MyFree(v->base);
    v->base = NULL;
    v->len  = 0;
  }
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
  unsigned int env_flags = 0;
  intptr_t size_floor, size_max, growth_step;
  int rc;

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
  env->max_cfs = max_cfs;

  rc = mdbx_env_create(&env->env);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "env_create", rc);
    log_write(LS_SYSTEM, L_ERROR, 0, "db_mdbx: %s", env->last_error);
    MyFree(env->path);
    MyFree(env);
    return translate_mdbx_rc(rc);
  }

  if (max_cfs > 0) {
    rc = mdbx_env_set_maxdbs(env->env, max_cfs);
    if (rc != MDBX_SUCCESS) {
      env_record_error(env, "env_set_maxdbs", rc);
      log_write(LS_SYSTEM, L_ERROR, 0, "db_mdbx: %s", env->last_error);
      mdbx_env_close(env->env);
      MyFree(env->path);
      MyFree(env);
      return translate_mdbx_rc(rc);
    }
  }

  /* Geometry: opts->size_max == 0 means "use a sensible default";
   * else honour both floor and max.  Negative values for libmdbx mean
   * "leave as is".  growth_step defaults to 16 MiB. */
  size_floor  = (opts && opts->size_floor) ? (intptr_t)opts->size_floor : -1;
  size_max    = (opts && opts->size_max)   ? (intptr_t)opts->size_max   : -1;
  growth_step = 16 * 1024 * 1024;
  if (size_floor != -1 || size_max != -1) {
    rc = mdbx_env_set_geometry(env->env,
                               size_floor,         /* lower */
                               -1,                 /* now */
                               size_max,           /* upper */
                               growth_step,        /* growth step */
                               growth_step,        /* shrink threshold */
                               -1);                /* page size */
    if (rc != MDBX_SUCCESS) {
      env_record_error(env, "env_set_geometry", rc);
      log_write(LS_SYSTEM, L_ERROR, 0, "db_mdbx: %s", env->last_error);
      mdbx_env_close(env->env);
      MyFree(env->path);
      MyFree(env);
      return translate_mdbx_rc(rc);
    }
  }

  /* Sync mode: if a sync_period is requested, we use SAFE_NOSYNC + the
   * periodic sync option.  Otherwise default durability. */
  if (opts && opts->sync_period_seconds)
    env_flags |= MDBX_SAFE_NOSYNC;

  /* Random-access workload hint disables read-ahead. */
  if (opts && opts->random_access)
    env_flags |= MDBX_NORDAHEAD;

  rc = mdbx_env_open(env->env, path, env_flags, 0644);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "env_open", rc);
    log_write(LS_SYSTEM, L_ERROR, 0, "db_mdbx: env_open(%s): %s",
              path, mdbx_strerror(rc));
    mdbx_env_close(env->env);
    MyFree(env->path);
    MyFree(env);
    return translate_mdbx_rc(rc);
  }

  if (opts && opts->sync_period_seconds) {
    /* MDBX_opt_sync_period is 16.16 fixed-point seconds. */
    rc = mdbx_env_set_option(env->env, MDBX_opt_sync_period,
                             (uint64_t)opts->sync_period_seconds * 65536);
    if (rc != MDBX_SUCCESS)
      log_write(LS_SYSTEM, L_WARNING, 0,
                "db_mdbx: env_set_option(sync_period) failed: %s",
                mdbx_strerror(rc));
  }

  *out = env;
  return DB_OK;
}

void db_env_close(struct db_env *env)
{
  if (!env)
    return;
  if (env->env)
    mdbx_env_close(env->env);
  if (env->path)
    MyFree(env->path);
  MyFree(env);
}

int db_env_sync(struct db_env *env)
{
  int rc;
  if (!env || !env->env)
    return DB_ERR_OTHER;
  rc = mdbx_env_sync_ex(env->env, /*force=*/1, /*nonblock=*/0);
  if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
    env_record_error(env, "env_sync", rc);
    return translate_mdbx_rc(rc);
  }
  return DB_OK;
}

int db_env_compact(struct db_env *env, struct db_cf *cf)
{
  int rc;
  (void)cf; /* libmdbx defrag is env-wide, not per-DBI */
  if (!env || !env->env)
    return DB_ERR_OTHER;
  rc = mdbx_env_defrag(env->env, /*pages_to_move=*/0);
  if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
    env_record_error(env, "env_defrag", rc);
    return translate_mdbx_rc(rc);
  }
  return DB_OK;
}

int db_env_warmup(struct db_env *env)
{
  int rc;
  if (!env || !env->env)
    return DB_ERR_OTHER;
  rc = mdbx_env_warmup(env->env, NULL, MDBX_warmup_default, 0);
  if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
    env_record_error(env, "env_warmup", rc);
    return translate_mdbx_rc(rc);
  }
  return DB_OK;
}

int db_env_reap_dead_readers(struct db_env *env)
{
  int dead = 0;
  int rc;
  if (!env || !env->env)
    return DB_ERR_OTHER;
  rc = mdbx_reader_check(env->env, &dead);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "reader_check", rc);
    return translate_mdbx_rc(rc);
  }
  return DB_OK;
}

int db_env_stats(struct db_env *env, struct db_env_stats *out)
{
  MDBX_envinfo info;
  MDBX_stat    stat;
  int rc;

  if (!env || !env->env || !out)
    return DB_ERR_OTHER;
  memset(out, 0, sizeof *out);

  rc = mdbx_env_info_ex(env->env, NULL, &info, sizeof info);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "env_info_ex", rc);
    return translate_mdbx_rc(rc);
  }
  rc = mdbx_env_stat_ex(env->env, NULL, &stat, sizeof stat);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "env_stat_ex", rc);
    return translate_mdbx_rc(rc);
  }

  out->on_disk_bytes  = info.mi_geo.current;
  out->approx_keys_total = stat.ms_entries;
  out->active_readers = info.mi_numreaders;
  /* pending_compaction, level0_files: RocksDB-only, leave 0 */
  return DB_OK;
}

int db_cf_stats(struct db_env *env, struct db_cf *cf, struct db_cf_stats *out)
{
  MDBX_txn *txn = NULL;
  MDBX_stat stat;
  int rc;

  if (!env || !env->env || !cf || !out)
    return DB_ERR_OTHER;
  memset(out, 0, sizeof *out);

  rc = mdbx_txn_begin(env->env, NULL, MDBX_TXN_RDONLY, &txn);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "txn_begin(stats)", rc);
    return translate_mdbx_rc(rc);
  }
  rc = mdbx_dbi_stat(txn, cf->dbi, &stat, sizeof stat);
  mdbx_txn_abort(txn);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "dbi_stat", rc);
    return translate_mdbx_rc(rc);
  }

  out->approx_keys = stat.ms_entries;
  out->depth       = stat.ms_depth;
  /* on_disk_bytes for a single DBI is hard to compute exactly in libmdbx;
   * approximate as branch+leaf+overflow pages times page size. */
  out->on_disk_bytes = (size_t)(stat.ms_branch_pages
                              + stat.ms_leaf_pages
                              + stat.ms_overflow_pages)
                     * stat.ms_psize;
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
  MDBX_txn *txn = NULL;
  unsigned int dbi_flags = MDBX_CREATE;
  int rc;

  assert(out);
  *out = NULL;
  if (!env || !env->env)
    return DB_ERR_OTHER;

  cf = MyCalloc(1, sizeof *cf);
  if (!cf)
    return DB_ERR_MEMORY;
  cf->env = env;

  if (name && *name) {
    cf->name = MyMalloc(strlen(name) + 1);
    if (!cf->name) {
      MyFree(cf);
      return DB_ERR_MEMORY;
    }
    strcpy(cf->name, name);
  }

  if (opts && opts->dupsort) {
    dbi_flags |= MDBX_DUPSORT;
    cf->dupsort = 1;
  }
  if (opts && opts->append_optimised)
    cf->put_flags |= MDBX_APPEND;

  rc = mdbx_txn_begin(env->env, NULL, 0, &txn);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "txn_begin(cf_open)", rc);
    if (cf->name) MyFree(cf->name);
    MyFree(cf);
    return translate_mdbx_rc(rc);
  }
  rc = mdbx_dbi_open(txn, name, dbi_flags, &cf->dbi);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "dbi_open", rc);
    mdbx_txn_abort(txn);
    if (cf->name) MyFree(cf->name);
    MyFree(cf);
    return translate_mdbx_rc(rc);
  }
  rc = mdbx_txn_commit(txn);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "txn_commit(cf_open)", rc);
    if (cf->name) MyFree(cf->name);
    MyFree(cf);
    return translate_mdbx_rc(rc);
  }

  *out = cf;
  return DB_OK;
}

void db_cf_close(struct db_env *env, struct db_cf *cf)
{
  if (!cf)
    return;
  if (env && env->env)
    mdbx_dbi_close(env->env, cf->dbi);
  if (cf->name)
    MyFree(cf->name);
  MyFree(cf);
}

/* -------------------------------------------------------------------- */
/* Snapshots (read-only txns)                                           */
/* -------------------------------------------------------------------- */

struct db_snapshot *db_snapshot_new(struct db_env *env)
{
  struct db_snapshot *s;
  int rc;
  if (!env || !env->env)
    return NULL;
  s = MyCalloc(1, sizeof *s);
  if (!s)
    return NULL;
  s->env = env;
  rc = mdbx_txn_begin(env->env, NULL, MDBX_TXN_RDONLY, &s->txn);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "txn_begin(snapshot)", rc);
    MyFree(s);
    return NULL;
  }
  return s;
}

void db_snapshot_destroy(struct db_snapshot *s)
{
  if (!s)
    return;
  if (s->txn)
    mdbx_txn_abort(s->txn);
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
  MDBX_txn *txn = NULL;
  int       owns_txn = 0;
  MDBX_val  k = { (void *)key, klen };
  MDBX_val  v;
  int       rc;

  if (!env || !env->env || !cf || !out)
    return DB_ERR_OTHER;
  out->base = NULL;
  out->len  = 0;

  if (snap) {
    txn = snap->txn;
  } else {
    rc = mdbx_txn_begin(env->env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS) {
      env_record_error(env, "txn_begin(get)", rc);
      return translate_mdbx_rc(rc);
    }
    owns_txn = 1;
  }

  rc = mdbx_get(txn, cf->dbi, &k, &v);
  if (rc == MDBX_SUCCESS) {
    /* Copy out into a heap buffer the caller owns. */
    out->base = MyMalloc(v.iov_len);
    if (!out->base) {
      if (owns_txn) mdbx_txn_abort(txn);
      return DB_ERR_MEMORY;
    }
    memcpy(out->base, v.iov_base, v.iov_len);
    out->len = v.iov_len;
    if (owns_txn) mdbx_txn_abort(txn);
    return DB_OK;
  }

  if (owns_txn) mdbx_txn_abort(txn);
  if (rc == MDBX_NOTFOUND)
    return DB_NOTFOUND;
  env_record_error(env, "get", rc);
  return translate_mdbx_rc(rc);
}

int db_exists(struct db_env *env,
              struct db_cf *cf,
              const void *key, size_t klen,
              struct db_snapshot *snap)
{
  MDBX_txn *txn = NULL;
  int       owns_txn = 0;
  MDBX_val  k = { (void *)key, klen };
  MDBX_val  v;
  int       rc;

  if (!env || !env->env || !cf)
    return DB_ERR_OTHER;

  if (snap) {
    txn = snap->txn;
  } else {
    rc = mdbx_txn_begin(env->env, NULL, MDBX_TXN_RDONLY, &txn);
    if (rc != MDBX_SUCCESS) {
      env_record_error(env, "txn_begin(exists)", rc);
      return translate_mdbx_rc(rc);
    }
    owns_txn = 1;
  }

  rc = mdbx_get(txn, cf->dbi, &k, &v);
  if (owns_txn) mdbx_txn_abort(txn);
  if (rc == MDBX_SUCCESS) return DB_OK;
  if (rc == MDBX_NOTFOUND) return DB_NOTFOUND;
  env_record_error(env, "exists", rc);
  return translate_mdbx_rc(rc);
}

/* -------------------------------------------------------------------- */
/* Write batches                                                        */
/* -------------------------------------------------------------------- */

struct db_writebatch *db_writebatch_new(struct db_env *env)
{
  struct db_writebatch *wb;
  if (!env || !env->env)
    return NULL;
  wb = MyCalloc(1, sizeof *wb);
  if (!wb)
    return NULL;
  wb->env = env;
  /* txn lazily begun on first op */
  return wb;
}

static int wb_lazy_begin(struct db_writebatch *wb)
{
  int rc;
  if (wb->txn)
    return DB_OK;
  rc = mdbx_txn_begin(wb->env->env, NULL, 0, &wb->txn);
  if (rc != MDBX_SUCCESS) {
    env_record_error(wb->env, "txn_begin(write)", rc);
    return translate_mdbx_rc(rc);
  }
  return DB_OK;
}

void db_writebatch_destroy(struct db_writebatch *wb)
{
  if (!wb)
    return;
  if (wb->txn)
    mdbx_txn_abort(wb->txn);
  MyFree(wb);
}

int db_writebatch_put(struct db_writebatch *wb,
                      struct db_cf *cf,
                      const void *key, size_t klen,
                      const void *val, size_t vlen)
{
  MDBX_val k, v;
  int rc;
  if (!wb || !cf)
    return DB_ERR_OTHER;
  rc = wb_lazy_begin(wb);
  if (rc != DB_OK)
    return rc;
  k.iov_base = (void *)key; k.iov_len = klen;
  v.iov_base = (void *)val; v.iov_len = vlen;
  rc = mdbx_put(wb->txn, cf->dbi, &k, &v, cf->put_flags);
  if (rc != MDBX_SUCCESS) {
    env_record_error(wb->env, "put", rc);
    return translate_mdbx_rc(rc);
  }
  wb->count++;
  return DB_OK;
}

int db_writebatch_put_append(struct db_writebatch *wb,
                             struct db_cf *cf,
                             const void *key, size_t klen,
                             const void *val, size_t vlen)
{
  MDBX_val k, v;
  int rc;
  if (!wb || !cf)
    return DB_ERR_OTHER;
  rc = wb_lazy_begin(wb);
  if (rc != DB_OK)
    return rc;
  k.iov_base = (void *)key; k.iov_len = klen;
  v.iov_base = (void *)val; v.iov_len = vlen;
  rc = mdbx_put(wb->txn, cf->dbi, &k, &v, cf->put_flags | MDBX_APPEND);
  if (rc != MDBX_SUCCESS) {
    env_record_error(wb->env, "put(append)", rc);
    return translate_mdbx_rc(rc);
  }
  wb->count++;
  return DB_OK;
}

int db_writebatch_del(struct db_writebatch *wb,
                      struct db_cf *cf,
                      const void *key, size_t klen)
{
  MDBX_val k;
  int rc;
  if (!wb || !cf)
    return DB_ERR_OTHER;
  rc = wb_lazy_begin(wb);
  if (rc != DB_OK)
    return rc;
  k.iov_base = (void *)key; k.iov_len = klen;
  rc = mdbx_del(wb->txn, cf->dbi, &k, NULL);
  if (rc != MDBX_SUCCESS && rc != MDBX_NOTFOUND) {
    env_record_error(wb->env, "del", rc);
    return translate_mdbx_rc(rc);
  }
  wb->count++;
  return DB_OK;
}

int db_writebatch_commit(struct db_writebatch *wb, int sync_durably)
{
  int rc;
  if (!wb)
    return DB_ERR_OTHER;
  /* Empty batch: nothing to commit, no-op. */
  if (!wb->txn) {
    wb->count = 0;
    return DB_OK;
  }
  rc = mdbx_txn_commit(wb->txn);
  wb->txn = NULL;
  if (rc != MDBX_SUCCESS) {
    env_record_error(wb->env, "txn_commit", rc);
    return translate_mdbx_rc(rc);
  }
  if (sync_durably) {
    rc = mdbx_env_sync_ex(wb->env->env, /*force=*/1, /*nonblock=*/0);
    if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE) {
      env_record_error(wb->env, "env_sync(commit)", rc);
      return translate_mdbx_rc(rc);
    }
  }
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
  int rc;

  if (!env || !env->env || !cf)
    return NULL;
  it = MyCalloc(1, sizeof *it);
  if (!it)
    return NULL;
  it->env = env;
  it->cf  = cf;

  if (snap) {
    it->txn = snap->txn;
    it->owns_txn = 0;
  } else {
    rc = mdbx_txn_begin(env->env, NULL, MDBX_TXN_RDONLY, &it->txn);
    if (rc != MDBX_SUCCESS) {
      env_record_error(env, "txn_begin(iter)", rc);
      MyFree(it);
      return NULL;
    }
    it->owns_txn = 1;
  }

  rc = mdbx_cursor_open(it->txn, cf->dbi, &it->cursor);
  if (rc != MDBX_SUCCESS) {
    env_record_error(env, "cursor_open", rc);
    if (it->owns_txn) mdbx_txn_abort(it->txn);
    MyFree(it);
    return NULL;
  }
  return it;
}

void db_iter_close(struct db_iter *it)
{
  if (!it)
    return;
  if (it->cursor)
    mdbx_cursor_close(it->cursor);
  if (it->owns_txn && it->txn)
    mdbx_txn_abort(it->txn);
  MyFree(it);
}

static int iter_step(struct db_iter *it, MDBX_cursor_op op)
{
  int rc = mdbx_cursor_get(it->cursor, &it->cur_key, &it->cur_val, op);
  if (rc == MDBX_SUCCESS) {
    it->positioned = 1;
    return DB_OK;
  }
  it->positioned = 0;
  if (rc == MDBX_NOTFOUND)
    return DB_NOTFOUND;
  env_record_error(it->env, "cursor_get", rc);
  return translate_mdbx_rc(rc);
}

int db_iter_seek(struct db_iter *it, const void *key, size_t klen)
{
  if (!it)
    return DB_ERR_OTHER;
  it->cur_key.iov_base = (void *)key;
  it->cur_key.iov_len  = klen;
  return iter_step(it, MDBX_SET_RANGE);
}

int db_iter_seek_first(struct db_iter *it)
{
  return it ? iter_step(it, MDBX_FIRST) : DB_ERR_OTHER;
}

int db_iter_seek_last(struct db_iter *it)
{
  return it ? iter_step(it, MDBX_LAST) : DB_ERR_OTHER;
}

int db_iter_next(struct db_iter *it)
{
  return it ? iter_step(it, MDBX_NEXT) : DB_ERR_OTHER;
}

int db_iter_prev(struct db_iter *it)
{
  return it ? iter_step(it, MDBX_PREV) : DB_ERR_OTHER;
}

int db_iter_valid(const struct db_iter *it)
{
  return it ? it->positioned : 0;
}

const void *db_iter_key(const struct db_iter *it, size_t *klen)
{
  if (!it || !it->positioned) {
    if (klen) *klen = 0;
    return NULL;
  }
  if (klen) *klen = it->cur_key.iov_len;
  return it->cur_key.iov_base;
}

const void *db_iter_value(const struct db_iter *it, size_t *vlen)
{
  if (!it || !it->positioned) {
    if (vlen) *vlen = 0;
    return NULL;
  }
  if (vlen) *vlen = it->cur_val.iov_len;
  return it->cur_val.iov_base;
}
