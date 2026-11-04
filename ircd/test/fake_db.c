/** @file fake_db.c
 * @brief In-memory fake backend for the storage API -- see fake_db.h.
 *
 * Follows the pattern of the narrower fake in
 * ircd/test/db_casefold_cmocka.c (sorted rows per CF, snapshot-at-open
 * iterators, ordered write batches), extended to the full db_cursor.h/
 * db_txn.h surface plus db_delete_range/db_suggest_compact, so it can
 * be linked against the SAME test source as the real RocksDB backend
 * (db_api_cmocka.c) without the fake drifting from what RocksDB does.
 *
 * A delete leaves a tombstone, as RocksDB does: the row stays in its
 * place in the sorted array, marked dead, until fake_db_drop_tombstones
 * (the fake's compaction).  Lookups and iterators skip dead rows; an
 * iterator opened with db_iter_open_bounded_limited counts the ones one
 * positioning call steps over and returns DB_INCOMPLETE past its cap
 * (RocksDB's max_skippable_internal_keys).
 */
#include "config.h"

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "fake_db.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------- */
/* Internal struct definitions                                          */
/* -------------------------------------------------------------------- */

struct row {
  char  *k;
  size_t kl;
  char  *v;
  size_t vl;
  int    dead;   /* a tombstone: deleted, not yet compacted away */
};

#define FAKE_MAX_CFS 16

struct db_cf {
  char        name[64];
  struct row *rows;
  size_t      n;
  size_t      cap;

  unsigned int iter_opens;
  unsigned int seek_firsts;
  unsigned int seek_lasts;
  unsigned int suggest_calls;
  unsigned int flush_calls;
  unsigned int busy_imm, busy_l0;   /* fake_db_set_busy */
  int          has_last_suggest;
  char        *last_start;   /* NULL if the call's start was NULL */
  size_t       last_slen;
  char        *last_end;     /* NULL if the call's end was NULL */
  size_t       last_elen;
  char        *iter_lower;   /* the last db_iter_open_bounded's lower bound */
  size_t       iter_llen;    /* (NULL/0: none, or an unbounded open) */
};

struct db_env {
  struct db_cf cfs[FAKE_MAX_CFS];
  size_t       ncf;
  unsigned int fail_commit_in;   /* the commit that many from now fails */
  int          fail_next_op;
  int          fail_next_iter;
  int          fail_next_flush;
  unsigned int fail_get_in;      /* the db_get that many from now fails */
  char         last_error[128];
};

struct db_snapshot {
  int dummy;   /* fake iterators copy at open regardless; nothing to pin */
};

struct db_iter {
  struct db_cf *cf;          /* for the seek-direction counters */
  struct row *snap;
  size_t      n;
  size_t      pos;
  int         positioned;
  unsigned long long max_skip;   /* 0 = no cap on dead rows stepped over */
};

struct op {
  int           del;
  struct db_cf *cf;
  char         *k;
  size_t        kl;
  char         *v;
  size_t        vl;
};

struct db_writebatch {
  struct db_env *env;
  struct op     *ops;
  size_t         n;
  size_t         cap;
};

/* -------------------------------------------------------------------- */
/* Byte-string helpers (sorted-row CF storage)                          */
/* -------------------------------------------------------------------- */

static char *dup_bytes(const void *p, size_t n)
{
  char *d = malloc(n ? n : 1);
  if (n)
    memcpy(d, p, n);
  return d;
}

static int bytes_cmp(const char *a, size_t al, const char *b, size_t bl)
{
  size_t n = al < bl ? al : bl;
  int c = memcmp(a, b, n);
  if (c)
    return c;
  return (al > bl) - (al < bl);
}

/** Index of the first row >= key; *found set when it is an exact match. */
static size_t cf_lower_bound(const struct db_cf *cf, const char *k, size_t kl,
                             int *found)
{
  size_t lo = 0, hi = cf->n;
  *found = 0;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = bytes_cmp(cf->rows[mid].k, cf->rows[mid].kl, k, kl);
    if (c < 0)
      lo = mid + 1;
    else
      hi = mid;
  }
  if (lo < cf->n && bytes_cmp(cf->rows[lo].k, cf->rows[lo].kl, k, kl) == 0)
    *found = 1;
  return lo;
}

static struct row *cf_find(const struct db_cf *cf, const char *k, size_t kl)
{
  int found;
  size_t i = cf_lower_bound(cf, k, kl, &found);
  return found && !cf->rows[i].dead ? &cf->rows[i] : NULL;
}

static void cf_put(struct db_cf *cf, const char *k, size_t kl,
                   const char *v, size_t vl)
{
  int found;
  size_t i = cf_lower_bound(cf, k, kl, &found);
  if (found) {                  /* a live row, or a tombstone it covers */
    free(cf->rows[i].v);
    cf->rows[i].v = dup_bytes(v, vl);
    cf->rows[i].vl = vl;
    cf->rows[i].dead = 0;
    return;
  }
  if (cf->n == cf->cap) {
    cf->cap = cf->cap ? cf->cap * 2 : 16;
    cf->rows = realloc(cf->rows, cf->cap * sizeof(*cf->rows));
  }
  memmove(&cf->rows[i + 1], &cf->rows[i], (cf->n - i) * sizeof(*cf->rows));
  cf->rows[i].k = dup_bytes(k, kl);
  cf->rows[i].kl = kl;
  cf->rows[i].v = dup_bytes(v, vl);
  cf->rows[i].vl = vl;
  cf->rows[i].dead = 0;
  cf->n++;
}

static void row_kill(struct row *r)
{
  free(r->v);
  r->v = NULL;
  r->vl = 0;
  r->dead = 1;
}

/* A delete leaves a tombstone where the key sorts, whether or not a row
 * was there (as RocksDB writes one). */
static void cf_del(struct db_cf *cf, const char *k, size_t kl)
{
  int found;
  size_t i = cf_lower_bound(cf, k, kl, &found);
  if (found) {
    row_kill(&cf->rows[i]);
    return;
  }
  cf_put(cf, k, kl, "", 0);
  row_kill(&cf->rows[i]);
}

/* Delete every row in [start,end) (lo/hi are cf_lower_bound indices,
 * i.e. the same half-open convention as the public db_delete_range). */
static void cf_del_range(struct db_cf *cf, size_t lo, size_t hi)
{
  size_t i;
  for (i = lo; i < hi; i++)
    if (!cf->rows[i].dead)
      row_kill(&cf->rows[i]);
}

/* -------------------------------------------------------------------- */
/* fake_db_* test control surface                                       */
/* -------------------------------------------------------------------- */

struct db_env *fake_db_new(void)
{
  return calloc(1, sizeof(struct db_env));
}

void fake_db_free(struct db_env *env)
{
  size_t i, j;
  if (!env)
    return;
  for (i = 0; i < env->ncf; i++) {
    struct db_cf *cf = &env->cfs[i];
    for (j = 0; j < cf->n; j++) {
      free(cf->rows[j].k);
      free(cf->rows[j].v);
    }
    free(cf->rows);
    free(cf->last_start);
    free(cf->last_end);
    free(cf->iter_lower);
  }
  free(env);
}

void fake_db_fail_next_commit(struct db_env *env)
{
  if (env)
    env->fail_commit_in = 1;
}

void fake_db_fail_commit_at(struct db_env *env, unsigned int n)
{
  if (env)
    env->fail_commit_in = n;
}

void fake_db_fail_next_batch_op(struct db_env *env)
{
  if (env)
    env->fail_next_op = 1;
}

void fake_db_fail_next_iter_open(struct db_env *env)
{
  if (env)
    env->fail_next_iter = 1;
}

void fake_db_fail_get_at(struct db_env *env, unsigned int n)
{
  if (env)
    env->fail_get_in = n;
}

unsigned int fake_db_seek_firsts(const struct db_cf *cf)
{
  return cf ? cf->seek_firsts : 0;
}

unsigned int fake_db_seek_lasts(const struct db_cf *cf)
{
  return cf ? cf->seek_lasts : 0;
}

unsigned int fake_db_iter_opens(const struct db_cf *cf)
{
  return cf ? cf->iter_opens : 0;
}

unsigned int fake_db_suggest_calls(const struct db_cf *cf)
{
  return cf ? cf->suggest_calls : 0;
}

unsigned int fake_db_flush_calls(const struct db_cf *cf)
{
  return cf ? cf->flush_calls : 0;
}

size_t fake_db_tombstones(const struct db_cf *cf)
{
  size_t i, n = 0;
  if (!cf)
    return 0;
  for (i = 0; i < cf->n; i++)
    n += cf->rows[i].dead != 0;
  return n;
}

void fake_db_drop_tombstones(struct db_cf *cf)
{
  size_t i, o = 0;
  if (!cf)
    return;
  for (i = 0; i < cf->n; i++) {
    if (cf->rows[i].dead) {
      free(cf->rows[i].k);
      free(cf->rows[i].v);
    } else
      cf->rows[o++] = cf->rows[i];
  }
  cf->n = o;
}

int fake_db_last_suggest(const struct db_cf *cf,
                         const void **start, size_t *slen,
                         const void **end, size_t *elen)
{
  if (!cf || !cf->has_last_suggest)
    return DB_NOTFOUND;
  if (start) *start = cf->last_start;
  if (slen)  *slen  = cf->last_slen;
  if (end)   *end   = cf->last_end;
  if (elen)  *elen  = cf->last_elen;
  return DB_OK;
}

void fake_db_last_iter_lower(const struct db_cf *cf, const void **lower, size_t *llen)
{
  if (lower) *lower = cf ? cf->iter_lower : NULL;
  if (llen)  *llen  = cf ? cf->iter_llen : 0;
}

size_t fake_db_rows(const struct db_cf *cf)
{
  return cf ? cf->n - fake_db_tombstones(cf) : 0;
}

/* -------------------------------------------------------------------- */
/* db_env.h -- db_cf_open/db_env_last_error are real; the rest are not  */
/* meaningful without an on-disk env (build with fake_db_new instead).  */
/* -------------------------------------------------------------------- */

int db_env_open(const char *path, const struct db_env_opts *opts,
                unsigned int max_cfs, struct db_env **out)
{
  (void)path;
  (void)opts;
  (void)max_cfs;
  if (out)
    *out = NULL;
  return DB_ERR_OTHER;
}

void db_env_close(struct db_env *env)
{
  (void)env;
}

int db_env_sync(struct db_env *env)
{
  (void)env;
  return DB_ERR_OTHER;
}

int db_env_compact(struct db_env *env, struct db_cf *cf)
{
  (void)env;
  (void)cf;
  return DB_ERR_OTHER;
}

int db_env_warmup(struct db_env *env)
{
  (void)env;
  return DB_ERR_OTHER;
}

int db_env_stats(struct db_env *env, struct db_env_stats *out)
{
  (void)env;
  (void)out;
  return DB_ERR_OTHER;
}

/* approx_keys = live rows; mem_deletes = tombstones (the fake has no
 * flush: they stay until fake_db_drop_tombstones). */
int db_cf_stats(struct db_env *env, struct db_cf *cf, struct db_cf_stats *out)
{
  (void)env;
  if (!cf || !out)
    return DB_ERR_OTHER;
  memset(out, 0, sizeof *out);
  out->approx_keys = fake_db_rows(cf);
  out->mem_deletes = fake_db_tombstones(cf);
  out->imm_memtables = cf->busy_imm;
  out->l0_files = cf->busy_l0;
  out->depth = cf->busy_l0;
  out->max_write_buffers = 2;          /* RocksDB's defaults */
  out->l0_slowdown_trigger = 20;
  return DB_OK;
}

int db_flush_cf(struct db_env *env, struct db_cf *cf, int wait)
{
  (void)wait;
  if (!cf)
    return DB_ERR_OTHER;
  cf->flush_calls++;
  if (env && env->fail_next_flush) {
    env->fail_next_flush = 0;
    snprintf(env->last_error, sizeof env->last_error,
             "fake_db: forced flush failure (fake_db_fail_next_flush)");
    return DB_ERR_IO;
  }
  return DB_OK;
}

void fake_db_set_busy(struct db_cf *cf, unsigned int imm_memtables,
                      unsigned int l0_files)
{
  if (!cf)
    return;
  cf->busy_imm = imm_memtables;
  cf->busy_l0 = l0_files;
}

void fake_db_fail_next_flush(struct db_env *env)
{
  if (env)
    env->fail_next_flush = 1;
}

int db_cf_open(struct db_env *env, const char *name,
               const struct db_cf_opts *opts, struct db_cf **out)
{
  const char *want = (name && *name) ? name : "default";
  size_t i;
  (void)opts;
  if (!out)
    return DB_ERR_OTHER;
  *out = NULL;
  if (!env)
    return DB_ERR_OTHER;
  for (i = 0; i < env->ncf; i++) {
    if (strcmp(env->cfs[i].name, want) == 0) {
      *out = &env->cfs[i];
      return DB_OK;
    }
  }
  if (env->ncf == FAKE_MAX_CFS)
    return DB_ERR_OTHER;
  snprintf(env->cfs[env->ncf].name, sizeof(env->cfs[env->ncf].name), "%s", want);
  *out = &env->cfs[env->ncf++];
  return DB_OK;
}

const char *db_env_last_error(struct db_env *env)
{
  return (env && env->last_error[0]) ? env->last_error : NULL;
}

/* -------------------------------------------------------------------- */
/* db_delete_range / db_suggest_compact                                 */
/* -------------------------------------------------------------------- */

int db_delete_range(struct db_env *env, struct db_cf *cf,
                    const void *start, size_t slen,
                    const void *end, size_t elen)
{
  int found;
  size_t lo, hi;
  (void)env;
  if (!cf)
    return DB_ERR_OTHER;
  lo = cf_lower_bound(cf, (const char *)start, slen, &found);
  hi = cf_lower_bound(cf, (const char *)end, elen, &found);
  cf_del_range(cf, lo, hi);
  return DB_OK;
}

int db_suggest_compact(struct db_env *env, struct db_cf *cf,
                       const void *start, size_t slen,
                       const void *end, size_t elen)
{
  (void)env;
  if (!cf)
    return DB_ERR_OTHER;
  cf->suggest_calls++;
  free(cf->last_start);
  free(cf->last_end);
  cf->last_start = NULL;
  cf->last_end   = NULL;
  cf->last_slen  = 0;
  cf->last_elen  = 0;
  if (start && slen) {
    cf->last_start = dup_bytes(start, slen);
    cf->last_slen  = slen;
  }
  if (end && elen) {
    cf->last_end = dup_bytes(end, elen);
    cf->last_elen = elen;
  }
  cf->has_last_suggest = 1;
  return DB_OK;
}

/* -------------------------------------------------------------------- */
/* db_cursor.h -- iterators                                             */
/* -------------------------------------------------------------------- */

static struct db_iter *iter_from_range(struct db_cf *cf, size_t lo, size_t hi)
{
  struct db_iter *it = calloc(1, sizeof(*it));
  size_t i, n = (hi > lo) ? (hi - lo) : 0;
  it->cf = cf;
  it->n = n;
  it->snap = calloc(n ? n : 1, sizeof(*it->snap));
  for (i = 0; i < n; i++) {
    struct row *r = &cf->rows[lo + i];
    it->snap[i].k = dup_bytes(r->k, r->kl);
    it->snap[i].kl = r->kl;
    it->snap[i].v = dup_bytes(r->v, r->vl);
    it->snap[i].vl = r->vl;
    it->snap[i].dead = r->dead;
  }
  return it;
}

/** From it->pos, step forward over tombstones to a live row. */
static int iter_settle_fwd(struct db_iter *it)
{
  unsigned long long skipped = 0;
  while (it->pos < it->n && it->snap[it->pos].dead) {
    it->pos++;
    if (it->max_skip && ++skipped > it->max_skip) {
      it->positioned = 0;
      return DB_INCOMPLETE;
    }
  }
  it->positioned = (it->pos < it->n);
  return it->positioned ? DB_OK : DB_NOTFOUND;
}

/** The live row at or before index @a from - 1, stepping back over
 * tombstones (@a from = one past the first candidate). */
static int iter_settle_back(struct db_iter *it, size_t from)
{
  unsigned long long skipped = 0;
  while (from > 0 && it->snap[from - 1].dead) {
    from--;
    if (it->max_skip && ++skipped > it->max_skip) {
      it->positioned = 0;
      return DB_INCOMPLETE;
    }
  }
  if (from == 0) {
    it->positioned = 0;
    return DB_NOTFOUND;
  }
  it->pos = from - 1;
  it->positioned = 1;
  return DB_OK;
}

struct db_iter *db_iter_open(struct db_env *env, struct db_cf *cf,
                             struct db_snapshot *snap)
{
  struct db_iter *it;
  (void)snap;
  if (!cf)
    return NULL;
  if (env && env->fail_next_iter) {
    env->fail_next_iter = 0;
    return NULL;
  }
  it = iter_from_range(cf, 0, cf->n);
  cf->iter_opens++;
  return it;
}

struct db_iter *db_iter_open_bounded(struct db_env *env, struct db_cf *cf,
                                     struct db_snapshot *snap,
                                     const void *lower, size_t llen,
                                     const void *upper, size_t ulen)
{
  return db_iter_open_bounded_limited(env, cf, snap, lower, llen, upper, ulen, 0);
}

struct db_iter *db_iter_open_bounded_limited(struct db_env *env, struct db_cf *cf,
                                             struct db_snapshot *snap,
                                             const void *lower, size_t llen,
                                             const void *upper, size_t ulen,
                                             unsigned long long max_skip)
{
  struct db_iter *it;
  size_t lo, hi;
  int found;
  (void)snap;
  if (!cf)
    return NULL;
  if (env && env->fail_next_iter) {
    env->fail_next_iter = 0;
    return NULL;
  }
  lo = (lower && llen) ? cf_lower_bound(cf, (const char *)lower, llen, &found) : 0;
  hi = (upper && ulen) ? cf_lower_bound(cf, (const char *)upper, ulen, &found) : cf->n;
  it = iter_from_range(cf, lo, hi);
  it->max_skip = max_skip;
  cf->iter_opens++;
  free(cf->iter_lower);
  cf->iter_lower = (lower && llen) ? dup_bytes(lower, llen) : NULL;
  cf->iter_llen  = cf->iter_lower ? llen : 0;
  return it;
}

void db_iter_close(struct db_iter *it)
{
  size_t i;
  if (!it)
    return;
  for (i = 0; i < it->n; i++) {
    free(it->snap[i].k);
    free(it->snap[i].v);
  }
  free(it->snap);
  free(it);
}

/* Bounded iterators are pre-filtered to their range at open (see
 * iter_from_range), so a plain lower_bound search within the already-
 * filtered snapshot gives the same "a seek below lower lands on
 * lower" clamping db_iter_open_bounded documents, with no extra
 * bookkeeping. */
int db_iter_seek(struct db_iter *it, const void *key, size_t klen)
{
  size_t lo, hi;
  if (!it)
    return DB_ERR_OTHER;
  lo = 0;
  hi = it->n;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int c = bytes_cmp(it->snap[mid].k, it->snap[mid].kl, (const char *)key, klen);
    if (c < 0)
      lo = mid + 1;
    else
      hi = mid;
  }
  it->pos = lo;
  return iter_settle_fwd(it);
}

int db_iter_seek_first(struct db_iter *it)
{
  if (!it)
    return DB_ERR_OTHER;
  if (it->cf)
    it->cf->seek_firsts++;
  it->pos = 0;
  return iter_settle_fwd(it);
}

int db_iter_seek_last(struct db_iter *it)
{
  if (!it)
    return DB_ERR_OTHER;
  if (it->cf)
    it->cf->seek_lasts++;
  return iter_settle_back(it, it->n);
}

int db_iter_next(struct db_iter *it)
{
  if (!it)
    return DB_ERR_OTHER;
  if (it->pos < it->n)
    it->pos++;
  return iter_settle_fwd(it);
}

int db_iter_prev(struct db_iter *it)
{
  if (!it)
    return DB_ERR_OTHER;
  if (!it->positioned || it->pos == 0) {
    it->positioned = 0;
    return DB_NOTFOUND;
  }
  return iter_settle_back(it, it->pos);
}

int db_iter_valid(const struct db_iter *it)
{
  return it && it->positioned && it->pos < it->n;
}

const void *db_iter_key(const struct db_iter *it, size_t *klen)
{
  if (!db_iter_valid(it)) {
    if (klen) *klen = 0;
    return NULL;
  }
  if (klen) *klen = it->snap[it->pos].kl;
  return it->snap[it->pos].k;
}

const void *db_iter_value(const struct db_iter *it, size_t *vlen)
{
  if (!db_iter_valid(it)) {
    if (vlen) *vlen = 0;
    return NULL;
  }
  if (vlen) *vlen = it->snap[it->pos].vl;
  return it->snap[it->pos].v;
}

/* -------------------------------------------------------------------- */
/* db_txn.h -- write batches, snapshots, single-shot get                */
/* -------------------------------------------------------------------- */

struct db_writebatch *db_writebatch_new(struct db_env *env)
{
  struct db_writebatch *wb = calloc(1, sizeof(*wb));
  wb->env = env;
  return wb;
}

/** One-shot staging failure (fake_db_fail_next_batch_op). */
static int wb_op_fails(struct db_writebatch *wb)
{
  if (wb && wb->env && wb->env->fail_next_op) {
    wb->env->fail_next_op = 0;
    return 1;
  }
  return 0;
}

static struct op *wb_push(struct db_writebatch *wb)
{
  if (wb->n == wb->cap) {
    wb->cap = wb->cap ? wb->cap * 2 : 64;
    wb->ops = realloc(wb->ops, wb->cap * sizeof(*wb->ops));
  }
  memset(&wb->ops[wb->n], 0, sizeof(wb->ops[wb->n]));
  return &wb->ops[wb->n++];
}

int db_writebatch_put(struct db_writebatch *wb, struct db_cf *cf,
                      const void *key, size_t klen,
                      const void *val, size_t vlen)
{
  struct op *o;
  if (wb_op_fails(wb))
    return DB_ERR_MEMORY;
  o = wb_push(wb);
  o->cf = cf;
  o->k = dup_bytes(key, klen);
  o->kl = klen;
  o->v = dup_bytes(val, vlen);
  o->vl = vlen;
  return DB_OK;
}

int db_writebatch_put_append(struct db_writebatch *wb, struct db_cf *cf,
                             const void *key, size_t klen,
                             const void *val, size_t vlen)
{
  /* APPEND is an ordering hint only; the fake keeps rows sorted
   * regardless. */
  return db_writebatch_put(wb, cf, key, klen, val, vlen);
}

int db_writebatch_del(struct db_writebatch *wb, struct db_cf *cf,
                      const void *key, size_t klen)
{
  struct op *o;
  if (wb_op_fails(wb))
    return DB_ERR_MEMORY;
  o = wb_push(wb);
  o->del = 1;
  o->cf = cf;
  o->k = dup_bytes(key, klen);
  o->kl = klen;
  return DB_OK;
}

static void wb_clear(struct db_writebatch *wb)
{
  size_t i;
  for (i = 0; i < wb->n; i++) {
    free(wb->ops[i].k);
    free(wb->ops[i].v);
  }
  wb->n = 0;
}

int db_writebatch_commit(struct db_writebatch *wb, int sync_durably)
{
  size_t i;
  (void)sync_durably;
  if (!wb)
    return DB_ERR_OTHER;
  if (wb->env && wb->env->fail_commit_in
      && --wb->env->fail_commit_in == 0) {
    snprintf(wb->env->last_error, sizeof wb->env->last_error,
             "fake_db: forced commit failure (fake_db_fail_next_commit)");
    wb_clear(wb);
    return DB_ERR_IO;
  }
  for (i = 0; i < wb->n; i++) {
    struct op *o = &wb->ops[i];
    if (o->del)
      cf_del(o->cf, o->k, o->kl);
    else
      cf_put(o->cf, o->k, o->kl, o->v, o->vl);
  }
  wb_clear(wb);
  return DB_OK;
}

void db_writebatch_destroy(struct db_writebatch *wb)
{
  if (!wb)
    return;
  wb_clear(wb);
  free(wb->ops);
  free(wb);
}

unsigned int db_writebatch_count(const struct db_writebatch *wb)
{
  return wb ? (unsigned int)wb->n : 0;
}

struct db_snapshot *db_snapshot_new(struct db_env *env)
{
  struct db_snapshot *s = calloc(1, sizeof(*s));
  (void)env;
  return s;
}

void db_snapshot_destroy(struct db_snapshot *s)
{
  free(s);
}

int db_get(struct db_env *env, struct db_cf *cf,
           const void *key, size_t klen, struct db_snapshot *snap,
           struct db_val *out)
{
  struct row *r;
  (void)snap;
  if (!cf || !out)
    return DB_ERR_OTHER;
  if (env && env->fail_get_in && --env->fail_get_in == 0)
    return DB_ERR_IO;
  r = cf_find(cf, (const char *)key, klen);
  if (!r)
    return DB_NOTFOUND;
  out->base = dup_bytes(r->v, r->vl);
  out->len = r->vl;
  return DB_OK;
}

int db_exists(struct db_env *env, struct db_cf *cf,
              const void *key, size_t klen, struct db_snapshot *snap)
{
  (void)env;
  (void)snap;
  if (!cf)
    return DB_ERR_OTHER;
  return cf_find(cf, (const char *)key, klen) ? DB_OK : DB_NOTFOUND;
}

/* -------------------------------------------------------------------- */
/* db_types.h -- db_val_free (amendment: db_casefold.o needs it when    */
/* linked alongside this fake in a future suite)                        */
/* -------------------------------------------------------------------- */

void db_val_free(struct db_val *v)
{
  if (!v)
    return;
  free(v->base);
  v->base = NULL;
  v->len = 0;
}
