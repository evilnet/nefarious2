/*
 * db_casefold_cmocka.c - key folding and the one-time key rewrite
 *
 * The store under the rewrite is a small in-memory fake defined here:
 * sorted rows per column family, iterators that read a copy taken at
 * open (snapshot semantics), write batches applied in order at commit.
 * Only db_casefold.o and the casemapping table are linked; no RocksDB.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "db_casefold.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"

/* ------------------------------------------------------------------ */
/* Fake store                                                          */
/* ------------------------------------------------------------------ */

struct row {
  char  *k;
  size_t kl;
  char  *v;
  size_t vl;
};

struct db_cf {
  char        name[32];
  struct row *rows;
  size_t      n;
  size_t      cap;
};

#define FAKE_MAX_CFS 8

struct db_env {
  struct db_cf cfs[FAKE_MAX_CFS];
  size_t       ncf;
};

struct db_iter {
  struct row *snap;
  size_t      n;
  size_t      pos;
  int         positioned;
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
  return found ? &cf->rows[i] : NULL;
}

static void cf_put(struct db_cf *cf, const char *k, size_t kl,
                   const char *v, size_t vl)
{
  int found;
  size_t i = cf_lower_bound(cf, k, kl, &found);
  if (found) {
    free(cf->rows[i].v);
    cf->rows[i].v = dup_bytes(v, vl);
    cf->rows[i].vl = vl;
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
  cf->n++;
}

static void cf_del(struct db_cf *cf, const char *k, size_t kl)
{
  int found;
  size_t i = cf_lower_bound(cf, k, kl, &found);
  if (!found)
    return;
  free(cf->rows[i].k);
  free(cf->rows[i].v);
  memmove(&cf->rows[i], &cf->rows[i + 1], (cf->n - i - 1) * sizeof(*cf->rows));
  cf->n--;
}

int db_cf_open(struct db_env *env, const char *name,
               const struct db_cf_opts *opts, struct db_cf **out)
{
  const char *want = (name && *name) ? name : "default";
  size_t i;
  (void)opts;
  *out = NULL;
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

struct db_iter *db_iter_open(struct db_env *env, struct db_cf *cf,
                             struct db_snapshot *snap)
{
  struct db_iter *it = calloc(1, sizeof(*it));
  size_t i;
  (void)env;
  (void)snap;
  it->n = cf->n;
  it->snap = calloc(cf->n ? cf->n : 1, sizeof(*it->snap));
  for (i = 0; i < cf->n; i++) {
    it->snap[i].k = dup_bytes(cf->rows[i].k, cf->rows[i].kl);
    it->snap[i].kl = cf->rows[i].kl;
    it->snap[i].v = dup_bytes(cf->rows[i].v, cf->rows[i].vl);
    it->snap[i].vl = cf->rows[i].vl;
  }
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

int db_iter_seek_first(struct db_iter *it)
{
  it->pos = 0;
  it->positioned = 1;
  return it->n ? DB_OK : DB_NOTFOUND;
}

int db_iter_next(struct db_iter *it)
{
  if (it->pos < it->n)
    it->pos++;
  return it->pos < it->n ? DB_OK : DB_NOTFOUND;
}

int db_iter_valid(const struct db_iter *it)
{
  return it && it->positioned && it->pos < it->n;
}

const void *db_iter_key(const struct db_iter *it, size_t *klen)
{
  if (!db_iter_valid(it))
    return NULL;
  *klen = it->snap[it->pos].kl;
  return it->snap[it->pos].k;
}

const void *db_iter_value(const struct db_iter *it, size_t *vlen)
{
  if (!db_iter_valid(it))
    return NULL;
  *vlen = it->snap[it->pos].vl;
  return it->snap[it->pos].v;
}

int db_exists(struct db_env *env, struct db_cf *cf,
              const void *key, size_t klen, struct db_snapshot *snap)
{
  (void)env;
  (void)snap;
  return cf_find(cf, key, klen) ? DB_OK : DB_NOTFOUND;
}

int db_get(struct db_env *env, struct db_cf *cf,
           const void *key, size_t klen, struct db_snapshot *snap,
           struct db_val *out)
{
  struct row *r;
  (void)env;
  (void)snap;
  r = cf_find(cf, key, klen);
  if (!r)
    return DB_NOTFOUND;
  out->base = dup_bytes(r->v, r->vl);
  out->len = r->vl;
  return DB_OK;
}

void db_val_free(struct db_val *v)
{
  if (!v)
    return;
  free(v->base);
  v->base = NULL;
  v->len = 0;
}

struct db_writebatch *db_writebatch_new(struct db_env *env)
{
  struct db_writebatch *wb = calloc(1, sizeof(*wb));
  wb->env = env;
  return wb;
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
  struct op *o = wb_push(wb);
  o->cf = cf;
  o->k = dup_bytes(key, klen);
  o->kl = klen;
  o->v = dup_bytes(val, vlen);
  o->vl = vlen;
  return DB_OK;
}

int db_writebatch_del(struct db_writebatch *wb, struct db_cf *cf,
                      const void *key, size_t klen)
{
  struct op *o = wb_push(wb);
  o->del = 1;
  o->cf = cf;
  o->k = dup_bytes(key, klen);
  o->kl = klen;
  return DB_OK;
}

unsigned int db_writebatch_count(const struct db_writebatch *wb)
{
  return (unsigned int)wb->n;
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

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

/** A string literal as (pointer, length) with embedded NULs kept. */
#define B(lit) lit, (sizeof(lit) - 1)

static struct db_env *env_new(void)
{
  return calloc(1, sizeof(struct db_env));
}

static void env_free(struct db_env *env)
{
  size_t i, j;
  for (i = 0; i < env->ncf; i++) {
    for (j = 0; j < env->cfs[i].n; j++) {
      free(env->cfs[i].rows[j].k);
      free(env->cfs[i].rows[j].v);
    }
    free(env->cfs[i].rows);
  }
  free(env);
}

static struct db_cf *cf_of(struct db_env *env, const char *name)
{
  struct db_cf *cf = NULL;
  assert_int_equal(db_cf_open(env, name, NULL, &cf), DB_OK);
  return cf;
}

static void seed(struct db_cf *cf, const char *k, size_t kl, const char *v)
{
  cf_put(cf, k, kl, v, strlen(v));
}

static void assert_row(struct db_cf *cf, const char *k, size_t kl,
                       const char *v)
{
  struct row *r = cf_find(cf, k, kl);
  assert_non_null(r);
  assert_int_equal(r->vl, strlen(v));
  assert_memory_equal(r->v, v, r->vl);
}

static void assert_no_row(struct db_cf *cf, const char *k, size_t kl)
{
  assert_null(cf_find(cf, k, kl));
}

static int marker_set(struct db_env *env)
{
  struct db_cf *dflt = cf_of(env, "default");
  return cf_find(dflt, B("schema/casefold")) != NULL;
}

/* ------------------------------------------------------------------ */
/* db_casefold_key                                                     */
/* ------------------------------------------------------------------ */

static void fold_key_first_component_only(void **state)
{
  char out[64];
  int n;
  (void)state;

  n = db_casefold_key(1u, B("#Linux\0T1.500\0MsgID"), out, sizeof(out));
  assert_int_equal(n, (int)(sizeof("#Linux\0T1.500\0MsgID") - 1));
  assert_memory_equal(out, "#linux\0T1.500\0MsgID", (size_t)n);
}

static void fold_key_all_components(void **state)
{
  char out[64];
  int n;
  (void)state;

  n = db_casefold_key(DB_CASEFOLD_ALL, B("Acct\0Draft/Key"), out, sizeof(out));
  assert_int_equal(n, (int)(sizeof("Acct\0Draft/Key") - 1));
  assert_memory_equal(out, "acct\0draft/key", (size_t)n);
}

static void fold_key_second_component_only(void **state)
{
  char out[64];
  int n;
  (void)state;

  /* msgid index: "msgid\0target" folds the target and keeps the msgid. */
  n = db_casefold_key(2u, B("MsgID\0#Linux"), out, sizeof(out));
  assert_int_equal(n, (int)(sizeof("MsgID\0#Linux") - 1));
  assert_memory_equal(out, "MsgID\0#linux", (size_t)n);

  /* A legacy bare msgid has no second component: untouched. */
  n = db_casefold_key(2u, B("MsgID"), out, sizeof(out));
  assert_int_equal(n, 5);
  assert_memory_equal(out, "MsgID", 5);
}

static void fold_key_rfc1459_brackets(void **state)
{
  char out[64];
  int n;
  (void)state;

  /* rfc1459 casemapping as the ircd's table has it: "[]\^" are the
   * upper-case forms of "{}|~", so a key spelled with either set folds
   * to the lower-case set. */
  n = db_casefold_key(1u, B("#Fold[X]\\~^"), out, sizeof(out));
  assert_int_equal(n, (int)(sizeof("#Fold[X]\\~^") - 1));
  assert_memory_equal(out, "#fold{x}|~~", (size_t)n);
}

static void fold_key_high_bytes_are_stable(void **state)
{
  /* UTF-8 bytes above 127 must index the casemapping table in range
   * and fold to a fixed point: folding twice equals folding once. */
  const char key[] = "#caf\xc3\xa9\x80\xff\0Z";
  char once[64], twice[64];
  int n1, n2;
  (void)state;

  n1 = db_casefold_key(1u, key, sizeof(key) - 1, once, sizeof(once));
  assert_int_equal(n1, (int)(sizeof(key) - 1));
  n2 = db_casefold_key(1u, once, (size_t)n1, twice, sizeof(twice));
  assert_int_equal(n2, n1);
  assert_memory_equal(once, twice, (size_t)n1);
  /* The unfolded component after the separator is untouched. */
  assert_int_equal(once[n1 - 1], 'Z');
}

static void fold_key_rejects_small_buffer(void **state)
{
  char out[4];
  (void)state;

  assert_int_equal(db_casefold_key(1u, B("#Linux"), out, sizeof(out)), -1);
}

/* ------------------------------------------------------------------ */
/* db_casefold_migrate                                                 */
/* ------------------------------------------------------------------ */

static void migrate_moves_unfolded_rows(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *msgs = cf_of(env, "messages");
  struct db_casefold_cf cfs[] = { { NULL, "messages", 1u } };
  (void)state;
  cfs[0].cf = msgs;

  seed(msgs, B("#Linux\0100.000\0M1"), "one");
  seed(msgs, B("#linux\0200.000\0M2"), "two");
  seed(msgs, B("#Fold[X]\0300.000\0M3"), "three");

  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);

  assert_int_equal(msgs->n, 3);
  assert_row(msgs, B("#linux\0100.000\0M1"), "one");
  assert_row(msgs, B("#linux\0200.000\0M2"), "two");
  assert_row(msgs, B("#fold{x}\0300.000\0M3"), "three");
  assert_no_row(msgs, B("#Linux\0100.000\0M1"));
  assert_no_row(msgs, B("#Fold[X]\0300.000\0M3"));
  assert_true(marker_set(env));

  env_free(env);
}

static void migrate_keeps_existing_folded_row_on_collision(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *meta = cf_of(env, "metadata");
  struct db_casefold_cf cfs[] = { { NULL, "metadata", DB_CASEFOLD_ALL } };
  (void)state;
  cfs[0].cf = meta;

  seed(meta, B("bob\0avatar"), "keep");
  seed(meta, B("Bob\0avatar"), "drop");
  seed(meta, B("Bob\0color"), "moved");

  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);

  assert_int_equal(meta->n, 2);
  assert_row(meta, B("bob\0avatar"), "keep");
  assert_row(meta, B("bob\0color"), "moved");
  assert_no_row(meta, B("Bob\0avatar"));
  assert_no_row(meta, B("Bob\0color"));

  env_free(env);
}

static void migrate_folds_only_masked_components(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *idx = cf_of(env, "msgid_index");
  struct db_casefold_cf cfs[] = { { NULL, "msgid_index", 2u } };
  (void)state;
  cfs[0].cf = idx;

  seed(idx, B("MsgA\0#Linux"), "100.000");
  seed(idx, B("MsgA"), "#Linux\0100.000");   /* legacy: bare msgid key */

  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);

  assert_int_equal(idx->n, 2);
  assert_row(idx, B("MsgA\0#linux"), "100.000");
  /* The msgid keeps its case; the legacy row's key and value are as written. */
  {
    struct row *r = cf_find(idx, B("MsgA"));
    assert_non_null(r);
    assert_int_equal(r->vl, sizeof("#Linux\0100.000") - 1);
    assert_memory_equal(r->v, "#Linux\0100.000", r->vl);
  }
  assert_no_row(idx, B("MsgA\0#Linux"));
  assert_no_row(idx, B("msga\0#linux"));

  env_free(env);
}

static void migrate_runs_once_per_env(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *tg = cf_of(env, "targets");
  struct db_casefold_cf cfs[] = { { NULL, "targets", DB_CASEFOLD_ALL } };
  (void)state;
  cfs[0].cf = tg;

  seed(tg, B("#First"), "1");
  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);
  assert_row(tg, B("#first"), "1");
  assert_true(marker_set(env));

  /* A row written unfolded after the marker is left alone: the
   * builders fold now, so the rewrite must not run again. */
  seed(tg, B("#Second"), "2");
  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);
  assert_row(tg, B("#Second"), "2");
  assert_no_row(tg, B("#second"));

  env_free(env);
}

static void migrate_handles_more_rows_than_one_batch(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *msgs = cf_of(env, "messages");
  struct db_casefold_cf cfs[] = { { NULL, "messages", 1u } };
  char key[64];
  int i, n;
  (void)state;
  cfs[0].cf = msgs;

  /* 1300 rows -> 2600 staged ops: three commits of the 512-op batch. */
  for (i = 0; i < 1300; i++) {
    n = snprintf(key, sizeof(key), "#Chan%04d", i);
    key[n] = '\0';
    memcpy(key + n + 1, "ts", 2);
    seed(msgs, key, (size_t)n + 3, "v");
  }

  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);

  assert_int_equal(msgs->n, 1300);
  for (i = 0; i < 1300; i++) {
    n = snprintf(key, sizeof(key), "#chan%04d", i);
    key[n] = '\0';
    memcpy(key + n + 1, "ts", 2);
    assert_row(msgs, key, (size_t)n + 3, "v");
  }
  assert_true(marker_set(env));

  env_free(env);
}

static void migrate_walks_every_cf_in_one_call(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *quotas = cf_of(env, "quotas");
  struct db_cf *reply = cf_of(env, "reply_index");
  struct db_casefold_cf cfs[] = {
    { NULL, "quotas", 3u },
    { NULL, "missing", 1u },   /* a CF that is not open is skipped */
    { NULL, "reply_index", 1u },
  };
  (void)state;
  cfs[0].cf = quotas;
  cfs[2].cf = reply;

  seed(quotas, B("#Chan\0Alice"), "7");
  seed(reply, B("#Chan\0ParentID\0100.000\0ChildID"), "");

  assert_int_equal(db_casefold_migrate(env, "t", cfs, 3), 0);

  assert_row(quotas, B("#chan\0alice"), "7");
  assert_no_row(quotas, B("#Chan\0Alice"));
  assert_row(reply, B("#chan\0ParentID\0100.000\0ChildID"), "");
  assert_no_row(reply, B("#Chan\0ParentID\0100.000\0ChildID"));
  assert_true(marker_set(env));

  env_free(env);
}

static void migrate_empty_store_only_sets_marker(void **state)
{
  struct db_env *env = env_new();
  struct db_cf *msgs = cf_of(env, "messages");
  struct db_casefold_cf cfs[] = { { NULL, "messages", 1u } };
  (void)state;
  cfs[0].cf = msgs;

  assert_int_equal(db_casefold_migrate(env, "t", cfs, 1), 0);
  assert_int_equal(msgs->n, 0);
  assert_true(marker_set(env));

  env_free(env);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(fold_key_first_component_only),
    cmocka_unit_test(fold_key_all_components),
    cmocka_unit_test(fold_key_second_component_only),
    cmocka_unit_test(fold_key_rfc1459_brackets),
    cmocka_unit_test(fold_key_high_bytes_are_stable),
    cmocka_unit_test(fold_key_rejects_small_buffer),
    cmocka_unit_test(migrate_moves_unfolded_rows),
    cmocka_unit_test(migrate_keeps_existing_folded_row_on_collision),
    cmocka_unit_test(migrate_folds_only_masked_components),
    cmocka_unit_test(migrate_runs_once_per_env),
    cmocka_unit_test(migrate_handles_more_rows_than_one_batch),
    cmocka_unit_test(migrate_walks_every_cf_in_one_call),
    cmocka_unit_test(migrate_empty_store_only_sets_marker),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
