/*
 * IRC - Internet Relay Chat, ircd/pm_pair_index.c
 * Copyright (C) 2026 Nefarious Development Team
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
 * @brief The PM pairs each identity takes part in (pm_pair_index.h).
 */
#include "config.h"

#include "pm_pair_index.h"
#include "db_casefold.h"
#include "db_cursor.h"
#include "db_txn.h"
#include "db_types.h"

#include <string.h>

int pm_pair_split(const char *pair, size_t len, size_t *colon)
{
  const char *c;

  if (!pair || len < 3 || pair[0] == '#' || pair[0] == '&')
    return -1;
  c = memchr(pair, ':', len);
  if (!c || c == pair || (size_t)(c - pair) + 1 >= len)
    return -1;
  if (memchr(c + 1, ':', len - (size_t)(c - pair) - 1))
    return -1;
  if (memchr(pair, '\0', len))
    return -1;
  if (colon)
    *colon = (size_t)(c - pair);
  return 0;
}

int pm_pair_index_key(char *out, size_t outsz, const char *identity, size_t ilen,
                      const char *pair, size_t plen)
{
  if (!out || ilen == 0 || ilen + 1 + plen > outsz)
    return -1;
  db_casefold_bytes(out, identity, ilen);
  out[ilen] = '\0';
  db_casefold_bytes(out + ilen + 1, pair, plen);
  return (int)(ilen + 1 + plen);
}

/** Stage a put (@a del 0) or a delete of the pair's two rows. */
static int pair_rows(struct db_writebatch *wb, struct db_cf *idx,
                     const char *pair, size_t plen, int del)
{
  char key[PM_PAIR_INDEX_KEYLEN];
  size_t colon;
  int half, n;

  if (!wb || !idx || pm_pair_split(pair, plen, &colon) != 0)
    return -1;
  for (half = 0; half < 2; half++) {
    const char *id = half ? pair + colon + 1 : pair;
    size_t ilen = half ? plen - colon - 1 : colon;
    n = pm_pair_index_key(key, sizeof key, id, ilen, pair, plen);
    if (n < 0)
      return -1;
    if ((del ? db_writebatch_del(wb, idx, key, (size_t)n)
             : db_writebatch_put(wb, idx, key, (size_t)n, "1", 1)) != DB_OK)
      return -1;
  }
  return 0;
}

int pm_pair_index_stage(struct db_writebatch *wb, struct db_cf *idx,
                        const char *pair, size_t plen)
{
  return pair_rows(wb, idx, pair, plen, 0);
}

int pm_pair_index_unstage(struct db_writebatch *wb, struct db_cf *idx,
                          const char *pair, size_t plen)
{
  return pair_rows(wb, idx, pair, plen, 1);
}

int pm_pair_index_walk(struct db_env *env, struct db_cf *idx,
                       const char *identity, pm_pair_fn fn, void *ctx)
{
  char lower[PM_PAIR_INDEX_KEYLEN], upper[PM_PAIR_INDEX_KEYLEN];
  struct db_iter *it;
  size_t ilen;
  int rc, n = 0;

  if (!env || !idx || !identity || !fn)
    return -1;
  ilen = strlen(identity);
  if (ilen == 0 || ilen + 1 > sizeof lower)
    return 0;
  /* [ "<identity>\0", "<identity>\1" ): exactly this identity's rows. */
  db_casefold_bytes(lower, identity, ilen);
  lower[ilen] = '\0';
  memcpy(upper, lower, ilen);
  upper[ilen] = '\1';
  it = db_iter_open_bounded(env, idx, NULL, lower, ilen + 1, upper, ilen + 1);
  if (!it)
    return -1;
  for (rc = db_iter_seek_first(it); rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen;
    const char *k = (const char *)db_iter_key(it, &klen);
    if (!k || klen <= ilen + 1)
      continue;
    n++;
    if (fn(k + ilen + 1, klen - ilen - 1, ctx))
      break;
  }
  db_iter_close(it);
  if (rc != DB_OK && rc != DB_NOTFOUND)
    return -1;
  return n;
}

/** A write batch that commits itself every PM_PAIR_INDEX_BATCH rows. */
struct rb_batch {
  struct db_env *env;
  struct db_writebatch *wb;
  int failed;
};

static int rb_flush(struct rb_batch *b)
{
  if (b->failed)
    return -1;
  if (b->wb && db_writebatch_count(b->wb) > 0
      && db_writebatch_commit(b->wb, 0) != DB_OK) {
    b->failed = 1;
    return -1;
  }
  return 0;
}

static struct db_writebatch *rb_wb(struct rb_batch *b)
{
  if (b->failed)
    return NULL;
  if (b->wb && db_writebatch_count(b->wb) >= PM_PAIR_INDEX_BATCH) {
    if (rb_flush(b) != 0)
      return NULL;
    /* A committed batch is empty and reusable (db_txn.h); a fresh one
     * after a failure is never needed: the rebuild stops. */
  }
  if (!b->wb && !(b->wb = db_writebatch_new(b->env)))
    b->failed = 1;
  return b->wb;
}

int pm_pair_index_rebuild(struct db_env *env, struct db_cf *targets,
                          struct db_cf *idx)
{
  struct rb_batch b;
  struct db_iter *it;
  int rc;

  if (!env || !targets || !idx)
    return -1;
  memset(&b, 0, sizeof b);
  b.env = env;

  /* 1. Orphans: an index row whose pair key has no targets row, or whose
   *    identity is neither half of that pair. */
  it = db_iter_open(env, idx, NULL);
  if (!it)
    return -1;
  for (rc = db_iter_seek_first(it); rc == DB_OK && db_iter_valid(it) && !b.failed;
       rc = db_iter_next(it)) {
    size_t klen, ilen, plen, colon;
    const char *k = (const char *)db_iter_key(it, &klen);
    const char *sep, *pair;
    int keep = 0;
    if (!k || !klen)
      continue;
    sep = memchr(k, '\0', klen);
    if (sep) {
      ilen = (size_t)(sep - k);
      pair = sep + 1;
      plen = klen - ilen - 1;
      if (ilen && pm_pair_split(pair, plen, &colon) == 0
          && ((ilen == colon && !memcmp(k, pair, ilen))
              || (ilen == plen - colon - 1 && !memcmp(k, pair + colon + 1, ilen)))) {
        int e = db_exists(env, targets, pair, plen, NULL);
        if (e == DB_OK)
          keep = 1;
        else if (e != DB_NOTFOUND) {
          b.failed = 1;   /* cannot tell: stop, the next open retries */
          break;
        }
      }
    }
    if (!keep) {
      struct db_writebatch *wb = rb_wb(&b);
      if (!wb || db_writebatch_del(wb, idx, k, klen) != DB_OK)
        b.failed = 1;
    }
  }
  db_iter_close(it);
  if (b.failed || (rc != DB_OK && rc != DB_NOTFOUND)) {
    db_writebatch_destroy(b.wb);
    return -1;
  }

  /* 2. Missing rows: a row under each half of every pair key in targets. */
  it = db_iter_open(env, targets, NULL);
  if (!it) {
    db_writebatch_destroy(b.wb);
    return -1;
  }
  for (rc = db_iter_seek_first(it); rc == DB_OK && db_iter_valid(it) && !b.failed;
       rc = db_iter_next(it)) {
    size_t klen, colon;
    const char *k = (const char *)db_iter_key(it, &klen);
    int half;
    if (!k || pm_pair_split(k, klen, &colon) != 0)
      continue;
    for (half = 0; half < 2 && !b.failed; half++) {
      char key[PM_PAIR_INDEX_KEYLEN];
      const char *id = half ? k + colon + 1 : k;
      size_t ilen = half ? klen - colon - 1 : colon;
      int n = pm_pair_index_key(key, sizeof key, id, ilen, k, klen);
      int e;
      if (n < 0)
        continue;   /* longer than any identity: not ours to index */
      e = db_exists(env, idx, key, (size_t)n, NULL);
      if (e == DB_OK)
        continue;
      if (e != DB_NOTFOUND) {
        b.failed = 1;
        break;
      }
      {
        struct db_writebatch *wb = rb_wb(&b);
        if (!wb || db_writebatch_put(wb, idx, key, (size_t)n, "1", 1) != DB_OK)
          b.failed = 1;
      }
    }
  }
  db_iter_close(it);
  if (!b.failed && (rc == DB_OK || rc == DB_NOTFOUND))
    rb_flush(&b);
  else
    b.failed = 1;
  db_writebatch_destroy(b.wb);
  return b.failed ? -1 : 0;
}
