/*
 * IRC - Internet Relay Chat, ircd/metadata_prereg.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/metadata_prereg.h.  Keep this file free of ircd headers:
 * it is compiled standalone for the cmocka suite.
 */
#include "metadata_prereg.h"

#include <string.h>

/** Keys compare without regard to ASCII letter case.  A key is letters,
 * digits and - _ . / (m_metadata.c is_valid_key()), where the ircd's
 * casemapping (ircd_strcmp()) folds exactly the ASCII letters. */
static int key_eq(const char *a, const char *b)
{
  for (; *a && *b; a++, b++) {
    char x = *a, y = *b;

    if (x >= 'A' && x <= 'Z')
      x += 'a' - 'A';
    if (y >= 'A' && y <= 'Z')
      y += 'a' - 'A';
    if (x != y)
      return 0;
  }
  return *a == *b;
}

int md_prereg_should_merge(int logged_in, int metadata_aware)
{
  return logged_in && metadata_aware;
}

enum md_prereg_verdict md_prereg_decide(const struct md_version *stored,
                                        const struct md_version *w,
                                        int no_row_is_state,
                                        int *user_keys, int max_keys,
                                        size_t max_value_bytes)
{
  int stored_live = stored && !stored->tombstone;

  if (max_keys < 0)
    max_keys = 0;

  if (w->tombstone) {
    if (stored_live) {
      /* A delete of a key the account holds. */
      if (!md_lww_take(stored, w))
        return MD_PREREG_SUPERSEDED;
      (*user_keys)--;
      return MD_PREREG_APPLY;
    }
    if (stored)
      /* Deleted here already: the row and the peers take the SET's stamp
       * when it is the newer (md_lww_take: newer stamp; two tombstones of
       * one stamp keep the existing). */
      return md_lww_take(stored, w) ? MD_PREREG_STAMP : MD_PREREG_ABSENT;
    /* No row here: a peer may hold one this server missed.  For a key
     * whose absence is a state of its own, the tombstone also changes
     * the account's connections (their default mode turned off). */
    return no_row_is_state ? MD_PREREG_APPLY : MD_PREREG_STAMP;
  }

  /* The value limit first, as a SET checks it before anything else: a
   * value over it (lowered by a rehash since the SET) is refused even when
   * the account holds the same one -- re-stamped and sent, it would go to
   * peers whose limit refuses it too. */
  if (w->vlen > max_value_bytes)
    return MD_PREREG_LIMIT_VALUE;

  /* The same value at the same visibility: nothing changes on this server;
   * the row still takes the SET's stamp when it is the newer (STAMP). */
  if (stored_live && stored->vis == w->vis && stored->vlen == w->vlen
      && (w->vlen == 0 || !memcmp(stored->value, w->value, w->vlen)))
    return md_lww_take(stored, w) ? MD_PREREG_STAMP : MD_PREREG_SAME;

  /* A write made after the client's SET (its stamp the newer) stands. */
  if (stored && !md_lww_take(stored, w))
    return MD_PREREG_SUPERSEDED;

  /* A new live key needs a place; an update of one the account holds
   * does not (as metadata_check_limits() rules for a SET). */
  if (!stored_live) {
    if (*user_keys >= max_keys)
      return MD_PREREG_LIMIT_KEYS;
    (*user_keys)++;
  }
  return MD_PREREG_APPLY;
}

int md_prereg_merge(const struct MetadataPrereg *list, int user_keys,
                    int max_keys, size_t max_value_bytes,
                    const struct md_prereg_ops *ops, void *ctx)
{
  const struct MetadataPrereg *n;
  int applied = 0;

  for (n = list; n; n = n->next) {
    struct md_version w, stored;
    char valbuf[MD_PREREG_VALUE_LEN];
    enum md_prereg_verdict v;
    int rc = 1;

    w.st = n->st;
    w.tombstone = (n->value == NULL);
    w.vis = n->visibility;
    w.value = n->value;
    w.vlen = n->value ? strlen(n->value) : 0;

    if (ops->row && (rc = ops->row(ctx, n->key, &stored, valbuf,
                                   sizeof(valbuf))) < 0) {
      ops->refuse(ctx, n->key, MD_PREREG_ERROR);
      continue;
    }
    v = md_prereg_decide(rc == 0 ? &stored : NULL, &w,
                         ops->no_row_is_state
                           && ops->no_row_is_state(ctx, n->key),
                         &user_keys, max_keys, max_value_bytes);
    switch (v) {
    case MD_PREREG_APPLY:
    case MD_PREREG_STAMP:
      break;
    case MD_PREREG_LIMIT_KEYS:
    case MD_PREREG_LIMIT_VALUE:
      ops->refuse(ctx, n->key, v);
      continue;
    default:
      continue;         /* SAME, ABSENT, SUPERSEDED: the row stands */
    }

    if (ops->store) {
      /* The store merges by the same LWW rule the decision just applied
       * to the same row, so it takes the write: a store that keeps its own
       * row (0) disagrees with what it was read as, and the write is lost
       * -- reported like a store error, as a SET's failed write is. */
      rc = ops->store(ctx, n->key, &w);
      if (rc != 1) {
        ops->refuse(ctx, n->key, MD_PREREG_ERROR);
        continue;
      }
    }
    if (v == MD_PREREG_APPLY) {
      ops->apply(ctx, n->key, &w);
      applied++;
    }
    ops->send(ctx, n->key, &w);
  }
  return applied;
}

/** Count @a list's notes by kind, leaving out the one for @a except. */
static void count_notes(const struct MetadataPrereg *list, const char *except,
                        int *sets, int *deletes)
{
  *sets = *deletes = 0;
  for (; list; list = list->next) {
    if (except && key_eq(list->key, except))
      continue;
    if (list->value)
      (*sets)++;
    else
      (*deletes)++;
  }
}

int md_prereg_fits(const struct MetadataPrereg *list, const char *key,
                   int is_delete, int max_keys)
{
  int sets, deletes;

  if (max_keys < 0)
    max_keys = 0;
  count_notes(list, key, &sets, &deletes);
  return (is_delete ? deletes : sets) < max_keys;
}

int md_prereg_deletes_fit(const struct MetadataPrereg *list,
                          const char *const *keys, int n, int max_keys)
{
  const struct MetadataPrereg *p;
  int deletes = n, i;

  if (max_keys < 0)
    max_keys = 0;
  /* The deletes noted for keys other than these, plus one per key. */
  for (p = list; p; p = p->next) {
    if (p->value)
      continue;
    for (i = 0; i < n; i++)
      if (key_eq(p->key, keys[i]))
        break;
    if (i == n)
      deletes++;
  }
  return deletes <= max_keys;
}
