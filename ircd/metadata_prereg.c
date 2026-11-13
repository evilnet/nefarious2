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

/** md_prereg_merge()'s state across the writes. */
struct merge_state {
  const struct md_prereg_ops *ops;
  void *ctx;
  int user_keys;
  int max_keys;
  size_t max_value_bytes;
  int applied;
  struct md_stamp clear_st;   /* the CLEAR's stamp, for clear_one() */
};

/** One write @a w of @a key: decide, then store, tell and send. */
static void merge_one(struct merge_state *m, const char *key,
                      const struct md_version *w)
{
  const struct md_prereg_ops *ops = m->ops;
  struct md_version stored;
  char valbuf[MD_PREREG_VALUE_LEN];
  enum md_prereg_verdict v;
  int rc = 1;

  if (ops->row && (rc = ops->row(m->ctx, key, &stored, valbuf,
                                 sizeof(valbuf))) < 0) {
    ops->refuse(m->ctx, key, MD_PREREG_ERROR);
    return;
  }
  v = md_prereg_decide(rc == 0 ? &stored : NULL, w,
                       ops->no_row_is_state
                         && ops->no_row_is_state(m->ctx, key),
                       &m->user_keys, m->max_keys, m->max_value_bytes);
  switch (v) {
  case MD_PREREG_APPLY:
  case MD_PREREG_STAMP:
    break;
  case MD_PREREG_LIMIT_KEYS:
  case MD_PREREG_LIMIT_VALUE:
    ops->refuse(m->ctx, key, v);
    return;
  default:
    return;             /* SAME, ABSENT, SUPERSEDED: the row stands */
  }

  if (ops->store) {
    /* The store merges by the same LWW rule the decision just applied
     * to the same row, so it takes the write: a store that keeps its own
     * row (0) disagrees with what it was read as, and the write is lost
     * -- reported like a store error, as a SET's failed write is. */
    rc = ops->store(m->ctx, key, w);
    if (rc != 1) {
      ops->refuse(m->ctx, key, MD_PREREG_ERROR);
      return;
    }
  }
  if (v == MD_PREREG_APPLY) {
    ops->apply(m->ctx, key, w);
    m->applied++;
  }
  ops->send(m->ctx, key, w);
}

/** A CLEAR's delete of one of the account's keys, under the CLEAR's
 * stamp, the key's own visibility (it scopes the notification). */
static void clear_one(void *arg, const char *key, int vis)
{
  struct merge_state *m = arg;
  struct md_version w;

  w.st = m->clear_st;
  w.tombstone = 1;
  w.vis = vis;
  w.value = NULL;
  w.vlen = 0;
  merge_one(m, key, &w);
}

int md_prereg_merge(const struct MetadataPrereg *list, int user_keys,
                    int max_keys, size_t max_value_bytes,
                    const struct md_prereg_ops *ops, void *ctx)
{
  const struct MetadataPrereg *n, *from = list;
  struct merge_state m;

  m.ops = ops;
  m.ctx = ctx;
  m.user_keys = user_keys;
  m.max_keys = max_keys;
  m.max_value_bytes = max_value_bytes;
  m.applied = 0;

  /* Only the last CLEAR counts, and nothing noted before it. */
  for (n = list; n; n = n->next)
    if (n->clear)
      from = n;

  for (n = from; n; n = n->next) {
    struct md_version w;

    if (n->clear) {
      m.clear_st = n->st;
      if (ops->clear_keys)
        ops->clear_keys(ctx, clear_one, &m);
      continue;
    }
    w.st = n->st;
    w.tombstone = (n->value == NULL);
    w.vis = n->visibility;
    w.value = n->value;
    w.vlen = n->value ? strlen(n->value) : 0;
    merge_one(&m, n->key, &w);
  }
  return m.applied;
}

void md_prereg_note_clear(struct MetadataPrereg **list,
                          struct MetadataPrereg *marker,
                          void (*release)(struct MetadataPrereg *))
{
  struct MetadataPrereg *n, *next;

  for (n = *list; n; n = next) {
    next = n->next;
    if (release)
      release(n);
  }
  marker->clear = 1;
  marker->key[0] = '\0';
  marker->value = NULL;
  marker->next = NULL;
  *list = marker;
}

/** Count @a list's notes by kind, leaving out the one for @a except. */
static void count_notes(const struct MetadataPrereg *list, const char *except,
                        int *sets, int *deletes)
{
  *sets = *deletes = 0;
  for (; list; list = list->next) {
    if (list->clear || (except && key_eq(list->key, except)))
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
