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

int md_prereg_should_merge(int logged_in, int metadata_aware)
{
  return logged_in && metadata_aware;
}

enum md_prereg_verdict md_prereg_decide(const struct md_version *stored,
                                        const struct md_version *w,
                                        int *user_keys, int max_keys,
                                        size_t max_value_bytes)
{
  int stored_live = stored && !stored->tombstone;

  if (max_keys < 0)
    max_keys = 0;

  if (w->tombstone) {
    /* A delete: nothing to do unless the account holds the key. */
    if (!stored_live)
      return MD_PREREG_ABSENT;
    if (!md_lww_take(stored, w))
      return MD_PREREG_SUPERSEDED;
    (*user_keys)--;
    return MD_PREREG_APPLY;
  }

  /* The same value at the same visibility: the account already says it. */
  if (stored_live && stored->vis == w->vis && stored->vlen == w->vlen
      && (w->vlen == 0 || !memcmp(stored->value, w->value, w->vlen)))
    return MD_PREREG_SAME;

  /* A write made after the client's SET (its stamp the newer) stands. */
  if (stored && !md_lww_take(stored, w))
    return MD_PREREG_SUPERSEDED;

  if (w->vlen > max_value_bytes)
    return MD_PREREG_LIMIT_VALUE;

  /* A new live key needs a place; an update of one the account holds
   * does not (as metadata_check_limits() rules for a SET). */
  if (!stored_live) {
    if (*user_keys >= max_keys)
      return MD_PREREG_LIMIT_KEYS;
    (*user_keys)++;
  }
  return MD_PREREG_APPLY;
}
