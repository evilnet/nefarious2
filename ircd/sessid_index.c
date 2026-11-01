/*
 * IRC - Internet Relay Chat, ircd/sessid_index.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * See include/sessid_index.h.  Keep this file free of ircd headers: it
 * is compiled standalone for the cmocka suite.
 */
#include "sessid_index.h"

#include <string.h>

/** Bucket count.  A power of two so the FNV-1a hash can be folded down
 * with a mask instead of a modulo. */
#define SESSID_INDEX_BUCKETS 4096

static struct SessidLink *buckets[SESSID_INDEX_BUCKETS];

/** FNV-1a over the key's bytes, folded to a bucket index.  Session ids
 * are UUID-v7-base64 or legacy hyphenated UUIDs -- short, fixed-ish
 * length ASCII -- so a byte-at-a-time hash is cheap enough and needs no
 * length argument beyond the NUL the key is guaranteed to carry. */
static size_t sessid_index_bucket(const char *key)
{
  unsigned long hash = 2166136261UL; /* FNV-1a 32-bit offset basis */
  const unsigned char *p = (const unsigned char *)key;

  while (*p) {
    hash ^= *p++;
    hash *= 16777619UL; /* FNV-1a 32-bit prime */
  }
  return (size_t)(hash & (SESSID_INDEX_BUCKETS - 1));
}

/** Copy @a key into @a dest (SESSID_INDEX_KEYLEN capacity), truncating
 * and always NUL-terminating -- this file may not include ircd_string.h
 * for ircd_strncpy, so it rolls its own bounded copy with the same
 * strlcpy-style contract the rest of the codebase expects. */
static void sessid_index_copy_key(char *dest, const char *src)
{
  size_t i;

  if (!src)
    src = "";
  for (i = 0; i + 1 < SESSID_INDEX_KEYLEN && src[i]; i++)
    dest[i] = src[i];
  dest[i] = '\0';
}

void sessid_index_unlink(struct SessidLink *link)
{
  struct SessidLink **walk;

  if (!link || !link->sl_linked)
    return;

  walk = &buckets[sessid_index_bucket(link->sl_key)];
  while (*walk) {
    if (*walk == link) {
      *walk = link->sl_next;
      break;
    }
    walk = &(*walk)->sl_next;
  }
  link->sl_next = NULL;
  link->sl_linked = 0;
}

void sessid_index_set(struct SessidLink *link, void *owner, const char *key)
{
  size_t bucket;

  if (!link)
    return;

  /* Unlink using the OLD key (link->sl_key), not the new one -- that is
   * the chain the node is actually filed in. */
  sessid_index_unlink(link);

  sessid_index_copy_key(link->sl_key, key);
  link->sl_owner = owner;

  if (!link->sl_key[0])
    return; /* empty key: deliberately not indexed */

  bucket = sessid_index_bucket(link->sl_key);
  link->sl_next = buckets[bucket];
  buckets[bucket] = link;
  link->sl_linked = 1;
}

size_t sessid_index_find(const char *key, void **owners, size_t max)
{
  struct SessidLink *node;
  size_t total = 0;

  if (!key || !key[0])
    return 0;

  for (node = buckets[sessid_index_bucket(key)]; node; node = node->sl_next) {
    if (0 != strcmp(node->sl_key, key))
      continue;
    if (owners && total < max)
      owners[total] = node->sl_owner;
    total++;
  }
  return total;
}

size_t sessid_index_count_if(const char *key, int (*pred)(void *owner))
{
  struct SessidLink *node;
  size_t count = 0;

  if (!key || !key[0] || !pred)
    return 0;

  for (node = buckets[sessid_index_bucket(key)]; node; node = node->sl_next) {
    if (0 != strcmp(node->sl_key, key))
      continue;
    if (pred(node->sl_owner))
      count++;
  }
  return count;
}
