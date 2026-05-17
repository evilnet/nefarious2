/*
 * IRC - Internet Relay Chat, ircd/persistence_profile.c
 * Copyright (C) 2026 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
/** @file
 * @brief draft/persistence configuration-profile data layer.
 *
 * See include/persistence_profile.h for the contract; this file
 * provides the implementation against the account-metadata LMDB tree.
 */
#include "config.h"

#include "client.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "persistence_profile.h"

#include <ctype.h>
#include <string.h>

#define PROFILE_KEY_PREFIX "bouncer/profile/"
#define PROFILE_PARENT_KEY "parent"
#define PROFILE_NAME_LEN_MAX PERSISTENCE_PROFILE_NAME_MAX

/* Maximum depth of an inheritance chain we'll walk; protects against
 * pathological inputs even though cycle detection at SET time should
 * prevent real cycles. */
#define PROFILE_INHERIT_MAX_DEPTH 16

/** Build the full metadata key for `bouncer/profile/<name>/<key>`.
 * @return Number of bytes written (excluding NUL), or -1 on overflow.
 */
static int build_profile_key(char *out, size_t outlen,
                              const char *profile, const char *key)
{
  int n = ircd_snprintf(NULL, out, outlen, "%s%s/%s",
                        PROFILE_KEY_PREFIX, profile, key);
  if (n < 0 || (size_t)n >= outlen)
    return -1;
  return n;
}

int persistence_profile_name_valid(const char *name)
{
  size_t len;
  size_t i;

  if (!name || !*name)
    return 0;
  len = strlen(name);
  if (len > PROFILE_NAME_LEN_MAX)
    return 0;
  for (i = 0; i < len; ++i) {
    char c = name[i];
    if (!(isalnum((unsigned char)c) || c == '_' || c == '-'))
      return 0;
  }
  return 1;
}

/** Compare two profile names case-insensitively. */
static int profile_name_eq(const char *a, const char *b)
{
  return a && b && ircd_strcmp(a, b) == 0;
}

int persistence_profile_get_own(const char *account, const char *profile,
                                 const char *key, char *value, size_t value_len)
{
  char full_key[256];
  char tmp[METADATA_VALUE_LEN];
  int rc;

  if (!account || !profile || !key || !value || value_len == 0)
    return -1;
  if (build_profile_key(full_key, sizeof(full_key), profile, key) < 0)
    return -1;
  rc = metadata_account_get(account, full_key, tmp);
  if (rc != 0) {
    value[0] = '\0';
    return rc; /* 1 = not found, -1 = error */
  }
  ircd_strncpy(value, tmp, value_len);
  return 0;
}

int persistence_profile_exists(const char *account, const char *name)
{
  char val[METADATA_VALUE_LEN];

  if (!account || !name)
    return 0;
  if (profile_name_eq(name, PERSISTENCE_PROFILE_DEFAULT))
    return 1; /* default is always implicit */
  /* A custom profile exists iff it has a `parent` key.  CREATE always
   * writes the parent key (defaults to "default" if unspecified). */
  return persistence_profile_get_own(account, name, PROFILE_PARENT_KEY,
                                      val, sizeof(val)) == 0;
}

/** Read the parent profile name into `out`.  Custom profiles store
 * their parent explicitly; the `default` profile has no parent.
 * @return 0 if a parent was read (or the empty-string sentinel for
 *         "root"), 1 if profile doesn't exist or has no parent,
 *         -1 on error.
 */
static int profile_read_parent(const char *account, const char *profile,
                                char *out, size_t outlen)
{
  if (profile_name_eq(profile, PERSISTENCE_PROFILE_DEFAULT)) {
    out[0] = '\0';
    return 1;
  }
  return persistence_profile_get_own(account, profile, PROFILE_PARENT_KEY,
                                      out, outlen);
}

int persistence_profile_get_effective(const char *account, const char *profile,
                                       const char *key,
                                       char *value, size_t value_len)
{
  char current[PROFILE_NAME_LEN_MAX + 1];
  char parent[PROFILE_NAME_LEN_MAX + 1];
  int depth;
  int rc;

  if (!account || !profile || !key || !value || value_len == 0)
    return -1;

  ircd_strncpy(current, profile, sizeof(current));

  for (depth = 0; depth < PROFILE_INHERIT_MAX_DEPTH; ++depth) {
    rc = persistence_profile_get_own(account, current, key, value, value_len);
    if (rc == 0)
      return 0; /* hit */
    if (rc < 0)
      return -1;

    /* Not on this profile; walk up. */
    rc = profile_read_parent(account, current, parent, sizeof(parent));
    if (rc != 0)
      break; /* no parent — fell off the top */
    if (!parent[0])
      break; /* explicit no-parent sentinel */

    /* Implicit fallthrough: any non-default profile that didn't set a
     * parent inherits from default; but at CREATE time we always set
     * the parent key, so this path is only taken if someone wrote a
     * profile key directly without going through CREATE. */
    ircd_strncpy(current, parent, sizeof(current));
  }

  value[0] = '\0';
  return 1;
}

/** Walk a candidate parent chain (without writing) and return non-zero
 * if it would create a cycle that includes `name`.
 */
static int parent_chain_would_cycle(const char *account,
                                     const char *name,
                                     const char *proposed_parent)
{
  char current[PROFILE_NAME_LEN_MAX + 1];
  char parent[PROFILE_NAME_LEN_MAX + 1];
  int depth;

  if (!proposed_parent || !proposed_parent[0])
    return 0;
  if (profile_name_eq(proposed_parent, name))
    return 1;

  ircd_strncpy(current, proposed_parent, sizeof(current));
  for (depth = 0; depth < PROFILE_INHERIT_MAX_DEPTH; ++depth) {
    int rc = profile_read_parent(account, current, parent, sizeof(parent));
    if (rc != 0)
      return 0; /* chain terminates */
    if (!parent[0])
      return 0;
    if (profile_name_eq(parent, name))
      return 1;
    ircd_strncpy(current, parent, sizeof(current));
  }
  return 1; /* depth limit exceeded — treat as cycle */
}

int persistence_profile_set(const char *account, const char *profile,
                             const char *key, const char *value)
{
  char full_key[256];

  if (!account || !profile || !key)
    return -1;

  /* Cycle check when editing the parent key. */
  if (ircd_strcmp(key, PROFILE_PARENT_KEY) == 0 && value && value[0]) {
    if (!persistence_profile_name_valid(value)) {
      log_write(LS_DEBUG, L_DEBUG, 0,
                "persistence_profile_set: invalid parent name '%s' for "
                "profile '%s'", value, profile);
      return -1;
    }
    if (parent_chain_would_cycle(account, profile, value)) {
      log_write(LS_DEBUG, L_DEBUG, 0,
                "persistence_profile_set: refused parent='%s' for profile "
                "'%s' (would create cycle)", value, profile);
      return -1;
    }
  }

  if (build_profile_key(full_key, sizeof(full_key), profile, key) < 0)
    return -1;

  /* metadata_account_set_permanent stores without TTL — profiles are
   * preferences, not cache entries.  The same call handles delete when
   * value is NULL. */
  if (value)
    return metadata_account_set_permanent(account, full_key, value);
  return metadata_account_set(account, full_key, NULL);
}

int persistence_profile_create(const char *account, const char *name,
                                const char *parent)
{
  const char *effective_parent;

  if (!persistence_profile_name_valid(name))
    return -1;
  if (profile_name_eq(name, PERSISTENCE_PROFILE_DEFAULT))
    return -1; /* default is implicit */
  if (persistence_profile_exists(account, name))
    return -1; /* already exists */

  effective_parent = (parent && parent[0]) ? parent : PERSISTENCE_PROFILE_DEFAULT;
  if (!persistence_profile_name_valid(effective_parent))
    return -1;
  if (!persistence_profile_exists(account, effective_parent))
    return -1; /* parent must exist (default always does) */

  return persistence_profile_set(account, name, PROFILE_PARENT_KEY,
                                  effective_parent);
}

/** Find profiles that have `name` as their parent.
 * metadata_account_list returns raw TTL-encoded values; we must fetch
 * the decoded value via metadata_account_get for each candidate key.
 */
static int has_children(const char *account, const char *name)
{
  struct MetadataEntry *list, *e;
  size_t prefix_len = strlen(PROFILE_KEY_PREFIX);
  size_t parent_suffix_len = strlen("/" PROFILE_PARENT_KEY);
  int found = 0;

  list = metadata_account_list(account);
  for (e = list; e; e = e->next) {
    const char *k = e->key;
    size_t klen;
    char decoded[METADATA_VALUE_LEN];
    if (!k || strncmp(k, PROFILE_KEY_PREFIX, prefix_len) != 0)
      continue;
    klen = strlen(k);
    if (klen < parent_suffix_len)
      continue;
    if (strcmp(k + klen - parent_suffix_len, "/" PROFILE_PARENT_KEY) != 0)
      continue;
    if (metadata_account_get(account, k, decoded) != 0)
      continue;
    if (profile_name_eq(decoded, name)) {
      found = 1;
      break;
    }
  }
  /* metadata_account_list returns a fresh allocation we must free. */
  while (list) {
    struct MetadataEntry *next = list->next;
    metadata_free_entry(list);
    list = next;
  }
  return found;
}

int persistence_profile_delete(const char *account, const char *name)
{
  struct MetadataEntry *list, *e;
  char prefix[64];
  size_t prefix_len;
  int rc = 0;

  if (!persistence_profile_name_valid(name))
    return -1;
  if (profile_name_eq(name, PERSISTENCE_PROFILE_DEFAULT))
    return -1; /* can't delete the implicit default */
  if (!persistence_profile_exists(account, name))
    return -1; /* nothing to delete */
  if (has_children(account, name))
    return -1; /* other profiles inherit from this one */

  ircd_snprintf(NULL, prefix, sizeof(prefix), "%s%s/",
                PROFILE_KEY_PREFIX, name);
  prefix_len = strlen(prefix);

  list = metadata_account_list(account);
  for (e = list; e; e = e->next) {
    if (e->key && strncmp(e->key, prefix, prefix_len) == 0) {
      if (metadata_account_set(account, e->key, NULL) < 0) {
        rc = -1;
        /* keep going — best-effort cleanup */
      }
    }
  }
  while (list) {
    struct MetadataEntry *next = list->next;
    metadata_free_entry(list);
    list = next;
  }
  return rc;
}

int persistence_profile_rename(const char *account,
                                const char *old_name,
                                const char *new_name)
{
  struct MetadataEntry *list, *e;
  char old_prefix[64];
  char new_key[256];
  size_t old_prefix_len;
  int rc = 0;

  if (!persistence_profile_name_valid(old_name)
      || !persistence_profile_name_valid(new_name))
    return -1;
  if (profile_name_eq(old_name, PERSISTENCE_PROFILE_DEFAULT)
      || profile_name_eq(new_name, PERSISTENCE_PROFILE_DEFAULT))
    return -1;
  if (profile_name_eq(old_name, new_name))
    return 0; /* trivially a no-op */
  if (!persistence_profile_exists(account, old_name))
    return -1;
  if (persistence_profile_exists(account, new_name))
    return -1;

  ircd_snprintf(NULL, old_prefix, sizeof(old_prefix), "%s%s/",
                PROFILE_KEY_PREFIX, old_name);
  old_prefix_len = strlen(old_prefix);

  list = metadata_account_list(account);

  /* Phase 1: copy old_name's keys to new_name.  metadata_account_list
   * returns raw TTL-encoded values; re-read each via metadata_account_get
   * to get the decoded value before re-writing — otherwise the encoded
   * "T0|..." prefix gets stored twice. */
  for (e = list; e; e = e->next) {
    const char *suffix;
    char decoded[METADATA_VALUE_LEN];
    if (!e->key || strncmp(e->key, old_prefix, old_prefix_len) != 0)
      continue;
    suffix = e->key + old_prefix_len;
    if (build_profile_key(new_key, sizeof(new_key), new_name, suffix) < 0) {
      rc = -1;
      continue;
    }
    if (metadata_account_get(account, e->key, decoded) != 0) {
      rc = -1;
      continue;
    }
    if (metadata_account_set_permanent(account, new_key, decoded) < 0)
      rc = -1;
  }

  /* Phase 2: update any child profile's parent reference from old to new. */
  {
    size_t parent_suffix_len = strlen("/" PROFILE_PARENT_KEY);
    size_t kp_len = strlen(PROFILE_KEY_PREFIX);
    for (e = list; e; e = e->next) {
      const char *k = e->key;
      size_t klen;
      char decoded[METADATA_VALUE_LEN];
      if (!k || strncmp(k, PROFILE_KEY_PREFIX, kp_len) != 0)
        continue;
      klen = strlen(k);
      if (klen < parent_suffix_len)
        continue;
      if (strcmp(k + klen - parent_suffix_len, "/" PROFILE_PARENT_KEY) != 0)
        continue;
      if (metadata_account_get(account, k, decoded) != 0)
        continue;
      if (profile_name_eq(decoded, old_name)) {
        if (metadata_account_set_permanent(account, k, new_name) < 0)
          rc = -1;
      }
    }
  }

  /* Phase 3: delete old_name's keys. */
  for (e = list; e; e = e->next) {
    if (e->key && strncmp(e->key, old_prefix, old_prefix_len) == 0) {
      if (metadata_account_set(account, e->key, NULL) < 0)
        rc = -1;
    }
  }

  while (list) {
    struct MetadataEntry *next = list->next;
    metadata_free_entry(list);
    list = next;
  }
  return rc;
}

int persistence_profile_list(const char *account,
                              persistence_profile_list_cb cb,
                              void *cookie)
{
  struct MetadataEntry *list, *e;
  size_t prefix_len = strlen(PROFILE_KEY_PREFIX);
  size_t parent_suffix_len = strlen("/" PROFILE_PARENT_KEY);
  int default_seen = 0;

  if (!cb)
    return -1;

  list = metadata_account_list(account);

  for (e = list; e; e = e->next) {
    const char *k = e->key;
    size_t klen;
    char name[PROFILE_NAME_LEN_MAX + 1];
    char decoded_parent[METADATA_VALUE_LEN];
    size_t name_len;
    if (!k || strncmp(k, PROFILE_KEY_PREFIX, prefix_len) != 0)
      continue;
    klen = strlen(k);
    if (klen < parent_suffix_len)
      continue;
    if (strcmp(k + klen - parent_suffix_len, "/" PROFILE_PARENT_KEY) != 0)
      continue;
    name_len = klen - prefix_len - parent_suffix_len;
    if (name_len == 0 || name_len > PROFILE_NAME_LEN_MAX)
      continue;
    memcpy(name, k + prefix_len, name_len);
    name[name_len] = '\0';
    if (profile_name_eq(name, PERSISTENCE_PROFILE_DEFAULT))
      default_seen = 1; /* should not happen, but be safe */
    /* metadata_account_list returns raw TTL-encoded values; fetch the
     * decoded parent value via metadata_account_get. */
    if (metadata_account_get(account, k, decoded_parent) != 0)
      decoded_parent[0] = '\0';
    cb(name, decoded_parent, cookie);
  }

  /* `default` is implicit — always advertise it even if no keys are set. */
  if (!default_seen)
    cb(PERSISTENCE_PROFILE_DEFAULT, "", cookie);

  while (list) {
    struct MetadataEntry *next = list->next;
    metadata_free_entry(list);
    list = next;
  }
  return 0;
}
