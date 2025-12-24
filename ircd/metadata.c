/*
 * IRC - Internet Relay Chat, ircd/metadata.c
 * Copyright (C) 2024 Nefarious Development Team
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
 * @brief Metadata storage implementation (IRCv3 draft/metadata-2).
 *
 * This module provides in-memory storage for user and channel metadata.
 * Each client and channel has a linked list of key-value pairs.
 *
 * Future enhancements:
 *   - LMDB persistence for logged-in users
 *   - X3/keycloak integration for account-linked metadata
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "ircd_alloc.h"
#include "ircd_string.h"
#include "metadata.h"

#include <string.h>

/** Initialize the metadata subsystem. */
void metadata_init(void)
{
  /* Nothing to do for in-memory storage */
}

/** Shutdown the metadata subsystem. */
void metadata_shutdown(void)
{
  /* Nothing to do for in-memory storage */
}

/** Validate a metadata key name.
 * Keys must be alphanumeric with hyphens, underscores, dots, colons, forward slashes.
 * Cannot start with a digit.
 */
int metadata_valid_key(const char *key)
{
  const char *p;

  if (!key || !*key)
    return 0;

  /* Cannot start with a digit */
  if (*key >= '0' && *key <= '9')
    return 0;

  /* Check all characters */
  for (p = key; *p; p++) {
    if ((*p >= 'a' && *p <= 'z') ||
        (*p >= 'A' && *p <= 'Z') ||
        (*p >= '0' && *p <= '9') ||
        *p == '-' || *p == '_' || *p == '.' || *p == ':' || *p == '/')
      continue;
    return 0;
  }

  /* Check length */
  if (strlen(key) > METADATA_KEY_LEN)
    return 0;

  return 1;
}

/** Create a new metadata entry. */
static struct MetadataEntry *create_entry(const char *key, const char *value)
{
  struct MetadataEntry *entry;

  entry = (struct MetadataEntry *)MyMalloc(sizeof(struct MetadataEntry));
  if (!entry)
    return NULL;

  ircd_strncpy(entry->key, key, METADATA_KEY_LEN - 1);
  entry->key[METADATA_KEY_LEN - 1] = '\0';

  if (value) {
    entry->value = (char *)MyMalloc(strlen(value) + 1);
    if (!entry->value) {
      MyFree(entry);
      return NULL;
    }
    strcpy(entry->value, value);
  } else {
    entry->value = NULL;
  }

  entry->visibility = METADATA_VIS_PUBLIC;
  entry->next = NULL;

  return entry;
}

/** Free a metadata entry. */
void metadata_free_entry(struct MetadataEntry *entry)
{
  if (!entry)
    return;

  if (entry->value)
    MyFree(entry->value);

  MyFree(entry);
}

/** Free an entire list of metadata entries. */
static void free_entry_list(struct MetadataEntry *head)
{
  struct MetadataEntry *entry, *next;

  for (entry = head; entry; entry = next) {
    next = entry->next;
    metadata_free_entry(entry);
  }
}

/** Get metadata for a client.
 * @param[in] cptr Client to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
struct MetadataEntry *metadata_get_client(struct Client *cptr, const char *key)
{
  struct MetadataEntry *entry;

  if (!cptr || !key)
    return NULL;

  for (entry = cli_metadata(cptr); entry; entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      return entry;
  }

  return NULL;
}

/** Set metadata for a client.
 * @param[in] cptr Client to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @return 0 on success, -1 on error.
 */
int metadata_set_client(struct Client *cptr, const char *key, const char *value)
{
  struct MetadataEntry *entry, *prev = NULL;

  if (!cptr || !key)
    return -1;

  /* Find existing entry */
  for (entry = cli_metadata(cptr); entry; prev = entry, entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      break;
  }

  if (value) {
    /* Set or update */
    if (entry) {
      /* Update existing */
      if (entry->value)
        MyFree(entry->value);
      entry->value = (char *)MyMalloc(strlen(value) + 1);
      if (!entry->value)
        return -1;
      strcpy(entry->value, value);
    } else {
      /* Create new */
      entry = create_entry(key, value);
      if (!entry)
        return -1;
      entry->next = cli_metadata(cptr);
      cli_metadata(cptr) = entry;
    }
  } else {
    /* Delete */
    if (entry) {
      if (prev)
        prev->next = entry->next;
      else
        cli_metadata(cptr) = entry->next;
      metadata_free_entry(entry);
    }
  }

  return 0;
}

/** List all metadata for a client.
 * @param[in] cptr Client to list metadata for.
 * @return Head of metadata list (read-only).
 */
struct MetadataEntry *metadata_list_client(struct Client *cptr)
{
  if (!cptr)
    return NULL;
  return cli_metadata(cptr);
}

/** Clear all metadata for a client.
 * @param[in] cptr Client to clear.
 */
void metadata_clear_client(struct Client *cptr)
{
  if (!cptr)
    return;

  free_entry_list(cli_metadata(cptr));
  cli_metadata(cptr) = NULL;
}

/** Count metadata entries for a client.
 * @param[in] cptr Client to count.
 * @return Number of metadata entries.
 */
int metadata_count_client(struct Client *cptr)
{
  struct MetadataEntry *entry;
  int count = 0;

  if (!cptr)
    return 0;

  for (entry = cli_metadata(cptr); entry; entry = entry->next)
    count++;

  return count;
}

/** Free all metadata for a client (called on disconnect).
 * @param[in] cptr Client being freed.
 */
void metadata_free_client(struct Client *cptr)
{
  metadata_clear_client(cptr);
  metadata_sub_free(cptr);
}

/** Get metadata for a channel.
 * @param[in] chptr Channel to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
struct MetadataEntry *metadata_get_channel(struct Channel *chptr, const char *key)
{
  struct MetadataEntry *entry;

  if (!chptr || !key)
    return NULL;

  for (entry = chptr->metadata; entry; entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      return entry;
  }

  return NULL;
}

/** Set metadata for a channel.
 * @param[in] chptr Channel to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @return 0 on success, -1 on error.
 */
int metadata_set_channel(struct Channel *chptr, const char *key, const char *value)
{
  struct MetadataEntry *entry, *prev = NULL;

  if (!chptr || !key)
    return -1;

  /* Find existing entry */
  for (entry = chptr->metadata; entry; prev = entry, entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      break;
  }

  if (value) {
    /* Set or update */
    if (entry) {
      /* Update existing */
      if (entry->value)
        MyFree(entry->value);
      entry->value = (char *)MyMalloc(strlen(value) + 1);
      if (!entry->value)
        return -1;
      strcpy(entry->value, value);
    } else {
      /* Create new */
      entry = create_entry(key, value);
      if (!entry)
        return -1;
      entry->next = chptr->metadata;
      chptr->metadata = entry;
    }
  } else {
    /* Delete */
    if (entry) {
      if (prev)
        prev->next = entry->next;
      else
        chptr->metadata = entry->next;
      metadata_free_entry(entry);
    }
  }

  return 0;
}

/** List all metadata for a channel.
 * @param[in] chptr Channel to list metadata for.
 * @return Head of metadata list (read-only).
 */
struct MetadataEntry *metadata_list_channel(struct Channel *chptr)
{
  if (!chptr)
    return NULL;
  return chptr->metadata;
}

/** Clear all metadata for a channel.
 * @param[in] chptr Channel to clear.
 */
void metadata_clear_channel(struct Channel *chptr)
{
  if (!chptr)
    return;

  free_entry_list(chptr->metadata);
  chptr->metadata = NULL;
}

/** Count metadata entries for a channel.
 * @param[in] chptr Channel to count.
 * @return Number of metadata entries.
 */
int metadata_count_channel(struct Channel *chptr)
{
  struct MetadataEntry *entry;
  int count = 0;

  if (!chptr)
    return 0;

  for (entry = chptr->metadata; entry; entry = entry->next)
    count++;

  return count;
}

/** Free all metadata for a channel (called on channel destruction).
 * @param[in] chptr Channel being freed.
 */
void metadata_free_channel(struct Channel *chptr)
{
  metadata_clear_channel(chptr);
}

/* ========== Subscription functions ========== */

/** Create a new subscription entry. */
static struct MetadataSub *create_sub(const char *key)
{
  struct MetadataSub *sub;

  sub = (struct MetadataSub *)MyMalloc(sizeof(struct MetadataSub));
  if (!sub)
    return NULL;

  ircd_strncpy(sub->key, key, METADATA_KEY_LEN - 1);
  sub->key[METADATA_KEY_LEN - 1] = '\0';
  sub->next = NULL;

  return sub;
}

/** Add a subscription for a client.
 * @param[in] cptr Client subscribing.
 * @param[in] key Key to subscribe to.
 * @return 0 on success, -1 if limit reached or already subscribed.
 */
int metadata_sub_add(struct Client *cptr, const char *key)
{
  struct MetadataSub *sub;

  if (!cptr || !key)
    return -1;

  /* Check if already subscribed */
  for (sub = cli_metadatasub(cptr); sub; sub = sub->next) {
    if (ircd_strcmp(sub->key, key) == 0)
      return 0;  /* Already subscribed, success */
  }

  /* Create new subscription */
  sub = create_sub(key);
  if (!sub)
    return -1;

  sub->next = cli_metadatasub(cptr);
  cli_metadatasub(cptr) = sub;

  return 0;
}

/** Remove a subscription for a client.
 * @param[in] cptr Client unsubscribing.
 * @param[in] key Key to unsubscribe from.
 * @return 0 on success, -1 if not subscribed.
 */
int metadata_sub_del(struct Client *cptr, const char *key)
{
  struct MetadataSub *sub, *prev = NULL;

  if (!cptr || !key)
    return -1;

  for (sub = cli_metadatasub(cptr); sub; prev = sub, sub = sub->next) {
    if (ircd_strcmp(sub->key, key) == 0) {
      if (prev)
        prev->next = sub->next;
      else
        cli_metadatasub(cptr) = sub->next;
      MyFree(sub);
      return 0;
    }
  }

  return -1;  /* Not found */
}

/** Check if a client is subscribed to a key.
 * @param[in] cptr Client to check.
 * @param[in] key Key to check.
 * @return 1 if subscribed, 0 if not.
 */
int metadata_sub_check(struct Client *cptr, const char *key)
{
  struct MetadataSub *sub;

  if (!cptr || !key)
    return 0;

  for (sub = cli_metadatasub(cptr); sub; sub = sub->next) {
    if (ircd_strcmp(sub->key, key) == 0)
      return 1;
  }

  return 0;
}

/** List subscriptions for a client.
 * @param[in] cptr Client to list.
 * @return Head of subscription list.
 */
struct MetadataSub *metadata_sub_list(struct Client *cptr)
{
  if (!cptr)
    return NULL;
  return cli_metadatasub(cptr);
}

/** Count subscriptions for a client.
 * @param[in] cptr Client to count.
 * @return Number of subscriptions.
 */
int metadata_sub_count(struct Client *cptr)
{
  struct MetadataSub *sub;
  int count = 0;

  if (!cptr)
    return 0;

  for (sub = cli_metadatasub(cptr); sub; sub = sub->next)
    count++;

  return count;
}

/** Free all subscriptions for a client.
 * @param[in] cptr Client being freed.
 */
void metadata_sub_free(struct Client *cptr)
{
  struct MetadataSub *sub, *next;

  if (!cptr)
    return;

  for (sub = cli_metadatasub(cptr); sub; sub = next) {
    next = sub->next;
    MyFree(sub);
  }

  cli_metadatasub(cptr) = NULL;
}
