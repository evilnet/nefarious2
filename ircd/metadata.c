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
 * This module provides storage for user and channel metadata with:
 *   - In-memory storage for transient (non-account) user metadata
 *   - LMDB persistence for account-linked user metadata
 *   - In-memory storage for channel metadata (persists with channel)
 *
 * Account metadata is persisted using LMDB when USE_LMDB is defined.
 * The LMDB environment is shared with the history subsystem.
 *
 * Key structure for account metadata: "account\0key"
 * Key structure for channel metadata: "#channel\0key"
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "ircd_alloc.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "metadata.h"
#include "s_user.h"
#include "struct.h"

#include <string.h>

#ifdef USE_LMDB
#include <lmdb.h>
#include "history.h"

/** LMDB environment (shared with history) */
static MDB_env *metadata_env = NULL;

/** Metadata database handle */
static MDB_dbi metadata_dbi;

/** Flag indicating if LMDB is available */
static int metadata_lmdb_available = 0;

/** Maximum metadata database size (100MB) */
#define METADATA_MAP_SIZE (100UL * 1024 * 1024)

/** Key separator */
#define KEY_SEP '\0'

/** Build a lookup key for LMDB.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] target Account name or channel name.
 * @param[in] metakey Metadata key name.
 * @return Length of key, or -1 on error.
 */
static int build_lmdb_key(char *key, int keysize, const char *target, const char *metakey)
{
  int pos = 0;
  int len;

  len = strlen(target);
  if (pos + len + 1 >= keysize) return -1;
  memcpy(key + pos, target, len);
  pos += len;
  key[pos++] = KEY_SEP;

  len = strlen(metakey);
  if (pos + len >= keysize) return -1;
  memcpy(key + pos, metakey, len);
  pos += len;

  return pos;
}

/** Initialize LMDB for metadata storage.
 * @param[in] dbpath Path to the database directory.
 * @return 0 on success, -1 on error.
 */
int metadata_lmdb_init(const char *dbpath)
{
  MDB_txn *txn;
  int rc;

  if (metadata_lmdb_available)
    return 0;

  /* Use existing history environment if available */
  if (history_is_available()) {
    /* History already initialized LMDB, we need to open our database */
    /* For now, we'll initialize our own environment */
  }

  rc = mdb_env_create(&metadata_env);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_env_create failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  rc = mdb_env_set_maxdbs(metadata_env, 2);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_env_set_maxdbs failed: %s",
              mdb_strerror(rc));
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdb_env_set_mapsize(metadata_env, METADATA_MAP_SIZE);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_env_set_mapsize failed: %s",
              mdb_strerror(rc));
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdb_env_open(metadata_env, dbpath, 0, 0644);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_env_open(%s) failed: %s",
              dbpath, mdb_strerror(rc));
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  /* Open database in a transaction */
  rc = mdb_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_txn_begin failed: %s",
              mdb_strerror(rc));
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdb_dbi_open(txn, "metadata", MDB_CREATE, &metadata_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_dbi_open failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdb_txn_commit failed: %s",
              mdb_strerror(rc));
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  metadata_lmdb_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "metadata: LMDB initialized at %s", dbpath);
  return 0;
}

/** Shutdown LMDB metadata storage. */
void metadata_lmdb_shutdown(void)
{
  if (metadata_env) {
    mdb_dbi_close(metadata_env, metadata_dbi);
    mdb_env_close(metadata_env);
    metadata_env = NULL;
    metadata_lmdb_available = 0;
  }
}

/** Check if LMDB metadata storage is available. */
int metadata_lmdb_is_available(void)
{
  return metadata_lmdb_available;
}

/** Get account metadata from LMDB.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] value Buffer for value (at least METADATA_VALUE_LEN).
 * @return 0 on success, 1 if not found, -1 on error.
 */
int metadata_account_get(const char *account, const char *key, char *value)
{
  MDB_txn *txn;
  MDB_val mkey, mdata;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  int keylen;
  int rc;

  if (!metadata_lmdb_available || !account || !key || !value)
    return -1;

  keylen = build_lmdb_key(keybuf, sizeof(keybuf), account, key);
  if (keylen < 0)
    return -1;

  rc = mdb_txn_begin(metadata_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = keybuf;
  mkey.mv_size = keylen;

  rc = mdb_get(txn, metadata_dbi, &mkey, &mdata);
  mdb_txn_abort(txn);

  if (rc == MDB_NOTFOUND)
    return 1;
  if (rc != 0)
    return -1;

  if (mdata.mv_size >= METADATA_VALUE_LEN)
    return -1;

  memcpy(value, mdata.mv_data, mdata.mv_size);
  value[mdata.mv_size] = '\0';

  return 0;
}

/** Set account metadata in LMDB.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set (NULL to delete).
 * @return 0 on success, -1 on error.
 */
int metadata_account_set(const char *account, const char *key, const char *value)
{
  MDB_txn *txn;
  MDB_val mkey, mdata;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  int keylen;
  int rc;

  if (!metadata_lmdb_available || !account || !key)
    return -1;

  keylen = build_lmdb_key(keybuf, sizeof(keybuf), account, key);
  if (keylen < 0)
    return -1;

  rc = mdb_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = keybuf;
  mkey.mv_size = keylen;

  if (value) {
    mdata.mv_data = (void *)value;
    mdata.mv_size = strlen(value);
    rc = mdb_put(txn, metadata_dbi, &mkey, &mdata, 0);
  } else {
    rc = mdb_del(txn, metadata_dbi, &mkey, NULL);
    if (rc == MDB_NOTFOUND)
      rc = 0; /* Deleting non-existent key is OK */
  }

  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
}

/** List all metadata for an account from LMDB.
 * Caller must free the returned list with metadata entries.
 * @param[in] account Account name.
 * @return Head of metadata list, or NULL if none/error.
 */
struct MetadataEntry *metadata_account_list(const char *account)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mdata;
  char prefix[ACCOUNTLEN + 2];
  int prefixlen;
  struct MetadataEntry *head = NULL, *tail = NULL, *entry;
  int rc;

  if (!metadata_lmdb_available || !account)
    return NULL;

  prefixlen = strlen(account);
  if (prefixlen >= ACCOUNTLEN)
    return NULL;
  memcpy(prefix, account, prefixlen);
  prefix[prefixlen++] = KEY_SEP;

  rc = mdb_txn_begin(metadata_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return NULL;

  rc = mdb_cursor_open(txn, metadata_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return NULL;
  }

  mkey.mv_data = prefix;
  mkey.mv_size = prefixlen;

  rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
  while (rc == 0) {
    /* Check if key still has our prefix */
    if (mkey.mv_size < prefixlen ||
        memcmp(mkey.mv_data, prefix, prefixlen) != 0)
      break;

    /* Extract the metadata key (after prefix) */
    entry = (struct MetadataEntry *)MyMalloc(sizeof(struct MetadataEntry));
    if (!entry)
      break;

    if (mkey.mv_size - prefixlen >= METADATA_KEY_LEN) {
      MyFree(entry);
      break;
    }
    memcpy(entry->key, (char *)mkey.mv_data + prefixlen, mkey.mv_size - prefixlen);
    entry->key[mkey.mv_size - prefixlen] = '\0';

    entry->value = (char *)MyMalloc(mdata.mv_size + 1);
    if (!entry->value) {
      MyFree(entry);
      break;
    }
    memcpy(entry->value, mdata.mv_data, mdata.mv_size);
    entry->value[mdata.mv_size] = '\0';

    entry->visibility = METADATA_VIS_PUBLIC;
    entry->next = NULL;

    if (tail)
      tail->next = entry;
    else
      head = entry;
    tail = entry;

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  return head;
}

/** Clear all metadata for an account in LMDB.
 * @param[in] account Account name.
 * @return 0 on success, -1 on error.
 */
int metadata_account_clear(const char *account)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mdata;
  char prefix[ACCOUNTLEN + 2];
  int prefixlen;
  int rc;

  if (!metadata_lmdb_available || !account)
    return -1;

  prefixlen = strlen(account);
  if (prefixlen >= ACCOUNTLEN)
    return -1;
  memcpy(prefix, account, prefixlen);
  prefix[prefixlen++] = KEY_SEP;

  rc = mdb_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, metadata_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  mkey.mv_data = prefix;
  mkey.mv_size = prefixlen;

  rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_SET_RANGE);
  while (rc == 0) {
    if (mkey.mv_size < prefixlen ||
        memcmp(mkey.mv_data, prefix, prefixlen) != 0)
      break;

    mdb_cursor_del(cursor, 0);
    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
  }

  mdb_cursor_close(cursor);

  rc = mdb_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
}

/** Store channel metadata to LMDB (for persistent channels).
 * @param[in] channel Channel name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set (NULL to delete).
 * @return 0 on success, -1 on error.
 */
int metadata_channel_persist(const char *channel, const char *key, const char *value)
{
  return metadata_account_set(channel, key, value);
}

/** Load channel metadata from LMDB.
 * @param[in] channel Channel name.
 * @return Head of metadata list, or NULL if none/error.
 */
struct MetadataEntry *metadata_channel_load(const char *channel)
{
  return metadata_account_list(channel);
}

#else /* !USE_LMDB */

/* Stub implementations when LMDB is not available */
int metadata_lmdb_init(const char *dbpath) { return -1; }
void metadata_lmdb_shutdown(void) { }
int metadata_lmdb_is_available(void) { return 0; }
int metadata_account_get(const char *account, const char *key, char *value) { return -1; }
int metadata_account_set(const char *account, const char *key, const char *value) { return -1; }
struct MetadataEntry *metadata_account_list(const char *account) { return NULL; }
int metadata_account_clear(const char *account) { return -1; }
int metadata_channel_persist(const char *channel, const char *key, const char *value) { return -1; }
struct MetadataEntry *metadata_channel_load(const char *channel) { return NULL; }

#endif /* USE_LMDB */

/** Initialize the metadata subsystem. */
void metadata_init(void)
{
  /* LMDB init is called separately from ircd.c */
}

/** Shutdown the metadata subsystem. */
void metadata_shutdown(void)
{
#ifdef USE_LMDB
  metadata_lmdb_shutdown();
#endif
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
 * First checks in-memory cache, then LMDB for logged-in users.
 * @param[in] cptr Client to get metadata from.
 * @param[in] key Key name.
 * @return Metadata entry or NULL if not found.
 */
struct MetadataEntry *metadata_get_client(struct Client *cptr, const char *key)
{
  struct MetadataEntry *entry;

  if (!cptr || !key)
    return NULL;

  /* Check in-memory cache first */
  for (entry = cli_metadata(cptr); entry; entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      return entry;
  }

  return NULL;
}

/** Set metadata for a client.
 * For logged-in users, also persists to LMDB.
 * @param[in] cptr Client to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
int metadata_set_client(struct Client *cptr, const char *key, const char *value, int visibility)
{
  struct MetadataEntry *entry, *prev = NULL;
  const char *account = NULL;

  if (!cptr || !key)
    return -1;

  /* Check if user is logged in */
  if (cli_user(cptr) && cli_user(cptr)->account[0])
    account = cli_user(cptr)->account;

  /* Find existing entry in memory */
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
      entry->visibility = visibility;
    } else {
      /* Create new */
      entry = create_entry(key, value);
      if (!entry)
        return -1;
      entry->visibility = visibility;
      entry->next = cli_metadata(cptr);
      cli_metadata(cptr) = entry;
    }

    /* Persist to LMDB for logged-in users */
    if (account && metadata_lmdb_is_available()) {
      metadata_account_set(account, key, value);
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

    /* Delete from LMDB for logged-in users */
    if (account && metadata_lmdb_is_available()) {
      metadata_account_set(account, key, NULL);
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
  const char *account = NULL;

  if (!cptr)
    return;

  /* Check if user is logged in */
  if (cli_user(cptr) && cli_user(cptr)->account[0])
    account = cli_user(cptr)->account;

  free_entry_list(cli_metadata(cptr));
  cli_metadata(cptr) = NULL;

  /* Clear from LMDB for logged-in users */
  if (account && metadata_lmdb_is_available()) {
    metadata_account_clear(account);
  }
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

/** Load metadata from LMDB for a logged-in user.
 * Called when a user logs into an account (via SASL or account-notify).
 * @param[in] cptr Client that just logged in.
 * @param[in] account Account name.
 */
void metadata_load_account(struct Client *cptr, const char *account)
{
  struct MetadataEntry *list, *entry;

  if (!cptr || !account || !metadata_lmdb_is_available())
    return;

  /* Clear any existing in-memory metadata */
  free_entry_list(cli_metadata(cptr));
  cli_metadata(cptr) = NULL;

  /* Load from LMDB */
  list = metadata_account_list(account);
  cli_metadata(cptr) = list;
}

/** Free all metadata for a client (called on disconnect).
 * @param[in] cptr Client being freed.
 */
void metadata_free_client(struct Client *cptr)
{
  /* Note: We don't clear LMDB on disconnect - metadata persists with account */
  free_entry_list(cli_metadata(cptr));
  cli_metadata(cptr) = NULL;
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
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
int metadata_set_channel(struct Channel *chptr, const char *key, const char *value, int visibility)
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
      entry->visibility = visibility;
    } else {
      /* Create new */
      entry = create_entry(key, value);
      if (!entry)
        return -1;
      entry->visibility = visibility;
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
