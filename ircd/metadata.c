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

#include "account_conn.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "s_debug.h"
#include "s_stats.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <string.h>

#include "ircd_compress.h"

/** Virtual $presence metadata key */
#define METADATA_KEY_PRESENCE "$presence"

/** Virtual $last_present metadata key */
#define METADATA_KEY_LAST_PRESENT "$last_present"

/** Static buffer for virtual presence metadata entry */
static struct MetadataEntry presence_entry;
static char presence_value[64];

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

/** TTL value prefix marker */
#define TTL_PREFIX 'T'

/** Encode a value with TTL timestamp.
 * Format: T<timestamp>|<value>
 * @param[out] buf Output buffer.
 * @param[in] bufsize Size of output buffer.
 * @param[in] value Value to encode.
 * @param[in] timestamp Unix timestamp when cached.
 * @return Length written, or -1 on error.
 */
static int encode_ttl_value(char *buf, size_t bufsize, const char *value, time_t timestamp)
{
  int len;
  size_t value_len = strlen(value);

  len = ircd_snprintf(0, buf, bufsize, "%c%lu|", TTL_PREFIX, (unsigned long)timestamp);
  if (len < 0 || (size_t)len >= bufsize)
    return -1;

  if (len + value_len >= bufsize)
    return -1;

  memcpy(buf + len, value, value_len);
  return len + value_len;
}

/** Decode a TTL-encoded value.
 * @param[in] data Raw stored data.
 * @param[in] data_len Length of raw data.
 * @param[out] value Buffer for decoded value.
 * @param[in] value_size Size of value buffer.
 * @param[out] timestamp_out Pointer to store timestamp (may be NULL).
 * @return 0 on success, 1 if not TTL-encoded (legacy), -1 on error.
 */
static int decode_ttl_value(const void *data, size_t data_len, char *value,
                            size_t value_size, time_t *timestamp_out)
{
  const char *p = (const char *)data;
  const char *pipe;
  unsigned long ts;
  char *endp;
  size_t value_len;

  if (data_len == 0 || p[0] != TTL_PREFIX) {
    /* Legacy format - no TTL prefix, copy as-is */
    if (data_len >= value_size)
      return -1;
    memcpy(value, data, data_len);
    value[data_len] = '\0';
    if (timestamp_out)
      *timestamp_out = 0; /* Unknown timestamp */
    return 1; /* Legacy format */
  }

  /* Find the pipe separator */
  pipe = memchr(p + 1, '|', data_len - 1);
  if (!pipe)
    return -1;

  /* Parse timestamp */
  ts = strtoul(p + 1, &endp, 10);
  if (endp != pipe)
    return -1;

  if (timestamp_out)
    *timestamp_out = (time_t)ts;

  /* Extract value */
  value_len = data_len - (pipe - p) - 1;
  if (value_len >= value_size)
    return -1;

  memcpy(value, pipe + 1, value_len);
  value[value_len] = '\0';

  return 0;
}

/** Check if a cached value has expired.
 * @param[in] timestamp When the value was cached.
 * @param[in] ttl TTL in seconds (0 = no expiry).
 * @return 1 if expired, 0 if still valid.
 */
static int is_value_expired(time_t timestamp, int ttl)
{
  if (ttl <= 0 || timestamp == 0)
    return 0; /* No TTL or unknown timestamp - never expires */

  return (CurrentTime - timestamp) > ttl;
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
 * @return 0 on success, 1 if not found or expired, -1 on error.
 */
int metadata_account_get(const char *account, const char *key, char *value)
{
  MDB_txn *txn;
  MDB_val mkey, mdata;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  char decoded[METADATA_VALUE_LEN];
  int keylen;
  int rc;
  time_t timestamp;
  int ttl;
#ifdef USE_ZSTD
  unsigned char decompressed[METADATA_VALUE_LEN + 64];
  size_t decompressed_len;
#endif

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

#ifdef USE_ZSTD
  /* Check if data is compressed and decompress if needed */
  if (is_compressed(mdata.mv_data, mdata.mv_size)) {
    if (decompress_data(mdata.mv_data, mdata.mv_size,
                        decompressed, sizeof(decompressed), &decompressed_len) < 0) {
      return -1;
    }
    /* Decode TTL from decompressed data */
    rc = decode_ttl_value(decompressed, decompressed_len, decoded,
                          sizeof(decoded), &timestamp);
    if (rc < 0)
      return -1;

    /* Check TTL */
    ttl = feature_int(FEAT_METADATA_CACHE_TTL);
    if (is_value_expired(timestamp, ttl)) {
      Debug((DEBUG_DEBUG, "metadata: cached value for %s.%s expired", account, key));
      return 1; /* Treat as not found */
    }

    if (strlen(decoded) >= METADATA_VALUE_LEN)
      return -1;
    strcpy(value, decoded);
    return 0;
  }
#endif

  /* Decode TTL from raw data */
  rc = decode_ttl_value(mdata.mv_data, mdata.mv_size, decoded,
                        sizeof(decoded), &timestamp);
  if (rc < 0)
    return -1;

  /* Check TTL */
  ttl = feature_int(FEAT_METADATA_CACHE_TTL);
  if (is_value_expired(timestamp, ttl)) {
    Debug((DEBUG_DEBUG, "metadata: cached value for %s.%s expired", account, key));
    return 1; /* Treat as not found */
  }

  if (strlen(decoded) >= METADATA_VALUE_LEN)
    return -1;
  strcpy(value, decoded);
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
  char encoded[METADATA_VALUE_LEN + 32]; /* Extra space for TTL prefix */
  int keylen;
  int encoded_len;
  int rc;
#ifdef USE_ZSTD
  unsigned char compressed[METADATA_VALUE_LEN + 64];
  size_t compressed_len;
#endif

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
    /* Encode value with current timestamp for TTL tracking */
    encoded_len = encode_ttl_value(encoded, sizeof(encoded), value, CurrentTime);
    if (encoded_len < 0) {
      mdb_txn_abort(txn);
      return -1;
    }

#ifdef USE_ZSTD
    if (compress_data((const unsigned char *)encoded, encoded_len,
                      compressed, sizeof(compressed), &compressed_len) >= 0) {
      mdata.mv_data = compressed;
      mdata.mv_size = compressed_len;
    } else {
      mdata.mv_data = encoded;
      mdata.mv_size = encoded_len;
    }
#else
    mdata.mv_data = encoded;
    mdata.mv_size = encoded_len;
#endif
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

/** Set account metadata in LMDB without compression (raw passthrough).
 * Used for compression passthrough when data is already compressed.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] raw_value Raw (possibly compressed) data.
 * @param[in] raw_len Length of raw data.
 * @return 0 on success, -1 on error.
 */
int metadata_account_set_raw(const char *account, const char *key,
                             const unsigned char *raw_value, size_t raw_len)
{
  MDB_txn *txn;
  MDB_val mkey, mdata;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  int keylen;
  int rc;

  if (!metadata_lmdb_available || !account || !key || !raw_value || raw_len == 0)
    return -1;

  keylen = build_lmdb_key(keybuf, sizeof(keybuf), account, key);
  if (keylen < 0)
    return -1;

  rc = mdb_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = keybuf;
  mkey.mv_size = keylen;

  /* Store raw data directly without compression */
  mdata.mv_data = (void *)raw_value;
  mdata.mv_size = raw_len;

  rc = mdb_put(txn, metadata_dbi, &mkey, &mdata, 0);
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
#ifdef USE_ZSTD
  unsigned char decompressed[METADATA_VALUE_LEN];
  size_t decompressed_len;
#endif

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

#ifdef USE_ZSTD
    /* Check if data is compressed and decompress if needed */
    if (is_compressed(mdata.mv_data, mdata.mv_size)) {
      if (decompress_data(mdata.mv_data, mdata.mv_size,
                          decompressed, sizeof(decompressed), &decompressed_len) < 0) {
        MyFree(entry);
        rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
        continue;
      }
      entry->value = (char *)MyMalloc(decompressed_len + 1);
      if (!entry->value) {
        MyFree(entry);
        break;
      }
      memcpy(entry->value, decompressed, decompressed_len);
      entry->value[decompressed_len] = '\0';
    } else
#endif
    {
      entry->value = (char *)MyMalloc(mdata.mv_size + 1);
      if (!entry->value) {
        MyFree(entry);
        break;
      }
      memcpy(entry->value, mdata.mv_data, mdata.mv_size);
      entry->value[mdata.mv_size] = '\0';
    }

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

/** Purge expired metadata entries from LMDB.
 * Called periodically to enforce METADATA_CACHE_TTL.
 * @return Number of entries purged, or -1 on error.
 */
int metadata_account_purge_expired(void)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mdata;
  int ttl;
  int purged = 0;
  int rc;
#ifdef USE_ZSTD
  unsigned char decompressed[METADATA_VALUE_LEN + 64];
  size_t decompressed_len;
#endif
  char decoded[METADATA_VALUE_LEN];
  time_t timestamp;

  if (!metadata_lmdb_available)
    return -1;

  ttl = feature_int(FEAT_METADATA_CACHE_TTL);
  if (ttl <= 0)
    return 0; /* TTL disabled, nothing to purge */

  rc = mdb_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: purge mdb_txn_begin failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  rc = mdb_cursor_open(txn, metadata_dbi, &cursor);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: purge mdb_cursor_open failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_FIRST);
  while (rc == 0) {
    int decode_rc;
    int expired = 0;

#ifdef USE_ZSTD
    if (is_compressed(mdata.mv_data, mdata.mv_size)) {
      if (decompress_data(mdata.mv_data, mdata.mv_size,
                          decompressed, sizeof(decompressed), &decompressed_len) >= 0) {
        decode_rc = decode_ttl_value(decompressed, decompressed_len, decoded,
                                     sizeof(decoded), &timestamp);
        if (decode_rc >= 0 && is_value_expired(timestamp, ttl)) {
          expired = 1;
        }
      }
    } else
#endif
    {
      decode_rc = decode_ttl_value(mdata.mv_data, mdata.mv_size, decoded,
                                   sizeof(decoded), &timestamp);
      if (decode_rc >= 0 && is_value_expired(timestamp, ttl)) {
        expired = 1;
      }
    }

    if (expired) {
      mdb_cursor_del(cursor, 0);
      purged++;
    }

    rc = mdb_cursor_get(cursor, &mkey, &mdata, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: purge mdb_txn_commit failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  if (purged > 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "metadata: purged %d expired cache entries", purged);
  }

  return purged;
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
int metadata_account_purge_expired(void) { return -1; }
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

  /* Handle virtual presence keys for presence aggregation */
  if (feature_bool(FEAT_PRESENCE_AGGREGATION) && IsAccount(cptr)) {
    /* Handle $presence key */
    if (ircd_strcmp(key, METADATA_KEY_PRESENCE) == 0) {
      struct AccountEntry *acc_entry = account_conn_find(cli_account(cptr));
      if (acc_entry) {
        const char *state_str;
        switch (acc_entry->effective_state) {
          case CONN_PRESENT:
            state_str = "present";
            break;
          case CONN_AWAY:
            if (acc_entry->effective_away_msg[0])
              ircd_snprintf(0, presence_value, sizeof(presence_value),
                            "away:%s", acc_entry->effective_away_msg);
            else
              strcpy(presence_value, "away");
            state_str = NULL;
            break;
          case CONN_AWAY_STAR:
            state_str = "away-star";
            break;
          default:
            state_str = "unknown";
            break;
        }
        if (state_str)
          strcpy(presence_value, state_str);

        memset(&presence_entry, 0, sizeof(presence_entry));
        ircd_strncpy(presence_entry.key, METADATA_KEY_PRESENCE, METADATA_KEY_LEN);
        presence_entry.value = presence_value;
        presence_entry.visibility = METADATA_VIS_PUBLIC;
        presence_entry.next = NULL;
        return &presence_entry;
      }
    }

    /* Handle $last_present key */
    if (ircd_strcmp(key, METADATA_KEY_LAST_PRESENT) == 0) {
      time_t last = account_conn_last_present(cli_account(cptr));
      if (last > 0) {
        ircd_snprintf(0, presence_value, sizeof(presence_value), "%lu",
                      (unsigned long)last);
        memset(&presence_entry, 0, sizeof(presence_entry));
        ircd_strncpy(presence_entry.key, METADATA_KEY_LAST_PRESENT, METADATA_KEY_LEN);
        presence_entry.value = presence_value;
        presence_entry.visibility = METADATA_VIS_PUBLIC;
        presence_entry.next = NULL;
        return &presence_entry;
      }
    }
  }

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
  metadata_cleanup_client_requests(cptr);
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

/* ========== X3 Availability Tracking ========== */

/** X3 availability flag */
static int metadata_x3_available_flag = 0;

/** Last time X3 sent us a message */
static time_t metadata_x3_last_seen = 0;

/** Check if X3 services are available. */
int metadata_x3_is_available(void)
{
  return metadata_x3_available_flag;
}

/** Signal that X3 has sent a message (heartbeat). */
void metadata_x3_heartbeat(void)
{
  int was_available = metadata_x3_available_flag;
  metadata_x3_available_flag = 1;
  metadata_x3_last_seen = CurrentTime;

  /* If X3 just came back online, replay queued writes */
  if (!was_available) {
    log_write(LS_SYSTEM, L_INFO, 0, "metadata: X3 services detected as available");
    metadata_replay_queue();
  }
}

/** Check X3 availability status based on timeout. */
void metadata_x3_check(void)
{
  int timeout = feature_int(FEAT_METADATA_X3_TIMEOUT);

  if (timeout <= 0)
    return;

  if (CurrentTime - metadata_x3_last_seen > timeout) {
    if (metadata_x3_available_flag) {
      metadata_x3_available_flag = 0;
      log_write(LS_SYSTEM, L_WARNING, 0,
                "metadata: X3 services unavailable (no heartbeat for %d seconds), "
                "switching to cache-only mode", timeout);
    }
  }
}

/** Handle X3 reconnection - replay queued writes. */
void metadata_x3_reconnected(void)
{
  metadata_x3_heartbeat();
}

/** Check if metadata writes can be sent to X3. */
int metadata_can_write_x3(void)
{
  return metadata_x3_available_flag && metadata_lmdb_is_available();
}

/* ========== Write Queue for X3 Unavailability ========== */

/** Write queue entry */
struct MetadataWriteQueue {
  char account[ACCOUNTLEN + 1];
  char key[METADATA_KEY_LEN];
  char *value;
  int visibility;
  time_t timestamp;
  struct MetadataWriteQueue *next;
};

/** Write queue head and tail */
static struct MetadataWriteQueue *write_queue_head = NULL;
static struct MetadataWriteQueue *write_queue_tail = NULL;
static int write_queue_count_val = 0;

/** Queue a metadata write for later replay. */
int metadata_queue_write(const char *account, const char *key,
                         const char *value, int visibility)
{
  struct MetadataWriteQueue *entry;
  int max_queue = feature_int(FEAT_METADATA_QUEUE_SIZE);

  if (!account || !key)
    return -1;

  /* Check if queue is full */
  if (write_queue_count_val >= max_queue) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "metadata: write queue full (%d entries), dropping oldest entry",
              max_queue);
    /* Remove oldest entry */
    if (write_queue_head) {
      struct MetadataWriteQueue *old = write_queue_head;
      write_queue_head = old->next;
      if (!write_queue_head)
        write_queue_tail = NULL;
      if (old->value)
        MyFree(old->value);
      MyFree(old);
      write_queue_count_val--;
    }
  }

  /* Create new entry */
  entry = (struct MetadataWriteQueue *)MyMalloc(sizeof(struct MetadataWriteQueue));
  if (!entry)
    return -1;

  ircd_strncpy(entry->account, account, ACCOUNTLEN);
  ircd_strncpy(entry->key, key, METADATA_KEY_LEN - 1);
  entry->key[METADATA_KEY_LEN - 1] = '\0';

  if (value) {
    entry->value = (char *)MyMalloc(strlen(value) + 1);
    if (!entry->value) {
      MyFree(entry);
      return -1;
    }
    strcpy(entry->value, value);
  } else {
    entry->value = NULL;
  }

  entry->visibility = visibility;
  entry->timestamp = CurrentTime;
  entry->next = NULL;

  /* Add to queue */
  if (write_queue_tail)
    write_queue_tail->next = entry;
  else
    write_queue_head = entry;
  write_queue_tail = entry;
  write_queue_count_val++;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "metadata: queued write for %s key %s (queue size: %d)",
            account, key, write_queue_count_val);

  return 0;
}

/** Replay all queued metadata writes to X3.
 * Note: This sends P10 MD tokens to X3. We need to include the
 * necessary headers for send functions.
 */
void metadata_replay_queue(void)
{
  struct MetadataWriteQueue *entry, *next;
  int replayed = 0;

  if (!write_queue_head) {
    return;
  }

  log_write(LS_SYSTEM, L_INFO, 0,
            "metadata: replaying %d queued writes to X3",
            write_queue_count_val);

  for (entry = write_queue_head; entry; entry = next) {
    next = entry->next;

    /* The actual P10 send is done by the caller who has access to
     * the services client. For now, we just update LMDB and clear
     * the queue. The MD token propagation happens through normal
     * means when X3 syncs on reconnect.
     */
    if (metadata_lmdb_is_available()) {
      metadata_account_set(entry->account, entry->key, entry->value);
    }

    if (entry->value)
      MyFree(entry->value);
    MyFree(entry);
    replayed++;
  }

  write_queue_head = write_queue_tail = NULL;
  write_queue_count_val = 0;

  log_write(LS_SYSTEM, L_INFO, 0,
            "metadata: replayed %d queued writes", replayed);
}

/** Clear the write queue without replaying. */
void metadata_clear_queue(void)
{
  struct MetadataWriteQueue *entry, *next;

  for (entry = write_queue_head; entry; entry = next) {
    next = entry->next;
    if (entry->value)
      MyFree(entry->value);
    MyFree(entry);
  }

  write_queue_head = write_queue_tail = NULL;
  write_queue_count_val = 0;
}

/** Get the number of queued writes. */
int metadata_queue_count(void)
{
  return write_queue_count_val;
}

/* ========== Cache-Aware Metadata Operations ========== */

/** Get metadata for a client with cache-through behavior.
 * Checks in-memory first, then LMDB cache for logged-in users.
 * If found in LMDB but not in memory, loads it into memory.
 */
struct MetadataEntry *metadata_get_client_cached(struct Client *cptr, const char *key)
{
  struct MetadataEntry *entry;
  const char *account;
  char value[METADATA_VALUE_LEN];

  if (!cptr || !key)
    return NULL;

  /* Check if caching is enabled */
  if (!feature_bool(FEAT_METADATA_CACHE_ENABLED)) {
    return metadata_get_client(cptr, key);
  }

  /* First check in-memory (includes virtual keys like $presence) */
  entry = metadata_get_client(cptr, key);
  if (entry)
    return entry;

  /* If not logged in, nothing more to check */
  if (!cli_user(cptr) || !cli_user(cptr)->account[0])
    return NULL;

  /* Skip virtual keys - they're handled by metadata_get_client */
  if (key[0] == '$')
    return NULL;

  account = cli_user(cptr)->account;

  /* Check LMDB cache */
  if (metadata_lmdb_is_available()) {
    if (metadata_account_get(account, key, value) == 0) {
      /* Found in LMDB - load into memory */
      if (metadata_set_client(cptr, key, value, METADATA_VIS_PUBLIC) == 0) {
        return metadata_get_client(cptr, key);
      }
    }
  }

  return NULL;
}

/* ========== Netburst Metadata ========== */

/** Burst all metadata for a client to a server.
 * This is a stub - the actual implementation requires send.h
 * and will be called from s_user.c during burst.
 */
void metadata_burst_client(struct Client *sptr, struct Client *cptr)
{
  /* Stub - actual implementation in s_user.c */
  (void)sptr;
  (void)cptr;
}

/** Burst all metadata for a channel to a server.
 * This is a stub - the actual implementation requires send.h
 * and will be called from channel.c during burst.
 */
void metadata_burst_channel(struct Channel *chptr, struct Client *cptr)
{
  /* Stub - actual implementation in channel.c */
  (void)chptr;
  (void)cptr;
}

/* ========== MDQ Request Tracking ========== */

/** Pending MDQ requests list */
static struct MetadataRequest *mdq_pending_head = NULL;
static int mdq_pending_count = 0;

/** Find the services server (X3).
 * @return Pointer to services server, or NULL if not connected.
 */
static struct Client *find_services_server(void)
{
  struct Client *acptr;

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (IsServer(acptr) && IsService(acptr))
      return acptr;
  }

  return NULL;
}

/** Initialize MDQ request tracking. */
void metadata_request_init(void)
{
  mdq_pending_head = NULL;
  mdq_pending_count = 0;
}

/** Send an MDQ query to services for a target.
 * @param[in] sptr Client requesting metadata.
 * @param[in] target Target account or channel name.
 * @param[in] key Key to query (or "*" for all).
 * @return 0 on success, -1 on error.
 */
int metadata_send_query(struct Client *sptr, const char *target, const char *key)
{
  struct Client *services;
  struct MetadataRequest *req;

  if (!sptr || !target || !key)
    return -1;

  /* Check if X3 is available */
  if (!metadata_x3_is_available()) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_send_query: X3 not available, cannot query %s", target);
    return -1;
  }

  /* Find services server */
  services = find_services_server();
  if (!services) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_send_query: No services server found");
    return -1;
  }

  /* Check if we've hit the pending request limit */
  if (mdq_pending_count >= METADATA_MAX_PENDING) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "metadata_send_query: Too many pending requests (%d), rejecting",
              mdq_pending_count);
    return -1;
  }

  /* Check if there's already a pending request for this target/key from this client */
  for (req = mdq_pending_head; req; req = req->next) {
    if (req->client == sptr &&
        ircd_strcmp(req->target, target) == 0 &&
        ircd_strcmp(req->key, key) == 0) {
      /* Already pending, don't send duplicate */
      log_write(LS_DEBUG, L_DEBUG, 0,
                "metadata_send_query: Duplicate request for %s key %s", target, key);
      return 0;
    }
  }

  /* Create pending request entry */
  req = (struct MetadataRequest *)MyMalloc(sizeof(struct MetadataRequest));
  if (!req)
    return -1;

  req->client = sptr;
  ircd_strncpy(req->target, target, ACCOUNTLEN);
  ircd_strncpy(req->key, key, METADATA_KEY_LEN - 1);
  req->key[METADATA_KEY_LEN - 1] = '\0';
  req->timestamp = CurrentTime;
  req->next = mdq_pending_head;
  mdq_pending_head = req;
  mdq_pending_count++;

  /* Send MDQ to services */
  sendcmdto_one(&me, CMD_METADATAQUERY, services, "%s %s", target, key);

  log_write(LS_DEBUG, L_DEBUG, 0,
            "metadata_send_query: Sent MDQ for %s key %s (pending: %d)",
            target, key, mdq_pending_count);

  return 0;
}

/** Check if there are pending MDQ requests for a target/key.
 * Called when MD response is received to forward to waiting clients.
 * @param[in] target Target that metadata was received for.
 * @param[in] key Key that was received.
 * @param[in] value Value received.
 * @param[in] visibility Visibility level.
 */
void metadata_handle_response(const char *target, const char *key,
                              const char *value, int visibility)
{
  struct MetadataRequest *req, *prev, *next;
  int matched = 0;

  if (!target || !key)
    return;

  prev = NULL;
  for (req = mdq_pending_head; req; req = next) {
    next = req->next;

    /* Check if this request matches the response */
    if (ircd_strcmp(req->target, target) == 0 &&
        (ircd_strcmp(req->key, "*") == 0 || ircd_strcmp(req->key, key) == 0)) {

      /* Send response to waiting client if still connected */
      if (req->client && !IsDead(req->client) && MyUser(req->client)) {
        const char *vis_str = (visibility == METADATA_VIS_PRIVATE) ? "private" : "*";

        if (value && *value) {
          send_reply(req->client, RPL_KEYVALUE, target, key, vis_str, value);
        } else {
          send_reply(req->client, RPL_KEYNOTSET, target, key);
        }

        matched++;
        log_write(LS_DEBUG, L_DEBUG, 0,
                  "metadata_handle_response: Forwarded %s.%s to %s",
                  target, key, cli_name(req->client));
      }

      /* For wildcard requests, keep the request alive for more responses
       * but mark timestamp to trigger timeout after a short period */
      if (req->key[0] == '*') {
        /* Set a shorter timeout for wildcard collection (5 seconds) */
        if (CurrentTime - req->timestamp < 5) {
          prev = req;
          continue;
        }
      }

      /* Remove this request */
      if (prev)
        prev->next = next;
      else
        mdq_pending_head = next;

      MyFree(req);
      mdq_pending_count--;
    } else {
      prev = req;
    }
  }

  if (matched > 0) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_handle_response: Matched %d requests for %s.%s",
              matched, target, key);
  }
}

/** Clean up expired MDQ requests.
 * Called periodically from the main loop.
 */
void metadata_expire_requests(void)
{
  struct MetadataRequest *req, *prev, *next;
  int expired = 0;

  prev = NULL;
  for (req = mdq_pending_head; req; req = next) {
    next = req->next;

    if (CurrentTime - req->timestamp > METADATA_REQUEST_TIMEOUT) {
      /* Request has timed out - send error to client */
      if (req->client && !IsDead(req->client) && MyUser(req->client)) {
        send_reply(req->client, RPL_KEYNOTSET, req->target, req->key);
        log_write(LS_DEBUG, L_DEBUG, 0,
                  "metadata_expire_requests: Timed out request for %s.%s from %s",
                  req->target, req->key, cli_name(req->client));
      }

      /* Remove this request */
      if (prev)
        prev->next = next;
      else
        mdq_pending_head = next;

      MyFree(req);
      mdq_pending_count--;
      expired++;
    } else {
      prev = req;
    }
  }

  if (expired > 0) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_expire_requests: Expired %d requests (remaining: %d)",
              expired, mdq_pending_count);
  }
}

/** Clean up MDQ requests for a disconnecting client.
 * @param[in] cptr Client that is disconnecting.
 */
void metadata_cleanup_client_requests(struct Client *cptr)
{
  struct MetadataRequest *req, *prev, *next;
  int cleaned = 0;

  if (!cptr)
    return;

  prev = NULL;
  for (req = mdq_pending_head; req; req = next) {
    next = req->next;

    if (req->client == cptr) {
      /* Remove this request */
      if (prev)
        prev->next = next;
      else
        mdq_pending_head = next;

      MyFree(req);
      mdq_pending_count--;
      cleaned++;
    } else {
      prev = req;
    }
  }

  if (cleaned > 0) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_cleanup_client_requests: Cleaned %d requests for %s",
              cleaned, cli_name(cptr));
  }
}

void
metadata_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :METADATA Statistics");

#ifdef USE_LMDB
  {
    MDB_stat stat;
    MDB_envinfo info;
    MDB_txn *txn;
    int rc;

    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "M :  LMDB Backend: %s",
               metadata_lmdb_available ? "Available" : "Unavailable");

    if (metadata_lmdb_available && metadata_env) {
      /* Get environment info */
      rc = mdb_env_info(metadata_env, &info);
      if (rc == 0) {
        send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                   "M :  Map size: %lu MB",
                   (unsigned long)(info.me_mapsize / (1024 * 1024)));
      }

      /* Get database stats */
      rc = mdb_txn_begin(metadata_env, NULL, MDB_RDONLY, &txn);
      if (rc == 0) {
        rc = mdb_stat(txn, metadata_dbi, &stat);
        if (rc == 0) {
          send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                     "M :  Account metadata DB: %lu entries",
                     (unsigned long)stat.ms_entries);
        }
        mdb_txn_abort(txn);
      }
    }
  }
#else
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :  LMDB Backend: Not compiled in");
#endif

  /* X3 availability status */
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :  X3 Services: %s",
             metadata_x3_is_available() ? "Available" : "Unavailable");

  /* Write queue status */
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :  Write queue: %d pending",
             metadata_queue_count());

  /* Pending MDQ requests */
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :  MDQ requests: %d pending",
             mdq_pending_count);
}
