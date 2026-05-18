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
 * Account metadata is persisted via the db_* abstraction (RocksDB).
 * The LMDB environment is shared with the history subsystem.
 *
 * Key structure for account metadata: "account\0key"
 * Key structure for channel metadata: "#channel\0key"
 */
#include "config.h"

#include "bouncer_session.h"
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

/** Virtual presence metadata key */
#define METADATA_KEY_PRESENCE "presence"

/** Virtual last_present metadata key */
#define METADATA_KEY_LAST_PRESENT "last_present"

/** Virtual $away_message metadata key */
#define METADATA_KEY_AWAY_MESSAGE "away_message"

/** Static buffer for virtual presence metadata entry */
static struct MetadataEntry presence_entry;
static char presence_value[AWAYLEN + 1];

#ifdef USE_ROCKSDB
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "history.h"

/** Storage environment opened through the db_* abstraction.
 * Owns the RocksDB env + per-CF handles; closed via db_env_close at
 * shutdown. */
static struct db_env *metadata_db_env = NULL;
static struct db_cf  *metadata_cf = NULL;
static struct db_cf  *readmarkers_cf = NULL;
static struct db_cf  *bouncer_cf = NULL;

/** Flag indicating if storage is available */
static int metadata_lmdb_available = 0;

/** Maximum metadata database size (100MB) */
#define METADATA_MAP_SIZE (100UL * 1024 * 1024)

/** Key separator */
#define KEY_SEP '\0'

/* The libmdbx-specific FNV B-tree-traversal cache (mdbx_cache_init /
 * mdbx_cache_get_SingleThreaded) was retired alongside the conversion
 * of metadata_account_get to the abstraction.  RocksDB has its own
 * block cache that serves the same purpose; libmdbx's mmap means
 * repeated key lookups are already cheap without the extra layer. */

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
  struct db_env_opts env_opts;
  struct db_cf_opts  cf_opts;
  int rc;

  if (metadata_lmdb_available)
    return 0;

  memset(&env_opts, 0, sizeof env_opts);
  if (feature_bool(FEAT_METADATA_DB_AUTOGROW)) {
    env_opts.size_floor = 0;
    env_opts.size_max   = METADATA_MAP_SIZE;
  } else {
    env_opts.size_floor = METADATA_MAP_SIZE;
    env_opts.size_max   = METADATA_MAP_SIZE;
  }
  if (feature_bool(FEAT_METADATA_DB_NORDAHEAD)) {
    env_opts.random_access = 1;
    log_write(LS_SYSTEM, L_INFO, 0,
              "metadata: random-access I/O hint enabled");
  }

  rc = db_env_open(dbpath, &env_opts, /*max_cfs=*/3, &metadata_db_env);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "metadata: db_env_open(%s) failed: %s", dbpath, db_strerror(rc));
    return -1;
  }

  memset(&cf_opts, 0, sizeof cf_opts);
  rc = db_cf_open(metadata_db_env, "metadata", &cf_opts, &metadata_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "metadata: db_cf_open(metadata): %s", db_strerror(rc));
    db_env_close(metadata_db_env);
    metadata_db_env = NULL;
    return -1;
  }
  rc = db_cf_open(metadata_db_env, "readmarkers", &cf_opts, &readmarkers_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "metadata: db_cf_open(readmarkers): %s", db_strerror(rc));
    db_cf_close(metadata_db_env, metadata_cf);
    db_env_close(metadata_db_env);
    metadata_cf = NULL;
    metadata_db_env = NULL;
    return -1;
  }
  rc = db_cf_open(metadata_db_env, "bouncer_sessions", &cf_opts, &bouncer_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "metadata: db_cf_open(bouncer_sessions): %s", db_strerror(rc));
    db_cf_close(metadata_db_env, readmarkers_cf);
    db_cf_close(metadata_db_env, metadata_cf);
    db_env_close(metadata_db_env);
    readmarkers_cf = NULL;
    metadata_cf = NULL;
    metadata_db_env = NULL;
    return -1;
  }

  metadata_lmdb_available = 1;

  log_write(LS_SYSTEM, L_INFO, 0, "metadata: storage initialized at %s", dbpath);

  /* Pre-fault database pages into OS page cache */
  db_env_warmup(metadata_db_env);

  return 0;
}

/** Get the storage environment handle (for bouncer persistence). */
struct db_env *metadata_get_env(void)
{
  return metadata_db_env;
}

/** Get the bouncer sessions CF handle (for bouncer persistence). */
struct db_cf *metadata_get_bouncer_cf(void)
{
  return bouncer_cf;
}

/** Shutdown metadata storage. */
void metadata_lmdb_shutdown(void)
{
  if (metadata_db_env) {
    db_cf_close(metadata_db_env, bouncer_cf);
    db_cf_close(metadata_db_env, readmarkers_cf);
    db_cf_close(metadata_db_env, metadata_cf);
    db_env_close(metadata_db_env);
    metadata_db_env = NULL;
    metadata_cf = NULL;
    readmarkers_cf = NULL;
    bouncer_cf = NULL;
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
  struct db_val val = { NULL, 0 };
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

  rc = db_get(metadata_db_env, metadata_cf, keybuf, (size_t)keylen,
              /*snap=*/NULL, &val);
  if (rc == DB_NOTFOUND)
    return 1;
  if (rc != DB_OK)
    return -1;

#ifdef USE_ZSTD
  if (is_compressed(val.base, val.len)) {
    if (decompress_data(val.base, val.len,
                        decompressed, sizeof(decompressed), &decompressed_len) < 0) {
      db_val_free(&val);
      return -1;
    }
    rc = decode_ttl_value(decompressed, decompressed_len, decoded,
                          sizeof(decoded), &timestamp);
    db_val_free(&val);
    if (rc < 0)
      return -1;

    ttl = feature_int(FEAT_METADATA_CACHE_TTL);
    if (is_value_expired(timestamp, ttl)) {
      Debug((DEBUG_DEBUG, "metadata: cached value for %s.%s expired", account, key));
      return 1;
    }
    if (strlen(decoded) >= METADATA_VALUE_LEN)
      return -1;
    strcpy(value, decoded);
    return 0;
  }
#endif

  rc = decode_ttl_value(val.base, val.len, decoded,
                        sizeof(decoded), &timestamp);
  db_val_free(&val);
  if (rc < 0)
    return -1;

  ttl = feature_int(FEAT_METADATA_CACHE_TTL);
  if (is_value_expired(timestamp, ttl)) {
    Debug((DEBUG_DEBUG, "metadata: cached value for %s.%s expired", account, key));
    return 1;
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
/** Internal helper for metadata_account_set with explicit timestamp.
 * Pass timestamp=0 for permanent values (no TTL expiry).
 */
static int metadata_account_set_ts(const char *account, const char *key,
                                    const char *value, time_t timestamp)
{
  struct db_writebatch *wb;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  char encoded[METADATA_VALUE_LEN + 32]; /* Extra space for TTL prefix */
  int keylen;
  int encoded_len;
  int rc;
#ifdef USE_ZSTD
  unsigned char compressed[METADATA_VALUE_LEN + 64];
  size_t compressed_len;
#endif
  const void *vbuf = NULL;
  size_t       vlen = 0;

  if (!metadata_lmdb_available || !account || !key)
    return -1;

  keylen = build_lmdb_key(keybuf, sizeof(keybuf), account, key);
  if (keylen < 0)
    return -1;

  wb = db_writebatch_new(metadata_db_env);
  if (!wb)
    return -1;

  if (value) {
    encoded_len = encode_ttl_value(encoded, sizeof(encoded), value, timestamp);
    if (encoded_len < 0) {
      db_writebatch_destroy(wb);
      return -1;
    }
#ifdef USE_ZSTD
    if (compress_data((const unsigned char *)encoded, encoded_len,
                      compressed, sizeof(compressed), &compressed_len) >= 0) {
      vbuf = compressed;
      vlen = compressed_len;
    } else {
      vbuf = encoded;
      vlen = (size_t)encoded_len;
    }
#else
    vbuf = encoded;
    vlen = (size_t)encoded_len;
#endif
    rc = db_writebatch_put(wb, metadata_cf, keybuf, (size_t)keylen, vbuf, vlen);
  } else {
    rc = db_writebatch_del(wb, metadata_cf, keybuf, (size_t)keylen);
    if (rc == DB_NOTFOUND)
      rc = DB_OK;
  }
  if (rc != DB_OK) {
    db_writebatch_destroy(wb);
    return -1;
  }

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
}

/** Set account metadata in LMDB with TTL timestamp (CurrentTime).
 * Values will expire after METADATA_CACHE_TTL seconds.
 * For permanent values (user preferences), use metadata_account_set_permanent().
 */
int metadata_account_set(const char *account, const char *key, const char *value)
{
  return metadata_account_set_ts(account, key, value, CurrentTime);
}

/** Set account metadata in LMDB with no TTL (timestamp 0 = permanent).
 * Used for user preferences that should survive indefinitely.
 */
int metadata_account_set_permanent(const char *account, const char *key, const char *value)
{
  return metadata_account_set_ts(account, key, value, 0);
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
  struct db_writebatch *wb;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  int keylen;
  int rc;

  if (!metadata_lmdb_available || !account || !key || !raw_value || raw_len == 0)
    return -1;

  keylen = build_lmdb_key(keybuf, sizeof(keybuf), account, key);
  if (keylen < 0)
    return -1;

  wb = db_writebatch_new(metadata_db_env);
  if (!wb)
    return -1;
  rc = db_writebatch_put(wb, metadata_cf, keybuf, (size_t)keylen,
                         raw_value, raw_len);
  if (rc != DB_OK) {
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
}

/*
 * Read Marker API (IRCv3 draft/read-marker)
 *
 * Read markers are stored in the metadata LMDB environment in a dedicated
 * "readmarkers" DBI. This makes them available on ALL servers (not just
 * storing servers), since the metadata LMDB is independent of chathistory.
 *
 * Key: "account\0target"
 * Value: Unix timestamp string (seconds.milliseconds)
 */

/** Build a readmarker LMDB key.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] account Account name.
 * @param[in] target Channel name or nick.
 * @return Length of key, or -1 on error.
 */
static int build_readmarker_key(char *key, int keysize,
                                const char *account, const char *target)
{
  int pos = 0;
  int len;

  len = strlen(account);
  if (pos + len + 1 >= keysize) return -1;
  memcpy(key + pos, account, len);
  pos += len;
  key[pos++] = KEY_SEP;

  len = strlen(target);
  if (pos + len >= keysize) return -1;
  memcpy(key + pos, target, len);
  pos += len;

  return pos;
}

/** Get the read marker timestamp for an account and target.
 * @param[in] account Account name.
 * @param[in] target Channel name or nick.
 * @param[out] timestamp Buffer for timestamp (at least 32 bytes).
 * @return 0 on success, 1 if not found, -1 on error.
 */
int metadata_readmarker_get(const char *account, const char *target, char *timestamp)
{
  struct db_val val = { NULL, 0 };
  char keybuf[ACCOUNTLEN + CHANNELLEN + 4];
  int keylen;
  int rc;

  if (!metadata_lmdb_available)
    return -1;

  keylen = build_readmarker_key(keybuf, sizeof(keybuf), account, target);
  if (keylen < 0)
    return -1;

  rc = db_get(metadata_db_env, readmarkers_cf, keybuf, (size_t)keylen,
              /*snap=*/NULL, &val);
  if (rc == DB_NOTFOUND)
    return 1;
  if (rc != DB_OK)
    return -1;

  if (val.len >= 32) {
    db_val_free(&val);
    return -1;
  }
  memcpy(timestamp, val.base, val.len);
  timestamp[val.len] = '\0';
  db_val_free(&val);
  return 0;
}

/** Set the read marker timestamp for an account and target.
 * Only updates if the new timestamp is greater than the stored one.
 * @param[in] account Account name.
 * @param[in] target Channel name or nick.
 * @param[in] timestamp Unix timestamp (seconds.milliseconds as string).
 * @return 0 on success (updated), 1 if not updated (older timestamp), -1 on error.
 */
int metadata_readmarker_set(const char *account, const char *target, const char *timestamp)
{
  struct db_writebatch *wb;
  struct db_val cur = { NULL, 0 };
  char keybuf[ACCOUNTLEN + CHANNELLEN + 4];
  char existing_ts[32];
  int keylen;
  int rc;

  if (!metadata_lmdb_available)
    return -1;

  keylen = build_readmarker_key(keybuf, sizeof(keybuf), account, target);
  if (keylen < 0)
    return -1;

  /* Check existing value via a get; only update if new timestamp is greater. */
  rc = db_get(metadata_db_env, readmarkers_cf, keybuf, (size_t)keylen,
              /*snap=*/NULL, &cur);
  if (rc == DB_OK) {
    if (cur.len < sizeof existing_ts) {
      memcpy(existing_ts, cur.base, cur.len);
      existing_ts[cur.len] = '\0';
      if (strcmp(timestamp, existing_ts) <= 0) {
        db_val_free(&cur);
        return 1;
      }
    }
    db_val_free(&cur);
  } else if (rc != DB_NOTFOUND) {
    return -1;
  }

  wb = db_writebatch_new(metadata_db_env);
  if (!wb)
    return -1;
  rc = db_writebatch_put(wb, readmarkers_cf, keybuf, (size_t)keylen,
                         timestamp, strlen(timestamp));
  if (rc != DB_OK) {
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
}

/** List all metadata for an account from LMDB.
 * Caller must free the returned list with metadata entries.
 * @param[in] account Account name.
 * @return Head of metadata list, or NULL if none/error.
 */
struct MetadataEntry *metadata_account_list(const char *account)
{
  struct db_iter *it;
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

  it = db_iter_open(metadata_db_env, metadata_cf, /*snap=*/NULL);
  if (!it)
    return NULL;

  for (rc = db_iter_seek(it, prefix, (size_t)prefixlen);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen, vlen;
    const void *kbuf = db_iter_key(it, &klen);
    const void *vbuf = db_iter_value(it, &vlen);

    if (klen < (size_t)prefixlen ||
        memcmp(kbuf, prefix, (size_t)prefixlen) != 0)
      break;

    entry = (struct MetadataEntry *)MyMalloc(sizeof(struct MetadataEntry));
    if (!entry)
      break;

    if (klen - prefixlen >= METADATA_KEY_LEN) {
      MyFree(entry);
      break;
    }
    memcpy(entry->key, (const char *)kbuf + prefixlen, klen - prefixlen);
    entry->key[klen - prefixlen] = '\0';

#ifdef USE_ZSTD
    if (is_compressed((const unsigned char *)vbuf, vlen)) {
      if (decompress_data((const unsigned char *)vbuf, vlen,
                          decompressed, sizeof(decompressed), &decompressed_len) < 0) {
        MyFree(entry);
        continue;
      }
      entry->value = (char *)MyMalloc(decompressed_len + 1);
      if (!entry->value) { MyFree(entry); break; }
      memcpy(entry->value, decompressed, decompressed_len);
      entry->value[decompressed_len] = '\0';
    } else
#endif
    {
      entry->value = (char *)MyMalloc(vlen + 1);
      if (!entry->value) { MyFree(entry); break; }
      memcpy(entry->value, vbuf, vlen);
      entry->value[vlen] = '\0';
    }

    entry->visibility = METADATA_VIS_PUBLIC;
    entry->next = NULL;
    if (tail) tail->next = entry; else head = entry;
    tail = entry;
  }

  db_iter_close(it);
  return head;
}

/** Clear all metadata for an account in LMDB.
 * @param[in] account Account name.
 * @return 0 on success, -1 on error.
 */
int metadata_account_clear(const char *account)
{
  struct db_iter *it;
  struct db_writebatch *wb;
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

  /* Two-pass: iterate to collect matching keys, then delete via a
   * single writebatch.  Mirrors the libmdbx cursor_del-during-scan
   * pattern but uses portable abstraction primitives. */
  wb = db_writebatch_new(metadata_db_env);
  if (!wb)
    return -1;
  it = db_iter_open(metadata_db_env, metadata_cf, /*snap=*/NULL);
  if (!it) {
    db_writebatch_destroy(wb);
    return -1;
  }
  for (rc = db_iter_seek(it, prefix, (size_t)prefixlen);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen;
    const void *kbuf = db_iter_key(it, &klen);
    if (klen < (size_t)prefixlen ||
        memcmp(kbuf, prefix, (size_t)prefixlen) != 0)
      break;
    db_writebatch_del(wb, metadata_cf, kbuf, klen);
  }
  db_iter_close(it);

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
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
  struct db_iter *it;
  struct db_writebatch *wb;
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

  wb = db_writebatch_new(metadata_db_env);
  if (!wb)
    return -1;
  it = db_iter_open(metadata_db_env, metadata_cf, /*snap=*/NULL);
  if (!it) {
    db_writebatch_destroy(wb);
    return -1;
  }

  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen, vlen;
    const void *kbuf = db_iter_key(it, &klen);
    const void *vbuf = db_iter_value(it, &vlen);
    int decode_rc;
    int expired = 0;

#ifdef USE_ZSTD
    if (is_compressed((const unsigned char *)vbuf, vlen)) {
      if (decompress_data((const unsigned char *)vbuf, vlen,
                          decompressed, sizeof(decompressed), &decompressed_len) >= 0) {
        decode_rc = decode_ttl_value(decompressed, decompressed_len, decoded,
                                     sizeof(decoded), &timestamp);
        if (decode_rc >= 0 && is_value_expired(timestamp, ttl))
          expired = 1;
      }
    } else
#endif
    {
      decode_rc = decode_ttl_value(vbuf, vlen, decoded,
                                   sizeof(decoded), &timestamp);
      if (decode_rc >= 0 && is_value_expired(timestamp, ttl))
        expired = 1;
    }

    if (expired) {
      db_writebatch_del(wb, metadata_cf, kbuf, klen);
      purged++;
    }
  }
  db_iter_close(it);

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "metadata: purge commit failed: %s", db_strerror(rc));
    return -1;
  }
  if (purged > 0)
    log_write(LS_SYSTEM, L_INFO, 0, "metadata: purged %d expired cache entries", purged);
  return purged;
}

#else /* !defined(USE_ROCKSDB) — no backend available */

/* Stub implementations when no storage backend is available */
int metadata_lmdb_init(const char *dbpath) { return -1; }
void metadata_lmdb_shutdown(void) { }
int metadata_lmdb_is_available(void) { return 0; }
int metadata_account_get(const char *account, const char *key, char *value) { return -1; }
int metadata_account_set(const char *account, const char *key, const char *value) { return -1; }
int metadata_account_set_permanent(const char *account, const char *key, const char *value) { return -1; }
int metadata_account_set_raw(const char *account, const char *key, const unsigned char *raw_value, size_t raw_len) { (void)account;(void)key;(void)raw_value;(void)raw_len; return -1; }
struct MetadataEntry *metadata_account_list(const char *account) { return NULL; }
int metadata_account_clear(const char *account) { return -1; }
int metadata_account_purge_expired(void) { return -1; }
int metadata_channel_persist(const char *channel, const char *key, const char *value) { return -1; }
struct MetadataEntry *metadata_channel_load(const char *channel) { return NULL; }
int metadata_readmarker_get(const char *account, const char *target, char *timestamp) { (void)account; (void)target; (void)timestamp; return -1; }
int metadata_readmarker_set(const char *account, const char *target, const char *timestamp) { (void)account; (void)target; (void)timestamp; return -1; }
int metadata_defrag(unsigned int t) { (void)t; return -1; }
int metadata_sync(void) { return -1; }

#endif /* USE_ROCKSDB */

/** Initialize the metadata subsystem. */
void metadata_init(void)
{
  /* LMDB init is called separately from ircd.c */
}

/** Shutdown the metadata subsystem. */
void metadata_shutdown(void)
{
#ifdef USE_ROCKSDB
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
    struct BouncerSession *session = bounce_get_session(cptr);

    /* Handle presence key - returns state only (present/away/away-star) */
    if (ircd_strcmp(key, METADATA_KEY_PRESENCE) == 0) {
      if (session) {
        const char *state_str;
        switch (session->hs_effective_away) {
          case 0:
            state_str = "present";
            break;
          case 1:
            state_str = "away";
            break;
          case 2:
            state_str = "away-star";
            break;
          default:
            state_str = "unknown";
            break;
        }
        strcpy(presence_value, state_str);

        memset(&presence_entry, 0, sizeof(presence_entry));
        ircd_strncpy(presence_entry.key, METADATA_KEY_PRESENCE, METADATA_KEY_LEN);
        presence_entry.value = presence_value;
        presence_entry.visibility = METADATA_VIS_PUBLIC;
        presence_entry.next = NULL;
        return &presence_entry;
      }
    }

    /* Handle $away_message key - returns effective away message */
    if (ircd_strcmp(key, METADATA_KEY_AWAY_MESSAGE) == 0) {
      if (session && session->hs_effective_away_msg[0]) {
        ircd_strncpy(presence_value, session->hs_effective_away_msg, AWAYLEN + 1);

        memset(&presence_entry, 0, sizeof(presence_entry));
        ircd_strncpy(presence_entry.key, METADATA_KEY_AWAY_MESSAGE, METADATA_KEY_LEN);
        presence_entry.value = presence_value;
        presence_entry.visibility = METADATA_VIS_PUBLIC;
        presence_entry.next = NULL;
        return &presence_entry;
      }
      /* No away message - return NULL (key not found) */
      return NULL;
    }

    /* Handle last_present key */
    if (ircd_strcmp(key, METADATA_KEY_LAST_PRESENT) == 0) {
      if (session && session->hs_last_active > 0) {
        ircd_snprintf(0, presence_value, sizeof(presence_value), "%lu",
                      (unsigned long)session->hs_last_active);
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

  /* Fall through to persistent store for logged-in users.
   * After a restart the client struct is fresh — load the value
   * from mdbx on first access.  Create the in-memory entry directly
   * (don't call metadata_set_client which would re-persist to mdbx). */
  if (cli_user(cptr) && cli_user(cptr)->account[0] && key[0] != '$'
      && metadata_lmdb_is_available()) {
    char value[METADATA_VALUE_LEN];
    if (metadata_account_get(cli_user(cptr)->account, key, value) == 0) {
      entry = create_entry(key, value);
      if (entry) {
        entry->visibility = METADATA_VIS_PRIVATE;
        entry->next = cli_metadata(cptr);
        cli_metadata(cptr) = entry;
        return entry;
      }
    }
  }

  return NULL;
}

/** Table mapping metadata keys to user mode flags for bidirectional sync.
 * When metadata is set/cleared, the corresponding mode flag is updated.
 * For normal keys: value present & non-"0" = set flag; absent = clear.
 * For inverted keys: value "0"/empty/NULL = set flag; anything else = clear.
 */
static const struct {
  const char *key;
  enum Flag flag;
  int invert;  /**< 1 = value "0"/empty means set flag (for chathistory.pm) */
} metadata_mode_sync[] = {
  { "umode.invisible",       FLAG_INVISIBLE,       0 },
  { "umode.nochan",          FLAG_NOCHAN,           0 },
  { "umode.commonchansonly", FLAG_COMMONCHANSONLY,  0 },
  { "umode.accountonly",     FLAG_ACCOUNTONLY,       0 },
  { "umode.privdeaf",        FLAG_PRIVDEAF,          0 },
  { "chathistory.nostorage", FLAG_NOSTORAGE,        0 },
  { "chathistory.pm",        FLAG_PM_OPTOUT,        1 },
  { "draft/persistence/hold", FLAG_BNC_HOLDPREF,   0 },
  { NULL, 0, 0 }
};

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

    /* Persist to LMDB for logged-in users — store permanently (no TTL).
     * Values set via metadata_set_client are user preferences, not cache
     * entries, and should not expire after METADATA_CACHE_TTL. */
    if (account && metadata_lmdb_is_available()) {
      metadata_account_set_permanent(account, key, value);
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

  /* Sync metadata keys with user mode flags */
  if (IsUser(cptr)) {
    int i;
    for (i = 0; metadata_mode_sync[i].key; i++) {
      if (ircd_strcmp(key, metadata_mode_sync[i].key) == 0) {
        if (metadata_mode_sync[i].invert) {
          /* Inverted: value "0" or empty = set flag; NULL or truthy = clear flag.
           * For chathistory.pm: "0" = opted out (flag set), deleted = not opted out (flag clear). */
          if (value && (value[0] == '\0' || value[0] == '0'))
            SetFlag(cptr, metadata_mode_sync[i].flag);
          else
            ClrFlag(cptr, metadata_mode_sync[i].flag);
        } else {
          /* Normal: value present & truthy = set flag; NULL/empty/"0" = clear flag */
          if (value && value[0] != '\0' && value[0] != '0')
            SetFlag(cptr, metadata_mode_sync[i].flag);
          else
            ClrFlag(cptr, metadata_mode_sync[i].flag);
        }
        break;
      }
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

/** Reserved prefixes for server-managed metadata.
 * Keys under these prefixes are written exclusively by server-side logic
 * (bouncer session state, persistence preferences, etc.) and are exempt
 * from the user-facing key-count budget.  Direct METADATA SET from a
 * client is refused for keys matching these prefixes.
 */
static const char *const server_managed_prefixes[] = {
  "draft/persistence/",
  NULL
};

int metadata_key_is_server_managed(const char *key)
{
  const char *const *p;
  size_t klen;

  if (!key)
    return 0;
  klen = strlen(key);
  for (p = server_managed_prefixes; *p; ++p) {
    size_t plen = strlen(*p);
    if (klen >= plen && strncasecmp(key, *p, plen) == 0)
      return 1;
  }
  return 0;
}

/** Count user-managed metadata entries for a client.
 * Server-managed entries (see metadata_key_is_server_managed) are skipped.
 * @param[in] cptr Client to count.
 * @return Number of user-managed metadata entries.
 */
int metadata_count_client(struct Client *cptr)
{
  struct MetadataEntry *entry;
  int count = 0;

  if (!cptr)
    return 0;

  for (entry = cli_metadata(cptr); entry; entry = entry->next) {
    if (metadata_key_is_server_managed(entry->key))
      continue;
    count++;
  }

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

  if (!cptr || !account) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_load_account: Invalid parameters (cptr=%p, account=%s)",
              (void *)cptr, account ? account : "(null)");
    return;
  }
  if (!metadata_lmdb_is_available()) {
    log_write(LS_DEBUG, L_DEBUG, 0,
              "metadata_load_account: LMDB not available for account '%s' (%C)",
              account, cptr);
    return;
  }

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

  for (entry = chptr->metadata; entry; entry = entry->next) {
    if (metadata_key_is_server_managed(entry->key))
      continue;
    count++;
  }

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

/* X3 dependency removed - Nefarious is now authoritative for metadata */

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

  /* First check in-memory (includes virtual keys like presence) */
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

/* MDQ removed - Nefarious answers GET from local LMDB only */

void
metadata_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct db_env_stats env_stats;
  struct db_cf_stats cf_stats;
  (void)sd; (void)param;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :METADATA Statistics");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :  Backend: RocksDB (%s)",
             metadata_lmdb_available ? "available" : "unavailable");

  if (!metadata_lmdb_available || !metadata_db_env)
    return;

  /* Env-wide stats — backend-agnostic via abstraction. */
  if (db_env_stats(metadata_db_env, &env_stats) == DB_OK) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "M :  On-disk: %lu KB, ~%lu keys total",
               (unsigned long)(env_stats.on_disk_bytes / 1024),
               (unsigned long)env_stats.approx_keys_total);
    if (env_stats.pending_compaction > 0)
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "M :  Pending compaction: %lu KB",
                 (unsigned long)(env_stats.pending_compaction / 1024));
    if (env_stats.level0_files > 0)
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "M :  L0 files: %u", env_stats.level0_files);
    if (env_stats.active_readers > 0)
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "M :  Active readers: %u", env_stats.active_readers);
  }

  /* Per-CF stats — backend-agnostic. */
  if (db_cf_stats(metadata_db_env, metadata_cf, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "M :  Account metadata: ~%lu keys, %lu KB, depth %u",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024),
               cf_stats.depth);
  if (db_cf_stats(metadata_db_env, readmarkers_cf, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "M :  Read markers: ~%lu entries",
               (unsigned long)cf_stats.approx_keys);
  if (db_cf_stats(metadata_db_env, bouncer_cf, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "M :  Bouncer sessions: ~%lu entries",
               (unsigned long)cf_stats.approx_keys);
}

/** \brief Compact / defragment the metadata database. */
int
metadata_defrag(unsigned int time_limit_seconds)
{
  int rc;
  (void)time_limit_seconds;  /* libmdbx-only knob; RocksDB compaction self-paces */

  if (!metadata_lmdb_available || !metadata_db_env)
    return -1;

  rc = db_env_compact(metadata_db_env, /*cf=*/NULL);
  log_write(LS_SYSTEM, L_INFO, 0,
            "metadata: compact complete rc=%d (%s)", rc, db_strerror(rc));
  return (rc == DB_OK) ? 0 : -1;
}

/** \brief Report compaction (defrag) results for metadata DB */
void
metadata_report_defrag(struct Client *to)
{
  int rc;
  if (!metadata_lmdb_available || !metadata_db_env) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "D :  Metadata: unavailable");
    return;
  }
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Metadata: compacting...");
  rc = db_env_compact(metadata_db_env, /*cf=*/NULL);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  Metadata: compact %s (%s)",
             rc == DB_OK ? "done" : "failed",
             db_strerror(rc));
}

/** \brief Force sync/flush the metadata database to disk. */
int
metadata_sync(void)
{
  if (!metadata_lmdb_available || !metadata_db_env)
    return -1;
  return (db_env_sync(metadata_db_env) == DB_OK) ? 0 : -1;
}

/** \brief Report compaction info for the metadata database. */
void
metadata_report_gc(struct Client *to)
{
  struct db_env_stats env_stats;

  if (!metadata_lmdb_available || !metadata_db_env) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  Metadata GC: unavailable");
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :  Metadata Compaction (RocksDB):");
  if (db_env_stats(metadata_db_env, &env_stats) == DB_OK) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Pending: %lu KB",
               (unsigned long)(env_stats.pending_compaction / 1024));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    L0 files: %u", env_stats.level0_files);
  }
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Background compactor self-paces; no operator GC needed");
}

/** \brief Report environment info for the metadata database. */
void
metadata_report_store_info(struct Client *to)
{
  struct db_env_stats env_stats;
  struct db_cf_stats cf_stats;

  if (!metadata_lmdb_available || !metadata_db_env) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  Metadata: unavailable");
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :  Metadata Environment (RocksDB):");

  if (db_env_stats(metadata_db_env, &env_stats) == DB_OK) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    On-disk: %lu KB total",
               (unsigned long)(env_stats.on_disk_bytes / 1024));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Approx keys (env-wide): %lu",
               (unsigned long)env_stats.approx_keys_total);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Pending compaction: %lu KB  L0 files: %u",
               (unsigned long)(env_stats.pending_compaction / 1024),
               env_stats.level0_files);
  }

  if (db_cf_stats(metadata_db_env, metadata_cf, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    metadata: ~%lu keys, %lu KB, max-level %u",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024),
               cf_stats.depth);
  if (db_cf_stats(metadata_db_env, readmarkers_cf, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    readmarkers: ~%lu keys, %lu KB",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024));
  if (db_cf_stats(metadata_db_env, bouncer_cf, &cf_stats) == DB_OK)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    bouncer_sessions: ~%lu keys, %lu KB",
               (unsigned long)cf_stats.approx_keys,
               (unsigned long)(cf_stats.on_disk_bytes / 1024));
}
