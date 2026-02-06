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
 * Account metadata is persisted using LMDB when USE_MDBX is defined.
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

#ifdef USE_MDBX
#include <mdbx.h>
#include "history.h"

/** LMDB environment (shared with history) */
static MDBX_env *metadata_env = NULL;

/** Metadata database handle */
static MDBX_dbi metadata_dbi;

/** Read markers database handle (IRCv3 draft/read-marker) */
static MDBX_dbi readmarkers_dbi;

/** Bouncer sessions database handle (persistent bouncer state) */
static MDBX_dbi bouncer_dbi;

/** Flag indicating if LMDB is available */
static int metadata_lmdb_available = 0;

/** Maximum metadata database size (100MB) */
#define METADATA_MAP_SIZE (100UL * 1024 * 1024)

/** Key separator */
#define KEY_SEP '\0'

/** Default number of B-tree cache slots for metadata lookups */
#define METADATA_CACHE_SLOTS_DEFAULT 128

/** B-tree traversal cache for metadata lookups */
static MDBX_cache_entry_t *metadata_cache = NULL;
static uint32_t *metadata_cache_hash = NULL;
static unsigned int metadata_cache_slots = 0;

/** FNV-1a 32-bit hash for cache slot selection */
static uint32_t cache_fnv1a(const void *data, size_t len)
{
  const unsigned char *p = (const unsigned char *)data;
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < len; i++) {
    h ^= p[i];
    h *= 16777619u;
  }
  return h ? h : 1; /* avoid 0 so we can use 0 as "empty" */
}

/** Get cache entry for a key, re-initializing on hash collision */
static MDBX_cache_entry_t *metadata_cache_slot(const MDBX_val *key)
{
  uint32_t h;
  unsigned int slot;

  if (!metadata_cache)
    return NULL;

  h = cache_fnv1a(key->iov_base, key->iov_len);
  slot = h & (metadata_cache_slots - 1);
  if (metadata_cache_hash[slot] != h) {
    mdbx_cache_init(&metadata_cache[slot]);
    metadata_cache_hash[slot] = h;
  }
  return &metadata_cache[slot];
}

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
  MDBX_txn *txn;
  int rc;

  if (metadata_lmdb_available)
    return 0;

  /* Use existing history environment if available */
  if (history_is_available()) {
    /* History already initialized LMDB, we need to open our database */
    /* For now, we'll initialize our own environment */
  }

  rc = mdbx_env_create(&metadata_env);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_env_create failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  rc = mdbx_env_set_maxdbs(metadata_env, 3);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_env_set_maxdbs failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  if (feature_bool(FEAT_METADATA_DB_AUTOGROW)) {
    rc = mdbx_env_set_geometry(metadata_env, -1, -1, METADATA_MAP_SIZE,
                               16 * 1024 * 1024, 16 * 1024 * 1024, -1);
  } else {
    rc = mdbx_env_set_geometry(metadata_env, METADATA_MAP_SIZE, METADATA_MAP_SIZE,
                               METADATA_MAP_SIZE, 0, 0, -1);
  }
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_env_set_geometry failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  {
    unsigned int env_flags = 0;
    if (feature_bool(FEAT_METADATA_DB_NORDAHEAD)) {
      env_flags |= MDBX_NORDAHEAD;
      log_write(LS_SYSTEM, L_INFO, 0, "metadata: using MDBX_NORDAHEAD for random-access pattern");
    }
    rc = mdbx_env_open(metadata_env, dbpath, env_flags, 0644);
  }
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_env_open(%s) failed: %s",
              dbpath, mdbx_strerror(rc));
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  /* Open database in a transaction */
  rc = mdbx_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_txn_begin failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdbx_dbi_open(txn, "metadata", MDBX_CREATE, &metadata_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_dbi_open failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdbx_dbi_open(txn, "readmarkers", MDBX_CREATE, &readmarkers_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_dbi_open(readmarkers) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdbx_dbi_open(txn, "bouncer_sessions", MDBX_CREATE, &bouncer_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_dbi_open(bouncer_sessions) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: mdbx_txn_commit failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(metadata_env);
    metadata_env = NULL;
    return -1;
  }

  metadata_lmdb_available = 1;

  /* Initialize B-tree traversal cache */
  {
    unsigned int slots = feature_int(FEAT_METADATA_CACHE_SLOTS);
    if (slots > 0) {
      /* Round up to next power of 2 */
      unsigned int s = 1;
      while (s < slots) s <<= 1;
      metadata_cache_slots = s;
      metadata_cache = (MDBX_cache_entry_t *)MyCalloc(s, sizeof(MDBX_cache_entry_t));
      metadata_cache_hash = (uint32_t *)MyCalloc(s, sizeof(uint32_t));
      for (unsigned int i = 0; i < s; i++)
        mdbx_cache_init(&metadata_cache[i]);
      log_write(LS_SYSTEM, L_INFO, 0, "metadata: B-tree cache initialized (%u slots)", s);
    }
  }

  log_write(LS_SYSTEM, L_INFO, 0, "metadata: LMDB initialized at %s", dbpath);

  /* Pre-fault database pages into OS page cache */
  rc = mdbx_env_warmup(metadata_env, NULL, MDBX_warmup_default, 0);
  if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE)
    log_write(LS_SYSTEM, L_WARNING, 0, "metadata: mdbx_env_warmup failed: %s",
              mdbx_strerror(rc));

  return 0;
}

/** Get the MDBX environment handle (for bouncer persistence). */
MDBX_env *metadata_get_env(void)
{
  return metadata_env;
}

/** Get the bouncer sessions DBI handle. */
MDBX_dbi metadata_get_bouncer_dbi(void)
{
  return bouncer_dbi;
}

/** Shutdown LMDB metadata storage. */
void metadata_lmdb_shutdown(void)
{
  if (metadata_env) {
    mdbx_dbi_close(metadata_env, bouncer_dbi);
    mdbx_dbi_close(metadata_env, readmarkers_dbi);
    mdbx_dbi_close(metadata_env, metadata_dbi);
    mdbx_env_close(metadata_env);
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
  MDBX_txn *txn;
  MDBX_val mkey, mdata;
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

  rc = mdbx_txn_begin(metadata_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  mkey.iov_base = keybuf;
  mkey.iov_len = keylen;

  {
    MDBX_cache_entry_t *ce = metadata_cache_slot(&mkey);
    if (ce) {
      MDBX_cache_result_t cr = mdbx_cache_get_SingleThreaded(txn, metadata_dbi, &mkey, &mdata, ce);
      rc = cr.errcode;
    } else {
      rc = mdbx_get(txn, metadata_dbi, &mkey, &mdata);
    }
  }
  mdbx_txn_abort(txn);

  if (rc == MDBX_NOTFOUND)
    return 1;
  if (rc != 0)
    return -1;

#ifdef USE_ZSTD
  /* Check if data is compressed and decompress if needed */
  if (is_compressed(mdata.iov_base, mdata.iov_len)) {
    if (decompress_data(mdata.iov_base, mdata.iov_len,
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
  rc = decode_ttl_value(mdata.iov_base, mdata.iov_len, decoded,
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
/** Internal helper for metadata_account_set with explicit timestamp.
 * Pass timestamp=0 for permanent values (no TTL expiry).
 */
static int metadata_account_set_ts(const char *account, const char *key,
                                    const char *value, time_t timestamp)
{
  MDBX_txn *txn;
  MDBX_val mkey, mdata;
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

  rc = mdbx_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.iov_base = keybuf;
  mkey.iov_len = keylen;

  if (value) {
    /* Encode value with timestamp for TTL tracking (0 = permanent) */
    encoded_len = encode_ttl_value(encoded, sizeof(encoded), value, timestamp);
    if (encoded_len < 0) {
      mdbx_txn_abort(txn);
      return -1;
    }

#ifdef USE_ZSTD
    if (compress_data((const unsigned char *)encoded, encoded_len,
                      compressed, sizeof(compressed), &compressed_len) >= 0) {
      mdata.iov_base = compressed;
      mdata.iov_len = compressed_len;
    } else {
      mdata.iov_base = encoded;
      mdata.iov_len = encoded_len;
    }
#else
    mdata.iov_base = encoded;
    mdata.iov_len = encoded_len;
#endif
    rc = mdbx_put(txn, metadata_dbi, &mkey, &mdata, 0);
  } else {
    rc = mdbx_del(txn, metadata_dbi, &mkey, NULL);
    if (rc == MDBX_NOTFOUND)
      rc = 0; /* Deleting non-existent key is OK */
  }

  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
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
  MDBX_txn *txn;
  MDBX_val mkey, mdata;
  char keybuf[ACCOUNTLEN + METADATA_KEY_LEN + 2];
  int keylen;
  int rc;

  if (!metadata_lmdb_available || !account || !key || !raw_value || raw_len == 0)
    return -1;

  keylen = build_lmdb_key(keybuf, sizeof(keybuf), account, key);
  if (keylen < 0)
    return -1;

  rc = mdbx_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.iov_base = keybuf;
  mkey.iov_len = keylen;

  /* Store raw data directly without compression */
  mdata.iov_base = (void *)raw_value;
  mdata.iov_len = raw_len;

  rc = mdbx_put(txn, metadata_dbi, &mkey, &mdata, 0);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
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
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[ACCOUNTLEN + CHANNELLEN + 4];
  int keylen;
  int rc;

  if (!metadata_lmdb_available)
    return -1;

  keylen = build_readmarker_key(keybuf, sizeof(keybuf), account, target);
  if (keylen < 0)
    return -1;

  rc = mdbx_txn_begin(metadata_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.iov_len = keylen;
  key.iov_base = keybuf;

  rc = mdbx_get(txn, readmarkers_dbi, &key, &data);
  mdbx_txn_abort(txn);

  if (rc == MDBX_NOTFOUND)
    return 1;
  if (rc != 0)
    return -1;

  if (data.iov_len >= 32)
    return -1;
  memcpy(timestamp, data.iov_base, data.iov_len);
  timestamp[data.iov_len] = '\0';

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
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[ACCOUNTLEN + CHANNELLEN + 4];
  char existing_ts[32];
  int keylen;
  int rc;

  if (!metadata_lmdb_available)
    return -1;

  keylen = build_readmarker_key(keybuf, sizeof(keybuf), account, target);
  if (keylen < 0)
    return -1;

  rc = mdbx_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  key.iov_len = keylen;
  key.iov_base = keybuf;

  /* Check existing value - only update if new timestamp is greater */
  rc = mdbx_get(txn, readmarkers_dbi, &key, &data);
  if (rc == 0) {
    if (data.iov_len < sizeof(existing_ts)) {
      memcpy(existing_ts, data.iov_base, data.iov_len);
      existing_ts[data.iov_len] = '\0';
      if (strcmp(timestamp, existing_ts) <= 0) {
        mdbx_txn_abort(txn);
        return 1;
      }
    }
  } else if (rc != MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return -1;
  }

  data.iov_len = strlen(timestamp);
  data.iov_base = (void *)timestamp;

  rc = mdbx_put(txn, readmarkers_dbi, &key, &data, 0);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0)
    return -1;

  return 0;
}

/** List all metadata for an account from LMDB.
 * Caller must free the returned list with metadata entries.
 * @param[in] account Account name.
 * @return Head of metadata list, or NULL if none/error.
 */
struct MetadataEntry *metadata_account_list(const char *account)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val mkey, mdata;
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

  rc = mdbx_txn_begin(metadata_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return NULL;

  rc = mdbx_cursor_open(txn, metadata_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return NULL;
  }

  mkey.iov_base = prefix;
  mkey.iov_len = prefixlen;

  rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
  while (rc == 0) {
    /* Check if key still has our prefix */
    if (mkey.iov_len < prefixlen ||
        memcmp(mkey.iov_base, prefix, prefixlen) != 0)
      break;

    /* Extract the metadata key (after prefix) */
    entry = (struct MetadataEntry *)MyMalloc(sizeof(struct MetadataEntry));
    if (!entry)
      break;

    if (mkey.iov_len - prefixlen >= METADATA_KEY_LEN) {
      MyFree(entry);
      break;
    }
    memcpy(entry->key, (char *)mkey.iov_base + prefixlen, mkey.iov_len - prefixlen);
    entry->key[mkey.iov_len - prefixlen] = '\0';

#ifdef USE_ZSTD
    /* Check if data is compressed and decompress if needed */
    if (is_compressed(mdata.iov_base, mdata.iov_len)) {
      if (decompress_data(mdata.iov_base, mdata.iov_len,
                          decompressed, sizeof(decompressed), &decompressed_len) < 0) {
        MyFree(entry);
        rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
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
      entry->value = (char *)MyMalloc(mdata.iov_len + 1);
      if (!entry->value) {
        MyFree(entry);
        break;
      }
      memcpy(entry->value, mdata.iov_base, mdata.iov_len);
      entry->value[mdata.iov_len] = '\0';
    }

    entry->visibility = METADATA_VIS_PUBLIC;
    entry->next = NULL;

    if (tail)
      tail->next = entry;
    else
      head = entry;
    tail = entry;

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

  return head;
}

/** Clear all metadata for an account in LMDB.
 * @param[in] account Account name.
 * @return 0 on success, -1 on error.
 */
int metadata_account_clear(const char *account)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val mkey, mdata;
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

  rc = mdbx_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, metadata_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  mkey.iov_base = prefix;
  mkey.iov_len = prefixlen;

  rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_SET_RANGE);
  while (rc == 0) {
    if (mkey.iov_len < prefixlen ||
        memcmp(mkey.iov_base, prefix, prefixlen) != 0)
      break;

    mdbx_cursor_del(cursor, 0);
    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);

  rc = mdbx_txn_commit(txn);
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
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val mkey, mdata;
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

  rc = mdbx_txn_begin(metadata_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: purge mdbx_txn_begin failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  rc = mdbx_cursor_open(txn, metadata_dbi, &cursor);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: purge mdbx_cursor_open failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_FIRST);
  while (rc == 0) {
    int decode_rc;
    int expired = 0;

#ifdef USE_ZSTD
    if (is_compressed(mdata.iov_base, mdata.iov_len)) {
      if (decompress_data(mdata.iov_base, mdata.iov_len,
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
      decode_rc = decode_ttl_value(mdata.iov_base, mdata.iov_len, decoded,
                                   sizeof(decoded), &timestamp);
      if (decode_rc >= 0 && is_value_expired(timestamp, ttl)) {
        expired = 1;
      }
    }

    if (expired) {
      mdbx_cursor_del(cursor, 0);
      purged++;
    }

    rc = mdbx_cursor_get(cursor, &mkey, &mdata, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);
  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "metadata: purge mdbx_txn_commit failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  if (purged > 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "metadata: purged %d expired cache entries", purged);
  }

  return purged;
}

#else /* !USE_MDBX */

/* Stub implementations when LMDB is not available */
int metadata_lmdb_init(const char *dbpath) { return -1; }
void metadata_lmdb_shutdown(void) { }
int metadata_lmdb_is_available(void) { return 0; }
int metadata_account_get(const char *account, const char *key, char *value) { return -1; }
int metadata_account_set(const char *account, const char *key, const char *value) { return -1; }
int metadata_account_set_permanent(const char *account, const char *key, const char *value) { return -1; }
struct MetadataEntry *metadata_account_list(const char *account) { return NULL; }
int metadata_account_clear(const char *account) { return -1; }
int metadata_account_purge_expired(void) { return -1; }
int metadata_channel_persist(const char *channel, const char *key, const char *value) { return -1; }
struct MetadataEntry *metadata_channel_load(const char *channel) { return NULL; }
int metadata_readmarker_get(const char *account, const char *target, char *timestamp) { (void)account; (void)target; (void)timestamp; return -1; }
int metadata_readmarker_set(const char *account, const char *target, const char *timestamp) { (void)account; (void)target; (void)timestamp; return -1; }

#endif /* USE_MDBX */

/** Initialize the metadata subsystem. */
void metadata_init(void)
{
  /* LMDB init is called separately from ircd.c */
}

/** Shutdown the metadata subsystem. */
void metadata_shutdown(void)
{
#ifdef USE_MDBX
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
  { "bouncer/hold",         FLAG_BNC_HOLDPREF,     0 },
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
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :METADATA Statistics");

#ifdef USE_MDBX
  {
    MDBX_stat stat;
    MDBX_envinfo info;
    MDBX_txn *txn;
    int rc;

    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "M :  LMDB Backend: %s",
               metadata_lmdb_available ? "Available" : "Unavailable");

    if (metadata_lmdb_available && metadata_env) {
      MDBX_stat envstat;

      /* Get environment info */
      rc = mdbx_env_info_ex(metadata_env, NULL, &info, sizeof(info));
      if (rc == MDBX_SUCCESS) {
        send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                   "M :  Geometry: %lu / %lu MB (current/max)",
                   (unsigned long)(info.mi_geo.current / (1024 * 1024)),
                   (unsigned long)(info.mi_geo.upper / (1024 * 1024)));
        send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                   "M :  Readers: %u active",
                   info.mi_numreaders);
      }

      rc = mdbx_env_stat_ex(metadata_env, NULL, &envstat, sizeof(envstat));
      if (rc == MDBX_SUCCESS) {
        size_t total_pages = (info.mi_last_pgno + 1);
        size_t data_pages = envstat.ms_branch_pages + envstat.ms_leaf_pages + envstat.ms_overflow_pages;
        size_t free_pages = total_pages > data_pages ? total_pages - data_pages : 0;
        send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                   "M :  Pages: branch=%lu leaf=%lu overflow=%lu free=%lu",
                   (unsigned long)envstat.ms_branch_pages,
                   (unsigned long)envstat.ms_leaf_pages,
                   (unsigned long)envstat.ms_overflow_pages,
                   (unsigned long)free_pages);
      }

      /* Get database stats */
      rc = mdbx_txn_begin(metadata_env, NULL, MDBX_RDONLY, &txn);
      if (rc == 0) {
        rc = mdbx_dbi_stat(txn, metadata_dbi, &stat, sizeof(stat));
        if (rc == 0) {
          send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                     "M :  Account metadata DB: %lu entries, depth %u",
                     (unsigned long)stat.ms_entries, stat.ms_depth);
        }
        rc = mdbx_dbi_stat(txn, readmarkers_dbi, &stat, sizeof(stat));
        if (rc == 0) {
          send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                     "M :  Read markers DB: %lu entries",
                     (unsigned long)stat.ms_entries);
        }
        mdbx_txn_abort(txn);
      }
    }
  }
#else
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "M :  LMDB Backend: Not compiled in");
#endif

  /* Nefarious is now authoritative for metadata - no X3 dependency */
}
