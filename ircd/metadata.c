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
#include "capab.h"
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

/** Forward decl: free an entire MetadataEntry list.  Defined below, OUTSIDE
 * the USE_ROCKSDB block; declared here so metadata_channel_load (B3), which
 * lives inside that block, can free the transient list it fetches. */
static void free_entry_list(struct MetadataEntry *head);

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

/** Decode the visibility prefix from a just-decoded (post-TTL-strip) row
 * value, per the class rule that metadata_account_set_ts encodes by:
 *   - server-managed keys are always stored bare -> read PRIVATE by rule.
 *   - a "P:" / "*:" prefix on any other row is authoritative for that row.
 *   - a bare non-exempt row is either legacy/pre-A2 data or a TTL-class
 *     public row (bare by design) -> reads PUBLIC.
 * @param[in] key Metadata key (used only for the server-managed check).
 * @param[in] decoded The post-TTL-strip value (NUL-terminated).
 * @param[out] stripped Set to the prefix-stripped value pointer (either
 *             @a decoded itself, or @a decoded + 2).
 * @return The decoded visibility.
 */
static int metadata_decode_visibility(const char *key, char *decoded,
                                      const char **stripped)
{
  if (metadata_key_is_server_managed(key)) {
    *stripped = decoded;
    return METADATA_VIS_PRIVATE;
  }
  if (decoded[0] == 'P' && decoded[1] == ':') {
    *stripped = decoded + 2;
    return METADATA_VIS_PRIVATE;
  }
  if (decoded[0] == '*' && decoded[1] == ':') {
    *stripped = decoded + 2;
    return METADATA_VIS_PUBLIC;
  }
  *stripped = decoded;
  return METADATA_VIS_PUBLIC;
}

/** Get account metadata from LMDB, decoding the visibility prefix.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] value Buffer for the STRIPPED value.
 * @param[in] value_len Size of the value buffer.
 * @param[out] visibility Decoded visibility, or NULL if not needed.
 * @return 0 on success, 1 if not found or expired, -1 on error.
 */
int metadata_account_get_vis(const char *account, const char *key,
                             char *value, size_t value_len, int *visibility)
{
  struct db_val val = { NULL, 0 };
  /* @a account is an account name (<=ACCOUNTLEN) OR, since B1/B2's opaque
   * "#chan\0key" reuse, a channel name (<=CHANNELLEN) — size for the wider
   * of the two so a channel target doesn't silently fail the length check
   * in build_lmdb_key below. */
  char keybuf[CHANNELLEN + METADATA_KEY_LEN + 2];
  char decoded[METADATA_VALUE_LEN];
  const void *raw;
  size_t rawlen;
  const char *stripped;
  int vis;
  int keylen;
  int rc;
  time_t timestamp;
  int ttl;
#ifdef USE_ZSTD
  unsigned char decompressed[METADATA_VALUE_LEN + 64];
  size_t decompressed_len;
#endif

  if (!metadata_lmdb_available || !account || !key || !value || !value_len)
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

  raw = val.base;
  rawlen = val.len;
#ifdef USE_ZSTD
  if (is_compressed(val.base, val.len)) {
    if (decompress_data(val.base, val.len,
                        decompressed, sizeof(decompressed), &decompressed_len) < 0) {
      db_val_free(&val);
      return -1;
    }
    raw = decompressed;
    rawlen = decompressed_len;
  }
#endif

  rc = decode_ttl_value(raw, rawlen, decoded, sizeof(decoded), &timestamp);
  db_val_free(&val);
  if (rc < 0)
    return -1;

  ttl = feature_int(FEAT_METADATA_CACHE_TTL);
  if (is_value_expired(timestamp, ttl)) {
    Debug((DEBUG_DEBUG, "metadata: cached value for %s.%s expired", account, key));
    return 1;
  }

  vis = metadata_decode_visibility(key, decoded, &stripped);
  if (strlen(stripped) >= value_len)
    return -1;
  strcpy(value, stripped);
  if (visibility)
    *visibility = vis;
  return 0;
}

/** Get account metadata from LMDB.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[out] value Buffer for value (at least METADATA_VALUE_LEN).
 * @return 0 on success, 1 if not found or expired, -1 on error.
 */
int metadata_account_get(const char *account, const char *key, char *value)
{
  return metadata_account_get_vis(account, key, value, METADATA_VALUE_LEN, NULL);
}

/** Set account metadata in LMDB.
 * @param[in] account Account name.
 * @param[in] key Metadata key.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE.
 * @return 0 on success, -1 on error.
 */
/** Internal helper for metadata_account_set with explicit timestamp.
 * Pass timestamp=0 for permanent values (no TTL expiry).
 *
 * Store-row encoding (innermost->outermost): [vis prefix][raw value] ->
 * encode_ttl_value -> zstd.  The vis prefix is the ONLY encode site — no
 * other caller anywhere may pre-prefix a value with "P:"/"*:".
 *   - server-managed keys (metadata_key_is_server_managed) are exempt:
 *     always stored bare, regardless of @a visibility.
 *   - non-exempt permanent rows (timestamp==0) are ALWAYS prefixed: "P:"
 *     for private, "*:" for public — every value round-trips byte-exact.
 *   - non-exempt TTL rows (timestamp!=0) are prefixed ONLY when private;
 *     a public TTL row stays bare (preserves the pre-A2 channel-cache and
 *     last_present on-disk shape exactly).
 * The prefixed buffer feeds encode_ttl_value.  (On the crdt-mesh branch the
 * same buffer also feeds the CRDT doc mirror at this chokepoint, so the doc
 * value carries visibility — no doc on this branch.)
 */
static int metadata_account_set_ts(const char *account, const char *key,
                                    const char *value, time_t timestamp,
                                    int visibility)
{
  struct db_writebatch *wb;
  /* @a account: account name (<=ACCOUNTLEN) or, since B1, a channel name
   * (<=CHANNELLEN) passed in by metadata_set_channel's +R persist leg — see
   * the keybuf comment in metadata_account_get_vis above. */
  char keybuf[CHANNELLEN + METADATA_KEY_LEN + 2];
  char prefixed[METADATA_VALUE_LEN + 8]; /* room for the 2-byte P:/ *: prefix */
  char encoded[METADATA_VALUE_LEN + 32]; /* Extra space for TTL prefix */
  const char *stored_value;
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

  stored_value = value;
  if (value && !metadata_key_is_server_managed(key)
      && (timestamp == 0 || visibility == METADATA_VIS_PRIVATE)) {
    const char *pfx = (visibility == METADATA_VIS_PRIVATE) ? "P:" : "*:";
    size_t vlen_raw = strlen(value);

    if (vlen_raw + 2 >= sizeof(prefixed)) {
      db_writebatch_destroy(wb);
      return -1;
    }
    memcpy(prefixed, pfx, 2);
    memcpy(prefixed + 2, value, vlen_raw + 1); /* + NUL */
    stored_value = prefixed;
  }

  if (stored_value) {
    encoded_len = encode_ttl_value(encoded, sizeof(encoded), stored_value, timestamp);
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
int metadata_account_set(const char *account, const char *key, const char *value, int visibility)
{
  return metadata_account_set_ts(account, key, value, CurrentTime, visibility);
}

/** Set account metadata in LMDB with no TTL (timestamp 0 = permanent).
 * Used for user preferences that should survive indefinitely.
 */
int metadata_account_set_permanent(const char *account, const char *key, const char *value, int visibility)
{
  return metadata_account_set_ts(account, key, value, 0, visibility);
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
  /* @a account: account name or (B1) a channel name via the #chan\0key
   * reuse — same widened cap as metadata_account_get_vis/set_ts; this is
   * metadata_channel_load's backing call (metadata-era2-completion §B3),
   * so it must accept a full-length channel name too, even though that
   * caller isn't wired up yet. */
  char prefix[CHANNELLEN + 2];
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
  /* '>' not '>=': a name of EXACTLY CHANNELLEN bytes is valid (buffer is
   * CHANNELLEN + 2, room for the name + KEY_SEP).  The old '>=' silently
   * rejected a full-length (200-char) +R channel — this backs
   * metadata_channel_load, so it must accept a full channel name. */
  if (prefixlen > CHANNELLEN)
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

    {
      const unsigned char *raw = (const unsigned char *)vbuf;
      size_t rawlen = vlen;
      char decoded[METADATA_VALUE_LEN];
      const char *stripped;
      time_t timestamp;
      int ttl;
#ifdef USE_ZSTD
      if (is_compressed((const unsigned char *)vbuf, vlen)) {
        if (decompress_data((const unsigned char *)vbuf, vlen,
                            decompressed, sizeof(decompressed), &decompressed_len) < 0) {
          MyFree(entry);
          continue;
        }
        raw = decompressed;
        rawlen = decompressed_len;
      }
#endif
      /* Strip the TTL wrapper (T<ts>|value) exactly like metadata_account_get,
       * and skip an expired cache row rather than loading a stale value into
       * memory. This function backs metadata_load_account (the eager auth-time
       * memory fill); before this fix it returned the raw "T0|..." store form
       * undecoded, so a reconnecting user saw the wrapper prefix — the
       * s5c_restore regression caught exactly that. Pre-existing gap,
       * independent of the M8 CLEAR fix. */
      if (decode_ttl_value(raw, rawlen, decoded, sizeof(decoded), &timestamp) < 0) {
        MyFree(entry);
        continue;
      }
      ttl = feature_int(FEAT_METADATA_CACHE_TTL);
      if (is_value_expired(timestamp, ttl)) {
        MyFree(entry);
        continue;
      }
      /* Decode the vis prefix (same class rule as metadata_account_get_vis)
       * and store the STRIPPED value — entry->value is never prefixed. */
      entry->visibility = metadata_decode_visibility(entry->key, decoded, &stripped);
      entry->value = (char *)MyMalloc(strlen(stripped) + 1);
      if (!entry->value) { MyFree(entry); break; }
      strcpy(entry->value, stripped);
    }

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
  /* CHANNELLEN, not ACCOUNTLEN: this now also wipes a channel's "#chan\0*"
   * rows (B3 -R hook via metadata_account_clear(chptr->chname)), so the
   * prefix buffer must hold a full channel name (<=CHANNELLEN=200) + KEY_SEP. */
  char prefix[CHANNELLEN + 2];
  int prefixlen;
  int rc;

  if (!metadata_lmdb_available || !account)
    return -1;

  prefixlen = strlen(account);
  /* '>' not '>=' (off-by-one), widened to CHANNELLEN: a full-length +R
   * channel name must clear its store rows, not silently no-op. */
  if (prefixlen > CHANNELLEN)
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

/** Count persisted metadata keys for an account, excluding
 * server-managed keys.  Bounded: stops counting at
 * FEAT_METADATA_MAX_KEYS + 1 so a pathological account cannot make the
 * scan unbounded.  Counts TTL-cached rows too (cheap approximation —
 * decoding every value to check expiry is not worth it; after the
 * commit that stops TTL-downgrading user rows, user rows are
 * effectively all permanent).
 * @param[in] account Account name.
 * @return number of keys (possibly capped at max_keys + 1), or 0 on
 *         storage unavailable/error.
 */
int metadata_account_count_keys(const char *account)
{
  struct db_iter *it;
  /* CHANNELLEN, not ACCOUNTLEN: the account slot now also carries channel
   * names (B1/B3 +R channel metadata), so size + gate on the wider cap. */
  char prefix[CHANNELLEN + 2];
  int prefixlen;
  int max_keys;
  int count = 0;
  int rc;

  if (!metadata_lmdb_available || !account)
    return 0;

  max_keys = feature_int(FEAT_METADATA_MAX_KEYS);
  if (max_keys < 0)
    max_keys = 0;

  prefixlen = strlen(account);
  /* '>' not '>=' (off-by-one), widened to CHANNELLEN — see the sibling
   * length checks in metadata_account_list / metadata_account_clear. */
  if (prefixlen > CHANNELLEN)
    return 0;
  memcpy(prefix, account, prefixlen);
  prefix[prefixlen++] = KEY_SEP;

  it = db_iter_open(metadata_db_env, metadata_cf, /*snap=*/NULL);
  if (!it)
    return 0;

  for (rc = db_iter_seek(it, prefix, (size_t)prefixlen);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen, kpartlen;
    const void *rawkey = db_iter_key(it, &klen);
    char kbuf[METADATA_KEY_LEN];

    if (klen < (size_t)prefixlen ||
        memcmp(rawkey, prefix, (size_t)prefixlen) != 0)
      break;

    /* The iterator key is not NUL-terminated; bound the copy and skip
     * anything that couldn't be a real key rather than misreading
     * adjacent memory. */
    kpartlen = klen - (size_t)prefixlen;
    if (kpartlen >= sizeof(kbuf))
      continue;
    memcpy(kbuf, (const char *)rawkey + prefixlen, kpartlen);
    kbuf[kpartlen] = '\0';

    if (metadata_key_is_server_managed(kbuf))
      continue;

    if (++count > max_keys)
      break;
  }
  db_iter_close(it);

  return count;
}

/** Hydrate a channel's in-memory metadata (chptr->metadata) from the
 * persistent store — the LOAD half of the B3 ±R transition hook
 * (metadata-era2-completion §B3, revived from its long-unwired stub).
 *
 * For every stored "#chan\0key" row NOT already present in chptr->metadata,
 * insert it via metadata_channel_memory_put (memory-only — NO notify: this
 * is hydration, not a change event, the same adjudication as the read-only
 * GET-fallback promotion).  A key already live in memory is left untouched:
 * the +R hook's persist half has just written memory -> store, so an
 * in-memory value is already consistent and may be fresher than the store.
 *
 * At burst/restart chptr->metadata is empty, so this materializes the whole
 * persisted set — the restart-hydration path.  At a live +R it only fills
 * rows the ephemeral memory did not already carry.
 *
 * Frees the transient list metadata_account_list() returns, per that API's
 * caller-frees contract.
 * @param[in] chptr Channel to hydrate.
 */
void metadata_channel_load(struct Channel *chptr)
{
  struct MetadataEntry *list, *entry;

  if (!chptr)
    return;

  list = metadata_account_list(chptr->chname);
  for (entry = list; entry; entry = entry->next) {
    if (!metadata_get_channel(chptr, entry->key))
      metadata_channel_memory_put(chptr, entry->key, entry->value,
                                  entry->visibility);
  }
  free_entry_list(list);
}

/** Purge expired metadata entries from LMDB.
 * Called periodically to enforce METADATA_CACHE_TTL.
 * LEGACY-AGER ONLY as of era-2 (P0-P2; writer survey 2026-07-25): no live
 * code path mints new TTL-stamped rows — every reachable non-NULL write is
 * metadata_account_set_permanent (ts=0). This sweep exists solely to
 * physically reclaim pre-era-2 rows (old last_present, the retired remote
 * channel cache) that read-time expiry only masks. Do NOT add a TTL writer
 * on the assumption this machinery is load-bearing for current data.
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
int metadata_account_get_vis(const char *account, const char *key, char *value, size_t value_len, int *visibility) { (void)account; (void)key; (void)value; (void)value_len; (void)visibility; return -1; }
int metadata_account_set(const char *account, const char *key, const char *value, int visibility) { (void)visibility; return -1; }
int metadata_account_set_permanent(const char *account, const char *key, const char *value, int visibility) { (void)visibility; return -1; }
struct MetadataEntry *metadata_account_list(const char *account) { return NULL; }
int metadata_account_clear(const char *account) { return -1; }
int metadata_account_count_keys(const char *account) { return 0; }
int metadata_account_purge_expired(void) { return -1; }
int metadata_account_foreach_key(void (*cb)(const void *key, size_t klen, void *arg), void *arg) { (void)cb; (void)arg; return -1; }
void metadata_channel_load(struct Channel *chptr) { (void)chptr; }
int metadata_readmarker_get(const char *account, const char *target, char *timestamp) { (void)account; (void)target; (void)timestamp; return -1; }
int metadata_readmarker_set(const char *account, const char *target, const char *timestamp) { (void)account; (void)target; (void)timestamp; return -1; }
int metadata_sync(void) { return -1; }

#endif /* USE_ROCKSDB */

/** Shutdown the metadata subsystem. */
void metadata_shutdown(void)
{
#ifdef USE_ROCKSDB
  metadata_lmdb_shutdown();
#endif
}

/** Create a new metadata entry. */
static struct MetadataEntry *create_entry(const char *key, const char *value)
{
  struct MetadataEntry *entry;

  entry = (struct MetadataEntry *)MyMalloc(sizeof(struct MetadataEntry));
  if (!entry)
    return NULL;

  ircd_strncpy(entry->key, key, METADATA_KEY_LEN);
  entry->key[METADATA_KEY_LEN - 1] = '\0';  /* redundant: strlcpy already NUL-terminates within bounds */

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

/** Insert or update a client's in-memory metadata entry WITHOUT touching
 * the persistent store or the CRDT doc — the pure-memory half of
 * metadata_set_client(), split out so read paths (GET-fallback promotion,
 * the lazy fill below) can cache a value they already fetched from the
 * store without re-entering the write chokepoint.  Re-entering it is
 * exactly the "reads stop writing" hole this closes: promoting a GET
 * result used to call metadata_set_client(), which re-persists the row as
 * permanent and re-mints a doc op — upgrading a TTL cache row into
 * permanent mesh state on a mere read.
 *
 * No mode-flag sync either (metadata_set_client's SetFlag/ClrFlag dance) —
 * this is a cache fill, not a semantic SET, matching the existing
 * lazy-fill precedent this function replaces below.
 *
 * @param[in] cptr Client whose in-memory cache gets the entry.
 * @param[in] key Key name.
 * @param[in] value Value to cache (non-NULL — promotion of a found value,
 *                   never a delete).
 * @param[in] visibility Visibility level, decoded from the store row.
 * @return The new-or-updated entry, or NULL on bad args / allocation failure.
 */
struct MetadataEntry *metadata_memory_put(struct Client *cptr, const char *key,
                                          const char *value, int visibility)
{
  struct MetadataEntry *entry;

  if (!cptr || !key || !value)
    return NULL;

  for (entry = cli_metadata(cptr); entry; entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      break;
  }

  if (entry) {
    char *newval = (char *)MyMalloc(strlen(value) + 1);
    if (!newval)
      return NULL;
    strcpy(newval, value);
    if (entry->value)
      MyFree(entry->value);
    entry->value = newval;
    entry->visibility = visibility;
  } else {
    entry = create_entry(key, value);
    if (!entry)
      return NULL;
    entry->visibility = visibility;
    entry->next = cli_metadata(cptr);
    cli_metadata(cptr) = entry;
  }

  return entry;
}

/** Insert or update a channel's in-memory metadata entry WITHOUT touching
 * the persistent store or the CRDT doc — the channel counterpart to
 * metadata_memory_put().  Factored out of metadata_set_channel()'s body so
 * the list-handling (find-or-create in chptr->metadata, update value +
 * visibility) lives in exactly one place: metadata_set_channel() calls this
 * for its memory half, then does its own (+R-gated) persist leg.  Also the
 * promotion primitive for the GET-fallback cache fill (m_metadata.c) — a
 * read must not persist or doc-mint, so it calls this, never
 * metadata_set_channel() directly, mirroring metadata_memory_put's role in
 * the user GET-fallback.
 *
 * @param[in] chptr Channel whose in-memory cache gets the entry.
 * @param[in] key Key name.
 * @param[in] value Value to cache (non-NULL — a delete goes through
 *                   metadata_channel_memory_del()).
 * @param[in] visibility Visibility level.
 * @return The new-or-updated entry, or NULL on bad args / allocation failure.
 */
struct MetadataEntry *metadata_channel_memory_put(struct Channel *chptr, const char *key,
                                                   const char *value, int visibility)
{
  struct MetadataEntry *entry;

  if (!chptr || !key || !value)
    return NULL;

  for (entry = chptr->metadata; entry; entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0)
      break;
  }

  if (entry) {
    char *newval = (char *)MyMalloc(strlen(value) + 1);
    if (!newval)
      return NULL;
    strcpy(newval, value);
    if (entry->value)
      MyFree(entry->value);
    entry->value = newval;
    entry->visibility = visibility;
  } else {
    entry = create_entry(key, value);
    if (!entry)
      return NULL;
    entry->visibility = visibility;
    entry->next = chptr->metadata;
    chptr->metadata = entry;
  }

  return entry;
}

/** Remove a channel's in-memory metadata entry only — no store write, no doc
 * mirror.  The delete counterpart to metadata_channel_memory_put(): the
 * memory half metadata_set_channel() calls before its own (+R-gated)
 * persist leg. Mirrors metadata_memory_del()'s shape for chptr->metadata.
 * @param[in] chptr Channel whose in-memory cache loses the entry.
 * @param[in] key Key name to remove.
 * @return 1 if an entry was removed, 0 if none matched / bad args.
 */
int metadata_channel_memory_del(struct Channel *chptr, const char *key)
{
  struct MetadataEntry *entry, *prev = NULL;

  if (!chptr || !key)
    return 0;

  for (entry = chptr->metadata; entry; prev = entry, entry = entry->next) {
    if (ircd_strcmp(entry->key, key) == 0) {
      if (prev)
        prev->next = entry->next;
      else
        chptr->metadata = entry->next;
      metadata_free_entry(entry);
      return 1;
    }
  }
  return 0;
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
   * from mdbx on first access.  Create the in-memory entry directly via
   * metadata_memory_put (don't call metadata_set_client which would
   * re-persist to mdbx and re-mint a doc op).
   * NOTE: this lazy fill is now a BACKSTOP, not the primary restore path.
   * P1 A3 (2026-07-24) made metadata_load_account fire at every account-
   * attach site: the register_user chokepoint (s_user.c — before the
   * MyConnect/remote split, covering pre-reg SASL, IAuth D-with-account,
   * WEBIRC, pre-reg REGISTER, and remote N-burst intros) plus residues at
   * the SVSMODE/server MODE +r stamp (set_user_mode, s_user.c), post-reg
   * REGISTER (m_register.c), mesh materialization (crdt_shadow.c), and
   * bouncer ghost restore (bouncer_session.c) — on top of the original
   * four call sites (m_account.c's AC R/M/legacy-AC and LOC-reply
   * branches, sasl_auth.c's post-reg reauth). This path now only
   * backstops an attach flow that predates that sweep or one we missed.
   * It is not a resurrection vector: METADATA CLEAR now broadcasts a
   * per-key unset that removes the store row on every node (see
   * metadata_cmd_clear), so a cleared key has nothing left to promote.
   * (clocktest M8 finding, 2026-07-24.) */
  if (cli_user(cptr) && cli_user(cptr)->account[0] && key[0] != '$'
      && metadata_lmdb_is_available()) {
    char value[METADATA_VALUE_LEN];
    int vis = METADATA_VIS_PUBLIC;
    if (metadata_account_get_vis(cli_user(cptr)->account, key, value,
                                 sizeof(value), &vis) == 0) {
      entry = metadata_memory_put(cptr, key, value, vis);
      if (entry)
        return entry;
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
      metadata_account_set_permanent(account, key, value, visibility);
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

    /* Delete from LMDB for logged-in users (visibility ignored — no value to encode) */
    if (account && metadata_lmdb_is_available()) {
      metadata_account_set(account, key, NULL, visibility);
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

void metadata_burst_self_to_client(struct Client *to)
{
  struct MetadataEntry *md;
  unsigned int seq;

  if (!to || !MyConnect(to))
    return;
  if (!CapActive(to, CAP_DRAFT_METADATA2))
    return;

  md = metadata_list_client(to);
  if (!md)
    return;

  /* Manual batch open with target parameter (send_batch_start doesn't
   * support the per-batch-type target arg the metadata spec requires). */
  seq = con_batch_seq(cli_connect(to))++;
  ircd_snprintf(NULL, cli_batch_id(to),
                sizeof(con_batch_id(cli_connect(to))),
                "%s%u", cli_yxx(to), seq);

  sendrawto_one(to, ":%s BATCH +%s metadata %s",
                cli_name(&me), cli_batch_id(to), cli_name(to));
  while (md) {
    sendrawto_one(to, "@batch=%s :%s METADATA %s %s %s :%s",
                  cli_batch_id(to), cli_name(&me),
                  cli_name(to), md->key,
                  get_visibility_str(md), md->value);
    md = md->next;
  }
  send_batch_end(to);
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
 * Keys under these prefixes (currently just draft/persistence/...) are
 * written exclusively by server-side logic and are exempt from the
 * user-facing key-count budget.  Direct METADATA SET from a client is
 * refused for keys matching these prefixes.
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

/** Load metadata from LMDB for a logged-in user.  REPLACES cli_metadata
 * wholesale from the store — a full replace, so redundant/double calls
 * are idempotent (wasted store iteration only, never wrong data).
 * Self-guards on metadata_lmdb_is_available().
 * Called at every point an account attaches to a client (P1 A3,
 * 2026-07-24): the register_user chokepoint (s_user.c — pre-reg SASL,
 * IAuth D-with-account, WEBIRC account, pre-reg REGISTER, and remote
 * N-burst intros), the SVSMODE/server MODE +r stamp in set_user_mode
 * (s_user.c), post-reg REGISTER on an already-registered client
 * (m_register.c), S2S ACCOUNT R/M/legacy-AC and the pre-reg LOC reply
 * (m_account.c), SASL reauth on an already-registered client
 * (sasl_auth.c), mesh materialization of a remote user (crdt_shadow.c),
 * and bouncer ghost restore at startup (bouncer_session.c).
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

/** Set metadata for a channel — THE persist chokepoint for +R channel
 * metadata (B1).
 *
 * Memory half: delegates to metadata_channel_memory_put()/
 * metadata_channel_memory_del() (find-or-create/update, or remove) so the
 * list-handling lives in exactly one place, shared with the GET-fallback
 * cache-fill promotion in m_metadata.c.
 *
 * Persist half: iff the channel is registered (MODE_REGISTERED), the
 * change also goes through metadata_account_set_permanent(chptr->chname,
 * key, value, visibility) — chptr->chname in the account slot reuses the
 * whole P1 machinery as-is (opaque "#chan\0key" store row, A2
 * visibility-prefixed): value!=NULL sets/updates the permanent row;
 * value==NULL deletes it. Not +R: memory only, unchanged.
 *
 * Runs on relayed applies too (ms_metadata, m_metadata.c): every node
 * persists its own store row from the applied value, which is what makes
 * +R rows restart-durable on every node of a legacy topology.  (On
 * crdt-mesh the same chokepoint also doc-mirrors at the origin only,
 * under ms_metadata's suspend bracket — no doc on this branch.)
 *
 * @param[in] chptr Channel to set metadata on.
 * @param[in] key Key name.
 * @param[in] value Value to set (NULL to delete).
 * @param[in] visibility Visibility level (METADATA_VIS_PUBLIC or METADATA_VIS_PRIVATE).
 * @return 0 on success, -1 on error.
 */
int metadata_set_channel(struct Channel *chptr, const char *key, const char *value, int visibility)
{
  if (!chptr || !key)
    return -1;

  if (value) {
    if (!metadata_channel_memory_put(chptr, key, value, visibility))
      return -1;
  } else {
    metadata_channel_memory_del(chptr, key);
  }

  /* +R persist leg — see function header. */
  if ((chptr->mode.mode & MODE_REGISTERED) && metadata_lmdb_is_available())
    metadata_account_set_permanent(chptr->chname, key, value, visibility);

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

  ircd_strncpy(sub->key, key, METADATA_KEY_LEN);
  sub->key[METADATA_KEY_LEN - 1] = '\0';  /* redundant: strlcpy already NUL-terminates within bounds */
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

/* MDQ removed entirely (protocol + responder) - Nefarious answers GET
 * from local LMDB only */

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
