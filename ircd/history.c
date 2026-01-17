/*
 * IRC - Internet Relay Chat, ircd/history.c
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
 * @brief Message history storage using LMDB.
 *
 * LMDB (Lightning Memory-Mapped Database) provides zero-copy reads
 * and MVCC for lock-free concurrent reads. Perfect for chathistory
 * where reads vastly outnumber writes.
 *
 * Key structure: "target\0timestamp\0msgid"
 * This allows efficient range queries by target and timestamp.
 *
 * Implements storage backend for IRCv3 draft/chathistory extension.
 * Specification: https://ircv3.net/specs/extensions/chathistory
 */
#include "config.h"

#ifdef USE_LMDB

#include "history.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "s_debug.h"
#include "s_stats.h"

#include <lmdb.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

/** LMDB environment */
static MDB_env *history_env = NULL;

/** Main message database */
static MDB_dbi history_dbi;

/** Secondary index: msgid -> timestamp (for msgid lookups) */
static MDB_dbi history_msgid_dbi;

/** Target tracking database for TARGETS query */
static MDB_dbi history_targets_dbi;

/** Read markers database (IRCv3 draft/read-marker) */
static MDB_dbi history_readmarkers_dbi;

/** Flag indicating if history is available */
static int history_available = 0;

/** Maximum database size (1GB default, configurable) */
static size_t history_map_size = 1UL * 1024 * 1024 * 1024;

/** Maximum number of named databases */
#define HISTORY_MAX_DBS 5

/** Key separator character */
#define KEY_SEP '\0'

/** Maximum value buffer size for serialization */
#define HISTORY_VALUE_BUFSIZE 1024

/** Message type names for serialization */
static const char *history_type_names[] = {
  "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
  "KICK", "MODE", "TOPIC", "TAGMSG"
};

/* Forward declaration for emergency eviction (used in history_store_message) */
static int history_emergency_evict(void);

/** Build a lookup key from target and timestamp.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] target Channel or nick.
 * @param[in] timestamp Unix timestamp (or NULL for just target).
 * @param[in] msgid Message ID (or NULL).
 * @return Length of key.
 */
static int build_key(char *key, int keysize, const char *target,
                     const char *timestamp, const char *msgid)
{
  int pos = 0;
  int len;

  /* Copy target */
  len = strlen(target);
  if (pos + len + 1 >= keysize) return -1;
  memcpy(key + pos, target, len);
  pos += len;
  key[pos++] = KEY_SEP;

  /* Copy timestamp if provided */
  if (timestamp) {
    len = strlen(timestamp);
    if (pos + len + 1 >= keysize) return -1;
    memcpy(key + pos, timestamp, len);
    pos += len;
    key[pos++] = KEY_SEP;

    /* Copy msgid if provided */
    if (msgid) {
      len = strlen(msgid);
      if (pos + len >= keysize) return -1;
      memcpy(key + pos, msgid, len);
      pos += len;
    }
  }

  return pos;
}

/** Serialize a message to a buffer.
 * Format: type|sender|account|content
 * @param[out] buf Output buffer.
 * @param[in] bufsize Size of output buffer.
 * @param[in] type Message type.
 * @param[in] sender Sender mask.
 * @param[in] account Account name (may be NULL).
 * @param[in] content Message content (may be NULL).
 * @return Length of serialized data.
 */
static int serialize_message(char *buf, int bufsize,
                             enum HistoryMessageType type,
                             const char *sender, const char *account,
                             const char *content)
{
  return ircd_snprintf(0, buf, bufsize, "%d|%s|%s|%s",
                       (int)type,
                       sender ? sender : "",
                       account ? account : "",
                       content ? content : "");
}

/** Deserialize a message from a buffer.
 * @param[in] data Serialized data (possibly compressed).
 * @param[in] datalen Length of data.
 * @param[out] msg Message structure to fill.
 * @return 0 on success, -1 on error.
 */
static int deserialize_message(const char *data, int datalen,
                               struct HistoryMessage *msg)
{
  const char *p, *end;
  char *field;
  int type;
#ifdef USE_ZSTD
  char decompressed[HISTORY_VALUE_BUFSIZE];
  size_t decompressed_len;

  /* Check if data is compressed and decompress if needed */
  if (is_compressed((const unsigned char *)data, datalen)) {
    if (decompress_data((const unsigned char *)data, datalen,
                        (unsigned char *)decompressed, sizeof(decompressed),
                        &decompressed_len) < 0) {
      return -1;
    }
    data = decompressed;
    datalen = decompressed_len;
  }
#endif

  p = data;
  end = data + datalen;

  /* Parse type */
  field = strchr(p, '|');
  if (!field || field >= end) return -1;
  type = atoi(p);
  if (type < 0 || type > HISTORY_TAGMSG) return -1;
  msg->type = (enum HistoryMessageType)type;
  p = field + 1;

  /* Parse sender */
  field = strchr(p, '|');
  if (!field || field >= end) return -1;
  if ((size_t)(field - p) >= sizeof(msg->sender)) return -1;
  memcpy(msg->sender, p, field - p);
  msg->sender[field - p] = '\0';
  p = field + 1;

  /* Parse account */
  field = strchr(p, '|');
  if (!field || field >= end) return -1;
  if ((size_t)(field - p) >= sizeof(msg->account)) return -1;
  memcpy(msg->account, p, field - p);
  msg->account[field - p] = '\0';
  p = field + 1;

  /* Parse content (rest of string) */
  if ((size_t)(end - p) >= sizeof(msg->content)) return -1;
  memcpy(msg->content, p, end - p);
  msg->content[end - p] = '\0';

  return 0;
}

/** Parse target and timestamp from a key.
 * @param[in] key Key data.
 * @param[in] keylen Key length.
 * @param[out] target Output for target (at least CHANNELLEN+1).
 * @param[out] timestamp Output for timestamp (at least HISTORY_TIMESTAMP_LEN).
 * @param[out] msgid Output for msgid (at least HISTORY_MSGID_LEN).
 * @return 0 on success, -1 on error.
 */
static int parse_key(const char *key, int keylen,
                     char *target, char *timestamp, char *msgid)
{
  const char *p, *end;
  const char *sep1, *sep2;

  p = key;
  end = key + keylen;

  /* Find first separator (end of target) */
  sep1 = memchr(p, KEY_SEP, end - p);
  if (!sep1) return -1;

  if (target) {
    if ((size_t)(sep1 - p) > CHANNELLEN) return -1;
    memcpy(target, p, sep1 - p);
    target[sep1 - p] = '\0';
  }
  p = sep1 + 1;

  /* Find second separator (end of timestamp) */
  sep2 = memchr(p, KEY_SEP, end - p);
  if (sep2) {
    if (timestamp) {
      if ((size_t)(sep2 - p) >= HISTORY_TIMESTAMP_LEN) return -1;
      memcpy(timestamp, p, sep2 - p);
      timestamp[sep2 - p] = '\0';
    }
    p = sep2 + 1;

    if (msgid) {
      if ((size_t)(end - p) >= HISTORY_MSGID_LEN) return -1;
      memcpy(msgid, p, end - p);
      msgid[end - p] = '\0';
    }
  } else {
    /* No msgid in key */
    if (timestamp) {
      if ((size_t)(end - p) >= HISTORY_TIMESTAMP_LEN) return -1;
      memcpy(timestamp, p, end - p);
      timestamp[end - p] = '\0';
    }
    if (msgid)
      msgid[0] = '\0';
  }

  return 0;
}

/*
 * Timestamp Conversion Functions
 *
 * Internal storage and S2S use Unix timestamps (seconds.milliseconds).
 * Client-facing @time= tags use ISO 8601 per IRCv3 spec.
 */

char *history_format_timestamp(char *buf, size_t buflen)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);
  ircd_snprintf(0, buf, buflen, "%lu.%03lu",
                (unsigned long)tv.tv_sec,
                (unsigned long)(tv.tv_usec / 1000));
  return buf;
}

int history_unix_to_iso(const char *unix_ts, char *iso_buf, size_t iso_buflen)
{
  unsigned long secs;
  unsigned int millis = 0;
  char *dot;
  time_t t;
  struct tm tm;

  if (!unix_ts || !iso_buf || iso_buflen < 25)
    return -1;

  secs = strtoul(unix_ts, &dot, 10);
  if (dot && *dot == '.') {
    millis = strtoul(dot + 1, NULL, 10);
    /* Ensure exactly 3 digits */
    if (millis > 999) millis = 999;
  }

  t = (time_t)secs;
  if (!gmtime_r(&t, &tm))
    return -1;

  ircd_snprintf(0, iso_buf, iso_buflen,
                "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, millis);
  return 0;
}

int history_iso_to_unix(const char *iso_ts, char *unix_buf, size_t unix_buflen)
{
  struct tm tm;
  time_t t;
  unsigned int millis = 0;
  const char *p;
  char *end;

  if (!iso_ts || !unix_buf || unix_buflen < 15)
    return -1;

  /* Parse ISO 8601: YYYY-MM-DDThh:mm:ss[.sss]Z */
  memset(&tm, 0, sizeof(tm));

  /* Parse date */
  tm.tm_year = strtol(iso_ts, &end, 10) - 1900;
  if (!end || *end != '-') return -1;
  p = end + 1;

  tm.tm_mon = strtol(p, &end, 10) - 1;
  if (!end || *end != '-') return -1;
  p = end + 1;

  tm.tm_mday = strtol(p, &end, 10);
  if (!end || *end != 'T') return -1;
  p = end + 1;

  /* Parse time */
  tm.tm_hour = strtol(p, &end, 10);
  if (!end || *end != ':') return -1;
  p = end + 1;

  tm.tm_min = strtol(p, &end, 10);
  if (!end || *end != ':') return -1;
  p = end + 1;

  tm.tm_sec = strtol(p, &end, 10);

  /* Parse optional milliseconds */
  if (end && *end == '.') {
    millis = strtoul(end + 1, &end, 10);
    if (millis > 999) millis = 999;
  }

  /* Convert to Unix time */
  t = timegm(&tm);
  if (t == (time_t)-1)
    return -1;

  ircd_snprintf(0, unix_buf, unix_buflen, "%lu.%03u",
                (unsigned long)t, millis);
  return 0;
}

int history_init(const char *dbpath)
{
  MDB_txn *txn;
  int rc;

  if (history_available)
    return 0; /* Already initialized */

  /* Create LMDB environment */
  rc = mdb_env_create(&history_env);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_env_create failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  /* Set maximum number of databases */
  rc = mdb_env_set_maxdbs(history_env, HISTORY_MAX_DBS);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_env_set_maxdbs failed: %s",
              mdb_strerror(rc));
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Set map size (configurable, default 1GB) */
  rc = mdb_env_set_mapsize(history_env, history_map_size);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_env_set_mapsize failed: %s",
              mdb_strerror(rc));
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open environment */
  rc = mdb_env_open(history_env, dbpath, 0, 0644);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_env_open(%s) failed: %s",
              dbpath, mdb_strerror(rc));
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open databases in a transaction */
  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_txn_begin failed: %s",
              mdb_strerror(rc));
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open main message database */
  rc = mdb_dbi_open(txn, "messages", MDB_CREATE, &history_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_dbi_open(messages) failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open msgid index database */
  rc = mdb_dbi_open(txn, "msgid_index", MDB_CREATE, &history_msgid_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_dbi_open(msgid_index) failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open targets database */
  rc = mdb_dbi_open(txn, "targets", MDB_CREATE, &history_targets_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_dbi_open(targets) failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open readmarkers database */
  rc = mdb_dbi_open(txn, "readmarkers", MDB_CREATE, &history_readmarkers_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_dbi_open(readmarkers) failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdb_txn_commit failed: %s",
              mdb_strerror(rc));
    mdb_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  history_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "history: LMDB initialized at %s", dbpath);

  return 0;
}

void history_shutdown(void)
{
  if (!history_available)
    return;

  mdb_dbi_close(history_env, history_dbi);
  mdb_dbi_close(history_env, history_msgid_dbi);
  mdb_dbi_close(history_env, history_targets_dbi);
  mdb_dbi_close(history_env, history_readmarkers_dbi);
  mdb_env_close(history_env);
  history_env = NULL;
  history_available = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "history: LMDB shutdown complete");
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *sender,
                          const char *account, enum HistoryMessageType type,
                          const char *content)
{
  MDB_txn *txn;
  MDB_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char valbuf[HISTORY_VALUE_BUFSIZE];
  int keylen, vallen;
  int rc;
  int retry = 0;
#ifdef USE_ZSTD
  unsigned char compressed[HISTORY_VALUE_BUFSIZE + 64];
  size_t compressed_len;
#endif

  if (!history_available)
    return -1;

  /* Build key: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0)
    return -1;

  /* Log the key being stored (with nulls as dots) */
  {
    char key_preview[128];
    int preview_len = keylen < 120 ? keylen : 120;
    memcpy(key_preview, keybuf, preview_len);
    key_preview[preview_len] = '\0';
    for (int i = 0; i < preview_len; i++) {
      if (key_preview[i] == '\0') key_preview[i] = '.';
    }
    log_write(LS_SYSTEM, L_INFO, 0, "history_store_message: storing key='%s' (len=%d) target='%s' ts='%s' msgid='%s'",
              key_preview, keylen, target, timestamp, msgid);
  }

  /* Serialize value */
  vallen = serialize_message(valbuf, sizeof(valbuf), type, sender, account, content);
  if (vallen < 0)
    return -1;

store_retry:
  /* Begin write transaction */
  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_txn_begin failed: %s", mdb_strerror(rc)));
    return -1;
  }

  /* Store message (with optional compression) */
  key.mv_size = keylen;
  key.mv_data = keybuf;
#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    compressed, sizeof(compressed), &compressed_len) >= 0) {
    data.mv_size = compressed_len;
    data.mv_data = compressed;
  } else {
    data.mv_size = vallen;
    data.mv_data = valbuf;
  }
#else
  data.mv_size = vallen;
  data.mv_data = valbuf;
#endif

  rc = mdb_put(txn, history_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_put failed: %s", mdb_strerror(rc)));
    mdb_txn_abort(txn);
    if (rc == MDB_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    return -1;
  }

  /* Store msgid -> target\0timestamp index */
  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;
  /* Value is target\0timestamp */
  {
    int idx_keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, NULL);
    data.mv_size = idx_keylen;
    data.mv_data = keybuf;
  }

  rc = mdb_put(txn, history_msgid_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_put(msgid) failed: %s", mdb_strerror(rc)));
    mdb_txn_abort(txn);
    if (rc == MDB_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    return -1;
  }

  /* Update target's last message timestamp */
  key.mv_size = strlen(target);
  key.mv_data = (void *)target;
  data.mv_size = strlen(timestamp);
  data.mv_data = (void *)timestamp;

  rc = mdb_put(txn, history_targets_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_put(target) failed: %s", mdb_strerror(rc)));
    mdb_txn_abort(txn);
    if (rc == MDB_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_txn_commit failed: %s", mdb_strerror(rc)));
    if (rc == MDB_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    return -1;
  }

  return 0;
}

int history_has_msgid(const char *msgid)
{
  MDB_txn *txn;
  MDB_val key, data;
  int rc;

  if (!history_available)
    return -1;

  if (!msgid || !msgid[0])
    return 0;

  /* Begin read transaction */
  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  /* Look up msgid in the msgid index */
  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;

  rc = mdb_get(txn, history_msgid_dbi, &key, &data);
  mdb_txn_abort(txn);

  if (rc == 0)
    return 1;  /* Found */
  if (rc == MDB_NOTFOUND)
    return 0;  /* Not found */
  return -1;   /* Error */
}

/** Internal query implementation with direction support.
 * @param[in] target Channel or nick to query.
 * @param[in] start_key Starting key for cursor.
 * @param[in] start_keylen Length of starting key.
 * @param[in] direction Query direction.
 * @param[in] limit Maximum messages to return.
 * @param[out] result Pointer to result list head.
 * @return Number of messages returned, or -1 on error.
 */
static int history_query_internal(const char *target,
                                  const char *start_key, int start_keylen,
                                  enum HistoryDirection direction,
                                  int limit, struct HistoryMessage **result)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, data;
  struct HistoryMessage *head = NULL, *tail = NULL, *msg;
  char target_prefix[CHANNELLEN + 2];
  int target_prefix_len;
  int count = 0;
  int rc;
  MDB_cursor_op op;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Build target prefix for boundary checking */
  target_prefix_len = ircd_snprintf(0, target_prefix, sizeof(target_prefix),
                                    "%s%c", target, KEY_SEP);

  /* Begin read transaction */
  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Position cursor */
  key.mv_size = start_keylen;
  key.mv_data = (void *)start_key;

  if (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST) {
    /* For BEFORE/LATEST, we want to go backwards from the reference */
    rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: SET_RANGE rc=%d (%s)",
              rc, rc == 0 ? "found" : (rc == MDB_NOTFOUND ? "not found" : mdb_strerror(rc)));
    if (rc == MDB_NOTFOUND) {
      /* Position at last entry */
      rc = mdb_cursor_get(cursor, &key, &data, MDB_LAST);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: MDB_LAST rc=%d", rc);
    } else if (rc == 0) {
      /* Move back one since SET_RANGE gives us >= */
      rc = mdb_cursor_get(cursor, &key, &data, MDB_PREV);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: MDB_PREV rc=%d", rc);
    }
    op = MDB_PREV;
  } else {
    /* For AFTER, go forwards from AFTER the reference */
    rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: AFTER SET_RANGE rc=%d", rc);
    /* Skip any messages that match the reference timestamp prefix
     * (AFTER means strictly after, not including the reference) */
    while (rc == 0 && key.mv_size >= (size_t)start_keylen &&
           memcmp(key.mv_data, start_key, start_keylen) == 0) {
      rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
    }
    op = MDB_NEXT;
  }

  /* Log cursor position after positioning */
  if (rc == 0) {
    char key_preview[64];
    size_t preview_len = key.mv_size < 60 ? key.mv_size : 60;
    memcpy(key_preview, key.mv_data, preview_len);
    key_preview[preview_len] = '\0';
    /* Replace null bytes with dots for display */
    for (size_t i = 0; i < preview_len; i++) {
      if (key_preview[i] == '\0') key_preview[i] = '.';
    }
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: positioned at key='%s' (len=%zu)",
              key_preview, key.mv_size);
  } else {
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: no position, rc=%d", rc);
  }

  /* Iterate and collect messages */
  while (rc == 0 && count < limit) {
    /* Check if still in target's range */
    if (key.mv_size < (size_t)target_prefix_len ||
        memcmp(key.mv_data, target_prefix, target_prefix_len) != 0) {
      /* Outside target range */
      char key_preview[64];
      size_t preview_len = key.mv_size < 60 ? key.mv_size : 60;
      memcpy(key_preview, key.mv_data, preview_len);
      key_preview[preview_len] = '\0';
      for (size_t i = 0; i < preview_len; i++) {
        if (key_preview[i] == '\0') key_preview[i] = '.';
      }
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: key='%s' outside target range, breaking",
                key_preview);
      if (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST)
        break;
      /* For AFTER, move to next */
      rc = mdb_cursor_get(cursor, &key, &data, op);
      continue;
    }

    /* Allocate message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    /* Parse key to get target, timestamp, msgid */
    if (parse_key(key.mv_data, key.mv_size,
                  msg->target, msg->timestamp, msg->msgid) != 0) {
      MyFree(msg);
      rc = mdb_cursor_get(cursor, &key, &data, op);
      continue;
    }

    /* Parse value */
    if (deserialize_message(data.mv_data, data.mv_size, msg) != 0) {
      MyFree(msg);
      rc = mdb_cursor_get(cursor, &key, &data, op);
      continue;
    }

    /* Add to list */
    msg->next = NULL;
    if (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST) {
      /* Prepend (we're going backwards) */
      msg->next = head;
      head = msg;
      if (!tail)
        tail = msg;
    } else {
      /* Append */
      if (tail)
        tail->next = msg;
      else
        head = msg;
      tail = msg;
    }
    count++;

    rc = mdb_cursor_get(cursor, &key, &data, op);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: returning count=%d for target='%s'",
            count, target);

  *result = head;
  return count;
}

int history_query_before(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;

  *result = NULL;

  /* Convert reference to Unix timestamp format */
  if (ref_type == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0; /* msgid not found, return empty */
    reference = timestamp;
  } else if (ref_type == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference, timestamp, sizeof(timestamp)) == 0)
      reference = timestamp;
    /* If conversion fails, assume it's already Unix format */
  }

  /* Build starting key */
  keylen = build_key(keybuf, sizeof(keybuf), target, reference, NULL);
  if (keylen < 0)
    return -1;

  log_write(LS_SYSTEM, L_INFO, 0, "history_query_before: target='%s' timestamp='%s' keylen=%d",
            target, reference, keylen);

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_BEFORE, limit, result);
}

int history_query_after(const char *target, enum HistoryRefType ref_type,
                        const char *reference, int limit,
                        struct HistoryMessage **result)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;

  *result = NULL;

  /* Convert reference to Unix timestamp format */
  if (ref_type == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0;
    reference = timestamp;
  } else if (ref_type == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference, timestamp, sizeof(timestamp)) == 0)
      reference = timestamp;
    /* If conversion fails, assume it's already Unix format */
  }

  keylen = build_key(keybuf, sizeof(keybuf), target, reference, NULL);
  if (keylen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_AFTER, limit, result);
}

int history_query_latest(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;

  *result = NULL;

  if (ref_type == HISTORY_REF_NONE) {
    /* LATEST * - start from end of target's range */
    /* Use a Unix timestamp far in the future (year 2999) */
    keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
  } else {
    /* Convert reference to Unix timestamp format */
    if (ref_type == HISTORY_REF_MSGID) {
      if (history_msgid_to_timestamp(reference, timestamp) != 0)
        return 0;
      reference = timestamp;
    } else if (ref_type == HISTORY_REF_TIMESTAMP) {
      /* Client sends ISO 8601, convert to Unix for lookup */
      if (history_iso_to_unix(reference, timestamp, sizeof(timestamp)) == 0)
        reference = timestamp;
      /* If conversion fails, assume it's already Unix format */
    }
    keylen = build_key(keybuf, sizeof(keybuf), target, reference, NULL);
  }

  if (keylen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_LATEST, limit, result);
}

int history_query_around(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  struct HistoryMessage *before = NULL, *after = NULL, *ref_msg = NULL;
  int half = limit / 2;
  int count_before, count_after, count_ref = 0;

  *result = NULL;

  /* For msgid references, also look up the reference message itself.
   * BEFORE and AFTER both exclude the reference, but AROUND should include it.
   */
  if (ref_type == HISTORY_REF_MSGID) {
    int rc = history_lookup_message(target, reference, &ref_msg);
    if (rc == 0 && ref_msg) {
      count_ref = 1;
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_around: found reference msg at ts=%s",
                ref_msg->timestamp);
    }
  }

  /* Get messages before reference */
  count_before = history_query_before(target, ref_type, reference, half, &before);
  if (count_before < 0) {
    history_free_messages(before);
    history_free_messages(ref_msg);
    return -1;
  }

  /* Get messages after reference (reduce limit by ref_msg if found) */
  count_after = history_query_after(target, ref_type, reference,
                                    limit - count_before - count_ref, &after);
  if (count_after < 0) {
    history_free_messages(before);
    history_free_messages(ref_msg);
    history_free_messages(after);
    return -1;
  }

  /* Concatenate lists: before + ref_msg + after */
  if (before) {
    struct HistoryMessage *tail = before;
    while (tail->next)
      tail = tail->next;
    if (ref_msg) {
      tail->next = ref_msg;
      ref_msg->next = after;
    } else {
      tail->next = after;
    }
    *result = before;
  } else if (ref_msg) {
    ref_msg->next = after;
    *result = ref_msg;
  } else {
    *result = after;
  }

  return count_before + count_ref + count_after;
}

int history_query_between(const char *target,
                          enum HistoryRefType ref_type1, const char *reference1,
                          enum HistoryRefType ref_type2, const char *reference2,
                          int limit, struct HistoryMessage **result)
{
  char timestamp1[HISTORY_TIMESTAMP_LEN];
  char timestamp2[HISTORY_TIMESTAMP_LEN];
  const char *ref1, *ref2;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char end_prefix[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  int keylen, end_prefix_len;
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, data;
  struct HistoryMessage *head = NULL, *tail = NULL, *msg;
  int count = 0;
  int rc;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Convert references to Unix timestamps */
  if (ref_type1 == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference1, timestamp1) != 0)
      return 0;
    ref1 = timestamp1;
  } else if (ref_type1 == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference1, timestamp1, sizeof(timestamp1)) == 0)
      ref1 = timestamp1;
    else
      ref1 = reference1;  /* Assume already Unix format */
  } else {
    ref1 = reference1;
  }

  if (ref_type2 == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference2, timestamp2) != 0)
      return 0;
    ref2 = timestamp2;
  } else if (ref_type2 == HISTORY_REF_TIMESTAMP) {
    /* Client sends ISO 8601, convert to Unix for lookup */
    if (history_iso_to_unix(reference2, timestamp2, sizeof(timestamp2)) == 0)
      ref2 = timestamp2;
    else
      ref2 = reference2;  /* Assume already Unix format */
  } else {
    ref2 = reference2;
  }

  /* Ensure ref1 < ref2 */
  if (strcmp(ref1, ref2) > 0) {
    const char *tmp = ref1;
    ref1 = ref2;
    ref2 = tmp;
  }

  /* Build start and end keys */
  keylen = build_key(keybuf, sizeof(keybuf), target, ref1, NULL);
  if (keylen < 0)
    return -1;

  end_prefix_len = build_key(end_prefix, sizeof(end_prefix), target, ref2, NULL);
  if (end_prefix_len < 0)
    return -1;

  /* Query */
  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  key.mv_size = keylen;
  key.mv_data = keybuf;
  rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);

  while (rc == 0 && count < limit) {
    /* Check if past end */
    if (key.mv_size >= (size_t)end_prefix_len &&
        memcmp(key.mv_data, end_prefix, end_prefix_len) >= 0)
      break;

    /* Parse and add message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    if (parse_key(key.mv_data, key.mv_size,
                  msg->target, msg->timestamp, msg->msgid) != 0 ||
        deserialize_message(data.mv_data, data.mv_size, msg) != 0) {
      MyFree(msg);
      rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
      continue;
    }

    msg->next = NULL;
    if (tail)
      tail->next = msg;
    else
      head = msg;
    tail = msg;
    count++;

    rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  *result = head;
  return count;
}

int history_query_targets(const char *timestamp1, const char *timestamp2,
                          int limit, struct HistoryTarget **result)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, data;
  struct HistoryTarget *head = NULL, *tail = NULL, *tgt;
  char unix_ts1[HISTORY_TIMESTAMP_LEN];
  char unix_ts2[HISTORY_TIMESTAMP_LEN];
  const char *ts1, *ts2;
  int count = 0;
  int rc;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Convert client ISO timestamps to Unix for comparison */
  if (history_iso_to_unix(timestamp1, unix_ts1, sizeof(unix_ts1)) == 0)
    ts1 = unix_ts1;
  else
    ts1 = timestamp1;  /* Assume already Unix format */

  if (history_iso_to_unix(timestamp2, unix_ts2, sizeof(unix_ts2)) == 0)
    ts2 = unix_ts2;
  else
    ts2 = timestamp2;  /* Assume already Unix format */

  /* Ensure ts1 < ts2 */
  if (strcmp(ts1, ts2) > 0) {
    const char *tmp = ts1;
    ts1 = ts2;
    ts2 = tmp;
  }

  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, history_targets_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Iterate all targets */
  rc = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
  while (rc == 0 && count < limit) {
    /* Check if target's last message is in range */
    char last_ts[HISTORY_TIMESTAMP_LEN];
    if (data.mv_size >= sizeof(last_ts)) {
      rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
      continue;
    }
    memcpy(last_ts, data.mv_data, data.mv_size);
    last_ts[data.mv_size] = '\0';

    if (strcmp(last_ts, ts1) >= 0 && strcmp(last_ts, ts2) <= 0) {
      tgt = (struct HistoryTarget *)MyMalloc(sizeof(struct HistoryTarget));
      if (!tgt)
        break;
      memset(tgt, 0, sizeof(*tgt));

      if (key.mv_size > CHANNELLEN) {
        MyFree(tgt);
        rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
        continue;
      }
      memcpy(tgt->target, key.mv_data, key.mv_size);
      tgt->target[key.mv_size] = '\0';
      ircd_strncpy(tgt->last_timestamp, last_ts, sizeof(tgt->last_timestamp) - 1);
      tgt->next = NULL;

      if (tail)
        tail->next = tgt;
      else
        head = tgt;
      tail = tgt;
      count++;
    }

    rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  *result = head;
  return count;
}

void history_free_messages(struct HistoryMessage *list)
{
  struct HistoryMessage *msg, *next;

  for (msg = list; msg; msg = next) {
    next = msg->next;
    MyFree(msg);
  }
}

void history_free_targets(struct HistoryTarget *list)
{
  struct HistoryTarget *tgt, *next;

  for (tgt = list; tgt; tgt = next) {
    next = tgt->next;
    MyFree(tgt);
  }
}

int history_enumerate_channels(history_channel_callback callback, void *data)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, val;
  char target[CHANNELLEN + 1];
  int count = 0;
  int rc;

  if (!history_available || !callback)
    return -1;

  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, history_targets_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Iterate all targets */
  rc = mdb_cursor_get(cursor, &key, &val, MDB_FIRST);
  while (rc == 0) {
    if (key.mv_size > 0 && key.mv_size <= CHANNELLEN) {
      memcpy(target, key.mv_data, key.mv_size);
      target[key.mv_size] = '\0';

      /* Only call back for channels (start with # or &) */
      if (target[0] == '#' || target[0] == '&') {
        count++;
        if (callback(target, data) != 0)
          break;  /* Callback requested stop */
      }
    }
    rc = mdb_cursor_get(cursor, &key, &val, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  return count;
}

int history_has_channel(const char *target)
{
  MDB_txn *txn;
  MDB_val key, val;
  int rc;

  if (!history_available || !target)
    return -1;

  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.mv_size = strlen(target);
  key.mv_data = (void *)target;

  rc = mdb_get(txn, history_targets_dbi, &key, &val);
  mdb_txn_abort(txn);

  if (rc == 0)
    return 1;  /* Found */
  if (rc == MDB_NOTFOUND)
    return 0;  /* Not found */
  return -1;   /* Error */
}

int history_purge_old(unsigned long max_age_seconds)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, data;
  time_t cutoff_time;
  char cutoff_ts[HISTORY_TIMESTAMP_LEN];
  char msg_target[CHANNELLEN + 1];
  char msg_timestamp[HISTORY_TIMESTAMP_LEN];
  char msg_msgid[HISTORY_MSGID_LEN];
  int deleted = 0;
  int rc;

  if (!history_available)
    return -1;

  if (max_age_seconds == 0)
    return 0; /* Retention disabled */

  /* Calculate cutoff timestamp (Unix format) */
  cutoff_time = time(NULL) - max_age_seconds;
  ircd_snprintf(0, cutoff_ts, sizeof(cutoff_ts), "%lu.000",
                (unsigned long)cutoff_time);

  Debug((DEBUG_DEBUG, "history: purging messages older than %s", cutoff_ts));

  /* Begin write transaction */
  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge mdb_txn_begin failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  /* Open cursor on messages database */
  rc = mdb_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge mdb_cursor_open failed: %s",
              mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  /* Iterate from the beginning (oldest messages first due to key structure) */
  rc = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
  while (rc == 0) {
    /* Parse the key to get timestamp */
    if (parse_key(key.mv_data, key.mv_size,
                  msg_target, msg_timestamp, msg_msgid) == 0) {
      /* Compare timestamp with cutoff */
      if (strcmp(msg_timestamp, cutoff_ts) < 0) {
        /* Message is older than cutoff - delete it */

        /* First delete from msgid index if we have a msgid */
        if (msg_msgid[0] != '\0') {
          MDB_val msgid_key;
          msgid_key.mv_size = strlen(msg_msgid);
          msgid_key.mv_data = msg_msgid;
          mdb_del(txn, history_msgid_dbi, &msgid_key, NULL);
        }

        /* Delete the message using cursor */
        rc = mdb_cursor_del(cursor, 0);
        if (rc == 0) {
          deleted++;
        }

        /* Move to next (cursor position is already at next after del) */
        rc = mdb_cursor_get(cursor, &key, &data, MDB_GET_CURRENT);
        if (rc == MDB_NOTFOUND) {
          /* Deleted last entry, try to get next */
          rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
        }
        continue;
      }
    }

    rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
  }

  mdb_cursor_close(cursor);

  /* Commit the transaction */
  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge mdb_txn_commit failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  if (deleted > 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "history: purged %d old messages (cutoff: %s)",
              deleted, cutoff_ts);
  }

  return deleted;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  MDB_txn *txn;
  MDB_val key, data;
  const char *sep;
  int rc;

  log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: looking up msgid=%s", msgid);

  if (!history_available) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: history not available");
    return -1;
  }

  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: txn_begin failed: %s", mdb_strerror(rc));
    return -1;
  }

  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;

  rc = mdb_get(txn, history_msgid_dbi, &key, &data);
  mdb_txn_abort(txn);

  if (rc != 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: mdb_get failed for msgid=%s: %s", msgid, mdb_strerror(rc));
    return -1;
  }

  /* Value is target\0timestamp\0 - extract timestamp (exclude trailing separator) */
  sep = memchr(data.mv_data, KEY_SEP, data.mv_size);
  if (!sep)
    return -1;

  sep++; /* Skip separator after target */

  /* Calculate copy length - exclude trailing KEY_SEP if present */
  {
    size_t copy_len = (char *)data.mv_data + data.mv_size - sep;
    /* build_key adds trailing KEY_SEP, exclude it */
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN)
      return -1;
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: extracted timestamp='%s' (len=%zu)", timestamp, copy_len);
  }

  return 0;
}

int history_lookup_message(const char *target, const char *msgid,
                            struct HistoryMessage **msg)
{
  MDB_txn *txn;
  MDB_val key, data;
  struct HistoryMessage *m;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  *msg = NULL;

  if (!history_available)
    return -1;

  /* First, look up the msgid to get target and timestamp */
  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;

  rc = mdb_get(txn, history_msgid_dbi, &key, &data);
  if (rc == MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return 1; /* Not found */
  }
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Value is target\0timestamp\0 - extract timestamp (exclude trailing KEY_SEP) */
  {
    const char *sep;
    size_t copy_len;
    sep = memchr(data.mv_data, KEY_SEP, data.mv_size);
    if (!sep) {
      mdb_txn_abort(txn);
      return -1;
    }
    sep++; /* Skip separator after target */
    copy_len = (char *)data.mv_data + data.mv_size - sep;
    /* build_key adds trailing KEY_SEP, exclude it */
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN) {
      mdb_txn_abort(txn);
      return -1;
    }
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
  }

  /* Build key for main database lookup: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  key.mv_size = keylen;
  key.mv_data = keybuf;

  rc = mdb_get(txn, history_dbi, &key, &data);
  if (rc == MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return 1; /* Not found */
  }
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Allocate and populate message structure */
  m = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
  if (!m) {
    mdb_txn_abort(txn);
    return -1;
  }
  memset(m, 0, sizeof(*m));

  /* Parse the message */
  if (deserialize_message(data.mv_data, data.mv_size, m) != 0) {
    MyFree(m);
    mdb_txn_abort(txn);
    return -1;
  }

  /* Fill in the key fields */
  ircd_strncpy(m->msgid, msgid, sizeof(m->msgid) - 1);
  ircd_strncpy(m->target, target, sizeof(m->target) - 1);
  ircd_strncpy(m->timestamp, timestamp, sizeof(m->timestamp) - 1);
  m->next = NULL;

  mdb_txn_abort(txn);
  *msg = m;
  return 0;
}

int history_delete_message(const char *target, const char *msgid)
{
  MDB_txn *txn;
  MDB_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  /* First, look up the msgid to get the timestamp */
  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;

  rc = mdb_get(txn, history_msgid_dbi, &key, &data);
  if (rc == MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return 1; /* Not found */
  }
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Extract timestamp from value (target\0timestamp) */
  {
    const char *sep;
    sep = memchr(data.mv_data, KEY_SEP, data.mv_size);
    if (!sep) {
      mdb_txn_abort(txn);
      return -1;
    }
    sep++; /* Skip separator */
    if ((size_t)((char *)data.mv_data + data.mv_size - sep) >= HISTORY_TIMESTAMP_LEN) {
      mdb_txn_abort(txn);
      return -1;
    }
    memcpy(timestamp, sep, (char *)data.mv_data + data.mv_size - sep);
    timestamp[(char *)data.mv_data + data.mv_size - sep] = '\0';
  }

  /* Delete from msgid index */
  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;
  rc = mdb_del(txn, history_msgid_dbi, &key, NULL);
  if (rc != 0 && rc != MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Build key for main database: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Delete from main message database */
  key.mv_size = keylen;
  key.mv_data = keybuf;
  rc = mdb_del(txn, history_dbi, &key, NULL);
  if (rc != 0 && rc != MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0)
    return -1;

  return 0;
}

int history_is_available(void)
{
  return history_available;
}

/** Build a readmarker key from account and target.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] account Account name.
 * @param[in] target Channel or nick.
 * @return Length of key, or -1 on error.
 */
static int build_readmarker_key(char *key, int keysize,
                                const char *account, const char *target)
{
  int pos = 0;
  int len;

  /* Copy account */
  len = strlen(account);
  if (pos + len + 1 >= keysize) return -1;
  memcpy(key + pos, account, len);
  pos += len;
  key[pos++] = KEY_SEP;

  /* Copy target */
  len = strlen(target);
  if (pos + len >= keysize) return -1;
  memcpy(key + pos, target, len);
  pos += len;

  return pos;
}

int readmarker_get(const char *account, const char *target, char *timestamp)
{
  MDB_txn *txn;
  MDB_val key, data;
  char keybuf[ACCOUNTLEN + CHANNELLEN + 4];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  keylen = build_readmarker_key(keybuf, sizeof(keybuf), account, target);
  if (keylen < 0)
    return -1;

  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.mv_size = keylen;
  key.mv_data = keybuf;

  rc = mdb_get(txn, history_readmarkers_dbi, &key, &data);
  mdb_txn_abort(txn);

  if (rc == MDB_NOTFOUND)
    return 1; /* Not found */
  if (rc != 0)
    return -1;

  /* Copy timestamp to output */
  if (data.mv_size >= HISTORY_TIMESTAMP_LEN)
    return -1;
  memcpy(timestamp, data.mv_data, data.mv_size);
  timestamp[data.mv_size] = '\0';

  return 0;
}

int readmarker_set(const char *account, const char *target, const char *timestamp)
{
  MDB_txn *txn;
  MDB_val key, data;
  char keybuf[ACCOUNTLEN + CHANNELLEN + 4];
  char existing_ts[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  keylen = build_readmarker_key(keybuf, sizeof(keybuf), account, target);
  if (keylen < 0)
    return -1;

  /* Begin write transaction */
  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  key.mv_size = keylen;
  key.mv_data = keybuf;

  /* Check existing value */
  rc = mdb_get(txn, history_readmarkers_dbi, &key, &data);
  if (rc == 0) {
    /* Existing timestamp found - only update if new is greater */
    if (data.mv_size < sizeof(existing_ts)) {
      memcpy(existing_ts, data.mv_data, data.mv_size);
      existing_ts[data.mv_size] = '\0';
      if (strcmp(timestamp, existing_ts) <= 0) {
        /* New timestamp is not greater, don't update */
        mdb_txn_abort(txn);
        return 1;
      }
    }
  } else if (rc != MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Store new timestamp */
  data.mv_size = strlen(timestamp);
  data.mv_data = (void *)timestamp;

  rc = mdb_put(txn, history_readmarkers_dbi, &key, &data, 0);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0)
    return -1;

  return 0;
}

/** Set history database map size.
 * Must be called before history_init().
 * @param[in] size_mb Size in megabytes.
 */
void history_set_map_size(size_t size_mb)
{
  if (size_mb > 0)
    history_map_size = size_mb * 1024 * 1024;
}

/** Get history database map size.
 * @return Current map size in bytes.
 */
size_t history_get_map_size(void)
{
  return history_map_size;
}

/*
 * Storage Management
 *
 * Implements graceful degradation and automatic eviction to prevent
 * database full conditions. Uses a watermark system:
 * - HIGH_WATERMARK: Start background eviction (default 85%)
 * - LOW_WATERMARK: Eviction target (default 75%)
 * - 95%: Critical - aggressive eviction
 * - 99%: Suspended - no new writes
 */

/** Last eviction statistics */
static int last_eviction_count = 0;
static time_t last_eviction_time = 0;
static time_t last_maintenance_time = 0;

/** Emergency eviction count (for inline MDB_MAP_FULL recovery) */
#define EMERGENCY_EVICT_BATCH 500

/** Emergency eviction for inline MDB_MAP_FULL recovery.
 * Called when a write fails due to database full condition.
 * Evicts a small batch of oldest messages to make room.
 * @return Number of messages evicted, or -1 on error.
 */
static int history_emergency_evict(void)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, data;
  char msg_target[CHANNELLEN + 1];
  char msg_timestamp[HISTORY_TIMESTAMP_LEN];
  char msg_msgid[HISTORY_MSGID_LEN];
  int evicted = 0;
  int rc;

  if (!history_available)
    return -1;

  log_write(LS_SYSTEM, L_WARNING, 0,
            "history: emergency eviction triggered (MDB_MAP_FULL)");

  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction txn_begin failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  rc = mdb_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Evict oldest entries */
  rc = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
  while (rc == 0 && evicted < EMERGENCY_EVICT_BATCH) {
    /* Parse key to get msgid for index cleanup */
    if (parse_key(key.mv_data, key.mv_size,
                  msg_target, msg_timestamp, msg_msgid) == 0) {
      if (msg_msgid[0] != '\0') {
        MDB_val msgid_key;
        msgid_key.mv_size = strlen(msg_msgid);
        msgid_key.mv_data = msg_msgid;
        mdb_del(txn, history_msgid_dbi, &msgid_key, NULL);
      }
    }

    rc = mdb_cursor_del(cursor, 0);
    if (rc != 0)
      break;

    evicted++;
    rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
  }

  mdb_cursor_close(cursor);

  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction commit failed: %s",
              mdb_strerror(rc));
    return -1;
  }

  /* Update stats */
  last_eviction_count += evicted;
  last_eviction_time = time(NULL);

  log_write(LS_SYSTEM, L_WARNING, 0,
            "history: emergency eviction complete, evicted %d messages",
            evicted);

  return evicted;
}

int history_db_utilization(void)
{
  MDB_envinfo info;
  MDB_stat envstat;
  int rc;
  size_t used_size;
  int percent;

  if (!history_available)
    return -1;

  /* Get environment info for map size */
  rc = mdb_env_info(history_env, &info);
  if (rc != 0)
    return -1;

  /* Get environment stats for page size */
  rc = mdb_env_stat(history_env, &envstat);
  if (rc != 0)
    return -1;

  /* Calculate used size: (last_pgno + 1) * page_size
   * Note: me_last_pgno is 0-indexed, so add 1 for count */
  used_size = (info.me_last_pgno + 1) * envstat.ms_psize;

  /* Calculate percentage */
  if (info.me_mapsize == 0)
    return 0;

  percent = (int)((used_size * 100) / info.me_mapsize);
  if (percent > 100)
    percent = 100;

  return percent;
}

enum HistoryStorageState history_storage_state(void)
{
  int util;

  if (!history_available)
    return HISTORY_STORAGE_SUSPENDED;

  util = history_db_utilization();
  if (util < 0)
    return HISTORY_STORAGE_SUSPENDED;

  if (util >= 99)
    return HISTORY_STORAGE_SUSPENDED;
  if (util >= 95)
    return HISTORY_STORAGE_CRITICAL;
  if (util >= 85)  /* HIGH_WATERMARK default */
    return HISTORY_STORAGE_WARNING;

  return HISTORY_STORAGE_NORMAL;
}

int history_evict_to_target(int target_percent)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val key, data;
  char msg_target[CHANNELLEN + 1];
  char msg_timestamp[HISTORY_TIMESTAMP_LEN];
  char msg_msgid[HISTORY_MSGID_LEN];
  int evicted = 0;
  int current_util;
  int rc;
  int batch_count = 0;
  int max_batch = 1000;  /* Limit per transaction */

  if (!history_available)
    return -1;

  current_util = history_db_utilization();
  if (current_util < 0)
    return -1;

  if (current_util <= target_percent)
    return 0;  /* Already at target */

  log_write(LS_SYSTEM, L_INFO, 0,
            "history: eviction starting, util=%d%% target=%d%%",
            current_util, target_percent);

  /* Evict oldest messages until we reach target */
  while (current_util > target_percent) {
    rc = mdb_txn_begin(history_env, NULL, 0, &txn);
    if (rc != 0)
      break;

    rc = mdb_cursor_open(txn, history_dbi, &cursor);
    if (rc != 0) {
      mdb_txn_abort(txn);
      break;
    }

    batch_count = 0;

    /* Iterate from beginning (oldest entries) */
    rc = mdb_cursor_get(cursor, &key, &data, MDB_FIRST);
    while (rc == 0 && batch_count < max_batch) {
      /* Parse key to get msgid for index cleanup */
      if (parse_key(key.mv_data, key.mv_size,
                    msg_target, msg_timestamp, msg_msgid) == 0) {
        /* Delete from msgid index if present */
        if (msg_msgid[0] != '\0') {
          MDB_val msgid_key;
          msgid_key.mv_size = strlen(msg_msgid);
          msgid_key.mv_data = msg_msgid;
          mdb_del(txn, history_msgid_dbi, &msgid_key, NULL);
        }
      }

      /* Delete from main database */
      rc = mdb_cursor_del(cursor, 0);
      if (rc != 0)
        break;

      evicted++;
      batch_count++;

      /* Move to next */
      rc = mdb_cursor_get(cursor, &key, &data, MDB_GET_CURRENT);
      if (rc == MDB_NOTFOUND)
        rc = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
    }

    mdb_cursor_close(cursor);

    rc = mdb_txn_commit(txn);
    if (rc != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history: eviction commit failed: %s", mdb_strerror(rc));
      break;
    }

    /* Recheck utilization */
    current_util = history_db_utilization();
    if (current_util < 0)
      break;

    /* If we didn't evict anything, we're done */
    if (batch_count == 0)
      break;
  }

  /* Update eviction stats */
  last_eviction_count = evicted;
  last_eviction_time = time(NULL);

  log_write(LS_SYSTEM, L_INFO, 0,
            "history: eviction complete, evicted=%d new_util=%d%%",
            evicted, current_util);

  return evicted;
}

void history_maintenance_tick(void)
{
  int util;
  int high_watermark;
  int low_watermark;
  time_t now;
  int interval;

  if (!history_available)
    return;

  now = time(NULL);

  /* Check if maintenance interval has passed */
  interval = feature_int(FEAT_CHATHISTORY_MAINTENANCE_INTERVAL);
  if (interval > 0 && last_maintenance_time > 0 &&
      (now - last_maintenance_time) < interval)
    return;

  last_maintenance_time = now;

  util = history_db_utilization();
  if (util < 0)
    return;

  high_watermark = feature_int(FEAT_CHATHISTORY_HIGH_WATERMARK);
  low_watermark = feature_int(FEAT_CHATHISTORY_LOW_WATERMARK);

  /* Sanity checks */
  if (high_watermark <= 0)
    high_watermark = 85;
  if (low_watermark <= 0)
    low_watermark = 75;
  if (low_watermark >= high_watermark)
    low_watermark = high_watermark - 10;

  /* Check if eviction is needed */
  if (util >= high_watermark) {
    enum HistoryStorageState state = history_storage_state();
    const char *state_name;

    switch (state) {
      case HISTORY_STORAGE_WARNING:  state_name = "WARNING"; break;
      case HISTORY_STORAGE_CRITICAL: state_name = "CRITICAL"; break;
      case HISTORY_STORAGE_SUSPENDED: state_name = "SUSPENDED"; break;
      default: state_name = "NORMAL"; break;
    }

    log_write(LS_SYSTEM, L_WARNING, 0,
              "history: storage at %d%% (state=%s), starting eviction",
              util, state_name);

    history_evict_to_target(low_watermark);
  }
}

void history_last_eviction(int *count, time_t *timestamp)
{
  if (count)
    *count = last_eviction_count;
  if (timestamp)
    *timestamp = last_eviction_time;
}

void
history_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  MDB_stat stat;
  MDB_stat envstat;
  MDB_envinfo info;
  MDB_txn *txn;
  int rc;
  int util;
  enum HistoryStorageState state;
  const char *state_name;
  size_t used_size;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :CHATHISTORY Statistics");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  LMDB Backend: %s",
             history_available ? "Available" : "Unavailable");

  if (!history_available) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  (LMDB not initialized)");
    return;
  }

  /* Get environment info and stats */
  rc = mdb_env_info(history_env, &info);
  if (rc != 0)
    return;

  rc = mdb_env_stat(history_env, &envstat);
  if (rc != 0)
    return;

  /* Calculate storage utilization */
  used_size = (info.me_last_pgno + 1) * envstat.ms_psize;
  util = history_db_utilization();
  state = history_storage_state();

  switch (state) {
    case HISTORY_STORAGE_WARNING:  state_name = "WARNING"; break;
    case HISTORY_STORAGE_CRITICAL: state_name = "CRITICAL"; break;
    case HISTORY_STORAGE_SUSPENDED: state_name = "SUSPENDED"; break;
    default: state_name = "NORMAL"; break;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Size: %lu MB / %lu MB (%d%%)",
             (unsigned long)(used_size / (1024 * 1024)),
             (unsigned long)(info.me_mapsize / (1024 * 1024)),
             util);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  State: %s", state_name);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Retention: %d days",
             feature_int(FEAT_CHATHISTORY_RETENTION));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "H :  Watermarks: high=%d%% low=%d%%",
             feature_int(FEAT_CHATHISTORY_HIGH_WATERMARK),
             feature_int(FEAT_CHATHISTORY_LOW_WATERMARK));

  /* Last eviction info */
  if (last_eviction_time > 0) {
    char timebuf[32];
    struct tm tm;
    gmtime_r(&last_eviction_time, &tm);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Last eviction: %s (%d messages)",
               timebuf, last_eviction_count);
  } else {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Last eviction: never");
  }

  /* Get per-database stats */
  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc == 0) {
    /* Main message database */
    rc = mdb_stat(txn, history_dbi, &stat);
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Messages: %lu entries, depth %u",
                 (unsigned long)stat.ms_entries, stat.ms_depth);
    }

    /* Targets database */
    rc = mdb_stat(txn, history_targets_dbi, &stat);
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Channels: %lu",
                 (unsigned long)stat.ms_entries);
    }

    /* Message ID index */
    rc = mdb_stat(txn, history_msgid_dbi, &stat);
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  MsgID index: %lu entries",
                 (unsigned long)stat.ms_entries);
    }

    /* Read markers database */
    rc = mdb_stat(txn, history_readmarkers_dbi, &stat);
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Read markers: %lu entries",
                 (unsigned long)stat.ms_entries);
    }

    mdb_txn_abort(txn);
  }
}

#else /* !USE_LMDB */

/* Stub implementations when LMDB is not available */
#include "history.h"
#include <stddef.h>
#include <time.h>

int history_init(const char *dbpath)
{
  (void)dbpath;
  return -1;
}

void history_shutdown(void)
{
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *sender,
                          const char *account, enum HistoryMessageType type,
                          const char *content)
{
  (void)msgid; (void)timestamp; (void)target; (void)sender;
  (void)account; (void)type; (void)content;
  return -1;
}

int history_has_msgid(const char *msgid)
{
  (void)msgid;
  return -1;
}

int history_query_before(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  (void)target; (void)ref_type; (void)reference; (void)limit;
  *result = NULL;
  return -1;
}

int history_query_after(const char *target, enum HistoryRefType ref_type,
                        const char *reference, int limit,
                        struct HistoryMessage **result)
{
  (void)target; (void)ref_type; (void)reference; (void)limit;
  *result = NULL;
  return -1;
}

int history_query_latest(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  (void)target; (void)ref_type; (void)reference; (void)limit;
  *result = NULL;
  return -1;
}

int history_query_around(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  (void)target; (void)ref_type; (void)reference; (void)limit;
  *result = NULL;
  return -1;
}

int history_query_between(const char *target,
                          enum HistoryRefType ref_type1, const char *reference1,
                          enum HistoryRefType ref_type2, const char *reference2,
                          int limit, struct HistoryMessage **result)
{
  (void)target; (void)ref_type1; (void)reference1;
  (void)ref_type2; (void)reference2; (void)limit;
  *result = NULL;
  return -1;
}

int history_query_targets(const char *timestamp1, const char *timestamp2,
                          int limit, struct HistoryTarget **result)
{
  (void)timestamp1; (void)timestamp2; (void)limit;
  *result = NULL;
  return -1;
}

void history_free_messages(struct HistoryMessage *list)
{
  (void)list;
}

void history_free_targets(struct HistoryTarget *list)
{
  (void)list;
}

int history_purge_old(unsigned long max_age_seconds)
{
  (void)max_age_seconds;
  return -1;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  (void)msgid; (void)timestamp;
  return -1;
}

int history_lookup_message(const char *target, const char *msgid,
                            struct HistoryMessage **msg)
{
  (void)target; (void)msgid;
  *msg = NULL;
  return -1;
}

int history_delete_message(const char *target, const char *msgid)
{
  (void)target; (void)msgid;
  return -1;
}

int history_is_available(void)
{
  return 0;
}

int readmarker_get(const char *account, const char *target, char *timestamp)
{
  (void)account; (void)target; (void)timestamp;
  return -1;
}

int readmarker_set(const char *account, const char *target, const char *timestamp)
{
  (void)account; (void)target; (void)timestamp;
  return -1;
}

void history_set_map_size(size_t size_mb)
{
  (void)size_mb;
}

size_t history_get_map_size(void)
{
  return 0;
}

int history_db_utilization(void)
{
  return -1;
}

enum HistoryStorageState history_storage_state(void)
{
  return HISTORY_STORAGE_SUSPENDED;
}

int history_evict_to_target(int target_percent)
{
  (void)target_percent;
  return -1;
}

void history_maintenance_tick(void)
{
}

void history_last_eviction(int *count, time_t *timestamp)
{
  if (count)
    *count = 0;
  if (timestamp)
    *timestamp = 0;
}

void
history_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  (void)sd; (void)param;
  /* For stub version, we need send_reply - include the headers */
  /* This function is only callable if stats are registered, which requires LMDB */
}

int history_enumerate_channels(history_channel_callback callback, void *data)
{
  (void)callback; (void)data;
  return -1;
}

int history_has_channel(const char *target)
{
  (void)target;
  return -1;
}

#endif /* USE_LMDB */
