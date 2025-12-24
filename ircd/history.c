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
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "s_debug.h"

#include <lmdb.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/** LMDB environment */
static MDB_env *history_env = NULL;

/** Main message database */
static MDB_dbi history_dbi;

/** Secondary index: msgid -> timestamp (for msgid lookups) */
static MDB_dbi history_msgid_dbi;

/** Target tracking database for TARGETS query */
static MDB_dbi history_targets_dbi;

/** Flag indicating if history is available */
static int history_available = 0;

/** Maximum database size (1GB default) */
#define HISTORY_MAP_SIZE (1UL * 1024 * 1024 * 1024)

/** Maximum number of named databases */
#define HISTORY_MAX_DBS 4

/** Key separator character */
#define KEY_SEP '\0'

/** Message type names for serialization */
static const char *history_type_names[] = {
  "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
  "KICK", "MODE", "TOPIC", "TAGMSG"
};

/** Build a lookup key from target and timestamp.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] target Channel or nick.
 * @param[in] timestamp ISO 8601 timestamp (or NULL for just target).
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
 * @param[in] data Serialized data.
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

  /* Set map size */
  rc = mdb_env_set_mapsize(history_env, HISTORY_MAP_SIZE);
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
  char valbuf[HISTORY_SENDER_LEN + ACCOUNTLEN + HISTORY_CONTENT_LEN + 16];
  int keylen, vallen;
  int rc;

  if (!history_available)
    return -1;

  /* Build key: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0)
    return -1;

  /* Serialize value */
  vallen = serialize_message(valbuf, sizeof(valbuf), type, sender, account, content);
  if (vallen < 0)
    return -1;

  /* Begin write transaction */
  rc = mdb_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_txn_begin failed: %s", mdb_strerror(rc)));
    return -1;
  }

  /* Store message */
  key.mv_size = keylen;
  key.mv_data = keybuf;
  data.mv_size = vallen;
  data.mv_data = valbuf;

  rc = mdb_put(txn, history_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_put failed: %s", mdb_strerror(rc)));
    mdb_txn_abort(txn);
    return -1;
  }

  /* Store msgid -> target\0timestamp index */
  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;
  /* Value is target\0timestamp */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, NULL);
  data.mv_size = keylen;
  data.mv_data = keybuf;

  rc = mdb_put(txn, history_msgid_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_put(msgid) failed: %s", mdb_strerror(rc)));
    mdb_txn_abort(txn);
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
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdb_txn_commit failed: %s", mdb_strerror(rc)));
    return -1;
  }

  return 0;
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
    if (rc == MDB_NOTFOUND) {
      /* Position at last entry */
      rc = mdb_cursor_get(cursor, &key, &data, MDB_LAST);
    } else if (rc == 0) {
      /* Move back one since SET_RANGE gives us >= */
      rc = mdb_cursor_get(cursor, &key, &data, MDB_PREV);
    }
    op = MDB_PREV;
  } else {
    /* For AFTER, go forwards */
    rc = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE);
    op = MDB_NEXT;
  }

  /* Iterate and collect messages */
  while (rc == 0 && count < limit) {
    /* Check if still in target's range */
    if (key.mv_size < (size_t)target_prefix_len ||
        memcmp(key.mv_data, target_prefix, target_prefix_len) != 0) {
      /* Outside target range */
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

  /* Convert msgid to timestamp if needed */
  if (ref_type == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0; /* msgid not found, return empty */
    reference = timestamp;
  }

  /* Build starting key */
  keylen = build_key(keybuf, sizeof(keybuf), target, reference, NULL);
  if (keylen < 0)
    return -1;

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

  /* Convert msgid to timestamp if needed */
  if (ref_type == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference, timestamp) != 0)
      return 0;
    reference = timestamp;
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
    /* Use a timestamp far in the future */
    keylen = build_key(keybuf, sizeof(keybuf), target, "9999-12-31T23:59:59.999Z", NULL);
  } else {
    if (ref_type == HISTORY_REF_MSGID) {
      if (history_msgid_to_timestamp(reference, timestamp) != 0)
        return 0;
      reference = timestamp;
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
  struct HistoryMessage *before = NULL, *after = NULL;
  int half = limit / 2;
  int count_before, count_after;

  *result = NULL;

  /* Get messages before reference */
  count_before = history_query_before(target, ref_type, reference, half, &before);
  if (count_before < 0) {
    history_free_messages(before);
    return -1;
  }

  /* Get messages after reference */
  count_after = history_query_after(target, ref_type, reference, limit - count_before, &after);
  if (count_after < 0) {
    history_free_messages(before);
    history_free_messages(after);
    return -1;
  }

  /* Concatenate lists: before + after */
  if (before) {
    struct HistoryMessage *tail = before;
    while (tail->next)
      tail = tail->next;
    tail->next = after;
    *result = before;
  } else {
    *result = after;
  }

  return count_before + count_after;
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

  /* Convert msgids to timestamps */
  if (ref_type1 == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference1, timestamp1) != 0)
      return 0;
    ref1 = timestamp1;
  } else {
    ref1 = reference1;
  }

  if (ref_type2 == HISTORY_REF_MSGID) {
    if (history_msgid_to_timestamp(reference2, timestamp2) != 0)
      return 0;
    ref2 = timestamp2;
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
  const char *ts1, *ts2;
  int count = 0;
  int rc;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Ensure ts1 < ts2 */
  if (strcmp(timestamp1, timestamp2) > 0) {
    ts1 = timestamp2;
    ts2 = timestamp1;
  } else {
    ts1 = timestamp1;
    ts2 = timestamp2;
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

int history_purge_old(unsigned long max_age_seconds)
{
  /* TODO: Implement purge logic
   * - Calculate cutoff timestamp
   * - Iterate all messages
   * - Delete those older than cutoff
   * - Update targets table accordingly
   */
  return 0;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  MDB_txn *txn;
  MDB_val key, data;
  const char *sep;
  int rc;

  if (!history_available)
    return -1;

  rc = mdb_txn_begin(history_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.mv_size = strlen(msgid);
  key.mv_data = (void *)msgid;

  rc = mdb_get(txn, history_msgid_dbi, &key, &data);
  mdb_txn_abort(txn);

  if (rc != 0)
    return -1;

  /* Value is target\0timestamp - extract timestamp */
  sep = memchr(data.mv_data, KEY_SEP, data.mv_size);
  if (!sep)
    return -1;

  sep++; /* Skip separator */
  if ((size_t)((char *)data.mv_data + data.mv_size - sep) >= HISTORY_TIMESTAMP_LEN)
    return -1;

  memcpy(timestamp, sep, (char *)data.mv_data + data.mv_size - sep);
  timestamp[(char *)data.mv_data + data.mv_size - sep] = '\0';

  return 0;
}

int history_is_available(void)
{
  return history_available;
}

#else /* !USE_LMDB */

/* Stub implementations when LMDB is not available */

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

int history_is_available(void)
{
  return 0;
}

#endif /* USE_LMDB */
