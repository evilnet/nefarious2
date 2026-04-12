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

#ifdef USE_MDBX

#include "history.h"
#include "ml_content.h"
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

#include <mdbx.h>
#include <string.h>
#ifdef USE_ZSTD
#include <zstd.h>
#endif
#include <stdlib.h>
#include <time.h>
#include <stdint.h>
#include <sys/time.h>

/* Forward declarations for quota functions */
static int quota_increment(const char *channel, const char *account);
static int quota_decrement(const char *channel, const char *account);

/** LMDB environment */
static MDBX_env *history_env = NULL;

/** Main message database */
static MDBX_dbi history_dbi;

/** Secondary index: msgid -> timestamp (for msgid lookups) */
static MDBX_dbi history_msgid_dbi;

/** Target tracking database for TARGETS query */
static MDBX_dbi history_targets_dbi;

/** Per-user quota counter database
 * Key: "channel\0account" -> count (uint32_t)
 */
static MDBX_dbi history_quota_dbi;

/** Reply/context index database (DUPSORT)
 * Key: "target\0parent_msgid"
 * Value: "timestamp\0child_msgid"
 * Used to find reactions/redacts that reference a given message.
 */
static MDBX_dbi history_reply_dbi;

/** Flag indicating if history is available */
static int history_available = 0;

/** Maximum database size (1GB default, configurable) */
static size_t history_map_size = 1UL * 1024 * 1024 * 1024;

/** Callback for channel removal notifications (for CH A - broadcasts) */
static history_channels_removed_cb channel_removed_callback = NULL;

/** Maximum number of named databases */
#define HISTORY_MAX_DBS 10

/** Key separator character */
#define KEY_SEP '\0'

/** Message type names for serialization */
static const char *history_type_names[] = {
  "PRIVMSG", "NOTICE", "JOIN", "PART", "QUIT",
  "KICK", "MODE", "TOPIC", "TAGMSG"
};

/* Forward declarations */
static int history_emergency_evict(void);
static int history_cleanup_empty_targets(void);

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
                             const char *content, const char *client_tags)
{
  /* When client_tags is present, prefix content with \x06tags\x06 sentinel.
   * \x06 (ACK) is unused by any IRC formatting or control code.
   * Old data without sentinel deserializes with empty client_tags. */
  if (client_tags && client_tags[0])
    return ircd_snprintf(0, buf, bufsize, "%d|%s|%s|\x06%s\x06%s",
                         (int)type,
                         sender ? sender : "",
                         account ? account : "",
                         client_tags,
                         content ? content : "");
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
  int ret = -1;
#ifdef USE_ZSTD
  char decomp_stack[HISTORY_VALUE_BUFSIZE];
  char *decompressed = NULL;
  int decomp_dynamic = 0;
  size_t decompressed_len;

  /* Check if data is compressed and decompress if needed */
  if (is_compressed((const unsigned char *)data, datalen)) {
    /* Determine decompressed size for buffer allocation */
    unsigned long long frame_size = ZSTD_getFrameContentSize(
        (const unsigned char *)data + 1, datalen - 1);
    size_t out_size;

    if (frame_size != ZSTD_CONTENTSIZE_ERROR
        && frame_size != ZSTD_CONTENTSIZE_UNKNOWN
        && frame_size > sizeof(decomp_stack)) {
      if (frame_size > COMPRESS_MAX_UNCOMPRESSED)
        goto deser_cleanup;
      decompressed = (char *)MyMalloc(frame_size + 1);
      decomp_dynamic = 1;
      out_size = frame_size + 1;
    } else {
      decompressed = decomp_stack;
      out_size = sizeof(decomp_stack);
    }

    if (decompress_data((const unsigned char *)data, datalen,
                        (unsigned char *)decompressed, out_size,
                        &decompressed_len) < 0) {
      goto deser_cleanup;
    }
    data = decompressed;
    datalen = decompressed_len;
  }
#endif

  p = data;
  end = data + datalen;

  /* Parse type */
  field = strchr(p, '|');
  if (!field || field >= end) goto deser_cleanup;
  type = atoi(p);
  if (type < 0 || type > HISTORY_REDACT) goto deser_cleanup;
  msg->type = (enum HistoryMessageType)type;
  p = field + 1;

  /* Parse sender */
  field = strchr(p, '|');
  if (!field || field >= end) goto deser_cleanup;
  if ((size_t)(field - p) >= sizeof(msg->sender)) goto deser_cleanup;
  memcpy(msg->sender, p, field - p);
  msg->sender[field - p] = '\0';
  p = field + 1;

  /* Parse account */
  field = strchr(p, '|');
  if (!field || field >= end) goto deser_cleanup;
  if ((size_t)(field - p) >= sizeof(msg->account)) goto deser_cleanup;
  memcpy(msg->account, p, field - p);
  msg->account[field - p] = '\0';
  p = field + 1;

  /* Parse content (rest of string), extracting client_tags if sentinel present.
   * New format: \x06client_tags\x06content
   * Old format: content (no sentinel) */
  {
    size_t content_len = end - p;
    msg->client_tags[0] = '\0';

    if (content_len > 2 && p[0] == '\x06') {
      const char *tag_end = memchr(p + 1, '\x06', content_len - 1);
      if (tag_end) {
        size_t tags_len = tag_end - (p + 1);
        if (tags_len >= sizeof(msg->client_tags))
          tags_len = sizeof(msg->client_tags) - 1;
        memcpy(msg->client_tags, p + 1, tags_len);
        msg->client_tags[tags_len] = '\0';
        p = tag_end + 1;
        content_len = end - p;
      }
    }

    if (content_len >= sizeof(msg->content))
      content_len = sizeof(msg->content) - 1;
    memcpy(msg->content, p, content_len);
    msg->content[content_len] = '\0';
  }

  ret = 0;

deser_cleanup:
#ifdef USE_ZSTD
  if (decomp_dynamic && decompressed)
    MyFree(decompressed);
#endif
  return ret;
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

/** Extract +reply= value from a client_tags string.
 * @param[in] client_tags Semicolon-separated tag list (e.g. "+draft/react=X;+reply=MSGID").
 * @param[out] buf Buffer for the extracted msgid.
 * @param[in] buflen Size of buf.
 * @return Pointer to buf on success, NULL if no +reply= found.
 */
static const char *extract_reply_tag(const char *client_tags, char *buf, size_t buflen)
{
  const char *p;

  if (!client_tags || !client_tags[0])
    return NULL;

  /* Search for "+reply=" in the tag string */
  p = client_tags;
  while ((p = strstr(p, "+reply=")) != NULL) {
    /* Ensure it's at the start or after a separator */
    if (p != client_tags && *(p - 1) != ';') {
      p += 7;
      continue;
    }
    p += 7; /* skip "+reply=" */
    {
      const char *end = strchr(p, ';');
      size_t len = end ? (size_t)(end - p) : strlen(p);
      if (len == 0 || len >= buflen)
        return NULL;
      memcpy(buf, p, len);
      buf[len] = '\0';
      return buf;
    }
  }
  return NULL;
}

/** Index a parent→child reply relationship.
 * @param[in] txn Active write transaction.
 * @param[in] target Channel or nick.
 * @param[in] parent_msgid The msgid being referenced.
 * @param[in] timestamp Timestamp of the child message.
 * @param[in] child_msgid Msgid of the child (reaction/redact).
 */
static void reply_index_put(MDBX_txn *txn, const char *target,
                            const char *parent_msgid,
                            const char *timestamp, const char *child_msgid)
{
  char keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
  char valbuf[HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 4];
  MDBX_val key, val;
  int kpos = 0, vpos = 0;
  size_t len;

  /* Key: target\0parent_msgid */
  len = strlen(target);
  if (kpos + len + 1 >= sizeof(keybuf)) return;
  memcpy(keybuf + kpos, target, len);
  kpos += len;
  keybuf[kpos++] = KEY_SEP;
  len = strlen(parent_msgid);
  if (kpos + len >= sizeof(keybuf)) return;
  memcpy(keybuf + kpos, parent_msgid, len);
  kpos += len;

  /* Value: timestamp\0child_msgid */
  len = strlen(timestamp);
  if (vpos + len + 1 >= sizeof(valbuf)) return;
  memcpy(valbuf + vpos, timestamp, len);
  vpos += len;
  valbuf[vpos++] = KEY_SEP;
  len = strlen(child_msgid);
  if (vpos + len >= sizeof(valbuf)) return;
  memcpy(valbuf + vpos, child_msgid, len);
  vpos += len;

  key.iov_base = keybuf;
  key.iov_len = kpos;
  val.iov_base = valbuf;
  val.iov_len = vpos;

  mdbx_put(txn, history_reply_dbi, &key, &val, 0);
}

/** Remove all reply index entries where child_msgid is the child.
 * Called during retention purge when a message is deleted.
 * @param[in] txn Active write transaction.
 * @param[in] target Channel or nick.
 * @param[in] child_msgid Msgid of the message being deleted.
 * @param[in] client_tags Client tags of the message (to find +reply=).
 * @param[in] type Message type.
 * @param[in] content Message content (for REDACT target extraction).
 */
static void reply_index_del_child(MDBX_txn *txn, const char *target,
                                  const char *child_msgid,
                                  const char *client_tags,
                                  enum HistoryMessageType type,
                                  const char *content)
{
  char parent_mid[HISTORY_MSGID_LEN];
  const char *parent = NULL;

  /* Find the parent msgid this child references */
  if (client_tags && client_tags[0])
    parent = extract_reply_tag(client_tags, parent_mid, sizeof(parent_mid));

  if (!parent && type == HISTORY_REDACT && content && content[0]) {
    /* REDACT content starts with target_msgid */
    const char *space = strchr(content, ' ');
    size_t len = space ? (size_t)(space - content) : strlen(content);
    if (len > 0 && len < sizeof(parent_mid)) {
      memcpy(parent_mid, content, len);
      parent_mid[len] = '\0';
      parent = parent_mid;
    }
  }

  if (parent) {
    /* Build key: target\0parent_msgid, scan dup values for matching child_msgid */
    char keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
    MDBX_val key, val;
    MDBX_cursor *cursor;
    int kpos = 0, rc;
    size_t len;

    len = strlen(target);
    if (kpos + len + 1 >= sizeof(keybuf)) return;
    memcpy(keybuf + kpos, target, len);
    kpos += len;
    keybuf[kpos++] = KEY_SEP;
    len = strlen(parent);
    if (kpos + len >= sizeof(keybuf)) return;
    memcpy(keybuf + kpos, parent, len);
    kpos += len;

    key.iov_base = keybuf;
    key.iov_len = kpos;

    rc = mdbx_cursor_open(txn, history_reply_dbi, &cursor);
    if (rc != 0) return;

    rc = mdbx_cursor_get(cursor, &key, &val, MDBX_SET_KEY);
    while (rc == 0) {
      /* Value is timestamp\0child_msgid — check if child matches */
      const char *sep = memchr(val.iov_base, KEY_SEP, val.iov_len);
      if (sep) {
        sep++;
        size_t cmid_len = (char *)val.iov_base + val.iov_len - sep;
        if (cmid_len == strlen(child_msgid) && memcmp(sep, child_msgid, cmid_len) == 0) {
          mdbx_cursor_del(cursor, 0);
          break;
        }
      }
      rc = mdbx_cursor_get(cursor, &key, &val, MDBX_NEXT_DUP);
    }
    mdbx_cursor_close(cursor);
  }
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
  MDBX_txn *txn;
  int rc;

  if (history_available)
    return 0; /* Already initialized */

  /* Create LMDB environment */
  rc = mdbx_env_create(&history_env);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_env_create failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  /* Set maximum number of databases */
  rc = mdbx_env_set_maxdbs(history_env, HISTORY_MAX_DBS);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_env_set_maxdbs failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Set database geometry (configurable, default 1GB upper limit) */
  if (feature_bool(FEAT_CHATHISTORY_DB_AUTOGROW)) {
    intptr_t growth_step = feature_int(FEAT_CHATHISTORY_DB_GROWTH_STEP);
    rc = mdbx_env_set_geometry(history_env, -1, -1, history_map_size,
                               growth_step, growth_step, -1);
  } else {
    rc = mdbx_env_set_geometry(history_env, history_map_size, history_map_size,
                               history_map_size, 0, 0, -1);
  }
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_env_set_geometry failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open environment */
  {
    unsigned int env_flags = 0;
    if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
      env_flags |= MDBX_SAFE_NOSYNC;
      log_write(LS_SYSTEM, L_INFO, 0, "history: using MDBX_SAFE_NOSYNC with %d second sync interval",
                feature_int(FEAT_CHATHISTORY_DB_SYNC_INTERVAL));
    }
    rc = mdbx_env_open(history_env, dbpath, env_flags, 0644);
  }
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_env_open(%s) failed: %s",
              dbpath, mdbx_strerror(rc));
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Configure built-in periodic sync when NOSYNC is enabled */
  if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
    int sync_interval = feature_int(FEAT_CHATHISTORY_DB_SYNC_INTERVAL);
    if (sync_interval > 0) {
      /* MDBX_opt_sync_period uses 16.16 fixed-point seconds */
      rc = mdbx_env_set_option(history_env, MDBX_opt_sync_period,
                               (uint64_t)sync_interval * 65536);
      if (rc != MDBX_SUCCESS)
        log_write(LS_SYSTEM, L_WARNING, 0, "history: mdbx_env_set_option(sync_period) failed: %s",
                  mdbx_strerror(rc));
    }
  }

  /* Open databases in a transaction */
  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_txn_begin failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open main message database */
  rc = mdbx_dbi_open(txn, "messages", MDBX_CREATE, &history_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_dbi_open(messages) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open msgid index database */
  rc = mdbx_dbi_open(txn, "msgid_index", MDBX_CREATE, &history_msgid_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_dbi_open(msgid_index) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open targets database */
  rc = mdbx_dbi_open(txn, "targets", MDBX_CREATE, &history_targets_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_dbi_open(targets) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open per-user quota counter database */
  rc = mdbx_dbi_open(txn, "quotas", MDBX_CREATE, &history_quota_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_dbi_open(quotas) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open reply/context index database (DUPSORT: one parent can have multiple children) */
  rc = mdbx_dbi_open(txn, "reply_index", MDBX_CREATE | MDBX_DUPSORT, &history_reply_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_dbi_open(reply_index) failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  /* Open multiline content databases (ml_content + ml_paste_secrets) */
  if (ml_content_init(history_env, txn) != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "history: ml_content_init failed, multiline content store unavailable");
    /* Non-fatal — history still works, just without separate multiline storage */
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: mdbx_txn_commit failed: %s",
              mdbx_strerror(rc));
    mdbx_env_close(history_env);
    history_env = NULL;
    return -1;
  }

  history_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "history: LMDB initialized at %s", dbpath);

  /* Pre-fault database pages into OS page cache for faster initial queries */
  rc = mdbx_env_warmup(history_env, NULL, MDBX_warmup_default, 0);
  if (rc != MDBX_SUCCESS && rc != MDBX_RESULT_TRUE)
    log_write(LS_SYSTEM, L_WARNING, 0, "history: mdbx_env_warmup failed: %s",
              mdbx_strerror(rc));

  return 0;
}

void history_shutdown(void)
{
  if (!history_available)
    return;

  /* Force sync before shutdown if NOSYNC mode was used */
  if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
    log_write(LS_SYSTEM, L_INFO, 0, "history: final sync before shutdown");
    mdbx_env_sync_ex(history_env, true, false);
  }

  ml_content_shutdown(history_env);
  mdbx_dbi_close(history_env, history_dbi);
  mdbx_dbi_close(history_env, history_msgid_dbi);
  mdbx_dbi_close(history_env, history_targets_dbi);
  mdbx_dbi_close(history_env, history_quota_dbi);
  mdbx_dbi_close(history_env, history_reply_dbi);
  mdbx_env_close(history_env);
  history_env = NULL;
  history_available = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "history: LMDB shutdown complete");
}

MDBX_env *history_get_env(void)
{
  return history_env;
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *sender,
                          const char *account, enum HistoryMessageType type,
                          const char *content, const char *client_tags)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, vallen;
  int rc;
  int retry = 0;

  /* Dynamic buffer sizing based on actual content length.
   * Stack fast-path for common single-line messages (<=HISTORY_VALUE_BUFSIZE),
   * heap allocation for multiline content that exceeds it.
   */
  size_t content_len = content ? strlen(content) : 0;
  size_t tags_len = client_tags ? strlen(client_tags) : 0;
  size_t bufsize = content_len + tags_len + HISTORY_SENDER_LEN + ACCOUNTLEN + 32;
  if (bufsize < HISTORY_VALUE_BUFSIZE)
    bufsize = HISTORY_VALUE_BUFSIZE;

  char valbuf_stack[HISTORY_VALUE_BUFSIZE];
  char *valbuf = (bufsize > sizeof(valbuf_stack))
      ? (char *)MyMalloc(bufsize) : valbuf_stack;
#ifdef USE_ZSTD
  unsigned char comp_stack[HISTORY_VALUE_BUFSIZE + 64];
  size_t comp_bufsize = bufsize + 64;
  unsigned char *compressed = (comp_bufsize > sizeof(comp_stack))
      ? (unsigned char *)MyMalloc(comp_bufsize) : comp_stack;
  size_t compressed_len;
#endif

  if (!history_available) {
    rc = -1;
    goto store_cleanup;
  }

  /* Build key: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    rc = -1;
    goto store_cleanup;
  }

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
  vallen = serialize_message(valbuf, bufsize, type, sender, account, content,
                             client_tags);
  if (vallen < 0) {
    rc = -1;
    goto store_cleanup;
  }
  /* Cap vallen — ircd_snprintf returns would-have-been length including overflow */
  if ((size_t)vallen >= bufsize)
    vallen = bufsize - 1;

store_retry:
  /* Begin write transaction */
  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdbx_txn_begin failed: %s", mdbx_strerror(rc)));
    rc = -1;
    goto store_cleanup;
  }

  /* Store message (with optional compression) */
  key.iov_len = keylen;
  key.iov_base = keybuf;
#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    compressed, comp_bufsize, &compressed_len) >= 0) {
    data.iov_len = compressed_len;
    data.iov_base = compressed;
  } else {
    data.iov_len = vallen;
    data.iov_base = valbuf;
  }
#else
  data.iov_len = vallen;
  data.iov_base = valbuf;
#endif

  /* Try MDBX_APPEND first — skips B-tree traversal when key is the global max.
   * Messages arrive chronologically per-channel, so for the most active channel
   * this often succeeds. Falls back to normal put on key mismatch. */
  rc = mdbx_put(txn, history_dbi, &key, &data, MDBX_APPEND);
  if (rc == MDBX_EKEYMISMATCH)
    rc = mdbx_put(txn, history_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdbx_put failed: %s", mdbx_strerror(rc)));
    mdbx_txn_abort(txn);
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }

  /* Store msgid -> target\0timestamp index */
  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;
  /* Value is target\0timestamp */
  {
    int idx_keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, NULL);
    data.iov_len = idx_keylen;
    data.iov_base = keybuf;
  }

  rc = mdbx_put(txn, history_msgid_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdbx_put(msgid) failed: %s", mdbx_strerror(rc)));
    mdbx_txn_abort(txn);
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }

  /* Update target's last message timestamp */
  key.iov_len = strlen(target);
  key.iov_base = (void *)target;
  data.iov_len = strlen(timestamp);
  data.iov_base = (void *)timestamp;

  rc = mdbx_put(txn, history_targets_dbi, &key, &data, 0);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdbx_put(target) failed: %s", mdbx_strerror(rc)));
    mdbx_txn_abort(txn);
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }

  /* Index reply references for draft/chathistory-context lookups.
   * Check for +reply= in client_tags (reactions) and REDACT target msgid. */
  {
    char parent_mid[HISTORY_MSGID_LEN];
    const char *parent = extract_reply_tag(client_tags, parent_mid, sizeof(parent_mid));
    if (parent)
      reply_index_put(txn, target, parent, timestamp, msgid);

    if (type == HISTORY_REDACT && content && content[0]) {
      /* REDACT content format: "target_msgid [:reason]" */
      const char *space = strchr(content, ' ');
      size_t len = space ? (size_t)(space - content) : strlen(content);
      if (len > 0 && len < sizeof(parent_mid)) {
        memcpy(parent_mid, content, len);
        parent_mid[len] = '\0';
        reply_index_put(txn, target, parent_mid, timestamp, msgid);
      }
    }
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    Debug((DEBUG_DEBUG, "history: mdbx_txn_commit failed: %s", mdbx_strerror(rc)));
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }

  /* Update quota counter for this user (if enabled and account is known) */
  if (feature_bool(FEAT_CHATHISTORY_USER_QUOTA) && account && account[0]) {
    int new_count = quota_increment(target, account);

    /* Check if user just exceeded their quota and warn */
    if (new_count > 0) {
      int quota_pct = feature_int(FEAT_CHATHISTORY_USER_QUOTA_PCT);
      int channel_limit = feature_int(FEAT_CHATHISTORY_MAX);
      int max_allowed = (channel_limit * quota_pct) / 100;

      /* Warn when first exceeding quota (at exactly max_allowed + 1) */
      if (quota_pct > 0 && quota_pct < 100 && new_count == max_allowed + 1) {
        log_write(LS_SYSTEM, L_WARNING, 0,
                  "history: user %s exceeded quota in %s (%d/%d messages, %d%%)",
                  account, target, new_count, channel_limit, quota_pct);
      }
    }
  }

  rc = 0;

store_cleanup:
  if (valbuf != valbuf_stack) MyFree(valbuf);
#ifdef USE_ZSTD
  if (compressed != comp_stack) MyFree(compressed);
#endif
  return rc;
}

int history_store_multiline(const char *msgid, const char *timestamp,
                            const char *target, const char *sender,
                            const char *account, const char *content,
                            size_t content_len, const char *paste_secret)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, vallen;
  int rc;
  int retry = 0;

  /* Serialize the history entry with the \x1Eml sentinel as content.
   * The actual multiline content goes in ml_content, not inline.
   */
  char valbuf[HISTORY_VALUE_BUFSIZE];
#ifdef USE_ZSTD
  unsigned char comp_buf[HISTORY_VALUE_BUFSIZE + 64];
  size_t compressed_len;
#endif

  if (!history_available)
    return -1;

  /* Build key: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0)
    return -1;

  /* Serialize with sentinel content */
  vallen = serialize_message(valbuf, sizeof(valbuf), HISTORY_PRIVMSG,
                             sender, account, ML_CONTENT_SENTINEL, NULL);
  if (vallen < 0)
    return -1;
  if ((size_t)vallen >= sizeof(valbuf))
    vallen = sizeof(valbuf) - 1;

store_ml_retry:
  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  /* Store multiline content in ml_content DBI */
  if (ml_content_store(txn, msgid, sender, target,
                       content, content_len, paste_secret) != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Store history entry with sentinel */
  key.iov_len = keylen;
  key.iov_base = keybuf;
#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    comp_buf, sizeof(comp_buf), &compressed_len) >= 0) {
    data.iov_len = compressed_len;
    data.iov_base = comp_buf;
  } else {
    data.iov_len = vallen;
    data.iov_base = valbuf;
  }
#else
  data.iov_len = vallen;
  data.iov_base = valbuf;
#endif

  rc = mdbx_put(txn, history_dbi, &key, &data, MDBX_APPEND);
  if (rc == MDBX_EKEYMISMATCH)
    rc = mdbx_put(txn, history_dbi, &key, &data, 0);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_ml_retry;
    }
    return -1;
  }

  /* Store msgid index */
  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;
  {
    int idx_keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, NULL);
    data.iov_len = idx_keylen;
    data.iov_base = keybuf;
  }
  rc = mdbx_put(txn, history_msgid_dbi, &key, &data, 0);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_ml_retry;
    }
    return -1;
  }

  /* Update target timestamp */
  key.iov_len = strlen(target);
  key.iov_base = (void *)target;
  data.iov_len = strlen(timestamp);
  data.iov_base = (void *)timestamp;
  rc = mdbx_put(txn, history_targets_dbi, &key, &data, 0);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_ml_retry;
    }
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    if (rc == MDBX_MAP_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_ml_retry;
    }
    return -1;
  }

  /* Update quota */
  if (feature_bool(FEAT_CHATHISTORY_USER_QUOTA) && account && account[0]) {
    quota_increment(target, account);
  }

  return 0;
}

int history_has_msgid(const char *msgid)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  int rc;

  if (!history_available)
    return -1;

  if (!msgid || !msgid[0])
    return 0;

  /* Begin read transaction */
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  /* Look up msgid in the msgid index */
  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_get(txn, history_msgid_dbi, &key, &data);
  mdbx_txn_abort(txn);

  if (rc == 0)
    return 1;  /* Found */
  if (rc == MDBX_NOTFOUND)
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
                                  int limit, struct HistoryMessage **result,
                                  const char *floor_key, int floor_keylen)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
  struct HistoryMessage *head = NULL, *tail = NULL, *msg;
  char target_prefix[CHANNELLEN + 2];
  int target_prefix_len;
  int count = 0;
  int rc;
  MDBX_cursor_op op;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Build target prefix for boundary checking */
  target_prefix_len = ircd_snprintf(0, target_prefix, sizeof(target_prefix),
                                    "%s%c", target, KEY_SEP);

  /* Begin read transaction */
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Position cursor */
  key.iov_len = start_keylen;
  key.iov_base = (void *)start_key;

  if (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST) {
    /* For BEFORE/LATEST, we want to go backwards from the reference */
    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: SET_RANGE rc=%d (%s)",
              rc, rc == 0 ? "found" : (rc == MDBX_NOTFOUND ? "not found" : mdbx_strerror(rc)));
    if (rc == MDBX_NOTFOUND) {
      /* Position at last entry */
      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_LAST);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: MDBX_LAST rc=%d", rc);
    } else if (rc == 0) {
      /* Move back one since SET_RANGE gives us >= */
      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: MDBX_PREV rc=%d", rc);
    }
    op = MDBX_PREV;
  } else {
    /* For AFTER, go forwards from AFTER the reference */
    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: AFTER SET_RANGE rc=%d", rc);
    /* Skip any messages that match the reference timestamp prefix
     * (AFTER means strictly after, not including the reference) */
    while (rc == 0 && key.iov_len >= (size_t)start_keylen &&
           memcmp(key.iov_base, start_key, start_keylen) == 0) {
      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
    }
    op = MDBX_NEXT;
  }

  /* Log cursor position after positioning */
  if (rc == 0) {
    char key_preview[64];
    size_t preview_len = key.iov_len < 60 ? key.iov_len : 60;
    memcpy(key_preview, key.iov_base, preview_len);
    key_preview[preview_len] = '\0';
    /* Replace null bytes with dots for display */
    for (size_t i = 0; i < preview_len; i++) {
      if (key_preview[i] == '\0') key_preview[i] = '.';
    }
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: positioned at key='%s' (len=%zu)",
              key_preview, key.iov_len);
  } else {
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: no position, rc=%d", rc);
  }

  /* Iterate and collect messages */
  while (rc == 0 && count < limit) {
    /* Check if still in target's range */
    if (key.iov_len < (size_t)target_prefix_len ||
        memcmp(key.iov_base, target_prefix, target_prefix_len) != 0) {
      /* Outside target range */
      char key_preview[64];
      size_t preview_len = key.iov_len < 60 ? key.iov_len : 60;
      memcpy(key_preview, key.iov_base, preview_len);
      key_preview[preview_len] = '\0';
      for (size_t i = 0; i < preview_len; i++) {
        if (key_preview[i] == '\0') key_preview[i] = '.';
      }
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: key='%s' outside target range, breaking",
                key_preview);
      /* For all directions, once outside target range we're done.
       * LMDB keys are sorted, so if we've moved past the target prefix,
       * we'll never find more messages for this target. */
      break;
    }

    /* Floor check for backward iteration: stop if we've walked past
     * the floor timestamp (used by auto-replay to get the most recent
     * N messages but no older than the since-timestamp). */
    if (floor_key && floor_keylen > 0 &&
        (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST)) {
      if (key.iov_len >= (size_t)floor_keylen &&
          memcmp(key.iov_base, floor_key, floor_keylen) <= 0)
        break;
    }

    /* Allocate message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    /* Parse key to get target, timestamp, msgid */
    if (parse_key(key.iov_base, key.iov_len,
                  msg->target, msg->timestamp, msg->msgid) != 0) {
      MyFree(msg);
      rc = mdbx_cursor_get(cursor, &key, &data, op);
      continue;
    }

#ifdef USE_ZSTD
    /* Preserve raw compressed data for federation passthrough */
    if (is_compressed((const unsigned char *)data.iov_base, data.iov_len)) {
      msg->raw_content = (unsigned char *)MyMalloc(data.iov_len);
      if (msg->raw_content) {
        memcpy(msg->raw_content, data.iov_base, data.iov_len);
        msg->raw_content_len = data.iov_len;
      }
    }
#endif

    /* Parse value */
    if (deserialize_message(data.iov_base, data.iov_len, msg) != 0) {
      if (msg->raw_content)
        MyFree(msg->raw_content);
      MyFree(msg);
      rc = mdbx_cursor_get(cursor, &key, &data, op);
      continue;
    }

    /* Resolve multiline content from ml_content store if needed */
    ml_content_resolve(txn, msg);

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

    /* Periodically park/unpark the read transaction to release the snapshot.
     * This prevents long-running reads from blocking GC page reclamation
     * by writers. The park interval is feature-controlled; 0 disables. */
    {
      int park_interval = feature_int(FEAT_CHATHISTORY_DB_PARK_INTERVAL);
      if (park_interval > 0 && count % park_interval == 0) {
        /* Save current key for cursor re-positioning */
        char saved_key[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
        size_t saved_keylen = key.iov_len < sizeof(saved_key) ? key.iov_len : sizeof(saved_key) - 1;
        memcpy(saved_key, key.iov_base, saved_keylen);

        mdbx_cursor_close(cursor);
        cursor = NULL;

        rc = mdbx_txn_park(txn, 0);
        if (rc != MDBX_SUCCESS) {
          /* Park failed — reopen cursor on the existing snapshot and
           * continue without parking.  The snapshot stays held longer
           * but the query still completes. */
          rc = mdbx_cursor_open(txn, history_dbi, &cursor);
          if (rc != MDBX_SUCCESS)
            break;
          /* Re-position and advance past the key we already processed */
          key.iov_base = saved_key;
          key.iov_len = saved_keylen;
          rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);
          if (rc != 0)
            break;
          if (op == MDBX_PREV) {
            rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
          } else if (key.iov_len == saved_keylen &&
                     memcmp(key.iov_base, saved_key, saved_keylen) == 0) {
            rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
          }
          if (rc != 0)
            break;
          continue;
        }

        rc = mdbx_txn_unpark(txn, 0);
        if (rc != MDBX_SUCCESS) {
          /* Unpark failed — transaction is no longer usable. */
          break;
        }

        rc = mdbx_cursor_open(txn, history_dbi, &cursor);
        if (rc != MDBX_SUCCESS)
          break;

        /* Re-position cursor at saved key */
        key.iov_base = saved_key;
        key.iov_len = saved_keylen;
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);

        if (rc != 0)
          break;

        /* For backwards iteration, the saved key was the last one we processed.
         * SET_RANGE lands on >= saved_key, so step back to continue. */
        if (op == MDBX_PREV) {
          rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
          if (rc != 0)
            break;
        }
        /* For forward iteration, SET_RANGE lands on >= saved_key. If it lands
         * on the exact same key we already processed, advance past it. */
        else if (key.iov_len == saved_keylen &&
                 memcmp(key.iov_base, saved_key, saved_keylen) == 0) {
          rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
          if (rc != 0)
            break;
        }

        continue;  /* Re-check target prefix boundary before processing */
      }
    }

    rc = mdbx_cursor_get(cursor, &key, &data, op);
  }

  if (cursor)
    mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

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
                                HISTORY_DIR_BEFORE, limit, result,
                                NULL, 0);
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
                                HISTORY_DIR_AFTER, limit, result,
                                NULL, 0);
}

int history_query_latest(const char *target, enum HistoryRefType ref_type,
                         const char *reference, int limit,
                         struct HistoryMessage **result)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char floorbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen, floorlen;

  *result = NULL;

  if (ref_type == HISTORY_REF_NONE) {
    /* LATEST * - start from end of target's range */
    keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
    if (keylen < 0)
      return -1;
    return history_query_internal(target, keybuf, keylen,
                                  HISTORY_DIR_LATEST, limit, result,
                                  NULL, 0);
  }

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

  /* LATEST with anchor: walk backwards from the end, stop at anchor.
   * Per IRCv3 spec, LATEST <target> <msgid> <limit> returns the most
   * recent messages AFTER the anchor, up to limit. */
  keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
  floorlen = build_key(floorbuf, sizeof(floorbuf), target, reference, NULL);
  if (keylen < 0 || floorlen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_LATEST, limit, result,
                                floorbuf, floorlen);
}

int history_query_latest_after(const char *target, int limit,
                               const char *after_timestamp,
                               struct HistoryMessage **result)
{
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char floorbuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  const char *floor_ts;
  int keylen, floorlen;

  *result = NULL;

  /* Convert after_timestamp if ISO 8601 */
  if (history_iso_to_unix(after_timestamp, timestamp, sizeof(timestamp)) == 0)
    floor_ts = timestamp;
  else
    floor_ts = after_timestamp;

  /* Start key: far future (scan backward from end of target's range) */
  keylen = build_key(keybuf, sizeof(keybuf), target, "32503680000.000", NULL);
  if (keylen < 0)
    return -1;

  /* Floor key: stop backward walk at (or before) the since-timestamp */
  floorlen = build_key(floorbuf, sizeof(floorbuf), target, floor_ts, NULL);
  if (floorlen < 0)
    return -1;

  return history_query_internal(target, keybuf, keylen,
                                HISTORY_DIR_LATEST, limit, result,
                                floorbuf, floorlen);
}

int history_find_last_join(const char *channel, const char *nick,
                           char *out_msgid, size_t msgid_len,
                           char *out_timestamp, size_t timestamp_len)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + 8];
  char target_prefix[CHANNELLEN + 2];
  int target_prefix_len, keylen, rc;
  int found = 0;
  size_t nick_len;

  if (!history_available || !channel || !nick)
    return 0;

  nick_len = strlen(nick);

  /* Build target prefix for boundary checking */
  target_prefix_len = ircd_snprintf(0, target_prefix, sizeof(target_prefix),
                                    "%s%c", channel, KEY_SEP);

  /* Start from end of channel's key range */
  keylen = build_key(keybuf, sizeof(keybuf), channel, "32503680000.000", NULL);
  if (keylen < 0)
    return 0;

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return 0;

  rc = mdbx_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return 0;
  }

  /* Position at or after the far-future key */
  key.iov_len = keylen;
  key.iov_base = (void *)keybuf;
  rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);
  if (rc == MDBX_NOTFOUND)
    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_LAST);
  else if (rc == 0)
    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);

  /* Walk backward through channel history looking for this user's last JOIN.
   * JOIN events are channel metadata, so they're relatively frequent —
   * typically found within a few hundred entries at most. Cap the scan
   * to avoid pathological cases. */
  {
    int scanned = 0;
    int max_scan = 2000;

    while (rc == 0 && scanned < max_scan) {
      const char *val;
      const char *pipe1, *pipe2;
      int type;

      /* Check if still in channel's range */
      if (key.iov_len < (size_t)target_prefix_len ||
          memcmp(key.iov_base, target_prefix, target_prefix_len) != 0)
        break;

      scanned++;
      val = (const char *)data.iov_base;

      /* Quick reject: compressed data won't start with a digit.
       * JOIN events are short and shouldn't be compressed, but skip
       * compressed entries rather than decompressing them all. */
      if (is_compressed((const unsigned char *)val, data.iov_len)) {
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
        continue;
      }

      /* Value format: type|sender|account|content
       * HISTORY_JOIN = 2, so we need "2|nick!..." */
      pipe1 = memchr(val, '|', data.iov_len);
      if (!pipe1) {
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
        continue;
      }

      type = atoi(val);
      if (type != HISTORY_JOIN) {
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
        continue;
      }

      /* Check sender: starts with "nick!" */
      pipe2 = memchr(pipe1 + 1, '|', data.iov_len - (pipe1 + 1 - val));
      if (!pipe2) {
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
        continue;
      }

      {
        const char *sender = pipe1 + 1;
        size_t sender_len = pipe2 - sender;
        if (sender_len > nick_len && sender[nick_len] == '!' &&
            ircd_strncmp(sender, nick, nick_len) == 0) {
          /* Found it — extract msgid and timestamp from the key */
          char tmp_target[CHANNELLEN + 1];
          char tmp_ts[HISTORY_TIMESTAMP_LEN];
          char tmp_msgid[HISTORY_MSGID_LEN];
          if (parse_key(key.iov_base, key.iov_len,
                        tmp_target, tmp_ts, tmp_msgid) == 0) {
            if (out_msgid && msgid_len > 0) {
              ircd_strncpy(out_msgid, tmp_msgid, msgid_len);
            }
            if (out_timestamp && timestamp_len > 0) {
              ircd_strncpy(out_timestamp, tmp_ts, timestamp_len);
            }
            found = 1;
          }
          break;
        }
      }

      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_PREV);
    }
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);
  return found;
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
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
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
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  key.iov_len = keylen;
  key.iov_base = keybuf;
  rc = mdbx_cursor_get(cursor, &key, &data, MDBX_SET_RANGE);

  while (rc == 0 && count < limit) {
    /* Check if past end */
    if (key.iov_len >= (size_t)end_prefix_len &&
        memcmp(key.iov_base, end_prefix, end_prefix_len) >= 0)
      break;

    /* Parse and add message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    if (parse_key(key.iov_base, key.iov_len,
                  msg->target, msg->timestamp, msg->msgid) != 0 ||
        deserialize_message(data.iov_base, data.iov_len, msg) != 0) {
      MyFree(msg);
      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
      continue;
    }

    /* Resolve multiline content from ml_content store if needed */
    ml_content_resolve(txn, msg);

    msg->next = NULL;
    if (tail)
      tail->next = msg;
    else
      head = msg;
    tail = msg;
    count++;

    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

  *result = head;
  return count;
}

int history_query_targets(const char *timestamp1, const char *timestamp2,
                          int limit, struct HistoryTarget **result)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
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

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, history_targets_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Iterate all targets */
  rc = mdbx_cursor_get(cursor, &key, &data, MDBX_FIRST);
  while (rc == 0 && count < limit) {
    /* Check if target's last message is in range */
    char last_ts[HISTORY_TIMESTAMP_LEN];
    if (data.iov_len >= sizeof(last_ts)) {
      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
      continue;
    }
    memcpy(last_ts, data.iov_base, data.iov_len);
    last_ts[data.iov_len] = '\0';

    if (strcmp(last_ts, ts1) >= 0 && strcmp(last_ts, ts2) <= 0) {
      tgt = (struct HistoryTarget *)MyMalloc(sizeof(struct HistoryTarget));
      if (!tgt)
        break;
      memset(tgt, 0, sizeof(*tgt));

      if (key.iov_len > CHANNELLEN) {
        MyFree(tgt);
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
        continue;
      }
      memcpy(tgt->target, key.iov_base, key.iov_len);
      tgt->target[key.iov_len] = '\0';
      ircd_strncpy(tgt->last_timestamp, last_ts, sizeof(tgt->last_timestamp) - 1);
      tgt->next = NULL;

      if (tail)
        tail->next = tgt;
      else
        head = tgt;
      tail = tgt;
      count++;
    }

    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

  *result = head;
  return count;
}

void history_free_messages(struct HistoryMessage *list)
{
  struct HistoryMessage *msg, *next;

  for (msg = list; msg; msg = next) {
    next = msg->next;
    if (msg->dyn_content)
      MyFree(msg->dyn_content);
    if (msg->raw_content)
      MyFree(msg->raw_content);
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
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, val;
  char target[CHANNELLEN + 1];
  int count = 0;
  int rc;

  if (!history_available || !callback)
    return -1;

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, history_targets_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Iterate all targets */
  rc = mdbx_cursor_get(cursor, &key, &val, MDBX_FIRST);
  while (rc == 0) {
    if (key.iov_len > 0 && key.iov_len <= CHANNELLEN) {
      memcpy(target, key.iov_base, key.iov_len);
      target[key.iov_len] = '\0';

      /* Only call back for channels (start with # or &) */
      if (target[0] == '#' || target[0] == '&') {
        count++;
        if (callback(target, data) != 0)
          break;  /* Callback requested stop */
      }
    }
    rc = mdbx_cursor_get(cursor, &key, &val, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

  return count;
}

int history_has_channel(const char *target)
{
  MDBX_txn *txn;
  MDBX_val key, val;
  int rc;

  if (!history_available || !target)
    return -1;

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.iov_len = strlen(target);
  key.iov_base = (void *)target;

  rc = mdbx_get(txn, history_targets_dbi, &key, &val);
  mdbx_txn_abort(txn);

  if (rc == 0)
    return 1;  /* Found */
  if (rc == MDBX_NOTFOUND)
    return 0;  /* Not found */
  return -1;   /* Error */
}

int history_channel_has_messages(const char *target)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, val;
  char prefix[CHANNELLEN + 2];
  int prefix_len;
  int rc;

  if (!history_available || !target)
    return -1;

  /* Build prefix key: "target\0" */
  prefix_len = strlen(target);
  if (prefix_len > CHANNELLEN)
    return -1;
  memcpy(prefix, target, prefix_len);
  prefix[prefix_len] = KEY_SEP;
  prefix_len++;

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Position at or after prefix */
  key.iov_len = prefix_len;
  key.iov_base = prefix;
  rc = mdbx_cursor_get(cursor, &key, &val, MDBX_SET_RANGE);

  if (rc == 0) {
    /* Check if key starts with our prefix */
    if (key.iov_len >= (size_t)prefix_len &&
        memcmp(key.iov_base, prefix, prefix_len) == 0) {
      /* Found at least one message for this channel */
      mdbx_cursor_close(cursor);
      mdbx_txn_abort(txn);
      return 1;
    }
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);
  return 0;  /* No messages found */
}

void history_set_channel_removed_callback(history_channels_removed_cb cb)
{
  channel_removed_callback = cb;
}

int history_purge_old(unsigned long max_age_seconds)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
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
  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge mdbx_txn_begin failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  /* Open cursor on messages database */
  rc = mdbx_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge mdbx_cursor_open failed: %s",
              mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Iterate from the beginning (oldest messages first due to key structure) */
  rc = mdbx_cursor_get(cursor, &key, &data, MDBX_FIRST);
  while (rc == 0) {
    /* Parse the key to get timestamp */
    if (parse_key(key.iov_base, key.iov_len,
                  msg_target, msg_timestamp, msg_msgid) == 0) {
      /* Compare timestamp with cutoff */
      if (strcmp(msg_timestamp, cutoff_ts) < 0) {
        /* Message is older than cutoff - delete it */

        /* First delete from msgid index and ml_content if we have a msgid */
        if (msg_msgid[0] != '\0') {
          MDBX_val msgid_key;
          msgid_key.iov_len = strlen(msg_msgid);
          msgid_key.iov_base = msg_msgid;
          mdbx_del(txn, history_msgid_dbi, &msgid_key, NULL);
          ml_content_delete(txn, msg_msgid);

          /* Delete reply index entries where this msgid is the parent.
           * Orphaned child entries (referencing deleted parents) are harmless
           * and cleaned when the child itself is purged. */
          {
            char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
            MDBX_val ri_key;
            int ri_kpos = 0;
            size_t tlen = strlen(msg_target), mlen = strlen(msg_msgid);
            if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
              memcpy(ri_keybuf, msg_target, tlen);
              ri_kpos += tlen;
              ri_keybuf[ri_kpos++] = KEY_SEP;
              memcpy(ri_keybuf + ri_kpos, msg_msgid, mlen);
              ri_kpos += mlen;
              ri_key.iov_base = ri_keybuf;
              ri_key.iov_len = ri_kpos;
              mdbx_del(txn, history_reply_dbi, &ri_key, NULL);
            }
          }
        }

        /* Delete the message using cursor */
        rc = mdbx_cursor_del(cursor, 0);
        if (rc == 0) {
          deleted++;
        }

        /* Move to next (cursor position is already at next after del) */
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_GET_CURRENT);
        if (rc == MDBX_NOTFOUND) {
          /* Deleted last entry, try to get next */
          rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
        }
        continue;
      }
    }

    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);

  /* Commit the transaction */
  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge mdbx_txn_commit failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  if (deleted > 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "history: purged %d old messages (cutoff: %s)",
              deleted, cutoff_ts);
    /* Clean up empty targets and notify via callback */
    history_cleanup_empty_targets();
  }

  return deleted;
}

/** Clean up targets_dbi entries for channels with no messages.
 * Called after eviction/purge to maintain consistency and trigger CH A - broadcasts.
 * @return Number of targets cleaned up, or -1 on error.
 */
static int history_cleanup_empty_targets(void)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, val;
  char target[CHANNELLEN + 1];
  char *channels_to_remove[256];  /* Buffer for channel names to remove */
  int remove_count = 0;
  int removed = 0;
  int rc, i;

  if (!history_available)
    return -1;

  /* First pass: collect channels that have no more messages (read-only) */
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_cursor_open(txn, history_targets_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_cursor_get(cursor, &key, &val, MDBX_FIRST);
  while (rc == 0 && remove_count < 256) {
    if (key.iov_len > 0 && key.iov_len <= CHANNELLEN) {
      memcpy(target, key.iov_base, key.iov_len);
      target[key.iov_len] = '\0';

      /* Only process channels (start with # or &) */
      if (target[0] == '#' || target[0] == '&') {
        /* Check if this channel still has messages */
        /* Need to abort current txn and check in a new one */
        mdbx_cursor_close(cursor);
        mdbx_txn_abort(txn);

        if (history_channel_has_messages(target) == 0) {
          /* No messages - add to removal list */
          channels_to_remove[remove_count] = MyMalloc(strlen(target) + 1);
          if (channels_to_remove[remove_count]) {
            strcpy(channels_to_remove[remove_count], target);
            remove_count++;
          }
        }

        /* Re-open transaction and cursor to continue */
        rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
        if (rc != 0)
          goto cleanup_list;

        rc = mdbx_cursor_open(txn, history_targets_dbi, &cursor);
        if (rc != 0) {
          mdbx_txn_abort(txn);
          goto cleanup_list;
        }

        /* Position cursor after current key */
        key.iov_len = strlen(target);
        key.iov_base = target;
        rc = mdbx_cursor_get(cursor, &key, &val, MDBX_SET_RANGE);
        if (rc == 0) {
          /* Skip if we landed on same key */
          if (key.iov_len == strlen(target) &&
              memcmp(key.iov_base, target, key.iov_len) == 0) {
            rc = mdbx_cursor_get(cursor, &key, &val, MDBX_NEXT);
          }
        }
        continue;
      }
    }
    rc = mdbx_cursor_get(cursor, &key, &val, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);
  mdbx_txn_abort(txn);

cleanup_list:
  /* Second pass: remove collected targets and call callback */
  if (remove_count > 0) {
    rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
    if (rc == 0) {
      for (i = 0; i < remove_count; i++) {
        key.iov_len = strlen(channels_to_remove[i]);
        key.iov_base = channels_to_remove[i];
        rc = mdbx_del(txn, history_targets_dbi, &key, NULL);
        if (rc == 0) {
          removed++;
          Debug((DEBUG_DEBUG, "history: removed empty target %s", channels_to_remove[i]));
        }
      }
      mdbx_txn_commit(txn);
    }

    /* Call callback with all removed channels at once (after DB commit) */
    if (channel_removed_callback && remove_count > 0) {
      channel_removed_callback((const char **)channels_to_remove, remove_count);
    }
  }

  /* Free allocated channel names */
  for (i = 0; i < remove_count; i++) {
    MyFree(channels_to_remove[i]);
  }

  if (removed > 0) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: cleaned up %d empty channel targets", removed);
  }

  return removed;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  const char *sep;
  int rc;

  log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: looking up msgid=%s", msgid);

  if (!history_available) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: history not available");
    return -1;
  }

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: txn_begin failed: %s", mdbx_strerror(rc));
    return -1;
  }

  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_get(txn, history_msgid_dbi, &key, &data);
  mdbx_txn_abort(txn);

  if (rc != 0) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: mdbx_get failed for msgid=%s: %s", msgid, mdbx_strerror(rc));
    return -1;
  }

  /* Value is target\0timestamp\0 - extract timestamp (exclude trailing separator) */
  sep = memchr(data.iov_base, KEY_SEP, data.iov_len);
  if (!sep)
    return -1;

  sep++; /* Skip separator after target */

  /* Calculate copy length - exclude trailing KEY_SEP if present */
  {
    size_t copy_len = (char *)data.iov_base + data.iov_len - sep;
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
  MDBX_txn *txn;
  MDBX_val key, data;
  struct HistoryMessage *m;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  *msg = NULL;

  if (!history_available)
    return -1;

  /* First, look up the msgid to get target and timestamp */
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return -1;

  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_get(txn, history_msgid_dbi, &key, &data);
  if (rc == MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return 1; /* Not found */
  }
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Value is target\0timestamp\0 - extract timestamp (exclude trailing KEY_SEP) */
  {
    const char *sep;
    size_t copy_len;
    sep = memchr(data.iov_base, KEY_SEP, data.iov_len);
    if (!sep) {
      mdbx_txn_abort(txn);
      return -1;
    }
    sep++; /* Skip separator after target */
    copy_len = (char *)data.iov_base + data.iov_len - sep;
    /* build_key adds trailing KEY_SEP, exclude it */
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN) {
      mdbx_txn_abort(txn);
      return -1;
    }
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
  }

  /* Build key for main database lookup: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  key.iov_len = keylen;
  key.iov_base = keybuf;

  rc = mdbx_get(txn, history_dbi, &key, &data);
  if (rc == MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return 1; /* Not found */
  }
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Allocate and populate message structure */
  m = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
  if (!m) {
    mdbx_txn_abort(txn);
    return -1;
  }
  memset(m, 0, sizeof(*m));

  /* Parse the message */
  if (deserialize_message(data.iov_base, data.iov_len, m) != 0) {
    MyFree(m);
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Fill in the key fields */
  ircd_strncpy(m->msgid, msgid, sizeof(m->msgid) - 1);
  ircd_strncpy(m->target, target, sizeof(m->target) - 1);
  ircd_strncpy(m->timestamp, timestamp, sizeof(m->timestamp) - 1);
  m->next = NULL;

  /* Resolve multiline content from ml_content store if needed */
  ml_content_resolve(txn, m);

  mdbx_txn_abort(txn);
  *msg = m;
  return 0;
}

int history_delete_message(const char *target, const char *msgid)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  /* First, look up the msgid to get the timestamp */
  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_get(txn, history_msgid_dbi, &key, &data);
  if (rc == MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return 1; /* Not found */
  }
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Extract timestamp from value (target\0timestamp) */
  {
    const char *sep;
    sep = memchr(data.iov_base, KEY_SEP, data.iov_len);
    if (!sep) {
      mdbx_txn_abort(txn);
      return -1;
    }
    sep++; /* Skip separator */
    if ((size_t)((char *)data.iov_base + data.iov_len - sep) >= HISTORY_TIMESTAMP_LEN) {
      mdbx_txn_abort(txn);
      return -1;
    }
    memcpy(timestamp, sep, (char *)data.iov_base + data.iov_len - sep);
    timestamp[(char *)data.iov_base + data.iov_len - sep] = '\0';
  }

  /* Delete from msgid index and ml_content */
  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;
  rc = mdbx_del(txn, history_msgid_dbi, &key, NULL);
  if (rc != 0 && rc != MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return -1;
  }
  ml_content_delete(txn, msgid);

  /* Build key for main database: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Delete from main message database */
  key.iov_len = keylen;
  key.iov_base = keybuf;
  rc = mdbx_del(txn, history_dbi, &key, NULL);
  if (rc != 0 && rc != MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Clean reply index entries where this msgid is the parent */
  {
    char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
    MDBX_val ri_key;
    int ri_kpos = 0;
    size_t tlen = strlen(target), mlen = strlen(msgid);
    if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
      memcpy(ri_keybuf, target, tlen);
      ri_kpos += tlen;
      ri_keybuf[ri_kpos++] = KEY_SEP;
      memcpy(ri_keybuf + ri_kpos, msgid, mlen);
      ri_kpos += mlen;
      ri_key.iov_base = ri_keybuf;
      ri_key.iov_len = ri_kpos;
      mdbx_del(txn, history_reply_dbi, &ri_key, NULL);
    }
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0)
    return -1;

  return 0;
}

int history_is_available(void)
{
  return history_available;
}

int history_attach_context(const char *target, struct HistoryMessage *messages)
{
  MDBX_txn *txn;
  MDBX_cursor *ri_cursor;
  struct HistoryMessage *msg;
  int added = 0;
  int rc;

  if (!history_available || !messages)
    return 0;

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return 0;

  rc = mdbx_cursor_open(txn, history_reply_dbi, &ri_cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return 0;
  }

  for (msg = messages; msg; msg = msg->next) {
    char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
    MDBX_val ri_key, ri_val;
    int ri_kpos = 0;
    size_t tlen, mlen;

    /* Skip context messages themselves (don't attach context to context) */
    if (msg->is_context)
      continue;

    /* Build reply index key: target\0msgid */
    tlen = strlen(target);
    mlen = strlen(msg->msgid);
    if (tlen + 1 + mlen >= sizeof(ri_keybuf))
      continue;
    memcpy(ri_keybuf, target, tlen);
    ri_kpos = tlen;
    ri_keybuf[ri_kpos++] = KEY_SEP;
    memcpy(ri_keybuf + ri_kpos, msg->msgid, mlen);
    ri_kpos += mlen;

    ri_key.iov_base = ri_keybuf;
    ri_key.iov_len = ri_kpos;

    /* Find all children for this parent */
    rc = mdbx_cursor_get(ri_cursor, &ri_key, &ri_val, MDBX_SET_KEY);
    while (rc == 0) {
      /* Value is timestamp\0child_msgid */
      const char *sep = memchr(ri_val.iov_base, KEY_SEP, ri_val.iov_len);
      if (sep) {
        char child_ts[HISTORY_TIMESTAMP_LEN];
        char child_mid[HISTORY_MSGID_LEN];
        size_t ts_len = sep - (const char *)ri_val.iov_base;
        size_t mid_len = (const char *)ri_val.iov_base + ri_val.iov_len - (sep + 1);

        if (ts_len < sizeof(child_ts) && mid_len < sizeof(child_mid) && mid_len > 0) {
          MDBX_val main_key, main_data;
          char main_keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
          int main_keylen;
          struct HistoryMessage *ctx;

          memcpy(child_ts, ri_val.iov_base, ts_len);
          child_ts[ts_len] = '\0';
          memcpy(child_mid, sep + 1, mid_len);
          child_mid[mid_len] = '\0';

          /* Check if this child msgid is already in the primary list (avoid dup) */
          {
            struct HistoryMessage *dup;
            int found = 0;
            for (dup = messages; dup; dup = dup->next) {
              if (strcmp(dup->msgid, child_mid) == 0) {
                found = 1;
                break;
              }
            }
            if (found)
              goto next_dup;
          }

          /* Fetch the full message from main DBI */
          main_keylen = build_key(main_keybuf, sizeof(main_keybuf), target, child_ts, child_mid);
          if (main_keylen < 0)
            goto next_dup;

          main_key.iov_base = main_keybuf;
          main_key.iov_len = main_keylen;
          rc = mdbx_get(txn, history_dbi, &main_key, &main_data);
          if (rc != 0)
            goto next_dup;

          ctx = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
          if (deserialize_message(main_data.iov_base, main_data.iov_len, ctx) != 0) {
            MyFree(ctx);
            goto next_dup;
          }

          /* Fill in key fields */
          ircd_strncpy(ctx->target, target, sizeof(ctx->target));
          ircd_strncpy(ctx->timestamp, child_ts, sizeof(ctx->timestamp));
          ircd_strncpy(ctx->msgid, child_mid, sizeof(ctx->msgid));
          ctx->is_context = 1;

          /* Splice into list immediately after the parent */
          ctx->next = msg->next;
          msg->next = ctx;
          added++;
        }
      }
next_dup:
      rc = mdbx_cursor_get(ri_cursor, &ri_key, &ri_val, MDBX_NEXT_DUP);
    }
  }

  mdbx_cursor_close(ri_cursor);
  mdbx_txn_abort(txn);
  return added;
}

int history_redact_message(const char *target, const char *msgid)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  /* Look up msgid to get timestamp */
  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_get(txn, history_msgid_dbi, &key, &data);
  if (rc == MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return 1;
  }
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Extract timestamp from value (target\0timestamp) */
  {
    const char *sep = memchr(data.iov_base, KEY_SEP, data.iov_len);
    if (!sep) {
      mdbx_txn_abort(txn);
      return -1;
    }
    sep++;
    if ((size_t)((char *)data.iov_base + data.iov_len - sep) >= HISTORY_TIMESTAMP_LEN) {
      mdbx_txn_abort(txn);
      return -1;
    }
    memcpy(timestamp, sep, (char *)data.iov_base + data.iov_len - sep);
    timestamp[(char *)data.iov_base + data.iov_len - sep] = '\0';
  }

  /* Build full key for main database */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Fetch the current message to get sender and account */
  key.iov_base = keybuf;
  key.iov_len = keylen;
  rc = mdbx_get(txn, history_dbi, &key, &data);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return (rc == MDBX_NOTFOUND) ? 1 : -1;
  }

  /* Deserialize to get type, sender, account */
  {
    struct HistoryMessage orig;
    char valbuf[HISTORY_VALUE_BUFSIZE];
    int vallen;
    MDBX_val new_data;

    memset(&orig, 0, sizeof(orig));
    if (deserialize_message(data.iov_base, data.iov_len, &orig) != 0) {
      mdbx_txn_abort(txn);
      return -1;
    }

    /* Re-serialize with empty content and no client_tags */
    vallen = serialize_message(valbuf, sizeof(valbuf), orig.type,
                               orig.sender, orig.account, "", NULL);
    if (vallen < 0 || (size_t)vallen >= sizeof(valbuf)) {
      mdbx_txn_abort(txn);
      return -1;
    }

    /* Overwrite in main DBI */
    key.iov_base = keybuf;
    key.iov_len = keylen;
#ifdef USE_ZSTD
    {
      unsigned char comp_buf[HISTORY_VALUE_BUFSIZE + 64];
      size_t comp_len;
      if (compress_data((unsigned char *)valbuf, vallen,
                        comp_buf, sizeof(comp_buf), &comp_len) >= 0) {
        new_data.iov_base = comp_buf;
        new_data.iov_len = comp_len;
      } else {
        new_data.iov_base = valbuf;
        new_data.iov_len = vallen;
      }
      rc = mdbx_put(txn, history_dbi, &key, &new_data, 0);
    }
#else
    new_data.iov_base = valbuf;
    new_data.iov_len = vallen;
    rc = mdbx_put(txn, history_dbi, &key, &new_data, 0);
#endif
    if (rc != 0) {
      mdbx_txn_abort(txn);
      return -1;
    }
  }

  /* Delete multiline content if any */
  ml_content_delete(txn, msgid);

  rc = mdbx_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
}

/** Build a readmarker key from account and target.
 * @param[out] key Output buffer.
 * @param[in] keysize Size of output buffer.
 * @param[in] account Account name.
 * @param[in] target Channel or nick.
 * @return Length of key, or -1 on error.
 */
/* Read marker functions removed - now in metadata.c (metadata_readmarker_get/set) */

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

/** Emergency eviction count (for inline MDBX_MAP_FULL recovery) */
#define EMERGENCY_EVICT_BATCH 500

/** Emergency eviction for inline MDBX_MAP_FULL recovery.
 * Called when a write fails due to database full condition.
 * Evicts a small batch of oldest messages to make room.
 * @return Number of messages evicted, or -1 on error.
 */
static int history_emergency_evict(void)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
  char msg_target[CHANNELLEN + 1];
  char msg_timestamp[HISTORY_TIMESTAMP_LEN];
  char msg_msgid[HISTORY_MSGID_LEN];
  struct HistoryMessage msg;
  int evicted = 0;
  int rc;
  int quota_enabled = feature_bool(FEAT_CHATHISTORY_USER_QUOTA);

  /* Collect accounts to decrement quotas after commit (avoid nested txns) */
  struct {
    char target[CHANNELLEN + 1];
    char account[ACCOUNTLEN + 1];
  } quota_updates[EMERGENCY_EVICT_BATCH];
  int quota_update_count = 0;

  if (!history_available)
    return -1;

  log_write(LS_SYSTEM, L_WARNING, 0,
            "history: emergency eviction triggered (MDBX_MAP_FULL)");

  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction txn_begin failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  rc = mdbx_cursor_open(txn, history_dbi, &cursor);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Evict oldest entries */
  rc = mdbx_cursor_get(cursor, &key, &data, MDBX_FIRST);
  while (rc == 0 && evicted < EMERGENCY_EVICT_BATCH) {
    /* Parse key to get target and msgid for index cleanup */
    if (parse_key(key.iov_base, key.iov_len,
                  msg_target, msg_timestamp, msg_msgid) == 0) {
      if (msg_msgid[0] != '\0') {
        MDBX_val msgid_key;
        msgid_key.iov_len = strlen(msg_msgid);
        msgid_key.iov_base = msg_msgid;
        mdbx_del(txn, history_msgid_dbi, &msgid_key, NULL);
        ml_content_delete(txn, msg_msgid);

        /* Clean reply index entries where this msgid is the parent */
        {
          char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
          MDBX_val ri_key;
          int ri_kpos = 0;
          size_t tlen = strlen(msg_target), mlen = strlen(msg_msgid);
          if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
            memcpy(ri_keybuf, msg_target, tlen);
            ri_kpos += tlen;
            ri_keybuf[ri_kpos++] = KEY_SEP;
            memcpy(ri_keybuf + ri_kpos, msg_msgid, mlen);
            ri_kpos += mlen;
            ri_key.iov_base = ri_keybuf;
            ri_key.iov_len = ri_kpos;
            mdbx_del(txn, history_reply_dbi, &ri_key, NULL);
          }
        }
      }
    }

    /* Collect account info for quota decrement after commit */
    if (quota_enabled && msg_target[0] != '\0' &&
        quota_update_count < EMERGENCY_EVICT_BATCH) {
      if (deserialize_message(data.iov_base, data.iov_len, &msg) == 0 &&
          msg.account[0] != '\0') {
        ircd_strncpy(quota_updates[quota_update_count].target, msg_target,
                     CHANNELLEN);
        ircd_strncpy(quota_updates[quota_update_count].account, msg.account,
                     ACCOUNTLEN);
        quota_update_count++;
      }
    }

    rc = mdbx_cursor_del(cursor, 0);
    if (rc != 0)
      break;

    evicted++;
    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
  }

  mdbx_cursor_close(cursor);

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction commit failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  /* Decrement quotas for evicted messages (now that main txn is committed) */
  for (int i = 0; i < quota_update_count; i++) {
    quota_decrement(quota_updates[i].target, quota_updates[i].account);
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
  MDBX_envinfo info;
  MDBX_stat envstat;
  int rc;
  size_t used_size;
  int percent;

  if (!history_available)
    return -1;

  /* Get environment info for map size */
  rc = mdbx_env_info_ex(history_env, NULL, &info, sizeof(info));
  if (rc != MDBX_SUCCESS)
    return -1;

  /* Get environment stats for page size */
  rc = mdbx_env_stat_ex(history_env, NULL, &envstat, sizeof(envstat));
  if (rc != MDBX_SUCCESS)
    return -1;

  /* Calculate used size: (last_pgno + 1) * page_size
   * Note: mi_last_pgno is 0-indexed, so add 1 for count */
  used_size = (info.mi_last_pgno + 1) * envstat.ms_psize;

  /* Calculate percentage */
  if (info.mi_geo.upper == 0)
    return 0;

  percent = (int)((used_size * 100) / info.mi_geo.upper);
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
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
  char msg_target[CHANNELLEN + 1];
  char msg_timestamp[HISTORY_TIMESTAMP_LEN];
  char msg_msgid[HISTORY_MSGID_LEN];
  struct HistoryMessage msg;
  int evicted = 0;
  int current_util;
  int rc;
  int batch_count = 0;
  int max_batch = 1000;  /* Limit per transaction */
  int quota_enabled = feature_bool(FEAT_CHATHISTORY_USER_QUOTA);

  /* Collect accounts to decrement quotas after commit (avoid nested txns) */
  struct {
    char target[CHANNELLEN + 1];
    char account[ACCOUNTLEN + 1];
  } *quota_updates = NULL;
  int quota_update_count = 0;
  int quota_update_capacity = 0;

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

  /* Allocate quota update buffer if enabled */
  if (quota_enabled) {
    quota_update_capacity = max_batch;
    quota_updates = MyMalloc(quota_update_capacity * sizeof(*quota_updates));
  }

  /* Evict oldest messages until we reach target */
  while (current_util > target_percent) {
    rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
    if (rc != 0)
      break;

    rc = mdbx_cursor_open(txn, history_dbi, &cursor);
    if (rc != 0) {
      mdbx_txn_abort(txn);
      break;
    }

    batch_count = 0;
    quota_update_count = 0;

    /* Iterate from beginning (oldest entries) */
    rc = mdbx_cursor_get(cursor, &key, &data, MDBX_FIRST);
    while (rc == 0 && batch_count < max_batch) {
      /* Parse key to get msgid for index cleanup */
      if (parse_key(key.iov_base, key.iov_len,
                    msg_target, msg_timestamp, msg_msgid) == 0) {
        /* Delete from msgid index and ml_content if present */
        if (msg_msgid[0] != '\0') {
          MDBX_val msgid_key;
          msgid_key.iov_len = strlen(msg_msgid);
          msgid_key.iov_base = msg_msgid;
          mdbx_del(txn, history_msgid_dbi, &msgid_key, NULL);
          ml_content_delete(txn, msg_msgid);

          /* Clean reply index entries where this msgid is the parent */
          {
            char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
            MDBX_val ri_key;
            int ri_kpos = 0;
            size_t tlen = strlen(msg_target), mlen = strlen(msg_msgid);
            if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
              memcpy(ri_keybuf, msg_target, tlen);
              ri_kpos += tlen;
              ri_keybuf[ri_kpos++] = KEY_SEP;
              memcpy(ri_keybuf + ri_kpos, msg_msgid, mlen);
              ri_kpos += mlen;
              ri_key.iov_base = ri_keybuf;
              ri_key.iov_len = ri_kpos;
              mdbx_del(txn, history_reply_dbi, &ri_key, NULL);
            }
          }
        }
      }

      /* Collect account info for quota decrement after commit */
      if (quota_enabled && quota_updates && msg_target[0] != '\0' &&
          quota_update_count < quota_update_capacity) {
        if (deserialize_message(data.iov_base, data.iov_len, &msg) == 0 &&
            msg.account[0] != '\0') {
          ircd_strncpy(quota_updates[quota_update_count].target, msg_target,
                       CHANNELLEN);
          ircd_strncpy(quota_updates[quota_update_count].account, msg.account,
                       ACCOUNTLEN);
          quota_update_count++;
        }
      }

      /* Delete from main database */
      rc = mdbx_cursor_del(cursor, 0);
      if (rc != 0)
        break;

      evicted++;
      batch_count++;

      /* Move to next */
      rc = mdbx_cursor_get(cursor, &key, &data, MDBX_GET_CURRENT);
      if (rc == MDBX_NOTFOUND)
        rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT);
    }

    mdbx_cursor_close(cursor);

    rc = mdbx_txn_commit(txn);
    if (rc != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history: eviction commit failed: %s", mdbx_strerror(rc));
      break;
    }

    /* Decrement quotas for evicted messages */
    for (int i = 0; i < quota_update_count; i++) {
      quota_decrement(quota_updates[i].target, quota_updates[i].account);
    }

    /* Recheck utilization */
    current_util = history_db_utilization();
    if (current_util < 0)
      break;

    /* If we didn't evict anything, we're done */
    if (batch_count == 0)
      break;
  }

  /* Free quota update buffer */
  if (quota_updates)
    MyFree(quota_updates);

  /* Update eviction stats */
  last_eviction_count = evicted;
  last_eviction_time = time(NULL);

  log_write(LS_SYSTEM, L_INFO, 0,
            "history: eviction complete, evicted=%d new_util=%d%%",
            evicted, current_util);

  /* Clean up empty targets and notify via callback */
  if (evicted > 0) {
    history_cleanup_empty_targets();
  }

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

  /* Clean up stale reader slots to prevent GC blockage */
  {
    int dead = 0;
    mdbx_reader_check(history_env, &dead);
    if (dead > 0)
      log_write(LS_SYSTEM, L_WARNING, 0, "history: cleared %d stale reader(s)", dead);
  }

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
  MDBX_stat stat;
  MDBX_stat envstat;
  MDBX_envinfo info;
  MDBX_txn *txn;
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
  rc = mdbx_env_info_ex(history_env, NULL, &info, sizeof(info));
  if (rc != MDBX_SUCCESS)
    return;

  rc = mdbx_env_stat_ex(history_env, NULL, &envstat, sizeof(envstat));
  if (rc != MDBX_SUCCESS)
    return;

  /* Calculate storage utilization */
  used_size = (info.mi_last_pgno + 1) * envstat.ms_psize;
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
             (unsigned long)(info.mi_geo.upper / (1024 * 1024)),
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

  /* Environment-level mdbx diagnostics */
  {
    size_t total_pages = (info.mi_last_pgno + 1);
    size_t data_pages = envstat.ms_branch_pages + envstat.ms_leaf_pages + envstat.ms_overflow_pages;
    size_t free_pages = total_pages > data_pages ? total_pages - data_pages : 0;

    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Geometry: %lu / %lu / %lu MB (current/grow-to/max)",
               (unsigned long)(info.mi_geo.current / (1024 * 1024)),
               (unsigned long)(info.mi_geo.grow / (1024 * 1024)),
               (unsigned long)(info.mi_geo.upper / (1024 * 1024)));
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Pages: branch=%lu leaf=%lu overflow=%lu free=%lu (psize=%u)",
               (unsigned long)envstat.ms_branch_pages,
               (unsigned long)envstat.ms_leaf_pages,
               (unsigned long)envstat.ms_overflow_pages,
               (unsigned long)free_pages,
               envstat.ms_psize);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "H :  Readers: %u active, nosync=%s",
               info.mi_numreaders,
               feature_bool(FEAT_CHATHISTORY_DB_NOSYNC) ? "yes" : "no");
  }

  /* Get per-database stats */
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc == 0) {
    /* Main message database */
    rc = mdbx_dbi_stat(txn, history_dbi, &stat, sizeof(stat));
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Messages: %lu entries, depth %u",
                 (unsigned long)stat.ms_entries, stat.ms_depth);
    }

    /* Targets database */
    rc = mdbx_dbi_stat(txn, history_targets_dbi, &stat, sizeof(stat));
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  Channels: %lu",
                 (unsigned long)stat.ms_entries);
    }

    /* Message ID index */
    rc = mdbx_dbi_stat(txn, history_msgid_dbi, &stat, sizeof(stat));
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "H :  MsgID index: %lu entries",
                 (unsigned long)stat.ms_entries);
    }

    /* GC (garbage collection) info */
    {
      MDBX_gc_info_t gc;
      memset(&gc, 0, sizeof(gc));
      rc = mdbx_gc_info(txn, &gc, sizeof(gc), NULL, NULL);
      if (rc == 0 || rc == MDBX_NOTFOUND) {
        send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                   "H :  GC: total=%lu backed=%lu alloc=%lu gc=%lu reclaimable=%lu",
                   (unsigned long)gc.pages_total,
                   (unsigned long)gc.pages_backed,
                   (unsigned long)gc.pages_allocated,
                   (unsigned long)gc.pages_gc,
                   (unsigned long)gc.gc_reclaimable.pages);
        if (gc.max_reader_lag > 0 || gc.max_retained_pages > 0) {
          send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                     "H :  GC pressure: reader_lag=%lu retained=%lu pages",
                     (unsigned long)gc.max_reader_lag,
                     (unsigned long)gc.max_retained_pages);
        }
      }
    }

    mdbx_txn_abort(txn);
  }
}

/** \brief Defragment the history database.
 * Moves pages from the end of the DB file to free pages near the beginning,
 * then truncates, reducing file size.
 * \param time_limit_seconds  Maximum wall-clock time to spend (0 = no limit)
 * \return 0 on success, negative on error */
int
history_defrag(unsigned int time_limit_seconds)
{
  MDBX_defrag_result_t result;
  size_t time_16dot16;
  int rc;

  if (!history_available || !history_env)
    return -1;

  memset(&result, 0, sizeof(result));
  /* Convert seconds to 16.16 fixed-point (seconds * 65536) */
  time_16dot16 = time_limit_seconds ? (size_t)time_limit_seconds * 65536 : 0;

  rc = mdbx_env_defrag(history_env,
                        0,              /* defrag_atleast: no minimum */
                        0,              /* time_atleast: no minimum time */
                        0,              /* defrag_enough: no upper goal */
                        time_16dot16,   /* time_limit */
                        -1,             /* acceptable_backlash: autopilot */
                        0,              /* preferred_batch: no limit */
                        NULL, NULL,     /* no progress callback */
                        &result);

  log_write(LS_SYSTEM, L_INFO, 0,
            "history: defrag complete rc=%d shrinked=%ld moved=%lu cycles=%u reasons=0x%x",
            rc, (long)result.pages_shrinked,
            (unsigned long)result.pages_moved,
            result.cycles, result.stopping_reasons);

  return rc;
}

/** \brief Report defrag results for history DB */
void
history_report_defrag(struct Client *to)
{
  MDBX_defrag_result_t result;
  size_t time_16dot16;
  int rc;

  if (!history_available || !history_env) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "D :  History: unavailable");
    return;
  }

  memset(&result, 0, sizeof(result));
  /* 5 second time limit for interactive defrag */
  time_16dot16 = 5 * 65536;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  History: defragmenting (5s limit)...");

  rc = mdbx_env_defrag(history_env,
                        0, 0, 0,
                        time_16dot16,
                        -1, 0,
                        NULL, NULL,
                        &result);

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "D :  History: rc=%d shrinked=%ld moved=%lu left=%lu cycles=%u",
             rc, (long)result.pages_shrinked,
             (unsigned long)result.pages_moved,
             (unsigned long)result.pages_left,
             result.cycles);

  if (result.stopping_reasons) {
    char reasons[128];
    reasons[0] = '\0';
    if (result.stopping_reasons & 1) strcat(reasons, "threshold ");
    if (result.stopping_reasons & 2) strcat(reasons, "time-limit ");
    if (result.stopping_reasons & 4) strcat(reasons, "laggard-reader ");
    if (result.stopping_reasons & 8) strcat(reasons, "large-chunk ");
    if (result.stopping_reasons & 16) strcat(reasons, "user-break ");
    if (result.stopping_reasons & 32) strcat(reasons, "error ");
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "D :  History: stopped: %s", reasons);
  }
}

/** \brief Force sync/flush the history database to disk.
 * \return 0 on success, -1 on error */
int
history_sync(void)
{
  if (!history_available || !history_env)
    return -1;
  return mdbx_env_sync_ex(history_env, 1, 0);
}

/** \brief Report detailed GC info for the history database. */
void
history_report_gc(struct Client *to)
{
  MDBX_txn *txn;
  MDBX_gc_info_t gc;
  MDBX_stat envstat;
  int rc;

  if (!history_available || !history_env) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  History GC: unavailable");
    return;
  }

  rc = mdbx_env_stat_ex(history_env, NULL, &envstat, sizeof(envstat));
  if (rc != MDBX_SUCCESS)
    return;

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return;

  memset(&gc, 0, sizeof(gc));
  rc = mdbx_gc_info(txn, &gc, sizeof(gc), NULL, NULL);
  if (rc == 0 || rc == MDBX_NOTFOUND) {
    size_t page_size = envstat.ms_psize;

    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  History GC:");
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Pages: total=%lu backed=%lu allocated=%lu",
               (unsigned long)gc.pages_total,
               (unsigned long)gc.pages_backed,
               (unsigned long)gc.pages_allocated);
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    GC pages=%lu reclaimable=%lu",
               (unsigned long)gc.pages_gc,
               (unsigned long)gc.gc_reclaimable.pages);
    if (page_size > 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "X :    Reclaimable: %lu KB (%lu MB)",
                 (unsigned long)(gc.gc_reclaimable.pages * page_size / 1024),
                 (unsigned long)(gc.gc_reclaimable.pages * page_size / (1024 * 1024)));
    }
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :    Reader lag=%lu retained=%lu pages",
               (unsigned long)gc.max_reader_lag,
               (unsigned long)gc.max_retained_pages);
  }

  mdbx_txn_abort(txn);
}

/** \brief Report detailed MDBX environment info for the history database. */
void
history_report_mdbx_info(struct Client *to)
{
  MDBX_envinfo info;
  MDBX_stat envstat;
  MDBX_stat stat;
  MDBX_txn *txn;
  int rc;

  if (!history_available || !history_env) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "X :  History: unavailable");
    return;
  }

  rc = mdbx_env_info_ex(history_env, NULL, &info, sizeof(info));
  if (rc != MDBX_SUCCESS)
    return;

  rc = mdbx_env_stat_ex(history_env, NULL, &envstat, sizeof(envstat));
  if (rc != MDBX_SUCCESS)
    return;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :  History Environment:");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Page size: %u bytes", envstat.ms_psize);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Geometry: min=%lu cur=%lu max=%lu MB",
             (unsigned long)(info.mi_geo.lower / (1024 * 1024)),
             (unsigned long)(info.mi_geo.current / (1024 * 1024)),
             (unsigned long)(info.mi_geo.upper / (1024 * 1024)));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Growth=%lu MB  Shrink=%lu MB",
             (unsigned long)(info.mi_geo.grow / (1024 * 1024)),
             (unsigned long)(info.mi_geo.shrink / (1024 * 1024)));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Last pgno=%lu  Readers=%u/%u",
             (unsigned long)info.mi_last_pgno,
             info.mi_numreaders, info.mi_maxreaders);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    Pages: branch=%lu leaf=%lu overflow=%lu",
             (unsigned long)envstat.ms_branch_pages,
             (unsigned long)envstat.ms_leaf_pages,
             (unsigned long)envstat.ms_overflow_pages);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "X :    B-tree depth: %u", envstat.ms_depth);

  /* Per-database stats */
  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc == 0) {
    rc = mdbx_dbi_stat(txn, history_dbi, &stat, sizeof(stat));
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "X :    messages: %lu entries depth=%u branch=%lu leaf=%lu overflow=%lu",
                 (unsigned long)stat.ms_entries, stat.ms_depth,
                 (unsigned long)stat.ms_branch_pages,
                 (unsigned long)stat.ms_leaf_pages,
                 (unsigned long)stat.ms_overflow_pages);
    }
    rc = mdbx_dbi_stat(txn, history_targets_dbi, &stat, sizeof(stat));
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "X :    targets: %lu entries depth=%u",
                 (unsigned long)stat.ms_entries, stat.ms_depth);
    }
    rc = mdbx_dbi_stat(txn, history_msgid_dbi, &stat, sizeof(stat));
    if (rc == 0) {
      send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
                 "X :    msgid_index: %lu entries depth=%u",
                 (unsigned long)stat.ms_entries, stat.ms_depth);
    }
    mdbx_txn_abort(txn);
  }
}


/* ========== Per-User Quota Tracking ========== */

/** Increment quota counter for a user in a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name (NULL = anonymous, not tracked).
 * @return New count, or -1 on error.
 */
static int quota_increment(const char *channel, const char *account)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + ACCOUNTLEN + 2];
  int keylen, rc;
  uint32_t count = 0;

  if (!history_available || !channel)
    return -1;

  /* Anonymous users not tracked for quotas */
  if (!account || !account[0])
    return 0;

  /* Build key: channel\0account */
  keylen = ircd_snprintf(0, keybuf, sizeof(keybuf), "%s%c%s",
                          channel, KEY_SEP, account);

  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  key.iov_base = keybuf;
  key.iov_len = keylen;

  /* Get current count */
  rc = mdbx_get(txn, history_quota_dbi, &key, &data);
  if (rc == 0 && data.iov_len == sizeof(uint32_t)) {
    memcpy(&count, data.iov_base, sizeof(uint32_t));
  }

  /* Increment */
  count++;

  /* Store new count */
  data.iov_base = &count;
  data.iov_len = sizeof(uint32_t);

  rc = mdbx_put(txn, history_quota_dbi, &key, &data, 0);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0)
    return -1;

  return (int)count;
}

/** Decrement quota counter for a user in a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name.
 * @return New count, or -1 on error.
 */
static int quota_decrement(const char *channel, const char *account)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + ACCOUNTLEN + 2];
  int keylen, rc;
  uint32_t count = 0;

  if (!history_available || !channel)
    return -1;

  if (!account || !account[0])
    return 0;

  keylen = ircd_snprintf(0, keybuf, sizeof(keybuf), "%s%c%s",
                          channel, KEY_SEP, account);

  rc = mdbx_txn_begin(history_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  key.iov_base = keybuf;
  key.iov_len = keylen;

  rc = mdbx_get(txn, history_quota_dbi, &key, &data);
  if (rc == 0 && data.iov_len == sizeof(uint32_t)) {
    memcpy(&count, data.iov_base, sizeof(uint32_t));
    if (count > 0)
      count--;

    data.iov_base = &count;
    data.iov_len = sizeof(uint32_t);

    rc = mdbx_put(txn, history_quota_dbi, &key, &data, 0);
    if (rc != 0) {
      mdbx_txn_abort(txn);
      return -1;
    }
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0)
    return -1;

  return (int)count;
}

/** Get quota count for a user in a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name.
 * @return Message count, or 0 if not found.
 */
int history_quota_get_count(const char *channel, const char *account)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char keybuf[CHANNELLEN + ACCOUNTLEN + 2];
  int keylen, rc;
  uint32_t count = 0;

  if (!history_available || !channel || !account || !account[0])
    return 0;

  keylen = ircd_snprintf(0, keybuf, sizeof(keybuf), "%s%c%s",
                          channel, KEY_SEP, account);

  rc = mdbx_txn_begin(history_env, NULL, MDBX_RDONLY, &txn);
  if (rc != 0)
    return 0;

  key.iov_base = keybuf;
  key.iov_len = keylen;

  rc = mdbx_get(txn, history_quota_dbi, &key, &data);
  if (rc == 0 && data.iov_len == sizeof(uint32_t)) {
    memcpy(&count, data.iov_base, sizeof(uint32_t));
  }

  mdbx_txn_abort(txn);
  return (int)count;
}

/** Check if a user is over their quota for a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name.
 * @param[in] channel_limit Total messages allowed in channel.
 * @return 1 if over quota, 0 if not.
 */
int history_quota_check(const char *channel, const char *account, int channel_limit)
{
  int count, quota_pct, max_allowed;

  if (!feature_bool(FEAT_CHATHISTORY_USER_QUOTA))
    return 0;  /* Quotas disabled */

  if (!account || !account[0])
    return 0;  /* Anonymous users not quota-limited */

  quota_pct = feature_int(FEAT_CHATHISTORY_USER_QUOTA_PCT);
  if (quota_pct <= 0 || quota_pct >= 100)
    return 0;  /* Invalid or disabled quota */

  count = history_quota_get_count(channel, account);
  max_allowed = (channel_limit * quota_pct) / 100;

  return (count >= max_allowed) ? 1 : 0;
}


#else /* !USE_MDBX */

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
                          const char *content, const char *client_tags)
{
  (void)msgid; (void)timestamp; (void)target; (void)sender;
  (void)account; (void)type; (void)content; (void)client_tags;
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

int history_query_latest_after(const char *target, int limit,
                               const char *after_timestamp,
                               struct HistoryMessage **result)
{
  (void)target; (void)limit; (void)after_timestamp;
  *result = NULL;
  return -1;
}

int history_find_last_join(const char *channel, const char *nick,
                           char *out_msgid, size_t msgid_len,
                           char *out_timestamp, size_t timestamp_len)
{
  (void)channel; (void)nick;
  (void)out_msgid; (void)msgid_len;
  (void)out_timestamp; (void)timestamp_len;
  return 0;
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

int history_channel_has_messages(const char *target)
{
  (void)target;
  return -1;
}

void history_set_channel_removed_callback(history_channels_removed_cb cb)
{
  (void)cb;
}

int history_defrag(unsigned int time_limit_seconds)
{
  (void)time_limit_seconds;
  return -1;
}

void history_report_defrag(struct Client *to)
{
  (void)to;
}

int history_sync(void)
{
  return -1;
}

void history_report_gc(struct Client *to)
{
  (void)to;
}

void history_report_mdbx_info(struct Client *to)
{
  (void)to;
}

/* Quota tracking stubs */
int history_quota_get_count(const char *channel, const char *account)
{
  (void)channel; (void)account;
  return 0;
}

int history_quota_check(const char *channel, const char *account, int channel_limit)
{
  (void)channel; (void)account; (void)channel_limit;
  return 0;  /* Never over quota when no LMDB */
}

#endif /* USE_MDBX */
