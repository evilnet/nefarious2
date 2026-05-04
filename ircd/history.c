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

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
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

/** Storage environment opened through the db_* abstraction.  Owns the
 * underlying MDBX env / CF handles; closed via db_env_close. */
static struct db_env *history_db_env = NULL;
static struct db_cf  *history_cf_messages = NULL;
static struct db_cf  *history_cf_msgid = NULL;
static struct db_cf  *history_cf_targets = NULL;
static struct db_cf  *history_cf_quotas = NULL;
static struct db_cf  *history_cf_reply = NULL;  /* DUPSORT */

/** Raw MDBX handles unwrapped from the abstraction.  Same underlying
 * env/dbi as the db_* statics above; exist because the function
 * bodies in this file haven't been fully converted off raw mdbx yet
 * (Phase 0g is incremental).  Phase 5 RocksDB migration completes
 * the conversion and deletes them. */
static MDBX_env *history_env = NULL;
static MDBX_dbi history_dbi;
static MDBX_dbi history_msgid_dbi;
static MDBX_dbi history_targets_dbi;
static MDBX_dbi history_quota_dbi;
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
 *
 * Accepts both the ratified +reply tag (IRCv3 #535, ratified 2026-02-13)
 * and the legacy +draft/reply form for backward compat with clients
 * that haven't updated yet. If both are present, the ratified form wins.
 *
 * @param[in] client_tags Semicolon-separated tag list (e.g.
 *   "+draft/react=X;+reply=MSGID" or "+draft/reply=MSGID").
 * @param[out] buf Buffer for the extracted msgid.
 * @param[in] buflen Size of buf.
 * @return Pointer to buf on success, NULL if neither form is present.
 */
static const char *extract_reply_tag(const char *client_tags, char *buf, size_t buflen)
{
  static const struct {
    const char *needle;
    size_t      len;
  } needles[] = {
    { "+reply=",       7 },   /* ratified — checked first */
    { "+draft/reply=", 13 },  /* legacy draft form */
  };
  size_t i;

  if (!client_tags || !client_tags[0])
    return NULL;

  for (i = 0; i < sizeof(needles) / sizeof(needles[0]); i++) {
    const char *p = client_tags;
    while ((p = strstr(p, needles[i].needle)) != NULL) {
      /* Ensure it's at the start or after a separator. */
      if (p != client_tags && *(p - 1) != ';') {
        p += needles[i].len;
        continue;
      }
      p += needles[i].len;
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

/* reply_index_del_child was an orphan-cleanup helper for retention purge,
 * never wired up — the actual purge / delete paths just delete the
 * parent-side entries directly (orphan child→parent links are harmless
 * and clean themselves when the child row goes away).  Removed. */

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
  struct db_env_opts env_opts;
  struct db_cf_opts  cf_opts;
  int rc;

  if (history_available)
    return 0; /* Already initialized */

  memset(&env_opts, 0, sizeof env_opts);
  if (feature_bool(FEAT_CHATHISTORY_DB_AUTOGROW)) {
    env_opts.size_floor = 0;
    env_opts.size_max   = history_map_size;
  } else {
    env_opts.size_floor = history_map_size;
    env_opts.size_max   = history_map_size;
  }
  if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
    env_opts.sync_period_seconds = (unsigned int)feature_int(FEAT_CHATHISTORY_DB_SYNC_INTERVAL);
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: using MDBX_SAFE_NOSYNC with %u second sync interval",
              env_opts.sync_period_seconds);
  }

  rc = db_env_open(dbpath, &env_opts, HISTORY_MAX_DBS, &history_db_env);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: db_env_open(%s) failed: %s",
              dbpath, db_strerror(rc));
    return -1;
  }

  /* Open the column families.  reply_index uses dupsort. */
  memset(&cf_opts, 0, sizeof cf_opts);
  if (db_cf_open(history_db_env, "messages", &cf_opts, &history_cf_messages) != DB_OK
      || db_cf_open(history_db_env, "msgid_index", &cf_opts, &history_cf_msgid) != DB_OK
      || db_cf_open(history_db_env, "targets", &cf_opts, &history_cf_targets) != DB_OK
      || db_cf_open(history_db_env, "quotas", &cf_opts, &history_cf_quotas) != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: db_cf_open failed: %s",
              db_env_last_error(history_db_env));
    db_env_close(history_db_env);
    history_db_env = NULL;
    return -1;
  }
  cf_opts.dupsort = 1;
  if (db_cf_open(history_db_env, "reply_index", &cf_opts, &history_cf_reply) != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: db_cf_open(reply_index): %s",
              db_env_last_error(history_db_env));
    db_env_close(history_db_env);
    history_db_env = NULL;
    return -1;
  }

  /* Populate the legacy raw-mdbx handles so the function bodies that
   * still use raw mdbx in this file (queries, store, eviction) keep
   * working against the same underlying env/dbis.  Will be retired
   * as the function bodies are converted in follow-up commits. */
  history_env         = db_mdbx_unwrap_env(history_db_env);
  history_dbi         = db_mdbx_unwrap_dbi(history_cf_messages);
  history_msgid_dbi   = db_mdbx_unwrap_dbi(history_cf_msgid);
  history_targets_dbi = db_mdbx_unwrap_dbi(history_cf_targets);
  history_quota_dbi   = db_mdbx_unwrap_dbi(history_cf_quotas);
  history_reply_dbi   = db_mdbx_unwrap_dbi(history_cf_reply);

  /* Open multiline content databases (shares this env) */
  if (ml_content_init(history_db_env) != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "history: ml_content_init failed, multiline content store unavailable");
    /* Non-fatal — history still works, just without separate multiline storage */
  }

  history_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "history: storage initialized at %s", dbpath);

  /* Pre-fault database pages into OS page cache for faster initial queries */
  db_env_warmup(history_db_env);

  return 0;
}

void history_shutdown(void)
{
  if (!history_available)
    return;

  /* Force sync before shutdown if NOSYNC mode was used */
  if (feature_bool(FEAT_CHATHISTORY_DB_NOSYNC)) {
    log_write(LS_SYSTEM, L_INFO, 0, "history: final sync before shutdown");
    db_env_sync(history_db_env);
  }

  ml_content_shutdown(history_db_env);
  db_cf_close(history_db_env, history_cf_messages);
  db_cf_close(history_db_env, history_cf_msgid);
  db_cf_close(history_db_env, history_cf_targets);
  db_cf_close(history_db_env, history_cf_quotas);
  db_cf_close(history_db_env, history_cf_reply);
  db_env_close(history_db_env);
  history_db_env = NULL;
  history_cf_messages = NULL;
  history_cf_msgid = NULL;
  history_cf_targets = NULL;
  history_cf_quotas = NULL;
  history_cf_reply = NULL;
  history_env = NULL;  /* legacy raw handle, owned by db_env */
  history_available = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "history: storage shutdown complete");
}

struct db_env *history_get_env(void)
{
  return history_db_env;
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *sender,
                          const char *account, enum HistoryMessageType type,
                          const char *content, const char *client_tags)
{
  struct db_writebatch *wb = NULL;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char idxkeybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, idx_keylen, vallen;
  int rc;
  int retry = 0;
  const void *vbuf;
  size_t       vlen;

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

  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    rc = -1;
    goto store_cleanup;
  }
  idx_keylen = build_key(idxkeybuf, sizeof(idxkeybuf), target, timestamp, NULL);
  if (idx_keylen < 0) {
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
    log_write(LS_SYSTEM, L_INFO, 0,
              "history_store_message: storing key='%s' (len=%d) target='%s' ts='%s' msgid='%s'",
              key_preview, keylen, target, timestamp, msgid);
  }

  vallen = serialize_message(valbuf, bufsize, type, sender, account, content,
                             client_tags);
  if (vallen < 0) {
    rc = -1;
    goto store_cleanup;
  }
  if ((size_t)vallen >= bufsize)
    vallen = bufsize - 1;

#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    compressed, comp_bufsize, &compressed_len) >= 0) {
    vbuf = compressed;
    vlen = compressed_len;
  } else {
    vbuf = valbuf;
    vlen = (size_t)vallen;
  }
#else
  vbuf = valbuf;
  vlen = (size_t)vallen;
#endif

store_retry:
  wb = db_writebatch_new(history_db_env);
  if (!wb) {
    rc = -1;
    goto store_cleanup;
  }

  /* Main message store — APPEND-optimised since msgids are
   * monotonic per channel.  libmdbx's MDBX_APPEND skips B-tree
   * walk on max-key inserts; RocksDB's memtable already handles
   * ordered inserts efficiently and treats put_append as a normal put. */
  rc = db_writebatch_put_append(wb, history_cf_messages,
                                keybuf, (size_t)keylen, vbuf, vlen);
  if (rc != DB_OK) {
    Debug((DEBUG_DEBUG, "history: writebatch_put failed: %s", db_strerror(rc)));
    db_writebatch_destroy(wb);
    wb = NULL;
    if (rc == DB_ERR_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }

  /* msgid → target\0timestamp index */
  rc = db_writebatch_put(wb, history_cf_msgid,
                         msgid, strlen(msgid),
                         idxkeybuf, (size_t)idx_keylen);
  if (rc != DB_OK) goto store_wb_fail;

  /* target → last-timestamp */
  rc = db_writebatch_put(wb, history_cf_targets,
                         target, strlen(target),
                         timestamp, strlen(timestamp));
  if (rc != DB_OK) goto store_wb_fail;

  /* Index reply references for draft/chathistory-context lookups.
   * libmdbx-specific: reply_index uses MDBX_DUPSORT and the conversion
   * to a flat-key encoding for portability is Phase 5 work.  For now
   * we reach into the writebatch's underlying mdbx_txn to keep the
   * existing reply_index_put working. */
#ifdef USE_MDBX
  {
    MDBX_txn *raw_txn = db_mdbx_unwrap_writebatch_txn(wb);
    char parent_mid[HISTORY_MSGID_LEN];
    const char *parent = extract_reply_tag(client_tags, parent_mid, sizeof(parent_mid));
    if (parent && raw_txn)
      reply_index_put(raw_txn, target, parent, timestamp, msgid);
    if (type == HISTORY_REDACT && content && content[0]) {
      const char *space = strchr(content, ' ');
      size_t len = space ? (size_t)(space - content) : strlen(content);
      if (len > 0 && len < sizeof(parent_mid) && raw_txn) {
        memcpy(parent_mid, content, len);
        parent_mid[len] = '\0';
        reply_index_put(raw_txn, target, parent_mid, timestamp, msgid);
      }
    }
  }
#endif

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  if (rc != DB_OK) {
    Debug((DEBUG_DEBUG, "history: writebatch_commit failed: %s", db_strerror(rc)));
    db_writebatch_destroy(wb);
    wb = NULL;
    if (rc == DB_ERR_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_retry;
    }
    rc = -1;
    goto store_cleanup;
  }
  db_writebatch_destroy(wb);
  wb = NULL;

  /* Quota counter (separate small write outside the main batch) */
  if (feature_bool(FEAT_CHATHISTORY_USER_QUOTA) && account && account[0]) {
    int new_count = quota_increment(target, account);
    if (new_count > 0) {
      int quota_pct = feature_int(FEAT_CHATHISTORY_USER_QUOTA_PCT);
      int channel_limit = feature_int(FEAT_CHATHISTORY_MAX);
      int max_allowed = (channel_limit * quota_pct) / 100;
      if (quota_pct > 0 && quota_pct < 100 && new_count == max_allowed + 1) {
        log_write(LS_SYSTEM, L_WARNING, 0,
                  "history: user %s exceeded quota in %s (%d/%d messages, %d%%)",
                  account, target, new_count, channel_limit, quota_pct);
      }
    }
  }

  rc = 0;
  goto store_cleanup;

store_wb_fail:
  Debug((DEBUG_DEBUG, "history: writebatch op failed: %s", db_strerror(rc)));
  db_writebatch_destroy(wb);
  wb = NULL;
  if (rc == DB_ERR_FULL && retry == 0) {
    retry = 1;
    if (history_emergency_evict() > 0)
      goto store_retry;
  }
  rc = -1;

store_cleanup:
  if (wb) db_writebatch_destroy(wb);
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
  struct db_writebatch *wb = NULL;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char idxkeybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  int keylen, idx_keylen, vallen;
  int rc;
  int retry = 0;
  const void *vbuf;
  size_t       vlen;

  char valbuf[HISTORY_VALUE_BUFSIZE];
#ifdef USE_ZSTD
  unsigned char comp_buf[HISTORY_VALUE_BUFSIZE + 64];
  size_t compressed_len;
#endif

  if (!history_available)
    return -1;

  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) return -1;
  idx_keylen = build_key(idxkeybuf, sizeof(idxkeybuf), target, timestamp, NULL);
  if (idx_keylen < 0) return -1;

  vallen = serialize_message(valbuf, sizeof(valbuf), HISTORY_PRIVMSG,
                             sender, account, ML_CONTENT_SENTINEL, NULL);
  if (vallen < 0) return -1;
  if ((size_t)vallen >= sizeof(valbuf)) vallen = sizeof(valbuf) - 1;

#ifdef USE_ZSTD
  if (compress_data((unsigned char *)valbuf, vallen,
                    comp_buf, sizeof(comp_buf), &compressed_len) >= 0) {
    vbuf = comp_buf;
    vlen = compressed_len;
  } else {
    vbuf = valbuf;
    vlen = (size_t)vallen;
  }
#else
  vbuf = valbuf;
  vlen = (size_t)vallen;
#endif

store_ml_retry:
  wb = db_writebatch_new(history_db_env);
  if (!wb) return -1;

  /* Stage the multiline content put on the same writebatch so it
   * lands atomically with the history.messages / msgid_index / targets
   * puts below. */
  if (ml_content_store(wb, msgid, sender, target,
                       content, content_len, paste_secret) != 0) {
    db_writebatch_destroy(wb);
    wb = NULL;
    return -1;
  }

  rc = db_writebatch_put_append(wb, history_cf_messages,
                                keybuf, (size_t)keylen, vbuf, vlen);
  if (rc != DB_OK) goto store_ml_fail;

  rc = db_writebatch_put(wb, history_cf_msgid,
                         msgid, strlen(msgid),
                         idxkeybuf, (size_t)idx_keylen);
  if (rc != DB_OK) goto store_ml_fail;

  rc = db_writebatch_put(wb, history_cf_targets,
                         target, strlen(target),
                         timestamp, strlen(timestamp));
  if (rc != DB_OK) goto store_ml_fail;

  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  wb = NULL;
  if (rc != DB_OK) {
    if (rc == DB_ERR_FULL && retry == 0) {
      retry = 1;
      if (history_emergency_evict() > 0)
        goto store_ml_retry;
    }
    return -1;
  }

  /* Update quota */
  if (feature_bool(FEAT_CHATHISTORY_USER_QUOTA) && account && account[0])
    quota_increment(target, account);
  return 0;

store_ml_fail:
  db_writebatch_destroy(wb);
  wb = NULL;
  if (rc == DB_ERR_FULL && retry == 0) {
    retry = 1;
    if (history_emergency_evict() > 0)
      goto store_ml_retry;
  }
  return -1;
}

int history_has_msgid(const char *msgid)
{
  int rc;

  if (!history_available)
    return -1;

  if (!msgid || !msgid[0])
    return 0;

  rc = db_exists(history_db_env, history_cf_msgid,
                 msgid, strlen(msgid), /*snap=*/NULL);
  if (rc == DB_OK)        return 1;
  if (rc == DB_NOTFOUND)  return 0;
  return -1;
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
  struct db_snapshot *snap = NULL;
  struct db_iter *it = NULL;
  struct HistoryMessage *head = NULL, *tail = NULL, *msg;
  char target_prefix[CHANNELLEN + 2];
  int target_prefix_len;
  int count = 0;
  int rc;
  int reverse;

  *result = NULL;

  if (!history_available)
    return -1;

  /* Build target prefix for boundary checking */
  target_prefix_len = ircd_snprintf(0, target_prefix, sizeof(target_prefix),
                                    "%s%c", target, KEY_SEP);

  /* Open a read snapshot.  history_query_internal returns a coherent
   * point-in-time view, so we pin a snapshot for the iter and (under
   * libmdbx) reuse its read txn for ml_content_resolve so multiline
   * content sees the same state as the message rows. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;

  it = db_iter_open(history_db_env, history_cf_messages, snap);
  if (!it) {
    db_snapshot_destroy(snap);
    return -1;
  }

  reverse = (direction == HISTORY_DIR_BEFORE || direction == HISTORY_DIR_LATEST);

  /* Position iterator */
  if (reverse) {
    /* For BEFORE/LATEST, we want to go backwards from the reference. */
    rc = db_iter_seek(it, start_key, start_keylen);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: seek rc=%d (%s)",
              rc, rc == DB_OK ? "found" : (rc == DB_NOTFOUND ? "not found" : "error"));
    if (rc == DB_NOTFOUND) {
      /* Past end of CF — fall back to the last key. */
      rc = db_iter_seek_last(it);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: seek_last rc=%d", rc);
    } else if (rc == DB_OK) {
      /* Move back one since seek lands on >= start_key */
      rc = db_iter_prev(it);
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: prev rc=%d", rc);
    }
  } else {
    /* For AFTER, go forwards from strictly after the reference. */
    rc = db_iter_seek(it, start_key, start_keylen);
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: AFTER seek rc=%d", rc);
    /* Skip any messages that match the reference key prefix
     * (AFTER means strictly after, not including the reference). */
    while (rc == DB_OK && db_iter_valid(it)) {
      size_t klen;
      const void *kbase = db_iter_key(it, &klen);
      if (klen < (size_t)start_keylen ||
          memcmp(kbase, start_key, start_keylen) != 0)
        break;
      rc = db_iter_next(it);
    }
  }

  /* Log iterator position */
  if (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);
    char key_preview[64];
    size_t preview_len = klen < 60 ? klen : 60;
    memcpy(key_preview, kbase, preview_len);
    key_preview[preview_len] = '\0';
    for (size_t i = 0; i < preview_len; i++) {
      if (key_preview[i] == '\0') key_preview[i] = '.';
    }
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: positioned at key='%s' (len=%zu)",
              key_preview, klen);
  } else {
    log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: no position, rc=%d", rc);
  }

  /* Iterate and collect messages */
  while (rc == DB_OK && db_iter_valid(it) && count < limit) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Check if still in target's range */
    if (klen < (size_t)target_prefix_len ||
        memcmp(kbase, target_prefix, target_prefix_len) != 0) {
      char key_preview[64];
      size_t preview_len = klen < 60 ? klen : 60;
      memcpy(key_preview, kbase, preview_len);
      key_preview[preview_len] = '\0';
      for (size_t i = 0; i < preview_len; i++) {
        if (key_preview[i] == '\0') key_preview[i] = '.';
      }
      log_write(LS_SYSTEM, L_INFO, 0, "history_query_internal: key='%s' outside target range, breaking",
                key_preview);
      /* Keys are sorted, so once outside target prefix we are done. */
      break;
    }

    /* Floor check for backward iteration: stop if we've walked past
     * the floor timestamp (used by auto-replay to get the most recent
     * N messages but no older than the since-timestamp). */
    if (reverse && floor_key && floor_keylen > 0) {
      if (klen >= (size_t)floor_keylen &&
          memcmp(kbase, floor_key, floor_keylen) <= 0)
        break;
    }

    /* Allocate message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    /* Parse key to get target, timestamp, msgid */
    if (parse_key((void *)kbase, klen,
                  msg->target, msg->timestamp, msg->msgid) != 0) {
      MyFree(msg);
      rc = reverse ? db_iter_prev(it) : db_iter_next(it);
      continue;
    }

#ifdef USE_ZSTD
    /* Preserve raw compressed data for federation passthrough */
    if (is_compressed((const unsigned char *)vbase, vlen)) {
      msg->raw_content = (unsigned char *)MyMalloc(vlen);
      if (msg->raw_content) {
        memcpy(msg->raw_content, vbase, vlen);
        msg->raw_content_len = vlen;
      }
    }
#endif

    /* Parse value */
    if (deserialize_message((void *)vbase, vlen, msg) != 0) {
      if (msg->raw_content)
        MyFree(msg->raw_content);
      MyFree(msg);
      rc = reverse ? db_iter_prev(it) : db_iter_next(it);
      continue;
    }

    /* Resolve multiline content from ml_content store if needed.
     * Reads through the same snapshot as this iterator for a coherent
     * point-in-time view. */
    ml_content_resolve(snap, msg);

    /* Add to list */
    msg->next = NULL;
    if (reverse) {
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

    rc = reverse ? db_iter_prev(it) : db_iter_next(it);
  }

  db_iter_close(it);
  db_snapshot_destroy(snap);

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
  struct db_iter *it;
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

  it = db_iter_open(history_db_env, history_cf_messages, NULL);
  if (!it)
    return 0;

  /* Position at or after the far-future key, then step back. */
  rc = db_iter_seek(it, keybuf, keylen);
  if (rc == DB_NOTFOUND)
    rc = db_iter_seek_last(it);
  else if (rc == DB_OK)
    rc = db_iter_prev(it);

  /* Walk backward through channel history looking for this user's last JOIN.
   * JOIN events are channel metadata, so they're relatively frequent —
   * typically found within a few hundred entries at most. Cap the scan
   * to avoid pathological cases. */
  {
    int scanned = 0;
    int max_scan = 2000;

    while (rc == DB_OK && db_iter_valid(it) && scanned < max_scan) {
      size_t klen, vlen;
      const void *kbase = db_iter_key(it, &klen);
      const void *vbase = db_iter_value(it, &vlen);
      const char *val;
      const char *pipe1, *pipe2;
      int type;

      /* Check if still in channel's range */
      if (klen < (size_t)target_prefix_len ||
          memcmp(kbase, target_prefix, target_prefix_len) != 0)
        break;

      scanned++;
      val = (const char *)vbase;

      /* Quick reject: compressed data won't start with a digit.
       * JOIN events are short and shouldn't be compressed, but skip
       * compressed entries rather than decompressing them all. */
      if (is_compressed((const unsigned char *)val, vlen)) {
        rc = db_iter_prev(it);
        continue;
      }

      /* Value format: type|sender|account|content
       * HISTORY_JOIN = 2, so we need "2|nick!..." */
      pipe1 = memchr(val, '|', vlen);
      if (!pipe1) {
        rc = db_iter_prev(it);
        continue;
      }

      type = atoi(val);
      if (type != HISTORY_JOIN) {
        rc = db_iter_prev(it);
        continue;
      }

      /* Check sender: starts with "nick!" */
      pipe2 = memchr(pipe1 + 1, '|', vlen - (pipe1 + 1 - val));
      if (!pipe2) {
        rc = db_iter_prev(it);
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
          if (parse_key((void *)kbase, klen,
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

      rc = db_iter_prev(it);
    }
  }

  db_iter_close(it);
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
  struct db_snapshot *snap = NULL;
  struct db_iter *it = NULL;
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

  /* Open a snapshot so the iter and ml_content_resolve see a coherent view. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;

  it = db_iter_open(history_db_env, history_cf_messages, snap);
  if (!it) {
    db_snapshot_destroy(snap);
    return -1;
  }

  rc = db_iter_seek(it, keybuf, keylen);

  while (rc == DB_OK && db_iter_valid(it) && count < limit) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Check if past end */
    if (klen >= (size_t)end_prefix_len &&
        memcmp(kbase, end_prefix, end_prefix_len) >= 0)
      break;

    /* Parse and add message */
    msg = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
    if (!msg)
      break;
    memset(msg, 0, sizeof(*msg));

    if (parse_key((void *)kbase, klen,
                  msg->target, msg->timestamp, msg->msgid) != 0 ||
        deserialize_message((void *)vbase, vlen, msg) != 0) {
      MyFree(msg);
      rc = db_iter_next(it);
      continue;
    }

    /* Resolve multiline content via the snapshot for coherent reads. */
    ml_content_resolve(snap, msg);

    msg->next = NULL;
    if (tail)
      tail->next = msg;
    else
      head = msg;
    tail = msg;
    count++;

    rc = db_iter_next(it);
  }

  db_iter_close(it);
  db_snapshot_destroy(snap);

  *result = head;
  return count;
}

int history_query_targets(const char *timestamp1, const char *timestamp2,
                          int limit, struct HistoryTarget **result)
{
  struct db_iter *it;
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

  it = db_iter_open(history_db_env, history_cf_targets, NULL);
  if (!it)
    return -1;

  /* Iterate all targets */
  rc = db_iter_seek_first(it);
  while (rc == DB_OK && db_iter_valid(it) && count < limit) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Check if target's last message is in range */
    char last_ts[HISTORY_TIMESTAMP_LEN];
    if (vlen >= sizeof(last_ts)) {
      rc = db_iter_next(it);
      continue;
    }
    memcpy(last_ts, vbase, vlen);
    last_ts[vlen] = '\0';

    if (strcmp(last_ts, ts1) >= 0 && strcmp(last_ts, ts2) <= 0) {
      tgt = (struct HistoryTarget *)MyMalloc(sizeof(struct HistoryTarget));
      if (!tgt)
        break;
      memset(tgt, 0, sizeof(*tgt));

      if (klen > CHANNELLEN) {
        MyFree(tgt);
        rc = db_iter_next(it);
        continue;
      }
      memcpy(tgt->target, kbase, klen);
      tgt->target[klen] = '\0';
      ircd_strncpy(tgt->last_timestamp, last_ts, sizeof(tgt->last_timestamp) - 1);
      tgt->next = NULL;

      if (tail)
        tail->next = tgt;
      else
        head = tgt;
      tail = tgt;
      count++;
    }

    rc = db_iter_next(it);
  }

  db_iter_close(it);

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
  struct db_iter *it;
  char target[CHANNELLEN + 1];
  int count = 0;
  int rc;

  if (!history_available || !callback)
    return -1;

  it = db_iter_open(history_db_env, history_cf_targets, NULL);
  if (!it)
    return -1;

  /* Iterate all targets */
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);

    if (klen > 0 && klen <= CHANNELLEN) {
      memcpy(target, kbase, klen);
      target[klen] = '\0';

      /* Only call back for channels (start with # or &) */
      if (target[0] == '#' || target[0] == '&') {
        count++;
        if (callback(target, data) != 0)
          break;  /* Callback requested stop */
      }
    }
  }

  db_iter_close(it);

  return count;
}

int history_has_channel(const char *target)
{
  int rc;

  if (!history_available || !target)
    return -1;

  rc = db_exists(history_db_env, history_cf_targets,
                 target, strlen(target), /*snap=*/NULL);
  if (rc == DB_OK)        return 1;
  if (rc == DB_NOTFOUND)  return 0;
  return -1;
}

int history_channel_has_messages(const char *target)
{
  struct db_iter *it;
  char prefix[CHANNELLEN + 2];
  int prefix_len;
  int rc;
  int result = 0;

  if (!history_available || !target)
    return -1;

  /* Build prefix key: "target\0" */
  prefix_len = strlen(target);
  if (prefix_len > CHANNELLEN)
    return -1;
  memcpy(prefix, target, prefix_len);
  prefix[prefix_len] = KEY_SEP;
  prefix_len++;

  it = db_iter_open(history_db_env, history_cf_messages, NULL);
  if (!it)
    return -1;

  rc = db_iter_seek(it, prefix, prefix_len);
  if (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);
    if (klen >= (size_t)prefix_len &&
        memcmp(kbase, prefix, prefix_len) == 0)
      result = 1;
  }

  db_iter_close(it);
  return result;
}

void history_set_channel_removed_callback(history_channels_removed_cb cb)
{
  channel_removed_callback = cb;
}

int history_purge_old(unsigned long max_age_seconds)
{
  struct db_iter *it;
  struct db_writebatch *wb;
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

  wb = db_writebatch_new(history_db_env);
  if (!wb) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge writebatch_new failed");
    return -1;
  }

  it = db_iter_open(history_db_env, history_cf_messages, NULL);
  if (!it) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge iter_open failed");
    db_writebatch_destroy(wb);
    return -1;
  }

  /* Iterate from the beginning (oldest messages first due to key structure)
   * and stage deletes in the writebatch.  Once we cross the cutoff timestamp
   * within a target's range we'd still need to keep scanning other targets,
   * so a full scan is unavoidable here. */
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);

    if (parse_key((void *)kbase, klen,
                  msg_target, msg_timestamp, msg_msgid) != 0)
      continue;

    if (strcmp(msg_timestamp, cutoff_ts) >= 0)
      continue;  /* not old enough */

    /* Stage delete from msgid index and ml_content if we have a msgid */
    if (msg_msgid[0] != '\0') {
      db_writebatch_del(wb, history_cf_msgid,
                        msg_msgid, strlen(msg_msgid));

      ml_content_delete(wb, msg_msgid);

      /* Delete reply index entries where this msgid is the parent.
       * Orphaned child entries (referencing deleted parents) are harmless
       * and cleaned when the child itself is purged. */
      {
        char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
        int ri_kpos = 0;
        size_t tlen = strlen(msg_target), mlen = strlen(msg_msgid);
        if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
          memcpy(ri_keybuf, msg_target, tlen);
          ri_kpos += tlen;
          ri_keybuf[ri_kpos++] = KEY_SEP;
          memcpy(ri_keybuf + ri_kpos, msg_msgid, mlen);
          ri_kpos += mlen;
          db_writebatch_del(wb, history_cf_reply,
                            ri_keybuf, ri_kpos);
        }
      }
    }

    /* Stage delete of the message itself.  Borrow the key — writebatch
     * copies, so it's safe to use the iterator's transient pointer. */
    db_writebatch_del(wb, history_cf_messages, kbase, klen);
    deleted++;
  }

  db_iter_close(it);

  /* Commit deletes */
  rc = db_writebatch_commit(wb, /*sync=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0, "history: purge commit failed: %s",
              db_strerror(rc));
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
  struct db_iter *it;
  char target[CHANNELLEN + 1];
  char *channels_to_remove[256];  /* Buffer for channel names to remove */
  int remove_count = 0;
  int removed = 0;
  int rc, i;

  if (!history_available)
    return -1;

  /* First pass: collect channel names from targets CF.  We avoid the
   * dance of "abort txn, check messages, reopen at next key" that the
   * old libmdbx version did: under the abstraction the iter is on its
   * own implicit snapshot, and history_channel_has_messages opens its
   * own iter — they don't conflict, so we can keep this iter open
   * across the inner check.  We still want to copy the target name out
   * before stepping (the iter borrow is invalidated by db_iter_next). */
  it = db_iter_open(history_db_env, history_cf_targets, NULL);
  if (!it)
    return -1;

  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it) && remove_count < 256;
       rc = db_iter_next(it)) {
    size_t klen;
    const void *kbase = db_iter_key(it, &klen);

    if (klen == 0 || klen > CHANNELLEN)
      continue;
    memcpy(target, kbase, klen);
    target[klen] = '\0';

    /* Only process channels (start with # or &) */
    if (target[0] != '#' && target[0] != '&')
      continue;

    if (history_channel_has_messages(target) == 0) {
      channels_to_remove[remove_count] = MyMalloc(strlen(target) + 1);
      if (channels_to_remove[remove_count]) {
        strcpy(channels_to_remove[remove_count], target);
        remove_count++;
      }
    }
  }

  db_iter_close(it);

  /* Second pass: remove collected targets atomically and call callback */
  if (remove_count > 0) {
    struct db_writebatch *wb = db_writebatch_new(history_db_env);
    if (wb) {
      for (i = 0; i < remove_count; i++) {
        if (db_writebatch_del(wb, history_cf_targets,
                              channels_to_remove[i],
                              strlen(channels_to_remove[i])) == DB_OK) {
          removed++;
          Debug((DEBUG_DEBUG, "history: removed empty target %s", channels_to_remove[i]));
        }
      }
      db_writebatch_commit(wb, /*sync=*/0);
      db_writebatch_destroy(wb);
    }

    /* Call callback with all removed channels at once (after DB commit) */
    if (channel_removed_callback && remove_count > 0)
      channel_removed_callback((const char **)channels_to_remove, remove_count);
  }

  /* Free allocated channel names */
  for (i = 0; i < remove_count; i++)
    MyFree(channels_to_remove[i]);

  if (removed > 0)
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: cleaned up %d empty channel targets", removed);

  return removed;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  struct db_val val = { NULL, 0 };
  const char *sep;
  int rc;

  log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: looking up msgid=%s", msgid);

  if (!history_available) {
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: history not available");
    return -1;
  }

  rc = db_get(history_db_env, history_cf_msgid,
              msgid, strlen(msgid), /*snap=*/NULL, &val);
  if (rc != DB_OK) {
    if (rc != DB_NOTFOUND)
      log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: db_get failed for msgid=%s: %s",
                msgid, db_strerror(rc));
    return -1;
  }

  /* Value is target\0timestamp\0 - extract timestamp (exclude trailing separator) */
  sep = memchr(val.base, KEY_SEP, val.len);
  if (!sep) {
    db_val_free(&val);
    return -1;
  }
  sep++; /* Skip separator after target */

  /* Calculate copy length - exclude trailing KEY_SEP if present */
  {
    size_t copy_len = (char *)val.base + val.len - sep;
    /* build_key adds trailing KEY_SEP, exclude it */
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN) {
      db_val_free(&val);
      return -1;
    }
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
    log_write(LS_SYSTEM, L_INFO, 0, "history_msgid_to_timestamp: extracted timestamp='%s' (len=%zu)", timestamp, copy_len);
  }

  db_val_free(&val);
  return 0;
}

int history_lookup_message(const char *target, const char *msgid,
                            struct HistoryMessage **msg)
{
  struct db_snapshot *snap;
  struct db_val val = { NULL, 0 };
  struct HistoryMessage *m;
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  *msg = NULL;

  if (!history_available)
    return -1;

  /* Pin a snapshot so the msgid_index lookup, the message lookup, and
   * ml_content_resolve all see the same point-in-time view. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return -1;

  /* First, look up the msgid to get target and timestamp */
  rc = db_get(history_db_env, history_cf_msgid,
              msgid, strlen(msgid), snap, &val);
  if (rc == DB_NOTFOUND) {
    db_snapshot_destroy(snap);
    return 1; /* Not found */
  }
  if (rc != DB_OK) {
    db_snapshot_destroy(snap);
    return -1;
  }

  /* Value is target\0timestamp\0 - extract timestamp (exclude trailing KEY_SEP) */
  {
    const char *sep;
    size_t copy_len;
    sep = memchr(val.base, KEY_SEP, val.len);
    if (!sep) {
      db_val_free(&val);
      db_snapshot_destroy(snap);
      return -1;
    }
    sep++; /* Skip separator after target */
    copy_len = (char *)val.base + val.len - sep;
    /* build_key adds trailing KEY_SEP, exclude it */
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN) {
      db_val_free(&val);
      db_snapshot_destroy(snap);
      return -1;
    }
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
  }
  db_val_free(&val);

  /* Build key for main database lookup: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0) {
    db_snapshot_destroy(snap);
    return -1;
  }

  rc = db_get(history_db_env, history_cf_messages,
              keybuf, keylen, snap, &val);
  if (rc == DB_NOTFOUND) {
    db_snapshot_destroy(snap);
    return 1; /* Not found */
  }
  if (rc != DB_OK) {
    db_snapshot_destroy(snap);
    return -1;
  }

  /* Allocate and populate message structure */
  m = (struct HistoryMessage *)MyMalloc(sizeof(struct HistoryMessage));
  if (!m) {
    db_val_free(&val);
    db_snapshot_destroy(snap);
    return -1;
  }
  memset(m, 0, sizeof(*m));

  /* Parse the message */
  if (deserialize_message(val.base, val.len, m) != 0) {
    MyFree(m);
    db_val_free(&val);
    db_snapshot_destroy(snap);
    return -1;
  }
  db_val_free(&val);

  /* Fill in the key fields */
  ircd_strncpy(m->msgid, msgid, sizeof(m->msgid) - 1);
  ircd_strncpy(m->target, target, sizeof(m->target) - 1);
  ircd_strncpy(m->timestamp, timestamp, sizeof(m->timestamp) - 1);
  m->next = NULL;

  /* Resolve multiline content via the same snapshot. */
  ml_content_resolve(snap, m);

  db_snapshot_destroy(snap);
  *msg = m;
  return 0;
}

int history_delete_message(const char *target, const char *msgid)
{
  struct db_writebatch *wb;
  struct db_val val = { NULL, 0 };
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  /* First, look up the msgid to get the timestamp */
  rc = db_get(history_db_env, history_cf_msgid,
              msgid, strlen(msgid), /*snap=*/NULL, &val);
  if (rc == DB_NOTFOUND)
    return 1; /* Not found */
  if (rc != DB_OK)
    return -1;

  /* Extract timestamp from value (target\0timestamp[\0]) */
  {
    const char *sep;
    size_t copy_len;
    sep = memchr(val.base, KEY_SEP, val.len);
    if (!sep) {
      db_val_free(&val);
      return -1;
    }
    sep++; /* Skip separator */
    copy_len = (char *)val.base + val.len - sep;
    /* build_key adds trailing KEY_SEP, exclude it if present. */
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN) {
      db_val_free(&val);
      return -1;
    }
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
  }
  db_val_free(&val);

  /* Build key for main database: target\0timestamp\0msgid */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0)
    return -1;

  wb = db_writebatch_new(history_db_env);
  if (!wb)
    return -1;

  /* Stage all deletes atomically. */
  db_writebatch_del(wb, history_cf_msgid, msgid, strlen(msgid));
  db_writebatch_del(wb, history_cf_messages, keybuf, keylen);

  ml_content_delete(wb, msgid);

  /* Clean reply index entries where this msgid is the parent */
  {
    char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
    int ri_kpos = 0;
    size_t tlen = strlen(target), mlen = strlen(msgid);
    if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
      memcpy(ri_keybuf, target, tlen);
      ri_kpos += tlen;
      ri_keybuf[ri_kpos++] = KEY_SEP;
      memcpy(ri_keybuf + ri_kpos, msgid, mlen);
      ri_kpos += mlen;
      db_writebatch_del(wb, history_cf_reply, ri_keybuf, ri_kpos);
    }
  }

  rc = db_writebatch_commit(wb, /*sync=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK)
    return -1;

  return 0;
}

int history_is_available(void)
{
  return history_available;
}

int history_attach_context(const char *target, struct HistoryMessage *messages)
{
  struct db_snapshot *snap;
  struct db_iter *ri_it;
  struct HistoryMessage *msg;
  int added = 0;
  int rc;

  if (!history_available || !messages)
    return 0;

  /* Pin a snapshot so the reply-index walk and main-DBI gets see the
   * same point-in-time view. */
  snap = db_snapshot_new(history_db_env);
  if (!snap)
    return 0;

  ri_it = db_iter_open(history_db_env, history_cf_reply, snap);
  if (!ri_it) {
    db_snapshot_destroy(snap);
    return 0;
  }

  for (msg = messages; msg; msg = msg->next) {
    char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
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

    /* Find all children for this parent.  Under libmdbx, reply_index is
     * MDBX_DUPSORT — so seek + step iterates through dups before moving
     * to the next key.  We stop once the current iter key no longer
     * matches our ri_keybuf exactly. */
    rc = db_iter_seek(ri_it, ri_keybuf, ri_kpos);
    while (rc == DB_OK && db_iter_valid(ri_it)) {
      size_t klen, vlen;
      const void *kbase = db_iter_key(ri_it, &klen);
      const void *vbase = db_iter_value(ri_it, &vlen);
      const char *sep;

      if (klen != (size_t)ri_kpos || memcmp(kbase, ri_keybuf, ri_kpos) != 0)
        break;

      /* Value is timestamp\0child_msgid */
      sep = memchr(vbase, KEY_SEP, vlen);
      if (sep) {
        char child_ts[HISTORY_TIMESTAMP_LEN];
        char child_mid[HISTORY_MSGID_LEN];
        size_t ts_len = sep - (const char *)vbase;
        size_t mid_len = (const char *)vbase + vlen - (sep + 1);

        if (ts_len < sizeof(child_ts) && mid_len < sizeof(child_mid) && mid_len > 0) {
          char main_keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
          int main_keylen;
          struct HistoryMessage *ctx;
          int dup_found = 0;
          struct HistoryMessage *dup;
          struct db_val main_val = { NULL, 0 };
          int grc;

          memcpy(child_ts, vbase, ts_len);
          child_ts[ts_len] = '\0';
          memcpy(child_mid, sep + 1, mid_len);
          child_mid[mid_len] = '\0';

          /* Check if this child msgid is already in the primary list (avoid dup) */
          for (dup = messages; dup; dup = dup->next) {
            if (strcmp(dup->msgid, child_mid) == 0) {
              dup_found = 1;
              break;
            }
          }
          if (dup_found)
            goto next_dup;

          /* Fetch the full message from main CF */
          main_keylen = build_key(main_keybuf, sizeof(main_keybuf), target, child_ts, child_mid);
          if (main_keylen < 0)
            goto next_dup;

          grc = db_get(history_db_env, history_cf_messages,
                       main_keybuf, main_keylen, snap, &main_val);
          if (grc != DB_OK)
            goto next_dup;

          ctx = (struct HistoryMessage *)MyCalloc(1, sizeof(struct HistoryMessage));
          if (deserialize_message(main_val.base, main_val.len, ctx) != 0) {
            MyFree(ctx);
            db_val_free(&main_val);
            goto next_dup;
          }
          db_val_free(&main_val);

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
      rc = db_iter_next(ri_it);
    }
  }

  db_iter_close(ri_it);
  db_snapshot_destroy(snap);
  return added;
}

int history_redact_message(const char *target, const char *msgid)
{
  struct db_writebatch *wb;
  struct db_val val = { NULL, 0 };
  char keybuf[CHANNELLEN + HISTORY_TIMESTAMP_LEN + HISTORY_MSGID_LEN + 8];
  char timestamp[HISTORY_TIMESTAMP_LEN];
  int keylen;
  int rc;

  if (!history_available)
    return -1;

  /* Look up msgid to get timestamp */
  rc = db_get(history_db_env, history_cf_msgid,
              msgid, strlen(msgid), /*snap=*/NULL, &val);
  if (rc == DB_NOTFOUND)
    return 1;
  if (rc != DB_OK)
    return -1;

  /* Extract timestamp from value (target\0timestamp[\0]) */
  {
    const char *sep = memchr(val.base, KEY_SEP, val.len);
    size_t copy_len;
    if (!sep) {
      db_val_free(&val);
      return -1;
    }
    sep++;
    copy_len = (char *)val.base + val.len - sep;
    if (copy_len > 0 && sep[copy_len - 1] == KEY_SEP)
      copy_len--;
    if (copy_len >= HISTORY_TIMESTAMP_LEN) {
      db_val_free(&val);
      return -1;
    }
    memcpy(timestamp, sep, copy_len);
    timestamp[copy_len] = '\0';
  }
  db_val_free(&val);

  /* Build full key for main database */
  keylen = build_key(keybuf, sizeof(keybuf), target, timestamp, msgid);
  if (keylen < 0)
    return -1;

  /* Fetch the current message to get sender and account */
  rc = db_get(history_db_env, history_cf_messages,
              keybuf, keylen, /*snap=*/NULL, &val);
  if (rc == DB_NOTFOUND)
    return 1;
  if (rc != DB_OK)
    return -1;

  /* Deserialize to get type, sender, account; re-serialize with empty
   * content and no client_tags; stage as a put. */
  wb = db_writebatch_new(history_db_env);
  if (!wb) {
    db_val_free(&val);
    return -1;
  }

  {
    struct HistoryMessage orig;
    char valbuf[HISTORY_VALUE_BUFSIZE];
    int vallen;

    memset(&orig, 0, sizeof(orig));
    if (deserialize_message(val.base, val.len, &orig) != 0) {
      db_val_free(&val);
      db_writebatch_destroy(wb);
      return -1;
    }
    db_val_free(&val);

    vallen = serialize_message(valbuf, sizeof(valbuf), orig.type,
                               orig.sender, orig.account, "", NULL);
    if (vallen < 0 || (size_t)vallen >= sizeof(valbuf)) {
      db_writebatch_destroy(wb);
      return -1;
    }

#ifdef USE_ZSTD
    {
      unsigned char comp_buf[HISTORY_VALUE_BUFSIZE + 64];
      size_t comp_len;
      if (compress_data((unsigned char *)valbuf, vallen,
                        comp_buf, sizeof(comp_buf), &comp_len) >= 0) {
        db_writebatch_put(wb, history_cf_messages,
                          keybuf, keylen, comp_buf, comp_len);
      } else {
        db_writebatch_put(wb, history_cf_messages,
                          keybuf, keylen, valbuf, vallen);
      }
    }
#else
    db_writebatch_put(wb, history_cf_messages,
                      keybuf, keylen, valbuf, vallen);
#endif
  }

  /* Delete multiline content if any. */
  ml_content_delete(wb, msgid);

  rc = db_writebatch_commit(wb, /*sync=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
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
  struct db_iter *it;
  struct db_writebatch *wb;
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
            "history: emergency eviction triggered (MAP_FULL)");

  wb = db_writebatch_new(history_db_env);
  if (!wb) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction writebatch_new failed");
    return -1;
  }

  it = db_iter_open(history_db_env, history_cf_messages, NULL);
  if (!it) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction iter_open failed");
    db_writebatch_destroy(wb);
    return -1;
  }

  /* Evict oldest entries — collect-then-batch-delete pattern. */
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it) && evicted < EMERGENCY_EVICT_BATCH;
       rc = db_iter_next(it)) {
    size_t klen, vlen;
    const void *kbase = db_iter_key(it, &klen);
    const void *vbase = db_iter_value(it, &vlen);

    /* Parse key to get target and msgid for index cleanup */
    if (parse_key((void *)kbase, klen,
                  msg_target, msg_timestamp, msg_msgid) == 0) {
      if (msg_msgid[0] != '\0') {
        db_writebatch_del(wb, history_cf_msgid,
                          msg_msgid, strlen(msg_msgid));

        ml_content_delete(wb, msg_msgid);

        /* Clean reply index entries where this msgid is the parent */
        {
          char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
          int ri_kpos = 0;
          size_t tlen = strlen(msg_target), mlen = strlen(msg_msgid);
          if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
            memcpy(ri_keybuf, msg_target, tlen);
            ri_kpos += tlen;
            ri_keybuf[ri_kpos++] = KEY_SEP;
            memcpy(ri_keybuf + ri_kpos, msg_msgid, mlen);
            ri_kpos += mlen;
            db_writebatch_del(wb, history_cf_reply, ri_keybuf, ri_kpos);
          }
        }
      }
    }

    /* Collect account info for quota decrement after commit */
    if (quota_enabled && msg_target[0] != '\0' &&
        quota_update_count < EMERGENCY_EVICT_BATCH) {
      if (deserialize_message((void *)vbase, vlen, &msg) == 0 &&
          msg.account[0] != '\0') {
        ircd_strncpy(quota_updates[quota_update_count].target, msg_target,
                     CHANNELLEN);
        ircd_strncpy(quota_updates[quota_update_count].account, msg.account,
                     ACCOUNTLEN);
        quota_update_count++;
      }
    }

    /* Stage delete of the message itself.  Iterator pointers are
     * transient — writebatch copies the key, so this is safe. */
    db_writebatch_del(wb, history_cf_messages, kbase, klen);
    evicted++;
  }

  db_iter_close(it);

  rc = db_writebatch_commit(wb, /*sync=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history: emergency eviction commit failed: %s",
              db_strerror(rc));
    return -1;
  }

  /* Decrement quotas for evicted messages (now that main commit landed) */
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
  char msg_target[CHANNELLEN + 1];
  char msg_timestamp[HISTORY_TIMESTAMP_LEN];
  char msg_msgid[HISTORY_MSGID_LEN];
  struct HistoryMessage msg;
  int evicted = 0;
  int current_util;
  int rc;
  int batch_count = 0;
  int max_batch = 1000;  /* Limit per writebatch */
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

  /* Evict oldest messages in batches until we reach target. */
  while (current_util > target_percent) {
    struct db_iter *it;
    struct db_writebatch *wb;

    wb = db_writebatch_new(history_db_env);
    if (!wb)
      break;

    it = db_iter_open(history_db_env, history_cf_messages, NULL);
    if (!it) {
      db_writebatch_destroy(wb);
      break;
    }

    batch_count = 0;
    quota_update_count = 0;

    for (rc = db_iter_seek_first(it);
         rc == DB_OK && db_iter_valid(it) && batch_count < max_batch;
         rc = db_iter_next(it)) {
      size_t klen, vlen;
      const void *kbase = db_iter_key(it, &klen);
      const void *vbase = db_iter_value(it, &vlen);

      /* Parse key to get msgid for index cleanup */
      if (parse_key((void *)kbase, klen,
                    msg_target, msg_timestamp, msg_msgid) == 0) {
        if (msg_msgid[0] != '\0') {
          db_writebatch_del(wb, history_cf_msgid,
                            msg_msgid, strlen(msg_msgid));

          ml_content_delete(wb, msg_msgid);

          /* Clean reply index entries where this msgid is the parent */
          {
            char ri_keybuf[CHANNELLEN + HISTORY_MSGID_LEN + 4];
            int ri_kpos = 0;
            size_t tlen = strlen(msg_target), mlen = strlen(msg_msgid);
            if (ri_kpos + tlen + 1 + mlen < sizeof(ri_keybuf)) {
              memcpy(ri_keybuf, msg_target, tlen);
              ri_kpos += tlen;
              ri_keybuf[ri_kpos++] = KEY_SEP;
              memcpy(ri_keybuf + ri_kpos, msg_msgid, mlen);
              ri_kpos += mlen;
              db_writebatch_del(wb, history_cf_reply, ri_keybuf, ri_kpos);
            }
          }
        }
      }

      /* Collect account info for quota decrement after commit */
      if (quota_enabled && quota_updates && msg_target[0] != '\0' &&
          quota_update_count < quota_update_capacity) {
        if (deserialize_message((void *)vbase, vlen, &msg) == 0 &&
            msg.account[0] != '\0') {
          ircd_strncpy(quota_updates[quota_update_count].target, msg_target,
                       CHANNELLEN);
          ircd_strncpy(quota_updates[quota_update_count].account, msg.account,
                       ACCOUNTLEN);
          quota_update_count++;
        }
      }

      /* Stage delete of the message itself */
      db_writebatch_del(wb, history_cf_messages, kbase, klen);
      evicted++;
      batch_count++;
    }

    db_iter_close(it);

    rc = db_writebatch_commit(wb, /*sync=*/0);
    db_writebatch_destroy(wb);
    if (rc != DB_OK) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history: eviction commit failed: %s", db_strerror(rc));
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
  struct db_writebatch *wb;
  struct db_val val = { NULL, 0 };
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

  /* Get current count */
  rc = db_get(history_db_env, history_cf_quotas,
              keybuf, keylen, /*snap=*/NULL, &val);
  if (rc == DB_OK && val.len == sizeof(uint32_t))
    memcpy(&count, val.base, sizeof(uint32_t));
  if (rc == DB_OK)
    db_val_free(&val);

  /* Increment */
  count++;

  /* Store new count atomically */
  wb = db_writebatch_new(history_db_env);
  if (!wb)
    return -1;
  rc = db_writebatch_put(wb, history_cf_quotas,
                         keybuf, keylen, &count, sizeof(count));
  if (rc != DB_OK) {
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync=*/0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK)
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
  struct db_val val = { NULL, 0 };
  char keybuf[CHANNELLEN + ACCOUNTLEN + 2];
  int keylen, rc;
  uint32_t count = 0;

  if (!history_available || !channel)
    return -1;

  if (!account || !account[0])
    return 0;

  keylen = ircd_snprintf(0, keybuf, sizeof(keybuf), "%s%c%s",
                          channel, KEY_SEP, account);

  rc = db_get(history_db_env, history_cf_quotas,
              keybuf, keylen, /*snap=*/NULL, &val);
  if (rc == DB_OK && val.len == sizeof(uint32_t)) {
    struct db_writebatch *wb;
    memcpy(&count, val.base, sizeof(uint32_t));
    db_val_free(&val);
    if (count > 0)
      count--;

    wb = db_writebatch_new(history_db_env);
    if (!wb)
      return -1;
    rc = db_writebatch_put(wb, history_cf_quotas,
                           keybuf, keylen, &count, sizeof(count));
    if (rc != DB_OK) {
      db_writebatch_destroy(wb);
      return -1;
    }
    rc = db_writebatch_commit(wb, /*sync=*/0);
    db_writebatch_destroy(wb);
    if (rc != DB_OK)
      return -1;
  } else if (rc == DB_OK) {
    db_val_free(&val);
  }

  return (int)count;
}

/** Get quota count for a user in a channel.
 * @param[in] channel Channel name.
 * @param[in] account Account name.
 * @return Message count, or 0 if not found.
 */
int history_quota_get_count(const char *channel, const char *account)
{
  struct db_val val = { NULL, 0 };
  char keybuf[CHANNELLEN + ACCOUNTLEN + 2];
  int keylen, rc;
  uint32_t count = 0;

  if (!history_available || !channel || !account || !account[0])
    return 0;

  keylen = ircd_snprintf(0, keybuf, sizeof(keybuf), "%s%c%s",
                          channel, KEY_SEP, account);

  rc = db_get(history_db_env, history_cf_quotas,
              keybuf, keylen, /*snap=*/NULL, &val);
  if (rc == DB_OK) {
    if (val.len == sizeof(uint32_t))
      memcpy(&count, val.base, sizeof(uint32_t));
    db_val_free(&val);
  }

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
