/*
 * paste_store.c - LMDB storage for multiline paste content
 *
 * Uses a dedicated LMDB environment with one named database:
 *   - "pastes": paste content
 *     Key:   <paste_id>
 *     Value: flags|sender|target|filename|created|expires|content
 *
 * Supports zstd compression for content when available.
 */

#include "config.h"

#ifdef USE_MDBX

#include "paste_store.h"
#include "ircd.h"          /* CurrentTime */
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_compress.h"
#include "ircd_string.h"
#include "numeric.h"       /* RPL_STATSDEBUG */
#include "ircd_reply.h"    /* SND_EXPLICIT */
#include "s_stats.h"       /* StatDesc */
#include "send.h"          /* send_reply */

#include <mdbx.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---------------------------------------------------------------------------
 * LMDB environment and databases
 * ---------------------------------------------------------------------------*/

static MDBX_env *paste_env = NULL;
static MDBX_dbi paste_dbi;
static int paste_db_available = 0;
static unsigned long paste_expired_count = 0;

/* Timer for periodic expiration */
static struct Timer paste_expire_timer;

#define PASTE_MAX_DBS       1
#define PASTE_MAP_SIZE      (100UL * 1024 * 1024)  /* 100 MB */
#define PASTE_GROWTH_STEP   (10UL * 1024 * 1024)   /* 10 MB growth */
#define PASTE_VALUE_MAX     (128 * 1024)           /* 128KB max value (compressed) */

/* Expiration check interval (seconds) */
#define PASTE_EXPIRE_INTERVAL 300  /* 5 minutes */

/* ---------------------------------------------------------------------------
 * Internal value format helpers
 *
 * Value format: flags(1)|sender|target|filename|created|expires|content
 * Fields separated by '|', content is last (may contain '|')
 * ---------------------------------------------------------------------------*/

static int parse_paste_value(const char *value, size_t value_len,
                             struct paste_entry *out)
{
  const char *p = value;
  const char *end = value + value_len;
  const char *field_start;
  int field = 0;
  unsigned char flags;
  char created_str[32], expires_str[32];
  const char *content_start = NULL;
  size_t content_len = 0;

  if (value_len < 2)
    return -1;

  /* First byte is flags */
  flags = (unsigned char)*p++;

  /* Skip '|' after flags */
  if (p >= end || *p != '|')
    return -1;
  p++;

  /* Parse pipe-separated fields */
  field_start = p;
  while (p <= end && field < 5) {
    if (p == end || *p == '|') {
      size_t len = p - field_start;
      switch (field) {
        case 0:  /* sender */
          if (len >= sizeof(out->sender)) len = sizeof(out->sender) - 1;
          memcpy(out->sender, field_start, len);
          out->sender[len] = '\0';
          break;
        case 1:  /* target */
          if (len >= sizeof(out->target)) len = sizeof(out->target) - 1;
          memcpy(out->target, field_start, len);
          out->target[len] = '\0';
          break;
        case 2:  /* filename */
          if (len >= sizeof(out->filename)) len = sizeof(out->filename) - 1;
          memcpy(out->filename, field_start, len);
          out->filename[len] = '\0';
          break;
        case 3:  /* created */
          if (len >= sizeof(created_str)) len = sizeof(created_str) - 1;
          memcpy(created_str, field_start, len);
          created_str[len] = '\0';
          out->created = (time_t)strtoll(created_str, NULL, 10);
          break;
        case 4:  /* expires */
          if (len >= sizeof(expires_str)) len = sizeof(expires_str) - 1;
          memcpy(expires_str, field_start, len);
          expires_str[len] = '\0';
          out->expires = (time_t)strtoll(expires_str, NULL, 10);
          /* Content starts after this field */
          if (p < end) {
            content_start = p + 1;
            content_len = end - content_start;
          }
          break;
      }
      field++;
      field_start = p + 1;
    }
    p++;
  }

  if (field < 5)
    return -1;

  /* Handle content (possibly compressed) */
  if (content_start && content_len > 0) {
    if (flags & PASTE_FLAG_COMPRESSED) {
      /* Decompress content */
      size_t decomp_len;
      unsigned char *decomp_buf = MyMalloc(feature_int(FEAT_PASTE_MAX_SIZE) + 1);
      if (!decomp_buf)
        return -1;

      if (decompress_data((const unsigned char *)content_start, content_len,
                          decomp_buf, feature_int(FEAT_PASTE_MAX_SIZE),
                          &decomp_len) < 0) {
        MyFree(decomp_buf);
        return -1;
      }

      out->content = MyMalloc(decomp_len + 1);
      if (!out->content) {
        MyFree(decomp_buf);
        return -1;
      }
      memcpy(out->content, decomp_buf, decomp_len);
      out->content[decomp_len] = '\0';
      out->content_len = decomp_len;
      MyFree(decomp_buf);
    } else {
      /* Uncompressed content */
      out->content = MyMalloc(content_len + 1);
      if (!out->content)
        return -1;
      memcpy(out->content, content_start, content_len);
      out->content[content_len] = '\0';
      out->content_len = content_len;
    }
  } else {
    out->content = MyMalloc(1);
    if (!out->content)
      return -1;
    out->content[0] = '\0';
    out->content_len = 0;
  }

  return 0;
}

static int build_paste_value(const char *sender, const char *target,
                             const char *filename, time_t created,
                             time_t expires, const char *content,
                             size_t content_len, char **out_value,
                             size_t *out_len)
{
  char header[512];
  int header_len;
  unsigned char *compressed = NULL;
  size_t compressed_len = 0;
  int did_compress = 0;
  unsigned char flags = 0;
  size_t threshold;

  /* Build header: flags|sender|target|filename|created|expires| */
  header_len = snprintf(header, sizeof(header), "X|%s|%s|%s|%lld|%lld|",
                        sender ? sender : "",
                        target ? target : "",
                        filename ? filename : "",
                        (long long)created,
                        (long long)expires);

  if (header_len < 0 || header_len >= (int)sizeof(header))
    return -1;

  /* Try to compress content if above threshold */
  threshold = (size_t)feature_int(FEAT_PASTE_COMPRESS_THRESHOLD);
  if (content_len >= threshold) {
    compressed = MyMalloc(content_len + 256);
    if (compressed) {
      int rc = compress_data((const unsigned char *)content, content_len,
                             compressed, content_len + 256, &compressed_len);
      if (rc > 0) {
        /* Compression succeeded and made it smaller */
        did_compress = 1;
        flags |= PASTE_FLAG_COMPRESSED;
      } else {
        MyFree(compressed);
        compressed = NULL;
      }
    }
  }

  /* Allocate output buffer */
  if (did_compress) {
    *out_len = header_len + compressed_len;
  } else {
    *out_len = header_len + content_len;
  }

  *out_value = MyMalloc(*out_len);
  if (!*out_value) {
    if (compressed)
      MyFree(compressed);
    return -1;
  }

  /* Copy header (flags byte first) */
  memcpy(*out_value, header, header_len);
  (*out_value)[0] = flags;  /* Replace 'X' placeholder with actual flags */

  /* Copy content */
  if (did_compress) {
    memcpy(*out_value + header_len, compressed, compressed_len);
    MyFree(compressed);
  } else {
    memcpy(*out_value + header_len, content, content_len);
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * Timer callback for periodic expiration
 * ---------------------------------------------------------------------------*/

static void paste_expire_callback(struct Event *ev)
{
  int expired;

  if (ev_type(ev) != ET_EXPIRE)
    return;

  expired = paste_store_expire();
  if (expired > 0) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "Paste store: expired %d pastes", expired);
  }
}

/* ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------*/

int paste_store_init(const char *dbpath)
{
  MDBX_txn *txn;
  int rc;

  if (paste_db_available)
    return 0;

  if (!dbpath || !dbpath[0]) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: no database path specified");
    return -1;
  }

  rc = mdbx_env_create(&paste_env);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_env_create: %s", mdbx_strerror(rc));
    return -1;
  }

  rc = mdbx_env_set_maxdbs(paste_env, PASTE_MAX_DBS);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_env_set_maxdbs: %s", mdbx_strerror(rc));
    goto fail;
  }

  if (feature_bool(FEAT_PASTE_DB_AUTOGROW)) {
    rc = mdbx_env_set_geometry(paste_env, -1, -1, PASTE_MAP_SIZE,
                               PASTE_GROWTH_STEP, PASTE_GROWTH_STEP, -1);
  } else {
    rc = mdbx_env_set_geometry(paste_env, PASTE_MAP_SIZE, PASTE_MAP_SIZE,
                               PASTE_MAP_SIZE, 0, 0, -1);
  }
  if (rc != MDBX_SUCCESS) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_env_set_geometry: %s", mdbx_strerror(rc));
    goto fail;
  }

  rc = mdbx_env_open(paste_env, dbpath, 0, 0644);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_env_open(%s): %s", dbpath, mdbx_strerror(rc));
    goto fail;
  }

  /* Open named database */
  rc = mdbx_txn_begin(paste_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_begin: %s", mdbx_strerror(rc));
    goto fail;
  }

  rc = mdbx_dbi_open(txn, "pastes", MDBX_CREATE, &paste_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: open pastes DBI: %s", mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    goto fail;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_commit: %s", mdbx_strerror(rc));
    goto fail;
  }

  paste_db_available = 1;

  /* Set up expiration timer */
  timer_add(timer_init(&paste_expire_timer), paste_expire_callback, NULL,
            TT_PERIODIC, PASTE_EXPIRE_INTERVAL);

  log_write(LS_SYSTEM, L_INFO, 0,
            "Paste store: initialized at %s", dbpath);
  return 0;

fail:
  if (paste_env) {
    mdbx_env_close(paste_env);
    paste_env = NULL;
  }
  return -1;
}

void paste_store_shutdown(void)
{
  if (!paste_db_available)
    return;

  if (t_active(&paste_expire_timer))
    timer_del(&paste_expire_timer);

  if (paste_env) {
    mdbx_env_close(paste_env);
    paste_env = NULL;
  }

  paste_db_available = 0;
  log_write(LS_SYSTEM, L_INFO, 0,
            "Paste store: shutdown (expired %lu total)", paste_expired_count);
}

int paste_store_available(void)
{
  return paste_db_available;
}

int paste_store_add(const char *paste_id, const char *sender,
                    const char *target, const char *filename,
                    const char *content, size_t content_len, time_t ttl)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char *value = NULL;
  size_t value_len;
  time_t now, expires;
  int rc;

  if (!paste_db_available)
    return -1;

  if (!paste_id || !content)
    return -1;

  /* Check size limit */
  if (content_len > (size_t)feature_int(FEAT_PASTE_MAX_SIZE)) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "Paste store: content too large (%zu > %d)",
              content_len, feature_int(FEAT_PASTE_MAX_SIZE));
    return -1;
  }

  now = CurrentTime;
  expires = now + ttl;

  /* Build value */
  if (build_paste_value(sender, target, filename, now, expires,
                        content, content_len, &value, &value_len) < 0) {
    return -1;
  }

  /* Store in LMDB */
  rc = mdbx_txn_begin(paste_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_begin: %s", mdbx_strerror(rc));
    MyFree(value);
    return -1;
  }

  key.iov_base = (void *)paste_id;
  key.iov_len = strlen(paste_id);
  data.iov_base = value;
  data.iov_len = value_len;

  rc = mdbx_put(txn, paste_dbi, &key, &data, 0);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_put: %s", mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    MyFree(value);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  MyFree(value);

  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_commit: %s", mdbx_strerror(rc));
    return -1;
  }

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "Paste store: added %s (%zu bytes, expires %lld)",
            paste_id, content_len, (long long)expires);
  return 0;
}

int paste_store_get(const char *paste_id, struct paste_entry *out)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  int rc;

  if (!paste_db_available)
    return -1;

  if (!paste_id || !out)
    return -1;

  memset(out, 0, sizeof(*out));

  rc = mdbx_txn_begin(paste_env, NULL, MDBX_TXN_RDONLY, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_begin: %s", mdbx_strerror(rc));
    return -1;
  }

  key.iov_base = (void *)paste_id;
  key.iov_len = strlen(paste_id);

  rc = mdbx_get(txn, paste_dbi, &key, &data);
  if (rc == MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return 1;  /* Not found */
  }
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_get: %s", mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Parse value */
  if (parse_paste_value(data.iov_base, data.iov_len, out) < 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "Paste store: failed to parse value for %s", paste_id);
    mdbx_txn_abort(txn);
    return -1;
  }

  /* Copy paste_id */
  ircd_strncpy(out->paste_id, paste_id, sizeof(out->paste_id) - 1);
  out->paste_id[sizeof(out->paste_id) - 1] = '\0';

  mdbx_txn_abort(txn);  /* Read-only, just abort */

  /* Check expiration */
  if (out->expires <= CurrentTime) {
    paste_entry_free(out);
    memset(out, 0, sizeof(*out));
    return 1;  /* Expired = not found */
  }

  return 0;
}

int paste_store_remove(const char *paste_id)
{
  MDBX_txn *txn;
  MDBX_val key;
  int rc;

  if (!paste_db_available)
    return -1;

  if (!paste_id)
    return -1;

  rc = mdbx_txn_begin(paste_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_begin: %s", mdbx_strerror(rc));
    return -1;
  }

  key.iov_base = (void *)paste_id;
  key.iov_len = strlen(paste_id);

  rc = mdbx_del(txn, paste_dbi, &key, NULL);
  if (rc == MDBX_NOTFOUND) {
    mdbx_txn_abort(txn);
    return 1;  /* Not found */
  }
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_del: %s", mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return -1;
  }

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store: mdbx_txn_commit: %s", mdbx_strerror(rc));
    return -1;
  }

  return 0;
}

int paste_store_expire(void)
{
  MDBX_txn *txn;
  MDBX_cursor *cursor;
  MDBX_val key, data;
  time_t now;
  int expired = 0;
  int rc;

  if (!paste_db_available)
    return 0;

  now = CurrentTime;

  rc = mdbx_txn_begin(paste_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store expire: mdbx_txn_begin: %s", mdbx_strerror(rc));
    return 0;
  }

  rc = mdbx_cursor_open(txn, paste_dbi, &cursor);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store expire: mdbx_cursor_open: %s", mdbx_strerror(rc));
    mdbx_txn_abort(txn);
    return 0;
  }

  /* Iterate all entries */
  while ((rc = mdbx_cursor_get(cursor, &key, &data, MDBX_NEXT)) == 0) {
    /* Parse just enough to get expires timestamp */
    const char *value = data.iov_base;
    size_t value_len = data.iov_len;
    const char *p;
    int field = 0;
    time_t expires = 0;

    if (value_len < 2)
      continue;

    /* Skip flags byte and separator */
    p = value + 2;
    while (p < value + value_len && field < 5) {
      if (*p == '|') {
        field++;
        if (field == 5) {
          /* Parse expires from previous field */
          const char *field_start = p;
          while (field_start > value + 2 && *(field_start - 1) != '|')
            field_start--;
          expires = (time_t)strtoll(field_start, NULL, 10);
          break;
        }
      }
      p++;
    }

    if (expires > 0 && expires <= now) {
      /* Delete this entry */
      rc = mdbx_cursor_del(cursor, 0);
      if (rc == 0) {
        expired++;
      }
    }
  }

  mdbx_cursor_close(cursor);

  rc = mdbx_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "Paste store expire: mdbx_txn_commit: %s", mdbx_strerror(rc));
    return 0;
  }

  paste_expired_count += expired;
  return expired;
}

int paste_store_get_stats(struct paste_store_stats *stats)
{
  MDBX_txn *txn;
  MDBX_stat mst;
  MDBX_envinfo mei;
  int rc;

  if (!stats)
    return -1;

  memset(stats, 0, sizeof(*stats));
  stats->expired = paste_expired_count;

  if (!paste_db_available)
    return 0;

  rc = mdbx_txn_begin(paste_env, NULL, MDBX_TXN_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdbx_dbi_stat(txn, paste_dbi, &mst, sizeof(mst));
  if (rc == 0) {
    stats->count = mst.ms_entries;
  }

  rc = mdbx_env_info_ex(paste_env, txn, &mei, sizeof(mei));
  if (rc == 0) {
    stats->bytes = mei.mi_mapsize;
  }

  mdbx_txn_abort(txn);
  return 0;
}

void paste_entry_free(struct paste_entry *entry)
{
  if (entry && entry->content) {
    MyFree(entry->content);
    entry->content = NULL;
    entry->content_len = 0;
  }
}

void paste_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct paste_store_stats stats;
  MDBX_envinfo mei;
  int rc;

  (void)sd; (void)param;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :Paste Store Statistics");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  LMDB Backend: %s",
             paste_db_available ? "Available" : "Unavailable");

  if (!paste_db_available) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  (LMDB not initialized)");
    return;
  }

  if (paste_store_get_stats(&stats) < 0) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  (Error getting stats)");
    return;
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  Stored pastes: %lu",
             stats.count);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  Expired (since startup): %lu",
             stats.expired);

  /* Get more detailed LMDB info */
  rc = mdbx_env_info_ex(paste_env, NULL, &mei, sizeof(mei));
  if (rc == MDBX_SUCCESS) {
    unsigned long used_mb = (unsigned long)(mei.mi_geo.current / (1024 * 1024));
    unsigned long max_mb = (unsigned long)(mei.mi_geo.upper / (1024 * 1024));
    int util = (mei.mi_geo.upper > 0)
               ? (int)((mei.mi_geo.current * 100) / mei.mi_geo.upper)
               : 0;

    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  Database size: %lu MB / %lu MB (%d%%)",
               used_mb, max_mb, util);
  }

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  TTL: %d seconds",
             feature_int(FEAT_PASTE_TTL));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "P :  HTTP Port: %d",
             feature_int(FEAT_PASTE_PORT));
}

#else /* !USE_MDBX */

/* Stub implementations when MDBX is not available */

#include "paste_store.h"
#include "ircd_log.h"
#include "s_stats.h"
#include <string.h>

int paste_store_init(const char *dbpath)
{
  log_write(LS_SYSTEM, L_WARNING, 0,
            "Paste store: MDBX not compiled in, paste storage disabled");
  return -1;
}

void paste_store_shutdown(void)
{
}

int paste_store_available(void)
{
  return 0;
}

int paste_store_add(const char *paste_id, const char *sender,
                    const char *target, const char *filename,
                    const char *content, size_t content_len, time_t ttl)
{
  return -1;
}

int paste_store_get(const char *paste_id, struct paste_entry *out)
{
  return -1;
}

int paste_store_remove(const char *paste_id)
{
  return -1;
}

int paste_store_expire(void)
{
  return 0;
}

int paste_store_get_stats(struct paste_store_stats *stats)
{
  if (stats)
    memset(stats, 0, sizeof(*stats));
  return 0;
}

void paste_entry_free(struct paste_entry *entry)
{
  (void)entry;
}

void paste_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  (void)to; (void)sd; (void)param;
  /* MDBX not available - nothing to report */
}

#endif /* USE_MDBX */
