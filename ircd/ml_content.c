/*
 * IRC - Internet Relay Chat, ircd/ml_content.c
 * Copyright (C) 2026 Nefarious Development Team
 *
 * Unified multiline content store.
 *
 * Replaces the separate ml_storage (in-memory hash table) and paste_store
 * (standalone MDBX) systems with a single column-family pair living within
 * history's storage environment.
 *
 * Two named CFs:
 *   ml_content       - msgid -> sender\0target\0content (compressed)
 *   ml_paste_secrets - paste_id -> msgid
 *
 * Content entries share history's retention lifecycle: when a history
 * entry is evicted or purged, the corresponding ml_content entry is
 * deleted in the same writebatch.
 */
#include "config.h"

#ifdef USE_MDBX

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "ml_content.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"

#include <string.h>
#ifdef USE_ZSTD
#include <zstd.h>
#endif

/** Storage environment (shared with history; not owned by us). */
static struct db_env *ml_db_env = NULL;
static struct db_cf  *ml_content_cf = NULL;
static struct db_cf  *ml_paste_secrets_cf = NULL;

/** Whether the module is initialized */
static int ml_available = 0;

/** Stack buffer for serialized values (sender\0target\0content) */
#define ML_VALUE_BUFSIZE 1024

int ml_content_init(struct db_env *env)
{
  struct db_cf_opts cf_opts;
  int rc;

  if (ml_available)
    return 0;
  if (!env)
    return -1;

  memset(&cf_opts, 0, sizeof cf_opts);
  rc = db_cf_open(env, "ml_content", &cf_opts, &ml_content_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "ml_content: db_cf_open(ml_content) failed: %s", db_strerror(rc));
    return -1;
  }
  rc = db_cf_open(env, "ml_paste_secrets", &cf_opts, &ml_paste_secrets_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "ml_content: db_cf_open(ml_paste_secrets) failed: %s", db_strerror(rc));
    db_cf_close(env, ml_content_cf);
    ml_content_cf = NULL;
    return -1;
  }

  ml_db_env = env;
  ml_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "ml_content: initialized");
  return 0;
}

void ml_content_shutdown(struct db_env *env)
{
  if (!ml_available)
    return;

  db_cf_close(env, ml_content_cf);
  db_cf_close(env, ml_paste_secrets_cf);
  ml_content_cf = NULL;
  ml_paste_secrets_cf = NULL;
  ml_db_env = NULL;
  ml_available = 0;
}

int ml_content_available(void)
{
  return ml_available;
}

/**
 * Build a serialized value: sender\0target\0content
 * Returns total length, or -1 on error.
 */
static int ml_build_value(char *buf, size_t bufsize,
                          const char *sender, const char *target,
                          const char *content, size_t content_len)
{
  size_t sender_len = sender ? strlen(sender) : 0;
  size_t target_len = target ? strlen(target) : 0;
  size_t total = sender_len + 1 + target_len + 1 + content_len;

  if (total > bufsize)
    return -1;

  memcpy(buf, sender, sender_len);
  buf[sender_len] = '\0';
  memcpy(buf + sender_len + 1, target, target_len);
  buf[sender_len + 1 + target_len] = '\0';
  memcpy(buf + sender_len + 1 + target_len + 1, content, content_len);

  return (int)total;
}

int ml_content_store(struct db_writebatch *wb, const char *msgid,
                     const char *sender, const char *target,
                     const char *content, size_t content_len,
                     const char *paste_secret)
{
  int rc;

  if (!ml_available)
    return -1;

  /* Build the value: sender\0target\0content */
  size_t sender_len = sender ? strlen(sender) : 0;
  size_t target_len = target ? strlen(target) : 0;
  size_t total = sender_len + 1 + target_len + 1 + content_len;

  char valbuf_stack[ML_VALUE_BUFSIZE];
  char *valbuf = (total > sizeof(valbuf_stack))
      ? (char *)MyMalloc(total) : valbuf_stack;

  int vallen = ml_build_value(valbuf, total, sender, target,
                               content, content_len);
  if (vallen < 0) {
    if (valbuf != valbuf_stack) MyFree(valbuf);
    return -1;
  }

  const void *put_data = valbuf;
  size_t put_len = vallen;

  /* Optional compression */
#ifdef USE_ZSTD
  size_t comp_bufsize = ZSTD_compressBound(vallen) + 2;
  unsigned char comp_stack[ML_VALUE_BUFSIZE + 64];
  unsigned char *compressed = (comp_bufsize > sizeof(comp_stack))
      ? (unsigned char *)MyMalloc(comp_bufsize) : comp_stack;
  size_t compressed_len;

  if (compress_data((unsigned char *)valbuf, vallen,
                    compressed, comp_bufsize, &compressed_len) >= 0) {
    put_data = compressed;
    put_len = compressed_len;
  }
#endif

  /* Stage the put on the caller's writebatch.  The wb copies, so the
   * scratch buffers can be freed immediately. */
  rc = db_writebatch_put(wb, ml_content_cf,
                         msgid, strlen(msgid),
                         put_data, put_len);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "ml_content: writebatch_put(content) failed: %s", db_strerror(rc));
    goto store_done;
  }

  /* Store paste secret mapping if provided */
  if (paste_secret && paste_secret[0]) {
    char paste_id[128];
    ircd_snprintf(0, paste_id, sizeof(paste_id), "%s-%s", msgid, paste_secret);

    rc = db_writebatch_put(wb, ml_paste_secrets_cf,
                           paste_id, strlen(paste_id),
                           msgid, strlen(msgid));
    if (rc != DB_OK) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "ml_content: writebatch_put(paste_secret) failed: %s",
                db_strerror(rc));
    }
  }

store_done:
  if (valbuf != valbuf_stack) MyFree(valbuf);
#ifdef USE_ZSTD
  if (compressed != comp_stack) MyFree(compressed);
#endif
  return (rc == DB_OK) ? 0 : -1;
}

char *ml_content_get(const char *msgid, size_t *content_len_out,
                     const char **sender_out, const char **target_out)
{
  struct db_val val = { NULL, 0 };
  char *result = NULL;
  int rc;

  if (!ml_available)
    return NULL;

  rc = db_get(ml_db_env, ml_content_cf,
              msgid, strlen(msgid), /*snap=*/NULL, &val);
  if (rc != DB_OK)
    return NULL;

  /* Decompress if needed */
  const char *raw = (const char *)val.base;
  size_t raw_len = val.len;
  char *decompressed = NULL;
  int decomp_dynamic = 0;

#ifdef USE_ZSTD
  if (is_compressed((const unsigned char *)raw, raw_len)) {
    unsigned long long frame_size = ZSTD_getFrameContentSize(
        (const unsigned char *)raw + 1, raw_len - 1);
    size_t out_size;
    char decomp_stack[ML_VALUE_BUFSIZE];

    if (frame_size != ZSTD_CONTENTSIZE_ERROR
        && frame_size != ZSTD_CONTENTSIZE_UNKNOWN
        && frame_size > sizeof(decomp_stack)) {
      if (frame_size > COMPRESS_MAX_UNCOMPRESSED) {
        db_val_free(&val);
        return NULL;
      }
      decompressed = (char *)MyMalloc(frame_size + 1);
      decomp_dynamic = 1;
      out_size = frame_size + 1;
    } else {
      decompressed = decomp_stack;
      out_size = sizeof(decomp_stack);
    }

    size_t decompressed_len;
    if (decompress_data((const unsigned char *)raw, raw_len,
                        (unsigned char *)decompressed, out_size,
                        &decompressed_len) < 0) {
      if (decomp_dynamic) MyFree(decompressed);
      db_val_free(&val);
      return NULL;
    }
    raw = decompressed;
    raw_len = decompressed_len;
  }
#endif

  /* Parse: sender\0target\0content */
  const char *sender = raw;
  const char *sender_end = memchr(raw, '\0', raw_len);
  if (!sender_end) goto get_done;

  const char *tgt = sender_end + 1;
  size_t remaining = raw_len - (tgt - raw);
  const char *target_end = memchr(tgt, '\0', remaining);
  if (!target_end) goto get_done;

  const char *content = target_end + 1;
  size_t clen = raw_len - (content - raw);

  /* Allocate result buffer and copy everything */
  result = (char *)MyMalloc(raw_len + 1);
  memcpy(result, raw, raw_len);
  result[raw_len] = '\0';

  if (sender_out) *sender_out = result;
  if (target_out) *target_out = result + (tgt - raw);
  if (content_len_out) *content_len_out = clen;

  /* Suppress unused warnings if neither paths use these aliases. */
  (void)sender;
  (void)content;

get_done:
  if (decomp_dynamic) MyFree(decompressed);
  db_val_free(&val);
  return result;
}

int ml_content_resolve(struct db_snapshot *snap, struct HistoryMessage *msg)
{
  struct db_val val = { NULL, 0 };
  int rc;

  if (!ml_available)
    return -1;

  /* Check for multiline sentinel */
  if (msg->content[0] != '\x1E' || msg->content[1] != 'm' || msg->content[2] != 'l')
    return 0;  /* Not a multiline ref — nothing to do */

  rc = db_get(ml_db_env, ml_content_cf,
              msg->msgid, strlen(msg->msgid), snap, &val);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "ml_content: resolve failed for msgid=%s: %s",
              msg->msgid, db_strerror(rc));
    return -1;
  }

  /* Decompress if needed */
  const char *raw = (const char *)val.base;
  size_t raw_len = val.len;
  char *decompressed = NULL;
  int decomp_dynamic = 0;

#ifdef USE_ZSTD
  if (is_compressed((const unsigned char *)raw, raw_len)) {
    unsigned long long frame_size = ZSTD_getFrameContentSize(
        (const unsigned char *)raw + 1, raw_len - 1);
    size_t out_size;
    char decomp_stack[ML_VALUE_BUFSIZE];

    if (frame_size != ZSTD_CONTENTSIZE_ERROR
        && frame_size != ZSTD_CONTENTSIZE_UNKNOWN
        && frame_size > sizeof(decomp_stack)) {
      if (frame_size > COMPRESS_MAX_UNCOMPRESSED) {
        db_val_free(&val);
        return -1;
      }
      decompressed = (char *)MyMalloc(frame_size + 1);
      decomp_dynamic = 1;
      out_size = frame_size + 1;
    } else {
      decompressed = decomp_stack;
      out_size = sizeof(decomp_stack);
    }

    size_t decompressed_len;
    if (decompress_data((const unsigned char *)raw, raw_len,
                        (unsigned char *)decompressed, out_size,
                        &decompressed_len) < 0) {
      if (decomp_dynamic) MyFree(decompressed);
      db_val_free(&val);
      return -1;
    }
    raw = decompressed;
    raw_len = decompressed_len;
  }
#endif

  /* Parse: sender\0target\0content — we only need the content portion */
  const char *p = raw;
  const char *end = raw + raw_len;

  /* Skip sender */
  const char *sep = memchr(p, '\0', end - p);
  if (!sep) goto resolve_done;
  p = sep + 1;

  /* Skip target */
  sep = memchr(p, '\0', end - p);
  if (!sep) goto resolve_done;
  p = sep + 1;

  /* p now points to content, (end - p) is content length */
  size_t clen = end - p;
  msg->dyn_content = (char *)MyMalloc(clen + 1);
  memcpy(msg->dyn_content, p, clen);
  msg->dyn_content[clen] = '\0';
  msg->dyn_content_len = clen;

resolve_done:
  if (decomp_dynamic) MyFree(decompressed);
  db_val_free(&val);
  return (msg->dyn_content != NULL) ? 0 : -1;
}

int ml_content_delete(struct db_writebatch *wb, const char *msgid)
{
  int rc;

  if (!ml_available || !msgid || !msgid[0])
    return 0;

  rc = db_writebatch_del(wb, ml_content_cf, msgid, strlen(msgid));
  if (rc != DB_OK)
    return -1;

  /* Note: paste_secret entries are not cleaned up here because we don't
   * know the paste_id (msgid-secret) from just the msgid. Orphaned paste
   * secret entries are harmless — they point to a deleted msgid, so
   * ml_content_paste_lookup will return a msgid that fails the subsequent
   * ml_content_get, resulting in a 404.
   */
  return 0;
}

const char *ml_content_paste_lookup(const char *paste_id)
{
  static char msgid_buf[64];
  struct db_val val = { NULL, 0 };
  int rc;

  if (!ml_available)
    return NULL;

  rc = db_get(ml_db_env, ml_paste_secrets_cf,
              paste_id, strlen(paste_id), /*snap=*/NULL, &val);
  if (rc != DB_OK)
    return NULL;

  size_t len = val.len;
  if (len >= sizeof(msgid_buf))
    len = sizeof(msgid_buf) - 1;
  memcpy(msgid_buf, val.base, len);
  msgid_buf[len] = '\0';

  db_val_free(&val);
  return msgid_buf;
}

#endif /* USE_MDBX */
