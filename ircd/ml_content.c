/*
 * IRC - Internet Relay Chat, ircd/ml_content.c
 * Copyright (C) 2026 Nefarious Development Team
 *
 * Unified multiline content store.
 *
 * Replaces the separate ml_storage (in-memory hash table) and paste_store
 * (standalone MDBX) systems with a single MDBX-backed store that lives
 * within history's MDBX environment.
 *
 * Two named databases:
 *   ml_content       - msgid -> sender\0target\0content (compressed)
 *   ml_paste_secrets - paste_id -> msgid
 *
 * Content entries share history's retention lifecycle: when a history
 * entry is evicted or purged, the corresponding ml_content entry is
 * deleted in the same transaction.
 */
#include "config.h"

#ifdef USE_MDBX

#include "ml_content.h"
#include "history.h"
#include "ircd_alloc.h"
#include "ircd_compress.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"

#include <mdbx.h>
#include <string.h>
#ifdef USE_ZSTD
#include <zstd.h>
#endif

/** MDBX environment (shared with history) */
static MDBX_env *ml_env = NULL;

/** DBI handle for multiline content */
static MDBX_dbi ml_content_dbi;

/** DBI handle for paste secret -> msgid index */
static MDBX_dbi ml_paste_secrets_dbi;

/** Whether the module is initialized */
static int ml_available = 0;

/** Stack buffer for serialized values (sender\0target\0content) */
#define ML_VALUE_BUFSIZE 1024

int ml_content_init(MDBX_env *env, MDBX_txn *txn)
{
  int rc;

  if (ml_available)
    return 0;

  rc = mdbx_dbi_open(txn, "ml_content", MDBX_CREATE, &ml_content_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "ml_content: mdbx_dbi_open(ml_content) failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  rc = mdbx_dbi_open(txn, "ml_paste_secrets", MDBX_CREATE, &ml_paste_secrets_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "ml_content: mdbx_dbi_open(ml_paste_secrets) failed: %s",
              mdbx_strerror(rc));
    return -1;
  }

  ml_env = env;
  ml_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0, "ml_content: initialized");
  return 0;
}

void ml_content_shutdown(MDBX_env *env)
{
  if (!ml_available)
    return;

  mdbx_dbi_close(env, ml_content_dbi);
  mdbx_dbi_close(env, ml_paste_secrets_dbi);
  ml_env = NULL;
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

int ml_content_store(MDBX_txn *txn, const char *msgid,
                     const char *sender, const char *target,
                     const char *content, size_t content_len,
                     const char *paste_secret)
{
  MDBX_val key, data;
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

  /* Optional compression */
#ifdef USE_ZSTD
  size_t comp_bufsize = ZSTD_compressBound(vallen) + 2;
  unsigned char comp_stack[ML_VALUE_BUFSIZE + 64];
  unsigned char *compressed = (comp_bufsize > sizeof(comp_stack))
      ? (unsigned char *)MyMalloc(comp_bufsize) : comp_stack;
  size_t compressed_len;

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

  /* Store content keyed by msgid */
  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_put(txn, ml_content_dbi, &key, &data, 0);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "ml_content: mdbx_put(content) failed: %s", mdbx_strerror(rc));
    goto store_done;
  }

  /* Store paste secret mapping if provided */
  if (paste_secret && paste_secret[0]) {
    char paste_id[128];
    ircd_snprintf(0, paste_id, sizeof(paste_id), "%s-%s", msgid, paste_secret);

    MDBX_val paste_key, paste_val;
    paste_key.iov_len = strlen(paste_id);
    paste_key.iov_base = paste_id;
    paste_val.iov_len = strlen(msgid);
    paste_val.iov_base = (void *)msgid;

    rc = mdbx_put(txn, ml_paste_secrets_dbi, &paste_key, &paste_val, 0);
    if (rc != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "ml_content: mdbx_put(paste_secret) failed: %s",
                mdbx_strerror(rc));
    }
  }

store_done:
  if (valbuf != valbuf_stack) MyFree(valbuf);
#ifdef USE_ZSTD
  if (compressed != comp_stack) MyFree(compressed);
#endif
  return (rc == 0) ? 0 : -1;
}

char *ml_content_get(const char *msgid, size_t *content_len_out,
                     const char **sender_out, const char **target_out)
{
  MDBX_txn *txn;
  MDBX_val key, data;
  char *result = NULL;
  int rc;

  if (!ml_available)
    return NULL;

  rc = mdbx_txn_begin(ml_env, NULL, MDBX_TXN_RDONLY, &txn);
  if (rc != 0)
    return NULL;

  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_get(txn, ml_content_dbi, &key, &data);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return NULL;
  }

  /* Decompress if needed */
  const char *raw = (const char *)data.iov_base;
  size_t raw_len = data.iov_len;
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
        mdbx_txn_abort(txn);
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
      mdbx_txn_abort(txn);
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

get_done:
  if (decomp_dynamic) MyFree(decompressed);
  mdbx_txn_abort(txn);
  return result;
}

int ml_content_resolve(MDBX_txn *txn, struct HistoryMessage *msg)
{
  MDBX_val key, data;
  int rc;

  if (!ml_available)
    return -1;

  /* Check for multiline sentinel */
  if (msg->content[0] != '\x1E' || msg->content[1] != 'm' || msg->content[2] != 'l')
    return 0;  /* Not a multiline ref — nothing to do */

  /* Look up content by msgid */
  key.iov_len = strlen(msg->msgid);
  key.iov_base = msg->msgid;

  rc = mdbx_get(txn, ml_content_dbi, &key, &data);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "ml_content: resolve failed for msgid=%s: %s",
              msg->msgid, mdbx_strerror(rc));
    return -1;
  }

  /* Decompress if needed */
  const char *raw = (const char *)data.iov_base;
  size_t raw_len = data.iov_len;
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
      if (frame_size > COMPRESS_MAX_UNCOMPRESSED) return -1;
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
  return (msg->dyn_content != NULL) ? 0 : -1;
}

int ml_content_delete(MDBX_txn *txn, const char *msgid)
{
  MDBX_val key;
  int rc;

  if (!ml_available || !msgid || !msgid[0])
    return 0;

  key.iov_len = strlen(msgid);
  key.iov_base = (void *)msgid;

  rc = mdbx_del(txn, ml_content_dbi, &key, NULL);
  if (rc != 0 && rc != MDBX_NOTFOUND)
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
  MDBX_txn *txn;
  MDBX_val key, data;
  int rc;

  if (!ml_available)
    return NULL;

  rc = mdbx_txn_begin(ml_env, NULL, MDBX_TXN_RDONLY, &txn);
  if (rc != 0)
    return NULL;

  key.iov_len = strlen(paste_id);
  key.iov_base = (void *)paste_id;

  rc = mdbx_get(txn, ml_paste_secrets_dbi, &key, &data);
  if (rc != 0) {
    mdbx_txn_abort(txn);
    return NULL;
  }

  /* Copy msgid to static buffer */
  size_t len = data.iov_len;
  if (len >= sizeof(msgid_buf))
    len = sizeof(msgid_buf) - 1;
  memcpy(msgid_buf, data.iov_base, len);
  msgid_buf[len] = '\0';

  mdbx_txn_abort(txn);
  return msgid_buf;
}

#endif /* USE_MDBX */
