/*
 * webpush_store.c - persistent storage for Web Push subscriptions and VAPID keys
 *
 * Two named column families in the webpush env:
 *   - "subscriptions": per-account push subscriptions
 *     Key:   account\0<sha256_hex(endpoint)[0:16]>
 *     Value: endpoint|p256dh_b64|auth_b64
 *   - "config": server-level config (VAPID key)
 *     Key:   "vapid_privkey"
 *     Value: 32-byte raw private key
 *
 * Routes through the storage abstraction (db_env.h / db_txn.h /
 * db_cursor.h).  Backend (libmdbx today, RocksDB after migration) is
 * selected at link time.
 */

#include "config.h"

#ifdef USE_MDBX  /* until phase 1 adds USE_ROCKSDB; tracks "abstraction available" */

#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "webpush_store.h"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------------------------------------------------------------------------
 * Storage state
 * ---------------------------------------------------------------------------*/

static struct db_env *webpush_env = NULL;
static struct db_cf  *webpush_sub_cf = NULL;     /* subscriptions */
static struct db_cf  *webpush_cfg_cf = NULL;     /* config (VAPID key) */
static int            webpush_db_available = 0;

#define WEBPUSH_MAX_DBS     2
#define WEBPUSH_MAP_SIZE    (10UL * 1024 * 1024)  /* 10 MB */
#define WEBPUSH_KEY_MAX     256
#define WEBPUSH_HASH_PREFIX 16  /* hex chars from SHA-256 of endpoint */

/* ---------------------------------------------------------------------------
 * Key building helpers (unchanged from libmdbx version)
 * ---------------------------------------------------------------------------*/

static int build_sub_key(char *key, int keysize,
                         const char *account, const char *endpoint)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  unsigned int hash_len = 0;
  EVP_MD_CTX *mdctx;
  int pos, i;
  int acct_len;

  if (!account || !endpoint)
    return -1;

  acct_len = (int)strlen(account);
  if (acct_len + 1 + WEBPUSH_HASH_PREFIX > keysize)
    return -1;

  memcpy(key, account, acct_len);
  pos = acct_len;
  key[pos++] = '\0';

  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return -1;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(mdctx, endpoint, strlen(endpoint)) != 1 ||
      EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
    EVP_MD_CTX_free(mdctx);
    return -1;
  }
  EVP_MD_CTX_free(mdctx);

  for (i = 0; i < WEBPUSH_HASH_PREFIX / 2 && i < (int)hash_len; i++) {
    snprintf(key + pos + i * 2, 3, "%02x", hash[i]);
  }
  pos += WEBPUSH_HASH_PREFIX;

  return pos;
}

static int build_prefix_key(char *key, int keysize, const char *account)
{
  int acct_len;

  if (!account)
    return -1;

  acct_len = (int)strlen(account);
  if (acct_len + 1 > keysize)
    return -1;

  memcpy(key, account, acct_len);
  key[acct_len] = '\0';

  return acct_len + 1;
}

/* ---------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------*/

int webpush_store_init(const char *dbpath)
{
  struct db_env_opts env_opts;
  struct db_cf_opts  cf_opts;
  int rc;

  if (webpush_db_available)
    return 0;

  if (!dbpath || !dbpath[0]) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: no database path specified");
    return -1;
  }

  memset(&env_opts, 0, sizeof env_opts);
  if (feature_bool(FEAT_WEBPUSH_DB_AUTOGROW)) {
    /* Autogrow up to WEBPUSH_MAP_SIZE; libmdbx grows from any starting size */
    env_opts.size_floor = 0;
    env_opts.size_max   = WEBPUSH_MAP_SIZE;
  } else {
    env_opts.size_floor = WEBPUSH_MAP_SIZE;
    env_opts.size_max   = WEBPUSH_MAP_SIZE;
  }

  rc = db_env_open(dbpath, &env_opts, WEBPUSH_MAX_DBS, &webpush_env);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: db_env_open(%s): %s", dbpath, db_strerror(rc));
    return -1;
  }

  memset(&cf_opts, 0, sizeof cf_opts);
  rc = db_cf_open(webpush_env, "subscriptions", &cf_opts, &webpush_sub_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: open subscriptions CF: %s", db_strerror(rc));
    db_env_close(webpush_env);
    webpush_env = NULL;
    return -1;
  }

  rc = db_cf_open(webpush_env, "config", &cf_opts, &webpush_cfg_cf);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: open config CF: %s", db_strerror(rc));
    db_cf_close(webpush_env, webpush_sub_cf);
    db_env_close(webpush_env);
    webpush_sub_cf = NULL;
    webpush_env = NULL;
    return -1;
  }

  webpush_db_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0,
            "WebPush store: storage initialized at %s", dbpath);
  return 0;
}

void webpush_store_shutdown(void)
{
  if (!webpush_db_available)
    return;

  db_cf_close(webpush_env, webpush_sub_cf);
  db_cf_close(webpush_env, webpush_cfg_cf);
  db_env_close(webpush_env);
  webpush_sub_cf = NULL;
  webpush_cfg_cf = NULL;
  webpush_env = NULL;
  webpush_db_available = 0;

  log_write(LS_SYSTEM, L_INFO, 0, "WebPush store: shutdown");
}

int webpush_store_available(void)
{
  return webpush_db_available;
}

int webpush_store_add(const char *account, const char *stored)
{
  struct db_writebatch *wb;
  char keybuf[WEBPUSH_KEY_MAX];
  int keylen;
  const char *endpoint_end;
  char endpoint[512];
  size_t elen;
  int rc;

  if (!webpush_db_available || !account || !stored)
    return -1;

  endpoint_end = strchr(stored, '|');
  if (!endpoint_end)
    return -1;

  elen = (size_t)(endpoint_end - stored);
  if (elen == 0 || elen >= sizeof(endpoint))
    return -1;
  memcpy(endpoint, stored, elen);
  endpoint[elen] = '\0';

  keylen = build_sub_key(keybuf, sizeof(keybuf), account, endpoint);
  if (keylen < 0)
    return -1;

  wb = db_writebatch_new(webpush_env);
  if (!wb)
    return -1;

  rc = db_writebatch_put(wb, webpush_sub_cf, keybuf, (size_t)keylen,
                         stored, strlen(stored));
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: add put failed for %s: %s",
              account, db_strerror(rc));
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
}

int webpush_store_remove(const char *account, const char *endpoint)
{
  struct db_writebatch *wb;
  char keybuf[WEBPUSH_KEY_MAX];
  int keylen;
  int rc;

  if (!webpush_db_available || !account || !endpoint)
    return -1;

  keylen = build_sub_key(keybuf, sizeof(keybuf), account, endpoint);
  if (keylen < 0)
    return -1;

  wb = db_writebatch_new(webpush_env);
  if (!wb)
    return -1;

  rc = db_writebatch_del(wb, webpush_sub_cf, keybuf, (size_t)keylen);
  if (rc != DB_OK && rc != DB_NOTFOUND) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: remove failed for %s: %s",
              account, db_strerror(rc));
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/0);
  db_writebatch_destroy(wb);
  return (rc == DB_OK) ? 0 : -1;
}

int webpush_store_clear(const char *account)
{
  /* Iterate to collect matching keys, then delete them via a single
   * write batch.  We don't delete during iteration because that's
   * libmdbx-cursor-specific behaviour and not portable to RocksDB. */
  struct db_iter *it;
  struct db_writebatch *wb;
  char prefix[WEBPUSH_KEY_MAX];
  int prefix_len;
  int count = 0;
  int rc;

  if (!webpush_db_available || !account)
    return -1;

  prefix_len = build_prefix_key(prefix, sizeof(prefix), account);
  if (prefix_len < 0)
    return -1;

  wb = db_writebatch_new(webpush_env);
  if (!wb)
    return -1;

  it = db_iter_open(webpush_env, webpush_sub_cf, NULL);
  if (!it) {
    db_writebatch_destroy(wb);
    return -1;
  }

  rc = db_iter_seek(it, prefix, (size_t)prefix_len);
  while (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *k = db_iter_key(it, &klen);
    if (klen < (size_t)prefix_len ||
        memcmp(k, prefix, (size_t)prefix_len) != 0)
      break;

    /* Stage the delete; key memory is borrowed and only valid until
     * the next iter op, so the writebatch must copy it.  Both
     * backends do (mdbx_del/rocksdb_writebatch_delete take a copy). */
    if (db_writebatch_del(wb, webpush_sub_cf, k, klen) == DB_OK)
      count++;

    rc = db_iter_next(it);
  }

  db_iter_close(it);

  if (count > 0) {
    if (db_writebatch_commit(wb, /*sync_durably=*/0) != DB_OK) {
      db_writebatch_destroy(wb);
      return -1;
    }
  }
  db_writebatch_destroy(wb);
  return count;
}

int webpush_store_count(const char *account)
{
  struct db_iter *it;
  char prefix[WEBPUSH_KEY_MAX];
  int prefix_len;
  int count = 0;
  int rc;

  if (!webpush_db_available || !account)
    return -1;

  prefix_len = build_prefix_key(prefix, sizeof(prefix), account);
  if (prefix_len < 0)
    return -1;

  it = db_iter_open(webpush_env, webpush_sub_cf, NULL);
  if (!it)
    return -1;

  rc = db_iter_seek(it, prefix, (size_t)prefix_len);
  while (rc == DB_OK && db_iter_valid(it)) {
    size_t klen;
    const void *k = db_iter_key(it, &klen);
    if (klen < (size_t)prefix_len ||
        memcmp(k, prefix, (size_t)prefix_len) != 0)
      break;
    count++;
    rc = db_iter_next(it);
  }
  db_iter_close(it);
  return count;
}

int webpush_store_foreach(const char *account, webpush_store_iter_cb cb,
                          void *data)
{
  struct db_iter *it;
  char prefix[WEBPUSH_KEY_MAX];
  int prefix_len;
  int count = 0;
  int rc;

  if (!webpush_db_available || !account || !cb)
    return -1;

  prefix_len = build_prefix_key(prefix, sizeof(prefix), account);
  if (prefix_len < 0)
    return -1;

  it = db_iter_open(webpush_env, webpush_sub_cf, NULL);
  if (!it)
    return -1;

  rc = db_iter_seek(it, prefix, (size_t)prefix_len);
  while (rc == DB_OK && db_iter_valid(it)) {
    size_t klen, vlen;
    const void *k = db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);

    if (klen < (size_t)prefix_len ||
        memcmp(k, prefix, (size_t)prefix_len) != 0)
      break;

    {
      char stored[4096];
      size_t slen = vlen;
      if (slen >= sizeof(stored))
        slen = sizeof(stored) - 1;
      memcpy(stored, v, slen);
      stored[slen] = '\0';

      if (cb(stored, data) != 0)
        break;
    }

    count++;
    rc = db_iter_next(it);
  }
  db_iter_close(it);
  return count;
}

int webpush_store_foreach_all(webpush_store_iter_all_cb cb, void *data)
{
  struct db_iter *it;
  int count = 0;
  int rc;

  if (!webpush_db_available || !cb)
    return -1;

  it = db_iter_open(webpush_env, webpush_sub_cf, NULL);
  if (!it)
    return -1;

  rc = db_iter_seek_first(it);
  while (rc == DB_OK && db_iter_valid(it)) {
    size_t klen, vlen;
    const void *k = db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);

    /* Key format: account\0<hash_hex>.  Account is the prefix up to
     * the embedded NUL.  Borrow it directly from the iterator key —
     * cb is not allowed to retain it past return. */
    {
      const char *account = (const char *)k;
      size_t acct_len = strnlen(account, klen);
      if (acct_len < klen) {
        char stored[4096];
        size_t slen = vlen;
        if (slen >= sizeof(stored))
          slen = sizeof(stored) - 1;
        memcpy(stored, v, slen);
        stored[slen] = '\0';

        if (cb(account, stored, data) != 0)
          break;
        count++;
      }
    }

    rc = db_iter_next(it);
  }
  db_iter_close(it);
  return count;
}

/* ---------------------------------------------------------------------------
 * VAPID key persistence
 * ---------------------------------------------------------------------------*/

static const char vapid_key_name[] = "vapid_privkey";

int webpush_store_set_vapid_key(const unsigned char *privkey, size_t privkey_len)
{
  struct db_writebatch *wb;
  int rc;

  if (!webpush_db_available || !privkey || privkey_len != 32)
    return -1;

  wb = db_writebatch_new(webpush_env);
  if (!wb)
    return -1;

  rc = db_writebatch_put(wb, webpush_cfg_cf,
                         vapid_key_name, sizeof(vapid_key_name) - 1,
                         privkey, privkey_len);
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: set VAPID key failed: %s", db_strerror(rc));
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = db_writebatch_commit(wb, /*sync_durably=*/1);
  db_writebatch_destroy(wb);
  if (rc != DB_OK)
    return -1;

  log_write(LS_SYSTEM, L_INFO, 0, "WebPush store: VAPID key persisted");
  return 0;
}

int webpush_store_get_vapid_key(unsigned char *privkey, size_t *privkey_len)
{
  struct db_val val = { NULL, 0 };
  int rc;

  if (!webpush_db_available || !privkey || !privkey_len || *privkey_len < 32)
    return -1;

  rc = db_get(webpush_env, webpush_cfg_cf,
              vapid_key_name, sizeof(vapid_key_name) - 1,
              /*snap=*/NULL, &val);
  if (rc == DB_NOTFOUND)
    return -1;  /* no key stored */
  if (rc != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: get VAPID key failed: %s", db_strerror(rc));
    return -1;
  }

  if (val.len != 32) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: stored VAPID key has wrong size (%zu)", val.len);
    db_val_free(&val);
    return -1;
  }

  memcpy(privkey, val.base, 32);
  *privkey_len = 32;
  db_val_free(&val);
  return 0;
}

/* ---------------------------------------------------------------------------
 * Statistics
 * ---------------------------------------------------------------------------*/

int webpush_store_get_stats(struct webpush_store_stats *stats)
{
  struct db_env_stats env_stats;
  struct db_cf_stats  cf_stats;
  int rc;

  if (!webpush_db_available || !stats)
    return -1;

  memset(stats, 0, sizeof(*stats));

  rc = db_cf_stats(webpush_env, webpush_sub_cf, &cf_stats);
  if (rc == DB_OK)
    stats->total_subscriptions = (unsigned long)cf_stats.approx_keys;

  rc = db_env_stats(webpush_env, &env_stats);
  if (rc == DB_OK)
    stats->db_size_bytes = (unsigned long)env_stats.on_disk_bytes;

  /* total_accounts requires a full scan — skip for now */
  return 0;
}

#else /* !USE_MDBX */

/* Stub implementations when storage is not available */
#include "webpush_store.h"

int webpush_store_init(const char *dbpath) { (void)dbpath; return -1; }
void webpush_store_shutdown(void) {}
int webpush_store_available(void) { return 0; }

int webpush_store_add(const char *account, const char *stored)
{ (void)account; (void)stored; return -1; }

int webpush_store_remove(const char *account, const char *endpoint)
{ (void)account; (void)endpoint; return -1; }

int webpush_store_clear(const char *account) { (void)account; return -1; }
int webpush_store_count(const char *account) { (void)account; return -1; }

int webpush_store_foreach(const char *account, webpush_store_iter_cb cb,
                          void *data)
{ (void)account; (void)cb; (void)data; return -1; }

int webpush_store_foreach_all(webpush_store_iter_all_cb cb, void *data)
{ (void)cb; (void)data; return -1; }

int webpush_store_set_vapid_key(const unsigned char *privkey, size_t privkey_len)
{ (void)privkey; (void)privkey_len; return -1; }

int webpush_store_get_vapid_key(unsigned char *privkey, size_t *privkey_len)
{ (void)privkey; (void)privkey_len; return -1; }

int webpush_store_get_stats(struct webpush_store_stats *stats)
{ (void)stats; return -1; }

#endif /* USE_MDBX */
