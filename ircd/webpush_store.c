/*
 * webpush_store.c - LMDB storage for Web Push subscriptions and VAPID keys
 *
 * Uses a dedicated LMDB environment with two named databases:
 *   - "subscriptions": per-account push subscriptions
 *     Key:   account\0<sha256_hex(endpoint)[0:16]>
 *     Value: endpoint|p256dh_b64|auth_b64
 *   - "config": server-level config (VAPID key)
 *     Key:   "vapid_privkey"
 *     Value: 32-byte raw private key
 */

#include "config.h"

#ifdef USE_LMDB

#include "webpush_store.h"
#include "ircd_log.h"

#include <lmdb.h>

#include <openssl/evp.h>   /* EVP_Digest for SHA-256 hash of endpoint */
#include <openssl/sha.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---------------------------------------------------------------------------
 * LMDB environment and databases
 * ---------------------------------------------------------------------------*/

static MDB_env *webpush_env = NULL;
static MDB_dbi webpush_sub_dbi;     /* subscriptions */
static MDB_dbi webpush_cfg_dbi;     /* config (VAPID key) */
static int webpush_db_available = 0;

#define WEBPUSH_MAX_DBS     2
#define WEBPUSH_MAP_SIZE    (10UL * 1024 * 1024)  /* 10 MB */
#define WEBPUSH_KEY_MAX     256
#define WEBPUSH_HASH_PREFIX 16  /* hex chars from SHA-256 of endpoint */

/* ---------------------------------------------------------------------------
 * Key building helpers
 * ---------------------------------------------------------------------------*/

/*
 * Build a subscription key: account\0<hex_prefix_of_sha256(endpoint)>
 * Returns key length, or -1 on error.
 */
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
  /* Need: acct_len + 1 (separator) + WEBPUSH_HASH_PREFIX */
  if (acct_len + 1 + WEBPUSH_HASH_PREFIX > keysize)
    return -1;

  /* Copy account + NUL separator */
  memcpy(key, account, acct_len);
  pos = acct_len;
  key[pos++] = '\0';

  /* SHA-256 hash of endpoint, take first 16 hex chars */
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

  /* Write first 8 bytes as 16 hex chars */
  for (i = 0; i < WEBPUSH_HASH_PREFIX / 2 && i < (int)hash_len; i++) {
    snprintf(key + pos + i * 2, 3, "%02x", hash[i]);
  }
  pos += WEBPUSH_HASH_PREFIX;

  return pos;
}

/*
 * Build a prefix key for cursor range scan: account\0
 * Returns prefix length.
 */
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
  MDB_txn *txn;
  int rc;

  if (webpush_db_available)
    return 0;

  if (!dbpath || !dbpath[0]) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: no database path specified");
    return -1;
  }

  rc = mdb_env_create(&webpush_env);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: mdb_env_create: %s", mdb_strerror(rc));
    return -1;
  }

  rc = mdb_env_set_maxdbs(webpush_env, WEBPUSH_MAX_DBS);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: mdb_env_set_maxdbs: %s", mdb_strerror(rc));
    goto fail;
  }

  rc = mdb_env_set_mapsize(webpush_env, WEBPUSH_MAP_SIZE);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: mdb_env_set_mapsize: %s", mdb_strerror(rc));
    goto fail;
  }

  rc = mdb_env_open(webpush_env, dbpath, 0, 0644);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: mdb_env_open(%s): %s", dbpath, mdb_strerror(rc));
    goto fail;
  }

  /* Open named databases */
  rc = mdb_txn_begin(webpush_env, NULL, 0, &txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: mdb_txn_begin: %s", mdb_strerror(rc));
    goto fail;
  }

  rc = mdb_dbi_open(txn, "subscriptions", MDB_CREATE, &webpush_sub_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: open subscriptions DBI: %s", mdb_strerror(rc));
    mdb_txn_abort(txn);
    goto fail;
  }

  rc = mdb_dbi_open(txn, "config", MDB_CREATE, &webpush_cfg_dbi);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: open config DBI: %s", mdb_strerror(rc));
    mdb_txn_abort(txn);
    goto fail;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: mdb_txn_commit: %s", mdb_strerror(rc));
    goto fail;
  }

  webpush_db_available = 1;
  log_write(LS_SYSTEM, L_INFO, 0,
            "WebPush store: LMDB initialized at %s", dbpath);
  return 0;

fail:
  mdb_env_close(webpush_env);
  webpush_env = NULL;
  return -1;
}

void webpush_store_shutdown(void)
{
  if (!webpush_db_available)
    return;

  mdb_dbi_close(webpush_env, webpush_sub_dbi);
  mdb_dbi_close(webpush_env, webpush_cfg_dbi);
  mdb_env_close(webpush_env);
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
  MDB_txn *txn;
  MDB_val mkey, mval;
  char keybuf[WEBPUSH_KEY_MAX];
  int keylen;
  const char *endpoint_end;
  char endpoint[512];
  size_t elen;
  int rc;

  if (!webpush_db_available || !account || !stored)
    return -1;

  /* Extract endpoint from stored format for key hashing */
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

  rc = mdb_txn_begin(webpush_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = keybuf;
  mkey.mv_size = (size_t)keylen;
  mval.mv_data = (void *)stored;
  mval.mv_size = strlen(stored);

  rc = mdb_put(txn, webpush_sub_dbi, &mkey, &mval, 0);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: add failed for %s: %s", account, mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
}

int webpush_store_remove(const char *account, const char *endpoint)
{
  MDB_txn *txn;
  MDB_val mkey;
  char keybuf[WEBPUSH_KEY_MAX];
  int keylen;
  int rc;

  if (!webpush_db_available || !account || !endpoint)
    return -1;

  keylen = build_sub_key(keybuf, sizeof(keybuf), account, endpoint);
  if (keylen < 0)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = keybuf;
  mkey.mv_size = (size_t)keylen;

  rc = mdb_del(txn, webpush_sub_dbi, &mkey, NULL);
  if (rc == MDB_NOTFOUND)
    rc = 0;  /* not found is fine */

  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: remove failed for %s: %s",
              account, mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  return (rc == 0) ? 0 : -1;
}

int webpush_store_clear(const char *account)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mval;
  char prefix[WEBPUSH_KEY_MAX];
  int prefix_len;
  int count = 0;
  int rc;

  if (!webpush_db_available || !account)
    return -1;

  prefix_len = build_prefix_key(prefix, sizeof(prefix), account);
  if (prefix_len < 0)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, webpush_sub_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Position at first key >= prefix */
  mkey.mv_data = prefix;
  mkey.mv_size = (size_t)prefix_len;

  rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_SET_RANGE);
  while (rc == 0) {
    /* Check if key still starts with our prefix */
    if (mkey.mv_size < (size_t)prefix_len ||
        memcmp(mkey.mv_data, prefix, (size_t)prefix_len) != 0)
      break;

    mdb_cursor_del(cursor, 0);
    count++;

    rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_NEXT);
  }

  mdb_cursor_close(cursor);

  rc = mdb_txn_commit(txn);
  if (rc != 0)
    return -1;

  return count;
}

int webpush_store_count(const char *account)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mval;
  char prefix[WEBPUSH_KEY_MAX];
  int prefix_len;
  int count = 0;
  int rc;

  if (!webpush_db_available || !account)
    return -1;

  prefix_len = build_prefix_key(prefix, sizeof(prefix), account);
  if (prefix_len < 0)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, webpush_sub_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  mkey.mv_data = prefix;
  mkey.mv_size = (size_t)prefix_len;

  rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_SET_RANGE);
  while (rc == 0) {
    if (mkey.mv_size < (size_t)prefix_len ||
        memcmp(mkey.mv_data, prefix, (size_t)prefix_len) != 0)
      break;

    count++;
    rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  return count;
}

int webpush_store_foreach(const char *account, webpush_store_iter_cb cb,
                          void *data)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mval;
  char prefix[WEBPUSH_KEY_MAX];
  int prefix_len;
  int count = 0;
  int rc;

  if (!webpush_db_available || !account || !cb)
    return -1;

  prefix_len = build_prefix_key(prefix, sizeof(prefix), account);
  if (prefix_len < 0)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, webpush_sub_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  mkey.mv_data = prefix;
  mkey.mv_size = (size_t)prefix_len;

  rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_SET_RANGE);
  while (rc == 0) {
    if (mkey.mv_size < (size_t)prefix_len ||
        memcmp(mkey.mv_data, prefix, (size_t)prefix_len) != 0)
      break;

    /* mval.mv_data is the stored subscription string (not NUL-terminated) */
    {
      char stored[4096];
      size_t slen = mval.mv_size;
      if (slen >= sizeof(stored))
        slen = sizeof(stored) - 1;
      memcpy(stored, mval.mv_data, slen);
      stored[slen] = '\0';

      if (cb(stored, data) != 0)
        break;
    }

    count++;
    rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  return count;
}

int webpush_store_foreach_all(webpush_store_iter_all_cb cb, void *data)
{
  MDB_txn *txn;
  MDB_cursor *cursor;
  MDB_val mkey, mval;
  int count = 0;
  int rc;

  if (!webpush_db_available || !cb)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_cursor_open(txn, webpush_sub_dbi, &cursor);
  if (rc != 0) {
    mdb_txn_abort(txn);
    return -1;
  }

  /* Iterate all entries in the subscriptions database */
  rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_FIRST);
  while (rc == 0) {
    /*
     * Key format: account\0<hash_hex>
     * The account name is the portion before the embedded NUL byte.
     * We can pass mkey.mv_data directly as the account string since
     * it starts with the account name followed by a NUL separator.
     */
    const char *account = (const char *)mkey.mv_data;

    /* Safety: verify there's a NUL within the key (separating account from hash) */
    size_t acct_len = strnlen(account, mkey.mv_size);
    if (acct_len < mkey.mv_size) {
      /* Valid key format — extract stored value */
      char stored[4096];
      size_t slen = mval.mv_size;
      if (slen >= sizeof(stored))
        slen = sizeof(stored) - 1;
      memcpy(stored, mval.mv_data, slen);
      stored[slen] = '\0';

      if (cb(account, stored, data) != 0)
        break;

      count++;
    }

    rc = mdb_cursor_get(cursor, &mkey, &mval, MDB_NEXT);
  }

  mdb_cursor_close(cursor);
  mdb_txn_abort(txn);

  return count;
}

/* ---------------------------------------------------------------------------
 * VAPID key persistence
 * ---------------------------------------------------------------------------*/

static const char vapid_key_name[] = "vapid_privkey";

int webpush_store_set_vapid_key(const unsigned char *privkey, size_t privkey_len)
{
  MDB_txn *txn;
  MDB_val mkey, mval;
  int rc;

  if (!webpush_db_available || !privkey || privkey_len != 32)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, 0, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = (void *)vapid_key_name;
  mkey.mv_size = sizeof(vapid_key_name) - 1;
  mval.mv_data = (void *)privkey;
  mval.mv_size = privkey_len;

  rc = mdb_put(txn, webpush_cfg_dbi, &mkey, &mval, 0);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: set VAPID key failed: %s", mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  rc = mdb_txn_commit(txn);
  if (rc != 0)
    return -1;

  log_write(LS_SYSTEM, L_INFO, 0, "WebPush store: VAPID key persisted");
  return 0;
}

int webpush_store_get_vapid_key(unsigned char *privkey, size_t *privkey_len)
{
  MDB_txn *txn;
  MDB_val mkey, mval;
  int rc;

  if (!webpush_db_available || !privkey || !privkey_len || *privkey_len < 32)
    return -1;

  rc = mdb_txn_begin(webpush_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  mkey.mv_data = (void *)vapid_key_name;
  mkey.mv_size = sizeof(vapid_key_name) - 1;

  rc = mdb_get(txn, webpush_cfg_dbi, &mkey, &mval);
  if (rc == MDB_NOTFOUND) {
    mdb_txn_abort(txn);
    return -1;  /* no key stored */
  }
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: get VAPID key failed: %s", mdb_strerror(rc));
    mdb_txn_abort(txn);
    return -1;
  }

  if (mval.mv_size != 32) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush store: stored VAPID key has wrong size (%zu)",
              mval.mv_size);
    mdb_txn_abort(txn);
    return -1;
  }

  memcpy(privkey, mval.mv_data, 32);
  *privkey_len = 32;
  mdb_txn_abort(txn);

  return 0;
}

/* ---------------------------------------------------------------------------
 * Statistics
 * ---------------------------------------------------------------------------*/

int webpush_store_get_stats(struct webpush_store_stats *stats)
{
  MDB_txn *txn;
  MDB_stat mst;
  MDB_envinfo mei;
  int rc;

  if (!webpush_db_available || !stats)
    return -1;

  memset(stats, 0, sizeof(*stats));

  rc = mdb_txn_begin(webpush_env, NULL, MDB_RDONLY, &txn);
  if (rc != 0)
    return -1;

  rc = mdb_stat(txn, webpush_sub_dbi, &mst);
  if (rc == 0) {
    stats->total_subscriptions = (unsigned long)mst.ms_entries;
  }

  mdb_txn_abort(txn);

  rc = mdb_env_info(webpush_env, &mei);
  if (rc == 0) {
    stats->db_size_bytes = (unsigned long)mei.me_mapsize;
  }

  /* total_accounts requires a full scan — skip for now */
  return 0;
}

#else /* !USE_LMDB */

/* Stub implementations when LMDB is not available */
#include "webpush_store.h"

int webpush_store_init(const char *dbpath)
{
  (void)dbpath;
  return -1;
}

void webpush_store_shutdown(void) {}
int webpush_store_available(void) { return 0; }

int webpush_store_add(const char *account, const char *stored)
{
  (void)account; (void)stored;
  return -1;
}

int webpush_store_remove(const char *account, const char *endpoint)
{
  (void)account; (void)endpoint;
  return -1;
}

int webpush_store_clear(const char *account)
{
  (void)account;
  return -1;
}

int webpush_store_count(const char *account)
{
  (void)account;
  return -1;
}

int webpush_store_foreach(const char *account, webpush_store_iter_cb cb,
                          void *data)
{
  (void)account; (void)cb; (void)data;
  return -1;
}

int webpush_store_foreach_all(webpush_store_iter_all_cb cb, void *data)
{
  (void)cb; (void)data;
  return -1;
}

int webpush_store_set_vapid_key(const unsigned char *privkey, size_t privkey_len)
{
  (void)privkey; (void)privkey_len;
  return -1;
}

int webpush_store_get_vapid_key(unsigned char *privkey, size_t *privkey_len)
{
  (void)privkey; (void)privkey_len;
  return -1;
}

int webpush_store_get_stats(struct webpush_store_stats *stats)
{
  (void)stats;
  return -1;
}

#endif /* USE_LMDB */
