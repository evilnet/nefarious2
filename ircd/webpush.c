/*
 * webpush.c - Web Push notification crypto and delivery for Nefarious
 *
 * Implements RFC 8291 (Message Encryption for Web Push) and
 * RFC 8292 (VAPID - Voluntary Application Server Identification).
 *
 * Uses OpenSSL 3.x EVP API for all cryptographic operations and
 * libkc's kc_http_request() for async HTTP delivery.
 */

#include "config.h"

/* Keys, encryption and VAPID signing need only OpenSSL; the HTTP delivery
 * needs libkc.  A build (or a boot) without libkc must still hold keys
 * and advertise the VAPID token -- that is what clients register
 * against -- so only the delivery path is gated on USE_LIBKC. */
#ifdef USE_SSL

#include "webpush.h"
#include "webpush_keyring.h"
#include "ircd_log.h"
#ifdef USE_LIBKC
#include "ircd_kc_adapter.h"
#include <kc/kc.h>
#include <kc/kc_http.h>
#endif

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

#ifdef USE_LIBKC
#include <curl/curl.h>   /* curl_slist */
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* ---------------------------------------------------------------------------
 * VAPID key table
 *
 * Every key of the ring (webpush_keyring.h) this server can sign with is
 * loaded here as an EVP_PKEY, keyed by its id (the base64url public key).
 * `wp_current` is the key advertised to clients and used for subscriptions
 * that carry no key id; delivery signs with the key a subscription is
 * bound to (webpush_send_async), which is how retired keys keep serving
 * the subscriptions registered under them.
 * ---------------------------------------------------------------------------*/

struct wp_key {
  char      id[WEBPUSH_KEY_ID_LEN + 1];
  EVP_PKEY *pkey;
};

static struct wp_key  wp_keys[WEBPUSH_KEYRING_MAX];
static int            wp_key_count = 0;
static struct wp_key *wp_current = NULL;

/* ---------------------------------------------------------------------------
 * Base64url encode / decode  (RFC 4648 Section 5)
 * ---------------------------------------------------------------------------*/

/** Encode binary data to base64url (no padding).
 *  Returns length of output string, or -1 on error. */
static int base64url_encode(const unsigned char *in, size_t in_len,
                            char *out, size_t out_size)
{
  int std_len;
  size_t i, j;

  /* EVP_EncodeBlock produces standard base64 with padding. */
  /* Output length for standard base64: 4 * ceil(in_len/3) + 1 (NUL) */
  size_t needed = ((in_len + 2) / 3) * 4 + 1;
  if (out_size < needed)
    return -1;

  std_len = EVP_EncodeBlock((unsigned char *)out, in, (int)in_len);
  if (std_len < 0)
    return -1;

  /* Replace +/ with -_, strip trailing = */
  j = 0;
  for (i = 0; i < (size_t)std_len; i++) {
    if (out[i] == '+')
      out[j++] = '-';
    else if (out[i] == '/')
      out[j++] = '_';
    else if (out[i] == '=')
      continue;  /* strip padding */
    else
      out[j++] = out[i];
  }
  out[j] = '\0';
  return (int)j;
}

/** Decode base64url string to binary.
 *  Returns 0 on success, -1 on error. */
static int base64url_decode(const char *in, size_t in_len,
                            unsigned char *out, size_t out_size,
                            size_t *out_len)
{
  char *std_buf = NULL;
  unsigned char *scratch = NULL;
  size_t padded_len, exact_len, i;
  int decoded_len;

  /* Calculate padded length (base64 must be multiple of 4) */
  padded_len = in_len;
  switch (in_len % 4) {
    case 2: padded_len += 2; break;
    case 3: padded_len += 1; break;
    case 0: break;
    default: return -1;  /* invalid base64url length */
  }

  /* Exact decoded length (padding excluded): 87 b64url chars -> 65 bytes,
   * 22 -> 16.  EVP_DecodeBlock always returns whole 4-char blocks (66 and
   * 18 here), so the caller's exact-sized buffer (65/16) is smaller than
   * the padded block size even though the real output fits.  Reject short
   * buffers up front; the decode below always goes through a block-sized
   * scratch buffer. */
  exact_len = (padded_len / 4) * 3 - (padded_len - in_len);
  if (out_size < exact_len)
    return -1;

  std_buf = (char *)malloc(padded_len + 1);
  if (!std_buf)
    return -1;

  /* Replace -_ with +/ */
  for (i = 0; i < in_len; i++) {
    if (in[i] == '-')
      std_buf[i] = '+';
    else if (in[i] == '_')
      std_buf[i] = '/';
    else
      std_buf[i] = in[i];
  }

  /* Add padding */
  for (; i < padded_len; i++)
    std_buf[i] = '=';
  std_buf[padded_len] = '\0';

  /* Decode — EVP_DecodeBlock returns decoded length, ignoring padding.
   * It may include up to 2 extra zero bytes for padding chars, so decode
   * into a scratch buffer sized for the whole block and copy the exact
   * length out. */
  scratch = (unsigned char *)malloc((padded_len / 4) * 3);
  if (!scratch) {
    free(std_buf);
    return -1;
  }
  decoded_len = EVP_DecodeBlock(scratch, (const unsigned char *)std_buf,
                                (int)padded_len);
  free(std_buf);
  if (decoded_len < 0) {
    free(scratch);
    return -1;
  }
  memcpy(out, scratch, exact_len);
  free(scratch);

  /* Subtract padding bytes from decoded length */
  if (padded_len > in_len)
    decoded_len -= (int)(padded_len - in_len);

  if (out_len)
    *out_len = (size_t)decoded_len;
  return 0;
}

/* ---------------------------------------------------------------------------
 * HKDF-SHA256
 * ---------------------------------------------------------------------------*/

static int hkdf_sha256(const unsigned char *salt, size_t salt_len,
                       const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *okm, size_t okm_len)
{
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *kctx = NULL;
  OSSL_PARAM params[5];
  int ret = -1;

  kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
  if (!kdf)
    goto cleanup;

  kctx = EVP_KDF_CTX_new(kdf);
  if (!kctx)
    goto cleanup;

  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                 "SHA256", 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                  (void *)salt, salt_len);
  params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                  (void *)ikm, ikm_len);
  params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                  (void *)info, info_len);
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(kctx, okm, okm_len, params) <= 0)
    goto cleanup;

  ret = 0;

cleanup:
  EVP_KDF_CTX_free(kctx);
  EVP_KDF_free(kdf);
  return ret;
}

/* ---------------------------------------------------------------------------
 * VAPID key management
 * ---------------------------------------------------------------------------*/

static struct wp_key *wp_key_find(const char *id)
{
  int i;
  if (!id || !id[0])
    return NULL;
  for (i = 0; i < wp_key_count; i++)
    if (0 == strcmp(wp_keys[i].id, id))
      return &wp_keys[i];
  return NULL;
}

/** Build a P-256 keypair from a 32-byte private scalar (the public point
 * is derived: EVP_PKEY_fromdata() does not compute it in OpenSSL 3.x) and
 * write the base64url public key -- the key's id -- into @a id_out.
 * Returns the key or NULL. */
static EVP_PKEY *wp_pkey_from_priv(const unsigned char *privkey, size_t privkey_len,
                                   char *id_out, size_t id_sz)
{
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY *ret = NULL;
  BIGNUM *priv_bn = NULL;
  unsigned char pub[65];
  size_t pub_len = 0;

  if (!privkey || privkey_len != 32 || !id_out || id_sz < WEBPUSH_KEY_ID_LEN + 1) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: key load requires a 32-byte private key");
    return NULL;
  }

  priv_bn = BN_bin2bn(privkey, (int)privkey_len, NULL);
  if (!priv_bn)
    goto cleanup;

  {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pub_point = NULL;
    if (group) {
      pub_point = EC_POINT_new(group);
      if (pub_point &&
          EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        pub_len = EC_POINT_point2oct(group, pub_point,
                                     POINT_CONVERSION_UNCOMPRESSED,
                                     pub, sizeof(pub), NULL);
      }
      EC_POINT_free(pub_point);
      EC_GROUP_free(group);
    }
    if (pub_len != 65) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "WebPush: failed to derive public key from private key");
      goto cleanup;
    }
  }

  bld = OSSL_PARAM_BLD_new();
  if (!bld)
    goto cleanup;
  if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0))
    goto cleanup;
  if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn))
    goto cleanup;
  if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len))
    goto cleanup;
  params = OSSL_PARAM_BLD_to_param(bld);
  if (!params)
    goto cleanup;
  pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!pctx)
    goto cleanup;
  if (EVP_PKEY_fromdata_init(pctx) <= 0)
    goto cleanup;
  if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params) <= 0)
    goto cleanup;

  if (base64url_encode(pub, pub_len, id_out, id_sz) < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: failed to base64url-encode public key");
    goto cleanup;
  }

  ret = pkey;
  pkey = NULL;

cleanup:
  BN_clear_free(priv_bn);
  OSSL_PARAM_BLD_free(bld);
  OSSL_PARAM_free(params);
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(pkey);
  return ret;
}

int webpush_key_load(const unsigned char *privkey, size_t privkey_len,
                     const char *expect_id, char *id_out, size_t id_sz)
{
  char id[WEBPUSH_KEY_ID_LEN + 1];
  EVP_PKEY *pkey;
  struct wp_key *k;

  pkey = wp_pkey_from_priv(privkey, privkey_len, id, sizeof(id));
  if (!pkey)
    return -1;

  /* A stored or wire record names the key it claims to carry; a private
   * scalar that derives a different public key is corrupt, and signing
   * with it would only earn 403s from the push service. */
  if (expect_id && expect_id[0] && 0 != strcmp(expect_id, id)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: private key does not match its id %.16s... (derives %.16s...)",
              expect_id, id);
    EVP_PKEY_free(pkey);
    return -2;
  }

  k = wp_key_find(id);
  if (k) {
    EVP_PKEY_free(k->pkey);
    k->pkey = pkey;
  } else {
    if (wp_key_count >= WEBPUSH_KEYRING_MAX) {
      log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: key table full");
      EVP_PKEY_free(pkey);
      return -1;
    }
    k = &wp_keys[wp_key_count++];
    memcpy(k->id, id, sizeof(k->id));
    k->pkey = pkey;
  }

  if (id_out && id_sz > 0) {
    strncpy(id_out, id, id_sz - 1);
    id_out[id_sz - 1] = '\0';
  }
  return 0;
}

void webpush_key_unload(const char *id)
{
  struct wp_key *k = wp_key_find(id);
  int idx;

  if (!k)
    return;
  EVP_PKEY_free(k->pkey);
  if (wp_current == k)
    wp_current = NULL;
  idx = (int)(k - wp_keys);
  if (idx != wp_key_count - 1) {
    wp_keys[idx] = wp_keys[wp_key_count - 1];
    if (wp_current == &wp_keys[wp_key_count - 1])
      wp_current = &wp_keys[idx];
  }
  memset(&wp_keys[wp_key_count - 1], 0, sizeof(wp_keys[0]));
  wp_key_count--;
}

int webpush_key_loaded(const char *id)
{
  return wp_key_find(id) != NULL;
}

int webpush_key_generate(unsigned char *priv_out, size_t *priv_len,
                         char *id_out, size_t id_sz)
{
  EVP_PKEY *gen;
  BIGNUM *priv_bn = NULL;
  int bn_len;
  int rc;

  if (!priv_out || !priv_len || *priv_len < 32)
    return -1;

  gen = EVP_EC_gen("P-256");
  if (!gen) {
    log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: failed to generate P-256 key");
    return -1;
  }
  if (!EVP_PKEY_get_bn_param(gen, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn)) {
    EVP_PKEY_free(gen);
    return -1;
  }
  bn_len = BN_bn2binpad(priv_bn, priv_out, 32);
  BN_clear_free(priv_bn);
  EVP_PKEY_free(gen);
  if (bn_len != 32)
    return -1;
  *priv_len = 32;

  /* Load through the same path a stored key takes, so the id is derived
   * exactly as it will be on every reload. */
  rc = webpush_key_load(priv_out, 32, NULL, id_out, id_sz);
  if (rc != 0)
    OPENSSL_cleanse(priv_out, 32);
  return rc == 0 ? 0 : -1;
}

int webpush_set_current_key(const char *id)
{
  struct wp_key *k;

  if (!id || !id[0]) {
    wp_current = NULL;
    return 0;
  }
  k = wp_key_find(id);
  if (!k)
    return -1;
  wp_current = k;
  return 0;
}

const char *webpush_get_vapid_pubkey(void)
{
  return wp_current ? wp_current->id : NULL;
}

void webpush_cleanup(void)
{
  int i;
  for (i = 0; i < wp_key_count; i++)
    EVP_PKEY_free(wp_keys[i].pkey);
  OPENSSL_cleanse(wp_keys, sizeof(wp_keys));
  wp_key_count = 0;
  wp_current = NULL;
}

/* ---------------------------------------------------------------------------
 * RFC 8291: Web Push message encryption (aes128gcm)
 * ---------------------------------------------------------------------------*/

int webpush_encrypt(const struct webpush_subscription *sub,
                    const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *out, size_t *out_len)
{
  unsigned char salt[16];
  EVP_PKEY *ephemeral_key = NULL;
  EVP_PKEY *client_key = NULL;
  EVP_PKEY_CTX *derive_ctx = NULL;
  EVP_PKEY_CTX *client_ctx = NULL;
  EVP_CIPHER_CTX *cipher_ctx = NULL;
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;

  unsigned char ephemeral_pub[65];
  size_t ephemeral_pub_len = 0;
  unsigned char ecdh_secret[32];
  size_t ecdh_secret_len = 0;

  /* RFC 8291 key derivation intermediates */
  unsigned char auth_info[144];   /* "WebPush: info\0" (14) + ua_pub(65) + as_pub(65) */
  unsigned char ikm[32];
  unsigned char cek[16];
  unsigned char nonce[12];

  /* aes128gcm content encoding info strings.  The implicit NUL of the C
   * string literal IS the 0x00 byte RFC 8291 appends to the info, so
   * sizeof() gives exactly the right length (28 / 24).  An extra explicit
   * "\0" would make the literal one byte longer and silently derive a
   * CEK/nonce the browser cannot reproduce (cryptography is exact here:
   * pushes would decrypt nowhere while FCM still accepts them). */
  static const unsigned char cek_info[] = "Content-Encoding: aes128gcm";
  static const unsigned char nonce_info[] = "Content-Encoding: nonce";

  /* Padded plaintext: content || 0x02 */
  unsigned char *padded = NULL;
  size_t padded_len;

  /* Encryption output */
  unsigned char *ciphertext = NULL;
  int ct_len = 0, final_len = 0;
  unsigned char tag[16];

  /* aes128gcm header: salt(16) + rs(4) + idlen(1) + keyid(65) = 86 bytes */
  size_t header_len = 86;
  size_t total_len;
  uint32_t rs = 4096;

  int ret = -1;

  /* ---- Validate inputs ---- */
  if (!sub || !plaintext || plaintext_len == 0 || !out || !out_len) {
    log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: encrypt: invalid arguments");
    return -1;
  }
  if (plaintext_len > WEBPUSH_MAX_PAYLOAD) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: payload too large (%zu > %d)",
              plaintext_len, WEBPUSH_MAX_PAYLOAD);
    return -1;
  }
  if (sub->p256dh_len != 65 || sub->p256dh[0] != 0x04) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: invalid client public key");
    return -1;
  }
  if (sub->auth_len != 16) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: invalid auth secret length (%zu)",
              sub->auth_len);
    return -1;
  }

  /* ---- Step 1: Generate 16-byte random salt ---- */
  if (RAND_bytes(salt, sizeof(salt)) != 1)
    goto cleanup;

  /* ---- Step 2: Generate ephemeral P-256 keypair ---- */
  ephemeral_key = EVP_EC_gen("P-256");
  if (!ephemeral_key) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: failed to generate ephemeral key");
    goto cleanup;
  }

  /* ---- Step 3: Extract ephemeral public key (uncompressed, 65 bytes) ---- */
  ephemeral_pub_len = sizeof(ephemeral_pub);
  if (!EVP_PKEY_get_octet_string_param(ephemeral_key, OSSL_PKEY_PARAM_PUB_KEY,
                                        ephemeral_pub, sizeof(ephemeral_pub),
                                        &ephemeral_pub_len)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: failed to extract ephemeral public key");
    goto cleanup;
  }

  /* ---- Step 4: Import client P-256 public key from subscription ---- */
  bld = OSSL_PARAM_BLD_new();
  if (!bld)
    goto cleanup;

  if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "P-256", 0))
    goto cleanup;
  if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         sub->p256dh, sub->p256dh_len))
    goto cleanup;

  params = OSSL_PARAM_BLD_to_param(bld);
  if (!params)
    goto cleanup;

  client_ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
  if (!client_ctx)
    goto cleanup;
  if (EVP_PKEY_fromdata_init(client_ctx) <= 0)
    goto cleanup;
  if (EVP_PKEY_fromdata(client_ctx, &client_key, EVP_PKEY_PUBLIC_KEY,
                         params) <= 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: failed to import client public key");
    goto cleanup;
  }

  /* ---- Step 5: ECDH — derive shared secret ---- */
  derive_ctx = EVP_PKEY_CTX_new(ephemeral_key, NULL);
  if (!derive_ctx)
    goto cleanup;
  if (EVP_PKEY_derive_init(derive_ctx) <= 0)
    goto cleanup;
  if (EVP_PKEY_derive_set_peer(derive_ctx, client_key) <= 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: ECDH set peer failed");
    goto cleanup;
  }

  /* Get required buffer size */
  if (EVP_PKEY_derive(derive_ctx, NULL, &ecdh_secret_len) <= 0)
    goto cleanup;
  if (ecdh_secret_len > sizeof(ecdh_secret))
    goto cleanup;

  if (EVP_PKEY_derive(derive_ctx, ecdh_secret, &ecdh_secret_len) <= 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: ECDH derivation failed");
    goto cleanup;
  }

  /* ---- Step 6: RFC 8291 key derivation ---- */

  /* auth_info = "WebPush: info\0" || ua_public(65) || as_public(65) */
  memcpy(auth_info, "WebPush: info", 13);
  auth_info[13] = '\0';
  memcpy(auth_info + 14, sub->p256dh, 65);     /* ua_public (client) */
  memcpy(auth_info + 14 + 65, ephemeral_pub, 65); /* as_public (server/ephemeral) */

  /* ikm = HKDF(salt=auth_secret, ikm=ecdh_secret, info=auth_info, L=32) */
  if (hkdf_sha256(sub->auth, sub->auth_len,
                   ecdh_secret, ecdh_secret_len,
                   auth_info, sizeof(auth_info),
                   ikm, sizeof(ikm)) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: HKDF for IKM failed");
    goto cleanup;
  }

  /* CEK = HKDF(salt=salt, ikm=ikm, info="Content-Encoding: aes128gcm\0", L=16) */
  if (hkdf_sha256(salt, sizeof(salt),
                   ikm, sizeof(ikm),
                   cek_info, sizeof(cek_info),
                   cek, sizeof(cek)) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: HKDF for CEK failed");
    goto cleanup;
  }

  /* nonce = HKDF(salt=salt, ikm=ikm, info="Content-Encoding: nonce\0", L=12) */
  if (hkdf_sha256(salt, sizeof(salt),
                   ikm, sizeof(ikm),
                   nonce_info, sizeof(nonce_info),
                   nonce, sizeof(nonce)) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: HKDF for nonce failed");
    goto cleanup;
  }

  /* ---- Step 7: Pad plaintext (single record) ---- */
  /* Record content: plaintext || 0x02 (final record delimiter) */
  padded_len = plaintext_len + 1;
  padded = (unsigned char *)malloc(padded_len);
  if (!padded)
    goto cleanup;
  memcpy(padded, plaintext, plaintext_len);
  padded[plaintext_len] = 0x02;  /* final record delimiter */

  /* ---- Step 8: AES-128-GCM encryption ---- */
  ciphertext = (unsigned char *)malloc(padded_len + 16); /* room for tag */
  if (!ciphertext)
    goto cleanup;

  cipher_ctx = EVP_CIPHER_CTX_new();
  if (!cipher_ctx)
    goto cleanup;

  if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
    goto cleanup;

  /* Set IV length to 12 bytes */
  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
    goto cleanup;

  if (EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, cek, nonce) != 1)
    goto cleanup;

  if (EVP_EncryptUpdate(cipher_ctx, ciphertext, &ct_len,
                         padded, (int)padded_len) != 1)
    goto cleanup;

  if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext + ct_len, &final_len) != 1)
    goto cleanup;
  ct_len += final_len;

  /* Get authentication tag (16 bytes) */
  if (EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    goto cleanup;

  /* ---- Step 9: Build aes128gcm output envelope ---- */
  /* Format: salt(16) || rs(4, big-endian) || idlen(1) || keyid(65) || ciphertext || tag(16) */
  total_len = header_len + (size_t)ct_len + 16;
  if (total_len > WEBPUSH_ENCRYPTED_MAX) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: encrypt: output too large (%zu > %d)",
              total_len, WEBPUSH_ENCRYPTED_MAX);
    goto cleanup;
  }

  {
    unsigned char *p = out;

    /* Salt (16 bytes) */
    memcpy(p, salt, 16);
    p += 16;

    /* Record size (4 bytes, big-endian) */
    p[0] = (unsigned char)((rs >> 24) & 0xFF);
    p[1] = (unsigned char)((rs >> 16) & 0xFF);
    p[2] = (unsigned char)((rs >> 8)  & 0xFF);
    p[3] = (unsigned char)( rs        & 0xFF);
    p += 4;

    /* Key ID length (1 byte) */
    *p++ = (unsigned char)ephemeral_pub_len;

    /* Key ID = ephemeral public key (65 bytes) */
    memcpy(p, ephemeral_pub, ephemeral_pub_len);
    p += ephemeral_pub_len;

    /* Ciphertext */
    memcpy(p, ciphertext, (size_t)ct_len);
    p += ct_len;

    /* Authentication tag (16 bytes) */
    memcpy(p, tag, 16);
    p += 16;

    *out_len = (size_t)(p - out);
  }

  ret = 0;

cleanup:
  /* Cleanse sensitive intermediates */
  OPENSSL_cleanse(ecdh_secret, sizeof(ecdh_secret));
  OPENSSL_cleanse(ikm, sizeof(ikm));
  OPENSSL_cleanse(cek, sizeof(cek));
  OPENSSL_cleanse(nonce, sizeof(nonce));

  free(padded);
  free(ciphertext);
  EVP_PKEY_free(ephemeral_key);
  EVP_PKEY_free(client_key);
  EVP_PKEY_CTX_free(derive_ctx);
  EVP_PKEY_CTX_free(client_ctx);
  EVP_CIPHER_CTX_free(cipher_ctx);
  OSSL_PARAM_BLD_free(bld);
  OSSL_PARAM_free(params);

  return ret;
}

/* ---------------------------------------------------------------------------
 * VAPID JWT creation (RFC 8292)
 * ---------------------------------------------------------------------------*/

/** Build VAPID Authorization header value.
 *  Format: vapid t=<JWT>, k=<pubkey_b64>
 *  Returns 0 on success, -1 on error. */
static int create_vapid_header(const char *endpoint, const struct wp_key *key,
                               char *out, size_t out_size)
{
  /* JWT parts */
  char header_b64[64];
  char payload_b64[512];
  char signature_b64[128];
  char signing_input[640];

  /* Audience extraction */
  char audience[256];
  const char *scheme_end;
  const char *host_end;
  size_t aud_len;

  /* Signing */
  EVP_MD_CTX *mdctx = NULL;
  unsigned char *der_sig = NULL;
  size_t der_sig_len = 0;
  ECDSA_SIG *ecdsa_sig = NULL;
  const BIGNUM *sig_r = NULL;
  const BIGNUM *sig_s = NULL;
  unsigned char raw_sig[64];

  /* JWT payload */
  char payload_json[384];
  time_t now;
  int len;

  int ret = -1;

  if (!endpoint || !out || !key || !key->pkey)
    return -1;

  /* ---- Extract audience (origin) from endpoint URL ---- */
  /* Expects https://host[:port]/... */
  scheme_end = strstr(endpoint, "://");
  if (!scheme_end)
    return -1;
  scheme_end += 3;  /* skip "://" */

  /* Find end of host[:port] */
  host_end = strchr(scheme_end, '/');
  if (!host_end)
    host_end = scheme_end + strlen(scheme_end);

  aud_len = (size_t)(host_end - endpoint);
  if (aud_len >= sizeof(audience))
    return -1;
  memcpy(audience, endpoint, aud_len);
  audience[aud_len] = '\0';

  /* ---- JWT header: {"typ":"JWT","alg":"ES256"} ---- */
  {
    static const char jwt_header[] = "{\"typ\":\"JWT\",\"alg\":\"ES256\"}";
    len = base64url_encode((const unsigned char *)jwt_header,
                           strlen(jwt_header),
                           header_b64, sizeof(header_b64));
    if (len < 0)
      goto cleanup;
  }

  /* ---- JWT payload ---- */
  now = time(NULL);
  snprintf(payload_json, sizeof(payload_json),
           "{\"aud\":\"%s\",\"exp\":%lu,\"sub\":\"mailto:noreply@afternet.org\"}",
           audience, (unsigned long)(now + 86400));

  len = base64url_encode((const unsigned char *)payload_json,
                         strlen(payload_json),
                         payload_b64, sizeof(payload_b64));
  if (len < 0)
    goto cleanup;

  /* ---- Build signing input: header.payload ---- */
  snprintf(signing_input, sizeof(signing_input), "%s.%s",
           header_b64, payload_b64);

  /* ---- Sign with ECDSA-SHA256 using VAPID key ---- */
  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    goto cleanup;

  if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key->pkey) != 1)
    goto cleanup;

  if (EVP_DigestSign(mdctx, NULL, &der_sig_len,
                     (const unsigned char *)signing_input,
                     strlen(signing_input)) != 1)
    goto cleanup;

  der_sig = (unsigned char *)OPENSSL_malloc(der_sig_len);
  if (!der_sig)
    goto cleanup;

  if (EVP_DigestSign(mdctx, der_sig, &der_sig_len,
                     (const unsigned char *)signing_input,
                     strlen(signing_input)) != 1)
    goto cleanup;

  /* ---- Convert DER signature to raw r||s (64 bytes) for ES256 JWT ---- */
  {
    const unsigned char *p = der_sig;
    ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, (long)der_sig_len);
    if (!ecdsa_sig)
      goto cleanup;
  }

  ECDSA_SIG_get0(ecdsa_sig, &sig_r, &sig_s);
  if (!sig_r || !sig_s)
    goto cleanup;

  if (BN_bn2binpad(sig_r, raw_sig, 32) != 32)
    goto cleanup;
  if (BN_bn2binpad(sig_s, raw_sig + 32, 32) != 32)
    goto cleanup;

  len = base64url_encode(raw_sig, 64, signature_b64, sizeof(signature_b64));
  if (len < 0)
    goto cleanup;

  /* ---- Build output: vapid t=<header>.<payload>.<signature>, k=<pubkey> ---- */
  snprintf(out, out_size, "vapid t=%s.%s.%s, k=%s",
           header_b64, payload_b64, signature_b64, key->id);

  ret = 0;

cleanup:
  EVP_MD_CTX_free(mdctx);
  if (der_sig)
    OPENSSL_free(der_sig);
  ECDSA_SIG_free(ecdsa_sig);
  OPENSSL_cleanse(raw_sig, sizeof(raw_sig));
  return ret;
}

/* ---------------------------------------------------------------------------
 * Async HTTP delivery
 * ---------------------------------------------------------------------------*/

#ifdef USE_LIBKC

struct webpush_send_ctx {
  webpush_send_cb cb;
  void *cb_data;
};

static void webpush_http_callback(struct kc_http_response *resp, void *data)
{
  struct webpush_send_ctx *ctx = (struct webpush_send_ctx *)data;
  int result;
  long status = 0;

  if (!resp) {
    result = WEBPUSH_ERR_HTTP;
  } else {
    status = resp->status_code;
    if (status >= 200 && status < 300) {
      result = WEBPUSH_OK;
    } else if (status == 410) {
      result = WEBPUSH_ERR_EXPIRED;
      log_write(LS_SYSTEM, L_WARNING, 0,
                "WebPush: subscription expired (HTTP 410)");
    } else if (status == 403) {
      /* The push service refused our VAPID signature: the subscription
       * was created under a key we no longer hold (or never had). */
      result = WEBPUSH_ERR_FORBIDDEN;
      log_write(LS_SYSTEM, L_WARNING, 0,
                "WebPush: delivery refused (HTTP 403, VAPID key mismatch?)%s%s",
                resp->error ? ": " : "", resp->error ? resp->error : "");
    } else {
      result = WEBPUSH_ERR_HTTP;
      log_write(LS_SYSTEM, L_WARNING, 0,
                "WebPush: delivery failed, HTTP %ld%s%s",
                status,
                resp->error ? ": " : "",
                resp->error ? resp->error : "");
    }
  }

  if (ctx) {
    if (ctx->cb)
      ctx->cb(result, status, ctx->cb_data);
    free(ctx);
  }
}

int webpush_send_async(const struct webpush_subscription *sub,
                       const unsigned char *encrypted, size_t encrypted_len,
                       unsigned long ttl,
                       webpush_send_cb cb, void *cb_data)
{
  struct kc_http_request req;
  struct webpush_send_ctx *ctx = NULL;
  struct curl_slist *headers = NULL;
  char auth_header[1024];
  char ttl_header[64];
  const struct wp_key *key;
  int rc;

  if (!sub || !encrypted || encrypted_len == 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: send_async: invalid arguments");
    return -1;
  }
  if (sub->endpoint[0] == '\0') {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: send_async: empty endpoint");
    return -1;
  }

  /* Sign with the key the subscription was registered under; a retired
   * key keeps signing for its subscriptions until they age out.  A
   * record without a key id (pre-ring) or bound to a key this server no
   * longer holds falls back to the current key -- the latter earns a 403
   * that the delivery callback counts toward reaping. */
  key = sub->key_id[0] ? wp_key_find(sub->key_id) : NULL;
  if (!key) {
    if (sub->key_id[0])
      log_write(LS_SYSTEM, L_WARNING, 0,
                "WebPush: subscription bound to unknown VAPID key %.16s..., signing with current",
                sub->key_id);
    key = wp_current;
  }
  if (!key) {
    log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: send_async: no VAPID key");
    return -1;
  }

  /* Create VAPID Authorization header */
  if (create_vapid_header(sub->endpoint, key, auth_header,
                           sizeof(auth_header)) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: send_async: failed to create VAPID header");
    return -1;
  }

  /* Build HTTP headers */
  headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
  if (!headers)
    goto error;

  headers = curl_slist_append(headers, "Content-Encoding: aes128gcm");
  if (!headers)
    goto error;

  if (ttl == 0)
    ttl = 86400;
  snprintf(ttl_header, sizeof(ttl_header), "TTL: %lu", ttl);
  headers = curl_slist_append(headers, ttl_header);
  if (!headers)
    goto error;

  {
    char auth_hdr_full[1100];
    snprintf(auth_hdr_full, sizeof(auth_hdr_full),
             "Authorization: %s", auth_header);
    headers = curl_slist_append(headers, auth_hdr_full);
    if (!headers)
      goto error;
  }

  /* Allocate callback context */
  ctx = (struct webpush_send_ctx *)malloc(sizeof(*ctx));
  if (!ctx)
    goto error;
  ctx->cb = cb;
  ctx->cb_data = cb_data;

  /* Build HTTP request */
  memset(&req, 0, sizeof(req));
  req.url = sub->endpoint;
  req.method = "POST";
  req.body = (const char *)encrypted;
  req.body_len = encrypted_len;
  req.headers = headers;
  req.bearer_token = NULL;
  req.timeout_ms = 30000;

  /* Submit async request */
  rc = kc_http_request(&req, webpush_http_callback, ctx);
  if (rc != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: send_async: kc_http_request failed");
    goto error;
  }

  /* Note: headers are owned by libkc/curl now; do NOT free them here.
   * ctx will be freed in the callback. */
  return 0;

error:
  if (headers)
    curl_slist_free_all(headers);
  free(ctx);
  return -1;
}

#else /* !USE_LIBKC: keys and the token exist, nothing can be delivered */

int webpush_send_async(const struct webpush_subscription *sub,
                       const unsigned char *encrypted, size_t encrypted_len,
                       unsigned long ttl,
                       webpush_send_cb cb, void *cb_data)
{
  (void)sub; (void)encrypted; (void)encrypted_len; (void)ttl; (void)cb; (void)cb_data;
  log_write(LS_SYSTEM, L_ERROR, 0,
            "WebPush: built without libkc (--enable-keycloak): cannot deliver");
  return -1;
}

#endif /* USE_LIBKC */

/* ---------------------------------------------------------------------------
 * High-level convenience
 * ---------------------------------------------------------------------------*/

int webpush_notify(const struct webpush_subscription *sub,
                   const char *message, size_t message_len,
                   webpush_send_cb cb, void *cb_data)
{
  unsigned char encrypted[WEBPUSH_ENCRYPTED_MAX];
  size_t encrypted_len = 0;

  if (!sub || !message || message_len == 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: notify: invalid arguments");
    return -1;
  }

  if (webpush_encrypt(sub, (const unsigned char *)message, message_len,
                       encrypted, &encrypted_len) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: notify: encryption failed");
    return -1;
  }

  {
    /* The endpoint is a capability URL: log its host only. */
    char host[128];
    const char *p = strstr(sub->endpoint, "://");
    size_t n = 0;
    p = p ? p + 3 : sub->endpoint;
    while (p[n] && p[n] != '/' && n < sizeof(host) - 1)
      n++;
    memcpy(host, p, n);
    host[n] = '\0';
    log_write(LS_SYSTEM, L_DEBUG, 0, "WebPush: posting %zu bytes to %s",
              encrypted_len, host);
  }

  return webpush_send_async(sub, encrypted, encrypted_len, 0, cb, cb_data);
}

/* ---------------------------------------------------------------------------
 * Subscription parsing
 * ---------------------------------------------------------------------------*/

int webpush_parse_subscription(const char *stored,
                               struct webpush_subscription *sub)
{
  const char *p1, *p2;
  size_t endpoint_len, p256dh_b64_len, auth_b64_len;

  if (!stored || !sub)
    return -1;

  memset(sub, 0, sizeof(*sub));

  /* Format: endpoint|p256dh_base64url|auth_base64url */
  p1 = strchr(stored, '|');
  if (!p1)
    return -1;

  p2 = strchr(p1 + 1, '|');
  if (!p2)
    return -1;

  /* Extract endpoint */
  endpoint_len = (size_t)(p1 - stored);
  if (endpoint_len == 0 || endpoint_len >= WEBPUSH_MAX_ENDPOINT)
    return -1;
  memcpy(sub->endpoint, stored, endpoint_len);
  sub->endpoint[endpoint_len] = '\0';

  /* Decode p256dh */
  p256dh_b64_len = (size_t)(p2 - (p1 + 1));
  if (p256dh_b64_len == 0)
    return -1;
  if (base64url_decode(p1 + 1, p256dh_b64_len,
                       sub->p256dh, sizeof(sub->p256dh),
                       &sub->p256dh_len) != 0)
    return -1;

  /* Validate p256dh: must be 65 bytes, starting with 0x04 (uncompressed) */
  if (sub->p256dh_len != 65 || sub->p256dh[0] != 0x04)
    return -1;

  /* Decode auth.  The record may carry a trailing "|armed" timestamp
   * (webpush_expiry.h); stop the auth field at the next '|' so both
   * record formats parse. */
  auth_b64_len = strcspn(p2 + 1, "|");
  if (auth_b64_len == 0)
    return -1;
  if (base64url_decode(p2 + 1, auth_b64_len,
                       sub->auth, sizeof(sub->auth),
                       &sub->auth_len) != 0)
    return -1;

  /* Validate auth: must be 16 bytes */
  if (sub->auth_len != 16)
    return -1;

  /* Key binding (5th field, webpush_keyring.h); absent on pre-ring
   * records, and an over-long field is treated as absent rather than
   * failing the whole record. */
  if (webpush_record_key_id(stored, sub->key_id, sizeof(sub->key_id)) != 0)
    sub->key_id[0] = '\0';

  return 0;
}

#endif /* USE_SSL */

/* ---------------------------------------------------------------------------
 * Stub implementations when crypto or HTTP transport unavailable
 * ---------------------------------------------------------------------------*/

#ifndef USE_SSL

#include "webpush.h"

void webpush_cleanup(void) {}
const char *webpush_get_vapid_pubkey(void) { return NULL; }
int webpush_key_load(const unsigned char *p, size_t pl, const char *e,
                     char *o, size_t os) {
  (void)p; (void)pl; (void)e; (void)o; (void)os;
  return -1;
}
void webpush_key_unload(const char *id) { (void)id; }
int webpush_key_loaded(const char *id) { (void)id; return 0; }
int webpush_key_generate(unsigned char *p, size_t *pl, char *o, size_t os) {
  (void)p; (void)pl; (void)o; (void)os;
  return -1;
}
int webpush_set_current_key(const char *id) { (void)id; return -1; }
int webpush_parse_subscription(const char *s,
                                struct webpush_subscription *sub) {
  (void)s; (void)sub;
  return -1;
}
int webpush_encrypt(const struct webpush_subscription *s,
                    const unsigned char *p, size_t pl,
                    unsigned char *o, size_t *ol) {
  (void)s; (void)p; (void)pl; (void)o; (void)ol;
  return -1;
}
int webpush_send_async(const struct webpush_subscription *s,
                       const unsigned char *e, size_t el,
                       unsigned long t, webpush_send_cb c, void *d) {
  (void)s; (void)e; (void)el; (void)t; (void)c; (void)d;
  return -1;
}
int webpush_notify(const struct webpush_subscription *s,
                   const char *m, size_t ml,
                   webpush_send_cb c, void *d) {
  (void)s; (void)m; (void)ml; (void)c; (void)d;
  return -1;
}

#endif /* !USE_SSL */
