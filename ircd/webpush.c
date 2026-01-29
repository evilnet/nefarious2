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

#if defined(USE_SSL) && defined(USE_LIBKC)

#include "webpush.h"
#include "ircd_log.h"
#include "ircd_kc_adapter.h"

#include <kc/kc.h>
#include <kc/kc_http.h>

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

#include <curl/curl.h>   /* curl_slist */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>

/* ---------------------------------------------------------------------------
 * Static globals — VAPID key state
 * ---------------------------------------------------------------------------*/

static EVP_PKEY *vapid_key = NULL;
static unsigned char vapid_pubkey_raw[65];  /* uncompressed P-256 */
static size_t vapid_pubkey_raw_len = 0;
static char vapid_pubkey_b64[WEBPUSH_VAPID_B64_LEN + 1];
static int vapid_initialized = 0;

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
  size_t padded_len, i;
  int decoded_len;

  /* Calculate padded length (base64 must be multiple of 4) */
  padded_len = in_len;
  switch (in_len % 4) {
    case 2: padded_len += 2; break;
    case 3: padded_len += 1; break;
    case 0: break;
    default: return -1;  /* invalid base64url length */
  }

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
   * It may include up to 2 extra zero bytes for padding chars. */
  if (out_size < (padded_len / 4) * 3) {
    free(std_buf);
    return -1;
  }

  decoded_len = EVP_DecodeBlock(out, (const unsigned char *)std_buf,
                                (int)padded_len);
  free(std_buf);

  if (decoded_len < 0)
    return -1;

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

/** Generate a fresh P-256 keypair for VAPID signing. */
static int generate_vapid_key(void)
{
  int enc_len;

  vapid_key = EVP_EC_gen("P-256");
  if (!vapid_key) {
    log_write(LS_SYSTEM, L_ERROR, 0, "WebPush: failed to generate P-256 key");
    return -1;
  }

  /* Extract uncompressed public key */
  vapid_pubkey_raw_len = sizeof(vapid_pubkey_raw);
  if (!EVP_PKEY_get_octet_string_param(vapid_key, OSSL_PKEY_PARAM_PUB_KEY,
                                        vapid_pubkey_raw,
                                        sizeof(vapid_pubkey_raw),
                                        &vapid_pubkey_raw_len)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: failed to extract VAPID public key");
    EVP_PKEY_free(vapid_key);
    vapid_key = NULL;
    return -1;
  }

  /* Base64url-encode the public key */
  enc_len = base64url_encode(vapid_pubkey_raw, vapid_pubkey_raw_len,
                             vapid_pubkey_b64, sizeof(vapid_pubkey_b64));
  if (enc_len < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: failed to base64url-encode VAPID public key");
    EVP_PKEY_free(vapid_key);
    vapid_key = NULL;
    return -1;
  }

  return 0;
}

int webpush_init(void)
{
  if (vapid_initialized)
    return 0;

  if (generate_vapid_key() != 0)
    return -1;

  vapid_initialized = 1;
  log_write(LS_SYSTEM, L_INFO, 0,
            "WebPush: VAPID key initialized, pubkey=%s", vapid_pubkey_b64);
  return 0;
}

void webpush_cleanup(void)
{
  if (vapid_key) {
    EVP_PKEY_free(vapid_key);
    vapid_key = NULL;
  }
  OPENSSL_cleanse(vapid_pubkey_raw, sizeof(vapid_pubkey_raw));
  OPENSSL_cleanse(vapid_pubkey_b64, sizeof(vapid_pubkey_b64));
  vapid_pubkey_raw_len = 0;
  vapid_initialized = 0;
}

const char *webpush_get_vapid_pubkey(void)
{
  if (!vapid_initialized)
    return NULL;
  return vapid_pubkey_b64;
}

const unsigned char *webpush_get_vapid_pubkey_raw(size_t *out_len)
{
  if (!vapid_initialized) {
    if (out_len)
      *out_len = 0;
    return NULL;
  }
  if (out_len)
    *out_len = vapid_pubkey_raw_len;
  return vapid_pubkey_raw;
}

int webpush_import_vapid_key(const unsigned char *privkey, size_t privkey_len,
                              const unsigned char *pubkey, size_t pubkey_len)
{
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  EVP_PKEY *pkey = NULL;
  BIGNUM *priv_bn = NULL;
  unsigned char derived_pub[65];
  size_t derived_pub_len = 0;
  int enc_len;
  int ret = -1;

  if (!privkey || privkey_len != 32) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: import requires 32-byte private key");
    return -1;
  }

  priv_bn = BN_bin2bn(privkey, (int)privkey_len, NULL);
  if (!priv_bn)
    goto cleanup;

  /* If no public key provided, derive it from the private key.
   * EVP_PKEY_fromdata() does not automatically compute the public point
   * from just the private scalar in OpenSSL 3.x. */
  if (!pubkey || pubkey_len != 65) {
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    EC_POINT *pub_point = NULL;
    if (group) {
      pub_point = EC_POINT_new(group);
      if (pub_point &&
          EC_POINT_mul(group, pub_point, priv_bn, NULL, NULL, NULL)) {
        derived_pub_len = EC_POINT_point2oct(group, pub_point,
                                              POINT_CONVERSION_UNCOMPRESSED,
                                              derived_pub, sizeof(derived_pub),
                                              NULL);
      }
      EC_POINT_free(pub_point);
      EC_GROUP_free(group);
    }
    if (derived_pub_len != 65) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "WebPush: failed to derive public key from private key");
      goto cleanup;
    }
    pubkey = derived_pub;
    pubkey_len = derived_pub_len;
  }

  bld = OSSL_PARAM_BLD_new();
  if (!bld)
    goto cleanup;

  if (!OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "P-256", 0))
    goto cleanup;

  if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn))
    goto cleanup;

  if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pubkey, pubkey_len))
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

  /* Replace current key */
  if (vapid_key)
    EVP_PKEY_free(vapid_key);
  vapid_key = pkey;
  pkey = NULL;  /* ownership transferred */

  /* Extract public key */
  vapid_pubkey_raw_len = sizeof(vapid_pubkey_raw);
  if (!EVP_PKEY_get_octet_string_param(vapid_key, OSSL_PKEY_PARAM_PUB_KEY,
                                        vapid_pubkey_raw,
                                        sizeof(vapid_pubkey_raw),
                                        &vapid_pubkey_raw_len)) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: failed to extract public key after import");
    EVP_PKEY_free(vapid_key);
    vapid_key = NULL;
    goto cleanup;
  }

  /* Base64url-encode */
  enc_len = base64url_encode(vapid_pubkey_raw, vapid_pubkey_raw_len,
                             vapid_pubkey_b64, sizeof(vapid_pubkey_b64));
  if (enc_len < 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WebPush: failed to base64url-encode imported key");
    EVP_PKEY_free(vapid_key);
    vapid_key = NULL;
    goto cleanup;
  }

  vapid_initialized = 1;
  log_write(LS_SYSTEM, L_INFO, 0,
            "WebPush: VAPID key imported, pubkey=%s", vapid_pubkey_b64);
  ret = 0;

cleanup:
  BN_free(priv_bn);
  OSSL_PARAM_BLD_free(bld);
  OSSL_PARAM_free(params);
  EVP_PKEY_CTX_free(pctx);
  EVP_PKEY_free(pkey);
  return ret;
}

int webpush_export_vapid_privkey(unsigned char *out, size_t *out_len)
{
  BIGNUM *priv_bn = NULL;
  int bn_len;

  if (!vapid_key || !out || !out_len)
    return -1;

  if (*out_len < 32)
    return -1;

  if (!EVP_PKEY_get_bn_param(vapid_key, OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn))
    return -1;

  bn_len = BN_bn2binpad(priv_bn, out, 32);
  BN_clear_free(priv_bn);

  if (bn_len != 32)
    return -1;

  *out_len = 32;
  return 0;
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

  /* aes128gcm content encoding info strings */
  static const unsigned char cek_info[] = "Content-Encoding: aes128gcm\0";
  static const unsigned char nonce_info[] = "Content-Encoding: nonce\0";

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
static int create_vapid_header(const char *endpoint, char *out, size_t out_size)
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

  if (!endpoint || !out || !vapid_key)
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

  if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, vapid_key) != 1)
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
           header_b64, payload_b64, signature_b64, vapid_pubkey_b64);

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

  /* Create VAPID Authorization header */
  if (create_vapid_header(sub->endpoint, auth_header,
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

  /* Decode auth */
  auth_b64_len = strlen(p2 + 1);
  if (auth_b64_len == 0)
    return -1;
  if (base64url_decode(p2 + 1, auth_b64_len,
                       sub->auth, sizeof(sub->auth),
                       &sub->auth_len) != 0)
    return -1;

  /* Validate auth: must be 16 bytes */
  if (sub->auth_len != 16)
    return -1;

  return 0;
}

#endif /* USE_SSL && USE_LIBKC */

/* ---------------------------------------------------------------------------
 * Stub implementations when crypto or HTTP transport unavailable
 * ---------------------------------------------------------------------------*/

#if !defined(USE_SSL) || !defined(USE_LIBKC)

#include "webpush.h"

int webpush_init(void) { return -1; }
void webpush_cleanup(void) {}
const char *webpush_get_vapid_pubkey(void) { return NULL; }
const unsigned char *webpush_get_vapid_pubkey_raw(size_t *out_len) {
  if (out_len) *out_len = 0;
  return NULL;
}
int webpush_import_vapid_key(const unsigned char *p, size_t pl,
                              const unsigned char *k, size_t kl) {
  (void)p; (void)pl; (void)k; (void)kl;
  return -1;
}
int webpush_export_vapid_privkey(unsigned char *o, size_t *l) {
  (void)o; (void)l;
  return -1;
}
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

#endif /* !USE_SSL || !USE_LIBKC */
