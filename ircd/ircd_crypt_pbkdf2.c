/*
 * IRC - Internet Relay Chat, ircd/ircd_crypt_pbkdf2.c
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
/**
 * @file
 * @brief PBKDF2 password hashing routines (SHA256 and SHA512)
 *
 * Provides PBKDF2-SHA256 and PBKDF2-SHA512 password hashing using OpenSSL 3.0+ EVP_KDF API.
 * Hash formats:
 *   SHA256: $PBKDF2$iterations$base64_salt$base64_hash
 *   SHA512: $PBKDF2-SHA512$iterations$base64_salt$base64_hash
 *
 * This is compatible with Keycloak credential import and follows
 * OWASP recommendations for password hashing (100,000+ iterations).
 */
#include "config.h"
#include "ircd_crypt.h"
#include "ircd_crypt_pbkdf2.h"
#include "ircd_log.h"
#include "s_debug.h"
#include "ircd_alloc.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>

/* PBKDF2 parameters */
#define PBKDF2_SALT_LEN       16      /* 128 bits */
#define PBKDF2_SHA256_LEN     32      /* 256 bits (SHA256 output) */
#define PBKDF2_SHA512_LEN     64      /* 512 bits (SHA512 output) */
#define PBKDF2_ITERATIONS     100000  /* OWASP 2023 minimum recommendation */

/* Token for mechanism detection */
#define PBKDF2_TOKEN          "$PBKDF2$"
#define PBKDF2_TOKEN_SIZE     8
#define PBKDF2_SHA512_TOKEN   "$PBKDF2-SHA512$"
#define PBKDF2_SHA512_TOKEN_SIZE 15

/* Standard base64 alphabet */
static const char base64_chars[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Encode binary data to base64 (no padding, no newlines)
 * @param input Binary input data
 * @param input_len Length of input
 * @param output Output buffer (must be at least (input_len * 4 / 3) + 4 bytes)
 * @return Length of encoded string
 */
static int base64_encode(const unsigned char *input, int input_len, char *output)
{
  int i, j;
  unsigned int triplet;

  for (i = 0, j = 0; i < input_len; ) {
    triplet = (i < input_len ? input[i++] : 0) << 16;
    triplet |= (i < input_len ? input[i++] : 0) << 8;
    triplet |= (i < input_len ? input[i++] : 0);

    output[j++] = base64_chars[(triplet >> 18) & 0x3f];
    output[j++] = base64_chars[(triplet >> 12) & 0x3f];
    output[j++] = base64_chars[(triplet >> 6) & 0x3f];
    output[j++] = base64_chars[triplet & 0x3f];
  }

  /* Handle padding - we don't add '=' padding chars, just adjust length */
  if (input_len % 3 == 1) j -= 2;
  else if (input_len % 3 == 2) j -= 1;

  output[j] = '\0';
  return j;
}

/** Decode base64 to binary
 * @param input Base64 input string
 * @param output Output buffer (must be at least (strlen(input) * 3 / 4) bytes)
 * @return Length of decoded data, or -1 on error
 */
static int base64_decode(const char *input, unsigned char *output)
{
  int i, j, len;
  unsigned int triplet;
  unsigned char c, d[4];
  const char *p;

  len = strlen(input);
  for (i = 0, j = 0; i < len; ) {
    /* Decode 4 base64 chars to 3 bytes */
    for (int k = 0; k < 4; k++) {
      if (i < len) {
        c = input[i++];
        p = strchr(base64_chars, c);
        if (p == NULL) return -1;
        d[k] = p - base64_chars;
      } else {
        d[k] = 0;
      }
    }

    triplet = (d[0] << 18) | (d[1] << 12) | (d[2] << 6) | d[3];
    output[j++] = (triplet >> 16) & 0xff;
    output[j++] = (triplet >> 8) & 0xff;
    output[j++] = triplet & 0xff;
  }

  /* Adjust for missing padding */
  if (len % 4 == 2) j -= 2;
  else if (len % 4 == 3) j -= 1;

  return j;
}

/** Perform PBKDF2 key derivation with specified digest
 * @param password The password to hash
 * @param salt The salt bytes
 * @param salt_len Length of salt
 * @param iterations Number of iterations
 * @param output Output buffer for derived key
 * @param output_len Desired output length
 * @param digest_name Digest algorithm ("SHA256" or "SHA512")
 * @return 1 on success, 0 on failure
 */
static int do_pbkdf2(const char *password, const unsigned char *salt,
                     size_t salt_len, int iterations,
                     unsigned char *output, size_t output_len,
                     const char *digest_name)
{
  EVP_KDF *kdf = NULL;
  EVP_KDF_CTX *ctx = NULL;
  OSSL_PARAM params[5];
  int ret = 0;

  kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
  if (kdf == NULL) {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: EVP_KDF_fetch failed"));
    goto cleanup;
  }

  ctx = EVP_KDF_CTX_new(kdf);
  if (ctx == NULL) {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: EVP_KDF_CTX_new failed"));
    goto cleanup;
  }

  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)digest_name, 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                 (void *)password, strlen(password));
  params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (void *)salt, salt_len);
  params[3] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER, &iterations);
  params[4] = OSSL_PARAM_construct_end();

  if (EVP_KDF_derive(ctx, output, output_len, params) != 1) {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: EVP_KDF_derive failed"));
    goto cleanup;
  }

  ret = 1;

cleanup:
  if (ctx) EVP_KDF_CTX_free(ctx);
  if (kdf) EVP_KDF_free(kdf);
  return ret;
}

/** Parse existing PBKDF2 hash to extract parameters
 * @param hash The hash string (format: $PBKDF2$iter$salt$hash or just $PBKDF2$)
 * @param iterations Output: iteration count
 * @param salt Output: decoded salt bytes
 * @param salt_len Output: salt length
 * @param stored_hash Output: decoded hash bytes
 * @param hash_len Output: hash length
 * @return 1 if valid existing hash, 0 if new hash request
 */
static int parse_pbkdf2_hash(const char *hash, int *iterations,
                             unsigned char *salt, int *salt_len,
                             unsigned char *stored_hash, int *hash_len)
{
  const char *p;
  char iter_str[16];
  char salt_b64[64];
  char hash_b64[128];
  int i;

  /* Check for token */
  if (strncmp(hash, PBKDF2_TOKEN, PBKDF2_TOKEN_SIZE) != 0)
    return 0;

  p = hash + PBKDF2_TOKEN_SIZE;

  /* If nothing after token, this is a new hash request */
  if (*p == '\0')
    return 0;

  /* Parse iterations */
  for (i = 0; *p && *p != '$' && i < 15; i++, p++)
    iter_str[i] = *p;
  iter_str[i] = '\0';

  if (*p != '$') return 0;
  p++;

  *iterations = atoi(iter_str);
  if (*iterations <= 0) return 0;

  /* Parse salt (base64) */
  for (i = 0; *p && *p != '$' && i < 63; i++, p++)
    salt_b64[i] = *p;
  salt_b64[i] = '\0';

  if (*p != '$') return 0;
  p++;

  /* Parse hash (base64) */
  for (i = 0; *p && i < 127; i++, p++)
    hash_b64[i] = *p;
  hash_b64[i] = '\0';

  /* Decode salt and hash */
  *salt_len = base64_decode(salt_b64, salt);
  if (*salt_len < 0) return 0;

  *hash_len = base64_decode(hash_b64, stored_hash);
  if (*hash_len < 0) return 0;

  return 1;
}

/** Parse existing PBKDF2-SHA512 hash to extract parameters
 * @param hash The hash string (format: $PBKDF2-SHA512$iter$salt$hash)
 * @param iterations Output: iteration count
 * @param salt Output: decoded salt bytes
 * @param salt_len Output: salt length
 * @param stored_hash Output: decoded hash bytes
 * @param hash_len Output: hash length
 * @return 1 if valid existing hash, 0 if new hash request
 */
static int parse_pbkdf2_sha512_hash(const char *hash, int *iterations,
                                    unsigned char *salt, int *salt_len,
                                    unsigned char *stored_hash, int *hash_len)
{
  const char *p;
  char iter_str[16];
  char salt_b64[64];
  char hash_b64[128];
  int i;

  /* Check for token */
  if (strncmp(hash, PBKDF2_SHA512_TOKEN, PBKDF2_SHA512_TOKEN_SIZE) != 0)
    return 0;

  p = hash + PBKDF2_SHA512_TOKEN_SIZE;

  /* If nothing after token, this is a new hash request */
  if (*p == '\0')
    return 0;

  /* Parse iterations */
  for (i = 0; *p && *p != '$' && i < 15; i++, p++)
    iter_str[i] = *p;
  iter_str[i] = '\0';

  if (*p != '$') return 0;
  p++;

  *iterations = atoi(iter_str);
  if (*iterations <= 0) return 0;

  /* Parse salt (base64) */
  for (i = 0; *p && *p != '$' && i < 63; i++, p++)
    salt_b64[i] = *p;
  salt_b64[i] = '\0';

  if (*p != '$') return 0;
  p++;

  /* Parse hash (base64) */
  for (i = 0; *p && i < 127; i++, p++)
    hash_b64[i] = *p;
  hash_b64[i] = '\0';

  /* Decode salt and hash */
  *salt_len = base64_decode(salt_b64, salt);
  if (*salt_len < 0) return 0;

  *hash_len = base64_decode(hash_b64, stored_hash);
  if (*hash_len < 0) return 0;

  return 1;
}

/** PBKDF2-SHA256 password hashing function
 * @param key The password to hash
 * @param salt The salt (if starts with $PBKDF2$iter$..., verify; else generate new)
 * @return The hashed password, or NULL on failure
 *
 * When called with an existing PBKDF2 hash as salt, extracts parameters and
 * re-hashes for verification. When called with just $PBKDF2$ or anything else,
 * generates a new hash with random salt.
 */
const char* ircd_crypt_pbkdf2(const char* key, const char* salt)
{
  static char result[256];
  unsigned char salt_bytes[PBKDF2_SALT_LEN];
  unsigned char hash_bytes[PBKDF2_SHA256_LEN];
  unsigned char stored_hash[PBKDF2_SHA256_LEN];
  char salt_b64[32];
  char hash_b64[64];
  int iterations = PBKDF2_ITERATIONS;
  int salt_len, hash_len;

  assert(NULL != key);
  assert(NULL != salt);

  Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: key = [hidden]"));
  Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: salt = %s", salt));

  /* Check if this is verification of existing hash */
  if (parse_pbkdf2_hash(salt, &iterations, salt_bytes, &salt_len,
                        stored_hash, &hash_len)) {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: verifying existing hash"));

    /* Re-derive the hash with the same parameters */
    if (!do_pbkdf2(key, salt_bytes, salt_len, iterations,
                   hash_bytes, PBKDF2_SHA256_LEN, "SHA256")) {
      Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: derivation failed"));
      return NULL;
    }

    /* Return the same format for comparison */
    base64_encode(salt_bytes, salt_len, salt_b64);
    base64_encode(hash_bytes, PBKDF2_SHA256_LEN, hash_b64);
    snprintf(result, sizeof(result), "%s%d$%s$%s",
             PBKDF2_TOKEN, iterations, salt_b64, hash_b64);
  }
  else {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: generating new hash"));

    /* Generate random salt */
    if (RAND_bytes(salt_bytes, PBKDF2_SALT_LEN) != 1) {
      Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: RAND_bytes failed"));
      return NULL;
    }

    /* Derive the hash */
    if (!do_pbkdf2(key, salt_bytes, PBKDF2_SALT_LEN, iterations,
                   hash_bytes, PBKDF2_SHA256_LEN, "SHA256")) {
      Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: derivation failed"));
      return NULL;
    }

    /* Format: $PBKDF2$iterations$base64_salt$base64_hash */
    base64_encode(salt_bytes, PBKDF2_SALT_LEN, salt_b64);
    base64_encode(hash_bytes, PBKDF2_SHA256_LEN, hash_b64);
    snprintf(result, sizeof(result), "%s%d$%s$%s",
             PBKDF2_TOKEN, iterations, salt_b64, hash_b64);
  }

  Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2: result = %s", result));
  return result;
}

/** Register the PBKDF2-SHA256 mechanism */
void ircd_register_crypt_pbkdf2(void)
{
  crypt_mech_t* crypt_mech;

  if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
  {
    Debug((DEBUG_MALLOC, "Could not allocate space for crypt_pbkdf2"));
    return;
  }

  crypt_mech->mechname = "pbkdf2";
  crypt_mech->shortname = "crypt_pbkdf2";
  crypt_mech->description = "PBKDF2-SHA256 password hash ($PBKDF2$).";
  crypt_mech->crypt_function = &ircd_crypt_pbkdf2;
  crypt_mech->crypt_token = PBKDF2_TOKEN;
  crypt_mech->crypt_token_size = PBKDF2_TOKEN_SIZE;

  ircd_crypt_register_mech(crypt_mech);
}

/** PBKDF2-SHA512 password hashing function
 * @param key The password to hash
 * @param salt The salt (if starts with $PBKDF2-SHA512$iter$..., verify; else generate new)
 * @return The hashed password, or NULL on failure
 *
 * When called with an existing PBKDF2-SHA512 hash as salt, extracts parameters and
 * re-hashes for verification. When called with just $PBKDF2-SHA512$ or anything else,
 * generates a new hash with random salt.
 */
const char* ircd_crypt_pbkdf2_sha512(const char* key, const char* salt)
{
  static char result[512];
  unsigned char salt_bytes[PBKDF2_SALT_LEN];
  unsigned char hash_bytes[PBKDF2_SHA512_LEN];
  unsigned char stored_hash[PBKDF2_SHA512_LEN];
  char salt_b64[32];
  char hash_b64[128];
  int iterations = PBKDF2_ITERATIONS;
  int salt_len, hash_len;

  assert(NULL != key);
  assert(NULL != salt);

  Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: key = [hidden]"));
  Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: salt = %s", salt));

  /* Check if this is verification of existing hash */
  if (parse_pbkdf2_sha512_hash(salt, &iterations, salt_bytes, &salt_len,
                               stored_hash, &hash_len)) {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: verifying existing hash"));

    /* Re-derive the hash with the same parameters */
    if (!do_pbkdf2(key, salt_bytes, salt_len, iterations,
                   hash_bytes, PBKDF2_SHA512_LEN, "SHA512")) {
      Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: derivation failed"));
      return NULL;
    }

    /* Return the same format for comparison */
    base64_encode(salt_bytes, salt_len, salt_b64);
    base64_encode(hash_bytes, PBKDF2_SHA512_LEN, hash_b64);
    snprintf(result, sizeof(result), "%s%d$%s$%s",
             PBKDF2_SHA512_TOKEN, iterations, salt_b64, hash_b64);
  }
  else {
    Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: generating new hash"));

    /* Generate random salt */
    if (RAND_bytes(salt_bytes, PBKDF2_SALT_LEN) != 1) {
      Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: RAND_bytes failed"));
      return NULL;
    }

    /* Derive the hash */
    if (!do_pbkdf2(key, salt_bytes, PBKDF2_SALT_LEN, iterations,
                   hash_bytes, PBKDF2_SHA512_LEN, "SHA512")) {
      Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: derivation failed"));
      return NULL;
    }

    /* Format: $PBKDF2-SHA512$iterations$base64_salt$base64_hash */
    base64_encode(salt_bytes, PBKDF2_SALT_LEN, salt_b64);
    base64_encode(hash_bytes, PBKDF2_SHA512_LEN, hash_b64);
    snprintf(result, sizeof(result), "%s%d$%s$%s",
             PBKDF2_SHA512_TOKEN, iterations, salt_b64, hash_b64);
  }

  Debug((DEBUG_DEBUG, "ircd_crypt_pbkdf2_sha512: result = %s", result));
  return result;
}

/** Register the PBKDF2-SHA512 mechanism */
void ircd_register_crypt_pbkdf2_sha512(void)
{
  crypt_mech_t* crypt_mech;

  if ((crypt_mech = (crypt_mech_t*)MyMalloc(sizeof(crypt_mech_t))) == NULL)
  {
    Debug((DEBUG_MALLOC, "Could not allocate space for crypt_pbkdf2_sha512"));
    return;
  }

  crypt_mech->mechname = "pbkdf2-sha512";
  crypt_mech->shortname = "crypt_pbkdf2_sha512";
  crypt_mech->description = "PBKDF2-SHA512 password hash ($PBKDF2-SHA512$).";
  crypt_mech->crypt_function = &ircd_crypt_pbkdf2_sha512;
  crypt_mech->crypt_token = PBKDF2_SHA512_TOKEN;
  crypt_mech->crypt_token_size = PBKDF2_SHA512_TOKEN_SIZE;

  ircd_crypt_register_mech(crypt_mech);
}
