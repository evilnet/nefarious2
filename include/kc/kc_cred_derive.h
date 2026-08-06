/* kc_cred_derive.h -- registration-time credential derivation.
 *
 * Pure derivation helpers used at account-REGISTER time to produce:
 *   - SCRAM-SHA-256 material (RFC 5802/7677), byte-identical to the
 *     keycloak-webhook-spi's ScramCredentialProvider (see kc_cred_derive.c
 *     for the lockstep contract).
 *   - Keycloak PBKDF2 credential-import JSON (credentialData/secretData),
 *     for direct admin-API credential import.
 *
 * MUST stay ircd-header-free (kc boundary; see check-kc-boundary in
 * ircd/Makefile.in).
 */
#ifndef KC_CRED_DERIVE_H
#define KC_CRED_DERIVE_H

#include <stddef.h>

#define SCRAM_SHA256_SALT_LEN   16
#define SCRAM_SHA256_KEY_LEN    32
#define SCRAM_SHA256_ITERATIONS 4096

/* Keycloak PBKDF2 import — constants CONFIRMED BY TASK 0's live probe. */
#define KC_PBKDF2_ITERATIONS    27500
#define KC_PBKDF2_KEY_LEN       32

struct scram_sha256_creds {
    char salt_b64[32];        /* 16 bytes -> 24 b64 chars + NUL */
    int  iterations;
    char stored_key_b64[48];  /* 32 bytes -> 44 b64 chars + NUL */
    char server_key_b64[48];
};

/* RFC 5802/7677: SaltedPassword=PBKDF2; ClientKey=HMAC(SP,"Client Key");
 * StoredKey=H(ClientKey); ServerKey=HMAC(SP,"Server Key"). Returns 0 / -1. */
int scram_sha256_derive(const char *password, const unsigned char *salt,
                        size_t salt_len, int iterations,
                        struct scram_sha256_creds *out);

/* RAND_bytes salt + canonical iteration count. */
int scram_sha256_derive_random(const char *password,
                               struct scram_sha256_creds *out);

/* Builds Keycloak credentialData/secretData JSON strings (malloc'd; caller
 * frees both). Returns 0 / -1. */
int kc_pbkdf2_cred_build(const char *password, char **cred_data,
                         char **secret_data);

#endif /* KC_CRED_DERIVE_H */
