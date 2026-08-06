/* ircd/kc/kc_cred_derive.c — registration-time credential derivation.
 * MUST stay ircd-header-free (kc boundary). Lockstep contract: the SCRAM
 * derivation here is byte-identical to keycloak-webhook-spi's
 * ScramCredentialProvider (SHA-256, 4096 iterations, 16-byte salt); both
 * write scram_sha256_* attributes. Change one, change both. */
#include <kc/kc_cred_derive.h>
#include <kc/kc_base64.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>

static void b64_fixed(const unsigned char *in, size_t inlen, char *out, size_t outsz) {
    kc_base64_encode((const char *)in, inlen, out, outsz);
}

int scram_sha256_derive(const char *password, const unsigned char *salt,
                        size_t salt_len, int iterations,
                        struct scram_sha256_creds *out)
{
    unsigned char sp[SCRAM_SHA256_KEY_LEN];
    unsigned char client_key[SCRAM_SHA256_KEY_LEN], stored_key[SCRAM_SHA256_KEY_LEN];
    unsigned char server_key[SCRAM_SHA256_KEY_LEN];
    unsigned int len;

    if (!password || !salt || !salt_len || iterations < 1 || !out)
        return -1;
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, salt_len,
                           iterations, EVP_sha256(), sizeof(sp), sp))
        return -1;
    if (!HMAC(EVP_sha256(), sp, sizeof(sp), (const unsigned char *)"Client Key", 10,
              client_key, &len))
        return -1;
    SHA256(client_key, sizeof(client_key), stored_key);
    if (!HMAC(EVP_sha256(), sp, sizeof(sp), (const unsigned char *)"Server Key", 10,
              server_key, &len))
        return -1;
    b64_fixed(salt, salt_len, out->salt_b64, sizeof(out->salt_b64));
    b64_fixed(stored_key, sizeof(stored_key), out->stored_key_b64, sizeof(out->stored_key_b64));
    b64_fixed(server_key, sizeof(server_key), out->server_key_b64, sizeof(out->server_key_b64));
    out->iterations = iterations;
    return 0;
}

int scram_sha256_derive_random(const char *password, struct scram_sha256_creds *out)
{
    unsigned char salt[SCRAM_SHA256_SALT_LEN];
    if (!password || !out || RAND_bytes(salt, sizeof(salt)) != 1)
        return -1;
    return scram_sha256_derive(password, salt, sizeof(salt),
                               SCRAM_SHA256_ITERATIONS, out);
}

int kc_pbkdf2_cred_build(const char *password, char **cred_data, char **secret_data)
{
    unsigned char salt[16], dk[KC_PBKDF2_KEY_LEN];
    char salt_b64[32], dk_b64[64];
    json_t *cj, *sj;

    if (!password || !cred_data || !secret_data)
        return -1;
    if (RAND_bytes(salt, sizeof(salt)) != 1)
        return -1;
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                           KC_PBKDF2_ITERATIONS, EVP_sha256(), sizeof(dk), dk))
        return -1;
    b64_fixed(salt, sizeof(salt), salt_b64, sizeof(salt_b64));
    b64_fixed(dk, sizeof(dk), dk_b64, sizeof(dk_b64));

    cj = json_pack("{sisss{}}", "hashIterations", KC_PBKDF2_ITERATIONS,
                   "algorithm", "pbkdf2-sha256", "additionalParameters");
    sj = json_pack("{ssss}", "value", dk_b64, "salt", salt_b64);
    if (!cj || !sj) { if (cj) json_decref(cj); if (sj) json_decref(sj); return -1; }
    *cred_data = json_dumps(cj, JSON_COMPACT);
    *secret_data = json_dumps(sj, JSON_COMPACT);
    json_decref(cj); json_decref(sj);
    if (!*cred_data || !*secret_data) {
        free(*cred_data); free(*secret_data);
        *cred_data = *secret_data = NULL;
        return -1;
    }
    return 0;
}
