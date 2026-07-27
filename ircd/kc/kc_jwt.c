/*
 * kc_jwt.c - JWKS fetching and JWT validation for libkc
 *
 * Ported from X3's kc_jwt.c. Changes:
 *   - log_module(jwt_log, ...) → kc_log_debug() / kc_log_info() / kc_log_warning()
 *   - base64_decode_alloc() → kc_base64_decode_alloc()
 *   - curl_perform() → kc_http_sync_perform()
 *   - `now` global → time(NULL)
 *   - struct kc_realm: base_uri → base_url
 *   - keycloak_free_token_info() → kc_jwt_token_info_free() (local, frees struct too)
 *   - No WITH_KEYCLOAK guard (libkc always builds with Keycloak support)
 */

#include <kc/kc.h>
#include <kc/kc_jwt.h>
#include <kc/kc_base64.h>
#include <kc/kc_http_sync.h>
#include <kc/kc_keycloak.h>  /* for KC_SUCCESS, KC_ERROR, KC_FORBIDDEN, struct kc_token_info */
#include <kc/kc_realm.h>

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <jansson.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#endif

/* Module-static statistics */
static struct kc_jwt_stats jwt_stats = {0};

/* Clock-skew tolerance (seconds) applied to time-based claim checks (nbf). */
#define KC_JWT_CLOCK_SKEW 60

/*
 * =============================================================================
 * JWKS Cache for Local JWT Validation
 * =============================================================================
 */

#define JWKS_CACHE_TTL 3600  /* Cache keys for 1 hour */
#define JWKS_MAX_KEYS 4      /* Max number of keys to cache */

struct jwks_key {
    char *kid;           /* Key ID */
    EVP_PKEY *pkey;      /* Parsed public key */
};

/* JWKS (JSON Web Key Set) cache for JWT signature verification.
 *
 * Thread-safety note: libkc is designed for single-threaded event-driven I/O.
 * The cache is refreshed synchronously via jwks_refresh() before any JWT
 * validation that finds a missing key.
 */
static struct {
    struct jwks_key keys[JWKS_MAX_KEYS];
    int key_count;
    time_t fetched;
    char *realm_url;     /* URL of the realm this cache is for */
} jwks_cache = {0};

/* Forward declarations */
static int jwks_refresh(struct kc_realm realm);
static void jwks_cleanup(void);
static EVP_PKEY *jwks_get_key(const char *kid);
static char *base64url_decode_alloc(const char *input, size_t *out_len);
static int jwt_verify_signature(const char *token, EVP_PKEY *pkey);
static int jwt_parse_claims(const char *payload_b64, struct kc_token_info *info);
static char *build_jwks_endpoint(struct kc_realm realm);

/*
 * =============================================================================
 * JWKS Cache Management
 * =============================================================================
 */

/* Cleanup JWKS cache */
static void
jwks_cleanup(void)
{
    for (int i = 0; i < jwks_cache.key_count; i++) {
        if (jwks_cache.keys[i].kid) {
            free(jwks_cache.keys[i].kid);
            jwks_cache.keys[i].kid = NULL;
        }
        if (jwks_cache.keys[i].pkey) {
            EVP_PKEY_free(jwks_cache.keys[i].pkey);
            jwks_cache.keys[i].pkey = NULL;
        }
    }
    jwks_cache.key_count = 0;
    jwks_cache.fetched = 0;
    if (jwks_cache.realm_url) {
        free(jwks_cache.realm_url);
        jwks_cache.realm_url = NULL;
    }
}

/* Convert base64url to standard base64 and decode */
static char *
base64url_decode_alloc(const char *input, size_t *out_len)
{
    if (!input || !out_len) return NULL;

    size_t input_len = strlen(input);
    if (input_len == 0) return NULL;

    /* Calculate padded length */
    size_t padded_len = input_len;
    int padding = (4 - (input_len % 4)) % 4;
    padded_len += padding;

    /* Allocate buffer for standard base64 */
    char *std_b64 = malloc(padded_len + 1);
    if (!std_b64) return NULL;

    /* Convert base64url to standard base64 */
    for (size_t i = 0; i < input_len; i++) {
        char c = input[i];
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
        std_b64[i] = c;
    }
    /* Add padding */
    for (size_t i = input_len; i < padded_len; i++) {
        std_b64[i] = '=';
    }
    std_b64[padded_len] = '\0';

    /* Decode using kc_base64 */
    char *decoded = NULL;
    if (!kc_base64_decode_alloc(std_b64, padded_len, &decoded, out_len)) {
        free(std_b64);
        return NULL;
    }
    free(std_b64);
    return decoded;
}

/* Parse RSA public key from JWKS 'n' and 'e' values */
static EVP_PKEY *
jwks_parse_rsa_key(const char *n_b64, const char *e_b64)
{
    EVP_PKEY *pkey = NULL;
    BIGNUM *n = NULL, *e = NULL;
    unsigned char *n_bin = NULL, *e_bin = NULL;
    size_t n_len = 0, e_len = 0;

    /* Decode modulus and exponent */
    n_bin = (unsigned char *)base64url_decode_alloc(n_b64, &n_len);
    e_bin = (unsigned char *)base64url_decode_alloc(e_b64, &e_len);
    if (!n_bin || !e_bin) {
        goto cleanup;
    }

    /* Create BIGNUMs */
    n = BN_bin2bn(n_bin, n_len, NULL);
    e = BN_bin2bn(e_bin, e_len, NULL);
    if (!n || !e) {
        goto cleanup;
    }

    /* Create EVP_PKEY with RSA parameters */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /* OpenSSL 3.0+ uses EVP_PKEY_fromdata */
    {
        OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
        if (!bld) goto cleanup;

        if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
            !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
            OSSL_PARAM_BLD_free(bld);
            goto cleanup;
        }

        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(bld);
        OSSL_PARAM_BLD_free(bld);
        if (!params) goto cleanup;

        EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
        if (ctx) {
            if (EVP_PKEY_fromdata_init(ctx) > 0) {
                EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
            }
            EVP_PKEY_CTX_free(ctx);
        }
        OSSL_PARAM_free(params);
    }
#else
    /* OpenSSL 1.1.x uses RSA_set0_key */
    {
        RSA *rsa = RSA_new();
        if (!rsa) goto cleanup;

        /* RSA_set0_key takes ownership of n and e on success */
        if (RSA_set0_key(rsa, n, e, NULL) != 1) {
            RSA_free(rsa);
            goto cleanup;
        }
        n = NULL; e = NULL;  /* Ownership transferred */

        pkey = EVP_PKEY_new();
        if (!pkey) {
            RSA_free(rsa);
            goto cleanup;
        }
        if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            RSA_free(rsa);
            EVP_PKEY_free(pkey);
            pkey = NULL;
            goto cleanup;
        }
    }
#endif

cleanup:
    if (n_bin) free(n_bin);
    if (e_bin) free(e_bin);
    if (n) BN_free(n);
    if (e) BN_free(e);
    return pkey;
}

/* JWKS endpoint: /realms/{realm}/protocol/openid-connect/certs */
static char *
build_jwks_endpoint(struct kc_realm realm)
{
    static const char tmpl[] = "%s/realms/%s/protocol/openid-connect/certs";
    if (!realm.base_url || !realm.realm) return NULL;

    int len = snprintf(NULL, 0, tmpl, realm.base_url, realm.realm) + 1;
    char *uri = malloc(len);
    if (uri) snprintf(uri, len, tmpl, realm.base_url, realm.realm);
    return uri;
}

/* Refresh JWKS cache from Keycloak */
static int
jwks_refresh(struct kc_realm realm)
{
    time_t current_time;

    if (!realm.base_url || !realm.realm) {
        return KC_ERROR;
    }

    /* Build JWKS URL using endpoint builder */
    char *url = build_jwks_endpoint(realm);
    if (!url) {
        return KC_ERROR;
    }

    /* Check if cache is still valid for this realm */
    current_time = time(NULL);
    if (jwks_cache.realm_url && strcmp(jwks_cache.realm_url, url) == 0) {
        if (current_time - jwks_cache.fetched < JWKS_CACHE_TTL && jwks_cache.key_count > 0) {
            kc_log_debug("JWKS cache still valid (%d keys)",
                         jwks_cache.key_count);
            free(url);
            return KC_SUCCESS;
        }
    }

    kc_log_info("Refreshing JWKS from %s", url);

    /* Cleanup old cache */
    jwks_cleanup();

    /* Fetch JWKS via sync HTTP */
    struct kc_http_sync_mem chunk = {0};
    struct kc_http_sync_opts opts = KC_HTTP_SYNC_OPTS_INIT;
    opts.uri = url;
    opts.method = KC_HTTP_GET;
    opts.max_retries = 1;
    opts.request_id = "jwks-fetch";

    long http_code = kc_http_sync_perform(opts, &chunk);

    if (http_code != 200 || !chunk.response) {
        kc_log_warning("Failed to fetch JWKS (HTTP %ld)", http_code);
        if (chunk.response) free(chunk.response);
        free(url);
        return KC_ERROR;
    }

    /* Parse JWKS JSON */
    json_error_t error;
    json_t *root = json_loads(chunk.response, 0, &error);
    free(chunk.response);

    if (!root) {
        kc_log_warning("Failed to parse JWKS: %s", error.text);
        free(url);
        return KC_ERROR;
    }

    json_t *keys = json_object_get(root, "keys");
    if (!json_is_array(keys)) {
        json_decref(root);
        free(url);
        return KC_ERROR;
    }

    /* Parse each signing key */
    size_t index;
    json_t *key;
    json_array_foreach(keys, index, key) {
        if (jwks_cache.key_count >= JWKS_MAX_KEYS) break;

        const char *kty = json_string_value(json_object_get(key, "kty"));
        const char *use = json_string_value(json_object_get(key, "use"));
        const char *alg = json_string_value(json_object_get(key, "alg"));
        const char *kid = json_string_value(json_object_get(key, "kid"));
        const char *n = json_string_value(json_object_get(key, "n"));
        const char *e_val = json_string_value(json_object_get(key, "e"));

        /* Only cache RSA signing keys (RS256) */
        if (!kty || strcmp(kty, "RSA") != 0) continue;
        if (use && strcmp(use, "sig") != 0) continue;  /* Skip encryption keys */
        if (alg && strcmp(alg, "RS256") != 0) continue;
        if (!kid || !n || !e_val) continue;

        EVP_PKEY *pkey = jwks_parse_rsa_key(n, e_val);
        if (!pkey) {
            kc_log_warning("Failed to parse RSA key kid=%s", kid);
            continue;
        }

        jwks_cache.keys[jwks_cache.key_count].kid = strdup(kid);
        jwks_cache.keys[jwks_cache.key_count].pkey = pkey;
        jwks_cache.key_count++;

        kc_log_debug("Cached JWKS key: kid=%s alg=%s", kid, alg ? alg : "RS256");
    }

    json_decref(root);

    if (jwks_cache.key_count == 0) {
        kc_log_warning("No usable signing keys in JWKS");
        free(url);
        return KC_ERROR;
    }

    jwks_cache.fetched = time(NULL);
    jwks_cache.realm_url = url;  /* Transfer ownership */

    kc_log_info("JWKS cache refreshed: %d keys", jwks_cache.key_count);
    return KC_SUCCESS;
}

/* Get cached key by kid */
static EVP_PKEY *
jwks_get_key(const char *kid)
{
    if (!kid) return NULL;

    for (int i = 0; i < jwks_cache.key_count; i++) {
        if (jwks_cache.keys[i].kid && strcmp(jwks_cache.keys[i].kid, kid) == 0) {
            return jwks_cache.keys[i].pkey;
        }
    }
    return NULL;
}

/* Verify JWT RS256 signature */
static int
jwt_verify_signature(const char *token, EVP_PKEY *pkey)
{
    if (!token || !pkey) return KC_ERROR;

    /* Find the two dots separating header.payload.signature */
    const char *dot1 = strchr(token, '.');
    if (!dot1) return KC_ERROR;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return KC_ERROR;

    /* The signed data is header.payload (everything before second dot) */
    size_t signed_len = dot2 - token;

    /* Decode signature */
    size_t sig_len = 0;
    unsigned char *sig = (unsigned char *)base64url_decode_alloc(dot2 + 1, &sig_len);
    if (!sig) return KC_ERROR;

    /* Verify RS256 signature */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(sig);
        return KC_ERROR;
    }

    int result = KC_ERROR;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1) {
        if (EVP_DigestVerifyUpdate(ctx, token, signed_len) == 1) {
            if (EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
                result = KC_SUCCESS;
            }
        }
    }

    EVP_MD_CTX_free(ctx);
    free(sig);
    return result;
}

/*
 * Parse LDAP generalized time format (YYYYMMDDHHMMSSZ) to epoch seconds.
 * Returns 0 on failure.
 */
static long
parse_ldap_time(const char *s)
{
    int y, mo, d, h, mi, sec;
    struct tm tm;

    if (!s || sscanf(s, "%4d%2d%2d%2d%2d%2d", &y, &mo, &d, &h, &mi, &sec) != 6)
        return 0;

    memset(&tm, 0, sizeof(tm));
    tm.tm_year = y - 1900;
    tm.tm_mon  = mo - 1;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min  = mi;
    tm.tm_sec  = sec;
    tm.tm_isdst = 0;

    /* LDAP generalized time is always UTC. Use timegm (POSIX.1-2024). */
    return (long)timegm(&tm);
}

/* Parse JWT claims from payload */
static int
jwt_parse_claims(const char *payload_b64, struct kc_token_info *info)
{
    if (!payload_b64 || !info) return KC_ERROR;

    size_t payload_len = 0;
    char *payload = base64url_decode_alloc(payload_b64, &payload_len);
    if (!payload) return KC_ERROR;

    /* Null-terminate for JSON parsing */
    char *json_str = malloc(payload_len + 1);
    if (!json_str) {
        free(payload);
        return KC_ERROR;
    }
    memcpy(json_str, payload, payload_len);
    json_str[payload_len] = '\0';
    free(payload);

    json_error_t error;
    json_t *root = json_loads(json_str, 0, &error);
    free(json_str);

    if (!root) {
        kc_log_debug("Failed to parse JWT claims: %s", error.text);
        return KC_ERROR;
    }

    /* Extract standard claims */
    json_t *exp = json_object_get(root, "exp");
    json_t *nbf = json_object_get(root, "nbf");
    json_t *iat = json_object_get(root, "iat");
    json_t *sub = json_object_get(root, "sub");
    json_t *iss = json_object_get(root, "iss");
    json_t *azp = json_object_get(root, "azp");
    json_t *preferred_username = json_object_get(root, "preferred_username");
    json_t *email = json_object_get(root, "email");

    time_t current_time = time(NULL);

    /* Expiration is mandatory.  A token with no exp claim would otherwise be
     * accepted forever, so treat a missing/invalid exp as a hard failure. */
    if (!json_is_integer(exp)) {
        kc_log_debug("JWT rejected: missing or invalid exp claim");
        json_decref(root);
        return KC_FORBIDDEN;
    }
    info->exp = json_integer_value(exp);
    if (info->exp <= current_time) {
        kc_log_debug("JWT expired: exp=%ld now=%ld", info->exp, (long)current_time);
        json_decref(root);
        return KC_FORBIDDEN;  /* Token expired */
    }

    /* Not-before: reject a token presented before its validity window opens.
     * Keycloak does not always emit nbf, so enforce it only when present, with
     * a small clock-skew tolerance. */
    if (json_is_integer(nbf)) {
        info->nbf = json_integer_value(nbf);
        if (info->nbf > current_time + KC_JWT_CLOCK_SKEW) {
            kc_log_debug("JWT not yet valid: nbf=%ld now=%ld", info->nbf, (long)current_time);
            json_decref(root);
            return KC_FORBIDDEN;
        }
    }

    if (json_is_integer(iat)) {
        info->iat = json_integer_value(iat);
    }

    /* Issuer and authorized-party: extracted for the caller's deployment
     * policy (expected-issuer + allowed-client checks).  The JWKS signature
     * already binds the token to the realm keys; these let the caller also
     * pin which realm URL and which client the token must come from. */
    if (json_is_string(iss)) {
        info->iss = strdup(json_string_value(iss));
        info->iss_size = strlen(info->iss);
    }

    if (json_is_string(azp)) {
        info->azp = strdup(json_string_value(azp));
        info->azp_size = strlen(info->azp);
    }

    if (json_is_string(sub)) {
        info->sub = strdup(json_string_value(sub));
        info->sub_size = strlen(info->sub);
    }

    if (json_is_string(preferred_username)) {
        info->username = strdup(json_string_value(preferred_username));
        info->username_size = strlen(info->username);
    }

    if (json_is_string(email)) {
        info->email = strdup(json_string_value(email));
        info->email_size = strlen(info->email);
    }

    /* Extract opserv level from custom claim if present */
    json_t *opserv_level = json_object_get(root, "x3_opserv_level");
    if (json_is_integer(opserv_level)) {
        info->opserv_level = json_integer_value(opserv_level);
    }

    /* Extract account creation time from custom claim (LDAP generalized time string) */
    json_t *created = json_object_get(root, "created_at");
    if (json_is_string(created)) {
        info->created_at = parse_ldap_time(json_string_value(created));
    }

    info->active = true;
    json_decref(root);
    return KC_SUCCESS;
}

/*
 * =============================================================================
 * Public API
 * =============================================================================
 */

int
kc_jwt_validate_local(struct kc_realm realm, const char *token,
                      struct kc_token_info **info_out)
{
    if (!token || !info_out) return KC_ERROR;
    *info_out = NULL;

    /* Ensure JWKS is cached */
    if (jwks_refresh(realm) != KC_SUCCESS) {
        jwt_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;  /* Can't validate locally, need fallback */
    }

    /* Parse JWT header to get kid */
    const char *dot1 = strchr(token, '.');
    if (!dot1) {
        kc_log_debug("Malformed JWT: no header separator");
        return KC_FORBIDDEN;  /* Not a valid JWT format - reject immediately */
    }

    size_t header_b64_len = dot1 - token;
    char *header_b64 = malloc(header_b64_len + 1);
    if (!header_b64) return KC_ERROR;
    memcpy(header_b64, token, header_b64_len);
    header_b64[header_b64_len] = '\0';

    size_t header_len = 0;
    char *header = base64url_decode_alloc(header_b64, &header_len);
    free(header_b64);
    if (!header) return KC_ERROR;

    /* Null-terminate for JSON parsing */
    char *header_json = malloc(header_len + 1);
    if (!header_json) {
        free(header);
        return KC_ERROR;
    }
    memcpy(header_json, header, header_len);
    header_json[header_len] = '\0';
    free(header);

    json_error_t error;
    json_t *hdr = json_loads(header_json, 0, &error);
    free(header_json);

    if (!hdr) {
        kc_log_debug("Malformed JWT header JSON: %s", error.text);
        return KC_FORBIDDEN;  /* Definitely not a valid JWT - reject immediately */
    }

    const char *alg = json_string_value(json_object_get(hdr, "alg"));
    const char *kid = json_string_value(json_object_get(hdr, "kid"));

    /* Only support RS256 */
    if (!alg || strcmp(alg, "RS256") != 0) {
        kc_log_debug("Unsupported JWT algorithm: %s", alg ? alg : "null");
        json_decref(hdr);
        jwt_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;  /* Fall back to introspection */
    }

    if (!kid) {
        kc_log_debug("JWT missing kid");
        json_decref(hdr);
        jwt_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;
    }

    /* Copy kid before freeing hdr - json_string_value returns pointer into JSON object */
    char *kid_copy = strdup(kid);
    json_decref(hdr);

    /* Get signing key */
    EVP_PKEY *pkey = jwks_get_key(kid_copy);
    if (!pkey) {
        kc_log_debug("Unknown kid in JWT: %s", kid_copy);
        free(kid_copy);
        jwt_stats.jwks_cache_misses++;  /* Need HTTP introspection */
        return KC_ERROR;  /* Unknown key - might need JWKS refresh or fallback */
    }
    free(kid_copy);

    /* Verify signature */
    if (jwt_verify_signature(token, pkey) != KC_SUCCESS) {
        kc_log_debug("JWT signature verification failed");
        return KC_FORBIDDEN;  /* Invalid signature */
    }

    /* Parse and validate claims */
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return KC_ERROR;

    size_t payload_b64_len = dot2 - dot1 - 1;
    char *payload_b64 = malloc(payload_b64_len + 1);
    if (!payload_b64) return KC_ERROR;
    memcpy(payload_b64, dot1 + 1, payload_b64_len);
    payload_b64[payload_b64_len] = '\0';

    struct kc_token_info *info = calloc(1, sizeof(*info));
    if (!info) {
        free(payload_b64);
        return KC_ERROR;
    }

    int result = jwt_parse_claims(payload_b64, info);
    free(payload_b64);

    if (result == KC_SUCCESS) {
        *info_out = info;
        jwt_stats.jwks_cache_hits++;  /* Validated locally, no HTTP needed */
        kc_log_debug("JWT validated locally: user=%s",
                     info->username ? info->username : "unknown");
    } else {
        kc_jwt_token_info_free(info);
    }

    return result;
}

void
kc_jwt_token_info_free(struct kc_token_info *info)
{
    if (!info) return;

    /* Free fields */
    kc_token_info_free(info);
    /* Free the struct itself (was calloc'd by kc_jwt_validate_local) */
    free(info);
}

/*
 * =============================================================================
 * Module Init / Cleanup / Stats
 * =============================================================================
 */

void
kc_jwt_init(void)
{
    memset(&jwt_stats, 0, sizeof(jwt_stats));
}

void
kc_jwt_cleanup(void)
{
    jwks_cleanup();
}

int
kc_jwt_prime_cache(struct kc_realm realm)
{
    return jwks_refresh(realm);
}

void
kc_jwt_stats_get(struct kc_jwt_stats *out)
{
    if (out) {
        *out = jwt_stats;
    }
}

long
kc_jwt_extract_created_at(const char *token)
{
    if (!token)
        return 0;

    /* Find payload between first and second '.' */
    const char *dot1 = strchr(token, '.');
    if (!dot1) return 0;
    const char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return 0;

    size_t payload_b64_len = dot2 - dot1 - 1;
    char *payload_b64 = malloc(payload_b64_len + 1);
    if (!payload_b64) return 0;
    memcpy(payload_b64, dot1 + 1, payload_b64_len);
    payload_b64[payload_b64_len] = '\0';

    size_t payload_len = 0;
    char *payload = base64url_decode_alloc(payload_b64, &payload_len);
    free(payload_b64);
    if (!payload) return 0;

    json_error_t error;
    json_t *root = json_loadb(payload, payload_len, 0, &error);
    free(payload);
    if (!root) return 0;

    long result = 0;
    json_t *created = json_object_get(root, "created_at");
    if (json_is_string(created)) {
        result = parse_ldap_time(json_string_value(created));
    }

    json_decref(root);
    return result;
}
