/*
 * kc_jwt_cmocka.c - unit tests for JWT claim validation (F-K3) and the
 * RS256 signature path (Phase 2 §2.3 item 4).
 *
 * jwt_parse_claims() is static and sits behind the JWKS fetch in
 * kc_jwt_validate_local(), so we #include the .c to reach it — the same
 * approach ircd_cloaking_cmocka.c and crule_cmocka.c use.
 *
 * The signature tests (OpenSSL 3.0+) generate a throwaway RSA keypair,
 * mint real RS256 tokens, and seed jwks_cache directly — jwks_refresh()
 * early-returns on a fresh matching cache, so no network is touched.
 * They cover jwt_verify_signature() (accept + tamper-reject), the
 * kc_jwt_validate_local() dispatch policy (alg pinning, unknown kid →
 * KC_ERROR fallback, never accept), and jwks_parse_rsa_key()'s
 * EVP_PKEY_fromdata reconstruction from JWKS n/e material.
 *
 * Payloads are base64url of:
 *   VALID       {"exp":4102444800,"sub":"u1","preferred_username":"alice"}
 *   NOEXP       {"sub":"u1","preferred_username":"alice"}
 *   EXPIRED     {"exp":1000000000,"sub":"u1"}
 *   FUTURE_NBF  {"exp":4102444800,"nbf":4102444800,"sub":"u1"}
 * exp 4102444800 = 2100-01-01; exp 1000000000 = 2001-09-09.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdlib.h>
#include <string.h>

#include <kc/kc_log.h>

const struct kc_log_ops *kc_get_log_ops(void);
const struct kc_log_ops *kc_get_log_ops(void) { return NULL; }

/*
 * kc_jwt_token_info_free() (compiled in below via #include, though no test
 * here calls it) calls kc_token_info_free(), which lives in kc_keycloak.c.
 * That object is not linked — it would drag in the whole async
 * Keycloak/curl-multi client for a symbol no test exercises — so stub it
 * here, same rationale as the kc_get_log_ops() stub above.
 */
struct kc_token_info;
void kc_token_info_free(struct kc_token_info *info);
void kc_token_info_free(struct kc_token_info *info) { (void)info; }

#include "../kc/kc_jwt.c"

#define P_VALID      "eyJleHAiOjQxMDI0NDQ4MDAsInN1YiI6InUxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2UifQ"
#define P_NOEXP      "eyJzdWIiOiJ1MSIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlIn0"
#define P_EXPIRED    "eyJleHAiOjEwMDAwMDAwMDAsInN1YiI6InUxIn0"
#define P_FUTURE_NBF "eyJleHAiOjQxMDI0NDQ4MDAsIm5iZiI6NDEwMjQ0NDgwMCwic3ViIjoidTEifQ"

static void free_info_fields(struct kc_token_info *i) {
    free(i->username); free(i->email); free(i->sub);
    free(i->iss); free(i->azp);
}

static void test_valid_claims_accepted(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_VALID, &info), KC_SUCCESS);
    assert_true(info.active);
    assert_int_equal(info.exp, 4102444800L);
    assert_string_equal(info.sub, "u1");
    assert_string_equal(info.username, "alice");
    free_info_fields(&info);
}

/* F-K3: a token with no exp would otherwise be valid forever. */
static void test_missing_exp_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_NOEXP, &info), KC_FORBIDDEN);
    free_info_fields(&info);
}

static void test_expired_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_EXPIRED, &info), KC_FORBIDDEN);
    free_info_fields(&info);
}

/* F-K3: nbf enforced when present, beyond the 60s skew tolerance. */
static void test_future_nbf_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_FUTURE_NBF, &info), KC_FORBIDDEN);
    free_info_fields(&info);
}

/* An absent nbf is not an error — Keycloak does not always emit it. */
static void test_absent_nbf_is_not_an_error(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    assert_int_equal(jwt_parse_claims(P_VALID, &info), KC_SUCCESS);
    assert_int_equal(info.nbf, 0);
    free_info_fields(&info);
}

static void test_garbage_payload_rejected(void **state) {
    (void)state;
    struct kc_token_info info;
    memset(&info, 0, sizeof info);
    int rc = jwt_parse_claims("!!!not-base64!!!", &info);
    assert_int_not_equal(rc, KC_SUCCESS);
    free_info_fields(&info);
}

static void test_extract_created_at_handles_malformed(void **state) {
    (void)state;
    assert_int_equal(kc_jwt_extract_created_at(NULL), 0);
    assert_int_equal(kc_jwt_extract_created_at("no-dots-here"), 0);
    assert_int_equal(kc_jwt_extract_created_at("only.one-dot"), 0);
}

/*
 * =============================================================================
 * RS256 signature path (OpenSSL 3.0+ only — same floor as the code under
 * test's EVP_PKEY_fromdata branch)
 * =============================================================================
 */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L

#define HDR_VALID   "{\"alg\":\"RS256\",\"kid\":\"testkid\"}"
#define HDR_BADKID  "{\"alg\":\"RS256\",\"kid\":\"otherkid\"}"
#define HDR_HS256   "{\"alg\":\"HS256\",\"kid\":\"testkid\"}"
#define HDR_NONE    "{\"alg\":\"none\",\"kid\":\"testkid\"}"
#define PAYLOAD_JSON "{\"exp\":4102444800,\"sub\":\"u1\",\"preferred_username\":\"alice\"}"

static const struct kc_realm test_realm = {
    .base_url = "http://kc.test",
    .realm    = "testrealm",
};

static EVP_PKEY *test_keypair;   /* group setup/teardown */

/* base64url (no padding) of arbitrary bytes, via EVP_EncodeBlock. */
static char *b64url(const unsigned char *in, size_t len) {
    char *std = malloc(((len + 2) / 3) * 4 + 1);
    assert_non_null(std);
    int out = EVP_EncodeBlock((unsigned char *)std, in, (int)len);
    for (int i = 0; i < out; i++) {
        if (std[i] == '+') std[i] = '-';
        else if (std[i] == '/') std[i] = '_';
        else if (std[i] == '=') { std[i] = '\0'; out = i; break; }
    }
    std[out] = '\0';
    return std;
}

/* Mint header.payload.signature signed with @a priv (RS256). */
static char *mint_token(EVP_PKEY *priv, const char *hdr_json,
                        const char *payload_json) {
    char *h64 = b64url((const unsigned char *)hdr_json, strlen(hdr_json));
    char *p64 = b64url((const unsigned char *)payload_json, strlen(payload_json));
    size_t body_len = strlen(h64) + 1 + strlen(p64);
    char *body = malloc(body_len + 1);
    assert_non_null(body);
    sprintf(body, "%s.%s", h64, p64);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    assert_non_null(ctx);
    assert_int_equal(EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv), 1);
    size_t siglen = 0;
    assert_int_equal(EVP_DigestSign(ctx, NULL, &siglen,
                                    (const unsigned char *)body, body_len), 1);
    unsigned char *sig = malloc(siglen);
    assert_non_null(sig);
    assert_int_equal(EVP_DigestSign(ctx, sig, &siglen,
                                    (const unsigned char *)body, body_len), 1);
    EVP_MD_CTX_free(ctx);

    char *s64 = b64url(sig, siglen);
    char *token = malloc(strlen(body) + 1 + strlen(s64) + 1);
    assert_non_null(token);
    sprintf(token, "%s.%s", body, s64);
    free(h64); free(p64); free(body); free(sig); free(s64);
    return token;
}

/* Seed jwks_cache so jwks_refresh(test_realm) early-returns without HTTP. */
static void seed_jwks_cache(EVP_PKEY *key, const char *kid) {
    jwks_cleanup();
    jwks_cache.keys[0].kid = strdup(kid);
    assert_int_equal(EVP_PKEY_up_ref(key), 1);   /* cleanup will free */
    jwks_cache.keys[0].pkey = key;
    jwks_cache.key_count = 1;
    jwks_cache.fetched = time(NULL);
    jwks_cache.realm_url = build_jwks_endpoint(test_realm);
    assert_non_null(jwks_cache.realm_url);
}

static int sig_group_setup(void **state) {
    (void)state;
    test_keypair = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    return test_keypair ? 0 : -1;
}

static int sig_group_teardown(void **state) {
    (void)state;
    jwks_cleanup();
    EVP_PKEY_free(test_keypair);
    test_keypair = NULL;
    return 0;
}

/* Full local validation: genuine token accepted, claims extracted. */
static void test_signed_token_validates_locally(void **state) {
    (void)state;
    char *token = mint_token(test_keypair, HDR_VALID, PAYLOAD_JSON);
    struct kc_token_info *info = NULL;
    seed_jwks_cache(test_keypair, "testkid");
    assert_int_equal(kc_jwt_validate_local(test_realm, token, &info), KC_SUCCESS);
    assert_non_null(info);
    assert_true(info->active);
    assert_string_equal(info->sub, "u1");
    assert_string_equal(info->username, "alice");
    free_info_fields(info);   /* kc_token_info_free is stubbed above */
    free(info);
    free(token);
}

/* One corrupted signature byte -> KC_FORBIDDEN, never accept. */
static void test_tampered_signature_rejected(void **state) {
    (void)state;
    char *token = mint_token(test_keypair, HDR_VALID, PAYLOAD_JSON);
    struct kc_token_info *info = NULL;
    char *sig = strrchr(token, '.') + 1;
    sig[0] = (sig[0] == 'A') ? 'B' : 'A';
    seed_jwks_cache(test_keypair, "testkid");
    assert_int_equal(kc_jwt_validate_local(test_realm, token, &info), KC_FORBIDDEN);
    assert_null(info);
    free(token);
}

/* Payload swapped after signing (signature covers header.payload). */
static void test_tampered_payload_rejected(void **state) {
    (void)state;
    char *good = mint_token(test_keypair, HDR_VALID, PAYLOAD_JSON);
    char *evil = mint_token(test_keypair, HDR_VALID,
        "{\"exp\":4102444800,\"sub\":\"u2\",\"preferred_username\":\"mallory\"}");
    /* graft good's signature onto evil's header.payload */
    char *gsig = strrchr(good, '.');
    char *esig = strrchr(evil, '.');
    *esig = '\0';
    char *frank = malloc(strlen(evil) + strlen(gsig) + 1);
    assert_non_null(frank);
    sprintf(frank, "%s%s", evil, gsig);
    struct kc_token_info *info = NULL;
    seed_jwks_cache(test_keypair, "testkid");
    assert_int_equal(kc_jwt_validate_local(test_realm, frank, &info), KC_FORBIDDEN);
    assert_null(info);
    free(good); free(evil); free(frank);
}

/* Unknown kid -> KC_ERROR (fall back to introspection), never accept. */
static void test_unknown_kid_falls_back(void **state) {
    (void)state;
    char *token = mint_token(test_keypair, HDR_BADKID, PAYLOAD_JSON);
    struct kc_token_info *info = NULL;
    seed_jwks_cache(test_keypair, "testkid");
    assert_int_equal(kc_jwt_validate_local(test_realm, token, &info), KC_ERROR);
    assert_null(info);
    free(token);
}

/* alg pinning: HS256 and none -> KC_ERROR fallback, never KC_SUCCESS
 * (the alg-confusion attack: an HS256 token "signed" with the public key
 * must not be verified as valid). */
static void test_alg_confusion_rejected(void **state) {
    (void)state;
    struct kc_token_info *info = NULL;
    seed_jwks_cache(test_keypair, "testkid");
    char *hs = mint_token(test_keypair, HDR_HS256, PAYLOAD_JSON);
    assert_int_equal(kc_jwt_validate_local(test_realm, hs, &info), KC_ERROR);
    assert_null(info);
    free(hs);
    char *none = mint_token(test_keypair, HDR_NONE, PAYLOAD_JSON);
    assert_int_equal(kc_jwt_validate_local(test_realm, none, &info), KC_ERROR);
    assert_null(info);
    free(none);
}

/* jwks_parse_rsa_key: reconstruct the public key from JWKS n/e material
 * (the EVP_PKEY_fromdata path) and verify a real signature with it. */
static void test_jwks_rsa_key_reconstruction(void **state) {
    (void)state;
    BIGNUM *n = NULL, *e = NULL;
    assert_int_equal(EVP_PKEY_get_bn_param(test_keypair, OSSL_PKEY_PARAM_RSA_N, &n), 1);
    assert_int_equal(EVP_PKEY_get_bn_param(test_keypair, OSSL_PKEY_PARAM_RSA_E, &e), 1);
    unsigned char nbin[512], ebin[16];
    int nlen = BN_bn2bin(n, nbin), elen = BN_bn2bin(e, ebin);
    assert_true(nlen > 0 && elen > 0);
    char *n64 = b64url(nbin, (size_t)nlen);
    char *e64 = b64url(ebin, (size_t)elen);
    BN_free(n); BN_free(e);

    EVP_PKEY *rebuilt = jwks_parse_rsa_key(n64, e64);
    assert_non_null(rebuilt);
    char *token = mint_token(test_keypair, HDR_VALID, PAYLOAD_JSON);
    assert_int_equal(jwt_verify_signature(token, rebuilt), KC_SUCCESS);
    char *sig = strrchr(token, '.') + 1;
    sig[0] = (sig[0] == 'A') ? 'B' : 'A';
    assert_int_not_equal(jwt_verify_signature(token, rebuilt), KC_SUCCESS);
    EVP_PKEY_free(rebuilt);
    free(token); free(n64); free(e64);
}

/* Garbage n/e must not yield a key. */
static void test_jwks_rsa_key_garbage_rejected(void **state) {
    (void)state;
    assert_null(jwks_parse_rsa_key("!!!", "AQAB"));
}

#endif /* OPENSSL_VERSION_NUMBER >= 3.0 */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_valid_claims_accepted),
        cmocka_unit_test(test_missing_exp_rejected),
        cmocka_unit_test(test_expired_rejected),
        cmocka_unit_test(test_future_nbf_rejected),
        cmocka_unit_test(test_absent_nbf_is_not_an_error),
        cmocka_unit_test(test_garbage_payload_rejected),
        cmocka_unit_test(test_extract_created_at_handles_malformed),
    };
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    const struct CMUnitTest sig_tests[] = {
        cmocka_unit_test(test_signed_token_validates_locally),
        cmocka_unit_test(test_tampered_signature_rejected),
        cmocka_unit_test(test_tampered_payload_rejected),
        cmocka_unit_test(test_unknown_kid_falls_back),
        cmocka_unit_test(test_alg_confusion_rejected),
        cmocka_unit_test(test_jwks_rsa_key_reconstruction),
        cmocka_unit_test(test_jwks_rsa_key_garbage_rejected),
    };
    int rc = cmocka_run_group_tests(tests, NULL, NULL);
    return rc | cmocka_run_group_tests(sig_tests, sig_group_setup,
                                       sig_group_teardown);
#else
    return cmocka_run_group_tests(tests, NULL, NULL);
#endif
}
