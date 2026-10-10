/*
 * kc_webhook_sig.c - signature check and replay ring for the webhook listener.
 * See kc/kc_webhook_sig.h.  Pure: OpenSSL and libc only.
 */
#include <kc/kc_webhook_sig.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

enum kc_sig_result kc_webhook_sig_verify(const char *secret, const char *header,
                                         const char *body, size_t body_len,
                                         long long now, int window_s, long long *t_out)
{
    const char *p, *v;
    char tbuf[24];
    size_t i, tl;
    long long t;
    unsigned char given[32], mac[32];
    unsigned int mac_len = 0;
    HMAC_CTX *ctx;

    if (!secret || !secret[0])
        return KC_SIG_MISMATCH;
    if (!header || !header[0])
        return KC_SIG_MISSING;

    /* t=<digits>,v1=<64 hex>: the shape is checked before anything touches
     * the key, and the window before the HMAC (a stale request is cheap to
     * refuse). */
    if (strncmp(header, "t=", 2) != 0)
        return KC_SIG_MALFORMED;
    p = header + 2;
    for (tl = 0; p[tl] && p[tl] != ','; tl++) {
        if (!isdigit((unsigned char)p[tl]) || tl >= sizeof(tbuf) - 1)
            return KC_SIG_MALFORMED;
    }
    if (tl == 0 || p[tl] != ',')
        return KC_SIG_MALFORMED;
    memcpy(tbuf, p, tl);
    tbuf[tl] = '\0';
    t = strtoll(tbuf, NULL, 10);
    v = p + tl + 1;
    if (strncmp(v, "v1=", 3) != 0)
        return KC_SIG_MALFORMED;
    v += 3;
    if (strlen(v) != 64)
        return KC_SIG_MALFORMED;
    for (i = 0; i < 32; i++) {
        int hi = hexval(v[2 * i]), lo = hexval(v[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return KC_SIG_MALFORMED;
        given[i] = (unsigned char)(hi * 16 + lo);
    }
    if (window_s > 0 && (now - t > window_s || t - now > window_s))
        return KC_SIG_STALE;

    ctx = HMAC_CTX_new();
    if (!ctx)
        return KC_SIG_MISMATCH;
    if (HMAC_Init_ex(ctx, secret, (int)strlen(secret), EVP_sha256(), NULL) != 1
        || HMAC_Update(ctx, (const unsigned char *)tbuf, tl) != 1
        || HMAC_Update(ctx, (const unsigned char *)".", 1) != 1
        || HMAC_Update(ctx, (const unsigned char *)body, body_len) != 1
        || HMAC_Final(ctx, mac, &mac_len) != 1) {
        HMAC_CTX_free(ctx);
        return KC_SIG_MISMATCH;
    }
    HMAC_CTX_free(ctx);
    if (mac_len != 32 || CRYPTO_memcmp(mac, given, 32) != 0)
        return KC_SIG_MISMATCH;
    if (t_out)
        *t_out = t;
    return KC_SIG_OK;
}

const char *kc_sig_result_name(enum kc_sig_result r)
{
    switch (r) {
    case KC_SIG_OK:        return "ok";
    case KC_SIG_MISSING:   return "missing";
    case KC_SIG_MALFORMED: return "malformed";
    case KC_SIG_STALE:     return "stale";
    case KC_SIG_MISMATCH:
    default:               return "mismatch";
    }
}

void kc_replay_ring_init(struct kc_replay_ring *r)
{
    memset(r, 0, sizeof(*r));
}

enum kc_ring_verdict kc_replay_ring_check(struct kc_replay_ring *r, const char *id, long long t)
{
    int i;

    if (!r || !id || !id[0])
        return KC_RING_NEW;
    for (i = 0; i < KC_REPLAY_RING; i++) {
        if (r->id[i][0] && strcmp(r->id[i], id) == 0) {
            if (t > r->t[i]) {
                r->t[i] = t;            /* the sender signed it again: its retry */
                return KC_RING_DUPLICATE;
            }
            return KC_RING_REPLAY;      /* no newer than the last accepted copy */
        }
    }
    snprintf(r->id[r->next], sizeof(r->id[r->next]), "%s", id);
    r->t[r->next] = t;
    r->next = (r->next + 1) % KC_REPLAY_RING;
    return KC_RING_NEW;
}

void kc_replay_ring_forget(struct kc_replay_ring *r, const char *id)
{
    int i;

    if (!r || !id || !id[0])
        return;
    for (i = 0; i < KC_REPLAY_RING; i++) {
        if (r->id[i][0] && strcmp(r->id[i], id) == 0) {
            r->id[i][0] = '\0';
            r->t[i] = 0;
            return;
        }
    }
}
