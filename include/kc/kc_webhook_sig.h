/*
 * kc_webhook_sig.h - signature check and replay ring for the webhook listener.
 *
 * The SPI signs every delivery: X-Webhook-Signature: t=<unix>,v1=<hex
 * HMAC-SHA256(secret, "<t>." + body)>.  Verify in constant time, within a
 * window, and remember event ids for the window so a captured request cannot
 * be played back.  Pure: OpenSSL only, no ircd or libkc transport headers.
 */
#ifndef KC_WEBHOOK_SIG_H
#define KC_WEBHOOK_SIG_H

#include <stddef.h>

enum kc_sig_result {
    KC_SIG_OK = 0,
    KC_SIG_MISSING,     /* no X-Webhook-Signature header */
    KC_SIG_MALFORMED,   /* not t=<digits>,v1=<64 hex> */
    KC_SIG_STALE,       /* t outside now +/- window_s */
    KC_SIG_MISMATCH     /* digest differs, or no secret to verify against */
};

/* Verify header against body with secret.  window_s <= 0 disables the
 * time check.  On KC_SIG_OK, *t_out (if given) receives the header's t. */
enum kc_sig_result kc_webhook_sig_verify(const char *secret, const char *header,
                                         const char *body, size_t body_len,
                                         long long now, int window_s, long long *t_out);

/* "ok", "missing", "malformed", "stale", "mismatch". */
const char *kc_sig_result_name(enum kc_sig_result r);

#define KC_REPLAY_RING 256
struct kc_replay_ring {
    char      id[KC_REPLAY_RING][40];
    long long t[KC_REPLAY_RING];
    int       next;
};

void kc_replay_ring_init(struct kc_replay_ring *r);

/* 1 = id was seen within window_s of now (a replay).  0 = new; remembered.
 * NULL or empty ids are never replays. */
int  kc_replay_ring_seen(struct kc_replay_ring *r, const char *id, long long now, int window_s);

#endif /* KC_WEBHOOK_SIG_H */
