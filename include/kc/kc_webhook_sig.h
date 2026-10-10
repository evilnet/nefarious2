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
    long long t[KC_REPLAY_RING];      /* newest signature time accepted for that id */
    int       next;
};

enum kc_ring_verdict {
    KC_RING_NEW = 0,     /* first sighting of the id: remembered */
    KC_RING_DUPLICATE,   /* same id, a newer signature: the sender signed it again (its retry); remembered */
    KC_RING_REPLAY       /* same id, a signature no newer than the last accepted one: a copy played back */
};

void kc_replay_ring_init(struct kc_replay_ring *r);

/* Classify a request whose signature already verified, by its event id and
 * the signature's time t.  Only a holder of the secret can make a newer
 * valid signature, so a known id with a newer t is the sender's own retry
 * (answer it, do not act again); anything not newer is a replay.  NULL or
 * empty ids are always new and are not remembered. */
enum kc_ring_verdict kc_replay_ring_check(struct kc_replay_ring *r, const char *id, long long t);

/* Drop an id the caller could not act on after all (the queue was full), so
 * the sender's retry is new rather than a duplicate that would be dropped. */
void kc_replay_ring_forget(struct kc_replay_ring *r, const char *id);

#endif /* KC_WEBHOOK_SIG_H */
