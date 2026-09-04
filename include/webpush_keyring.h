/*
 * webpush_keyring.h - the VAPID key ring (pure decision logic).
 *
 * A server holds a SET of immutable VAPID keys.  Each key is identified by
 * its base64url public key and carries the private scalar, the generation
 * it was minted at, its creation time, the server that minted it and a
 * manual flag (imported from WEBPUSH_VAPID_PRIVKEY by an operator).
 *
 * Rings merge by union (webpush_keyring_add is idempotent by id), so the
 * exchange between servers (WP K, see m_webpush.c) is order-free.  The
 * CURRENT key -- the one advertised in the VAPID ISUPPORT token and used
 * for new registrations -- is never replicated; every server computes it
 * from its ring with webpush_keyring_current():
 *
 *   highest generation wins; among equals the oldest `created` wins;
 *   remaining ties break on the id bytes.
 *
 * So a freshly booted server's generation-0 key never displaces an
 * established network's key, a deliberate rotation (generation max+1)
 * wins everywhere once it replicates, and two sides of a split that both
 * rotated converge on the older of the two.  A key that is in the ring
 * and not current is "retired": it still signs every subscription bound to
 * it and is pruned (webpush_key_prunable) once nothing here references it
 * and a grace period has passed.
 *
 * Subscription records bind to a key by id in their 5th field:
 * "endpoint|p256dh|auth|armed|keyid" (webpush_record_key_id).
 *
 * Pure: no ircd dependencies; unit-tested in
 * ircd/test/webpush_keyring_cmocka.c.
 */
#ifndef INCLUDED_webpush_keyring_h
#define INCLUDED_webpush_keyring_h

#include <stddef.h>

/** base64url of a 65-byte uncompressed P-256 point is 87 characters. */
#define WEBPUSH_KEY_ID_LEN      88
#define WEBPUSH_KEY_ORIGIN_LEN  63
#define WEBPUSH_KEY_PRIV_LEN    32
/** Longest serialized key record ("gen|created|origin|manual|priv"). */
#define WEBPUSH_KEY_TEXT_LEN    160
/** Ring capacity.  Pruning keeps a live ring to a handful of keys. */
#define WEBPUSH_KEYRING_MAX     16

struct webpush_key {
  char          id[WEBPUSH_KEY_ID_LEN + 1];     /**< base64url public key */
  unsigned char priv[WEBPUSH_KEY_PRIV_LEN];     /**< P-256 private scalar */
  unsigned int  generation;                     /**< 0 = boot key; rotation = max+1 */
  long long     created;                        /**< unix seconds minted */
  char          origin[WEBPUSH_KEY_ORIGIN_LEN + 1]; /**< server that minted it */
  int           manual;                         /**< imported from config */
  int           refs;                           /**< local subscriptions bound (caller-maintained) */
};

struct webpush_keyring {
  struct webpush_key keys[WEBPUSH_KEYRING_MAX];
  int count;
};

void webpush_keyring_init(struct webpush_keyring *ring);

/** The key with this id, or NULL. */
struct webpush_key *webpush_keyring_find(struct webpush_keyring *ring,
                                         const char *id);

/** Union-add: 1 when added, 0 when a key with that id was already present
 * (the existing entry is left untouched -- keys are immutable), -1 when the
 * key is invalid or the ring is full. */
int webpush_keyring_add(struct webpush_keyring *ring,
                        const struct webpush_key *key);

/** Remove the key with this id: 1 removed, 0 not present. */
int webpush_keyring_remove(struct webpush_keyring *ring, const char *id);

/** The current key by the rule above, or NULL for an empty ring. */
const struct webpush_key *webpush_keyring_current(const struct webpush_keyring *ring);

/** Generation for a key minted now: max(generation) + 1, or 0 when the
 * ring is empty. */
unsigned int webpush_keyring_next_generation(const struct webpush_keyring *ring);

/** Total order used for the current rule: negative when `a` ranks ahead
 * of `b` (should be current over it), positive when behind, 0 same id. */
int webpush_key_compare(const struct webpush_key *a,
                        const struct webpush_key *b);

/** 1 when `key` (a member of `ring`) may be dropped: it is not current and
 * either nothing local references it (refs == 0) and it is at least
 * `grace` seconds old, or, with `expire` > 0, it is older than `expire`
 * seconds at `now` -- past that, subscriptions bound to it have aged out
 * on the same clock.  The grace covers the window in which a peer's
 * registration bound to the key (a client that saw it in ISUPPORT) can
 * still arrive after the key was retired here. */
int webpush_key_prunable(const struct webpush_keyring *ring,
                         const struct webpush_key *key,
                         long long now, long long expire, long long grace);

/** Serialize a key (everything but its id) as
 * "gen|created|origin|manual|priv_b64url" for the store and the WP K
 * wire.  Returns 0, or -1 when `out` cannot hold it. */
int webpush_key_format(const struct webpush_key *key, char *out, size_t outsz);

/** Parse the record produced by webpush_key_format for key `id`.  Returns
 * 0 and fills `out` (refs = 0), -1 on a malformed record. */
int webpush_key_parse(const char *id, const char *text, struct webpush_key *out);

/** Copy the key id from a stored subscription record
 * ("endpoint|p256dh|auth|armed|keyid") into `out`.  Returns 0 when the
 * record carries one, 1 when it does not (pre-ring record), -1 when `out`
 * is too small. */
int webpush_record_key_id(const char *stored, char *out, size_t outsz);

/** Unpadded base64url helpers shared with the crypto layer.  Encode
 * returns the length written (NUL-terminated) or -1; decode returns 0 and
 * sets *out_len, or -1 on bad input / overflow. */
int webpush_b64url_encode(const unsigned char *in, size_t in_len,
                          char *out, size_t out_size);
int webpush_b64url_decode(const char *in, size_t in_len,
                          unsigned char *out, size_t out_size,
                          size_t *out_len);

#endif /* INCLUDED_webpush_keyring_h */
