/*
 * webpush.h - Web Push notification crypto and delivery for Nefarious
 *
 * Implements RFC 8291 (Message Encryption for Web Push) and
 * RFC 8292 (VAPID - Voluntary Application Server Identification).
 *
 * Provides:
 *   - VAPID P-256 keypair generation and persistence
 *   - Web Push message encryption (aes128gcm content encoding)
 *   - VAPID JWT signing for Authorization headers
 *   - Async HTTP delivery via libkc
 *
 * Requires: OpenSSL 3.x, libkc (for async HTTP delivery)
 */

#ifndef INCLUDED_webpush_h
#define INCLUDED_webpush_h

#include <stddef.h>

/* Maximum sizes */
#define WEBPUSH_MAX_ENDPOINT   512   /* Endpoint URL */
#define WEBPUSH_MAX_PAYLOAD    4096  /* Plaintext message */
#define WEBPUSH_P256DH_LEN    65     /* Uncompressed P-256 public key */
#define WEBPUSH_AUTH_LEN      16     /* Subscription auth secret */
#define WEBPUSH_ENCRYPTED_MAX 4352   /* Encrypted payload + overhead */
#define WEBPUSH_VAPID_B64_LEN 88     /* base64url(65-byte pubkey) */

/* Result codes */
enum webpush_result {
  WEBPUSH_OK          =  0,
  WEBPUSH_ERR_CRYPTO  = -1,  /* Encryption or signing failure */
  WEBPUSH_ERR_HTTP    = -2,  /* HTTP delivery failure */
  WEBPUSH_ERR_EXPIRED = -3,  /* Subscription expired (HTTP 410) */
  WEBPUSH_ERR_INVALID = -4,  /* Invalid input */
  WEBPUSH_ERR_MEMORY  = -5   /* Allocation failure */
};

/* Subscription parsed from stored format */
struct webpush_subscription {
  char endpoint[WEBPUSH_MAX_ENDPOINT];
  unsigned char p256dh[WEBPUSH_P256DH_LEN];
  size_t p256dh_len;
  unsigned char auth[WEBPUSH_AUTH_LEN];
  size_t auth_len;
};

/* Async delivery callback */
typedef void (*webpush_send_cb)(int result, long http_code, void *data);

/*
 * Initialize the webpush subsystem.
 * Generates VAPID keypair if not already loaded.
 * Must be called after OpenSSL is initialized.
 * Returns 0 on success, -1 on error.
 */
int webpush_init(void);

/*
 * Shutdown the webpush subsystem.
 * Frees VAPID keypair.
 */
void webpush_cleanup(void);

/*
 * Get the VAPID public key in base64url encoding.
 * Returns pointer to static buffer, or NULL if not initialized.
 */
const char *webpush_get_vapid_pubkey(void);

/*
 * Get the raw VAPID public key bytes.
 * Returns pointer to 65-byte uncompressed P-256 point, or NULL.
 */
const unsigned char *webpush_get_vapid_pubkey_raw(size_t *out_len);

/*
 * Import VAPID keypair from raw bytes (for persistence/restore).
 * privkey: 32-byte private key scalar
 * pubkey: 65-byte uncompressed public key (optional, derived if NULL)
 * Returns 0 on success, -1 on error.
 */
int webpush_import_vapid_key(const unsigned char *privkey, size_t privkey_len,
                             const unsigned char *pubkey, size_t pubkey_len);

/*
 * Export VAPID private key bytes for persistence.
 * out: buffer to receive 32-byte private key
 * out_len: in/out buffer size
 * Returns 0 on success, -1 on error.
 */
int webpush_export_vapid_privkey(unsigned char *out, size_t *out_len);

/*
 * Import VAPID private key from base64url-encoded string.
 * Decodes and delegates to webpush_import_vapid_key().
 * Returns 0 on success, -1 on error.
 */
int webpush_import_vapid_key_b64(const char *b64, size_t b64_len);

/*
 * Parse subscription from stored format: "endpoint|p256dh_base64|auth_base64"
 * Returns 0 on success, -1 on parse error.
 */
int webpush_parse_subscription(const char *stored,
                               struct webpush_subscription *sub);

/*
 * Encrypt a message for a subscription using RFC 8291 aes128gcm encoding.
 *
 * sub: parsed subscription with client public key and auth secret
 * plaintext: message to encrypt
 * plaintext_len: message length
 * out: buffer for encrypted payload (must be WEBPUSH_ENCRYPTED_MAX bytes)
 * out_len: receives actual output length
 *
 * Returns 0 on success, -1 on error.
 */
int webpush_encrypt(const struct webpush_subscription *sub,
                    const unsigned char *plaintext, size_t plaintext_len,
                    unsigned char *out, size_t *out_len);

/*
 * Send an encrypted push notification asynchronously via libkc HTTP.
 *
 * sub: parsed subscription (endpoint URL used for POST)
 * encrypted: encrypted payload from webpush_encrypt()
 * encrypted_len: payload length
 * ttl: TTL in seconds (0 for default 86400)
 * cb: completion callback (may be NULL for fire-and-forget)
 * cb_data: opaque data for callback
 *
 * Returns 0 if request was submitted, -1 on error.
 */
int webpush_send_async(const struct webpush_subscription *sub,
                       const unsigned char *encrypted, size_t encrypted_len,
                       unsigned long ttl,
                       webpush_send_cb cb, void *cb_data);

/*
 * High-level: encrypt and send a push notification to a subscription.
 * Combines webpush_encrypt() + webpush_send_async().
 *
 * Returns 0 if request was submitted, -1 on error.
 */
int webpush_notify(const struct webpush_subscription *sub,
                   const char *message, size_t message_len,
                   webpush_send_cb cb, void *cb_data);

/*
 * IRCd-level webpush functions (defined in m_webpush.c)
 * These depend on IRCd internals (Client structs, P10, LMDB store).
 */

struct Client;

/*
 * Initialize webpush subsystem with VAPID key persistence.
 * Loads or generates VAPID key, broadcasts to linked servers.
 * Must be called after webpush_store_init().
 * Returns 0 on success, -1 on error.
 */
int webpush_setup(void);

/*
 * Burst all webpush subscriptions to a newly linked server.
 * Called during server link burst phase.
 */
void webpush_burst(struct Client *cptr);

/*
 * Send push notifications to all subscriptions for an account.
 * Called from message relay path for locally-originated messages.
 */
struct Client;

/*
 * Push payload wire contract (consumed by the seance service worker).
 *
 * The encrypted aes128gcm body is one compact JSON object, `{"t":KIND,...}`:
 *
 *   "msg"     DM to the account: from=<sender nick>
 *   "notice"  as "msg", for NOTICE
 *   "hl"      channel message in target mentioning the account
 *   "read"    read-marker relay: {"t":"read","target":T,"ts":TIME};
 *             ungated by hold/mute/cooldown so devices can close
 *             notifications
 *
 * Non-"read" payloads carry the route fields `from`, `target` (a nick for
 * msg/notice, a channel for hl), optional `msgid` and `time` (ISO 8601),
 * and — full tier only — `text` plus `trunc:true` when the text was
 * clamped.  WEBPUSH_MAX_PAYLOAD bounds the whole body.
 *
 * The tier comes from the account's `draft/webpush/payload` metadata:
 *   "ping"   bare notification, no route fields
 *   "route"  from/target/msgid/time, no text
 *   "full"   route + text — the default; the body is encrypted
 *            server-to-device, so accounts must opt down explicitly
 *
 * Mutes come from `draft/webpush/mute`: ';'-separated `target:until`
 * entries (unix seconds; `*` is a global snooze; 0 or negative =
 * indefinite), checked per push against the sender/channel and pruned by
 * writers.
 */

/*
 * PM/NOTICE push trigger (v1, design: webpush-trigger-payload.md).
 * Called from the PM delivery path; sends a push to the target's
 * subscriptions iff the target is a held bouncer session with
 * subscriptions, FEAT_WEBPUSH_NOTIFY is on, and the per-(account,
 * sender) cooldown passes.  Payload tier (ping/route/full) comes from
 * the account's draft/webpush/payload metadata key (default: full).
 */
void webpush_notify_pm(struct Client *sptr, struct Client *acptr,
                       const char *text, int is_notice,
                       const char *msgid, const char *timestamp);

struct Channel;

/*
 * Channel-highlight push trigger (v2, design: webpush-trigger-payload.md).
 * Called from the channel PRIVMSG store path; pushes to held members
 * whose nick the message mentions (word-boundary, casemapped), same
 * gate stack as the PM trigger plus FEAT_WEBPUSH_HIGHLIGHTS.
 */
void webpush_notify_channel(struct Client *sptr, struct Channel *chptr,
                            const char *text, const char *msgid,
                            const char *timestamp);

/** Relay an account read marker (MARKREAD set) as a `{"t":"read",...}`
 * payload so other devices can close their notifications.  Ungated by
 * hold/mute/cooldown on purpose. */
void webpush_notify_read(const char *account, const char *target,
                         const char *timestamp);

/** Drop every subscription of @a account here and on every peer (a
 * `WP U` per endpoint).  PERSISTENCE DETACH uses it. */
void webpush_forget_account(const char *account);

void webpush_notify_account(const char *account, const char *message,
                            size_t message_len);

#endif /* INCLUDED_webpush_h */
