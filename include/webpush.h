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

#include "webpush_keyring.h"

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
  WEBPUSH_ERR_MEMORY  = -5,  /* Allocation failure */
  WEBPUSH_ERR_FORBIDDEN = -6 /* Push service refused the VAPID signature (HTTP 403) */
};

/* Subscription parsed from stored format */
struct webpush_subscription {
  char endpoint[WEBPUSH_MAX_ENDPOINT];
  unsigned char p256dh[WEBPUSH_P256DH_LEN];
  size_t p256dh_len;
  unsigned char auth[WEBPUSH_AUTH_LEN];
  size_t auth_len;
  char key_id[WEBPUSH_KEY_ID_LEN + 1];  /* VAPID key it was registered under; "" = unbound */
};

/* Async delivery callback */
typedef void (*webpush_send_cb)(int result, long http_code, void *data);

/*
 * VAPID key table (crypto layer).  The ring of keys this server holds is
 * modelled in webpush_keyring.h; every key it can sign with is loaded here
 * by id (base64url public key).  The CURRENT key is the one advertised in
 * the VAPID ISUPPORT token and used for subscriptions without a key id;
 * delivery signs with the key each subscription is bound to.
 */

/*
 * Load a P-256 private scalar (32 bytes) into the table, deriving its
 * public key = id.  When expect_id is non-empty the derived id must match
 * it (a stored/wire record naming a different key is corrupt): returns -2
 * on mismatch.  Re-loading an id already present replaces its key.
 * Returns 0 on success (id copied into id_out when given), -1 on error.
 */
int webpush_key_load(const unsigned char *privkey, size_t privkey_len,
                     const char *expect_id, char *id_out, size_t id_sz);

/* Drop a key from the table (no-op when absent). */
void webpush_key_unload(const char *id);

/* 1 when the table holds a key with this id. */
int webpush_key_loaded(const char *id);

/*
 * Generate a fresh P-256 keypair, load it, and export the private scalar
 * (priv_out, *priv_len >= 32 in; 32 out) and its id.  Returns 0 or -1.
 */
int webpush_key_generate(unsigned char *priv_out, size_t *priv_len,
                         char *id_out, size_t id_sz);

/*
 * Make a loaded key the current one (NULL/"" clears).  Returns -1 when
 * the id is not loaded.
 */
int webpush_set_current_key(const char *id);

/*
 * Shutdown the webpush subsystem.
 * Frees every loaded key.
 */
void webpush_cleanup(void);

/*
 * Get the current VAPID public key in base64url encoding.
 * Returns pointer to the table entry's id, or NULL if no current key.
 */
const char *webpush_get_vapid_pubkey(void);

/*
 * Parse subscription from stored format:
 *   "endpoint|p256dh_base64|auth_base64[|armed[|keyid]]"
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
 * Loads the key ring (or generates its first key), computes the current
 * key, advertises it, and starts the maintenance timer.
 * Must be called after webpush_store_init().  Safe to call again (REHASH,
 * config key change, maintenance retry).
 * Returns 0 on success, -1 on error.
 */
int webpush_setup(void);

/*
 * Record on a connection which VAPID key it was just told about (every
 * ISUPPORT emission calls this); WEBPUSH REGISTER binds the subscription
 * to that key, the only one the client can have used.
 */
void webpush_note_key_seen(struct Client *cptr);

/* STATS webpush */
struct StatDesc;
void webpush_report_stats(struct Client *to, const struct StatDesc *sd, char *param);

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
 * Design: docs/projects/push-payload-multiline.md in the Seance repo.
 *
 * full tier (the DEFAULT): one raw IRC line, no CRLF, as draft/webpush
 * requires -- the message as a client with server-time, message-tags and
 * account-tag would receive it:
 *
 *   @msgid=..;time=..;account=.. :nick!user@host PRIVMSG|NOTICE target :text
 *
 * A draft/multiline batch is one push PER LINE (WEBPUSH_MULTILINE_LINES at
 * most, itself clamped to at most 64), ordered by a vendor tag because a
 * batch shares one msgid and time:
 *
 *   @batch=<base msgid>;msgid=<base>;time=..;account=..;evilnet.github.io/line=<i>/<sent>/<total>[;draft/multiline-concat] :nick!user@host PRIVMSG|NOTICE target :line
 *
 * A read-marker relay is the MARKREAD line: ":server MARKREAD target timestamp=<ts>".
 *
 * route / ping tiers (account metadata draft/webpush/payload): JSON
 * opt-downs carrying no message -- {"t":KIND,"from":..,"target":..,
 * "msgid":..,"time":..} and {"t":KIND}; KIND is msg, notice or hl.
 * WEBPUSH_MAX_PAYLOAD bounds every body; an oversize payload is logged.
 *
 * The full tier carries the text exactly as sent, CTCP ACTION bytes
 * included (the JSON tiers carry no text); the client is responsible
 * for splitting the ACTION itself.
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

/** One line of a draft/multiline batch, for webpush_notify_multiline. */
struct webpush_batch_line {
  const char *text;
  int concat;   /**< non-zero when the line carried draft/multiline-concat */
};

/*
 * Multiline push trigger.  Called once per delivered batch from
 * process_multiline_batch (local) and deliver_s2s_multiline_batch (S2S),
 * after the message was delivered; exactly one of chptr / acptr is set.
 * The batch is one message: the highlight test runs over every line, the
 * cooldown is checked once per recipient, and then each of the first
 * WEBPUSH_MULTILINE_LINES lines goes out as its own push (one IRC message
 * per push, ordered by the evilnet.github.io/line tag).  The batch
 * reference is base_msgid.
 */
void webpush_notify_multiline(struct Client *sptr, struct Channel *chptr,
                              struct Client *acptr,
                              const struct webpush_batch_line *lines, int nlines,
                              const char *base_msgid, const char *timestamp,
                              int is_notice);

/** Relay an account read marker (MARKREAD set) as the line
 * ":<server> MARKREAD <target> timestamp=<iso>" so other devices can
 * close their notifications.  Ungated by hold/mute/cooldown on purpose. */
void webpush_notify_read(const char *account, const char *target,
                         const char *timestamp);

/** Drop every subscription of @a account here and on every peer (a
 * `WP U` per endpoint).  PERSISTENCE DETACH uses it. */
void webpush_forget_account(const char *account);

void webpush_notify_account(const char *account, const char *message,
                            size_t message_len);

#endif /* INCLUDED_webpush_h */
