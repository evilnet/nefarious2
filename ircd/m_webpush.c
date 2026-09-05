/*
 * IRC - Internet Relay Chat, ircd/m_webpush.c
 * Copyright (C) 2024 Nefarious Development Team
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Handler for WEBPUSH command (IRCv3 draft/webpush).
 *
 * Specification: https://github.com/ircv3/ircv3-specifications/pull/471
 *
 * Subcommands:
 *   REGISTER <endpoint> <keys>
 *   UNREGISTER <endpoint>
 *
 * This implementation handles webpush subscriptions locally using LMDB for
 * persistent storage and the webpush crypto library for VAPID key management
 * and push delivery. Subscriptions are synchronized across linked servers
 * via P10 WP token.
 *
 * P10 server-to-server subcommands:
 *   WP K <id> <gen> <created> <origin> <manual> :<priv>  - Key ring entry (burst + rotation)
 *   WP V :<vapid_pubkey>                                  - Advertised key (legacy, advisory)
 *   WP R <account> <endpoint> <p256dh> <auth> <armed> <keyid|->  - Register subscription
 *   WP U <account> <endpoint>                             - Unregister subscription
 *   WP B <account> <endpoint> <p256dh> <auth> <armed> <keyid|->  - Burst subscription on link
 *
 * VAPID keys form a ring (webpush_keyring.h): every server holds every key,
 * the current key is computed locally by one rule, subscriptions bind to
 * the key their client saw in ISUPPORT, and delivery signs with that key.
 * Design: .claude/para/projects/webpush-vapid-key-plan.md (testnet repo).
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_user.h"
#include "send.h"
#include "webpush.h"
#include "webpush_keyring.h"
#include "webpush_attention.h"
#include "webpush_mute.h"
#include "webpush_expiry.h"
#include "webpush_store.h"
#include "bouncer_session.h"
#include "channel.h"
#include "ircd_events.h"
#include "metadata.h"
#include "s_stats.h"

#ifdef HAVE_JANSSON
#include <jansson.h>
#endif

static void webpush_subs_cache_invalidate(const char *account);
static int webpush_store_count_cached(const char *account);
static int webpush_pm_cooldown_ok(const char *account, const char *origin);
static long long webpush_wire_armed(int parc, char *parv[]);
static const char *webpush_wire_keyid(int parc, char *parv[]);
static void webpush_store_receive(const char *account, const char *endpoint,
                                  const char *p256dh, const char *auth_secret,
                                  long long armed, const char *keyid);
static void webpush_forbidden(const char *account, const char *endpoint);
static void webpush_delivered(const char *account, const char *endpoint);
static int webpush_cooldown_ok(const char *account, const char *origin,
                               int cd, const char *ns);

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

/** Maximum endpoint URL length */
#define WEBPUSH_MAX_ENDPOINT_LEN 512

/** Maximum p256dh key length (base64) */
#define WEBPUSH_MAX_P256DH 128

/** Maximum auth secret length (base64) */
#define WEBPUSH_MAX_AUTH 32

/** Send a FAIL response using standard-replies format.
 * @param[in] sptr Client to send to.
 * @param[in] code Error code.
 * @param[in] context Context (subcommand).
 * @param[in] message Human-readable message.
 */
static void send_webpush_fail(struct Client *sptr, const char *code,
                              const char *context, const char *message)
{
  sendrawto_one(sptr, "FAIL WEBPUSH %s %s :%s",
                code, context ? context : "*", message);
}

/** Check if an endpoint URL is valid (HTTPS only, no internal IPs).
 * @param[in] endpoint The endpoint URL to validate.
 * @return 1 if valid, 0 otherwise.
 */
static int is_valid_endpoint(const char *endpoint)
{
  /* Must start with https:// */
  if (strncmp(endpoint, "https://", 8) != 0)
    return 0;

  /* Check length */
  if (strlen(endpoint) > WEBPUSH_MAX_ENDPOINT_LEN)
    return 0;

  /* Block localhost and private IPs */
  if (strstr(endpoint, "://localhost") ||
      strstr(endpoint, "://127.") ||
      strstr(endpoint, "://10.") ||
      strstr(endpoint, "://192.168.") ||
      strstr(endpoint, "://172.16.") ||
      strstr(endpoint, "://172.17.") ||
      strstr(endpoint, "://172.18.") ||
      strstr(endpoint, "://172.19.") ||
      strstr(endpoint, "://172.2") ||
      strstr(endpoint, "://172.30.") ||
      strstr(endpoint, "://172.31.") ||
      strstr(endpoint, "://[::1]") ||
      strstr(endpoint, "://[fe80:") ||
      strstr(endpoint, "://[fc") ||
      strstr(endpoint, "://[fd"))
    return 0;

  return 1;
}

/** Parse keys parameter in format "p256dh=...;auth=..."
 * @param[in] keys The keys string to parse.
 * @param[out] p256dh Buffer to receive p256dh key.
 * @param[in] p256dh_size Size of p256dh buffer.
 * @param[out] auth Buffer to receive auth secret.
 * @param[in] auth_size Size of auth buffer.
 * @return 1 if parsed successfully, 0 otherwise.
 */
static int parse_keys(const char *keys, char *p256dh, size_t p256dh_size,
                      char *auth, size_t auth_size)
{
  const char *p256dh_start, *auth_start;
  const char *p256dh_end, *auth_end;

  /* Find p256dh= */
  p256dh_start = strstr(keys, "p256dh=");
  if (!p256dh_start)
    return 0;
  p256dh_start += 7; /* skip "p256dh=" */

  /* Find end of p256dh (semicolon or end of string) */
  p256dh_end = strchr(p256dh_start, ';');
  if (!p256dh_end)
    p256dh_end = keys + strlen(keys);

  /* Find auth= */
  auth_start = strstr(keys, "auth=");
  if (!auth_start)
    return 0;
  auth_start += 5; /* skip "auth=" */

  /* Find end of auth (semicolon or end of string) */
  auth_end = strchr(auth_start, ';');
  if (!auth_end)
    auth_end = keys + strlen(keys);

  /* Check lengths */
  if ((size_t)(p256dh_end - p256dh_start) >= p256dh_size ||
      (size_t)(auth_end - auth_start) >= auth_size)
    return 0;

  /* Copy values */
  /* Copy values.  ircd_strncpy copies at most len-1 chars (strlcpy
   * semantics), so pass the value length + 1 — the destination buffers
   * have room for the full value plus the NUL.  With the bare length a
   * full-size browser key (87-char p256dh, 22-char auth) lost its last
   * char(s), the point then decoded to 64 bytes and failed the 65-byte
   * check, and every push silently skipped in notify_iter_cb. */
  ircd_strncpy(p256dh, p256dh_start, p256dh_end - p256dh_start + 1);
  p256dh[p256dh_end - p256dh_start] = '\0';

  ircd_strncpy(auth, auth_start, auth_end - auth_start + 1);
  auth[auth_end - auth_start] = '\0';

  /* Basic validation - should be non-empty base64 */
  if (!*p256dh || !*auth)
    return 0;

  return 1;
}

/** Handle WEBPUSH REGISTER subcommand.
 * Stores the subscription locally in LMDB and broadcasts to linked servers.
 * @param[in] sptr Source client.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
static int webpush_cmd_register(struct Client *sptr, int parc, char *parv[])
{
  const char *endpoint;
  const char *keys;
  char p256dh[WEBPUSH_MAX_P256DH];
  char auth[WEBPUSH_MAX_AUTH];
  char stored[4096];
  const char *keyid;

  /* WEBPUSH REGISTER <endpoint> <keys> */
  if (parc < 4) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "REGISTER",
                      "Usage: WEBPUSH REGISTER <endpoint> <keys>");
    return 0;
  }

  endpoint = parv[2];
  keys = parv[3];

  /* Must be authenticated */
  if (!IsAccount(sptr)) {
    send_webpush_fail(sptr, "ACCOUNT_REQUIRED", "REGISTER",
                      "You must be logged in to register for push notifications");
    return 0;
  }

  /* Validate endpoint */
  if (!is_valid_endpoint(endpoint)) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "REGISTER",
                      "Invalid push endpoint (must be HTTPS, no internal IPs)");
    return 0;
  }

  /* Parse keys */
  if (!parse_keys(keys, p256dh, sizeof(p256dh), auth, sizeof(auth))) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "REGISTER",
                      "Invalid keys format (expected p256dh=...;auth=...)");
    return 0;
  }

  /* Check if store is available */
  if (!webpush_store_available()) {
    send_webpush_fail(sptr, "INTERNAL_ERROR", "REGISTER",
                      "Push subscription storage is not available");
    return 0;
  }

  /* Cap per account (spec: FAIL WEBPUSH MAX_REGISTRATIONS).  A re-REGISTER
   * of an endpoint already held re-arms it and never counts against the
   * cap; without a cap one account could register thousands of endpoints
   * and fan every message out to all of them. */
  {
    int max = feature_int(FEAT_WEBPUSH_MAX_REGISTRATIONS);
    char existing[4096];
    if (max > 0
        && webpush_store_get(cli_user(sptr)->account, endpoint,
                             existing, sizeof(existing)) != 0
        && webpush_store_count(cli_user(sptr)->account) >= max) {
      sendrawto_one(sptr, "FAIL WEBPUSH MAX_REGISTRATIONS REGISTER %s "
                    ":This account already has %d push registrations",
                    endpoint, max);
      return 0;
    }
  }

  /* The key this client registered under is the one in the last VAPID
   * ISUPPORT token it was sent (webpush_note_key_seen), not whatever is
   * current now: a rotation between the client's 005 and its REGISTER
   * must not mis-bind the subscription.  A connection that never saw a
   * token (none existed) binds to the current key if one exists since. */
  keyid = cli_vapid_seen(sptr)[0] ? cli_vapid_seen(sptr) : webpush_get_vapid_pubkey();
  if (!keyid)
    keyid = "";

  /* Build stored format: "endpoint|p256dh|auth|armed|keyid" -- the arming
   * timestamp is this REGISTER (clients re-arm on every login; the
   * expiry sweep removes records not re-armed within
   * FEAT_WEBPUSH_EXPIRE). */
  snprintf(stored, sizeof(stored), "%s|%s|%s|%lld|%s", endpoint, p256dh, auth,
           (long long)CurrentTime, keyid);

  /* Store locally in LMDB */
  webpush_subs_cache_invalidate(cli_user(sptr)->account);
  if (webpush_store_add(cli_user(sptr)->account, stored) != 0) {
    send_webpush_fail(sptr, "INTERNAL_ERROR", "REGISTER",
                      "Failed to store push subscription");
    return 0;
  }

  /* Broadcast to all linked servers */
  /* The arming time rides the wire (trailing param; older peers read
   * parv[2..5] and ignore it) so every server ages the record from the
   * same instant. */
  sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "R %s %s %s %s %lld %s",
                        cli_user(sptr)->account, endpoint, p256dh, auth,
                        (long long)CurrentTime, keyid[0] ? keyid : "-");

  /* Echo success to client per spec */
  sendrawto_one(sptr, "WEBPUSH REGISTER %s", endpoint);

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBPUSH: %s!%s@%s registered endpoint for account %s",
            cli_name(sptr), cli_user(sptr)->username,
            cli_user(sptr)->host, cli_user(sptr)->account);

  return 0;
}

/** Handle WEBPUSH UNREGISTER subcommand.
 * Removes the subscription from LMDB and broadcasts to linked servers.
 * @param[in] sptr Source client.
 * @param[in] parc Parameter count.
 * @param[in] parv Parameters.
 * @return 0 on success.
 */
static int webpush_cmd_unregister(struct Client *sptr, int parc, char *parv[])
{
  const char *endpoint;

  /* WEBPUSH UNREGISTER <endpoint> */
  if (parc < 3) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "UNREGISTER",
                      "Usage: WEBPUSH UNREGISTER <endpoint>");
    return 0;
  }

  endpoint = parv[2];

  /* Must be authenticated */
  if (!IsAccount(sptr)) {
    send_webpush_fail(sptr, "ACCOUNT_REQUIRED", "UNREGISTER",
                      "You must be logged in to unregister push notifications");
    return 0;
  }

  /* Remove locally from LMDB */
  if (webpush_store_available()) {
    webpush_subs_cache_invalidate(cli_user(sptr)->account);
    webpush_store_remove(cli_user(sptr)->account, endpoint);
  }

  /* Broadcast to all linked servers */
  sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "U %s %s",
                        cli_user(sptr)->account, endpoint);

  /* Echo success to client per spec (silently succeeds even if not registered) */
  sendrawto_one(sptr, "WEBPUSH UNREGISTER %s", endpoint);

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBPUSH: %s!%s@%s unregistered endpoint for account %s",
            cli_name(sptr), cli_user(sptr)->username,
            cli_user(sptr)->host, cli_user(sptr)->account);

  return 0;
}

/** Handle WEBPUSH command from a local client.
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int m_webpush(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  /* Check if capability is enabled */
  if (!CapActive(sptr, CAP_DRAFT_WEBPUSH)) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "*",
                      "You must enable the draft/webpush capability");
    return 0;
  }

  if (parc < 2) {
    send_webpush_fail(sptr, "INVALID_PARAMS", "*",
                      "Usage: WEBPUSH <REGISTER|UNREGISTER> ...");
    return 0;
  }

  subcmd = parv[1];

  if (!ircd_strcmp(subcmd, "REGISTER"))
    return webpush_cmd_register(sptr, parc, parv);
  else if (!ircd_strcmp(subcmd, "UNREGISTER"))
    return webpush_cmd_unregister(sptr, parc, parv);
  else {
    send_webpush_fail(sptr, "INVALID_PARAMS", subcmd,
                      "Unknown subcommand (expected REGISTER or UNREGISTER)");
    return 0;
  }
}

/* ---------------------------------------------------------------------------
 * Notification delivery
 * ---------------------------------------------------------------------------*/

/* Delivery counters for STATS webpush: the only surface a deployment
 * that drops LS_SYSTEM has for "is push working". */
static struct {
  unsigned long attempts;    /* pushes handed to the HTTP transport */
  unsigned long submit_fail; /* refused before leaving (encrypt/sign/no transport) */
  unsigned long ok;          /* 2xx */
  unsigned long expired;     /* 410 */
  unsigned long forbidden;   /* 403 */
  unsigned long failed;      /* anything else */
  long last_http;            /* last HTTP status seen */
  time_t last_at;            /* time of the last completed attempt */
  time_t last_ok_at;
} wp_delivery;

/** Context for async push notification delivery callback. */
struct notify_ctx {
  char account[256];
  char endpoint[WEBPUSH_MAX_ENDPOINT];
};

/** Callback for async webpush_notify completion.
 * Handles expired subscriptions by removing them from store and
 * broadcasting the removal to linked servers.
 */
static void notify_send_cb(int result, long http_code, void *data)
{
  struct notify_ctx *ctx = data;

  if (!ctx)
    return;

  wp_delivery.last_http = http_code;
  wp_delivery.last_at = CurrentTime;
  if (result == WEBPUSH_OK) {
    wp_delivery.ok++;
    wp_delivery.last_ok_at = CurrentTime;
  } else if (result == WEBPUSH_ERR_EXPIRED)
    wp_delivery.expired++;
  else if (result == WEBPUSH_ERR_FORBIDDEN)
    wp_delivery.forbidden++;
  else
    wp_delivery.failed++;

  if (result == WEBPUSH_ERR_EXPIRED) {
    /* Subscription expired (HTTP 410) — remove from store */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: subscription expired for %s (HTTP %ld)",
              ctx->account, http_code);

    if (webpush_store_available()) {
      webpush_subs_cache_invalidate(ctx->account);
      webpush_store_remove(ctx->account, ctx->endpoint);
    }

    /* Broadcast removal to linked servers */
    sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "U %s %s",
                          ctx->account, ctx->endpoint);
  } else if (result == WEBPUSH_ERR_FORBIDDEN) {
    /* The push service refused our VAPID signature: the subscription was
     * created under a key this server no longer holds.  Transient
     * service trouble looks the same, so reap only after repeats. */
    webpush_forbidden(ctx->account, ctx->endpoint);
  } else if (result == WEBPUSH_OK) {
    webpush_delivered(ctx->account, ctx->endpoint);
  }

  free(ctx);
}

/* Per-subscription HTTP 403 counter: reap after this many in a row. */
#define WEBPUSH_FORBIDDEN_REAP  3
#define WEBPUSH_FORBIDDEN_SLOTS 64

static struct {
  char account[ACCOUNTLEN + 1];
  char endpoint[WEBPUSH_MAX_ENDPOINT];
  int count;
} wp_forbidden[WEBPUSH_FORBIDDEN_SLOTS];

static unsigned int wp_forbidden_slot(const char *account, const char *endpoint)
{
  unsigned int h = 2166136261u;
  const char *p;
  for (p = account; *p; ++p) { h ^= (unsigned char)*p; h *= 16777619u; }
  for (p = endpoint; *p; ++p) { h ^= (unsigned char)*p; h *= 16777619u; }
  return h & (WEBPUSH_FORBIDDEN_SLOTS - 1);
}

static void webpush_delivered(const char *account, const char *endpoint)
{
  unsigned int i = wp_forbidden_slot(account, endpoint);
  if (wp_forbidden[i].count
      && 0 == strcmp(wp_forbidden[i].account, account)
      && 0 == strcmp(wp_forbidden[i].endpoint, endpoint))
    wp_forbidden[i].count = 0;
}

static void webpush_forbidden(const char *account, const char *endpoint)
{
  unsigned int i = wp_forbidden_slot(account, endpoint);

  if (0 != strcmp(wp_forbidden[i].account, account)
      || 0 != strcmp(wp_forbidden[i].endpoint, endpoint)) {
    ircd_strncpy(wp_forbidden[i].account, account, sizeof(wp_forbidden[i].account));
    ircd_strncpy(wp_forbidden[i].endpoint, endpoint, sizeof(wp_forbidden[i].endpoint));
    wp_forbidden[i].count = 0;
  }
  if (++wp_forbidden[i].count < WEBPUSH_FORBIDDEN_REAP)
    return;

  log_write(LS_SYSTEM, L_WARNING, 0,
            "WEBPUSH: reaping subscription of %s after %d HTTP 403s (VAPID key mismatch)",
            account, wp_forbidden[i].count);
  wp_forbidden[i].count = 0;
  if (webpush_store_available()) {
    webpush_subs_cache_invalidate(account);
    webpush_store_remove(account, endpoint);
  }
  sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "U %s %s", account, endpoint);
}

/** Iterator callback for webpush_notify_account — sends push to each subscription. */
struct notify_iter_data {
  const char *account;
  const char *message;
  size_t message_len;
};

static int notify_iter_cb(const char *stored, void *data)
{
  struct notify_iter_data *nid = data;
  struct webpush_subscription sub;
  struct notify_ctx *ctx;

  if (!kc_transport_ready) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "WebPush: notify_iter: HTTP transport not initialised, push dropped");
    return 1;   /* stop: every subscription would fail the same way */
  }

  /* Parse subscription from stored format */
  if (webpush_parse_subscription(stored, &sub) != 0)
  {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "WebPush: notify_iter: parse FAILED: len=%d",
              (int)strlen(stored));
    return 0; /* skip invalid, continue iteration */
  }

  /* Allocate callback context */
  ctx = malloc(sizeof(*ctx));
  if (!ctx)
    return 0; /* skip on alloc failure, continue */

  ircd_strncpy(ctx->account, nid->account, sizeof(ctx->account) - 1);
  ctx->account[sizeof(ctx->account) - 1] = '\0';
  ircd_strncpy(ctx->endpoint, sub.endpoint, sizeof(ctx->endpoint) - 1);
  ctx->endpoint[sizeof(ctx->endpoint) - 1] = '\0';

  /* Send push notification asynchronously */
  if (webpush_notify(&sub, nid->message, nid->message_len,
                     notify_send_cb, ctx) != 0) {
    /* Delivery submission failed */
    wp_delivery.submit_fail++;
    free(ctx);
  } else {
    wp_delivery.attempts++;
  }

  return 0; /* continue iteration */
}

/** Send push notifications to all subscriptions for an account.
 * Iterates all subscriptions in LMDB for the given account and sends
 * a push notification to each one.
 * @param[in] account IRC account name.
 * @param[in] message Notification message payload.
 * @param[in] message_len Length of message.
 */
void webpush_notify_account(const char *account, const char *message,
                            size_t message_len)
{
  struct notify_iter_data nid;

  if (!account || !message || !message_len)
    return;

  if (!webpush_store_available())
    return;

  nid.account = account;
  nid.message = message;
  nid.message_len = message_len;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "WebPush: notify_account: iterating subscriptions for %s", account);
  webpush_store_foreach(account, notify_iter_cb, &nid);
}

/* ---------------------------------------------------------------------------
 * PM push trigger (v1 -- design: webpush-trigger-payload.md)
 * ---------------------------------------------------------------------------*/

/** Per-account subscription-count cache (TTL'd) so the channel-highlight
 * walk never hits the store per message.  Invalidated beside every store
 * mutation (local WEBPUSH R/U, S2S sync, 410-reap), so R/U changes take
 * effect immediately; the TTL only bounds staleness across restarts of
 * the pattern. */
#define WP_SUBS_CACHE_SLOTS 1024
#define WP_SUBS_CACHE_TTL   30

static struct {
  char account[ACCOUNTLEN + 1];
  int count;
  time_t at;
} wp_subs_cache[WP_SUBS_CACHE_SLOTS];

static unsigned int wp_subs_slot(const char *account)
{
  unsigned int h = 2166136261u;
  const char *p;
  for (p = account; *p; ++p) {
    h ^= (unsigned char)*p;
    h *= 16777619u;
  }
  return h & (WP_SUBS_CACHE_SLOTS - 1);
}

static void webpush_subs_cache_invalidate(const char *account)
{
  unsigned int i;
  if (!account || !account[0])
    return;
  i = wp_subs_slot(account);
  if (0 == ircd_strcmp(wp_subs_cache[i].account, account))
    wp_subs_cache[i].at = 0;
}

static int webpush_store_count_cached(const char *account)
{
  unsigned int i = wp_subs_slot(account);
  int c;

  if (0 == ircd_strcmp(wp_subs_cache[i].account, account)
      && wp_subs_cache[i].at + WP_SUBS_CACHE_TTL > CurrentTime)
    return wp_subs_cache[i].count;
  c = webpush_store_count(account);
  ircd_strncpy(wp_subs_cache[i].account, account, sizeof(wp_subs_cache[i].account));
  wp_subs_cache[i].count = c;
  wp_subs_cache[i].at = CurrentTime;
  return c;
}

#define WEBPUSH_CD_SLOTS 256

/** Per-(account, origin) push cooldown -- open-addressed, overwrite on
 * collision (best-effort: a collision can only cause an extra push,
 * never a lost one beyond the window).  Entries expire by time; no
 * revive-reset needed: pushes are gated on HOLDING state, so a stale
 * entry can only suppress within FEAT_WEBPUSH_COOLDOWN seconds of the
 * previous push, which is the intended behavior anyway. */
static struct {
  char key[ACCOUNTLEN + NICKLEN + 2];
  time_t last;
} wp_cooldown[WEBPUSH_CD_SLOTS];

/** Seconds within which repeated read-marker pushes for one target
 * are coalesced. */
#define WEBPUSH_READ_COALESCE 3

/** One push per (account, origin) per @a cd seconds; @a ns keeps the
 * read-marker keys apart from the PM/highlight keys in the same table. */
static int webpush_cooldown_ok(const char *account, const char *origin,
                               int cd, const char *ns)
{
  char key[ACCOUNTLEN + CHANNELLEN + 8];
  unsigned int h = 2166136261u;
  const char *p;

  if (cd <= 0)
    return 1;
  ircd_snprintf(0, key, sizeof(key), "%s%s/%s", ns ? ns : "", account, origin);
  for (p = key; *p; ++p) {
    h ^= (unsigned char)*p;
    h *= 16777619u;
  }
  h &= (WEBPUSH_CD_SLOTS - 1);
  if (0 == strcmp(wp_cooldown[h].key, key)
      && wp_cooldown[h].last + cd > CurrentTime)
    return 0;
  ircd_strncpy(wp_cooldown[h].key, key, sizeof(wp_cooldown[h].key));
  wp_cooldown[h].last = CurrentTime;
  return 1;
}

static int webpush_pm_cooldown_ok(const char *account, const char *origin)
{
  return webpush_cooldown_ok(account, origin, feature_int(FEAT_WEBPUSH_COOLDOWN), NULL);
}

static void webpush_emit_push(const char *account, const char *kind,
                              const char *from, const char *target,
                              const char *msgid, const char *timestamp,
                              const char *text);

/* ---------------------------------------------------------------------------
 * Attention: push only when nobody is looking
 * ------------------------------------------------------------------------- */

/* Why the last pushes were NOT sent, for STATS webpush. */
static struct {
  unsigned long attended, cooldown, muted;
  char last_reason[48];
  time_t last_at;
} wp_suppress;

static void wp_suppressed(unsigned long *counter, const char *reason,
                          const char *account)
{
  (*counter)++;
  ircd_snprintf(0, wp_suppress.last_reason, sizeof(wp_suppress.last_reason),
                "%s (%s)", reason, account);
  wp_suppress.last_at = CurrentTime;
}

/** Idle window for an account: its `draft/webpush/idle` metadata (seconds)
 * when set, else WEBPUSH_IDLE. */
static long long webpush_idle_window(const char *account)
{
  char v[METADATA_VALUE_LEN];
  if (metadata_account_get(account, "draft/webpush/idle", v) == 0 && v[0]) {
    char *endp;
    long long n = strtoll(v, &endp, 10);
    if (endp != v && n >= 0)
      return n;
  }
  return (long long)feature_int(FEAT_WEBPUSH_IDLE);
}

static void wp_conn_state(struct Client *c, int held, long long replicated,
                          struct webpush_conn_state *out)
{
  out->held = held;
  out->away = 0;
  out->last_msg = replicated;
  if (!c) {
    out->held = 1;
    return;
  }
  if (MyConnect(c) && cli_connect(c))
    out->away = con_pre_away(cli_connect(c)) != 0;
  else
    out->away = (cli_user(c) && cli_user(c)->away) ? 1 : 0;
  if (cli_user(c) && (long long)cli_user(c)->last > out->last_msg)
    out->last_msg = cli_user(c)->last;
}

/** 1 when no connection of @a acptr's account attends: every one is held,
 * away, or idle past the window.  @a acptr is the session primary (or a
 * plain client); aliases are read from the session, local ones through
 * their own idle clock and away state, remote ones through the activity
 * the bouncer replicates (BX U la=) and their AWAY.  See
 * webpush-attention-trigger.md. */
static int webpush_account_unattended(struct Client *acptr, const char *account)
{
  struct webpush_conn_state st[BOUNCER_MAX_ALIASES + 1];
  struct BouncerSession *sess = bounce_get_session(acptr);
  long long idle = webpush_idle_window(account);
  int n = 0, i;

  if (!sess) {
    wp_conn_state(acptr, 0, 0, &st[n++]);
    return webpush_unattended(st, n, (long long)CurrentTime, idle);
  }
  wp_conn_state(sess->hs_client, sess->hs_state == BOUNCE_HOLDING,
                (long long)sess->hs_last_active, &st[n++]);
  for (i = 0; i < sess->hs_alias_count && n < (int)(sizeof(st) / sizeof(st[0])); i++) {
    struct Client *al = findNUser(sess->hs_aliases[i].ba_numeric);
    wp_conn_state(al, al ? 0 : 1, (long long)sess->hs_aliases[i].ba_last_active, &st[n++]);
  }
  return webpush_unattended(st, n, (long long)CurrentTime, idle);
}

/** Mute-list name compare: the ircd casemapping, exact length. */
static int webpush_mute_name_eq(const char *a, size_t alen,
                                const char *b, size_t blen)
{
  return alen == blen && ircd_strncmp(a, b, alen) == 0;
}

/** 1 when the account's `draft/webpush/mute` metadata mutes `target`
 * (a DM peer nick or a channel) right now. */
static int webpush_mute_blocked(const char *account, const char *target)
{
  char value[METADATA_VALUE_LEN];

  if (metadata_account_get(account, "draft/webpush/mute", value) != 0)
    return 0;

  /* Channel names and nicks are case-insensitive under the casemapping;
   * the highlight path passes the channel's canonical spelling. */
  return webpush_mute_check_cmp(value, target, CurrentTime, webpush_mute_name_eq);
}

/** Relay a read marker to the account's webpush subscriptions so other
 * devices can close their notifications (`{"t":"read",...}`).  Deliberately
 * ungated by hold/cooldown/mute: it is how they clear. */
static void webpush_emit_read(const char *account, const char *target,
                              const char *timestamp);

void webpush_notify_read(const char *account, const char *target,
                         const char *timestamp)
{
  if (!account || !account[0] || !target || !target[0])
    return;
  if (!feature_bool(FEAT_WEBPUSH_NOTIFY))
    return;
  if (webpush_store_count_cached(account) <= 0)
    return;
  /* Reading a busy conversation sets a marker every few seconds; one
   * push per target per short window is enough for devices to close
   * their notifications (deliberately not the minute-long PM cooldown). */
  if (!webpush_cooldown_ok(account, target, WEBPUSH_READ_COALESCE, "read/"))
    return;
  webpush_emit_read(account, target, timestamp ? timestamp : "*");
}

void webpush_notify_pm(struct Client *sptr, struct Client *acptr,
                       const char *text, int is_notice,
                       const char *msgid, const char *timestamp)
{
  const char *account;

  if (!feature_bool(FEAT_WEBPUSH_NOTIFY))
    return;
  /* acptr is the account's primary (a held ghost, or a live client); the
   * decision runs once per message there, never per alias delivery. */
  if (!sptr || !acptr || !MyConnect(acptr) || IsBouncerAlias(acptr))
    return;
  /* Only people push.  Server and service NOTICEs -- the connect-time
   * "you are connected with TLS", AuthServ's recognition, X3 bots --
   * are not conversation, and a client reviving a session received a
   * notification per line of its own welcome. */
  if (IsServer(sptr) || IsServiceClient(sptr) || !cli_user(sptr))
    return;
  if (!cli_user(acptr) || !cli_user(acptr)->account[0])
    return;
  account = cli_user(acptr)->account;
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "WebPush: notify_pm entry: from=%s target=%s store=%d",
            cli_name(sptr), cli_name(acptr), webpush_store_count_cached(account));
  if (webpush_store_count_cached(account) <= 0)
    return;
  /* Push only when nobody is attending the account (held, away, or idle
   * on every connection) -- not only when the session is held. */
  if (!webpush_account_unattended(acptr, account)) {
    wp_suppressed(&wp_suppress.attended, "attended", account);
    return;
  }
  if (!webpush_pm_cooldown_ok(account, cli_name(sptr))) {
    wp_suppressed(&wp_suppress.cooldown, "cooldown", account);
    return;
  }
  /* Mutes name a nick or, for a logged-in sender, an account: a nick
   * change must not bypass a mute. */
  if (webpush_mute_blocked(account, cli_name(sptr))
      || (cli_user(sptr)->account[0]
          && webpush_mute_blocked(account, cli_user(sptr)->account))) {
    wp_suppressed(&wp_suppress.muted, "muted", account);
    return;
  }

  webpush_emit_push(account, is_notice ? "notice" : "msg",
                    cli_name(sptr), cli_name(acptr), msgid, timestamp, text);
}

/** Build the tiered JSON payload and hand it to webpush_notify_account.
 * Tier from the account's draft/webpush/payload metadata key, defaulting
 * to full: full (route + text, UTF-8-clamped -- never reject-and-drop;
 * invalid UTF-8 text degrades the push to route because json_string()
 * rejects it and the field is simply omitted), route (from/target/msgid/
 * time, no content) or ping (bare).  The payload is encrypted
 * server-to-device, so the push service never sees the text; an empty
 * default that renders notifications without content is just a worse
 * product, so accounts must explicitly opt down. */
static void webpush_emit_push(const char *account, const char *kind,
                              const char *from, const char *target,
                              const char *msgid, const char *timestamp,
                              const char *text)
{
  char tier[METADATA_VALUE_LEN];
#ifndef HAVE_JANSSON
  char esc[WEBPUSH_MAX_PAYLOAD];
  char out[WEBPUSH_MAX_PAYLOAD];
  size_t pos = 0;
#endif

  tier[0] = '\0';
  (void)metadata_account_get(account, "draft/webpush/payload", tier);
  if (tier[0] == '\0')
    ircd_strncpy(tier, "full", sizeof(tier));

#ifdef HAVE_JANSSON
  /* jansson path (preferred when the library is available -- abc9cc6
   * dropped it wholesale to fix the non-keycloak link; configure now
   * probes jansson independently of keycloak, so use it when found).
   * Same shape as the fallback: same fields, same 3000-byte UTF-8-safe
   * clamp for the full tier. */
  {
    json_t *obj;
    char *dump;
    size_t dumplen;

    obj = json_object();
    if (!obj)
      return;
    json_object_set_new(obj, "t", json_string(kind));
    if (0 != ircd_strcmp(tier, "ping")) {
      json_object_set_new(obj, "from", json_string(from));
      json_object_set_new(obj, "target", json_string(target));
      if (msgid && msgid[0])
        json_object_set_new(obj, "msgid", json_string(msgid));
      if (timestamp && timestamp[0])
        json_object_set_new(obj, "time", json_string(timestamp));
      if (0 == ircd_strcmp(tier, "full") && text && text[0]) {
        char body[WEBPUSH_MAX_PAYLOAD];
        ircd_strncpy(body, text, sizeof(body));
        if (ircd_utf8_clamp(body, 3000))
          json_object_set_new(obj, "trunc", json_true());
        json_object_set_new(obj, "text", json_string(body));
      }
    }
    dump = json_dumps(obj, JSON_COMPACT);
    json_decref(obj);
    if (!dump)
      return;
    dumplen = strlen(dump);
    if (dumplen > 0 && dumplen <= WEBPUSH_MAX_PAYLOAD)
      webpush_notify_account(account, dump, dumplen);
    free(dump);
  }
#else
  /* Hand-rolled fallback (jansson not found at configure time).  All
   * string content goes through ircd_json_escape; UTF-8 bytes pass
   * through verbatim. */
  str_appendf(out, sizeof(out), &pos, "{\"t\":\"%s\"", kind);
  if (0 != ircd_strcmp(tier, "ping")) {
    str_appendf(out, sizeof(out), &pos, ",\"from\":\"%s\"",
                ircd_json_escape(esc, sizeof(esc), from));
    str_appendf(out, sizeof(out), &pos, ",\"target\":\"%s\"",
                ircd_json_escape(esc, sizeof(esc), target));
    if (msgid && msgid[0])
      str_appendf(out, sizeof(out), &pos, ",\"msgid\":\"%s\"",
                  ircd_json_escape(esc, sizeof(esc), msgid));
    if (timestamp && timestamp[0])
      str_appendf(out, sizeof(out), &pos, ",\"time\":\"%s\"",
                  ircd_json_escape(esc, sizeof(esc), timestamp));
    if (0 == ircd_strcmp(tier, "full") && text && text[0]) {
      char body[WEBPUSH_MAX_PAYLOAD];
      ircd_strncpy(body, text, sizeof(body));
      if (ircd_utf8_clamp(body, 3000))
        str_appendf(out, sizeof(out), &pos, ",\"trunc\":true");
      str_appendf(out, sizeof(out), &pos, ",\"text\":\"%s\"",
                  ircd_json_escape(esc, sizeof(esc), body));
    }
  }
  str_appendf(out, sizeof(out), &pos, "}");
  /* A payload that hit the buffer ceiling may be un-terminated JSON;
   * guard on the closing brace before sending. */
  if (pos > 1 && pos < sizeof(out) && out[pos - 1] == '}')
    webpush_notify_account(account, out, pos);
#endif
}

/** `{"t":"read","target":T,"ts":TIME}` with the same escaping as every
 * other payload: a channel name or nick may contain a quote or a
 * backslash. */
static void webpush_emit_read(const char *account, const char *target,
                              const char *timestamp)
{
#ifdef HAVE_JANSSON
  json_t *obj = json_object();
  char *dump;
  size_t dumplen;

  if (!obj)
    return;
  json_object_set_new(obj, "t", json_string("read"));
  json_object_set_new(obj, "target", json_string(target));
  json_object_set_new(obj, "ts", json_string(timestamp));
  dump = json_dumps(obj, JSON_COMPACT);
  json_decref(obj);
  if (!dump)
    return;
  dumplen = strlen(dump);
  if (dumplen > 0 && dumplen <= WEBPUSH_MAX_PAYLOAD)
    webpush_notify_account(account, dump, dumplen);
  free(dump);
#else
  char esc[WEBPUSH_MAX_PAYLOAD];
  char out[WEBPUSH_MAX_PAYLOAD];
  size_t pos = 0;

  str_appendf(out, sizeof(out), &pos, "{\"t\":\"read\",\"target\":\"%s\"",
              ircd_json_escape(esc, sizeof(esc), target));
  str_appendf(out, sizeof(out), &pos, ",\"ts\":\"%s\"}",
              ircd_json_escape(esc, sizeof(esc), timestamp));
  if (pos > 1 && pos < sizeof(out) && out[pos - 1] == '}')
    webpush_notify_account(account, out, pos);
#endif
}

/** The arming time carried on a WP R/B line (trailing param), or 0 when
 * the peer did not send one. */
static long long webpush_wire_armed(int parc, char *parv[])
{
  long long armed = 0;
  if (parc >= 7 && parv[6] && parv[6][0] && parv[6][0] != '-') {
    char *endp;
    armed = (long long)strtoull(parv[6], &endp, 10);
    if (endp == parv[6])
      armed = 0;
  }
  return armed;
}

/** The key id carried on a WP R/B line (7th param), "" when the peer
 * sent none or the "-" placeholder. */
static const char *webpush_wire_keyid(int parc, char *parv[])
{
  if (parc >= 8 && parv[7] && parv[7][0] && 0 != strcmp(parv[7], "-")
      && strlen(parv[7]) <= WEBPUSH_KEY_ID_LEN)
    return parv[7];
  return "";
}

/** Store a subscription received from a peer.  The record keeps the
 * newer of the arming times we hold and the one the peer sent (a peer
 * without one is stamped now), so a burst never re-arms a record. */
static void webpush_store_receive(const char *account, const char *endpoint,
                                  const char *p256dh, const char *auth_secret,
                                  long long armed, const char *keyid)
{
  char stored[4096];
  char existing[4096];

  if (!webpush_store_available())
    return;
  if (armed <= 0)
    armed = (long long)CurrentTime;
  if (webpush_store_get(account, endpoint, existing, sizeof(existing)) == 0
      && webpush_armed_at(existing) >= armed)
    return;   /* ours is at least as fresh */
  snprintf(stored, sizeof(stored), "%s|%s|%s|%lld|%s", endpoint, p256dh,
           auth_secret, armed, keyid ? keyid : "");
  webpush_subs_cache_invalidate(account);
  webpush_store_add(account, stored);
}

struct forget_ctx { const char *account; };

static int forget_iter_cb(const char *stored, void *data)
{
  struct forget_ctx *ctx = data;
  char endpoint[WEBPUSH_MAX_ENDPOINT];
  size_t len = strcspn(stored, "|");
  if (len == 0 || len >= sizeof(endpoint))
    return 0;
  memcpy(endpoint, stored, len);
  endpoint[len] = '\0';
  sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "U %s %s",
                           ctx->account, endpoint);
  return 0;
}

void webpush_forget_account(const char *account)
{
  struct forget_ctx ctx;
  if (!account || !account[0] || !webpush_store_available())
    return;
  /* Tell the peers first, endpoint by endpoint, then drop ours. */
  ctx.account = account;
  webpush_store_foreach(account, forget_iter_cb, &ctx);
  webpush_subs_cache_invalidate(account);
  webpush_store_clear(account);
}

/** Channel-highlight push trigger (v2 -- design:
 * webpush-trigger-payload.md).  Called from the channel PRIVMSG store
 * choke point; scans members for held sessions whose nick the message
 * mentions.  Cost when no held members: one bit test per member. */
void webpush_notify_channel(struct Client *sptr, struct Channel *chptr,
                            const char *text, const char *msgid,
                            const char *timestamp)
{
  struct Membership *member;
  const char *scan = text;
  const char *sender_acct;

  if (!feature_bool(FEAT_WEBPUSH_NOTIFY)
      || !feature_bool(FEAT_WEBPUSH_HIGHLIGHTS))
    return;
  if (!sptr || !chptr || !text || !cli_user(sptr))
    return;
  if (text[0] == '\001') {
    /* ACTION text participates; any other CTCP never highlights. */
    if (0 != ircd_strncmp(text, "\001ACTION ", 8))
      return;
    scan = text + 8;
  }
  sender_acct = cli_user(sptr)->account[0] ? cli_user(sptr)->account : NULL;

  for (member = chptr->members; member; member = member->next_member) {
    struct Client *u = member->user;
    const char *account;

    if (IsZombie(member))
      continue;
    /* One decision per session: its primary (held ghost or live client),
     * never its aliases. */
    if (!MyConnect(u) || IsBouncerAlias(u))
      continue;
    if (!cli_user(u) || !cli_user(u)->account[0])
      continue;
    account = cli_user(u)->account;
    if (sender_acct && 0 == ircd_strcmp(sender_acct, account))
      continue;  /* no self-highlights via own aliases */
    /* Cheap tests first.  Everything below the mention test touches
     * the store or the session; with the trigger no longer limited to
     * held members it would otherwise run for every local member of
     * every channel on every line. */
    if (!ircd_text_mentions(scan, cli_name(u)))
      continue;
    if (is_silenced(sptr, u, 1))
      continue;
    if (webpush_store_count_cached(account) <= 0)
      continue;
    if (!webpush_account_unattended(u, account)) {
      wp_suppressed(&wp_suppress.attended, "attended", account);
      continue;
    }
    if (!webpush_pm_cooldown_ok(account, chptr->chname)) {
      wp_suppressed(&wp_suppress.cooldown, "cooldown", account);
      continue;
    }
    if (webpush_mute_blocked(account, chptr->chname)) {
      wp_suppressed(&wp_suppress.muted, "muted", account);
      continue;
    }
    webpush_emit_push(account, "hl", cli_name(sptr), chptr->chname,
                      msgid, timestamp, scan);
  }
}

/* ---------------------------------------------------------------------------
 * Server burst
 * ---------------------------------------------------------------------------*/

/** Context for webpush_burst iteration. */
struct burst_ctx {
  struct Client *cptr;  /* target server to send burst data to */
};

/** Iterator callback for webpush_burst — sends each subscription to linking server. */
static int burst_iter_cb(const char *account, const char *stored, void *data)
{
  struct burst_ctx *bctx = data;
  const char *endpoint;
  const char *p256dh;
  const char *auth_secret;
  const char *sep1, *sep2;
  char ep_buf[WEBPUSH_MAX_ENDPOINT];
  char p256dh_buf[WEBPUSH_MAX_P256DH];
  char auth_buf[WEBPUSH_MAX_AUTH];
  char keyid[WEBPUSH_KEY_ID_LEN + 1];
  size_t len;

  /* Parse stored format: "endpoint|p256dh|auth[|armed[|keyid]]" */
  sep1 = strchr(stored, '|');
  if (!sep1)
    return 0;
  sep2 = strchr(sep1 + 1, '|');
  if (!sep2)
    return 0;

  /* Extract endpoint */
  len = (size_t)(sep1 - stored);
  if (len == 0 || len >= sizeof(ep_buf))
    return 0;
  memcpy(ep_buf, stored, len);
  ep_buf[len] = '\0';
  endpoint = ep_buf;

  /* Extract p256dh */
  len = (size_t)(sep2 - sep1 - 1);
  if (len == 0 || len >= sizeof(p256dh_buf))
    return 0;
  memcpy(p256dh_buf, sep1 + 1, len);
  p256dh_buf[len] = '\0';
  p256dh = p256dh_buf;

  /* Extract auth.  Stored records may carry a trailing "|armed"
   * timestamp (webpush_expiry.h); the WP wire format stays 3-field, so
   * stop the auth field at the next '|'. */
  auth_secret = sep2 + 1;
  len = strcspn(auth_secret, "|");
  if (len == 0 || len >= sizeof(auth_buf))
    return 0;
  memcpy(auth_buf, auth_secret, len);
  auth_buf[len] = '\0';

  /* Send burst entry to target server:
   *   WP B <account> <endpoint> <p256dh> <auth> <armed> <keyid|->
   * The arming time rides along so the peer ages the record from the
   * same instant we do (0 = timestamp-less record; the peer stamps it);
   * the key id so the peer signs with the key the client subscribed
   * under. */
  if (webpush_record_key_id(stored, keyid, sizeof(keyid)) != 0)
    keyid[0] = '\0';
  sendcmdto_one(&me, CMD_WEBPUSH, bctx->cptr, "B %s %s %s %s %lld %s",
                account, endpoint, p256dh, auth_buf, webpush_armed_at(stored),
                keyid[0] ? keyid : "-");

  return 0; /* continue iteration */
}

/* ---------------------------------------------------------------------------
 * The key ring
 * ------------------------------------------------------------------------- */

static struct webpush_keyring wp_ring;
static int wp_ring_loaded = 0;          /* ring read from the store once */
static char wp_last_error[200];         /* last setup problem, for STATS */
static time_t wp_last_error_at = 0;

static void wp_error(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  ircd_vsnprintf(0, wp_last_error, sizeof(wp_last_error), fmt, ap);
  va_end(ap);
  wp_last_error_at = CurrentTime;
  log_write(LS_SYSTEM, L_ERROR, 0, "WEBPUSH: %s", wp_last_error);
  /* Prod drops LS_SYSTEM; a snomask notice is the surface opers see. */
  sendto_opmask_butone(0, SNO_OLDSNO, "WEBPUSH: %s", wp_last_error);
}

/** Persist a ring key ("key/<id>" -> record text). */
static int wp_persist_key(const struct webpush_key *key)
{
  char text[WEBPUSH_KEY_TEXT_LEN];
  if (webpush_key_format(key, text, sizeof(text)) != 0)
    return -1;
  return webpush_store_key_put(key->id, text);
}

/** Send one ring key to a server (or, with @a to NULL, to every IRCv3-
 * aware peer except @a except):
 *   WP K <id> <gen> <created> <origin> <manual> :<priv_b64> */
static void wp_send_key(struct Client *to, struct Client *except,
                        const struct webpush_key *key)
{
  char priv_b64[64];

  if (webpush_b64url_encode(key->priv, sizeof(key->priv), priv_b64,
                            sizeof(priv_b64)) < 0)
    return;
  if (to)
    sendcmdto_one(&me, CMD_WEBPUSH, to, "K %s %u %lld %s %d :%s",
                  key->id, key->generation, key->created, key->origin,
                  key->manual ? 1 : 0, priv_b64);
  else
    sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, except, "K %s %u %lld %s %d :%s",
                             key->id, key->generation, key->created,
                             key->origin, key->manual ? 1 : 0, priv_b64);
  memset(priv_b64, 0, sizeof(priv_b64));
}

/** Load a key into the crypto table (its private scalar must derive its
 * id) and union it into the ring, persisting it when new.
 * Returns 1 added, 0 already held, -1 rejected. */
static int wp_ring_adopt(const struct webpush_key *key, const char *how)
{
  int rc;

  rc = webpush_key_load(key->priv, sizeof(key->priv), key->id, NULL, 0);
  if (rc != 0) {
    wp_error("rejected VAPID key %.16s... from %s (%s)", key->id, how,
             rc == -2 ? "private key does not derive its id" : "unloadable");
    return -1;
  }
  rc = webpush_keyring_add(&wp_ring, key);
  if (rc < 0) {
    webpush_key_unload(key->id);
    wp_error("key ring full, dropping VAPID key %.16s... from %s", key->id, how);
    return -1;
  }
  if (rc == 1) {
    if (wp_persist_key(key) != 0)
      wp_error("failed to persist VAPID key %.16s...", key->id);
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: ring += key %.16s... gen %u created %lld origin %s%s (%s)",
              key->id, key->generation, key->created, key->origin,
              key->manual ? " manual" : "", how);
  }
  return rc;
}

/** Recompute the current key and, when it changed, re-advertise:
 * ISUPPORT VAPID (re-sent to draft/extended-isupport clients), the cap
 * value, and a legacy WP V for peers that predate the ring. */
static void wp_announce(const char *why)
{
  const struct webpush_key *cur = webpush_keyring_current(&wp_ring);
  const char *old = webpush_get_vapid_pubkey();
  char oldbuf[WEBPUSH_KEY_ID_LEN + 1];
  int changed;

  ircd_strncpy(oldbuf, old ? old : "", sizeof(oldbuf));
  changed = cur ? (0 != strcmp(oldbuf, cur->id)) : (oldbuf[0] != '\0');

  if (cur) {
    webpush_set_current_key(cur->id);
    set_vapid_pubkey(cur->id);
    add_isupport_s("VAPID", cur->id);
  } else {
    webpush_set_current_key(NULL);
    set_vapid_pubkey(NULL);
    del_isupport("VAPID");
  }

  if (!changed)
    return;

  /* touch_isupport happens inside add/del; push the new 005 to clients
   * that asked for updates.  Everyone else learns it on their next
   * connection, which is when they register anyway. */
  send_isupport_update();
  if (cur)
    sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "V :%s", cur->id);

  log_write(LS_SYSTEM, L_INFO, 0, "WEBPUSH: current VAPID key %s %.16s... (%s)",
            cur ? "now" : "cleared", cur ? cur->id : "", why);
  sendto_opmask_butone(0, SNO_OLDSNO, "WEBPUSH: current VAPID key %s%.16s%s (%s)",
                       cur ? "now " : "cleared", cur ? cur->id : "",
                       cur ? "..." : "", why);
}

/** Mint a key here: generate one (@a priv NULL) or wrap a given scalar,
 * at @a generation, persist, broadcast to peers, re-announce. */
static const struct webpush_key *wp_mint(unsigned int generation, int manual,
                                         const unsigned char *priv,
                                         const char *why)
{
  struct webpush_key key;
  size_t plen = sizeof(key.priv);
  int rc;

  memset(&key, 0, sizeof(key));
  if (priv) {
    memcpy(key.priv, priv, sizeof(key.priv));
    rc = webpush_key_load(key.priv, sizeof(key.priv), NULL, key.id, sizeof(key.id));
  } else {
    rc = webpush_key_generate(key.priv, &plen, key.id, sizeof(key.id));
  }
  if (rc != 0) {
    wp_error("failed to %s a VAPID key (%s)", priv ? "import" : "generate", why);
    memset(&key, 0, sizeof(key));
    return NULL;
  }
  key.generation = generation;
  key.created = (long long)CurrentTime;
  ircd_strncpy(key.origin, cli_name(&me), sizeof(key.origin));
  key.manual = manual ? 1 : 0;

  rc = wp_ring_adopt(&key, why);
  if (rc < 0) {
    memset(&key, 0, sizeof(key));
    return NULL;
  }
  if (rc == 1)
    wp_send_key(NULL, NULL, &key);
  memset(&key, 0, sizeof(key));
  wp_announce(why);
  return webpush_keyring_current(&wp_ring);
}

/** Move a config record that will not load aside for post-mortem
 * ("bad/<name>.<time>") and drop the original. */
static void wp_quarantine(const char *name, const void *val, size_t len)
{
  char aside[WEBPUSH_KEY_ID_LEN + 40];
  ircd_snprintf(0, aside, sizeof(aside), "bad/%s.%lld", name, (long long)CurrentTime);
  if (webpush_store_cfg_put(aside, val, len) == 0)
    webpush_store_cfg_del(name);
}

struct ring_load_ctx { int loaded; int bad; };

static int ring_load_cb(const char *id, const char *text, void *data)
{
  struct ring_load_ctx *ctx = data;
  struct webpush_key key;
  char name[WEBPUSH_KEY_ID_LEN + 8];

  if (webpush_key_parse(id, text, &key) != 0
      || webpush_key_load(key.priv, sizeof(key.priv), key.id, NULL, 0) != 0
      || webpush_keyring_add(&wp_ring, &key) != 1) {
    /* Never leave a bad blob where the next boot trips over it again,
     * never destroy it either. */
    webpush_key_unload(id);
    ircd_snprintf(0, name, sizeof(name), "key/%s", id);
    wp_quarantine(name, text, strlen(text));
    wp_error("quarantined unloadable VAPID ring key %.16s...", id);
    ctx->bad++;
  } else {
    ctx->loaded++;
  }
  memset(&key, 0, sizeof(key));
  return 0;
}

/* Pre-ring records carry no key id; stamp them with the key that was in
 * the single slot when the ring arrived (the only one they can have been
 * registered under).  Collect first, rewrite after: no writes under an
 * open iterator. */
struct migrate_rec { char account[ACCOUNTLEN + 1]; char stored[4096]; };
struct migrate_ctx { struct migrate_rec *recs; int n, cap; };

static int migrate_collect_cb(const char *account, const char *stored, void *data)
{
  struct migrate_ctx *ctx = data;
  char keyid[WEBPUSH_KEY_ID_LEN + 1];

  if (webpush_record_key_id(stored, keyid, sizeof(keyid)) != 1)
    return 0;   /* already bound (or malformed: leave it) */
  if (ctx->n == ctx->cap) {
    int ncap = ctx->cap ? ctx->cap * 2 : 64;
    struct migrate_rec *nr = realloc(ctx->recs, (size_t)ncap * sizeof(*nr));
    if (!nr)
      return 1;
    ctx->recs = nr;
    ctx->cap = ncap;
  }
  ircd_strncpy(ctx->recs[ctx->n].account, account, sizeof(ctx->recs[ctx->n].account));
  ircd_strncpy(ctx->recs[ctx->n].stored, stored, sizeof(ctx->recs[ctx->n].stored));
  ctx->n++;
  return 0;
}

static void wp_migrate_records(const char *keyid)
{
  struct migrate_ctx ctx = { NULL, 0, 0 };
  int i, done = 0;

  webpush_store_foreach_all(migrate_collect_cb, &ctx);
  for (i = 0; i < ctx.n; i++) {
    char out[4096 + WEBPUSH_KEY_ID_LEN + 4];
    const char *stored = ctx.recs[i].stored;
    int fields = 1;
    const char *q;
    for (q = stored; (q = strchr(q, '|')) != NULL; q++)
      fields++;
    /* 3 fields: no arming stamp either -> "|0|keyid" keeps armed_at's
     * "never sweep a timestamp-less record" contract. */
    ircd_snprintf(0, out, sizeof(out), "%s%s|%s", stored,
                  fields < 4 ? "|0" : "", keyid);
    if (webpush_store_add(ctx.recs[i].account, out) == 0)
      done++;
  }
  free(ctx.recs);
  if (ctx.n)
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: bound %d/%d pre-ring subscription(s) to key %.16s...",
              done, ctx.n, keyid);
}

/** First-boot ring load: the persisted ring, then the pre-ring single
 * key (migrated in as a generation-0 key, its records stamped). */
static void wp_ring_load(void)
{
  struct ring_load_ctx lctx = { 0, 0 };
  unsigned char priv[WEBPUSH_KEY_PRIV_LEN];
  size_t plen = sizeof(priv);

  webpush_store_key_foreach(ring_load_cb, &lctx);
  if (lctx.loaded || lctx.bad)
    log_write(LS_SYSTEM, L_INFO, 0, "WEBPUSH: ring loaded: %d key(s), %d quarantined",
              lctx.loaded, lctx.bad);

  if (webpush_store_get_vapid_key(priv, &plen) == 0) {
    struct webpush_key key;
    memset(&key, 0, sizeof(key));
    if (webpush_key_load(priv, plen, NULL, key.id, sizeof(key.id)) != 0) {
      wp_quarantine("vapid_privkey", priv, plen);
      wp_error("quarantined the pre-ring VAPID key: it does not load");
    } else {
      memcpy(key.priv, priv, sizeof(key.priv));
      key.generation = 0;
      key.created = (long long)CurrentTime;   /* mint time unknown */
      ircd_strncpy(key.origin, cli_name(&me), sizeof(key.origin));
      if (wp_ring_adopt(&key, "pre-ring store key") >= 0) {
        webpush_store_cfg_del("vapid_privkey");
        wp_migrate_records(key.id);
      }
    }
    memset(&key, 0, sizeof(key));
  }
  memset(priv, 0, sizeof(priv));
}

/** Apply WEBPUSH_VAPID_PRIVKEY: a set key joins the ring as manual at
 * generation max+1 (so it wins everywhere once replicated) or, if
 * already held, is flagged manual; a cleared config demotes the keys
 * this server flagged, which lets scheduled rotation displace them.  The
 * flag is local bookkeeping (replicated at mint, mutable here) -- the
 * current-key rule never reads it. */
static void wp_apply_config_key(void)
{
  const char *config_key = feature_str(FEAT_WEBPUSH_VAPID_PRIVKEY);
  unsigned char priv[WEBPUSH_KEY_PRIV_LEN];
  char id[WEBPUSH_KEY_ID_LEN + 1];
  size_t plen = 0;
  struct webpush_key *k;
  int i;

  if (!config_key || !config_key[0]) {
    for (i = 0; i < wp_ring.count; i++) {
      k = &wp_ring.keys[i];
      if (k->manual && 0 == ircd_strcmp(k->origin, cli_name(&me))) {
        k->manual = 0;
        wp_persist_key(k);
        log_write(LS_SYSTEM, L_INFO, 0,
                  "WEBPUSH: config key cleared; key %.16s... demoted to automatic", k->id);
      }
    }
    return;
  }

  if (webpush_b64url_decode(config_key, strlen(config_key), priv, sizeof(priv), &plen) != 0
      || plen != sizeof(priv)) {
    wp_error("WEBPUSH_VAPID_PRIVKEY is not a base64url 32-byte P-256 scalar; ignored");
    memset(priv, 0, sizeof(priv));
    return;
  }
  if (webpush_key_load(priv, plen, NULL, id, sizeof(id)) != 0) {
    wp_error("WEBPUSH_VAPID_PRIVKEY does not load as a P-256 key; ignored");
    memset(priv, 0, sizeof(priv));
    return;
  }
  k = webpush_keyring_find(&wp_ring, id);
  if (k) {
    if (!k->manual) {
      k->manual = 1;
      wp_persist_key(k);
    }
  } else {
    wp_mint(webpush_keyring_next_generation(&wp_ring), 1, priv,
            "config key WEBPUSH_VAPID_PRIVKEY");
  }
  memset(priv, 0, sizeof(priv));
}

/* ---------------------------------------------------------------------------
 * Maintenance: stale-subscription sweep, key reference counts, rotation,
 * ring pruning
 * ------------------------------------------------------------------------- */

/* Sweep period: cheap (one RocksDB scan over the subs keyspace), so an
 * hour keeps stale records' residency bounded to an hour past their
 * expiry, and an initial sweep runs at boot. */
#define WEBPUSH_SWEEP_INTERVAL 3600

static struct Timer webpush_sweep_timer;
static int webpush_sweep_started = 0;

struct sweep_ctx
{
  time_t now;
  long long max_age;
  int checked;
  int reaped;
  int unbound;
};

static int sweep_iter_cb(const char *account, const char *stored, void *data)
{
  struct sweep_ctx *ctx = data;
  long long armed = webpush_armed_at(stored);
  char endpoint[WEBPUSH_MAX_ENDPOINT];
  char keyid[WEBPUSH_KEY_ID_LEN + 1];
  size_t len;

  ctx->checked++;

  if (!webpush_expired(armed, ctx->now, ctx->max_age)) {
    /* Live record: it references its key. */
    struct webpush_key *k = NULL;
    if (webpush_record_key_id(stored, keyid, sizeof(keyid)) == 0)
      k = webpush_keyring_find(&wp_ring, keyid);
    if (k)
      k->refs++;
    else
      ctx->unbound++;
    return 0;
  }

  /* Endpoint = the record's first field. */
  len = strcspn(stored, "|");
  if (len == 0 || len >= sizeof(endpoint))
    return 0;
  memcpy(endpoint, stored, len);
  endpoint[len] = '\0';

  if (webpush_store_remove(account, endpoint) != 0)
    return 0;

  ctx->reaped++;
  webpush_subs_cache_invalidate(account);
  /* Peers hold their own copy; without this they keep it and burst it
   * back at the next link. */
  sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "U %s %s", account, endpoint);
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "WebPush: swept stale subscription for %s (armed %lld)",
            account, armed);
  return 0;
}

/** Scheduled rotation: mint generation max+1 once the current key is
 * older than WEBPUSH_KEY_ROTATE.  Exactly one server does it in steady
 * state -- the key's origin -- so a linked network rotates once, not
 * once per server; any server may once the origin is gone.  A manual
 * key (config) is the operator's to rotate: never displaced here. */
static void wp_rotate_if_due(time_t now)
{
  const struct webpush_key *cur = webpush_keyring_current(&wp_ring);
  long long rotate = (long long)feature_int(FEAT_WEBPUSH_KEY_ROTATE);

  if (!cur || rotate <= 0 || cur->manual || cur->created <= 0)
    return;
  if (cur->created + rotate > (long long)now)
    return;
  if (0 != ircd_strcmp(cur->origin, cli_name(&me)) && FindServer(cur->origin))
    return;
  wp_mint(webpush_keyring_next_generation(&wp_ring), 0, NULL, "scheduled rotation");
}

/* Reference count only (no sweeping): which keys do live records bind to. */
static int refs_iter_cb(const char *account, const char *stored, void *data)
{
  char keyid[WEBPUSH_KEY_ID_LEN + 1];
  struct webpush_key *k;
  (void)account; (void)data;
  if (webpush_record_key_id(stored, keyid, sizeof(keyid)) == 0
      && (k = webpush_keyring_find(&wp_ring, keyid)) != NULL)
    k->refs++;
  return 0;
}

static void wp_count_refs(void)
{
  int i;
  for (i = 0; i < wp_ring.count; i++)
    wp_ring.keys[i].refs = 0;
  if (webpush_store_available())
    webpush_store_foreach_all(refs_iter_cb, NULL);
}

/* A retired key nothing references is kept this long past its creation:
 * a client that saw it in ISUPPORT on another server can still register
 * under it, and that registration reaches us as a WP R bound to the key.
 * A day covers any burst or relink; a connection older than that which
 * registers for the first time binds to a key we may have dropped, and
 * delivery's 403 reaping plus the client's next login recover it. */
#define WEBPUSH_KEY_GRACE 86400

/** Drop retired keys nothing here references (past the grace) or past
 * the expiry window.  A peer still holding one re-sends it at the next
 * link and it is re-adopted -- harmless and bounded by the same rule
 * there. */
static void wp_prune(time_t now, long long expire)
{
  int i;
  for (i = 0; i < wp_ring.count; ) {
    struct webpush_key *k = &wp_ring.keys[i];
    if (webpush_key_prunable(&wp_ring, k, (long long)now, expire, WEBPUSH_KEY_GRACE)) {
      char id[WEBPUSH_KEY_ID_LEN + 1];
      ircd_strncpy(id, k->id, sizeof(id));
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBPUSH: pruning retired VAPID key %.16s... (gen %u, %d refs)",
                id, k->generation, k->refs);
      webpush_store_key_del(id);
      webpush_key_unload(id);
      webpush_keyring_remove(&wp_ring, id);   /* moves the last key into slot i */
      continue;
    }
    i++;
  }
}

/** Periodic maintenance: remove subscriptions not re-armed (via
 * WEBPUSH REGISTER) within FEAT_WEBPUSH_EXPIRE seconds, count which
 * keys the survivors reference, rotate when due, prune the ring.  Also
 * the retry path for a setup that found the store unavailable. */
static void webpush_maintenance(struct Event *ev)
{
  struct sweep_ctx ctx;
  int i;

  (void)ev;
  if (!webpush_store_available())
    return;
  if (!wp_ring_loaded || !webpush_keyring_current(&wp_ring)) {
    webpush_setup();
    if (!wp_ring_loaded)
      return;
  }

  ctx.now = CurrentTime;
  ctx.max_age = (long long)feature_int(FEAT_WEBPUSH_EXPIRE);
  ctx.checked = 0;
  ctx.reaped = 0;
  ctx.unbound = 0;
  for (i = 0; i < wp_ring.count; i++)
    wp_ring.keys[i].refs = 0;

  /* max_age <= 0 disables the expiry; the walk still counts references. */
  webpush_store_foreach_all(sweep_iter_cb, &ctx);

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "WebPush: sweep checked=%d reaped=%d unbound=%d",
            ctx.checked, ctx.reaped, ctx.unbound);
  if (ctx.reaped > 0)
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: expired %d subscription(s) not re-armed within %d seconds",
              ctx.reaped, feature_int(FEAT_WEBPUSH_EXPIRE));

  wp_rotate_if_due(ctx.now);
  wp_prune(ctx.now, ctx.max_age);
}

/** Burst the key ring, then every subscription, to a newly linked server.
 * Keys go first so the peer can sign for the subscriptions that follow.
 * @param[in] cptr Target server to send burst data to.
 */
void webpush_burst(struct Client *cptr)
{
  struct burst_ctx bctx;
  int i;

  if (!cptr || !webpush_store_available())
    return;

  for (i = 0; i < wp_ring.count; i++)
    wp_send_key(cptr, NULL, &wp_ring.keys[i]);

  bctx.cptr = cptr;
  webpush_store_foreach_all(burst_iter_cb, &bctx);

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBPUSH: burst %d key(s) and subscriptions sent to %s",
            wp_ring.count, cli_name(cptr));
}

/* ---------------------------------------------------------------------------
 * VAPID key initialization and persistence
 * ---------------------------------------------------------------------------*/

/** Initialize the webpush subsystem: load the key ring, apply the config
 * key, generate a first key if the ring is empty, compute and advertise
 * the current key.  Never leaves the server keyless while the store is
 * open: a key that fails to load is quarantined and the next source
 * takes over.  With the store unavailable (transient) nothing is
 * advertised and the maintenance timer retries.
 *
 * Safe to call again (REHASH, config key change, maintenance retry).
 *
 * @return 0 on success (a current key exists), -1 otherwise.
 */
int webpush_setup(void)
{
  /* Maintenance runs whether or not the store is open yet: it is also
   * the retry path. */
  if (!webpush_sweep_started) {
    webpush_sweep_started = 1;
    timer_add(timer_init(&webpush_sweep_timer), webpush_maintenance, 0,
              TT_PERIODIC, WEBPUSH_SWEEP_INTERVAL);
  }

  if (!webpush_store_available()) {
    wp_error("store not available, VAPID key ring not loaded (will retry)");
    return -1;
  }

  if (!wp_ring_loaded) {
    wp_ring_loaded = 1;
    wp_ring_load();
    if (!kc_transport_ready)
      wp_error("HTTP transport (libkc) not initialised: keys are advertised "
               "but no push can be delivered");
  }

  wp_apply_config_key();

  if (wp_ring.count == 0) {
    if (!wp_mint(0, 0, NULL, "first key")) {
      wp_announce("setup");
      return -1;
    }
    /* wp_mint announced. */
  } else {
    wp_announce("setup");
  }

  if (!webpush_get_vapid_pubkey())
    return -1;

  /* Boot-time sweep + reference count + prune. */
  webpush_maintenance(NULL);
  return 0;
}

/** Remember, per connection, the VAPID key id in the ISUPPORT block just
 * sent to it: the key the client will register under.  Called from
 * every 005 emitter. */
void webpush_note_key_seen(struct Client *cptr)
{
  const char *cur;

  if (!cptr || !MyConnect(cptr) || !cli_connect(cptr))
    return;
  cur = webpush_get_vapid_pubkey();
  if (cur)
    ircd_strncpy(cli_vapid_seen(cptr), cur, WEBPUSH_KEY_ID_LEN + 1);
}

/* ---------------------------------------------------------------------------
 * STATS webpush
 * ------------------------------------------------------------------------- */

void webpush_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct webpush_store_stats st;
  const struct webpush_key *cur = webpush_keyring_current(&wp_ring);
  int i;

  (void)sd; (void)param;

  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "W :WEBPUSH VAPID key ring");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "W :  Store: %s, ring %s",
             webpush_store_available() ? "available" : "UNAVAILABLE",
             wp_ring_loaded ? "loaded" : "not loaded");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "W :  Delivery: %s",
#ifdef USE_LIBKC
             kc_transport_ready ? "libkc HTTP transport ready"
                                : "libkc HTTP transport FAILED at boot -- pushes cannot be sent"
#else
             "built without libkc (--enable-keycloak) -- pushes cannot be sent"
#endif
             );
  if (webpush_store_available() && webpush_store_get_stats(&st) == 0)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :  Subscriptions: ~%lu, store %lu bytes",
               st.total_subscriptions, st.db_size_bytes);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Pushes since boot: %lu sent, %lu ok, %lu expired(410), %lu forbidden(403), "
             "%lu failed, %lu not submitted",
             wp_delivery.attempts, wp_delivery.ok, wp_delivery.expired,
             wp_delivery.forbidden, wp_delivery.failed, wp_delivery.submit_fail);
  if (wp_delivery.last_at)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :  Last push: HTTP %ld, %lld s ago; last success %s",
               wp_delivery.last_http, (long long)(CurrentTime - wp_delivery.last_at),
               wp_delivery.last_ok_at ? "" : "never");
  if (wp_delivery.last_ok_at)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :  Last successful push: %lld s ago",
               (long long)(CurrentTime - wp_delivery.last_ok_at));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Suppressed since boot: %lu attended, %lu cooldown, %lu muted; idle window %d s",
             wp_suppress.attended, wp_suppress.cooldown, wp_suppress.muted,
             feature_int(FEAT_WEBPUSH_IDLE));
  if (wp_suppress.last_at)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :  Last suppressed: %s, %lld s ago",
               wp_suppress.last_reason, (long long)(CurrentTime - wp_suppress.last_at));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Current key: %s", cur ? cur->id : "(none)");
  /* Fresh counts: the hourly maintenance figures would lag a REGISTER
   * made since. */
  wp_count_refs();
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Rotation: every %d s (0 = never); config key %s",
             feature_int(FEAT_WEBPUSH_KEY_ROTATE),
             (feature_str(FEAT_WEBPUSH_VAPID_PRIVKEY)
              && feature_str(FEAT_WEBPUSH_VAPID_PRIVKEY)[0]) ? "set" : "unset");
  for (i = 0; i < wp_ring.count; i++) {
    const struct webpush_key *k = &wp_ring.keys[i];
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :  Key %.16s... gen %u created %lld origin %s%s%s refs %d%s",
               k->id, k->generation, k->created, k->origin,
               k->manual ? " manual" : "",
               webpush_key_loaded(k->id) ? "" : " NOT LOADED",
               k->refs, (cur && cur == k) ? " (current)" : "");
  }
  if (wp_last_error[0])
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :  Last error (%lld s ago): %s",
               (long long)(CurrentTime - wp_last_error_at), wp_last_error);
}

/* ---------------------------------------------------------------------------
 * Server-to-server handler
 * ---------------------------------------------------------------------------*/

/** Handle WEBPUSH (WP) command from a server (P10).
 *
 * Incoming formats:
 *   WP K <id> <gen> <created> <origin> <manual> :<priv>   - Ring key
 *   WP V :<vapid_pubkey>                                   - Legacy advisory
 *   WP R <account> <endpoint> <p256dh> <auth> <armed> <keyid|->
 *   WP U <account> <endpoint>
 *   WP B <account> <endpoint> <p256dh> <auth> <armed> <keyid|->
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int ms_webpush(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *subcmd;

  if (parc < 2)
    return 0;

  subcmd = parv[1];

  /* Ring key from a peer: WP K <id> <gen> <created> <origin> <manual> :<priv>.
   * Union into the ring; only a key we did not hold propagates onward
   * (that is what terminates the flood), and a key whose private half
   * does not derive its id is dropped without propagation. */
  if (subcmd[0] == 'K') {
    struct webpush_key key;
    char text[WEBPUSH_KEY_TEXT_LEN];
    int rc;

    if (parc < 8)
      return 0;
    if (!webpush_store_available() || !wp_ring_loaded)
      return 0;   /* no ring to union into yet; peers re-send at the next link */

    ircd_snprintf(0, text, sizeof(text), "%s|%s|%s|%s|%s",
                  parv[3], parv[4], parv[5], parv[6], parv[7]);
    if (webpush_key_parse(parv[2], text, &key) != 0) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "WEBPUSH: malformed WP K from %s ignored", cli_name(sptr));
      return 0;
    }
    rc = wp_ring_adopt(&key, cli_name(sptr));
    if (rc == 1) {
      wp_send_key(NULL, cptr, &key);
      wp_announce("key from peer");
      /* A local key this one displaces is retired, not dropped: the
       * maintenance prune takes it once nothing references it and the
       * grace has passed. */
    }
    memset(&key, 0, sizeof(key));
    return 0;
  }

  /* Legacy advisory from a pre-ring peer: WP V :<vapid_pubkey>.  Never
   * adopt it -- a key we cannot sign with must never be advertised, or
   * clients register subscriptions nobody can push to.  Fan out for
   * other legacy peers. */
  if (subcmd[0] == 'V') {
    if (parc < 3)
      return 0;
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "V :%s", parv[2]);
    return 0;
  }

  if (parc < 3)
    return 0;

  /* Registration from a peer */
  if (subcmd[0] == 'R' && parc >= 6) {
    const char *account = parv[2];
    const char *endpoint = parv[3];
    const char *p256dh = parv[4];
    const char *auth_secret = parv[5];
    long long armed = webpush_wire_armed(parc, parv);
    const char *keyid = webpush_wire_keyid(parc, parv);

    webpush_store_receive(account, endpoint, p256dh, auth_secret, armed, keyid);

    /* Propagate to other servers, arming time and key id included */
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "R %s %s %s %s %lld %s",
                          account, endpoint, p256dh, auth_secret, armed,
                          keyid[0] ? keyid : "-");

    return 0;
  }

  /* Removal from a peer: WP U <account> <endpoint> */
  if (subcmd[0] == 'U' && parc >= 4) {
    const char *account = parv[2];
    const char *endpoint = parv[3];

    if (webpush_store_available()) {
      webpush_subs_cache_invalidate(account);
      webpush_store_remove(account, endpoint);
    }

    /* Propagate to other servers */
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "U %s %s",
                          account, endpoint);

    return 0;
  }

  /* Burst from a linking server */
  if (subcmd[0] == 'B' && parc >= 6) {
    const char *account = parv[2];
    const char *endpoint = parv[3];
    const char *p256dh = parv[4];
    const char *auth_secret = parv[5];
    long long armed = webpush_wire_armed(parc, parv);
    const char *keyid = webpush_wire_keyid(parc, parv);

    /* A burst is a peer's copy: it must never re-arm a record we hold
     * with a newer stamp, or every relink would resurrect what the
     * sweep removed. */
    webpush_store_receive(account, endpoint, p256dh, auth_secret, armed, keyid);

    /* Relay onward: the servers behind us never see the linking
     * server's burst otherwise, so a registration made on a split-off
     * leaf only ever reached its direct peer.  Idempotent at every hop
     * (newer arming time wins), tree topology terminates it. */
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "B %s %s %s %s %lld %s",
                          account, endpoint, p256dh, auth_secret, armed,
                          keyid[0] ? keyid : "-");
    return 0;
  }

  return 0;
}
