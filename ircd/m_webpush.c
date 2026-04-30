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
 *   WP V :<vapid_pubkey>                               - VAPID key broadcast
 *   WP R <account> <endpoint> <p256dh> <auth>          - Register subscription
 *   WP U <account> <endpoint>                          - Unregister subscription
 *   WP B <account> <endpoint> <p256dh> <auth>          - Burst subscription on link
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
#include "webpush_store.h"

#include <string.h>
#include <stdlib.h>

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
  ircd_strncpy(p256dh, p256dh_start, p256dh_end - p256dh_start);
  p256dh[p256dh_end - p256dh_start] = '\0';

  ircd_strncpy(auth, auth_start, auth_end - auth_start);
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

  /* Build stored format: "endpoint|p256dh|auth" */
  snprintf(stored, sizeof(stored), "%s|%s|%s", endpoint, p256dh, auth);

  /* Store locally in LMDB */
  if (webpush_store_add(cli_user(sptr)->account, stored) != 0) {
    send_webpush_fail(sptr, "INTERNAL_ERROR", "REGISTER",
                      "Failed to store push subscription");
    return 0;
  }

  /* Broadcast to all linked servers */
  sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "R %s %s %s %s",
                        cli_user(sptr)->account, endpoint, p256dh, auth);

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

  if (result == WEBPUSH_ERR_EXPIRED) {
    /* Subscription expired (HTTP 410) — remove from store */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: subscription expired for %s endpoint %s (HTTP %ld)",
              ctx->account, ctx->endpoint, http_code);

    if (webpush_store_available()) {
      webpush_store_remove(ctx->account, ctx->endpoint);
    }

    /* Broadcast removal to linked servers */
    sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "U %s %s",
                          ctx->account, ctx->endpoint);
  }

  free(ctx);
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

  /* Parse subscription from stored format */
  if (webpush_parse_subscription(stored, &sub) != 0)
    return 0; /* skip invalid, continue iteration */

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
    free(ctx);
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

  webpush_store_foreach(account, notify_iter_cb, &nid);
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
  size_t len;

  /* Parse stored format: "endpoint|p256dh|auth" */
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

  /* Extract auth */
  auth_secret = sep2 + 1;
  len = strlen(auth_secret);
  if (len == 0 || len >= sizeof(auth_buf))
    return 0;
  memcpy(auth_buf, auth_secret, len);
  auth_buf[len] = '\0';

  /* Send burst entry to target server: WP B <account> <endpoint> <p256dh> <auth> */
  sendcmdto_one(&me, CMD_WEBPUSH, bctx->cptr, "B %s %s %s %s",
                account, endpoint, p256dh, auth_buf);

  return 0; /* continue iteration */
}

/** Burst all webpush subscriptions to a newly linked server.
 * Called during server link (e.g., from burst handling code).
 * Iterates all subscriptions in LMDB and sends them via WP B.
 * @param[in] cptr Target server to send burst data to.
 */
void webpush_burst(struct Client *cptr)
{
  struct burst_ctx bctx;

  if (!cptr || !webpush_store_available())
    return;

  bctx.cptr = cptr;
  webpush_store_foreach_all(burst_iter_cb, &bctx);

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBPUSH: burst subscriptions sent to %s",
            cli_name(cptr));
}

/* ---------------------------------------------------------------------------
 * VAPID key initialization and persistence
 * ---------------------------------------------------------------------------*/

/** Initialize the webpush subsystem with VAPID key persistence.
 * Key loading priority:
 *   1. FEAT_WEBPUSH_VAPID_PRIVKEY (config/gitsync) — shared across network
 *   2. Existing key in LMDB store — standalone/legacy
 *   3. Generate new keypair — first start
 *
 * Safe to call on REHASH: compares config key against current key and
 * only re-imports if actually changed.
 *
 * @return 0 on success, -1 on error.
 */
int webpush_setup(void)
{
  unsigned char privkey[32];
  size_t privkey_len = sizeof(privkey);
  const char *vapid_pubkey;
  const char *config_key;
  char old_pubkey[WEBPUSH_VAPID_B64_LEN + 1];
  int had_key = 0;
  int key_loaded = 0;
  int changed;

  if (!webpush_store_available()) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "WEBPUSH: store not available, cannot initialize VAPID key");
    return -1;
  }

  /* Remember old pubkey for change detection (static buffer gets overwritten) */
  vapid_pubkey = webpush_get_vapid_pubkey();
  if (vapid_pubkey) {
    ircd_strncpy(old_pubkey, vapid_pubkey, sizeof(old_pubkey));
    had_key = 1;
  } else {
    old_pubkey[0] = '\0';
  }

  /* Priority 1: Config-based key (FEAT_WEBPUSH_VAPID_PRIVKEY) */
  config_key = feature_str(FEAT_WEBPUSH_VAPID_PRIVKEY);
  if (config_key && config_key[0] != '\0') {
    /* Import config key (base64url-encoded 32-byte P-256 private scalar).
     * On REHASH this may re-import the same key — we detect that below
     * by comparing old_pubkey vs new pubkey and skip broadcast if unchanged. */
    if (webpush_import_vapid_key_b64(config_key, strlen(config_key)) != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "WEBPUSH: failed to import config VAPID key (WEBPUSH_VAPID_PRIVKEY)");
      /* Fall through to LMDB/generation */
    } else {
      /* Persist config key to LMDB so it survives config removal */
      privkey_len = sizeof(privkey);
      if (webpush_export_vapid_privkey(privkey, &privkey_len) == 0) {
        webpush_store_set_vapid_key(privkey, privkey_len);
        memset(privkey, 0, sizeof(privkey));
      }

      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBPUSH: loaded VAPID key from config (WEBPUSH_VAPID_PRIVKEY)");
      key_loaded = 1;
    }
  }

  /* Priority 2: Load from LMDB persistent store */
  if (!key_loaded) {
    privkey_len = sizeof(privkey);
    if (webpush_store_get_vapid_key(privkey, &privkey_len) == 0) {
      if (webpush_import_vapid_key(privkey, privkey_len, NULL, 0) != 0) {
        log_write(LS_SYSTEM, L_ERROR, 0,
                  "WEBPUSH: failed to import persisted VAPID key");
        memset(privkey, 0, sizeof(privkey));
        return -1;
      }
      memset(privkey, 0, sizeof(privkey));
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBPUSH: loaded VAPID key from persistent store");
      key_loaded = 1;
    }
  }

  /* Priority 3: Generate new keypair */
  if (!key_loaded) {
    if (webpush_init() != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "WEBPUSH: failed to generate VAPID keypair");
      return -1;
    }

    privkey_len = sizeof(privkey);
    if (webpush_export_vapid_privkey(privkey, &privkey_len) != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "WEBPUSH: failed to export VAPID private key");
      return -1;
    }

    if (webpush_store_set_vapid_key(privkey, privkey_len) != 0) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "WEBPUSH: failed to persist VAPID key");
    }
    memset(privkey, 0, sizeof(privkey));

    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: generated and persisted new VAPID keypair");
  }

  /* Set the VAPID public key for capability advertisement */
  vapid_pubkey = webpush_get_vapid_pubkey();
  if (vapid_pubkey) {
    /* Only broadcast if the key actually changed */
    changed = (!had_key || strcmp(old_pubkey, vapid_pubkey) != 0);

    set_vapid_pubkey(vapid_pubkey);
    add_isupport_s("VAPID", vapid_pubkey);

    if (changed) {
      sendcmdto_serv_butone_v3(&me, CMD_WEBPUSH, NULL, "V :%s", vapid_pubkey);
      send_isupport_update();
    }

    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBPUSH: VAPID public key: %s%s", vapid_pubkey,
              changed ? " (changed)" : "");
  }

  return 0;
}

/* ---------------------------------------------------------------------------
 * Server-to-server handler
 * ---------------------------------------------------------------------------*/

/** Handle WEBPUSH (WP) command from a server (P10).
 *
 * Incoming formats:
 *   WP V :<vapid_pubkey>                               - VAPID key from peer
 *   WP R <account> <endpoint> <p256dh> <auth>          - Register subscription
 *   WP U <account> <endpoint>                          - Unregister subscription
 *   WP B <account> <endpoint> <p256dh> <auth>          - Burst subscription on link
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

  /* Handle VAPID key broadcast from peer: WP V :<vapid_pubkey> */
  if (subcmd[0] == 'V') {
    const char *vapid_key;

    if (parc < 3)
      return 0;

    vapid_key = parv[2];

    /* Only accept VAPID key if we don't have one yet.
     * Each server generates its own VAPID key; we don't overwrite ours
     * with a peer's key. However if we haven't initialized yet (e.g.,
     * store unavailable), we can use the peer's key as a fallback. */
    if (!webpush_get_vapid_pubkey()) {
      set_vapid_pubkey(vapid_key);
      add_isupport_s("VAPID", vapid_key);

      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBPUSH: accepted VAPID key from peer %s: %s",
                cli_name(sptr), vapid_key);
    } else {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "WEBPUSH: ignoring VAPID key from peer %s (already have our own)",
                cli_name(sptr));
    }

    /* Propagate to other servers regardless */
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "V :%s", vapid_key);

    return 0;
  }

  if (parc < 3)
    return 0;

  /* Handle subscription registration from peer: WP R <account> <endpoint> <p256dh> <auth> */
  if (subcmd[0] == 'R' && parc >= 6) {
    const char *account = parv[2];
    const char *endpoint = parv[3];
    const char *p256dh = parv[4];
    const char *auth_secret = parv[5];
    char stored[4096];

    snprintf(stored, sizeof(stored), "%s|%s|%s", endpoint, p256dh, auth_secret);

    if (webpush_store_available()) {
      webpush_store_add(account, stored);
    }

    /* Propagate to other servers */
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "R %s %s %s %s",
                          account, endpoint, p256dh, auth_secret);

    return 0;
  }

  /* Handle subscription removal from peer: WP U <account> <endpoint> */
  if (subcmd[0] == 'U' && parc >= 4) {
    const char *account = parv[2];
    const char *endpoint = parv[3];

    if (webpush_store_available()) {
      webpush_store_remove(account, endpoint);
    }

    /* Propagate to other servers */
    sendcmdto_serv_butone_v3(sptr, CMD_WEBPUSH, cptr, "U %s %s",
                          account, endpoint);

    return 0;
  }

  /* Handle burst subscription from linking server: WP B <account> <endpoint> <p256dh> <auth> */
  if (subcmd[0] == 'B' && parc >= 6) {
    const char *account = parv[2];
    const char *endpoint = parv[3];
    const char *p256dh = parv[4];
    const char *auth_secret = parv[5];
    char stored[4096];

    snprintf(stored, sizeof(stored), "%s|%s|%s", endpoint, p256dh, auth_secret);

    if (webpush_store_available()) {
      webpush_store_add(account, stored);
    }

    /* Don't propagate burst entries — they come from a single source during link */
    return 0;
  }

  return 0;
}
