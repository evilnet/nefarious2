/*
 * IRC - Internet Relay Chat, ircd/sasl_webhook.c
 * Copyright (C) 2026 Afternet Development
 *
 * Keycloak webhook handler for Nefarious.
 * Business-logic callback on top of libkc's kc_webhook TCP/HTTP server.
 *
 * Events handled:
 *   - Password change  → invalidate auth caches for user
 *   - Account delete   → invalidate caches + kill sessions
 *   - Account disable  → invalidate positive cache + optionally kill sessions
 *   - Cert revoked     → log
 *   - Session logout   → log (future: revoke OAUTHBEARER tokens)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#include "config.h"

/* Common includes needed by both USE_LIBKC and stub/P10 handler paths */
#include "sasl_webhook.h"
#include "sasl_auth.h"
#include "client.h"
#include "ircd_log.h"
#include "msg.h"
#include "send.h"

#include <string.h>

#ifdef USE_LIBKC

#include "ircd.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_misc.h"
#include "s_user.h"
#include "bouncer_deauth.h"
#include "bouncer_session.h"

#include <jansson.h>
#include <kc/kc_webhook.h>

static struct sasl_webhook_stats wh_stats;
static int webhook_initialized = 0;

/* ---- Session deauth/kill helpers ---- */

/** Force-deauth a single client: clear account, broadcast AC U, notify channels.
 *  The client stays connected but loses all account-associated privileges.
 *  This is the P10 AC U flow — works across the network without patches.
 */
static void deauth_client(struct Client *cptr, const char *reason)
{
  if (!IsAccount(cptr) || !cli_user(cptr))
    return;

  /* Tell the user why before the account goes away. */
  sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :%s", cptr, reason);

  /* Shared with ms_account's AC U receiver: session destroy, metadata
   * clear, authusers, presence anchor, alias propagation, account clear. */
  bounce_account_deauth_apply(cptr);

  /* Notify channel members with account-notify capability. */
  sendcmdto_common_channels_capab_butone(cptr, CMD_ACCOUNT, cptr,
                                          CAP_ACCNOTIFY, CAP_NONE, "*");

  /* Propagate the account clear.  "AC <numeric> U" is EXTENDED_ACCOUNTS
   * syntax; the legacy AC grammar has no unregister form at all (a
   * legacy parser reads "U" as an account name and raises a protocol
   * violation on the already-registered user).  handle_user_event
   * refuses a deauth under legacy accounts before reaching here. */
  sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C U", cptr);

  wh_stats.sessions_killed++;
}

/** Apply an account deauth or kill to every LOCAL session of an account.
 *
 * Local only, deliberately.  GlobalClientList is network-wide, and
 * exit_client() on a remote victim emits no KILL while broadcasting a
 * victim-sourced QUIT on every downlink -- servers on the victim's own
 * side discard it as wrong-direction, so the account holder stays online
 * at home and disappears elsewhere, permanently, with no oper-visible
 * KILL.  Remote sessions are reached by the AC U broadcast, which each
 * server applies to its own clients.
 *
 * Walks GlobalClientList -- O(n), but account disable/delete is rare.
 *
 * Iterator note: the saved next is safe because nothing on this path
 * sets FLAG_KILLED, which is what gates every cross-client exit_client()
 * in the teardown chain; aliases sit ahead of their primary in the list.
 * If this path ever sets FLAG_KILLED, re-walk as collect-then-act.
 */
static void handle_sessions_for_account(const char *account, const char *reason,
                                         int do_kill)
{
  struct Client *cptr, *next;

  for (cptr = GlobalClientList; cptr; cptr = next) {
    struct BounceDeauthSubject subj;
    enum BounceDeauthAction action;

    next = cli_next(cptr);

    memset(&subj, 0, sizeof(subj));
    subj.is_user         = IsUser(cptr) ? 1 : 0;
    subj.is_account      = IsAccount(cptr) ? 1 : 0;
    subj.account_matches = (cli_user(cptr)
                            && 0 == ircd_strcmp(cli_user(cptr)->account,
                                                account)) ? 1 : 0;
    subj.is_alias        = IsBouncerAlias(cptr) ? 1 : 0;
    subj.is_hold         = IsBouncerHold(cptr) ? 1 : 0;
    subj.is_local        = MyConnect(cptr) ? 1 : 0;

    action = bounce_deauth_classify(&subj, do_kill);

    switch (action) {
    case BOUNCE_DEAUTH_SKIP:
      break;

    case BOUNCE_DEAUTH_CLEAR_ACCOUNT:
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Deauthing session for %C (account %s): %s",
                cptr, account, reason);
      deauth_client(cptr, reason);
      break;

    case BOUNCE_DEAUTH_KILL_SOCKET:
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Killing session for %C (account %s): %s",
                cptr, account, reason);
      exit_client_msg(cptr, cptr, &me, "%s", reason);
      wh_stats.sessions_killed++;
      break;

    case BOUNCE_DEAUTH_DESTROY_SESSION: {
      /* Held ghost: no live socket to notify or kill.  Remove the
       * session itself, which is what "the account is gone" means for a
       * hold, and which neither a clear nor exit_client_msg() achieves
       * (the latter leaves it HOLDING with the DB record intact because
       * FLAG_KILLED is unset). */
      struct BouncerSession *sess;
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Destroying held session for %C (account %s): %s",
                cptr, account, reason);
      while ((sess = bounce_find_any_session(account)) != NULL)
        bounce_destroy(sess);
      wh_stats.sessions_killed++;
      break;
    }
    }
  }
}

/* ---- Credential events (password change, cert revoke) ---- */

static void handle_credential_event(const struct kc_webhook_event *event)
{
  wh_stats.credential_events++;

  if (!event->username)
    return;

  if (event->operation_type == KC_WH_OP_CREATE ||
      event->operation_type == KC_WH_OP_UPDATE) {
    /* Password change — invalidate all auth caches for this user */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: Password change for %s — invalidating auth caches",
              event->username);
    sasl_cache_invalidate_user(event->username);
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s", event->username);
    wh_stats.cache_invalidations++;
  }
  else if (event->operation_type == KC_WH_OP_DELETE && event->representation) {
    /* Credential deleted — check if it's an x509 cert */
    json_t *type = json_object_get(event->representation, "type");
    if (type && json_is_string(type) &&
        strcmp(json_string_value(type), "x509") == 0) {
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Certificate revoked for %s", event->username);
      /* Future: fingerprint cache invalidation */
    } else {
      /* Password deleted — invalidate caches */
      sasl_cache_invalidate_user(event->username);
      sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s", event->username);
      wh_stats.cache_invalidations++;
    }
  }
}

/* ---- User events (delete, disable) ---- */

static void handle_user_event(const struct kc_webhook_event *event)
{
  wh_stats.user_events++;

  if (!event->username)
    return;

  if (event->operation_type == KC_WH_OP_DELETE) {
    /* Account deleted — invalidate caches + deauth or kill sessions */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: Account deleted: %s — invalidating caches",
              event->username);
    sasl_cache_invalidate_user(event->username);
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s", event->username);
    wh_stats.cache_invalidations++;

    /* Default: deauth (AC U), which propagates network-wide.
     * KILL_ON_DELETE escalates to disconnecting LOCAL sockets only. */
    handle_sessions_for_account(event->username, "Account deleted",
                                 feature_bool(FEAT_WEBHOOK_KILL_ON_DELETE));
  }
  else if (event->operation_type == KC_WH_OP_UPDATE && event->representation) {
    /* Account updated — check if disabled */
    json_t *enabled = json_object_get(event->representation, "enabled");
    if (enabled && json_is_false(enabled)) {
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Account disabled: %s — invalidating caches",
                event->username);
      sasl_cache_invalidate_user(event->username);
      sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s", event->username);
      wh_stats.cache_invalidations++;

      /* Default: deauth (AC U), which propagates network-wide.
       * KILL_ON_DISABLE escalates to disconnecting LOCAL sockets only. */
      handle_sessions_for_account(event->username, "Account disabled",
                                   feature_bool(FEAT_WEBHOOK_KILL_ON_DISABLE));
    }
  }
}

/* ---- Session events (logout) ---- */

static void handle_session_event(const struct kc_webhook_event *event)
{
  wh_stats.session_events++;

  if (event->operation_type == KC_WH_OP_DELETE) {
    const char *username = event->username;
    if (!username && event->has_auth_details)
      username = event->auth_details.username;

    if (username) {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "WEBHOOK: Session logout for %s", username);
      /* Future: revoke OAUTHBEARER tokens for this user */
    }
  }
}

/* ---- Main event dispatcher ---- */

static void nef_webhook_handle_event(const struct kc_webhook_event *event,
                                      void *data)
{
  (void)data;

  wh_stats.events_processed++;
  wh_stats.last_event_time = CurrentTime;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "WEBHOOK: Event %s/%s user=%s path=%s",
            event->resource_type_str ? event->resource_type_str : "?",
            event->operation_type_str ? event->operation_type_str : "?",
            event->username ? event->username : "(null)",
            event->resource_path ? event->resource_path : "(null)");

  switch (event->resource_type) {
  case KC_WH_RESOURCE_CREDENTIAL:
    handle_credential_event(event);
    break;

  case KC_WH_RESOURCE_USER:
    handle_user_event(event);
    break;

  case KC_WH_RESOURCE_USER_SESSION:
  case KC_WH_RESOURCE_ADMIN_EVENT:
    handle_session_event(event);
    break;

  case KC_WH_RESOURCE_GROUP_MEMBERSHIP:
  case KC_WH_RESOURCE_GROUP:
    /* No ChanServ in Nefarious — group events are X3's concern */
    break;

  default:
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "WEBHOOK: Ignoring unhandled resource type: %s",
              event->resource_type_str ? event->resource_type_str : "unknown");
    break;
  }
}

/* ---- Public API ---- */

int sasl_webhook_init(int port, const char *secret)
{
  struct kc_webhook_config cfg;

  if (port <= 0)
    return 0; /* Not an error — just disabled */

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = port;
  cfg.secret = secret;
  /* Use libkc defaults for everything else */

  if (kc_webhook_init(&cfg, nef_webhook_handle_event, NULL) != 0) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WEBHOOK: Failed to start Keycloak webhook listener on port %d",
              port);
    return -1;
  }

  memset(&wh_stats, 0, sizeof(wh_stats));
  webhook_initialized = 1;

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "WEBHOOK: Keycloak webhook listener started on port %d", port);
  return 0;
}

void sasl_webhook_shutdown(void)
{
  if (webhook_initialized) {
    kc_webhook_shutdown();
    webhook_initialized = 0;
    log_write(LS_SYSTEM, L_NOTICE, 0, "WEBHOOK: Shutdown");
  }
}

void sasl_webhook_stats_get(struct sasl_webhook_stats *out)
{
  if (out)
    memcpy(out, &wh_stats, sizeof(wh_stats));
}

#else /* !USE_LIBKC */

int sasl_webhook_init(int port, const char *secret)
{
  (void)port; (void)secret;
  return -1;
}

void sasl_webhook_shutdown(void) {}

void sasl_webhook_stats_get(struct sasl_webhook_stats *out)
{
  if (out)
    memset(out, 0, sizeof(*out));
}

#endif /* USE_LIBKC */

/* ---- P10 CI (Cache Invalidate) handler ----
 * This handler is independent of USE_LIBKC since any server
 * can receive CI messages from a peer that has webhook support.
 *
 * Format: <servernumeric> CI <username>
 */
int ms_cacheinval(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *username;

  if (parc < 2)
    return 0;

  username = parv[1];

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "CI: Cache invalidation for %s from %C", username, sptr);

  /* Invalidate local auth caches for this user */
  sasl_cache_invalidate_user(username);

  /* Relay to all other servers (flood-fill) */
  sendcmdto_serv_butone_v3(sptr, CMD_CACHEINVAL, cptr, "%s", username);

  return 0;
}
