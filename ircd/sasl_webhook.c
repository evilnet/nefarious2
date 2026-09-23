/*
 * IRC - Internet Relay Chat, ircd/sasl_webhook.c
 * Copyright (C) 2026 Afternet Development
 *
 * Keycloak webhook handler for Nefarious.
 * Business-logic callback on top of libkc's kc_webhook TCP/HTTP server.
 *
 * Events handled:
 *   - Password change  → invalidate auth caches for user (by name)
 *   - Account delete   → caches purged + sessions deauthed (or local sockets
 *                        killed), the subject resolved by its Keycloak id
 *   - Account disable  → same, from an update carrying enabled:false
 *   - Admin reset      → caches purged by Keycloak id
 *   - Cert revoked     → log
 *   - Session logout   → log (future: revoke OAUTHBEARER tokens)
 * A USER admin event names its subject only by the uuid in resourcePath;
 * the decision is include/webhook_subject.h.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#include "config.h"

/* Common includes needed by both USE_LIBKC and stub/P10 handler paths */
#include "sasl_webhook.h"
#include "account_id.h"
#include "sasl_auth.h"
#include "client.h"
#include "ircd_log.h"
#include "msg.h"
#include "send.h"

#include <string.h>

#ifdef USE_LIBKC

#include "ircd.h"
#include "ircd_features.h"
#include "ircd_alloc.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_misc.h"
#include "s_user.h"
#include "bouncer_deauth.h"
#include "webhook_subject.h"
#include "bouncer_session.h"

#include <jansson.h>
#include <kc/kc_webhook.h>

static struct sasl_webhook_stats wh_stats;
static int webhook_initialized = 0;

/* ---- Session deauth/kill helpers ---- */

/** Force-deauth a single client: clear account, broadcast AC U, notify channels.
 *  The client stays connected but loses all account-associated privileges.
 *  This is the P10 AC U flow — works across the network without patches.
 *  A local held ghost is the one client that does not stay: with its
 *  account gone there is no session to revive, so it leaves once the
 *  clear has been told.
 */
static void deauth_client(struct Client *cptr, const char *reason)
{
  int exit_ghost;

  if (!IsAccount(cptr) || !cli_user(cptr))
    return;

  /* Tell the user why before the account goes away.  A held ghost has
   * no one behind it to tell. */
  if (!IsBouncerHold(cptr))
    sendcmdto_one(&me, CMD_NOTICE, cptr, "%C :%s", cptr, reason);

  /* Shared with ms_account's AC U receiver: alias propagation, session
   * destroy, metadata clear, authusers, presence anchor, account clear. */
  exit_ghost = bounce_account_deauth_apply(cptr);

  /* Notify channel members with account-notify capability. */
  sendcmdto_common_channels_capab_butone(cptr, CMD_ACCOUNT, cptr,
                                          CAP_ACCNOTIFY, CAP_NONE, "*");

  /* Propagate the account clear.  "AC <numeric> U" is EXTENDED_ACCOUNTS
   * syntax; the legacy AC grammar has no unregister form at all (a
   * legacy parser reads "U" as an account name and raises a protocol
   * violation on the already-registered user).  handle_user_event
   * refuses a deauth under legacy accounts before reaching here.
   * For a remote client this is what reaches its home server, which
   * runs the full receiver on the socket it owns. */
  sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C U", cptr);

  wh_stats.sessions_killed++;

  if (exit_ghost) {
    ClearBouncerHold(cptr);
    exit_client(cptr, cptr, &me, reason);
  }
}

/** Purge the auth caches for a subject here and on every fork server: by
 * name when the payload names it, by Keycloak id when it carries one.  The
 * id reaches servers that never saw a client for the user. */
static void cache_invalidate_subject(const char *username, const char *kc_id)
{
  int has_id = (kc_id && kc_id[0]) ? 1 : 0;

  if (username)
    sasl_cache_invalidate_user(username);
  if (has_id)
    sasl_cache_invalidate_id(kc_id);

  if (has_id)
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s %s",
                             username ? username : "*", kc_id);
  else if (username)
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s", username);

  wh_stats.cache_invalidations++;
}

/** Classify one client for the account walk (pure decision in
 * bounce_deauth_classify; this only reads the flags). */
static enum BounceDeauthAction
deauth_action_for(struct Client *cptr, const char *account, const char *kc_id,
                  int do_kill)
{
  struct BounceDeauthSubject subj;

  memset(&subj, 0, sizeof(subj));
  subj.is_user         = IsUser(cptr) ? 1 : 0;
  subj.is_account      = IsAccount(cptr) ? 1 : 0;
  subj.account_matches = (cli_user(cptr)
                          && 0 == ircd_strcmp(cli_user(cptr)->account, account)
                          /* A name can be reused; an id cannot.  When the
                           * event and the client both carry one they must
                           * agree.  A client without one (legacy hop,
                           * restored ghost) still matches by name: for a
                           * deauth the safe error is to include it. */
                          && (!kc_id || !kc_id[0] || !cli_user(cptr)->kc_id[0]
                              || 0 == strcmp(cli_user(cptr)->kc_id, kc_id))) ? 1 : 0;
  subj.is_alias        = IsBouncerAlias(cptr) ? 1 : 0;
  subj.is_hold         = IsBouncerHold(cptr) ? 1 : 0;
  subj.is_local        = MyConnect(cptr) ? 1 : 0;

  return bounce_deauth_classify(&subj, do_kill);
}

/** One client the account walk decided to act on, by numeric so the
 * act pass can look it up again after earlier actions have exited
 * clients (an alias of a killed primary, a held ghost). */
struct deauth_hit {
  char numeric[6];
  enum BounceDeauthAction action;
};

/** Apply an account deauth or kill to every session of an account
 * (matched by id too when known).
 *
 * Sockets are only ever exited LOCALLY: exit_client() on a remote victim
 * emits no KILL while broadcasting a victim-sourced QUIT on every
 * downlink -- servers on the victim's own side discard it as
 * wrong-direction, so the account holder stays online at home and
 * disappears elsewhere, permanently, with no oper-visible KILL.  The
 * ACCOUNT is cleared everywhere: a remote client's replica here, and the
 * AC U each deauth broadcasts reaches its home server, which runs the
 * full receiver (and exits a held ghost it owns).
 *
 * Collect-then-act over GlobalClientList (O(n), but account
 * disable/delete is rare): the act pass exits clients (aliases of a
 * killed primary, held ghosts), which would invalidate a saved next
 * pointer, so the walk first records numerics and re-resolves each.
 */
static void handle_sessions_for_account(const char *account, const char *reason,
                                         int do_kill, const char *kc_id)
{
  struct Client *cptr;
  struct deauth_hit *hits;
  int count = 0, n = 0, i;

  /* Pass 1: classify.  Nothing is touched yet, so the list is stable. */
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr))
    if (deauth_action_for(cptr, account, kc_id, do_kill) != BOUNCE_DEAUTH_SKIP)
      count++;
  if (!count)
    return;

  hits = (struct deauth_hit *)MyMalloc(count * sizeof(*hits));
  for (cptr = GlobalClientList; cptr && n < count; cptr = cli_next(cptr)) {
    enum BounceDeauthAction action = deauth_action_for(cptr, account, kc_id, do_kill);
    if (action == BOUNCE_DEAUTH_SKIP)
      continue;
    ircd_snprintf(0, hits[n].numeric, sizeof(hits[n].numeric), "%s%s",
                  cli_yxx(cli_user(cptr)->server), cli_yxx(cptr));
    hits[n].action = action;
    n++;
  }

  /* Pass 2: a killed primary takes its whole session down first --
   * every alias, everywhere, the way a network KILL does -- before any
   * deauth destroys the record the aliases hang off.  A plain socket
   * exit would instead hold the session (a ghost that revives on the
   * next login) or hand it to an alias elsewhere (promotion): the
   * deleted account would live on. */
  if (do_kill) {
    for (i = 0; i < n; i++) {
      struct BouncerSession *sess;
      if (hits[i].action != BOUNCE_DEAUTH_KILL_SOCKET)
        continue;
      cptr = findNUser(hits[i].numeric);
      if (!cptr || IsBouncerAlias(cptr))
        continue;
      sess = bounce_get_session(cptr);
      if (sess && sess->hs_client == cptr)
        bounce_kill_session(sess, reason);
    }
  }

  /* Pass 3: act.  A numeric that no longer resolves was exited by an
   * earlier action and is done; one that no longer carries the account
   * was already cleared. */
  for (i = 0; i < n; i++) {
    cptr = findNUser(hits[i].numeric);
    if (!cptr || !cli_user(cptr) || !IsAccount(cptr)
        || 0 != ircd_strcmp(cli_user(cptr)->account, account))
      continue;

    switch (hits[i].action) {
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
      /* The primary is deauthed before it goes (AC U for the network and
       * X3, every remaining session of the account gone); an alias only
       * loses its socket, its account went with its primary's. */
      if (!IsBouncerAlias(cptr))
        deauth_client(cptr, reason);
      exit_client_msg(cptr, cptr, &me, "%s", reason);
      wh_stats.sessions_killed++;
      break;

    case BOUNCE_DEAUTH_DESTROY_SESSION:
      /* Held ghost: no live socket to notify or kill.  The deauth body
       * takes the session, its aliases, and then the ghost itself --
       * which is what "the account is gone" means for a hold, and which
       * neither a clear nor exit_client_msg() alone achieves (the latter
       * leaves it HOLDING with the DB record intact because FLAG_KILLED
       * is unset; the former leaves a ghost with no timer). */
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Destroying held session for %C (account %s): %s",
                cptr, account, reason);
      deauth_client(cptr, reason);
      break;
    }
  }

  MyFree(hits);
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
    cache_invalidate_subject(event->username, NULL);
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
      cache_invalidate_subject(event->username, NULL);
    }
  }
}

/* ---- User events (delete, disable, admin password reset) ---- */

#define WH_SUBJECT_MAX_NAMES 4

/** The account names a subject resolves to: the payload's own name when it
 * carries one, and the account of every client (local or replica) carrying
 * the subject's Keycloak id.  Distinct; the cap covers a rename race. */
static int subject_account_names(const struct WebhookSubject *s,
                                 char names[][ACCOUNTLEN + 1], int max)
{
  struct Client *cptr;
  int n = 0, i;

  if (s->username && n < max)
    ircd_strncpy(names[n++], s->username, ACCOUNTLEN + 1);
  if (!s->kc_id[0])
    return n;

  for (cptr = GlobalClientList; cptr && n < max; cptr = cli_next(cptr)) {
    if (!IsUser(cptr) || !IsAccount(cptr) || !cli_user(cptr))
      continue;
    if (0 != strcmp(cli_user(cptr)->kc_id, s->kc_id))
      continue;
    for (i = 0; i < n; i++)
      if (0 == ircd_strcmp(names[i], cli_user(cptr)->account))
        break;
    if (i == n)
      ircd_strncpy(names[n++], cli_user(cptr)->account, ACCOUNTLEN + 1);
  }
  return n;
}

/** Deauth (or kill, when the switch is on) every session the subject
 * resolves to, after purging its caches everywhere. */
static void deauth_subject(const struct WebhookSubject *s, const char *reason,
                           enum Feature kill_feature, const char *kill_name)
{
  char names[WH_SUBJECT_MAX_NAMES][ACCOUNTLEN + 1];
  int do_kill = feature_bool(kill_feature);
  int n, i;

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBHOOK: %s: id %s name %s -- invalidating caches",
            reason, s->kc_id[0] ? s->kc_id : "-", s->username ? s->username : "-");
  cache_invalidate_subject(s->username, s->kc_id);

  /* Deauth is not implementable under legacy accounts: the legacy AC
   * grammar has no unregister form, so peers cannot be told, while the
   * BX U alias propagation would still fire -- leaving one session whose
   * connections disagree about their own account and a network that
   * disagrees with us.  A relink then re-teaches the account from the
   * peer's N token, undoing the local clear.  Refuse loudly instead. */
  if (!feature_bool(FEAT_EXTENDED_ACCOUNTS) && !do_kill) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "WEBHOOK: %s deauth REFUSED -- EXTENDED_ACCOUNTS is off and %s "
              "is off; no coherent deauth exists.  Enable one of them.",
              reason, kill_name);
    return;
  }

  n = subject_account_names(s, names, WH_SUBJECT_MAX_NAMES);
  if (!n) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: %s: no session carries id %s", reason, s->kc_id);
    return;
  }
  /* Default: deauth (AC U), which propagates network-wide.  The kill
   * switch escalates to disconnecting LOCAL sockets only. */
  for (i = 0; i < n; i++)
    handle_sessions_for_account(names[i], reason, do_kill, s->kc_id);
}

static void handle_user_event(const struct kc_webhook_event *event)
{
  struct WebhookSubject s;

  wh_stats.user_events++;

  if (!webhook_subject_resolve(event, &s)) {
    log_write(LS_SYSTEM, L_DEBUG, 0,
              "WEBHOOK: USER/%s for %s: nothing to do",
              event->operation_type_str ? event->operation_type_str : "?",
              event->resource_path ? event->resource_path : "(no path)");
    return;
  }

  switch (s.kind) {
  case WH_SUBJECT_DELETE:
    deauth_subject(&s, "Account deleted", FEAT_WEBHOOK_KILL_ON_DELETE, "KILL_ON_DELETE");
    break;
  case WH_SUBJECT_DISABLE:
    deauth_subject(&s, "Account disabled", FEAT_WEBHOOK_KILL_ON_DISABLE, "KILL_ON_DISABLE");
    break;
  case WH_SUBJECT_PASSWORD_RESET:
    /* Keycloak emits no user-level event for an admin reset; this is the
     * only chance to stop the old password answering from the cache. */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: Admin password reset: id %s name %s -- invalidating caches",
              s.kc_id[0] ? s.kc_id : "-", s.username ? s.username : "-");
    cache_invalidate_subject(s.username, s.kc_id);
    break;
  case WH_SUBJECT_ENABLE:
    /* A re-enabled account may sit in the negative cache from a refused
     * attempt while it was disabled; that cache is keyed by name, so it
     * can be purged only when the payload names the user (a console save
     * does, a bare {"enabled":true} toggle does not -- then the entry
     * simply expires, SASL_NEGCACHE_TTL). */
    if (s.username) {
      log_write(LS_SYSTEM, L_INFO, 0,
                "WEBHOOK: Account enabled: %s -- invalidating caches", s.username);
      cache_invalidate_subject(s.username, NULL);
    } else {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "WEBHOOK: USER enable for id %s: no name to purge", s.kc_id);
    }
    break;
  case WH_SUBJECT_LOGOUT:
    log_write(LS_SYSTEM, L_DEBUG, 0, "WEBHOOK: USER logout for id %s: noted",
              s.kc_id[0] ? s.kc_id : "-");
    break;
  case WH_SUBJECT_NONE:
    break;
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
 * Format: <servernumeric> CI <username|*> [<kc_id>]
 *
 * The name form is the original; the id form (step 5's compact Keycloak
 * id) reaches a server that never saw a client for the user, whose
 * positive cache may still hold their password.  "*" stands for "no
 * name".  A receiver without the id form ignores the second parameter and
 * finds nothing under "*"; the message is relayed as received.
 */
int ms_cacheinval(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *username, *kc_id;

  if (parc < 2)
    return 0;

  username = parv[1];
  kc_id = (parc > 2 && account_id_valid(parv[2])) ? parv[2] : NULL;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "CI: Cache invalidation for %s id %s from %C",
            username, kc_id ? kc_id : "-", sptr);

  if (0 != strcmp(username, "*"))
    sasl_cache_invalidate_user(username);
  if (kc_id)
    sasl_cache_invalidate_id(kc_id);

  if (kc_id)
    sendcmdto_serv_butone_v3(sptr, CMD_CACHEINVAL, cptr, "%s %s", username, kc_id);
  else
    sendcmdto_serv_butone_v3(sptr, CMD_CACHEINVAL, cptr, "%s", username);

  return 0;
}
