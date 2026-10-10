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
#include "ircd_reply.h"
#include "numeric.h"
#include "s_stats.h"
#include "send.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "webhook_eventlog.h"

#include <string.h>
#include <stdio.h>

/** Handler counters (both build variants: the CI receiver below counts too). */
static struct sasl_webhook_stats wh_stats;

#define WH_SUBJECT_MAX_NAMES WH_RELAY_MAX_NAMES

/** Add a name to the list unless it is there; the cap is a rename race. */
static int names_add(char names[][ACCOUNTLEN + 1], int n, int max,
                     const char *name)
{
  int i;

  if (!name || !name[0])
    return n;
  for (i = 0; i < n; i++)
    if (0 == ircd_strcmp(names[i], name))
      return n;
  if (n >= max) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "WEBHOOK: more than %d account names for one subject; %s not walked",
              max, name);
    return n;
  }
  ircd_strncpy(names[n++], name, ACCOUNTLEN + 1);
  return n;
}

/** The relay's name slot: the resolved names comma-joined, "*" when none. */
static const char *names_join(char names[][ACCOUNTLEN + 1], int n, char *buf, size_t size)
{
  size_t used = 0;
  int i;

  if (n <= 0)
    return "*";
  buf[0] = '\0';
  for (i = 0; i < n; i++) {
    int w = snprintf(buf + used, size - used, "%s%s", i ? "," : "", names[i]);
    if (w < 0 || (size_t)w >= size - used)
      break;
    used += (size_t)w;
  }
  return buf;
}

/** The applied-events log is sized from WEBHOOK_EVENTLOG_SIZE on first use;
 * a later change to the feature takes effect at the next restart. */
static void eventlog_ensure(void)
{
  static int sized = 0;
  if (!sized) {
    webhook_eventlog_init((unsigned int)feature_int(FEAT_WEBHOOK_EVENTLOG_SIZE));
    sized = 1;
  }
}

/** One relay per event to every IRCv3-aware server: the five-parameter CI
 * (webhook plan 4).  Without a usable event id (a synthetic event without
 * one, a credential event from an older SPI) the two- and three-parameter
 * forms go, as before: purge only, no dedupe. */
static void relay_event(const char *username, const char *kc_id,
                        const char *event_id, char kind)
{
  const char *name = (username && username[0]) ? username : "*";
  const char *id = (kc_id && kc_id[0]) ? kc_id : NULL;

  if (event_id && webhook_eventlog_valid_id(event_id) && webhook_eventlog_valid_kind(kind)) {
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s %s %s %c",
                             name, id ? id : "*", event_id, kind);
    wh_stats.relays_sent++;
  } else if (id) {
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s %s", name, id);
  } else if (username && username[0]) {
    sendcmdto_serv_butone_v3(&me, CMD_CACHEINVAL, NULL, "%s", name);
  }
}

struct catchup_ctx {
  struct Client *peer;
  unsigned int   sent;
};

static void catchup_emit(const struct WebhookEventLogEntry *e, void *data)
{
  struct catchup_ctx *ctx = (struct catchup_ctx *)data;

  sendcmdto_one(&me, CMD_CACHEINVAL, ctx->peer, "%s %s %s %c B",
                e->names[0] ? e->names : "*", e->kc_id[0] ? e->kc_id : "*",
                e->id, e->kind);
  ctx->sent++;
}

/** Catch a newly linked peer up on the events applied here within the
 * window, oldest first, as catch-up relay lines (the trailing B): it
 * applies what it lacks and forwards it on, drops what it has.  A disable
 * that a later enable of the same subject superseded goes as a purge only.
 * Both ends of a relink do this, so what either side applied during a
 * split converges. */
void sasl_webhook_link_catchup(struct Client *cptr)
{
  struct catchup_ctx ctx;
  time_t window = (time_t)feature_int(FEAT_WEBHOOK_EVENTLOG_WINDOW);

  if (!IsIRCv3Aware(cptr))
    return;
  eventlog_ensure();
  ctx.peer = cptr;
  ctx.sent = 0;
  webhook_eventlog_catchup(CurrentTime - window, catchup_emit, &ctx,
                           (unsigned int)feature_int(FEAT_WEBHOOK_EVENTLOG_SIZE));
  if (ctx.sent) {
    wh_stats.catchup_sent += ctx.sent;
    log_write(LS_SYSTEM, L_INFO, 0, "WEBHOOK: caught %C up on %u applied events",
              cptr, ctx.sent);
  }
}

#ifdef USE_LIBKC

#include "ircd_alloc.h"
#include "ircd_snprintf.h"
#include "numnicks.h"
#include "s_misc.h"
#include "s_user.h"
#include "bouncer_deauth.h"
#include "webhook_subject.h"
#include "bouncer_session.h"

#include <jansson.h>
#include <kc/kc_webhook.h>

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

/** Purge the auth caches for a subject here, by name when the payload names
 * it and by Keycloak id when it carries one, then send the one relay that
 * tells every other server to do the same (and, for a delete or disable,
 * to deauth the sessions it owns). */
static int cache_invalidate_subject(const char *username, const char *kc_id,
                                    const char *event_id, char kind,
                                    char names[][ACCOUNTLEN + 1], int max)
{
  int has_id = (kc_id && kc_id[0]) ? 1 : 0;
  int n = 0;

  if (username)
    sasl_cache_invalidate_user(username);
  if (has_id)
    n = sasl_cache_invalidate_id(kc_id, names, max);

  relay_event(username, kc_id, event_id, kind);

  wh_stats.cache_invalidations++;
  return n;
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
  /* Every server receives every event (webhook plan 4): a remote client
   * is its home server's to clear. */
  subj.remote_ok       = 0;

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
      if (sess && sess->hs_client == cptr) {
        bounce_kill_session(sess, reason);
      } else if (!sess) {
        /* Every server receives the event now, and a sibling session's
         * AC U from its own server destroys every session of the account
         * here before this pass runs.  The LOCAL aliases still hang off
         * the primary by pointer; exit them the way bounce_kill_session
         * does, one at a time because each exit unlinks it from the list.
         * A remote alias is its home server's: an exit_client here would
         * broadcast its BX X everywhere but toward that home (the B-2
         * hole), and without a session record no session-level X follows
         * to reach it. */
        struct Client *alias;
        for (;;) {
          for (alias = GlobalClientList; alias; alias = cli_next(alias))
            if (IsBouncerAlias(alias) && MyConnect(alias) && cli_alias_primary(alias) == cptr)
              break;
          if (!alias)
            break;
          exit_client(alias, alias, &me, reason && *reason ? (char *)reason : "Session killed");
        }
      }
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

  /* Every server receives every event: one that arrived here already,
   * directly or through a peer's relay, is done. */
  if (event->id) {
    eventlog_ensure();
    if (webhook_eventlog_record(event->id, WH_RELAY_PURGE, NULL, event->username, CurrentTime)) {
      wh_stats.already_direct++;
      log_write(LS_SYSTEM, L_DEBUG, 0, "WEBHOOK: event %s already applied: dropped", event->id);
      return;
    }
    wh_stats.applied_direct++;
  }

  if (event->operation_type == KC_WH_OP_CREATE ||
      event->operation_type == KC_WH_OP_UPDATE) {
    /* Password change — invalidate all auth caches for this user */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: Password change for %s — invalidating auth caches",
              event->username);
    cache_invalidate_subject(event->username, NULL, event->id, WH_RELAY_PURGE, NULL, 0);
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
      cache_invalidate_subject(event->username, NULL, event->id, WH_RELAY_PURGE, NULL, 0);
    }
  }
}

/* ---- User events (delete, disable, admin password reset) ---- */

/** The account of every client carrying the Keycloak id -- replicas too:
 * resolution is global, only the action is local, and the names go on the
 * relay for peers that own an id-less session of the account. */
static int names_for_id(const char *kc_id, char names[][ACCOUNTLEN + 1], int n, int max)
{
  struct Client *cptr;

  if (!kc_id || !kc_id[0])
    return n;
  for (cptr = GlobalClientList; cptr; cptr = cli_next(cptr)) {
    if (!IsUser(cptr) || !IsAccount(cptr) || !cli_user(cptr))
      continue;
    if (0 != strcmp(cli_user(cptr)->kc_id, kc_id))
      continue;
    n = names_add(names, n, max, cli_user(cptr)->account);
  }
  return n;
}

static int subject_account_names(const struct WebhookSubject *s,
                                 char names[][ACCOUNTLEN + 1], int n, int max)
{
  return names_for_id(s->kc_id, names, n, max);
}

/** Deauth (or kill, when the switch is on) every session the subject
 * resolves to, after purging its caches everywhere.
 *
 * The subject is reached three ways: the name the payload carries (a
 * synthetic event, a full representation), the account names the id purge
 * drops from the positive cache (whoever logged in through local SASL
 * within SASL_POSCACHE_TTL), and the account of every client carrying the
 * id.  A session that has none of those -- authenticated through X3, or
 * behind a legacy hop, or restored from the bouncer DB, all of which carry
 * no id -- is NOT reached by a real (nameless) event; the warning below is
 * the operator's cue. */
static void deauth_subject(const struct WebhookSubject *s, const char *event_id,
                           const char *reason, enum Feature kill_feature,
                           const char *kill_name)
{
  char names[WH_SUBJECT_MAX_NAMES][ACCOUNTLEN + 1];
  char dropped[WH_SUBJECT_MAX_NAMES][ACCOUNTLEN + 1];
  char joined[WH_EVENTLOG_NAMES_LEN];
  int do_kill = feature_bool(kill_feature);
  int n = 0, nd = 0, i;

  log_write(LS_SYSTEM, L_INFO, 0,
            "WEBHOOK: %s: id %s name %s -- invalidating caches",
            reason, s->kc_id[0] ? s->kc_id : "-", s->username ? s->username : "-");

  /* Resolve every name FIRST -- the payload's, the ones the id purge drops
   * from the positive cache, the account of every client carrying the id
   * (replicas included) -- because the relay must carry them: a peer that
   * owns an id-less session of the account (authenticated through X3,
   * restored from the bouncer DB) can match it by name only. */
  n = names_add(names, n, WH_SUBJECT_MAX_NAMES, s->username);
  if (s->username)
    sasl_cache_invalidate_user(s->username);
  if (s->kc_id[0])
    nd = sasl_cache_invalidate_id(s->kc_id, dropped, WH_SUBJECT_MAX_NAMES);
  for (i = 0; i < nd; i++)
    n = names_add(names, n, WH_SUBJECT_MAX_NAMES, dropped[i]);
  n = subject_account_names(s, names, n, WH_SUBJECT_MAX_NAMES);
  wh_stats.cache_invalidations++;
  relay_event(names_join(names, n, joined, sizeof(joined)), s->kc_id, event_id,
              webhook_relay_kind_for(s->kind));
  /* The entry was recorded before the names were known (the dedupe comes
   * first); a catch-up must carry them too. */
  if (event_id)
    webhook_eventlog_set_names(event_id, n ? joined : NULL);

  /* Deauth is not implementable under legacy accounts: the legacy AC
   * grammar has no unregister form, so peers cannot be told, while the
   * BX U alias propagation would still fire -- leaving one session whose
   * connections disagree about their own account and a network that
   * disagrees with us.  A relink then re-teaches the account from the
   * peer's N token, undoing the local clear.  Refuse loudly instead (the
   * purge above still went out). */
  if (!feature_bool(FEAT_EXTENDED_ACCOUNTS) && !do_kill) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "WEBHOOK: %s deauth REFUSED -- EXTENDED_ACCOUNTS is off and %s "
              "is off; no coherent deauth exists.  Enable one of them.",
              reason, kill_name);
    return;
  }

  if (!n) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "WEBHOOK: %s: nothing names the subject of id %s -- no client "
              "carries the id, the cache held no entry, the event carried no "
              "name.  A session authenticated through X3, a legacy hop, or "
              "restored from the bouncer DB carries no id and keeps its account.",
              reason, s->kc_id);
    return;
  }
  /* Deauth the sessions this server owns (the classifier skips remote
   * clients: their home server receives the same event); the kill switch
   * escalates to disconnecting the sockets. */
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

  /* Every server receives every event (directly, through a peer's relay,
   * or through a catch-up): one already applied here is dropped.  An id
   * the log cannot hold (junk, or none) is applied without dedupe. */
  {
    char kind = webhook_relay_kind_for(s.kind);
    if (kind && event->id) {
      eventlog_ensure();
      if (webhook_eventlog_record(event->id, kind, s.kc_id, s.username, CurrentTime)) {
        wh_stats.already_direct++;
        log_write(LS_SYSTEM, L_DEBUG, 0, "WEBHOOK: event %s (%s) already applied: dropped",
                  event->id, webhook_subject_kind_name(s.kind));
        return;
      }
      wh_stats.applied_direct++;
    }
  }

  switch (s.kind) {
  case WH_SUBJECT_DELETE:
    deauth_subject(&s, event->id, "Account deleted", FEAT_WEBHOOK_KILL_ON_DELETE, "KILL_ON_DELETE");
    break;
  case WH_SUBJECT_DISABLE:
    deauth_subject(&s, event->id, "Account disabled", FEAT_WEBHOOK_KILL_ON_DISABLE, "KILL_ON_DISABLE");
    break;
  case WH_SUBJECT_PASSWORD_RESET:
    /* Keycloak emits no user-level event for an admin reset; this is the
     * only chance to stop the old password answering from the cache. */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: Admin password reset: id %s name %s -- invalidating caches",
              s.kc_id[0] ? s.kc_id : "-", s.username ? s.username : "-");
    cache_invalidate_subject(s.username, s.kc_id, event->id, WH_RELAY_RESET, NULL, 0);
    break;
  case WH_SUBJECT_CREDENTIAL_REMOVED:
    /* An admin removed a credential (the password, a certificate); the
     * positive cache would keep answering it. */
    log_write(LS_SYSTEM, L_INFO, 0,
              "WEBHOOK: Credential removed: id %s name %s -- invalidating caches",
              s.kc_id[0] ? s.kc_id : "-", s.username ? s.username : "-");
    cache_invalidate_subject(s.username, s.kc_id, event->id, WH_RELAY_CREDENTIAL, NULL, 0);
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
    } else {
      log_write(LS_SYSTEM, L_DEBUG, 0,
                "WEBHOOK: USER enable for id %s: no name to purge", s.kc_id);
    }
    /* Relayed even without a name: the enable is in this server's
     * applied-events log (it supersedes an earlier disable of the same
     * subject in a catch-up), so every peer must hold it too, or the
     * catch-up would be the first they hear of it. */
    cache_invalidate_subject(s.username, s.kc_id, event->id, WH_RELAY_ENABLE, NULL, 0);
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

/** The listener refused a request: count it, keep the cause, and tell the
 * opers -- at most one notice per cause per minute, with the running count,
 * so a wrong secret or a replay is loud without being a flood. */
static void webhook_reject_notice(const char *peer, const char *cause, void *data)
{
  static const char *const causes[] = { "missing", "malformed", "stale", "mismatch",
                                        "replay", "realm", "no secret configured" };
  static time_t last_notice[8];
  unsigned int i;

  (void)data;
  wh_stats.rejections++;
  wh_stats.last_rejection = CurrentTime;
  ircd_strncpy(wh_stats.last_reject_cause, cause, sizeof(wh_stats.last_reject_cause));
  for (i = 0; i < 7; i++)
    if (0 == strcmp(cause, causes[i]))
      break;
  if (CurrentTime - last_notice[i] < 60)
    return;
  last_notice[i] = CurrentTime;
  sendto_opmask_butone(0, SNO_UNAUTH,
                       "WEBHOOK: request from %s rejected: %s (%lu rejections since boot)",
                       peer, cause, wh_stats.rejections);
}

int sasl_webhook_init(const struct kc_webhook_config *cfg_in)
{
  struct kc_webhook_config cfg;

  if (!cfg_in || cfg_in->port <= 0)
    return 0; /* Not an error -- just disabled */

  cfg = *cfg_in;
  cfg.on_reject = webhook_reject_notice;
  cfg.reject_data = NULL;

  if (kc_webhook_init(&cfg, nef_webhook_handle_event, NULL) != 0) {
    /* kc_webhook_init closed the previous listener before it failed: no
     * event arrives until a rehash brings one up, STATS webhook says so, and
     * every oper hears it (a silent dead listener is what P0-4 set out to end). */
    webhook_initialized = 0;
    log_write(LS_SYSTEM, L_ERROR, 0,
              "WEBHOOK: Failed to start Keycloak webhook listener on %s:%d; "
              "no events are received until a rehash brings it back",
              cfg.bind_address ? cfg.bind_address : "*", cfg.port);
    sendto_opmask_butone(0, SNO_OLDSNO,
                         "WEBHOOK: listener failed to start on %s:%d; Keycloak events are "
                         "NOT received until a rehash brings it back (see STATS webhook)",
                         cfg.bind_address ? cfg.bind_address : "*", cfg.port);
    return -1;
  }

  /* wh_stats is NOT reset: a rehash keeps the counters. */
  webhook_initialized = 1;
  eventlog_ensure();

  log_write(LS_SYSTEM, L_NOTICE, 0,
            "WEBHOOK: Keycloak webhook listener on %s:%d path %s; signature required%s; realm %s",
            cfg.bind_address ? cfg.bind_address : "*", cfg.port,
            cfg.path ? cfg.path : "(default)",
            cfg.legacy_secret ? " (plain secret accepted during the deploy window)" : "",
            cfg.realm_name ? cfg.realm_name : "(not checked)");
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

void sasl_webhook_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  struct kc_webhook_stats t;

  (void)sd; (void)param;
  if (!webhook_initialized) {
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :WEBHOOK listener NOT RUNNING (no Webhook block, port 0, or the last start "
               "failed: see the log; a rehash retries)");
    return;
  }
  kc_webhook_stats_get(&t);
  if (!kc_webhook_is_running())
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
               "W :WEBHOOK listener NOT RUNNING (socket closed); the counters below are the last listener's");
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :WEBHOOK listener: %lu connections (%lu active, %lu refused over the limit), %lu bytes",
             t.connections_total, t.connections_active, t.connections_rejected, t.bytes_received);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Events: %lu authenticated, %lu processed, %lu invalid, %lu dropped (queue %lu)",
             t.events_received, t.events_processed, t.events_invalid, t.events_dropped, t.queue_depth);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Refused: %lu bad or missing signature, %lu replayed, %lu other realm, "
             "%lu plain-secret (transition)",
             t.events_rejected_auth, t.events_replayed, t.events_rejected_realm, t.events_unsigned_legacy);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Without realmName: %lu (accepted; a pre-signing SPI names no realm)",
             t.events_no_realm);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Duplicates: %lu (the SPI's re-signed retries of accepted events: answered 200, not acted on)",
             t.events_duplicate);
  if (t.last_reject_time)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "W :  Last refusal: %s, %lld s ago",
               t.last_reject_cause, (long long)(CurrentTime - t.last_reject_time));
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Handler: %lu user events, %lu credential events, %lu session events; "
             "%lu cache purges, %lu deauths or kills",
             wh_stats.user_events, wh_stats.credential_events, wh_stats.session_events,
             wh_stats.cache_invalidations, wh_stats.sessions_killed);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Applied: %lu direct, %lu via relay, %lu via catch-up; "
             "already applied: %lu direct, %lu relay",
             wh_stats.applied_direct, wh_stats.applied_relay, wh_stats.applied_catchup,
             wh_stats.already_direct, wh_stats.already_relay);
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :  Relays: %lu sent, %lu forwarded; catch-up %lu sent, %lu received; "
             "log %u entries, oldest %lld s",
             wh_stats.relays_sent, wh_stats.relays_forwarded,
             wh_stats.catchup_sent, wh_stats.catchup_received,
             webhook_eventlog_count(),
             webhook_eventlog_oldest() ? (long long)(CurrentTime - webhook_eventlog_oldest()) : 0LL);
  if (t.last_event_time)
    send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG, "W :  Last event: %lld s ago",
               (long long)(CurrentTime - t.last_event_time));
}

void sasl_webhook_stats_get(struct sasl_webhook_stats *out)
{
  if (out)
    memcpy(out, &wh_stats, sizeof(wh_stats));
}

#else /* !USE_LIBKC */

int sasl_webhook_init(const struct kc_webhook_config *cfg)
{
  (void)cfg;
  return -1;
}

void sasl_webhook_shutdown(void) {}

void sasl_webhook_report_stats(struct Client *to, const struct StatDesc *sd, char *param)
{
  (void)sd; (void)param;
  send_reply(to, SND_EXPLICIT | RPL_STATSDEBUG,
             "W :WEBHOOK built without libkc (--disable-keycloak): no listener");
}

void sasl_webhook_stats_get(struct sasl_webhook_stats *out)
{
  if (out)
    memcpy(out, &wh_stats, sizeof(wh_stats));
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
#ifdef USE_LIBKC
/** A relayed delete or disable: deauth every session THIS server owns for
 * the names the relay carries and the ones resolved here.  Remote replicas
 * are their home server's job (it receives the same event). */
static void relay_deauth(char kind, char names[][ACCOUNTLEN + 1], int n, const char *kc_id)
{
  const char *reason;
  enum Feature kill_feature;
  int i, do_kill;

  if (kind == WH_RELAY_DELETE) {
    reason = "Account deleted";
    kill_feature = FEAT_WEBHOOK_KILL_ON_DELETE;
  } else if (kind == WH_RELAY_DISABLE) {
    reason = "Account disabled";
    kill_feature = FEAT_WEBHOOK_KILL_ON_DISABLE;
  } else
    return;
  do_kill = feature_bool(kill_feature);
  if (!feature_bool(FEAT_EXTENDED_ACCOUNTS) && !do_kill)
    return;                     /* the refusal deauth_subject logs; the purge was done */
  for (i = 0; i < n; i++)
    handle_sessions_for_account(names[i], reason, do_kill, kc_id);
}
#endif /* USE_LIBKC */

/** A five-parameter CI that could not be parsed: purge what it names, keep
 * it off the wire, say so once a minute. */
static void relay_junk(struct Client *sptr, int parc, char *parv[])
{
  static time_t last = 0;

  if (parc > 1 && parv[1][0] && strcmp(parv[1], "*") != 0)
    sasl_cache_invalidate_user(parv[1]);
  if (parc > 2 && strcmp(parv[2], "*") != 0 && account_id_valid(parv[2]))
    sasl_cache_invalidate_id(parv[2], NULL, 0);
  if (CurrentTime - last >= 60) {
    last = CurrentTime;
    log_write(LS_SYSTEM, L_WARNING, 0,
              "CI: relay from %C not applied (%d parameters, id %.40s, kind %.4s): purged what it named, forwarded nothing",
              sptr, parc - 1, parc > 3 ? parv[3] : "-", parc > 4 ? parv[4] : "-");
  }
}

/** Apply a relayed (or caught-up) event once: dedupe by its id, purge the
 * caches for every name it carries and every name resolved here, deauth
 * the sessions this server owns for a delete or disable, and pass the
 * plain relay form on.  The B marker of a catch-up line travels one link
 * only. */
static void apply_relay(const struct WebhookRelay *r, struct Client *sptr, struct Client *cptr)
{
  const char *kc_id = (r->kc_id && account_id_valid(r->kc_id)) ? r->kc_id : NULL;
  char names[WH_SUBJECT_MAX_NAMES][ACCOUNTLEN + 1];
  char dropped[WH_SUBJECT_MAX_NAMES][ACCOUNTLEN + 1];
  char list[WH_EVENTLOG_NAMES_LEN];
  char *tok, *save = NULL;
  int n = 0, nd = 0, i;

  eventlog_ensure();
  if (r->catchup)
    wh_stats.catchup_received++;
  if (webhook_eventlog_record(r->event_id, r->kind, kc_id, r->username, CurrentTime)) {
    wh_stats.already_relay++;
    log_write(LS_SYSTEM, L_DEBUG, 0, "CI: event %s from %C already applied: dropped",
              r->event_id, sptr);
    return;
  }
  log_write(LS_SYSTEM, L_INFO, 0,
            "CI: applying event %s (kind %c) for %s id %s from %C%s",
            r->event_id, r->kind, r->username ? r->username : "-",
            kc_id ? kc_id : "-", sptr, r->catchup ? " (catch-up)" : "");

  /* The names the sender resolved, then our own: what the id purge drops
   * here and every client carrying the id. */
  if (r->username) {
    snprintf(list, sizeof(list), "%s", r->username);
    for (tok = strtok_r(list, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
      if (!tok[0])
        continue;
      sasl_cache_invalidate_user(tok);
      n = names_add(names, n, WH_SUBJECT_MAX_NAMES, tok);
    }
  }
  if (kc_id)
    nd = sasl_cache_invalidate_id(kc_id, dropped, WH_SUBJECT_MAX_NAMES);
  for (i = 0; i < nd; i++)
    n = names_add(names, n, WH_SUBJECT_MAX_NAMES, dropped[i]);
  wh_stats.cache_invalidations++;
#ifdef USE_LIBKC
  n = names_for_id(kc_id, names, n, WH_SUBJECT_MAX_NAMES);
  relay_deauth(r->kind, names, n, kc_id);
#else
  (void)n;   /* a build without the Keycloak client purges and forwards only */
#endif
  /* This server's catch-ups carry the merged list: what came on the line
   * plus what was resolved here. */
  if (n) {
    char merged[WH_EVENTLOG_NAMES_LEN];
    webhook_eventlog_set_names(r->event_id, names_join(names, n, merged, sizeof(merged)));
  }
  if (r->catchup)
    wh_stats.applied_catchup++;
  else
    wh_stats.applied_relay++;

  sendcmdto_serv_butone_v3(sptr, CMD_CACHEINVAL, cptr, "%s %s %s %c",
                           r->username ? r->username : "*", kc_id ? kc_id : "*",
                           r->event_id, r->kind);
  wh_stats.relays_forwarded++;
}

int ms_cacheinval(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *username, *kc_id;
  struct WebhookRelay r;

  if (parc < 2)
    return 0;

  /* The five-parameter form (webhook plan 4): an event to apply once. */
  if (parc >= 5) {
    if (!webhook_relay_parse(parc, parv, &r))
      relay_junk(sptr, parc, parv);
    else
      apply_relay(&r, sptr, cptr);
    return 0;
  }

  /* The older forms: purge by name and id, forward, no dedupe. */
  username = parv[1];
  kc_id = (parc > 2 && account_id_valid(parv[2])) ? parv[2] : NULL;

  log_write(LS_SYSTEM, L_DEBUG, 0,
            "CI: Cache invalidation for %s id %s from %C",
            username, kc_id ? kc_id : "-", sptr);

  if (0 != strcmp(username, "*"))
    sasl_cache_invalidate_user(username);
  if (kc_id)
    sasl_cache_invalidate_id(kc_id, NULL, 0);

  if (kc_id)
    sendcmdto_serv_butone_v3(sptr, CMD_CACHEINVAL, cptr, "%s %s", username, kc_id);
  else
    sendcmdto_serv_butone_v3(sptr, CMD_CACHEINVAL, cptr, "%s", username);

  return 0;
}
