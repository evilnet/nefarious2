/*
 * IRC - Internet Relay Chat, ircd/sasl_conf.c
 * Copyright (C) 2026 Nefarious Development
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * @brief Owns the parsed Keycloak {} and Webhook {} block state.
 *
 * See include/sasl_conf.h for the API contract.
 */
#include "config.h"

#include "sasl_conf.h"
#include "client.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "sasl_auth.h"
#include "sasl_webhook.h"

#include <string.h>

#ifdef USE_LIBKC
#include <kc/kc_keycloak.h>
#include <kc/kc_webhook.h>
#endif

/* Buffer sizes — tracked separately so we don't bake an opaque magic number
 * across many lines.  These bound the on-disk conf strings; libkc copies
 * internally so its own limits don't constrain us here. */
#define SC_URL_LEN          256
#define SC_REALM_LEN        128
#define SC_CLIENT_ID_LEN    128
#define SC_CLIENT_SECRET_LEN 256
#define SC_WH_SECRET_LEN    256
#define SC_VHOST_LEN        128
#define SC_PATH_LEN         128

/* ---- Keycloak state ---- */
struct keycloak_state {
  int  seen;                              /* block was parsed this pass */
  char url[SC_URL_LEN];
  char realm[SC_REALM_LEN];
  char client_id[SC_CLIENT_ID_LEN];
  char client_secret[SC_CLIENT_SECRET_LEN];
};
static struct keycloak_state kc_pending;
static struct keycloak_state kc_active;

/* ---- Webhook state ---- */
struct webhook_state {
  int  seen;                              /* block was parsed this pass */
  int  port;
  char secret[SC_WH_SECRET_LEN];
  char vhost[SC_VHOST_LEN];
  char path[SC_PATH_LEN];
  int  max_connections;
  int  max_request_size;
  int  queue_max;
  int  batch_size;
};
static struct webhook_state wh_pending;
static struct webhook_state wh_active;

/* ---- Boot deferral ---- */
static int  sasl_conf_libkc_ready = 0;    /* set true at sasl_conf_boot_apply() */
static int  sasl_conf_deferred_pending = 0; /* "we'd have applied if libkc was ready" */

/* ---- Helpers ---- */
static void copy_str(char *dst, size_t dstsz, const char *src)
{
  if (!src) { dst[0] = '\0'; return; }
  ircd_strncpy(dst, src, dstsz);
}

static int kc_changed(void)
{
  return strcmp(kc_pending.url, kc_active.url)
      || strcmp(kc_pending.realm, kc_active.realm)
      || strcmp(kc_pending.client_id, kc_active.client_id)
      || strcmp(kc_pending.client_secret, kc_active.client_secret);
}

static int wh_changed(void)
{
  return wh_pending.port != wh_active.port
      || strcmp(wh_pending.secret, wh_active.secret)
      || strcmp(wh_pending.vhost, wh_active.vhost)
      || strcmp(wh_pending.path, wh_active.path)
      || wh_pending.max_connections != wh_active.max_connections
      || wh_pending.max_request_size != wh_active.max_request_size
      || wh_pending.queue_max != wh_active.queue_max
      || wh_pending.batch_size != wh_active.batch_size;
}

static int kc_is_configured(const struct keycloak_state *s)
{
  return s->url[0] && s->realm[0] && s->client_id[0];
}

/* ---- Parser-facing API ---- */

void sasl_conf_reset_pending(void)
{
  memset(&kc_pending, 0, sizeof(kc_pending));
  memset(&wh_pending, 0, sizeof(wh_pending));
}

void sasl_conf_keycloak_begin(void)        { kc_pending.seen = 1; }
void sasl_conf_keycloak_set_url(const char *s)
                                           { copy_str(kc_pending.url, sizeof kc_pending.url, s); kc_pending.seen = 1; }
void sasl_conf_keycloak_set_realm(const char *s)
                                           { copy_str(kc_pending.realm, sizeof kc_pending.realm, s); kc_pending.seen = 1; }
void sasl_conf_keycloak_set_client_id(const char *s)
                                           { copy_str(kc_pending.client_id, sizeof kc_pending.client_id, s); kc_pending.seen = 1; }
void sasl_conf_keycloak_set_client_secret(const char *s)
                                           { copy_str(kc_pending.client_secret, sizeof kc_pending.client_secret, s); kc_pending.seen = 1; }

void sasl_conf_webhook_begin(void)         { wh_pending.seen = 1; }
void sasl_conf_webhook_set_port(int port)  { wh_pending.port = port; wh_pending.seen = 1; }
void sasl_conf_webhook_set_secret(const char *s)
                                           { copy_str(wh_pending.secret, sizeof wh_pending.secret, s); wh_pending.seen = 1; }
void sasl_conf_webhook_set_vhost(const char *s)
                                           { copy_str(wh_pending.vhost, sizeof wh_pending.vhost, s); wh_pending.seen = 1; }
void sasl_conf_webhook_set_path(const char *s)
                                           { copy_str(wh_pending.path, sizeof wh_pending.path, s); wh_pending.seen = 1; }
void sasl_conf_webhook_set_max_connections(int n)
                                           { wh_pending.max_connections = n; wh_pending.seen = 1; }
void sasl_conf_webhook_set_max_request_size(int n)
                                           { wh_pending.max_request_size = n; wh_pending.seen = 1; }
void sasl_conf_webhook_set_queue_max(int n)
                                           { wh_pending.queue_max = n; wh_pending.seen = 1; }
void sasl_conf_webhook_set_batch_size(int n)
                                           { wh_pending.batch_size = n; wh_pending.seen = 1; }

/* ---- Apply (push pending → active, re-init libkc on change) ---- */

#ifdef USE_LIBKC

/** Push a single string into a feature via feature_set so existing readers
 * (sasl_local_init, m_authenticate, etc.) transparently see the block
 * values without each having to learn about sasl_conf_*. */
static void push_feature_str(const char *name, const char *value)
{
  const char *fields[2];
  fields[0] = name;
  fields[1] = value ? value : "";
  feature_set(NULL, (const char * const *)fields, 2);
}

/** Push an integer into a feature (feature_set parses it from the string). */
static void push_feature_int(const char *name, int value)
{
  char buf[32];
  const char *fields[2];
  ircd_snprintf(0, buf, sizeof buf, "%d", value);
  fields[0] = name;
  fields[1] = buf;
  feature_set(NULL, (const char * const *)fields, 2);
}

/** Mirror Keycloak{} block values into the legacy features so any code
 * still reading feature_str(FEAT_KEYCLOAK_*) gets the block-derived
 * effective values. */
static void mirror_keycloak_to_features(void)
{
  push_feature_str("KEYCLOAK_URL",           kc_pending.url);
  push_feature_str("KEYCLOAK_REALM",         kc_pending.realm);
  push_feature_str("KEYCLOAK_CLIENT_ID",     kc_pending.client_id);
  push_feature_str("KEYCLOAK_CLIENT_SECRET", kc_pending.client_secret);
}

/** Mirror Webhook{} block values into the legacy features. */
static void mirror_webhook_to_features(void)
{
  push_feature_int("WEBHOOK_PORT",   wh_pending.port);
  push_feature_str("WEBHOOK_SECRET", wh_pending.secret);
}

/** Fill kc_pending from the legacy F_S features (used when no block parsed). */
static void kc_fallback_from_features(void)
{
  copy_str(kc_pending.url,           sizeof kc_pending.url,           feature_str(FEAT_KEYCLOAK_URL));
  copy_str(kc_pending.realm,         sizeof kc_pending.realm,         feature_str(FEAT_KEYCLOAK_REALM));
  copy_str(kc_pending.client_id,     sizeof kc_pending.client_id,     feature_str(FEAT_KEYCLOAK_CLIENT_ID));
  copy_str(kc_pending.client_secret, sizeof kc_pending.client_secret, feature_str(FEAT_KEYCLOAK_CLIENT_SECRET));

  if (kc_pending.url[0]) {
    log_write(LS_CONFIG, L_WARNING, 0,
              "Keycloak: KEYCLOAK_URL/REALM/CLIENT_ID/CLIENT_SECRET features "
              "are deprecated; migrate to a Keycloak {} block.");
  }
}

static void wh_fallback_from_features(void)
{
  wh_pending.port = feature_int(FEAT_WEBHOOK_PORT);
  copy_str(wh_pending.secret, sizeof wh_pending.secret, feature_str(FEAT_WEBHOOK_SECRET));

  if (wh_pending.port > 0) {
    log_write(LS_CONFIG, L_WARNING, 0,
              "Webhook: WEBHOOK_PORT/WEBHOOK_SECRET features are deprecated; "
              "migrate to a Webhook {} block.");
  }
}

static void kc_apply_now(void)
{
  struct kc_config cfg;
  int first_time = (kc_active.url[0] == '\0');

  memset(&cfg, 0, sizeof(cfg));
  cfg.base_url     = kc_pending.url;
  cfg.realm        = kc_pending.realm;
  cfg.client_id    = kc_pending.client_id;
  cfg.client_secret = kc_pending.client_secret;

  /* libkc's init copies the cfg internally and reinitialises on second call. */
  if (kc_keycloak_init(&cfg) != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "Keycloak: kc_keycloak_init failed for realm '%s' on '%s'",
              kc_pending.realm, kc_pending.url);
    return;
  }
  if (first_time && feature_bool(FEAT_SASL_LOCAL))
    sasl_local_init();              /* first-time arming of local SASL */

  memcpy(&kc_active, &kc_pending, sizeof(kc_active));
}

static void wh_apply_now(void)
{
  struct kc_webhook_config cfg;

  if (wh_pending.port == 0) {
    if (wh_active.port != 0) {
      sasl_webhook_shutdown();
      memset(&wh_active, 0, sizeof(wh_active));
    }
    return;
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.port             = wh_pending.port;
  cfg.bind_address     = wh_pending.vhost[0]  ? wh_pending.vhost  : NULL;
  cfg.secret           = wh_pending.secret[0] ? wh_pending.secret : NULL;
  cfg.path             = wh_pending.path[0]   ? wh_pending.path   : NULL;
  cfg.max_request_size = (size_t)wh_pending.max_request_size;
  cfg.max_connections  = wh_pending.max_connections;
  cfg.queue_max        = wh_pending.queue_max;
  cfg.batch_size       = wh_pending.batch_size;

  if (sasl_webhook_init(cfg.port, cfg.secret) != 0)
    return;                          /* sasl_webhook_init already logged */

  memcpy(&wh_active, &wh_pending, sizeof(wh_active));
}

#endif /* USE_LIBKC */

void sasl_conf_apply(void)
{
#ifdef USE_LIBKC
  /* Fall back to legacy features if no block was parsed this pass.
   * If a block WAS parsed, mirror its values into the legacy features
   * so existing readers see them transparently. */
  if (kc_pending.seen)
    mirror_keycloak_to_features();
  else
    kc_fallback_from_features();

  if (wh_pending.seen)
    mirror_webhook_to_features();
  else
    wh_fallback_from_features();

  if (!sasl_conf_libkc_ready) {
    /* Boot path: parser ran before libkc init.  Defer; boot_apply will pick it up. */
    sasl_conf_deferred_pending = 1;
    return;
  }

  if (kc_is_configured(&kc_pending) && kc_changed())
    kc_apply_now();

  if (wh_changed())
    wh_apply_now();
#else
  (void)kc_pending; (void)wh_pending;
  (void)kc_active;  (void)wh_active;
#endif
}

void sasl_conf_boot_apply(void)
{
#ifdef USE_LIBKC
  sasl_conf_libkc_ready = 1;
  if (!sasl_conf_deferred_pending)
    return;
  sasl_conf_deferred_pending = 0;
  if (kc_is_configured(&kc_pending) && kc_changed())
    kc_apply_now();
  if (wh_changed())
    wh_apply_now();
#endif
}
