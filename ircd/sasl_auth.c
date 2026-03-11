/*
 * IRC - Internet Relay Chat, ircd/sasl_auth.c
 * Copyright (C) 2026 Afternet Development
 *
 * Local SASL authentication via Keycloak (libkc).
 * Handles SASL PLAIN directly in the IRCd without relaying through X3 services.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 */
#include "config.h"

#include "sasl_auth.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"
#include "send.h"
#include "bouncer_session.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_user.h"
#include "metadata.h"

#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>

#ifdef USE_LIBKC
#include <kc/kc_keycloak.h>
#include <kc/kc_jwt.h>
#endif

/* Forward declarations */
static void sasl_local_timeout_cb(struct Event *ev);
#ifdef USE_LIBKC
static void sasl_health_cb(int result, const struct kc_access_token *token, void *data);
#endif

/* ---- Health tracking ---- */

/** Whether the Keycloak SASL backend is currently healthy. */
static int kc_sasl_healthy = 0;

/** Whether sasl_local_init() succeeded. */
static int sasl_local_initialized = 0;

/* ---- Base64 helpers ---- */

/** Decode standard base64 into output buffer.
 *  @return 1 on success, 0 on failure.
 */
static int sasl_base64_decode(const char *input, unsigned char *output,
                              size_t output_size, size_t *decoded_len)
{
  int inlen = strlen(input);
  int outlen;

  if (inlen == 0) {
    *decoded_len = 0;
    return 1;
  }

  /* EVP_DecodeBlock requires output buffer of at least 3/4 of input */
  if ((size_t)inlen * 3 / 4 > output_size)
    return 0;

  outlen = EVP_DecodeBlock(output, (const unsigned char *)input, inlen);
  if (outlen < 0)
    return 0;

  /* EVP_DecodeBlock doesn't account for padding, adjust for = characters */
  if (inlen > 0 && input[inlen - 1] == '=') {
    outlen--;
    if (inlen > 1 && input[inlen - 2] == '=')
      outlen--;
  }

  *decoded_len = outlen;
  return 1;
}

/* ---- Session management ---- */

/** Allocate and initialize a new SASL session. */
static struct SASLSession *sasl_session_alloc(enum SASLMechanism mech)
{
  struct SASLSession *s = (struct SASLSession *)MyCalloc(1, sizeof(struct SASLSession));
  s->mech = mech;
  s->state = SASL_STATE_INIT;
  return s;
}

/** Free a SASL session and all its resources. */
void sasl_session_free(struct Client *sptr)
{
  struct SASLSession *s = cli_saslsession(sptr);
  if (!s)
    return;

  if (s->accumulated_data) {
    MyFree(s->accumulated_data);
    s->accumulated_data = NULL;
  }
  MyFree(s);
  cli_saslsession(sptr) = NULL;
}

/* ---- sasl_complete_login: shared between local and P10 paths ---- */

/** Complete a successful SASL login.
 *
 *  This is the shared function called by both the local Keycloak SASL path
 *  and the P10 relay path (ms_sasl D/S handler).  It performs:
 *   1. Set cli_saslaccount
 *   2. Send RPL_LOGGEDIN to client
 *   3. auth_set_account (pre-registration)
 *   4. SetHiddenHost (pre-registration, if configured)
 *   5. SetSASLComplete + RPL_SASLSUCCESS
 *   6. For registered users: metadata_load_account, account update,
 *      bounce_emit_alias_update, account-notify, AC broadcast, hide_hostmask
 *   7. auth_sasl_done to unblock registration
 *   8. Clean up SASL session state and timer
 */
void sasl_complete_login(struct Client *sptr, const char *account,
                         time_t acc_create)
{
  /* 1. Set account name */
  ircd_strncpy(cli_saslaccount(sptr), account, ACCOUNTLEN + 1);

  /* 2. Send RPL_LOGGEDIN */
  send_reply(sptr, RPL_LOGGEDIN,
             BadPtr(cli_name(sptr)) ? "*" : cli_name(sptr),
             (!cli_user(sptr) || BadPtr(cli_user(sptr)->username)) ? "*" : cli_user(sptr)->username,
             (!cli_user(sptr) || BadPtr(cli_user(sptr)->host)) ? "*" : cli_user(sptr)->host,
             cli_saslaccount(sptr), cli_saslaccount(sptr));

  /* 3. Set account in auth request (pre-registration) */
  if (cli_auth(sptr))
    auth_set_account(cli_auth(sptr), cli_saslaccount(sptr));

  /* 4. Set account creation time */
  if (acc_create)
    cli_saslacccreate(sptr) = acc_create;

  /* 5. Pre-registration hidden host setup */
  if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
       (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
      feature_bool(FEAT_SASL_AUTOHIDEHOST)) {
    SetHiddenHost(sptr);
  }

  /* 6. SetSASLComplete + RPL_SASLSUCCESS */
  SetSASLComplete(sptr);
  send_reply(sptr, RPL_SASLSUCCESS);

  /* 7. Post-registration account update (reauth or if already registered) */
  if (IsRegistered(sptr) && cli_user(sptr) && cli_saslaccount(sptr)[0]) {
    char type = IsAccount(sptr) ? 'M' : 'R';

    if (ircd_strcmp(cli_user(sptr)->account, cli_saslaccount(sptr)) != 0) {
      /* Load account-linked metadata BEFORE setting account flag */
      metadata_load_account(sptr, cli_saslaccount(sptr));

      ircd_strncpy(cli_user(sptr)->account, cli_saslaccount(sptr), ACCOUNTLEN + 1);
      SetAccount(sptr);

      bounce_emit_alias_update(sptr, "account", cli_user(sptr)->account);

      if (cli_saslacccreate(sptr))
        cli_user(sptr)->acc_create = cli_saslacccreate(sptr);

      /* Notify channel members with account-notify capability */
      sendcmdto_common_channels_capab_butone(sptr, CMD_ACCOUNT, sptr,
                                              CAP_ACCNOTIFY, CAP_NONE,
                                              "%s", cli_user(sptr)->account);

      /* Propagate to other servers */
      if (feature_bool(FEAT_EXTENDED_ACCOUNTS)) {
        if (cli_user(sptr)->acc_create) {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %c %s %Tu",
                                sptr, type, cli_user(sptr)->account,
                                cli_user(sptr)->acc_create);
        } else {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %c %s",
                                sptr, type, cli_user(sptr)->account);
        }
      } else {
        if (cli_user(sptr)->acc_create) {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %s %Tu",
                                sptr, cli_user(sptr)->account,
                                cli_user(sptr)->acc_create);
        } else {
          sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %s",
                                sptr, cli_user(sptr)->account);
        }
      }

      /* Apply hidden host if applicable */
      if (((feature_int(FEAT_HOST_HIDING_STYLE) == 1) ||
           (feature_int(FEAT_HOST_HIDING_STYLE) == 3)) &&
          IsHiddenHost(sptr))
        hide_hostmask(sptr);
    }
  }

  /* 8. Clean up SASL session state */
  if ((cli_saslagent(sptr) != NULL) && cli_saslagentref(cli_saslagent(sptr)))
    cli_saslagentref(cli_saslagent(sptr))--;
  cli_saslagent(sptr) = NULL;
  cli_saslcookie(sptr) = 0;
  cli_saslstart(sptr) = 0;
  if (t_active(&cli_sasltimeout(sptr)))
    timer_del(&cli_sasltimeout(sptr));

  /* Free local SASL session if present */
  sasl_session_free(sptr);

  /* 9. Unblock registration */
  if (cli_auth(sptr))
    auth_sasl_done(cli_auth(sptr));
}

/* ---- PLAIN mechanism handler ---- */

#ifdef USE_LIBKC

/** Callback from kc_user_verify_password(). */
static void sasl_plain_cb(int result, const struct kc_access_token *token, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;

  /* Re-resolve client via FD + cookie (use-after-free protection) */
  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;  /* Client disconnected or FD reused */
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL PLAIN: Callback for %C but session state is wrong", acptr);
    return;
  }

  if (result == KC_SUCCESS) {
    const char *login_as = session->authzid[0] ? session->authzid : session->authcid;
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL PLAIN: Successful authentication for %s (client %C)",
              login_as, acptr);
    sasl_complete_login(acptr, login_as, CurrentTime);
  } else {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL PLAIN: Failed authentication for %s (client %C, result %d)",
              session->authcid, acptr, result);
    /* Send failure and clean up */
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
  }
}

/** Handle decoded PLAIN data: authzid\0authcid\0password */
static int sasl_handle_plain(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *authzid_str;
  const char *authcid_str;
  const char *password_str;
  const char *p;
  const char *end = (const char *)decoded + len;
  struct sasl_cb_ctx *ctx;

  /* Parse PLAIN: authzid\0authcid\0password
   * authzid may be empty (starts with \0).
   */
  authzid_str = (const char *)decoded;

  /* Find first NUL — boundary between authzid and authcid */
  p = memchr(decoded, '\0', len);
  if (!p || p >= end - 1) {
    send_reply(sptr, ERR_SASLFAIL, ": malformed PLAIN data");
    return -1;
  }
  authcid_str = p + 1;

  /* Find second NUL — boundary between authcid and password */
  p = memchr(authcid_str, '\0', end - authcid_str);
  if (!p || p >= end - 1) {
    send_reply(sptr, ERR_SASLFAIL, ": malformed PLAIN data");
    return -1;
  }
  password_str = p + 1;

  /* Validate authcid and password are non-empty */
  if (!*authcid_str || !*password_str) {
    send_reply(sptr, ERR_SASLFAIL, ": empty username or password");
    return -1;
  }

  /* Validate lengths */
  if (strlen(authcid_str) > ACCOUNTLEN) {
    send_reply(sptr, ERR_SASLFAIL, ": username too long");
    return -1;
  }

  /* Save authcid and authzid in session */
  ircd_strncpy(session->authcid, authcid_str, sizeof(session->authcid));
  if (*authzid_str && ircd_strcmp(authzid_str, authcid_str) != 0) {
    if (strlen(authzid_str) > ACCOUNTLEN) {
      send_reply(sptr, ERR_SASLFAIL, ": authzid too long");
      return -1;
    }
    ircd_strncpy(session->authzid, authzid_str, sizeof(session->authzid));
    /* TODO: Validate authcid is authorized to assert authzid (service account check) */
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL PLAIN: authzid impersonation: %s acting as %s (client %C)",
              authcid_str, authzid_str, sptr);
  }

  /* Set state to waiting for Keycloak response */
  session->state = SASL_STATE_WAITING_KC;

  /* Allocate callback context — NEVER pass raw Client pointer */
  ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
  ctx->fd = cli_fd(sptr);
  ctx->cookie = cli_saslcookie(sptr);

  /* Fire async Keycloak password verification */
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL PLAIN: Verifying credentials for %s (client %C)",
            authcid_str, sptr);
  kc_user_verify_password(authcid_str, password_str, sasl_plain_cb, ctx);

  return 0;
}

/* ---- EXTERNAL mechanism handler ---- */

/** Callback from kc_user_search() for fingerprint lookup. */
static void sasl_external_cb(int result, const struct kc_user *users, int count, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;

  /* Re-resolve client via FD + cookie (use-after-free protection) */
  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL EXTERNAL: Callback for %C but session state is wrong", acptr);
    return;
  }

  if (result == KC_SUCCESS && count == 1) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL EXTERNAL: Fingerprint matched user %s (client %C)",
              users[0].username, acptr);
    sasl_complete_login(acptr, users[0].username, CurrentTime);
  } else if (count > 1) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL EXTERNAL: Fingerprint collision — %d users matched (client %C)",
              count, acptr);
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
  } else {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL EXTERNAL: No user found for fingerprint (client %C, result %d)",
              acptr, result);
    send_reply(acptr, ERR_SASLFAIL, "");
    session->state = SASL_STATE_FAILED;
    cli_saslcookie(acptr) = 0;
    cli_saslstart(acptr) = 0;
    if (t_active(&cli_sasltimeout(acptr)))
      timer_del(&cli_sasltimeout(acptr));
    sasl_session_free(acptr);
    if (cli_auth(acptr))
      auth_sasl_done(cli_auth(acptr));
  }
}

/** Handle EXTERNAL mechanism — lookup client certificate fingerprint in Keycloak. */
static int sasl_handle_external(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  const char *fingerprint = cli_sslclifp(sptr);
  char query[256];
  struct sasl_cb_ctx *ctx;

  /* Client must have a TLS client certificate */
  if (!fingerprint || !*fingerprint) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL EXTERNAL: No client certificate for %C", sptr);
    send_reply(sptr, ERR_SASLFAIL, ": no client certificate");
    return -1;
  }

  /* If client sent an authzid, save it (for authorization identity assertion) */
  if (decoded && len > 0) {
    size_t zlen = len < ACCOUNTLEN ? len : ACCOUNTLEN;
    memcpy(session->authzid, decoded, zlen);
    session->authzid[zlen] = '\0';
  }

  session->state = SASL_STATE_WAITING_KC;

  /* Allocate callback context */
  ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
  ctx->fd = cli_fd(sptr);
  ctx->cookie = cli_saslcookie(sptr);

  /* Search Keycloak for user with matching x509_fingerprints attribute */
  snprintf(query, sizeof(query), "x509_fingerprints:%s", fingerprint);
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL EXTERNAL: Searching for fingerprint %s (client %C)",
            fingerprint, sptr);
  kc_user_search(query, true, sasl_external_cb, ctx);

  return 0;
}

/* ---- OAUTHBEARER mechanism handler ---- */

/** Parse RFC 7628 OAUTHBEARER initial client response.
 *  Format: gs2-header kvsep *kvpair kvsep
 *  gs2-header = "n" / "y" / "p=..." "," [authzid] ","
 *  kvpair = key "=" value (separated by \x01)
 *
 *  Example: n,a=user,\x01auth=Bearer <token>\x01\x01
 *  Example: n,,\x01auth=Bearer <token>\x01\x01
 *
 *  @return 0 on success (token extracted), -1 on parse error.
 */
static int oauthbearer_parse(const unsigned char *data, size_t len,
                             char *authzid_out, size_t authzid_size,
                             const char **token_out, size_t *token_len_out)
{
  const char *p = (const char *)data;
  const char *end = p + len;
  const char *comma;

  /* Must start with gs2-cb-flag: 'n' (no channel binding), 'y', or 'p=' */
  if (p >= end || (*p != 'n' && *p != 'y' && *p != 'p'))
    return -1;

  /* Skip gs2-cb-flag to first comma */
  comma = memchr(p, ',', end - p);
  if (!comma)
    return -1;
  p = comma + 1;

  /* Optional authzid: "a=<value>" or empty */
  comma = memchr(p, ',', end - p);
  if (!comma)
    return -1;

  if (comma > p && p[0] == 'a' && p[1] == '=') {
    size_t azlen = comma - p - 2;
    if (azlen > 0 && azlen < authzid_size) {
      memcpy(authzid_out, p + 2, azlen);
      authzid_out[azlen] = '\0';
    }
  }
  p = comma + 1;

  /* Now at key-value pairs separated by \x01.
   * Must start with \x01, then key=value pairs. */
  if (p >= end || *p != '\x01')
    return -1;
  p++;

  /* Search for "auth=Bearer " key-value pair */
  while (p < end && *p != '\x01') {
    const char *kvsep = memchr(p, '\x01', end - p);
    if (!kvsep)
      kvsep = end;

    if (kvsep - p > 12 && strncmp(p, "auth=Bearer ", 12) == 0) {
      *token_out = p + 12;
      *token_len_out = kvsep - p - 12;
      return 0;
    }

    p = kvsep;
    if (p < end && *p == '\x01')
      p++;
  }

  return -1;  /* No bearer token found */
}

/** Callback from kc_token_introspect() for OAUTHBEARER fallback. */
static void sasl_oauth_introspect_cb(int result, const struct kc_token_info *info, void *data)
{
  struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)data;
  struct Client *acptr;
  struct SASLSession *session;

  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie) {
    MyFree(ctx);
    return;
  }
  MyFree(ctx);

  session = cli_saslsession(acptr);
  if (!session || session->state != SASL_STATE_WAITING_KC) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL OAUTHBEARER: Introspect callback for %C but session state is wrong", acptr);
    return;
  }

  if (result == KC_SUCCESS && info && info->active && info->username) {
    /* Use authzid if set, otherwise username from token */
    const char *login_as = session->authzid[0] ? session->authzid : info->username;
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: Introspect success for %s (client %C)",
              login_as, acptr);
    sasl_complete_login(acptr, login_as, CurrentTime);
  } else {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: Introspect failed for %C (result %d, active=%d)",
              acptr, result, info ? info->active : 0);
    /* RFC 7628 §3.2.3: Send error challenge, then wait for client to send
     * "*" (abort).  The abort triggers sasl_abort_local → ERR_SASLFAIL. */
    sendrawto_one(acptr, MSG_AUTHENTICATE " "
                  "eyJzdGF0dXMiOiJpbnZhbGlkX3Rva2VuIn0=");  /* {"status":"invalid_token"} */
    session->state = SASL_STATE_FAILED;
  }
}

/** Handle decoded OAUTHBEARER data. */
static int sasl_handle_oauthbearer(struct Client *sptr, const unsigned char *decoded, size_t len)
{
  struct SASLSession *session = cli_saslsession(sptr);
  char authzid[ACCOUNTLEN + 1] = {0};
  const char *token_str = NULL;
  size_t token_len = 0;
  char *token_nul = NULL;
  struct kc_realm realm;
  struct kc_token_info *info = NULL;
  int rc;

  /* Parse OAUTHBEARER format */
  if (oauthbearer_parse(decoded, len, authzid, sizeof(authzid),
                        &token_str, &token_len) != 0 || !token_str || token_len == 0) {
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: Malformed data from %C", sptr);
    send_reply(sptr, ERR_SASLFAIL, ": malformed OAUTHBEARER data");
    return -1;
  }

  /* Save authzid if present */
  if (authzid[0])
    ircd_strncpy(session->authzid, authzid, sizeof(session->authzid));

  /* NUL-terminate token for libkc (which expects C strings) */
  token_nul = (char *)MyMalloc(token_len + 1);
  memcpy(token_nul, token_str, token_len);
  token_nul[token_len] = '\0';

  /* Strategy 1: Try local JWKS validation (synchronous, fast if cached) */
  realm.base_url = feature_str(FEAT_KEYCLOAK_URL);
  realm.realm = feature_str(FEAT_KEYCLOAK_REALM);

  rc = kc_jwt_validate_local(realm, token_nul, &info);
  if (rc == KC_SUCCESS && info && info->username) {
    const char *login_as = session->authzid[0] ? session->authzid : info->username;
    log_write(LS_SYSTEM, L_INFO, 0,
              "SASL OAUTHBEARER: JWT validated locally for %s (client %C)",
              login_as, sptr);
    MyFree(token_nul);
    sasl_complete_login(sptr, login_as, CurrentTime);
    kc_jwt_token_info_free(info);
    return 0;
  }

  if (info) {
    kc_jwt_token_info_free(info);
    info = NULL;
  }

  /* Strategy 2: Fall back to async token introspection */
  log_write(LS_SYSTEM, L_DEBUG, 0,
            "SASL OAUTHBEARER: JWT local validation failed (rc=%d), "
            "falling back to introspection for %C", rc, sptr);

  session->state = SASL_STATE_WAITING_KC;

  {
    struct sasl_cb_ctx *ctx = (struct sasl_cb_ctx *)MyMalloc(sizeof(struct sasl_cb_ctx));
    ctx->fd = cli_fd(sptr);
    ctx->cookie = cli_saslcookie(sptr);

    if (kc_token_introspect(token_nul, sasl_oauth_introspect_cb, ctx) != 0) {
      MyFree(ctx);
      MyFree(token_nul);
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL OAUTHBEARER: Failed to submit introspection for %C", sptr);
      send_reply(sptr, ERR_SASLFAIL, ": introspection unavailable");
      return -1;
    }
  }

  MyFree(token_nul);
  return 0;
}

#endif /* USE_LIBKC */

/* ---- Framework functions ---- */

int sasl_local_available(void)
{
#ifdef USE_LIBKC
  return sasl_local_initialized && feature_bool(FEAT_SASL_LOCAL) && kc_sasl_healthy;
#else
  return 0;
#endif
}

const char *sasl_local_mechanisms(void)
{
  if (!sasl_local_available())
    return NULL;
  return "PLAIN,EXTERNAL,OAUTHBEARER";
}

int sasl_start(struct Client *sptr, const char *mechanism)
{
  enum SASLMechanism mech;

  if (!sasl_local_available())
    return -1;

  /* Parse mechanism name */
  if (ircd_strcmp(mechanism, "PLAIN") == 0)
    mech = SASL_MECH_PLAIN;
  else if (ircd_strcmp(mechanism, "EXTERNAL") == 0)
    mech = SASL_MECH_EXTERNAL;
  else if (ircd_strcmp(mechanism, "OAUTHBEARER") == 0)
    mech = SASL_MECH_OAUTHBEARER;
  else
    return -1;  /* Unsupported mechanism — fall through to P10 */

#ifdef USE_LIBKC
  {
    struct SASLSession *session;

    /* Allocate session */
    session = sasl_session_alloc(mech);
    cli_saslsession(sptr) = session;

    /* Generate SASL cookie if needed */
    if (!cli_saslcookie(sptr)) {
      do {
        cli_saslcookie(sptr) = ircrandom() & 0x7fffffff;
      } while (!cli_saslcookie(sptr));
      cli_saslstart(sptr) = CurrentTime;
      if (cli_auth(sptr))
        auth_sasl_start(cli_auth(sptr));
    }

    /* Send AUTHENTICATE + to request client data */
    sendrawto_one(sptr, MSG_AUTHENTICATE " +");

    /* Start timeout timer */
    if (!t_active(&cli_sasltimeout(sptr)))
      timer_add(timer_init(&cli_sasltimeout(sptr)), sasl_local_timeout_cb, (void *)sptr,
                TT_RELATIVE, feature_int(FEAT_SASL_TIMEOUT));

    return 0;
  }
#else
  return -1;
#endif
}

int sasl_continue(struct Client *sptr, const char *data)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (!session)
    return -1;

  /* OAUTHBEARER §3.2.3: After server sends error challenge, client responds
   * with dummy data or "*".  Either way, we send ERR_SASLFAIL and clean up. */
  if (session->state == SASL_STATE_FAILED) {
    send_reply(sptr, ERR_SASLFAIL, "");
    sasl_abort_local(sptr);
    return 0;
  }

  /* Only accept data in INIT or WAITING_DATA states */
  if (session->state != SASL_STATE_INIT && session->state != SASL_STATE_WAITING_DATA)
    return -1;

  /* Handle chunk accumulation per IRCv3 SASL spec:
   * - Exactly 400 bytes = more data follows
   * - "+" alone after a 400-byte chunk = previous chunk was final
   * - < 400 bytes = final chunk
   */
  if (data[0] == '+' && data[1] == '\0') {
    /* Empty continuation or final marker after 400-byte chunk */
    if (!session->accumulated_data || session->data_len == 0) {
      /* No accumulated data — this is an empty response (valid for some mechs) */
      goto dispatch;
    }
    /* Previous 400-byte chunk was the last one — dispatch accumulated data */
    goto dispatch;
  }

  {
    size_t chunk_len = strlen(data);

    /* Accumulate data */
    if (!session->accumulated_data) {
      session->data_alloc = (chunk_len < 400) ? chunk_len + 1 : SASL_DATA_MAX;
      session->accumulated_data = (char *)MyMalloc(session->data_alloc);
      session->data_len = 0;
    }

    /* Check for overflow */
    if (session->data_len + chunk_len >= session->data_alloc) {
      size_t new_alloc = session->data_len + chunk_len + 1;
      if (new_alloc > SASL_DATA_MAX) {
        send_reply(sptr, ERR_SASLTOOLONG);
        sasl_abort_local(sptr);
        return 0;
      }
      session->accumulated_data = (char *)MyRealloc(session->accumulated_data, new_alloc);
      session->data_alloc = new_alloc;
    }

    memcpy(session->accumulated_data + session->data_len, data, chunk_len);
    session->data_len += chunk_len;
    session->accumulated_data[session->data_len] = '\0';
    session->chunks_received++;
    session->state = SASL_STATE_WAITING_DATA;

    /* If exactly 400 bytes, more data expected */
    if (chunk_len == 400)
      return 0;
  }

dispatch:
  /* We have all the data — decode base64 and dispatch to mechanism handler */
  {
    unsigned char decoded[SASL_DATA_MAX];
    size_t decoded_len = 0;
    int rc;

    if (session->accumulated_data && session->data_len > 0) {
      if (!sasl_base64_decode(session->accumulated_data, decoded,
                              sizeof(decoded), &decoded_len)) {
        send_reply(sptr, ERR_SASLFAIL, ": base64 decode failed");
        sasl_abort_local(sptr);
        return 0;
      }
    }

    switch (session->mech) {
#ifdef USE_LIBKC
      case SASL_MECH_PLAIN:
        rc = sasl_handle_plain(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
      case SASL_MECH_EXTERNAL:
        rc = sasl_handle_external(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
      case SASL_MECH_OAUTHBEARER:
        rc = sasl_handle_oauthbearer(sptr, decoded, decoded_len);
        if (rc < 0) {
          sasl_abort_local(sptr);
          return 0;
        }
        break;
#endif
      default:
        send_reply(sptr, ERR_SASLFAIL, ": unsupported mechanism");
        sasl_abort_local(sptr);
        return 0;
    }
  }

  return 0;
}

int sasl_abort_local(struct Client *sptr)
{
  struct SASLSession *session = cli_saslsession(sptr);

  if (!session)
    return 0;

  /* Clean up timer */
  if (t_active(&cli_sasltimeout(sptr)))
    timer_del(&cli_sasltimeout(sptr));

  /* Clean up session state */
  cli_saslcookie(sptr) = 0;
  cli_saslstart(sptr) = 0;
  sasl_session_free(sptr);

  /* Unblock registration */
  if (cli_auth(sptr))
    auth_sasl_done(cli_auth(sptr));

  return 0;
}

/* ---- Timeout callback for local SASL ---- */

static void sasl_local_timeout_cb(struct Event *ev)
{
  struct Client *cptr;

  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));

  if (ev_type(ev) == ET_EXPIRE) {
    cptr = (struct Client *)t_data(ev_timer(ev));

    if (cli_saslsession(cptr)) {
      /* Local SASL timeout */
      log_write(LS_SYSTEM, L_INFO, 0,
                "SASL: Local session timeout for %C", cptr);
      send_reply(cptr, ERR_SASLFAIL, ": request timed out");
      sasl_abort_local(cptr);
    }
  }
}

/* ---- Initialization and health tracking ---- */

int sasl_local_init(void)
{
#ifdef USE_LIBKC
  if (!feature_bool(FEAT_SASL_LOCAL))
    return 0;  /* Not an error — just not configured */

  /* Verify Keycloak config is present */
  if (EmptyString(feature_str(FEAT_KEYCLOAK_URL)) ||
      EmptyString(feature_str(FEAT_KEYCLOAK_CLIENT_ID)) ||
      EmptyString(feature_str(FEAT_KEYCLOAK_CLIENT_SECRET))) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "SASL LOCAL: Missing Keycloak configuration (URL/CLIENT_ID/CLIENT_SECRET)");
    return -1;
  }

  sasl_local_initialized = 1;
  kc_sasl_healthy = 1;  /* Optimistic — kc_keycloak_init() already succeeded */
  log_write(LS_SYSTEM, L_NOTICE, 0,
            "SASL LOCAL: Initialized — will validate credentials via Keycloak");

  /* Prime the Keycloak client credentials token (async — fires callback
   * when complete, which also validates Keycloak availability) */
  kc_token_ensure(sasl_health_cb, NULL);

  /* Prime the JWKS cache for offline JWT validation (sync HTTP — blocks
   * briefly on first fetch, then cached for 1 hour) */
  {
    struct kc_realm realm;
    realm.base_url = feature_str(FEAT_KEYCLOAK_URL);
    realm.realm = feature_str(FEAT_KEYCLOAK_REALM);
    if (kc_jwt_prime_cache(realm) == KC_SUCCESS) {
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "SASL LOCAL: JWKS cache primed for OAUTHBEARER");
    } else {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL LOCAL: Failed to prime JWKS cache — OAUTHBEARER will fetch on first use");
    }
  }

  return 0;
#else
  return -1;
#endif
}

/** Health check callback — called from kc_token_ensure() result. */
#ifdef USE_LIBKC
static void sasl_health_cb(int result, const struct kc_access_token *token, void *data)
{
  int was_healthy = kc_sasl_healthy;

  if (result == KC_SUCCESS) {
    kc_sasl_healthy = 1;
    if (!was_healthy && sasl_local_initialized) {
      log_write(LS_SYSTEM, L_NOTICE, 0,
                "SASL LOCAL: Keycloak is now reachable — advertising SASL");
      send_cap_notify("sasl", 1, sasl_local_mechanisms());
    }
  } else {
    kc_sasl_healthy = 0;
    if (was_healthy && sasl_local_initialized) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "SASL LOCAL: Keycloak became unreachable (result %d) — removing SASL", result);
      send_cap_notify("sasl", 0, NULL);
    }
  }
}
#endif

void sasl_health_check(void)
{
#ifdef USE_LIBKC
  if (!sasl_local_initialized || !feature_bool(FEAT_SASL_LOCAL))
    return;
  kc_token_ensure(sasl_health_cb, NULL);
#endif
}
