/*
 * IRC - Internet Relay Chat, ircd/m_register.c
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
 * @brief Handler for REGISTER/VERIFY commands (IRCv3 draft/account-registration).
 *
 * Specification: https://ircv3.net/specs/extensions/account-registration
 *
 * REGISTER <account> {<email> | "*"} <password>
 * VERIFY <account> <code>
 *
 * The account is created directly in Keycloak through libkc; there is no
 * services relay any more (the old RG/VF/RR P10 round-trip is gone).  The
 * IRCd derives the credential material itself:
 *
 *   - a Keycloak PBKDF2 credential (credentialData/secretData) so the
 *     account can log in with SASL PLAIN immediately, and
 *   - SCRAM-SHA-256 attributes (scram_sha256_*) so SASL SCRAM works without
 *     ever seeing the plaintext again.
 *
 * Both are derived synchronously in m_register(), before the first async
 * hop, so the plaintext password never enters the async context.
 *
 * When FEAT_REGISTER_VERIFY_EMAIL is on, the account is created unverified
 * (emailVerified=false + a VERIFY_EMAIL required action) and Keycloak mails
 * a verification link.  Verification therefore completes out-of-band in the
 * browser, not over IRC -- which is why VERIFY only declines gracefully.
 */
#include "config.h"

#include "capab.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "metadata.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_debug.h"
#include "s_user.h"
#include "sasl_auth.h"
#include "send.h"

#ifdef USE_LIBKC
#include <kc/kc_cred_derive.h>
#include <kc/kc_keycloak.h>
#endif

#include <stdlib.h>
#include <string.h>

/** Advertised CAP 302 value when e-mail verification is required. */
#define ACCOUNTREG_CAPVALUE_EMAIL \
  "before-connect,custom-account-name,email-required," \
  "min-password-length=5,max-password-length=300"
/** Advertised CAP 302 value when e-mail is optional. */
#define ACCOUNTREG_CAPVALUE_NOEMAIL \
  "before-connect,custom-account-name," \
  "min-password-length=5,max-password-length=300"

/** Minimum accepted password length (mirrored in the CAP value above). */
#define REGISTER_PASSWORD_MIN 5
/** Maximum accepted password length (mirrored in the CAP value above). */
#define REGISTER_PASSWORD_MAX 300

/** Feature-notify hook for FEAT_REGISTER_VERIFY_EMAIL.
 *
 * Keeps the draft/account-registration CAP value in step with the policy,
 * so a rehash that flips the feature cannot leave "email-required" (or its
 * absence) stale in CAP LS output.
 */
void feature_notify_accountreg_capvalue(void)
{
  cap_set_value(CAP_DRAFT_ACCOUNTREG,
                feature_bool(FEAT_REGISTER_VERIFY_EMAIL) ?
                ACCOUNTREG_CAPVALUE_EMAIL : ACCOUNTREG_CAPVALUE_NOEMAIL);
}

#ifdef USE_LIBKC

extern struct Client* LocalClientArray[];

/** Async registration context.
 *
 * Carries no plaintext: every piece of credential material is derived in
 * m_register() before the first async hop.  The client is re-found by
 * fd+cookie (the SASL callback pattern) because the callbacks run on later
 * event-loop iterations, by which time the client may be gone and its fd
 * reused by an unrelated connection.
 */
struct reg_ctx {
  int fd;                          /**< Connection fd at REGISTER time. */
  unsigned int cookie;             /**< cli_saslcookie() at REGISTER time. */
  int stage;                       /**< 0=search, 1=create, 2=verify-email. */
  int verify_email;                /**< Policy snapshot at REGISTER time. */
  char account[ACCOUNTLEN + 1];    /**< Account being created. */
  char email[201];                 /**< E-mail, or "" for none. */
  char *cred_data;                 /**< Keycloak credentialData JSON. */
  char *secret_data;               /**< Keycloak secretData JSON. */
  struct scram_sha256_creds scram; /**< SCRAM-SHA-256 attribute material. */
};

/** Re-find the client that issued the REGISTER, if it is still there.
 * @param[in] ctx Registration context.
 * @return The client, or NULL if it disconnected or the fd was reused.
 */
static struct Client *reg_ctx_client(struct reg_ctx *ctx)
{
  struct Client *acptr;

  if (ctx->fd < 0 || ctx->fd >= MAXCONNECTIONS)
    return NULL;
  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_saslcookie(acptr) != ctx->cookie)
    return NULL;
  return acptr;
}

/** Release a registration context and cleanse its key material.
 * @param[in] ctx Registration context (must not be NULL).
 */
static void reg_ctx_free(struct reg_ctx *ctx)
{
  if (ctx->cred_data)
    free(ctx->cred_data);
  if (ctx->secret_data)
    free(ctx->secret_data);
  memset(&ctx->scram, 0, sizeof(ctx->scram));
  MyFree(ctx);
}

/** Attach the freshly created account to the client and tell it so.
 *
 * Two shapes, matching the two moments a REGISTER can complete:
 *  - the client already finished registration (post-connect REGISTER), so
 *    the account is stamped directly and announced to account-notify peers;
 *  - the client is still pre-registration (before-connect REGISTER), so the
 *    account is parked in cli_saslaccount() and auth_complete_sasl() applies
 *    it when NICK/USER finish.
 *
 * @param[in] acptr Client to log in.
 * @param[in] account Account name that was created.
 */
static void register_complete_success(struct Client *acptr, const char *account)
{
  if (IsRegistered(acptr)) {
    if (!IsAccount(acptr) && cli_user(acptr)) {
      /* ircd_strncpy() is strlcpy-shaped: the third argument is the buffer
       * SIZE, not a max character count.  The pre-rewrite ms_regreply()
       * passed sizeof-1 here, which silently truncated a full-length
       * (ACCOUNTLEN) account name to ACCOUNTLEN-1 -- and would now diverge
       * from the name actually created in Keycloak. */
      ircd_strncpy(cli_user(acptr)->account, account,
                   sizeof(cli_user(acptr)->account));
      SetAccount(acptr);
      /* P1 A3 residue: a post-registration REGISTER attaches an account to
       * an already-registered client outside the register_user chokepoint
       * (that ran at initial registration) -- load metadata here. */
      metadata_load_account(acptr, cli_user(acptr)->account);
      sendrawto_one(acptr, "REGISTER SUCCESS %s :Account registered", account);
      sendcmdto_common_channels_capab_butone(acptr, CMD_ACCOUNT, acptr,
                                             CAP_ACCNOTIFY, CAP_NONE,
                                             "%s", account);
    }
  } else {
    ircd_strncpy(cli_saslaccount(acptr), account, ACCOUNTLEN + 1);
    SetSASLComplete(acptr);
    if (cli_auth(acptr))
      auth_set_account(cli_auth(acptr), account);
    sendrawto_one(acptr, "REGISTER SUCCESS %s :Account registered", account);
  }
}

/** Stage 2 result: the verification mail was (or was not) triggered.
 *
 * Always non-fatal.  The account exists and is in the correct state either
 * way; a failure here only means the mail has to be re-triggered
 * out-of-band, so the client is still told to go look for the link.
 *
 * @param[in] result KC_SUCCESS or a kc_error code.
 * @param[in] data The struct reg_ctx.
 */
static void reg_email_cb(int result, void *data)
{
  struct reg_ctx *ctx = (struct reg_ctx *)data;
  struct Client *acptr = reg_ctx_client(ctx);

  if (result != KC_SUCCESS)
    log_write(LS_SYSTEM, L_WARNING, 0,
              "REGISTER: send-verify-email failed for %s (result %d) - "
              "account state is correct; verification completable out-of-band",
              ctx->account, result);

  if (acptr)
    sendrawto_one(acptr, "REGISTER VERIFICATION_REQUIRED %s :Account created - "
                  "check your email for a verification link, then log in "
                  "normally (SASL)", ctx->account);

  reg_ctx_free(ctx);
}

/** Stage 2 lookup: fetch the new account's Keycloak id for send-verify-email.
 * @param[in] result KC_SUCCESS or a kc_error code.
 * @param[in] user The user record (borrowed), or NULL.
 * @param[in] data The struct reg_ctx.
 */
static void reg_verify_lookup_cb(int result, const struct kc_user *user,
                                 void *data)
{
  struct reg_ctx *ctx = (struct reg_ctx *)data;

  if (result != KC_SUCCESS || !user || !user->id) {
    reg_email_cb(KC_ERROR, ctx);        /* non-fatal; frees ctx */
    return;
  }

  if (kc_user_send_verify_email(user->id, reg_email_cb, ctx) != 0)
    reg_email_cb(KC_ERROR, ctx);        /* non-fatal; frees ctx */
}

/** Stage 1 result: the account create either landed or did not.
 * @param[in] result KC_SUCCESS, KC_CONFLICT, or another kc_error code.
 * @param[in] data The struct reg_ctx.
 */
static void reg_create_cb(int result, void *data)
{
  struct reg_ctx *ctx = (struct reg_ctx *)data;
  struct Client *acptr = reg_ctx_client(ctx);

  if (result != KC_SUCCESS) {
    if (acptr) {
      if (result == KC_CONFLICT)
        send_fail(acptr, "REGISTER", "ACCOUNT_EXISTS", ctx->account,
                  "Account already exists");
      else
        send_fail(acptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", ctx->account,
                  "Registration is temporarily unavailable");
    }
    reg_ctx_free(ctx);
    return;
  }

  if (ctx->verify_email) {
    /* send-verify-email is addressed by user id, which the create response
     * does not give us -- look the account up by its (exact) username. */
    ctx->stage = 2;
    if (kc_user_get(ctx->account, reg_verify_lookup_cb, ctx) != 0)
      reg_email_cb(KC_ERROR, ctx);      /* non-fatal; frees ctx */
    return;
  }

  if (acptr)
    register_complete_success(acptr, ctx->account);
  reg_ctx_free(ctx);
}

/** Stage 0 result: does the account name already exist?
 * @param[in] result KC_SUCCESS (taken), KC_NOT_FOUND (free), or an error.
 * @param[in] user The matching user (borrowed), or NULL.
 * @param[in] data The struct reg_ctx.
 */
static void reg_search_cb(int result, const struct kc_user *user, void *data)
{
  struct reg_ctx *ctx = (struct reg_ctx *)data;
  struct Client *acptr = reg_ctx_client(ctx);
  struct kc_user_create_req req;
  static const char *const keys[4] = {
    "scram_sha256_salt", "scram_sha256_iterations",
    "scram_sha256_stored_key", "scram_sha256_server_key"
  };
  const char *vals[4];
  char iterbuf[16];

  if (result == KC_SUCCESS && user) {           /* name taken */
    if (acptr)
      send_fail(acptr, "REGISTER", "ACCOUNT_EXISTS", ctx->account,
                "Account already exists");
    reg_ctx_free(ctx);
    return;
  }
  if (result != KC_NOT_FOUND) {                 /* connectivity trouble */
    if (acptr)
      send_fail(acptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", ctx->account,
                "Registration is temporarily unavailable");
    reg_ctx_free(ctx);
    return;
  }

  ircd_snprintf(0, iterbuf, sizeof(iterbuf), "%d", ctx->scram.iterations);
  vals[0] = ctx->scram.salt_b64;
  vals[1] = iterbuf;
  vals[2] = ctx->scram.stored_key_b64;
  vals[3] = ctx->scram.server_key_b64;

  memset(&req, 0, sizeof(req));
  req.username = ctx->account;
  req.email = ctx->email[0] ? ctx->email : NULL;
  req.cred_data = ctx->cred_data;
  req.secret_data = ctx->secret_data;
  req.set_email_verified = ctx->verify_email;
  req.attr_keys = keys;
  req.attr_values = vals;
  req.n_attrs = 4;

  ctx->stage = 1;
  if (kc_user_create_full(&req, reg_create_cb, ctx) != 0) {
    if (acptr)
      send_fail(acptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", ctx->account,
                "Registration is temporarily unavailable");
    reg_ctx_free(ctx);
  }
}

#endif /* USE_LIBKC */

/** m_register - Handle REGISTER command from local client.
 *
 * parv[0] = sender prefix
 * parv[1] = account name (or "*" for current nick)
 * parv[2] = email address (or "*" for none)
 * parv[3] = password
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int m_register(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *account;
  const char *email;
  const char *password;
  const char *p;
#ifdef USE_LIBKC
  struct reg_ctx *ctx;
#endif

  /* Check if feature is enabled */
  if (!feature_bool(FEAT_CAP_draft_account_registration)) {
    send_fail(sptr, "REGISTER", "DISABLED", NULL,
              "Account registration is not enabled on this server");
    return 0;
  }

  /* Need account, email, and password */
  if (parc < 4) {
    send_fail(sptr, "REGISTER", "NEED_MORE_PARAMS", NULL,
              "Not enough parameters");
    return 0;
  }

  account = parv[1];
  email = parv[2];
  password = parv[3];

  /* Check if already authenticated */
  if (IsAccount(sptr)) {
    send_fail(sptr, "REGISTER", "ALREADY_AUTHENTICATED", account,
              "You are already authenticated");
    return 0;
  }

  /* "*" means "register my current nickname" */
  if (account[0] == '*' && account[1] == '\0')
    account = cli_name(sptr);

  if (!*account || strlen(account) > ACCOUNTLEN) {
    send_fail(sptr, "REGISTER", "BAD_ACCOUNT_NAME", account,
              "Account name is empty or too long");
    return 0;
  }

  /* The account name has to be nick-shaped: it is stamped into
   * cli_user()->account and travels the network as an account name. */
  for (p = account; *p; p++) {
    if (!IsNickChar(*p)) {
      send_fail(sptr, "REGISTER", "BAD_ACCOUNT_NAME", account,
                "Account name contains invalid characters");
      return 0;
    }
  }

  /* Password length gates -- these bounds are advertised in the
   * draft/account-registration CAP value, keep them in step. */
  if (strlen(password) < REGISTER_PASSWORD_MIN) {
    send_fail(sptr, "REGISTER", "WEAK_PASSWORD", account,
              "Password too short (minimum 5 characters)");
    return 0;
  }
  if (strlen(password) > REGISTER_PASSWORD_MAX) {
    send_fail(sptr, "REGISTER", "WEAK_PASSWORD", account,
              "Password too long (maximum 300 characters)");
    return 0;
  }

  /* Email handling.  "*" (and an empty string) mean "no address"; that is
   * only acceptable when the verification policy is off. */
  if (!*email || (email[0] == '*' && email[1] == '\0')) {
    if (feature_bool(FEAT_REGISTER_VERIFY_EMAIL)) {
      send_fail(sptr, "REGISTER", "INVALID_EMAIL", account,
                "An email address is required to register on this server");
      return 0;
    }
    email = NULL;
  } else {
    if (!strchr(email, '@') || strchr(email, ' ') || strlen(email) > 200) {
      send_fail(sptr, "REGISTER", "INVALID_EMAIL", account,
                "Invalid email address");
      return 0;
    }
  }

  /* Keycloak is where accounts live; without it there is nothing to do. */
  if (!sasl_local_available()) {
    send_fail(sptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account,
              "Registration service is not available");
    return 0;
  }

#ifdef USE_LIBKC
  /* A real cookie is needed so the async callbacks can tell "still the same
   * connection" from "fd reused" (the SASL pattern). */
  if (!cli_saslcookie(cptr)) {
    do {
      cli_saslcookie(cptr) = ircrandom() & 0x7fffffff;
    } while (!cli_saslcookie(cptr));
  }

  ctx = (struct reg_ctx *)MyMalloc(sizeof(*ctx));
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = cli_fd(cptr);
  ctx->cookie = cli_saslcookie(cptr);
  ctx->verify_email = feature_bool(FEAT_REGISTER_VERIFY_EMAIL);
  /* ircd_strncpy() takes the buffer SIZE (strlcpy semantics), so pass
   * sizeof() -- sizeof()-1 would clip the last character of a full-length
   * account name or address. */
  ircd_strncpy(ctx->account, account, sizeof(ctx->account));
  if (email)
    ircd_strncpy(ctx->email, email, sizeof(ctx->email));

  /* Derive everything from the plaintext up front; past this point the
   * password is not needed and never enters the async context. */
  if (scram_sha256_derive_random(password, &ctx->scram) != 0 ||
      kc_pbkdf2_cred_build(password, &ctx->cred_data,
                           &ctx->secret_data) != 0) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "REGISTER: credential derivation failed for %s", ctx->account);
    send_fail(sptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account,
              "Registration is temporarily unavailable");
    reg_ctx_free(ctx);
    return 0;
  }

  ctx->stage = 0;
  if (kc_user_get(ctx->account, reg_search_cb, ctx) != 0) {
    send_fail(sptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account,
              "Registration is temporarily unavailable");
    reg_ctx_free(ctx);
  }
#endif /* USE_LIBKC */

  return 0;
}

/** m_verify - Handle VERIFY command from local client.
 *
 * Verification is Keycloak's own e-mail flow: the account is created with a
 * VERIFY_EMAIL required action and the user clicks the link in the mail.
 * There is no code for the client to relay back over IRC, so VERIFY exists
 * only to decline gracefully and point at the link.
 *
 * parv[0] = sender prefix
 * parv[1] = account name
 * parv[2] = verification code
 *
 * @param[in] cptr Client that sent us the message.
 * @param[in] sptr Original source of message.
 * @param[in] parc Number of arguments.
 * @param[in] parv Argument vector.
 * @return 0 on success.
 */
int m_verify(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  const char *account;

  /* Check if feature is enabled */
  if (!feature_bool(FEAT_CAP_draft_account_registration)) {
    send_fail(sptr, "VERIFY", "DISABLED", NULL,
              "Account registration is not enabled on this server");
    return 0;
  }

  /* Need account and code */
  if (parc < 3) {
    send_fail(sptr, "VERIFY", "NEED_MORE_PARAMS", NULL,
              "Not enough parameters");
    return 0;
  }

  account = parv[1];

  /* Check if already authenticated */
  if (IsAccount(sptr)) {
    send_fail(sptr, "VERIFY", "ALREADY_AUTHENTICATED", account,
              "You are already authenticated");
    return 0;
  }

  send_fail(sptr, "VERIFY", "INVALID_CODE", account,
            "Verification is completed via the link in your email - "
            "after clicking it, log in normally (SASL)");
  return 0;
}
