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

#include "account_id.h"
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
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "random.h"
#include "register_throttle.h"
#include "s_auth.h"
#include "s_conf.h"
#include "s_debug.h"
#include "sasl_auth.h"
#include "send.h"

#ifdef USE_LIBKC
#include <kc/kc_cred_derive.h>
#include <kc/kc_keycloak.h>
#include <kc/kc_url.h>
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

/** Current draft/account-registration CAP 302 value under the active
 * policy. */
static const char *accountreg_capvalue(void)
{
  return feature_bool(FEAT_REGISTER_VERIFY_EMAIL) ?
    ACCOUNTREG_CAPVALUE_EMAIL : ACCOUNTREG_CAPVALUE_NOEMAIL;
}

/** Feature-notify hook for FEAT_REGISTER_VERIFY_EMAIL.
 *
 * Keeps the draft/account-registration CAP value in step with the policy.
 * cap_set_value() only updates the stored CAP LS value -- it does not
 * notify -- so a policy flip must also emit CAP NEW with the new value
 * to cap-notify clients (only when the capability itself is advertised).
 * During a rehash the notify batch (cap_notify_begin_batch/flush)
 * deduplicates this against feature_notify_cap_accountreg(). */
void feature_notify_accountreg_capvalue(void)
{
  cap_set_value(CAP_DRAFT_ACCOUNTREG, accountreg_capvalue());
  if (feature_bool(FEAT_CAP_draft_account_registration))
    send_cap_notify("draft/account-registration", 1, accountreg_capvalue());
}

/** Feature-notify hook for FEAT_CAP_draft_account_registration itself.
 *
 * Replaces the generic DEFINE_CAP_NOTIFY hook, which sent CAP NEW with
 * no value: this capability's value is load-bearing (email-required,
 * password bounds), so enabling the cap must advertise it. */
void feature_notify_cap_accountreg(void)
{
  cap_set_value(CAP_DRAFT_ACCOUNTREG, accountreg_capvalue());
  if (feature_bool(FEAT_CAP_draft_account_registration)) {
    send_cap_notify("draft/account-registration", 1, accountreg_capvalue());
    log_write(LS_SYSTEM, L_INFO, 0,
              "draft/account-registration: capability enabled, "
              "sent CAP NEW to cap-notify clients");
  } else {
    send_cap_notify("draft/account-registration", 0, NULL);
    log_write(LS_SYSTEM, L_INFO, 0,
              "draft/account-registration: capability disabled, "
              "sent CAP DEL to cap-notify clients");
  }
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
  unsigned int cookie;             /**< cli_regcookie() at REGISTER time. */
  int stage;                       /**< 0=search, 1=create, 2=verify-email,
                                        3=the new user's id. */
  int verify_email;                /**< Policy snapshot at REGISTER time. */
  char account[ACCOUNTLEN + 1];    /**< Account being created. */
  char email[201];                 /**< E-mail, or "" for none. */
  char *cred_data;                 /**< Keycloak credentialData JSON. */
  char *secret_data;               /**< Keycloak secretData JSON. */
  struct scram_sha256_creds scram; /**< SCRAM-SHA-256 attribute material. */
  char label[64];                  /**< The REGISTER line's labeled-response
                                        label ("" none): the answer's own */
};

/** The labeled-response state of whatever line the connection is on, kept
 * aside while an answer to an earlier REGISTER goes out under that
 * REGISTER's label (reg_answer_begin()). */
struct reg_label_state {
  char label[64];
  unsigned char responded;
  unsigned char labeled_batch;
  char batch_id[16];
  int batch;                       /**< a batch was opened for the answer */
};

/** Start sending the answer to \a ctx's REGISTER to \a acptr.  An answer
 * comes later than its line (a Keycloak answer), by which time the
 * connection's label is a later line's, or one already answered: the
 * answer goes out under the REGISTER's own label, or none, and an answer
 * of more than one line (a login: REGISTER SUCCESS, 900, ...) in a
 * labeled-response batch, as a command's multi-line reply is
 * (labeled_batch_start()).  reg_answer_end() puts the line's state back.
 * @param[in] acptr The client that sent the REGISTER.
 * @param[in] ctx Its registration context.
 * @param[out] st Where the connection's own state is kept meanwhile.
 * @param[in] lines Non-zero when the answer may be more than one line. */
static void reg_answer_begin(struct Client *acptr, const struct reg_ctx *ctx,
                             struct reg_label_state *st, int lines)
{
  memcpy(st->label, cli_label(acptr), sizeof(st->label));
  st->responded = cli_label_responded(acptr);
  st->labeled_batch = cli_labeled_batch(acptr);
  memcpy(st->batch_id, cli_batch_id(acptr), sizeof(st->batch_id));
  ircd_strncpy(cli_label(acptr), ctx->label, sizeof(st->label));
  cli_label_responded(acptr) = 0;
  cli_labeled_batch(acptr) = 0;
  cli_batch_id(acptr)[0] = '\0';
  st->batch = (lines && ctx->label[0]) ? labeled_batch_start(acptr) : 0;
}

/** End an answer reg_answer_begin() started. */
static void reg_answer_end(struct Client *acptr, struct reg_label_state *st)
{
  if (st->batch)
    labeled_batch_end(acptr);
  memcpy(cli_label(acptr), st->label, sizeof(st->label));
  cli_label_responded(acptr) = st->responded;
  cli_labeled_batch(acptr) = st->labeled_batch;
  memcpy(cli_batch_id(acptr), st->batch_id, sizeof(st->batch_id));
}

/** An asynchronous FAIL REGISTER, under the REGISTER's label. */
static void reg_answer_fail(struct reg_ctx *ctx, struct Client *acptr,
                            const char *code, const char *text)
{
  struct reg_label_state st;

  reg_answer_begin(acptr, ctx, &st, 0);
  send_fail(acptr, "REGISTER", code, ctx->account, text);
  reg_answer_end(acptr, &st);
}

/** Re-find the client that issued the REGISTER, if it is still there.
 *
 * Keyed on cli_regcookie() rather than cli_saslcookie(): SASL zeroes its own
 * cookie on its failure paths (e.g. sasl_plain_cb at sasl_auth.c:774), so a
 * client that failed a SASL attempt while a REGISTER was in flight would
 * become unfindable -- losing its REGISTER reply and stranding the in-flight
 * guard set, which locks REGISTER out on that connection until it reconnects.
 * A dedicated cookie is owned solely by this file and cannot be clobbered.
 * A bouncer revive that moves the socket onto a held session's ghost before
 * the answer moves the cookie with it (bounce_revive()), so the answer
 * reaches the connection that asked.
 *
 * @param[in] ctx Registration context.
 * @return The client, or NULL if it disconnected or the fd was reused.
 */
static struct Client *reg_ctx_client(struct reg_ctx *ctx)
{
  struct Client *acptr;

  if (ctx->fd < 0 || ctx->fd >= MAXCONNECTIONS)
    return NULL;
  acptr = LocalClientArray[ctx->fd];
  if (!acptr || cli_regcookie(acptr) != ctx->cookie)
    return NULL;
  return acptr;
}

/** Release a registration context, clear its in-flight guard, and cleanse
 * its key material.
 *
 * This is the single terminal point of a context's life, so retiring
 * cli_regcookie() here makes the in-flight guard's lifetime identical to the
 * context's: set once at birth in m_register(), cleared once here, on every
 * path.  reg_ctx_client() validates fd AND cookie, so a connection that
 * merely reused the fd is never touched -- and a client that disconnected
 * mid-chain needs no clearing at all, because alloc_client() memsets the
 * whole struct Client on allocation and on reuse from the free list
 * (list.c:122), so the guard cannot outlive the connection.
 *
 * @param[in] ctx Registration context (must not be NULL).
 */
static void reg_ctx_free(struct reg_ctx *ctx)
{
  struct Client *acptr = reg_ctx_client(ctx);

  if (acptr)
    cli_regcookie(acptr) = 0;      /* releases the one-in-flight guard */

  if (ctx->cred_data)
    free(ctx->cred_data);
  if (ctx->secret_data)
    free(ctx->secret_data);
  memset(&ctx->scram, 0, sizeof(ctx->scram));
  MyFree(ctx);
}

/** Log the client in to the account its REGISTER created, and tell it so.
 *
 * draft/account-registration: after REGISTER SUCCESS the client "is
 * assumed to be authenticated to the <account> as if it used SASL".  So it
 * is a SASL login's completion, shared (sasl_register_login(),
 * sasl_auth.c): before connection registration the identity registration
 * applies, after it the account set and announced; 900, the hidden host,
 * the account's metadata and modes, account-notify, the AC, the bouncer
 * aliases -- with REGISTER SUCCESS where a SASL login sends 903.
 *
 * The login carries the account's Keycloak id, as Keycloak gave it in this
 * registration (the create's answer, or the lookup after it), confirmed as
 * a grant's is; without one -- the lookup failed, or the id is not a UUID,
 * as for a grant whose ID token names none -- it goes ahead without, and
 * the account is no less created.  No timestamp, as for every local
 * Keycloak login.
 *
 * A login that finished while the REGISTER was in flight (REGISTER and SASL
 * may overlap) is not undone:
 *  - a login to this very account (the create landed, and a SASL login of
 *    it was answered first): REGISTER SUCCESS is true as it stands -- the
 *    client is authenticated to the account -- and is all that is sent;
 *  - after connection registration, a login to another account: that login
 *    stays.  REGISTER SUCCESS would say the client is now authenticated to
 *    the new account, which it is not, and a FAIL would say the REGISTER
 *    failed, while the account was created.  The reply is the spec's code
 *    for the reason, ALREADY_AUTHENTICATED ("the client is already
 *    authenticated"), as a WARN: standard replies' type for a command that
 *    was processed with something the client should know, and no new code.
 *    The text says the account exists and how to use it;
 *  - before connection registration the later answer still replaces a
 *    completed login (the overlaps as pinned in sasl_handler_cmocka).
 *
 * Every line goes out under the REGISTER's own label (reg_answer_begin()).
 *
 * @param[in] acptr Client to log in.
 * @param[in] ctx Its registration context (the account, the label).
 * @param[in] id The new user's Keycloak id (a UUID), or NULL.
 */
static void register_complete_success(struct Client *acptr,
                                      struct reg_ctx *ctx, const char *id)
{
  const char *account = ctx->account;
  char kcid[ACCOUNT_ID_LEN + 1] = "";
  const char *held = IsAccount(acptr) ? cli_user(acptr)->account
                   : IsSASLComplete(acptr) ? cli_saslaccount(acptr) : "";
  struct reg_label_state st;

  if (held[0] && 0 == ircd_strcmp(held, account)) {
    reg_answer_begin(acptr, ctx, &st, 0);
    sendrawto_one_tags(acptr, "REGISTER SUCCESS %s :Account registered",
                       account);
    reg_answer_end(acptr, &st);
    return;
  }
  if (IsAccount(acptr)) {
    char text[200];

    ircd_snprintf(0, text, sizeof(text), "Account %s was created, but you are "
                  "already logged in as %s; log in to %s with SASL to use it",
                  account, held, account);
    reg_answer_begin(acptr, ctx, &st, 0);
    send_warn(acptr, "REGISTER", "ALREADY_AUTHENTICATED", account, text);
    reg_answer_end(acptr, &st);
    return;
  }
  if (id && !account_id_from_uuid(id, kcid))
    kcid[0] = '\0';                     /* the callers pass UUIDs only */
  reg_answer_begin(acptr, ctx, &st, 1);
  sasl_register_login(acptr, account, kcid[0] ? kcid : NULL);
  reg_answer_end(acptr, &st);
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

  if (acptr) {
    struct reg_label_state st;

    reg_answer_begin(acptr, ctx, &st, 0);
    sendrawto_one_tags(acptr, "REGISTER VERIFICATION_REQUIRED %s "
                       ":Account created - check your email for a verification "
                       "link, then log in normally (SASL)", ctx->account);
    reg_answer_end(acptr, &st);
  }

  reg_ctx_free(ctx);
}

/** A Keycloak user id from an answer, if it is a UUID (8-4-4-4-12 hex):
 * the only form put into a request's URL path, logged, or carried by a
 * login.  Anything else from the wire is no id.
 * @param[in] id The id as Keycloak's answer gives it, or NULL.
 * @return \a id, or NULL. */
static const char *reg_uuid_or_null(const char *id)
{
  return (id && kc_url_is_uuid(id, strlen(id))) ? id : NULL;
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

  if (result != KC_SUCCESS || !user || !reg_uuid_or_null(user->id)) {
    if (result == KC_SUCCESS && user)
      log_write(LS_SYSTEM, L_WARNING, 0,
                "REGISTER: the lookup of %s answered an id that is not a "
                "UUID; no verification mail is asked for", ctx->account);
    reg_email_cb(KC_ERROR, ctx);        /* non-fatal; frees ctx */
    return;
  }

  if (kc_user_send_verify_email(user->id, reg_email_cb, ctx) != 0)
    reg_email_cb(KC_ERROR, ctx);        /* non-fatal; frees ctx */
}

/** Stage 3 result: the new account's Keycloak id, asked for because the
 * create's answer named none.  The account exists whatever this says: a
 * lookup that fails logs the client in without an id, and never turns the
 * registration into a failure.
 * @param[in] result KC_SUCCESS or a kc_error code.
 * @param[in] user The user record (borrowed), or NULL.
 * @param[in] data The struct reg_ctx.
 */
static void reg_id_lookup_cb(int result, const struct kc_user *user,
                             void *data)
{
  struct reg_ctx *ctx = (struct reg_ctx *)data;
  struct Client *acptr = reg_ctx_client(ctx);
  const char *id = NULL;

  if (result != KC_SUCCESS || !user)
    log_write(LS_SYSTEM, L_WARNING, 0,
              "REGISTER: %s was created, but looking up its Keycloak id "
              "failed (result %d); logged in without one", ctx->account,
              result);
  else if (!user->username || 0 != ircd_strcmp(user->username, ctx->account))
    log_write(LS_SYSTEM, L_WARNING, 0,
              "REGISTER: %s was created, but the lookup for its Keycloak id "
              "answered another user's record; logged in without one",
              ctx->account);
  else if (!(id = reg_uuid_or_null(user->id)))
    log_write(LS_SYSTEM, L_WARNING, 0,
              "REGISTER: %s was created, but the id the lookup answered is "
              "not a UUID; logged in without one", ctx->account);

  if (acptr)
    register_complete_success(acptr, ctx, id);
  reg_ctx_free(ctx);
}

/** Stage 1 result: the account create either landed or did not.
 * @param[in] result KC_SUCCESS, or why Keycloak refused the create
 *   (kc_classify_create_error()), or another kc_error code.
 * @param[in] id The new user's Keycloak id as the answer names it, or NULL.
 * @param[in] data The struct reg_ctx.
 */
static void reg_create_cb(int result, const char *id, void *data)
{
  struct reg_ctx *ctx = (struct reg_ctx *)data;
  struct Client *acptr = reg_ctx_client(ctx);

  if (result != KC_SUCCESS) {
    /* A refusal of what was sent is the client's to fix, and says what:
     * the draft/account-registration code for it where one fits, and
     * INVALID_PARAMS for a refusal Keycloak gave no reason we can name.
     * Only a failure to reach or use Keycloak (5xx, a timeout, a token
     * that would not come) is TEMPORARILY_UNAVAILABLE. */
    if (acptr) {
      switch (result) {
      case KC_CONFLICT:
        reg_answer_fail(ctx, acptr, "ACCOUNT_EXISTS",
                  "Account already exists");
        break;
      case KC_CONFLICT_EMAIL:
        reg_answer_fail(ctx, acptr, "UNACCEPTABLE_EMAIL",
                  "That email address is already used by another account");
        break;
      case KC_BAD_USERNAME:
        reg_answer_fail(ctx, acptr, "BAD_ACCOUNT_NAME",
                  "The account server does not accept this account name");
        break;
      case KC_BAD_EMAIL:
        reg_answer_fail(ctx, acptr, "INVALID_EMAIL",
                  "The account server does not accept this email address");
        break;
      case KC_BAD_PASSWORD:
        reg_answer_fail(ctx, acptr, "WEAK_PASSWORD",
                  "The account server does not accept this password");
        break;
      case KC_REJECTED:
        reg_answer_fail(ctx, acptr, "INVALID_PARAMS",
                  "The account server refused this registration");
        break;
      default:
        reg_answer_fail(ctx, acptr, "TEMPORARILY_UNAVAILABLE",
                  "Registration is temporarily unavailable");
        break;
      }
    }
    reg_ctx_free(ctx);
    return;
  }

  id = reg_uuid_or_null(id);           /* libkc gives UUIDs only; still */

  if (ctx->verify_email) {
    /* send-verify-email is addressed by user id: the one the create's
     * answer names, else the one a lookup by the (exact) username finds.
     * Sent whether or not the client is still here: the mail is the
     * account's. */
    ctx->stage = 2;
    if (id) {
      if (kc_user_send_verify_email(id, reg_email_cb, ctx) != 0)
        reg_email_cb(KC_ERROR, ctx);    /* non-fatal; frees ctx */
    } else if (kc_user_get(ctx->account, reg_verify_lookup_cb, ctx) != 0)
      reg_email_cb(KC_ERROR, ctx);      /* non-fatal; frees ctx */
    return;
  }

  if (!acptr) {                         /* gone: no one to log in */
    reg_ctx_free(ctx);
    return;
  }

  if (!id) {
    /* The answer named no user (Keycloak names it in the 201's Location;
     * something on the way dropped it): ask once, by the exact name.
     * REGISTER SUCCESS waits for that answer, bounded by libkc's request
     * timeout, so that the login -- the 900, the N or AC its peers get --
     * is made once and whole, never announced and then changed. */
    ctx->stage = 3;
    if (kc_user_get(ctx->account, reg_id_lookup_cb, ctx) == 0)
      return;
    log_write(LS_SYSTEM, L_WARNING, 0,
              "REGISTER: %s was created, but its Keycloak id could not be "
              "looked up; logged in without one", ctx->account);
  }

  register_complete_success(acptr, ctx, id);
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
      reg_answer_fail(ctx, acptr, "ACCOUNT_EXISTS",
                "Account already exists");
    reg_ctx_free(ctx);
    return;
  }
  if (result != KC_NOT_FOUND) {                 /* connectivity trouble */
    if (acptr)
      reg_answer_fail(ctx, acptr, "TEMPORARILY_UNAVAILABLE",
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
      reg_answer_fail(ctx, acptr, "TEMPORARILY_UNAVAILABLE",
                "Registration is temporarily unavailable");
    reg_ctx_free(ctx);
  }
}

#endif /* USE_LIBKC */

/** The nick characters (the only ones an account name can hold) the ircd's
 * casemapping folds together with another character that is not the same
 * ASCII letter in the other case: under rfc1459 "[\\]^" and "{|}~".  Read
 * from the casemapping table itself (ToLower()), never written out by
 * hand.
 * @return Their set, NUL-terminated, built once. */
static const char *reg_folding_chars(void)
{
  static char set[257];
  static int built;
  int b, d, n = 0;

  if (built)
    return set;
  for (b = 1; b < 256; b++)
    for (d = 1; d < 256 && IsNickChar((char)b); d++) {
      int letters = ((b | 0x20) >= 'a' && (b | 0x20) <= 'z'
                     && (b | 0x20) == (d | 0x20));
      if (d != b && !letters && ToLower((char)b) == ToLower((char)d)) {
        set[n++] = (char)b;
        break;
      }
    }
  set[n] = '\0';
  built = 1;
  return set;
}

/** Is \a c one of reg_folding_chars()? */
static int reg_folds_apart(char c)
{
  return c && strchr(reg_folding_chars(), c) != NULL;
}

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

  /* Check if already authenticated: logged in, or, before registration,
   * holding a completed SASL login (or an earlier REGISTER) that
   * registration has yet to apply (auth_complete_sasl() reads the same
   * two fields).  Otherwise the new account's name would be parked over
   * that login while the login's Keycloak id stays, and the client would
   * register under the new name with the old login's id. */
  if (IsAccount(sptr)
      || (!IsRegistered(sptr) && IsSASLComplete(sptr)
          && cli_saslaccount(sptr)[0])) {
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

  /* One REGISTER in flight per connection.  Without this an unauthenticated
   * connection could pipeline REGISTERs and mint a distinct Keycloak account
   * for each one, spending the server's Keycloak quota unthrottled.  A
   * nonzero cli_regcookie() *is* the guard; it is set when the context is
   * allocated below and cleared in reg_ctx_free() on every terminal path.
   * (Cross-connection rate limiting is the register_throttle.c check below.) */
  if (cli_regcookie(cptr)) {
    send_fail(sptr, "REGISTER", "TEMPORARILY_UNAVAILABLE", account,
              "Registration already in progress");
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

  /* ... and one the ircd tells apart from every other account name as
   * Keycloak does: no character the casemapping folds together with
   * another character that is not its own letter case (reg_folds_apart()).
   * Keycloak's "is the name taken?" folds letter case only, so "victim{"
   * would be created beside an existing "victim[", and the ircd -- which
   * compares account names under its casemapping -- would hold the two as
   * one account: sessions, history and metadata keys. */
  for (p = account; *p; p++) {
    if (reg_folds_apart(*p)) {
      char text[128];
      ircd_snprintf(0, text, sizeof(text), "Account names may not contain "
                    "any of %s: the server does not tell them apart",
                    reg_folding_chars());
      send_fail(sptr, "REGISTER", "BAD_ACCOUNT_NAME", account, text);
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

  /* Cross-connection throttle: per-IP rolling window plus a server-wide
   * backstop (register_throttle.c).  Placed after all synchronous
   * validation and before the in-flight cookie/context, so a throttled
   * request neither arms the guard nor derives credentials.  Attempts
   * are counted, not successes: a later duplicate-name or Keycloak
   * failure still consumed budget, so account-name enumeration is not
   * free.  Opers bypass (metadata-limiter precedent). */
  if (!IsOper(sptr)) {
    enum reg_throttle_result tres =
      reg_throttle_check(&cli_ip(cptr), CurrentTime,
                         feature_int(FEAT_REGISTER_THROTTLE_LIMIT),
                         feature_int(FEAT_REGISTER_THROTTLE_PERIOD),
                         feature_int(FEAT_REGISTER_THROTTLE_GLOBAL));
    if (tres != REG_THROTTLE_OK) {
      if (tres == REG_THROTTLE_GLOBAL)
        log_write(LS_SYSTEM, L_WARNING, 0,
                  "REGISTER: server-wide registration cap reached "
                  "(client %C)", cptr);
      send_fail(sptr, "REGISTER", "RATE_LIMITED", account,
                "Too many registration attempts; try again later");
      return 0;
    }
  }

#ifdef USE_LIBKC
  /* A real cookie is needed so the async callbacks can tell "still the same
   * connection" from "fd reused" (the SASL pattern, with REGISTER's own
   * cookie -- see reg_ctx_client()).  Setting it also arms the one-in-flight
   * guard, and it stays armed for exactly as long as the context below
   * lives: every exit path goes through reg_ctx_free(), which clears it. */
  do {
    cli_regcookie(cptr) = ircrandom() & 0x7fffffff;
  } while (!cli_regcookie(cptr));

  ctx = (struct reg_ctx *)MyMalloc(sizeof(*ctx));
  memset(ctx, 0, sizeof(*ctx));
  ctx->fd = cli_fd(cptr);
  ctx->cookie = cli_regcookie(cptr);
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

  /* labeled-response: the answer comes from Keycloak, after this line;
   * it goes out under this line's label (reg_answer_begin()), and this line
   * is not answered with an ACK meanwhile.  Taken here, where nothing
   * before the request has answered. */
  if (cli_label(cptr)[0]) {
    ircd_strncpy(ctx->label, cli_label(cptr), sizeof(ctx->label));
    cli_label_responded(cptr) = 1;
  }

  ctx->stage = 0;
  if (kc_user_get(ctx->account, reg_search_cb, ctx) != 0) {
    cli_label_responded(cptr) = 0;   /* the answer is this line's after all */
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
  /* #595: "*" means the current nick, same as REGISTER */
  if (account[0] == '*' && !account[1])
    account = cli_name(sptr);

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
