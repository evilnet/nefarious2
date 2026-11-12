/*
 * sasl_handler_cmocka.c - what AUTHENTICATE answers its parser when the
 * SASL exchange ends inside it, and where a Keycloak answer lets
 * registration go on.
 *
 * Registration waits on a SASL exchange in flight (AR_SASL_PENDING).  A
 * client that sends CAP END before its last AUTHENTICATE line has its
 * registration run when the exchange ends, and registration can exit the
 * client (a K-line, a SASL-required class) or free it (a bouncer revive
 * moves its socket onto the held session).
 *
 * - An exchange that ends inside the client's own AUTHENTICATE line -- a
 *   cached credential, OAUTHBEARER's local token check, the last step of
 *   SCRAM and of ECDSA, an abort -- hands the parser that result:
 *   CPTR_KILLED when registration exited or freed the client.
 * - An answer from Keycloak (a libkc completion) never runs registration
 *   in its own stack: libkc can deliver it inside ANY request call
 *   (kc_http_request() drives the transfers and reaps finished ones before
 *   it returns), so inside some handler -- the client's own AUTHENTICATE
 *   or REGISTER, or another client's.  It ends the exchange and leaves the
 *   registration check to the event loop (auth_recheck_later()).
 *
 * The REAL sasl_auth.o, m_authenticate.o and m_register.o are linked (with
 * ircd_string.o, ircd_alloc.o, account_id.o, webpush_keyring.o and
 * OpenSSL).  Around them a fake world: the registration machinery is the
 * AR_SASL_PENDING hold plus CAP END, modelled on check_auth_finished() (a
 * check with the hold on or CAP not ended keeps waiting; otherwise the
 * client registers, and an exiting registration frees it as free_client()
 * does, then poisons it, so any later use of it crashes the test); the
 * event loop is run_event_loop(), which runs the queued registration
 * checks; libkc answers when the test says so -- later (the event loop),
 * before the request call returns, or by delivering an earlier request's
 * pending answer inside a new request call.  Every stub that takes a
 * client counts a call for a client registration freed.
 *
 * The Keycloak cases are #ifdef USE_LIBKC: without it sasl_auth.c has no
 * local mechanisms and only the shared login completion is tested.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include "account_id.h"
#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "register_throttle.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "sasl_auth.h"
#include "send.h"

#ifdef USE_LIBKC
#include <kc/kc_cred_derive.h>
#include <kc/kc_keycloak.h>
#include <kc/kc_jwt.h>
#endif

/* The handlers (not in a header). */
extern int m_authenticate(struct Client *cptr, struct Client *sptr,
                          int parc, char *parv[]);
extern int m_register(struct Client *cptr, struct Client *sptr,
                      int parc, char *parv[]);

/* ------------------------------------------------------------------ */
/* The fake world                                                      */
/* ------------------------------------------------------------------ */

time_t CurrentTime = 1000000;
int log_inassert;
struct Client me;
struct Client *LocalClientArray[MAXCONNECTIONS];

/** What registration does to a client once nothing holds it. */
enum reg_outcome { REG_KEEPS, REG_EXITS };

/** A local client: the Client, its Connection, its User and the state of
 * the registration machinery that check_auth_finished() reads. */
struct fake {
  struct Client cli;
  struct Connection con;
  struct User user;
  char auth;                  /**< its AuthRequest: only the address is used */
  int in_use;
  int fd;
  int hold;                   /**< AR_SASL_PENDING */
  int cap_done;               /**< CAP END was sent (no AR_CAP_PENDING) */
  int recheck_queued;         /**< a registration check waits for the loop */
  enum reg_outcome outcome;   /**< what registration does to it */
  int registered;             /**< registration ran and kept it */
  int freed;                  /**< registration ran and exited it */
  int runs_inside_kc;         /**< registrations run while a libkc request
                                   call was running */
  int checks_unheld_in_login; /**< checks from auth_set_account() with no
                                   hold, inside sasl_complete_login() */
  int touched_after_free;     /**< a stub was handed it once freed */
  int numerics[16];           /**< numerics sent to it, in order */
  int n_numerics;
  char raw[600];              /**< the last raw line sent to it */
  char fail_code[64];         /**< the code of the last FAIL sent to it */
};

#define NFAKE 8
static struct fake fakes[NFAKE];
static int in_kc_call;        /**< a libkc request call is running */
static int in_login;          /**< inside sasl_complete_login() (test 1) */

static struct fake *fake_of(const struct Client *cptr)
{
  int i;
  for (i = 0; i < NFAKE; i++)
    if (fakes[i].in_use && &fakes[i].cli == cptr)
      return &fakes[i];
  return NULL;
}

static struct fake *fake_of_auth(const struct AuthRequest *auth)
{
  int i;
  for (i = 0; i < NFAKE; i++)
    if (fakes[i].in_use && !fakes[i].freed
        && (const void *)&fakes[i].auth == (const void *)auth)
      return &fakes[i];
  fail_msg("an auth request of no live client was used");
  return NULL;
}

/** A stub was handed \a cptr: count it if registration had freed it. */
static void touch(const struct Client *cptr)
{
  struct fake *f = fake_of(cptr);
  if (f && f->freed)
    f->touched_after_free++;
}

/** A connecting client on \a fd, past NICK and USER, CAP sasl active. */
static struct Client *new_client(int fd, const char *nick, int cap_done,
                                 enum reg_outcome outcome)
{
  struct fake *f = &fakes[fd % NFAKE];

  memset(f, 0, sizeof(*f));
  f->in_use = 1;
  f->fd = fd;
  f->cap_done = cap_done;
  f->outcome = outcome;
  cli_magic(&f->cli) = CLIENT_MAGIC;
  con_magic(&f->con) = CONNECTION_MAGIC;
  cli_connect(&f->cli) = &f->con;
  con_client(&f->con) = &f->cli;
  s_fd(&con_socket(&f->con)) = fd;
  cli_status(&f->cli) = STAT_UNKNOWN_USER;
  cli_user(&f->cli) = &f->user;
  ircd_strncpy(cli_name(&f->cli), nick, sizeof(cli_name(&f->cli)));
  ircd_strncpy(f->user.username, "user", sizeof(f->user.username));
  ircd_strncpy(f->user.host, "host.test", sizeof(f->user.host));
  ircd_strncpy(cli_sockhost(&f->cli), "host.test", sizeof(cli_sockhost(&f->cli)));
  CapSet(cli_active(&f->cli), CAP_SASL);
  cli_auth(&f->cli) = (struct AuthRequest *)&f->auth;
  LocalClientArray[fd] = &f->cli;
  return &f->cli;
}

/** check_auth_finished(), as far as SASL is concerned: waits while the
 * exchange holds it or CAP is not ended; else registers the client, and
 * an exiting registration frees it the way free_client() does -- out of
 * LocalClientArray, no Connection -- and poisons what is left, so any
 * later use crashes the test rather than reading a stale client. */
static int registration_check(struct fake *f)
{
  if (f->hold || !f->cap_done)
    return 0;
  if (in_kc_call)
    f->runs_inside_kc++;
  cli_auth(&f->cli) = NULL;              /* destroy_auth_request() */
  if (f->outcome == REG_KEEPS) {
    f->registered++;
    return 0;
  }
  LocalClientArray[f->fd] = NULL;
  f->freed = 1;
  memset(&f->cli, 0xA5, sizeof(f->cli));   /* free_client(), poisoned */
  memset(&f->con, 0xA5, sizeof(f->con));
  memset(&f->user, 0xA5, sizeof(f->user));
  return CPTR_KILLED;
}

#ifdef USE_LIBKC
/** The event loop: run the registration checks a Keycloak answer left to
 * it (auth_recheck_later()). */
static void run_event_loop(void)
{
  int i;
  for (i = 0; i < NFAKE; i++) {
    struct fake *f = &fakes[i];
    if (f->in_use && !f->freed && f->recheck_queued) {
      f->recheck_queued = 0;
      if (cli_auth(&f->cli))
        registration_check(f);
    }
  }
}
#endif

/* s_auth.c */
void auth_sasl_start(struct AuthRequest *auth)
{
  fake_of_auth(auth)->hold = 1;
}

void auth_sasl_clear(struct AuthRequest *auth)
{
  fake_of_auth(auth)->hold = 0;
}

int auth_sasl_done(struct AuthRequest *auth)
{
  struct fake *f = fake_of_auth(auth);
  f->hold = 0;
  return registration_check(f);
}

int auth_set_account(struct AuthRequest *auth, const char *account)
{
  struct fake *f = fake_of_auth(auth);
  if (in_login && !f->hold)
    f->checks_unheld_in_login++;
  return registration_check(f);
}

void auth_recheck_later(struct AuthRequest *auth)
{
  fake_of_auth(auth)->recheck_queued = 1;
}

void auth_set_account_later(struct AuthRequest *auth, const char *account)
{
  fake_of_auth(auth)->recheck_queued = 1;
}

int auth_iauth_handles_sasl(void) { return 0; }
int auth_send_sasl_start(struct Client *c, const char *m, const char *f) { return 0; }
int auth_send_sasl_host(struct Client *c, const char *u, const char *h, const char *i) { return 0; }
int auth_send_sasl_data(struct Client *c, const char *d) { return 0; }
int auth_send_sasl_abort(struct Client *c) { return 0; }
int auth_iauth_sasl_fail(struct Client *c) { return 0; }

/* m_sasl.c */
int abort_sasl(struct Client *cptr, int timeout) { touch(cptr); return 0; }

/* The send layer: records what reaches a client. */
int send_reply(struct Client *to, int reply, ...)
{
  struct fake *f = fake_of(to);
  touch(to);
  if (f && !f->freed && f->n_numerics < 16)
    f->numerics[f->n_numerics++] = reply & ~SND_EXPLICIT;
  return 0;
}

void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  struct fake *f = fake_of(to);
  va_list vl;
  touch(to);
  if (f && !f->freed) {
    va_start(vl, pattern);
    vsnprintf(f->raw, sizeof(f->raw), pattern, vl);
    va_end(vl);
  }
}

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  struct fake *f = fake_of(to);
  touch(to);
  if (f && !f->freed)
    ircd_strncpy(f->fail_code, code, sizeof(f->fail_code));
}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{ touch(to); }
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{ touch(from); }
void sendcmdto_common_channels_capab_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Client *one, int require,
                                            int forbid, const char *pattern, ...)
{ touch(from); }
void send_cap_notify(const char *capname, int available, const char *value) {}
void cap_set_value(enum Capab cap, const char *value) {}
int need_more_params(struct Client *cptr, const char *cmd) { touch(cptr); return 0; }
int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{ touch(victim); return cptr == victim ? CPTR_KILLED : 0; }
int ircd_snprintf(struct Client *dest, char *buf, size_t len,
                  const char *format, ...)
{
  va_list vl;
  int r;
  va_start(vl, format);
  r = vsnprintf(buf, len, format, vl);
  va_end(vl);
  return r;
}

/* Features */
static int verify_email_on;   /**< FEAT_REGISTER_VERIFY_EMAIL */

int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_REGISTER_VERIFY_EMAIL:
    return verify_email_on;
  case FEAT_SASL_LOCAL:
  case FEAT_KEYCLOAK_INSECURE_TOKEN_VALIDATION:
  case FEAT_CAP_draft_account_registration:
    return 1;
  default:
    return 0;
  }
}

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_SASL_TIMEOUT: return 30;
  case FEAT_SASL_NEGCACHE_TTL: return 60;
  case FEAT_SASL_POSCACHE_TTL: return 300;
  default: return 0;
  }
}

const char *feature_str(enum Feature feat)
{
  switch (feat) {
  case FEAT_SASL_LOCAL_MECHANISMS:
    return "PLAIN,EXTERNAL,OAUTHBEARER,SCRAM-SHA-256,ECDSA-NIST256P-CHALLENGE";
  case FEAT_KEYCLOAK_URL: return "http://kc.test";
  case FEAT_KEYCLOAK_REALM: return "test";
  case FEAT_KEYCLOAK_CLIENT_ID: return "ircd";
  case FEAT_KEYCLOAK_CLIENT_SECRET: return "secret";
  case FEAT_SASL_SERVER: return "*";
  default: return "";
  }
}

/* Timers: nothing fires in this world. */
struct Timer *timer_init(struct Timer *timer) { memset(timer, 0, sizeof(*timer)); return timer; }
void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value) {}
void timer_del(struct Timer *timer) {}
void free_connection(struct Connection *con) {}

/* Logging */
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
void debug(int level, const char *form, ...) {}

/* Everything else a login or a REGISTER reaches, none of which matters
 * here. */
struct Client *find_match_server(char *mask) { return NULL; }
unsigned int ircrandom(void) { static unsigned int r = 12345; return r += 7919; }
struct BouncerSession *bounce_get_session(struct Client *cptr) { touch(cptr); return NULL; }
const char *bounce_session_kc_id(struct BouncerSession *s) { return ""; }
void bounce_session_adopt_kc_id(struct BouncerSession *s, const char *id) {}
int bounce_account_kc_conflict(const char *account, const char *kc_id) { return 0; }
int bounce_rebind_kc_conflict(const char *ghost_id, const char *incoming_id) { return 0; }
void bounce_emit_alias_update(struct Client *primary, const char *field,
                              const char *value) { touch(primary); }
void bounce_sync_alias_identity(struct Client *primary) { touch(primary); }
void channel_account_adjust(struct Client *cptr, int delta) { touch(cptr); }
void presence_anchor_transfer(struct Client *cptr, const char *old_anchor,
                              int old_is_session, const char *new_anchor,
                              int new_is_session) { touch(cptr); }
int hide_hostmask(struct Client *cptr) { touch(cptr); return 0; }
void metadata_load_account(struct Client *cptr, const char *account) { touch(cptr); }
void metadata_mode_sync_restore(struct Client *cptr, int live) { touch(cptr); }
enum reg_throttle_result reg_throttle_check(const struct irc_in_addr *ip,
                                            time_t now, int limit, int period,
                                            int global_limit)
{ return REG_THROTTLE_OK; }

/* ------------------------------------------------------------------ */
/* libkc: answers later, before the request call returns, or delivers  */
/* an earlier request's answer inside a new request call               */
/* ------------------------------------------------------------------ */

#ifdef USE_LIBKC
/** How the next request call answers. */
static enum {
  KC_LATER,          /**< the test answers it later: the event loop */
  KC_INLINE_OK,      /**< answered (success) before the call returns */
  KC_INLINE_FAIL,    /**< answered (a failure) before the call returns */
  KC_REAP,          /**< first delivers the pending answer of an earlier
                          request (as kc_http_request()'s timeout action and
                          finished-transfer reap do), then waits itself */
  KC_REFUSE          /**< the call cannot start the request: non-zero, and
                          the callback never runs */
} kc_mode;
/** What a reaped pending answer says. */
static int reap_ok;
static int kc_requests;               /**< request calls made */
static char next_grant_user[32];      /**< the user of the grant being made */

/** An answer libkc owes (one request at a time is enough here). */
enum pend_kind { P_NONE, P_TOKEN, P_USER, P_USERS, P_INTRO, P_RESULT };
struct pending {
  enum pend_kind kind;
  void *cb;
  void *data;
  char user[32];        /**< a grant's user: its ID token names it */
};
#define NPEND 4
static struct pending pend[NPEND];

static const char *TEST_SUB = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
static char user_pem[600];            /**< ECDSA public key a lookup returns */
static char scram_salt[64], scram_stored[64], scram_server[64];
static int scram_iters;

static void pend_push(enum pend_kind kind, void *cb, void *data)
{
  int i;
  for (i = 0; i < NPEND; i++)
    if (pend[i].kind == P_NONE) {
      pend[i].kind = kind;
      pend[i].cb = cb;
      pend[i].data = data;
      return;
    }
  fail_msg("too many pending answers");
}

/** Deliver pending answer \a i with result \a res (KC_SUCCESS, or a
 * failure code: KC_FORBIDDEN, KC_NOT_FOUND, KC_UNVERIFIED, ...). */
static void pend_deliver_at(int i, int res)
{
  struct pending p = pend[i];
  struct kc_access_token tok;
  struct kc_user user;
  struct kc_token_info info;
  char idt[64];
  int ok = (res == KC_SUCCESS);

  assert_int_not_equal(p.kind, P_NONE);
  memmove(pend + i, pend + i + 1, sizeof(pend) - (i + 1) * sizeof(pend[0]));
  memset(&pend[NPEND - 1], 0, sizeof(pend[0]));

  memset(&tok, 0, sizeof(tok));
  tok.access_token = "user-token";
  snprintf(idt, sizeof(idt), "hdr.%s.sig", p.user[0] ? p.user : "payload");
  tok.id_token = idt;
  memset(&user, 0, sizeof(user));
  user.id = (char *)TEST_SUB;
  user.username = "who";
  user.ecdsa_pubkey = user_pem[0] ? user_pem : NULL;
  if (scram_salt[0]) {
    user.scram_salt = scram_salt;
    user.scram_iterations = scram_iters;
    user.scram_stored_key = scram_stored;
    user.scram_server_key = scram_server;
  }
  memset(&info, 0, sizeof(info));
  info.active = true;
  info.username = "ian";
  info.sub = (char *)TEST_SUB;

  switch (p.kind) {
  case P_TOKEN:
    ((kc_token_cb)p.cb)(ok ? KC_SUCCESS : res == KC_ERROR ? KC_FORBIDDEN : res,
                        ok ? &tok : NULL, p.data);
    break;
  case P_USER:
    ((kc_user_cb)p.cb)(ok ? KC_SUCCESS : KC_NOT_FOUND, ok ? &user : NULL, p.data);
    break;
  case P_USERS:
    ((kc_users_cb)p.cb)(ok ? KC_SUCCESS : KC_NOT_FOUND, ok ? &user : NULL,
                        ok ? 1 : 0, p.data);
    break;
  case P_INTRO:
    ((kc_introspect_cb)p.cb)(ok ? KC_SUCCESS : KC_FORBIDDEN, ok ? &info : NULL,
                             p.data);
    break;
  case P_RESULT:
    ((kc_result_cb)p.cb)(ok ? KC_SUCCESS : KC_ERROR, p.data);
    break;
  default:
    break;
  }
}

/** Deliver the oldest pending answer: success or a failure. */
static void pend_deliver(int ok)
{
  pend_deliver_at(0, ok ? KC_SUCCESS : KC_ERROR);
}

/** Deliver the oldest pending answer of \a kind with result \a res. */
static void pend_deliver_kind(enum pend_kind kind, int res)
{
  int i;
  for (i = 0; i < NPEND; i++)
    if (pend[i].kind == kind) {
      pend_deliver_at(i, res);
      return;
    }
  fail_msg("no pending answer of kind %d", kind);
}

/** One request call: answer per #kc_mode. */
static int kc_request(enum pend_kind kind, void *cb, void *data)
{
  kc_requests++;
  if (kc_mode == KC_REFUSE)
    return -1;
  in_kc_call++;
  if (kc_mode == KC_REAP)
    pend_deliver(reap_ok);
  pend_push(kind, cb, data);
  if (kind == P_TOKEN) {
    int i;
    for (i = NPEND - 1; i >= 0; i--)
      if (pend[i].kind == P_TOKEN && pend[i].data == data)
        ircd_strncpy(pend[i].user, next_grant_user, sizeof(pend[i].user));
  }
  if (kc_mode == KC_INLINE_OK || kc_mode == KC_INLINE_FAIL)
    pend_deliver(kc_mode == KC_INLINE_OK);
  in_kc_call--;
  return 0;
}

int kc_user_verify_password(const char *username, const char *password,
                            kc_token_cb cb, void *data)
{
  ircd_strncpy(next_grant_user, username, sizeof(next_grant_user));
  return kc_request(P_TOKEN, (void *)cb, data);
}
int kc_user_get(const char *username, kc_user_cb cb, void *data)
{ return kc_request(P_USER, (void *)cb, data); }
int kc_user_search(const char *query, bool exact, kc_users_cb cb, void *data)
{ return kc_request(P_USERS, (void *)cb, data); }
int kc_token_introspect(const char *token, kc_introspect_cb cb, void *data)
{ return kc_request(P_INTRO, (void *)cb, data); }
int kc_user_create_full(const struct kc_user_create_req *req,
                        kc_result_cb cb, void *data)
{ return kc_request(P_RESULT, (void *)cb, data); }
int kc_user_send_verify_email(const char *id, kc_result_cb cb, void *data)
{ return kc_request(P_RESULT, (void *)cb, data); }
int kc_token_ensure(kc_token_cb cb, void *data) { return 0; }
int kc_jwt_prime_cache(struct kc_realm realm) { return KC_SUCCESS; }

/** The Keycloak user id (a uuid) of \a user, as the fake grants issue it. */
static void user_sub(const char *user, char *out, size_t size)
{
  unsigned long h = 5381;
  for (; *user; user++)
    h = h * 33 + (unsigned char)*user;
  snprintf(out, size, "6e4e28ba-2fa1-11d2-883f-%012lx", h & 0xffffffffffffUL);
}

/** The compact id a login of \a user gets. */
static const char *user_id(const char *user, char out[ACCOUNT_ID_LEN + 1])
{
  char sub[40];
  user_sub(user, sub, sizeof(sub));
  account_id_from_uuid(sub, out);
  return out;
}

/** A grant's ID token is "hdr.<user>.sig": its sub is that user's. */
int kc_jwt_extract_sub(const char *token, char *out, size_t out_size)
{
  const char *a = strchr(token, '.'), *b = a ? strchr(a + 1, '.') : NULL;
  char user[32];

  if (!a || !b || b - a - 1 >= (int)sizeof(user) || !strncmp(a + 1, "payload", 7)) {
    ircd_strncpy(out, TEST_SUB, out_size);
    return 1;
  }
  memcpy(user, a + 1, b - a - 1);
  user[b - a - 1] = '\0';
  user_sub(user, out, out_size);
  return 1;
}

/** OAUTHBEARER's local check: any token is carol's, unless the test says
 * the check cannot decide (introspection then). */
static int jwt_local_undecided;
int kc_jwt_validate_local(struct kc_realm realm, const char *token,
                          struct kc_token_info **info_out)
{
  struct kc_token_info *info;
  if (jwt_local_undecided)
    return KC_ERROR;
  info = calloc(1, sizeof(*info));
  info->active = true;
  info->username = strdup("carol");
  info->sub = strdup(TEST_SUB);
  *info_out = info;
  return KC_SUCCESS;
}

void kc_jwt_token_info_free(struct kc_token_info *info)
{
  if (!info)
    return;
  free(info->username);
  free(info->sub);
  free(info);
}

/* REGISTER's credential derivation: not under test. */
int scram_sha256_derive_random(const char *password,
                               struct scram_sha256_creds *out)
{
  memset(out, 0, sizeof(*out));
  out->iterations = 4096;
  return 0;
}

int kc_pbkdf2_cred_build(const char *password, char **cred_data,
                         char **secret_data)
{
  *cred_data = strdup("{}");
  *secret_data = strdup("{}");
  return 0;
}
#endif /* USE_LIBKC */

/* ------------------------------------------------------------------ */
/* Driving the handlers                                                */
/* ------------------------------------------------------------------ */

static int has_numeric(const struct fake *f, int numeric)
{
  int i;
  for (i = 0; i < f->n_numerics; i++)
    if (f->numerics[i] == numeric)
      return 1;
  return 0;
}

#ifdef USE_LIBKC
/** One AUTHENTICATE line from \a cptr, through the real handler. */
static int authenticate(struct Client *cptr, const char *arg)
{
  char buf[512];
  char *parv[3];

  ircd_strncpy(buf, arg, sizeof(buf));
  parv[0] = cli_name(cptr);
  parv[1] = buf;
  parv[2] = NULL;
  return m_authenticate(cptr, cptr, 2, parv);
}

/** "REGISTER <account> <email> <password>" from \a cptr, through the real
 * handler. */
static int register_as(struct Client *cptr, const char *account,
                       const char *email, const char *password)
{
  char a[32], e[64], p[64];
  char *parv[5];

  ircd_strncpy(a, account, sizeof(a));
  ircd_strncpy(e, email, sizeof(e));
  ircd_strncpy(p, password, sizeof(p));
  parv[0] = cli_name(cptr);
  parv[1] = a;
  parv[2] = e;
  parv[3] = p;
  parv[4] = NULL;
  return m_register(cptr, cptr, 4, parv);
}

/** "REGISTER * * <password>" from \a cptr. */
static int register_line(struct Client *cptr, const char *password)
{
  return register_as(cptr, "*", "*", password);
}

static void b64(const unsigned char *in, size_t len, char *out)
{
  EVP_EncodeBlock((unsigned char *)out, in, (int)len);
}

static size_t unb64(const char *in, unsigned char *out)
{
  size_t n = strlen(in);
  int len = EVP_DecodeBlock(out, (const unsigned char *)in, (int)n);
  while (n > 0 && in[n - 1] == '=') { n--; len--; }
  return (size_t)len;
}

static void plain_b64(const char *user, const char *pass, char *out)
{
  unsigned char raw[200];
  size_t ul = strlen(user), pl = strlen(pass);
  raw[0] = '\0';
  memcpy(raw + 1, user, ul);
  raw[1 + ul] = '\0';
  memcpy(raw + 2 + ul, pass, pl);
  b64(raw, 2 + ul + pl, out);
}
#endif /* USE_LIBKC */

static int setup(void **state)
{
  memset(fakes, 0, sizeof(fakes));
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  in_kc_call = in_login = 0;
#ifdef USE_LIBKC
  kc_mode = KC_LATER;
  reap_ok = 0;
  kc_requests = 0;
  memset(pend, 0, sizeof(pend));
  jwt_local_undecided = 0;
  verify_email_on = 0;
  user_pem[0] = scram_salt[0] = '\0';
#endif
  return 0;
}

/* ------------------------------------------------------------------ */
/* The shared login completion (the P10 relay's too)                   */
/* ------------------------------------------------------------------ */

/** sasl_complete_login() holds registration until its own end, even for an
 * exchange whose hold was already dropped (one started while an earlier
 * exchange's cookie was still set: an IAuth answer leaves it), and says
 * whether the registration it resumed kept the client. */
static void complete_login_holds_registration_to_its_end(void **state)
{
  struct Client *c = new_client(10, "dan", 1, REG_EXITS);
  struct fake *f = fake_of(c);
  int rc;

  f->hold = 0;                     /* the precondition, as IAuth's Z leaves it */
  in_login = 1;
  rc = sasl_complete_login(c, "dan", 0, NULL, 0);
  in_login = 0;

  assert_int_equal(f->checks_unheld_in_login, 0);
  assert_true(f->freed);
  assert_int_equal(rc, CPTR_KILLED);
  assert_int_equal(f->touched_after_free, 0);
}

/** A client registration keeps: 0, and it is registered once, after 903. */
static void complete_login_keeps(void **state)
{
  struct Client *c = new_client(11, "dan", 1, REG_KEEPS);
  struct fake *f = fake_of(c);

  auth_sasl_start(cli_auth(c));
  assert_int_equal(sasl_complete_login(c, "dan", 0, NULL, 0), 0);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_int_equal(f->registered, 1);
  assert_false(f->freed);
}

#ifdef USE_LIBKC
/* ------------------------------------------------------------------ */
/* Exchanges that end inside the client's own AUTHENTICATE line        */
/* ------------------------------------------------------------------ */

/** Logs \a user in once, the way a first login goes: Keycloak answers
 * later, from the event loop.  Fills the positive (\a ok) or negative
 * cache for those credentials. */
static void first_login(int fd, const char *user, const char *pass, int ok)
{
  struct Client *c = new_client(fd, "first", 0, REG_KEEPS);
  struct fake *f = fake_of(c);
  char data[300];

  plain_b64(user, pass, data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(ok);                       /* the event loop */
  run_event_loop();
  assert_true(has_numeric(f, ok ? RPL_SASLSUCCESS : ERR_SASLFAIL));
  f->in_use = 0;
  LocalClientArray[fd] = NULL;
}

static void sasl_init_once(void)
{
  static int done;
  if (!done) {
    assert_int_equal(sasl_local_init(), 0);
    done = 1;
  }
}

/** A positive-cache hit completes the login inside AUTHENTICATE; with CAP
 * END already sent, registration runs there and exits the client. */
static void poscache_hit_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];
  int requests;

  sasl_init_once();
  first_login(20, "alice", "alicepw", 1);
  requests = kc_requests;

  c = new_client(21, "alice2", 1, REG_EXITS);
  f = fake_of(c);
  plain_b64("alice", "alicepw", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), CPTR_KILLED);
  assert_int_equal(kc_requests, requests);     /* answered from the cache */
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** The same with a registration that keeps the client: 0. */
static void poscache_hit_registration_keeps(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  first_login(22, "amy", "amypw", 1);
  c = new_client(23, "amy2", 1, REG_KEEPS);
  f = fake_of(c);
  plain_b64("amy", "amypw", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_int_equal(f->registered, 1);
  assert_false(f->freed);
}

/** A negative-cache hit fails the exchange inside AUTHENTICATE; registration
 * runs there (a SASL-required class, a K-line) and exits the client. */
static void negcache_hit_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  first_login(24, "bob", "wrong", 0);
  c = new_client(25, "bob2", 1, REG_EXITS);
  f = fake_of(c);
  plain_b64("bob", "wrong", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** OAUTHBEARER's local token check completes the login inside AUTHENTICATE. */
static void oauthbearer_local_check_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char data[300];

  sasl_init_once();
  c = new_client(29, "carol", 1, REG_EXITS);
  f = fake_of(c);
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  assert_int_equal(authenticate(c, data), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** ECDSA-NIST256P-CHALLENGE: the signed challenge completes the login
 * inside AUTHENTICATE. */
static void ecdsa_response_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;
  EVP_PKEY *key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
  BIO *bio = BIO_new(BIO_s_mem());
  char *pem_data, data[600], *sp;
  unsigned char challenge[64], sig[128];
  size_t siglen = sizeof(sig), challenge_len;
  long pem_len;
  EVP_MD_CTX *md = EVP_MD_CTX_new();

  assert_non_null(key);
  PEM_write_bio_PUBKEY(bio, key);
  pem_len = BIO_get_mem_data(bio, &pem_data);
  assert_true(pem_len < (long)sizeof(user_pem));
  memcpy(user_pem, pem_data, pem_len);
  user_pem[pem_len] = '\0';

  sasl_init_once();
  c = new_client(30, "dave", 1, REG_EXITS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "ECDSA-NIST256P-CHALLENGE"), 0);
  b64((const unsigned char *)"dave", 4, data);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(1);                        /* the key lookup: the event loop */
  run_event_loop();
  assert_false(f->freed);

  sp = strchr(f->raw, ' ');                /* "AUTHENTICATE <challenge>" */
  assert_non_null(sp);
  challenge_len = unb64(sp + 1, challenge);
  assert_int_equal(challenge_len, 32);
  assert_int_equal(EVP_DigestSignInit(md, NULL, EVP_sha256(), NULL, key), 1);
  assert_int_equal(EVP_DigestSign(md, sig, &siglen, challenge, challenge_len), 1);
  b64(sig, siglen, data);

  assert_int_equal(authenticate(c, data), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);

  EVP_MD_CTX_free(md);
  BIO_free(bio);
  EVP_PKEY_free(key);
}

/** SCRAM-SHA-256: the client's acknowledgement of the server's signature
 * completes the login inside AUTHENTICATE. */
static void scram_ack_registration_exits(void **state)
{
  static const char pass[] = "erinpw";
  static const char salt[] = "0123456789abcdef";
  const int iters = 1024;
  struct Client *c;
  struct fake *f;
  unsigned char salted[32], ckey[32], skey[32], stored[32], csig[32], proof[32];
  unsigned char server_first[300];
  char proof_b64[64];
  char first_bare[] = "n=erin,r=clientnonce";
  char msg[600], data[800], authmsg[1200], cfwp[300], *nonce, *sp, *end;
  unsigned int hl;
  size_t sf_len;
  int i;

  PKCS5_PBKDF2_HMAC(pass, sizeof(pass) - 1, (const unsigned char *)salt,
                    sizeof(salt) - 1, iters, EVP_sha256(), 32, salted);
  HMAC(EVP_sha256(), salted, 32, (const unsigned char *)"Client Key", 10, ckey, &hl);
  HMAC(EVP_sha256(), salted, 32, (const unsigned char *)"Server Key", 10, skey, &hl);
  EVP_Digest(ckey, 32, stored, NULL, EVP_sha256(), NULL);
  b64((const unsigned char *)salt, sizeof(salt) - 1, scram_salt);
  b64(stored, 32, scram_stored);
  b64(skey, 32, scram_server);
  scram_iters = iters;

  sasl_init_once();
  c = new_client(31, "erin", 1, REG_EXITS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "SCRAM-SHA-256"), 0);
  snprintf(msg, sizeof(msg), "n,,%s", first_bare);
  b64((const unsigned char *)msg, strlen(msg), data);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(1);                        /* the credentials: the event loop */
  run_event_loop();
  assert_false(f->freed);

  sp = strchr(f->raw, ' ');                /* "AUTHENTICATE <server-first>" */
  assert_non_null(sp);
  sf_len = unb64(sp + 1, server_first);
  server_first[sf_len] = '\0';
  nonce = strstr((char *)server_first, "r=");
  assert_non_null(nonce);
  end = strchr(nonce, ',');
  assert_non_null(end);
  snprintf(cfwp, sizeof(cfwp), "c=biws,%.*s", (int)(end - nonce), nonce);
  snprintf(authmsg, sizeof(authmsg), "%s,%s,%s", first_bare,
           (char *)server_first, cfwp);
  HMAC(EVP_sha256(), stored, 32, (const unsigned char *)authmsg,
       strlen(authmsg), csig, &hl);
  for (i = 0; i < 32; i++)
    proof[i] = ckey[i] ^ csig[i];
  b64(proof, 32, proof_b64);
  snprintf(msg, sizeof(msg), "%s,p=%s", cfwp, proof_b64);
  b64((const unsigned char *)msg, strlen(msg), data);
  assert_int_equal(authenticate(c, data), 0);   /* server-final sent */
  assert_false(f->freed);

  assert_int_equal(authenticate(c, "+"), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** AUTHENTICATE * aborts a local exchange inside the line; registration
 * runs there. */
static void star_abort_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(32, "sam", 1, REG_EXITS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, "*"), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** Data that is not base64 aborts the exchange inside the line. */
static void bad_base64_abort_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(33, "bea", 1, REG_EXITS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, "!!!!"), CPTR_KILLED);
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** An exchange Keycloak failed (OAUTHBEARER introspection: the error
 * challenge, state FAILED) is aborted by the client's next data line,
 * inside it. */
static void failed_state_abort_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;
  const char msg[] = "n,,\001auth=Bearer opaque-token\001\001";
  char data[300];

  sasl_init_once();
  c = new_client(34, "fae", 1, REG_EXITS);
  f = fake_of(c);
  jwt_local_undecided = 1;                 /* goes on to introspection */
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(0);                         /* inactive: the event loop */
  run_event_loop();
  assert_false(f->freed);                  /* the error challenge only */
  assert_int_equal(authenticate(c, "AQ=="), CPTR_KILLED);
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/* ------------------------------------------------------------------ */
/* Keycloak answers: registration from the event loop, never inline    */
/* ------------------------------------------------------------------ */

/** An answer from the event loop: the callback ends the exchange and the
 * registration check runs from the loop. */
static void later_answer_registers_from_the_event_loop(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  c = new_client(40, "gus", 1, REG_EXITS);
  f = fake_of(c);
  plain_b64("gus", "guspw", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(1);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_false(f->freed);                  /* not in the callback's stack */
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** libkc fails the grant before kc_user_verify_password() returns: the
 * handler returns with the client alive, and registration runs from the
 * event loop. */
static void inline_failure_registers_from_the_event_loop(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  c = new_client(41, "eve", 1, REG_EXITS);
  f = fake_of(c);
  plain_b64("eve", "evepw-inline-fail", data);
  kc_mode = KC_INLINE_FAIL;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_int_equal(f->runs_inside_kc, 0);
  assert_false(f->freed);
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** The same for a grant that succeeds before the call returns. */
static void inline_success_registers_from_the_event_loop(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  c = new_client(42, "fay", 1, REG_EXITS);
  f = fake_of(c);
  plain_b64("fay", "faypw-inline-ok", data);
  kc_mode = KC_INLINE_OK;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_int_equal(f->runs_inside_kc, 0);
  assert_false(f->freed);
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** SCRAM's and ECDSA's credential lookups answered (a failure: no such
 * credentials) before kc_user_get() returns. */
static void inline_lookup_failures_register_from_the_event_loop(void **state)
{
  static const char *const mechs[2] = { "SCRAM-SHA-256", "ECDSA-NIST256P-CHALLENGE" };
  static const char *const firsts[2] = { "n,,n=lou,r=nonce", "lou" };
  int m;

  sasl_init_once();
  for (m = 0; m < 2; m++) {
    struct Client *c = new_client(43 + m, "lou", 1, REG_EXITS);
    struct fake *f = fake_of(c);
    char data[300];

    kc_mode = KC_LATER;
    assert_int_equal(authenticate(c, mechs[m]), 0);
    b64((const unsigned char *)firsts[m], strlen(firsts[m]), data);
    kc_mode = KC_INLINE_FAIL;
    assert_int_equal(authenticate(c, data), 0);
    assert_true(has_numeric(f, ERR_SASLFAIL));
    assert_int_equal(f->runs_inside_kc, 0);
    assert_false(f->freed);
    run_event_loop();
    assert_true(f->freed);
    assert_int_equal(f->touched_after_free, 0);
  }
}

/** EXTERNAL's fingerprint search answered (a match) before kc_user_search()
 * returns. */
static void inline_external_registers_from_the_event_loop(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(45, "xen", 1, REG_EXITS);
  f = fake_of(c);
  ircd_strncpy(cli_sslclifp(c), "ab12cd34", sizeof(cli_sslclifp(c)));
  assert_int_equal(authenticate(c, "EXTERNAL"), 0);
  kc_mode = KC_INLINE_OK;
  assert_int_equal(authenticate(c, "+"), 0);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_int_equal(f->runs_inside_kc, 0);
  assert_false(f->freed);
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** OAUTHBEARER's introspection answered (active) before
 * kc_token_introspect() returns. */
static void inline_introspection_registers_from_the_event_loop(void **state)
{
  struct Client *c;
  struct fake *f;
  const char msg[] = "n,,\001auth=Bearer opaque-token\001\001";
  char data[300];

  sasl_init_once();
  c = new_client(46, "ian", 1, REG_EXITS);
  f = fake_of(c);
  jwt_local_undecided = 1;
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  kc_mode = KC_INLINE_OK;
  assert_int_equal(authenticate(c, data), 0);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_int_equal(f->runs_inside_kc, 0);
  assert_false(f->freed);
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** Another client's pending answer delivered inside this client's request
 * call: the other client's registration does not run there either (the
 * handler holds pointers; registration exits and frees clients). */
static void another_clients_answer_inside_the_call(void **state)
{
  struct Client *a, *b;
  struct fake *fa, *fb;
  char data[300];

  sasl_init_once();
  a = new_client(47, "abe", 1, REG_EXITS);
  fa = fake_of(a);
  b = new_client(48, "ben", 0, REG_KEEPS);
  fb = fake_of(b);

  plain_b64("abe", "abepw", data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(a, "PLAIN"), 0);
  assert_int_equal(authenticate(a, data), 0);           /* a's grant pending */

  plain_b64("ben", "benpw", data);
  assert_int_equal(authenticate(b, "PLAIN"), 0);
  kc_mode = KC_REAP;
  reap_ok = 1;
  assert_int_equal(authenticate(b, data), 0);           /* reaps a's answer */
  assert_true(has_numeric(fa, RPL_SASLSUCCESS));
  assert_int_equal(fa->runs_inside_kc, 0);
  assert_false(fa->freed);
  run_event_loop();
  assert_true(fa->freed);
  assert_int_equal(fa->touched_after_free, 0);
  assert_false(fb->freed);
}

/** The review's chain: a client's pending SASL answer (here a refusal; on a
 * stalled Keycloak, the grant's timeout) delivered inside its own REGISTER
 * line's lookup.  REGISTER returns with the client alive; registration runs
 * from the event loop. */
static void register_reaps_pending_sasl_answer(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  c = new_client(49, "rex", 1, REG_EXITS);
  f = fake_of(c);
  plain_b64("rex", "rexpw", data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);           /* grant pending */

  kc_mode = KC_REAP;
  reap_ok = 0;
  assert_int_equal(register_line(c, "longpassword"), 0); /* lookup reaps it */
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_int_equal(f->runs_inside_kc, 0);
  assert_false(f->freed);
  assert_int_equal(f->touched_after_free, 0);
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);

  kc_mode = KC_LATER;
  pend_deliver(1);                 /* REGISTER's lookup: its client is gone */
  assert_int_equal(f->touched_after_free, 0);
}

/** The mirror: a pending REGISTER (the account created) delivered inside a
 * later AUTHENTICATE's request.  It leaves the check to the event loop, and
 * the AUTHENTICATE exchange's own hold keeps registration waiting. */
static void authenticate_reaps_pending_register_answer(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];

  sasl_init_once();
  c = new_client(50, "ray", 1, REG_EXITS);
  f = fake_of(c);
  kc_mode = KC_LATER;
  assert_int_equal(register_line(c, "longpassword"), 0); /* lookup pending */
  pend_deliver(0);                 /* not found: the create goes out */
  assert_false(f->freed);

  plain_b64("ray", "raypw", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  kc_mode = KC_REAP;
  reap_ok = 1;
  assert_int_equal(authenticate(c, data), 0);           /* reaps the create */
  assert_int_equal(f->runs_inside_kc, 0);
  assert_false(f->freed);
  run_event_loop();
  assert_false(f->freed);          /* the PLAIN exchange holds registration */

  kc_mode = KC_LATER;
  pend_deliver(0);                 /* the grant: refused */
  run_event_loop();
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** REGISTER from a client whose SASL login completed (903) but which has
 * not registered yet is refused: ALREADY_AUTHENTICATED, nothing asked of
 * Keycloak, the login left as it is.  Without that, REGISTER parked the
 * new account's name over the login while its Keycloak id stayed, and the
 * client registered under the new name with the old login's id. */
static void register_after_completed_login_is_refused(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];
  int requests;

  sasl_init_once();
  c = new_client(55, "liz", 0, REG_KEEPS);
  f = fake_of(c);
  plain_b64("liz", "lizpw", data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(1);                          /* 903: logged in as liz */
  run_event_loop();
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_false(IsAccount(c));               /* not registered yet */

  requests = kc_requests;
  assert_int_equal(register_line(c, "longpassword"), 0);
  assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
  assert_int_equal(kc_requests, requests);  /* nothing asked of Keycloak */
  assert_int_equal(cli_regcookie(c), 0);
  assert_string_equal(cli_saslaccount(c), "liz");
}

/** Logs nina in as liz (PLAIN, 903), then starts over with OAUTHBEARER: the one
 * re-authentication allowed after 903, which clears the SASL-complete
 * flag. */
static struct Client *login_then_restart(int fd)
{
  struct Client *c = new_client(fd, "nina", 0, REG_KEEPS);
  char data[300], pw[16];

  snprintf(pw, sizeof(pw), "lizpw%d", fd);   /* uncached: Keycloak answers */
  plain_b64("liz", pw, data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(1);
  run_event_loop();
  assert_true(IsSASLComplete(c));
  assert_string_equal(cli_saslaccount(c), "liz");
  assert_true(cli_saslkcid(c)[0] != '\0');      /* the grant's id */
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  return c;
}

/** Undoing a completed login undoes its identity with the flag: account,
 * timestamp, Keycloak id and its live mark, all of them. */
static void undoing_a_login_clears_its_identity(void **state)
{
  struct Client *c;

  sasl_init_once();
  c = login_then_restart(56);
  assert_false(IsSASLComplete(c));
  assert_string_equal(cli_saslaccount(c), "");
  assert_string_equal(cli_saslkcid(c), "");
  assert_int_equal(cli_saslkcidlive(c), 0);
  assert_int_equal(cli_saslacccreate(c), 0);
}

/** The review's sequence: login, a re-authentication abandoned (here
 * AUTHENTICATE *), then REGISTER -- allowed, nothing is logged in -- and
 * the new account carries its own identity (no id: the create answer has
 * none), never the abandoned login's id. */
static void register_after_undone_login_carries_no_old_id(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = login_then_restart(57);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "*"), 0);
  assert_int_equal(register_line(c, "longpassword"), 0);
  assert_string_equal(f->fail_code, "");
  pend_deliver(0);                          /* the lookup: name free */
  pend_deliver(1);                          /* the create: done */
  assert_true(IsSASLComplete(c));
  assert_string_equal(cli_saslaccount(c), "nina");  /* "*": the nick */
  assert_string_equal(cli_saslkcid(c), "");
  assert_int_equal(cli_saslkcidlive(c), 0);
  assert_int_equal(cli_saslacccreate(c), 0);
}

/* ------------------------------------------------------------------ */
/* Registering and authenticating in one connection flow               */
/* ------------------------------------------------------------------ */

/* draft/account-registration: after REGISTER SUCCESS the client is
 * "assumed to be authenticated to the <account> as if it used SASL"; with
 * e-mail verification on, REGISTER answers VERIFICATION_REQUIRED, the
 * server keeps nothing, and the user logs in with SASL once verified,
 * possibly on the same connection.  Each sequence runs before connection
 * registration (the identity registration will apply) and after it (the
 * user's own). */

/** A client that has finished connection registration, with no account. */
static struct Client *new_registered(int fd, const char *nick)
{
  struct Client *c = new_client(fd, nick, 1, REG_KEEPS);

  cli_auth(c) = NULL;
  cli_status(c) = STAT_USER;
  return c;
}

/** REGISTER answered: the lookup (the name is free) and the create; with
 * verification on also the lookup for the mail and the mail. */
static void register_through(struct Client *c, const char *account,
                             const char *email)
{
  kc_mode = KC_LATER;
  assert_int_equal(register_as(c, account, email, "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  pend_deliver_kind(P_RESULT, KC_SUCCESS);
  if (verify_email_on) {
    pend_deliver_kind(P_USER, KC_SUCCESS);
    pend_deliver_kind(P_RESULT, KC_SUCCESS);
  }
}

/** A PLAIN exchange for \a user, its grant left pending. */
static void plain_pending(struct Client *c, const char *user, const char *pw)
{
  char data[300];

  plain_b64(user, pw, data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
}

/** The identity \a c holds: before registration what registration will
 * apply (the SASL-complete flag and the login's fields), after it the
 * user's own.  A login's timestamp is 0 here: local logins stamp none. */
static void assert_identity(struct Client *c, const char *account,
                            const char *kc_id, int live)
{
  if (IsRegistered(c)) {
    assert_true(IsAccount(c));
    assert_string_equal(cli_user(c)->account, account);
    assert_string_equal(cli_user(c)->kc_id, kc_id);
    assert_int_equal(cli_user(c)->acc_create, 0);
  } else {
    assert_true(IsSASLComplete(c));
    assert_string_equal(cli_saslaccount(c), account);
    assert_string_equal(cli_saslkcid(c), kc_id);
    assert_int_equal(cli_saslkcidlive(c), live);
    assert_int_equal(cli_saslacccreate(c), 0);
  }
}

/** a. Verification off: REGISTER SUCCESS logs the client in as the new
 * account -- with no Keycloak id, the create answer has none -- and a
 * second REGISTER is ALREADY_AUTHENTICATED. */
static void flow_register_logs_in(void **state)
{
  static const char *const names[2][2] = { { "na1", "nx1" }, { "na2", "nx2" } };
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(61, "fa2") : new_client(60, "fa1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char want[64];
    int n;

    register_through(c, names[post][0], "*");
    snprintf(want, sizeof(want), "REGISTER SUCCESS %s", names[post][0]);
    assert_non_null(strstr(f->raw, want));
    assert_identity(c, names[post][0], "", 0);
    n = kc_requests;
    assert_int_equal(register_as(c, names[post][1], "*", "longpassword"), 0);
    assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
    assert_int_equal(kc_requests, n);
    if (!post) {                           /* CAP END: it registers */
      f->cap_done = 1;
      run_event_loop();
      assert_int_equal(f->registered, 1);
    }
  }
}

/** b. Verification on: VERIFICATION_REQUIRED keeps nothing; a SASL login to
 * the new account before the link is clicked fails with the verify-your-
 * email reply, can be retried, and then gives the account's own Keycloak
 * id, confirmed by Keycloak (a real login). */
static void flow_verify_then_sasl(void **state)
{
  static const char *const names[2] = { "nb1", "nb2" };
  int post;

  sasl_init_once();
  verify_email_on = 1;
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(63, "fb2") : new_client(62, "fb1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char want[64], id[ACCOUNT_ID_LEN + 1];

    register_through(c, names[post], "user@example.test");
    snprintf(want, sizeof(want), "REGISTER VERIFICATION_REQUIRED %s", names[post]);
    assert_non_null(strstr(f->raw, want));
    assert_false(IsSASLComplete(c));
    assert_false(IsAccount(c));
    assert_string_equal(cli_saslaccount(c), "");

    plain_pending(c, names[post], "verifypw");
    pend_deliver_kind(P_TOKEN, KC_UNVERIFIED);      /* not verified yet */
    assert_string_equal(f->fail_code, "VERIFICATION_REQUIRED");
    assert_true(has_numeric(f, ERR_SASLFAIL));
    assert_null(cli_saslsession(c));
    assert_false(IsSASLComplete(c));

    plain_pending(c, names[post], "verifypw");      /* the link clicked */
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    assert_true(has_numeric(f, RPL_SASLSUCCESS));
    assert_identity(c, names[post], user_id(names[post], id), 1);
  }
}

/** c. Verification on, and the client gives up on the new account and
 * logs in to another, existing one: that account's identity, nothing of
 * the REGISTER. */
static void flow_verify_then_other_account(void **state)
{
  int post;

  sasl_init_once();
  verify_email_on = 1;
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(65, "fc2") : new_client(64, "fc1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1];

    register_through(c, post ? "nc2" : "nc1", "user@example.test");
    assert_non_null(strstr(f->raw, "REGISTER VERIFICATION_REQUIRED"));
    plain_pending(c, post ? "cal2" : "cal1", "calpw");
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    assert_true(has_numeric(f, RPL_SASLSUCCESS));
    assert_identity(c, post ? "cal2" : "cal1", user_id(post ? "cal2" : "cal1", id), 1);
  }
}

/* d. The overlaps, deliberate (no exclusion: the spec lets a client
 * register and authenticate in one flow and says nothing of overlap), the
 * identity whole in every outcome. */

/** REGISTER's answer lands while a SASL exchange is in flight, which then
 * succeeds: the SASL account with its id. */
static void flow_register_answer_mid_sasl_then_success(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(67, "fd2") : new_client(66, "fd1", 0, REG_KEEPS);
    char id[ACCOUNT_ID_LEN + 1];
    const char *acct = post ? "nd2" : "nd1", *user = post ? "dan2" : "dan1";

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);        /* the create goes out */
    plain_pending(c, user, "danpw");
    pend_deliver_kind(P_RESULT, KC_SUCCESS);        /* REGISTER SUCCESS */
    assert_identity(c, acct, "", 0);
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);         /* then 903 */
    assert_identity(c, user, user_id(user, id), 1);
  }
}

/** ... which then fails: the REGISTER account, no id. */
static void flow_register_answer_mid_sasl_then_failure(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(69, "fe2") : new_client(68, "fe1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    const char *acct = post ? "ne2" : "ne1";

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    plain_pending(c, post ? "eve2" : "eve1", "evepw-bad");
    pend_deliver_kind(P_RESULT, KC_SUCCESS);
    pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);       /* 904 */
    assert_true(has_numeric(f, ERR_SASLFAIL));
    assert_identity(c, acct, "", 0);
  }
}

/** SASL finishes before REGISTER's answer.  Before registration the
 * REGISTER account replaces the login (its answer is the later success);
 * after registration the login stays and REGISTER's answer is dropped
 * without a reply (register_complete_success() on an account holder). */
static void flow_sasl_then_register_answer(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(71, "fg2") : new_client(70, "fg1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1];
    const char *acct = post ? "ng2" : "ng1", *user = post ? "gus2" : "gus1";

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    plain_pending(c, user, "guspw");
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);         /* 903 first */
    assert_identity(c, user, user_id(user, id), 1);
    pend_deliver_kind(P_RESULT, KC_SUCCESS);        /* then REGISTER's */
    if (post) {
      assert_identity(c, user, id, 1);
      assert_null(strstr(f->raw, "REGISTER"));
    } else {
      assert_non_null(strstr(f->raw, "REGISTER SUCCESS"));
      assert_identity(c, acct, "", 0);
    }
  }
}

/* ------------------------------------------------------------------ */
/* A request that cannot be started                                    */
/* ------------------------------------------------------------------ */

/** A Keycloak request libkc refuses to start (it never calls back) fails
 * the exchange at once -- ERR_SASLFAIL, the exchange gone -- instead of
 * leaving it to the SASL timeout; registration goes on there, in the
 * line, with the result to the parser. */
static void refused_request_fails_at_once(void **state)
{
  static const char *const mechs[4] = {
    "PLAIN", "EXTERNAL", "SCRAM-SHA-256", "ECDSA-NIST256P-CHALLENGE"
  };
  int m, keeps;

  sasl_init_once();
  for (keeps = 0; keeps < 2; keeps++)
    for (m = 0; m < 4; m++) {
      struct Client *c = new_client(51 + m, "rae", 1,
                                    keeps ? REG_KEEPS : REG_EXITS);
      struct fake *f = fake_of(c);
      char data[300];
      int requests;

      ircd_strncpy(cli_sslclifp(c), "ab12cd34", sizeof(cli_sslclifp(c)));
      kc_mode = KC_LATER;
      assert_int_equal(authenticate(c, mechs[m]), 0);
      if (m == 0)
        plain_b64("rae", keeps ? "raepw2" : "raepw", data);
      else if (m == 1)
        strcpy(data, "+");
      else if (m == 2)
        b64((const unsigned char *)"n,,n=rae,r=nonce", 16, data);
      else
        b64((const unsigned char *)"rae", 3, data);
      kc_mode = KC_REFUSE;
      requests = kc_requests;
      assert_int_equal(authenticate(c, data), keeps ? 0 : CPTR_KILLED);
      assert_int_equal(kc_requests, requests + 1);
      assert_int_equal(pend[0].kind, P_NONE);        /* nothing to answer */
      if (keeps) {
        assert_true(has_numeric(f, ERR_SASLFAIL));
        assert_null(cli_saslsession(c));
        assert_int_equal(cli_saslcookie(c), 0);
        assert_int_equal(f->registered, 1);
      } else {
        assert_true(f->freed);
        assert_int_equal(f->touched_after_free, 0);
      }
    }
}
#endif /* USE_LIBKC */

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(complete_login_holds_registration_to_its_end, setup),
    cmocka_unit_test_setup(complete_login_keeps, setup),
#ifdef USE_LIBKC
    cmocka_unit_test_setup(poscache_hit_registration_exits, setup),
    cmocka_unit_test_setup(poscache_hit_registration_keeps, setup),
    cmocka_unit_test_setup(negcache_hit_registration_exits, setup),
    cmocka_unit_test_setup(oauthbearer_local_check_registration_exits, setup),
    cmocka_unit_test_setup(ecdsa_response_registration_exits, setup),
    cmocka_unit_test_setup(scram_ack_registration_exits, setup),
    cmocka_unit_test_setup(star_abort_registration_exits, setup),
    cmocka_unit_test_setup(bad_base64_abort_registration_exits, setup),
    cmocka_unit_test_setup(failed_state_abort_registration_exits, setup),
    cmocka_unit_test_setup(later_answer_registers_from_the_event_loop, setup),
    cmocka_unit_test_setup(inline_failure_registers_from_the_event_loop, setup),
    cmocka_unit_test_setup(inline_success_registers_from_the_event_loop, setup),
    cmocka_unit_test_setup(inline_lookup_failures_register_from_the_event_loop, setup),
    cmocka_unit_test_setup(inline_external_registers_from_the_event_loop, setup),
    cmocka_unit_test_setup(inline_introspection_registers_from_the_event_loop, setup),
    cmocka_unit_test_setup(another_clients_answer_inside_the_call, setup),
    cmocka_unit_test_setup(register_reaps_pending_sasl_answer, setup),
    cmocka_unit_test_setup(authenticate_reaps_pending_register_answer, setup),
    cmocka_unit_test_setup(refused_request_fails_at_once, setup),
    cmocka_unit_test_setup(register_after_completed_login_is_refused, setup),
    cmocka_unit_test_setup(undoing_a_login_clears_its_identity, setup),
    cmocka_unit_test_setup(register_after_undone_login_carries_no_old_id, setup),
    cmocka_unit_test_setup(flow_register_logs_in, setup),
    cmocka_unit_test_setup(flow_verify_then_sasl, setup),
    cmocka_unit_test_setup(flow_verify_then_other_account, setup),
    cmocka_unit_test_setup(flow_register_answer_mid_sasl_then_success, setup),
    cmocka_unit_test_setup(flow_register_answer_mid_sasl_then_failure, setup),
    cmocka_unit_test_setup(flow_sasl_then_register_answer, setup),
#endif
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
