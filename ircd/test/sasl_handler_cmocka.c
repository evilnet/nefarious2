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
#include "handlers.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numeric.h"
#include "register_throttle.h"
#include "s_auth.h"
#include "s_bsd.h"
#include "s_misc.h"
#include "s_user.h"
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
  char warn[160];             /**< the last WARN sent to it */
  char fail_context[64];      /**< that FAIL's context parameter */
  char fail_desc[200];        /**< that FAIL's description */
  char saslfail[200];         /**< the reason of the last ERR_SASLFAIL */
  char loggedin_as[32];       /**< the account the last 900 named */
  char exit_reason[64];       /**< why it was closed (registration's check
                                   or exit_client()), "" while open */
};

/** What a login announces beyond the client itself: the aliases told, the
 * network told (AC), the channels told (account-notify), and the rest of
 * step 7.  A re-authentication that is refused changes none of them. */
struct effects {
  int alias_updates;          /**< bounce_emit_alias_update() */
  int alias_syncs;            /**< bounce_sync_alias_identity() */
  int adopts;                 /**< bounce_session_adopt_kc_id() */
  int broadcasts;             /**< sendcmdto_serv_butone(): AC */
  int notifies;               /**< account-notify to common channels */
  int metadata_loads;         /**< metadata_load_account() */
  int mode_syncs;             /**< metadata_mode_sync_restore() */
  int hostmasks;              /**< hide_hostmask() */
  int account_adjusts;        /**< channel_account_adjust() */
  int anchors;                /**< presence_anchor_transfer() */
  int oper_notices;           /**< sendto_opmask_butone_ratelimited(): sent */
  int oper_notices_tried;     /**< ... called */
};
static struct effects fx;

/** A bouncer session for the cases that need one: its members (a primary
 * and aliases) and the Keycloak id it is bound to. */
static struct fake_session {
  struct Client *members[4];
  char kc_id[ACCOUNT_ID_LEN + 1];
} fsess;

#define NFAKE 8
static struct fake fakes[NFAKE];
static int in_kc_call;        /**< a libkc request call is running */
static int in_login;          /**< inside sasl_complete_login() (test 1) */
static int local_off;         /**< SASL_LOCAL off: the services (P10) tier */

/* What a login completion does, in order: the lines it sends the client
 * and the network and the calls it makes, one entry each (tlog_add()).
 * Cleared before a completion, compared after it. */
#define TLOG_MAX 48
#define TLOG_LEN 200
static char tlog[TLOG_MAX][TLOG_LEN];
static int ntlog;

static void tlog_add(const char *fmt, ...)
{
  va_list vl;
  if (ntlog >= TLOG_MAX)
    fail_msg("transcript full");
  va_start(vl, fmt);
  vsnprintf(tlog[ntlog++], TLOG_LEN, fmt, vl);
  va_end(vl);
}

static const char *tname(const struct Client *cptr);

/** The ircd's send patterns, formatted the way the ircd would: %C is a
 * client (its name), %Tu a time_t; %s %c %d %u as usual. */
static void fmt_ircd(char *buf, size_t size, const char *pattern, va_list vl)
{
  size_t n = 0;
  const char *p;

  for (p = pattern; *p && n + 1 < size; p++) {
    char tmp[64];
    const char *s = tmp;

    if (*p != '%') {
      buf[n++] = *p;
      continue;
    }
    switch (*++p) {
    case 'C': {
      struct Client *c = va_arg(vl, struct Client *);
      s = c ? tname(c) : "(null)";
      break;
    }
    case 'T':                                   /* %Tu */
      if (p[1] == 'u')
        p++;
      snprintf(tmp, sizeof(tmp), "%lu", (unsigned long)va_arg(vl, time_t));
      break;
    case 's':
      s = va_arg(vl, const char *);
      if (!s)
        s = "(null)";
      break;
    case 'c':
      tmp[0] = (char)va_arg(vl, int);
      tmp[1] = '\0';
      break;
    case 'd':
      snprintf(tmp, sizeof(tmp), "%d", va_arg(vl, int));
      break;
    case 'u':
      snprintf(tmp, sizeof(tmp), "%u", va_arg(vl, unsigned int));
      break;
    case '%':
      strcpy(tmp, "%");
      break;
    default:
      fail_msg("pattern \"%s\": no fake for %%%c", pattern, *p);
      return;
    }
    while (*s && n + 1 < size)
      buf[n++] = *s++;
  }
  buf[n] = '\0';
}

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

/** \a cptr's name for a transcript entry; a client registration freed is
 * poisoned, so it is not read. */
static const char *tname(const struct Client *cptr)
{
  struct fake *f = fake_of(cptr);
  return (f && f->freed) ? "(freed)" : cli_name(cptr);
}

/** A connecting client on \a fd, past NICK and USER, CAP sasl active.  It
 * sent CAP LS 302, as the bed's clients do: SASL 3.2, re-authentication
 * included (the SASL 3.1 cases below lower the version themselves). */
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
  cli_capab_version(&f->cli) = CAP_VERSION_302;
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
  /* SASL_MAX_FAILURES reached before registration: the check closes the
   * connection, whatever else it waits for (check_auth_finished()). */
  if (con_sasl_limited(&f->con) && !f->hold) {   /* not under an exchange's hold */
    ircd_strncpy(f->exit_reason, "Too many SASL failures", sizeof(f->exit_reason));
    LocalClientArray[f->fd] = NULL;
    f->freed = 1;
    memset(&f->cli, 0xA5, sizeof(f->cli));
    memset(&f->con, 0xA5, sizeof(f->con));
    memset(&f->user, 0xA5, sizeof(f->user));
    return CPTR_KILLED;
  }
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
  tlog_add("iauth R %s", account);      /* both forms tell IAuth the same */
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
  tlog_add("iauth R %s", account);
  fake_of_auth(auth)->recheck_queued = 1;
}

/* The IAuth tier, off unless a test turns it on: the lines that would go
 * to the program, counted. */
static int iauth_on, iauth_starts, iauth_datas, iauth_aborts;
int auth_iauth_handles_sasl(void) { return iauth_on; }
int auth_send_sasl_start(struct Client *c, const char *m, const char *f)
{ if (iauth_on) iauth_starts++; return iauth_on; }
/** The address the IAuth tier was told when an exchange started. */
static char iauth_host_ip[64];
int auth_send_sasl_host(struct Client *c, const char *u, const char *h, const char *i)
{ ircd_strncpy(iauth_host_ip, i, sizeof(iauth_host_ip)); return iauth_on; }
int auth_send_sasl_data(struct Client *c, const char *d)
{ if (iauth_on) iauth_datas++; return iauth_on; }
int auth_send_sasl_abort(struct Client *c)
{ if (iauth_on) iauth_aborts++; return iauth_on; }
int auth_iauth_sasl_fail(struct Client *c) { return 0; }

/* m_sasl.c: the end of a services exchange, as the real one leaves the
 * client (EndSASLExchange(), the hold), and the reply it was asked for
 * (-1: not called). */
static int abort_reply = -1;
int abort_sasl(struct Client *cptr, int timeout)
{
  touch(cptr);
  if (!cli_saslcookie(cptr) || IsSASLExchangeDone(cptr))
    return 0;
  abort_reply = timeout;
  EndSASLExchange(cptr);
  if (cli_auth(cptr))
    auth_sasl_clear(cli_auth(cptr));
  return 0;
}

/* labeled-response, as send.c does it: a line answering a labeled command
 * carries its label once (the first line), unless the command opened a
 * labeled-response batch (labeled_batch_start()), whose lines carry the
 * batch.  The transcript notes the label a line went out with. */
static const char *label_take(struct Client *to)
{
  struct fake *f = fake_of(to);
  if (!f || f->freed || cli_labeled_batch(to))
    return "";
  if (cli_label(to)[0] && !cli_label_responded(to)) {
    cli_label_responded(to) = 1;
    return cli_label(to);
  }
  return "";
}

static void tlog_label(const char *label)
{
  if (label[0] && ntlog > 0) {
    size_t n = strlen(tlog[ntlog - 1]);
    snprintf(tlog[ntlog - 1] + n, TLOG_LEN - n, " [label=%s]", label);
  }
}

int labeled_batch_start(struct Client *sptr)
{
  if (!cli_label(sptr)[0])
    return 0;
  tlog_add("BATCH + labeled-response %s [label=%s]", tname(sptr), cli_label(sptr));
  cli_label_responded(sptr) = 1;
  ircd_strncpy(cli_connect(sptr)->con_batch[0].id, "lrb",
               sizeof(cli_connect(sptr)->con_batch[0].id));
  cli_connect(sptr)->con_batch[0].parent[0] = '\0';
  cli_connect(sptr)->con_batch_depth = 1;
  cli_labeled_batch(sptr) = 1;
  return 1;
}

/* send.c's batch_save()/batch_restore(): set the open batches aside for
 * an asynchronous answer and put them back. */
void batch_save(struct Client *to, struct BatchSave *save)
{
  struct Connection *con = cli_connect(to);
  memcpy(save->frames, con->con_batch, sizeof(save->frames));
  save->depth = con->con_batch_depth;
  save->over = con->con_batch_over;
  save->labeled = con->con_labeled_batch;
  con->con_batch_depth = con->con_batch_over = con->con_labeled_batch = 0;
}

void batch_restore(struct Client *to, const struct BatchSave *save)
{
  struct Connection *con = cli_connect(to);
  memcpy(con->con_batch, save->frames, sizeof(con->con_batch));
  con->con_batch_depth = save->depth;
  con->con_batch_over = save->over;
  con->con_labeled_batch = save->labeled;
}

/* send.c's batch_current_id(): the innermost open batch. */
const char *batch_current_id(struct Client *cli)
{
  struct Connection *con = cli_connect(cli);
  return con->con_batch_depth ? con->con_batch[con->con_batch_depth - 1].id : "";
}

void labeled_batch_end(struct Client *sptr)
{
  if (!cli_labeled_batch(sptr))
    return;
  tlog_add("BATCH - %s", tname(sptr));
  cli_labeled_batch(sptr) = 0;
  cli_connect(sptr)->con_batch_depth = 0;
}

/* The send layer: records what reaches a client. */
int send_reply(struct Client *to, int reply, ...)
{
  struct fake *f = fake_of(to);
  va_list vl;
  touch(to);
  if (f && !f->freed && f->n_numerics < 16)
    f->numerics[f->n_numerics++] = reply & ~SND_EXPLICIT;
  if ((reply & ~SND_EXPLICIT) == RPL_LOGGEDIN) {
    const char *nick, *user, *host, *account;
    va_start(vl, reply);
    nick = va_arg(vl, const char *);
    user = va_arg(vl, const char *);
    host = va_arg(vl, const char *);
    account = va_arg(vl, const char *);
    va_end(vl);
    tlog_add("900 %s %s!%s@%s %s", tname(to), nick, user, host, account);
    if (f && !f->freed)
      ircd_strncpy(f->loggedin_as, account, sizeof(f->loggedin_as));
  } else
    tlog_add("%03d %s", reply & ~SND_EXPLICIT, tname(to));
  tlog_label(label_take(to));
  if (f && !f->freed && (reply & ~SND_EXPLICIT) == ERR_SASLFAIL) {
    const char *reason;
    va_start(vl, reply);
    reason = va_arg(vl, const char *);
    va_end(vl);
    ircd_strncpy(f->saslfail, reason ? reason : "", sizeof(f->saslfail));
  }
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
    tlog_add("raw %s %s", tname(to), f->raw);
  }
}

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  struct fake *f = fake_of(to);
  touch(to);
  if (f && !f->freed) {
    ircd_strncpy(f->fail_code, code, sizeof(f->fail_code));
    ircd_strncpy(f->fail_context, context ? context : "", sizeof(f->fail_context));
    ircd_strncpy(f->fail_desc, description ? description : "", sizeof(f->fail_desc));
  }
  tlog_add("FAIL %s %s %s", command, code, context ? context : "");
  tlog_label(label_take(to));
}
void send_warn(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  struct fake *f = fake_of(to);
  touch(to);
  if (f && !f->freed)
    snprintf(f->warn, sizeof(f->warn), "%s %s %s :%s", command, code,
             context ? context : "", description);
  tlog_add("WARN %s %s %s", command, code, context ? context : "");
  tlog_label(label_take(to));
}
void sendrawto_one_tags(struct Client *to, const char *pattern, ...)
{
  struct fake *f = fake_of(to);
  char buf[TLOG_LEN];
  va_list vl;
  touch(to);
  va_start(vl, pattern);
  fmt_ircd(buf, sizeof(buf), pattern, vl);
  va_end(vl);
  if (f && !f->freed) {
    ircd_strncpy(f->raw, buf, sizeof(f->raw));
    tlog_add("raw %s %s", tname(to), f->raw);
    tlog_label(label_take(to));
  }
}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{ touch(to); }
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{
  char buf[TLOG_LEN];
  va_list vl;
  touch(from);
  fx.broadcasts++;
  va_start(vl, pattern);
  fmt_ircd(buf, sizeof(buf), pattern, vl);
  va_end(vl);
  tlog_add("servers %s %s", tok, buf);
}
/* account-notify sends (#220): about whom, and whether that user's own
 * connections were among the recipients (the walk with one == from leaves
 * the user out; the session form includes it).  Both forms also count as
 * fx.notifies, so "nothing announced" covers the user itself. */
static struct Client *an_about[16];
static int an_self[16];
static int n_an;
static void an_record(struct Client *from, int cap, int self)
{
  if (cap != CAP_ACCNOTIFY || n_an >= 16)
    return;
  an_about[n_an] = from;
  an_self[n_an++] = self;
}
void sendcmdto_common_channels_capab_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Client *one, int require,
                                            int forbid, const char *pattern, ...)
{
  char buf[TLOG_LEN];
  va_list vl;
  touch(from);
  fx.notifies++;
  an_record(from, require, one != from);
  va_start(vl, pattern);
  fmt_ircd(buf, sizeof(buf), pattern, vl);
  va_end(vl);
  tlog_add("channels %s %s %s", tname(from), cmd, buf);
}
void sendcmdto_common_channels_capab_session(struct Client *from,
                                             const char *cmd, const char *tok,
                                             int require, const char *pattern, ...)
{
  char buf[TLOG_LEN];
  va_list vl;
  touch(from);
  fx.notifies++;
  an_record(from, require, 1);
  va_start(vl, pattern);
  fmt_ircd(buf, sizeof(buf), pattern, vl);
  va_end(vl);
  tlog_add("channels %s %s %s", tname(from), cmd, buf);
}
/* The oper notice: rate-limited as the real one is (once per 30 s per
 * rate); tried counts every call, oper_notices the ones sent. */
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
                                      time_t *rate, const char *pattern, ...)
{
  fx.oper_notices_tried++;
  if (CurrentTime - *rate < 30)
    return;
  *rate = CurrentTime;
  fx.oper_notices++;
}
void send_cap_notify(const char *capname, int available, const char *value) {}
void cap_set_value(enum Capab cap, const char *value) {}
int need_more_params(struct Client *cptr, const char *cmd) { touch(cptr); return 0; }
int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{
  struct fake *f = fake_of(victim);
  touch(victim);
  if (f && !f->freed)
    ircd_strncpy(f->exit_reason, comment, sizeof(f->exit_reason));
  return cptr == victim ? CPTR_KILLED : 0;
}
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
static int bed_features;      /**< the bed's account and host-hiding features:
                                   EXTENDED_ACCOUNTS, SASL_AUTOHIDEHOST and
                                   HOST_HIDING_STYLE 1 (off: all three 0) */

static int sendhost_on;     /**< FEAT_SASL_SENDHOST */
/** FEAT_SASL_REAUTH.  The cases written before the setting existed pin
 * what is now "refresh" (setup()); the setting's own cases set it. */
static const char *reauth_setting = "refresh";
/** FEAT_SASL_MAX_FAILURES; 0 (no limit) unless a case sets it. */
static int max_failures;
/* N067: the account change's event -- the msgid armed for its
 * account-notify lines, and the one armed for its AC relay. */
static int msgid_on;

void sendcmdto_set_client_event(const char *msgid, uint64_t event_ms)
{
  (void)event_ms;
  tlog_add("event %s", msgid ? msgid : "-");
}

void sendcmdto_set_client_msgid(const char *msgid)
{
  if (msgid)
    tlog_add("event %s", msgid);
}

void sendcmdto_set_s2s_tags(uint64_t time_ms, const char *msgid)
{
  (void)time_ms;
  tlog_add("s2s %s", msgid ? msgid : "-");
}

void sendcmdto_want_s2s_tags(int want)
{
  (void)want;
}

char *generate_msgid(char *buf, size_t buflen)
{
  ircd_strncpy(buf, "ABAAAAAAEVENT1", buflen);
  return buf;
}

uint64_t history_event_time_ms(struct Client *link)
{
  (void)link;
  return 1763000000000ULL;
}

int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_MSGID:
    return msgid_on;
  case FEAT_REGISTER_VERIFY_EMAIL:
    return verify_email_on;
  case FEAT_EXTENDED_ACCOUNTS:
  case FEAT_SASL_AUTOHIDEHOST:
    return bed_features;
  case FEAT_SASL_LOCAL:
    return !local_off;
  case FEAT_SASL_SENDHOST:
    return sendhost_on;
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
  case FEAT_SASL_MAX_FAILURES: return max_failures;
  case FEAT_SASL_NEGCACHE_TTL: return 60;
  case FEAT_SASL_POSCACHE_TTL: return 300;
  case FEAT_HOST_HIDING_STYLE: return bed_features ? 1 : 0;
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
  case FEAT_SASL_REAUTH: return reauth_setting;
  default: return "";
  }
}

/* Timers: nothing fires in this world. */
/* Timers: nothing fires unless a case fires one (fire_timer()); an armed
 * timer is active until deleted, as in the server. */
#define NTIMERS 16
static struct { struct Timer *t; EventCallBack cb; } timers[NTIMERS];
struct Timer *timer_init(struct Timer *timer) { memset(timer, 0, sizeof(*timer)); return timer; }
void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{
  int i, free_slot = -1;
  for (i = 0; i < NTIMERS; i++) {
    if (timers[i].t == timer)
      break;
    if (!timers[i].t && free_slot < 0)
      free_slot = i;
  }
  if (i == NTIMERS)
    i = free_slot;
  assert_true(i >= 0);
  timers[i].t = timer;
  timers[i].cb = call;
  t_data(timer) = data;
  timer->t_header.gh_flags |= GEN_ACTIVE;
}
void timer_del(struct Timer *timer) { timer->t_header.gh_flags &= ~GEN_ACTIVE; }

/** The armed \a timer expires: its callback runs with ET_EXPIRE. */
static void fire_timer(struct Timer *timer)
{
  struct Event ev;
  int i;

  assert_true(t_active(timer));
  for (i = 0; i < NTIMERS && timers[i].t != timer; i++)
    ;
  assert_true(i < NTIMERS);
  timer->t_header.gh_flags &= ~GEN_ACTIVE;
  memset(&ev, 0, sizeof(ev));
  ev.ev_type = ET_EXPIRE;
  ev.ev_gen.gen_timer = timer;
  timers[i].cb(&ev);
}
void free_connection(struct Connection *con) {}

/* Logging */
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
void debug(int level, const char *form, ...) {}

/* Everything else a login or a REGISTER reaches, none of which matters
 * here. */
struct Client *find_match_server(char *mask) { return NULL; }
unsigned int ircrandom(void) { static unsigned int r = 12345; return r += 7919; }
/* The bouncer: a client is in the fake session when the case put it there;
 * bounce_rebind_kc_conflict() is the real one (bouncer_rebind_auth.o). */
struct BouncerSession *bounce_get_session(struct Client *cptr)
{
  int i;
  touch(cptr);
  for (i = 0; i < 4; i++)
    if (fsess.members[i] && fsess.members[i] == cptr)
      return (struct BouncerSession *)&fsess;
  return NULL;
}
/* bounce_client_in_session(): every session, whatever its account -- the
 * fake session's members, and a client a case files in a session that
 * bounce_get_session() cannot find through the client's account (a
 * primary services renamed: the session stays under the old name). */
static struct Client *in_session_too;
int bounce_client_in_session(struct Client *cptr)
{
  int i;
  touch(cptr);
  if (cptr && cptr == in_session_too)
    return 1;
  for (i = 0; i < 4; i++)
    if (fsess.members[i] && fsess.members[i] == cptr)
      return 1;
  return 0;
}
const char *bounce_session_kc_id(struct BouncerSession *s)
{ return s ? ((struct fake_session *)s)->kc_id : ""; }
void bounce_session_adopt_kc_id(struct BouncerSession *s, const char *id) { fx.adopts++; }
int bounce_account_kc_conflict(const char *account, const char *kc_id) { return 0; }
void bounce_emit_alias_update(struct Client *primary, const char *field,
                              const char *value)
{ touch(primary); fx.alias_updates++; tlog_add("alias update %s %s %s", tname(primary), field, value); }
void bounce_sync_alias_identity(struct Client *primary)
{ touch(primary); fx.alias_syncs++; tlog_add("alias sync %s", tname(primary)); }
/* channel.c: a member's cached ban verdicts forgotten. */
void member_ban_cache_clear(struct Client *cptr)
{ touch(cptr); tlog_add("ban cache %s", tname(cptr)); }
void channel_account_adjust(struct Client *cptr, int delta)
{ touch(cptr); fx.account_adjusts++; tlog_add("channel account count %s %+d", tname(cptr), delta); }
/* An account change's presence move: a switch carries nothing. */
void presence_anchor_move(struct Client *cptr, const char *old_anchor,
                          int old_is_session, const char *new_anchor,
                          int new_is_session, int carry)
{
  touch(cptr);
  fx.anchors++;
  tlog_add("presence %s %s/%d -> %s/%d%s", tname(cptr), old_anchor,
           old_is_session, new_anchor, new_is_session,
           carry ? "" : " (no carry)");
}
void presence_anchor_transfer(struct Client *cptr, const char *old_anchor,
                              int old_is_session, const char *new_anchor,
                              int new_is_session)
{
  touch(cptr);
  fx.anchors++;
  tlog_add("presence %s %s/%d -> %s/%d", tname(cptr), old_anchor,
           old_is_session, new_anchor, new_is_session);
}
int hide_hostmask(struct Client *cptr)
{ touch(cptr); fx.hostmasks++; tlog_add("hide_hostmask %s", tname(cptr)); return 0; }
void metadata_load_account(struct Client *cptr, const char *account)
{ touch(cptr); fx.metadata_loads++; tlog_add("metadata load %s %s", tname(cptr), account); }
void metadata_mode_sync_restore(struct Client *cptr, int live)
{ touch(cptr); fx.mode_syncs++; tlog_add("mode restore %s %d", tname(cptr), live); }
void metadata_mode_sync_rederive(struct Client *cptr)
{ touch(cptr); fx.mode_syncs++; tlog_add("mode rederive %s", tname(cptr)); }
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
static char next_user[32];            /**< the user the request being made
                                           names (a grant's, a lookup's,
                                           a create's) */
static int grant_has_id;              /**< a grant's ID token carries a sub */
static int create_names_id;           /**< a create's answer names the new
                                           user (its Location header) */
static const char *lookup_user;       /**< a lookup by name answers this
                                           user instead (NULL: that name) */
static const char *lookup_id;         /**< ... with this id (NULL: its own) */

/** An answer libkc owes (one request at a time is enough here).  P_CREATED
 * is REGISTER's account create; P_RESULT any other plain result. */
enum pend_kind { P_NONE, P_TOKEN, P_USER, P_USERS, P_INTRO, P_RESULT, P_CREATED };
struct pending {
  enum pend_kind kind;
  void *cb;
  void *data;
  char user[32];        /**< the user the request names: a grant's ID token,
                             a lookup's answer */
};
#define NPEND 4
static struct pending pend[NPEND];

static const char *TEST_SUB = "1b4e28ba-2fa1-11d2-883f-0016d3cca427";
static void user_sub(const char *user, char *out, size_t size);

/** Whose token the client's OAUTHBEARER line carries, as each validation
 * strategy reads it: the local check (kc_jwt_validate_local()) and the
 * introspection answer.  A sub of NULL is a token without one. */
static char *jwt_user, *jwt_sub;
static char *intro_user, *intro_sub;
static char tok_user[32], tok_sub[40];
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
  char idt[64], sub[40];
  int ok = (res == KC_SUCCESS);

  assert_int_not_equal(p.kind, P_NONE);
  memmove(pend + i, pend + i + 1, sizeof(pend) - (i + 1) * sizeof(pend[0]));
  memset(&pend[NPEND - 1], 0, sizeof(pend[0]));

  memset(&tok, 0, sizeof(tok));
  tok.access_token = "user-token";
  snprintf(idt, sizeof(idt), "hdr.%s.sig", p.user[0] ? p.user : "payload");
  tok.id_token = idt;
  memset(&user, 0, sizeof(user));
  if (p.user[0]) {                 /* a lookup by name answers that user */
    user_sub(p.user, sub, sizeof(sub));
    user.id = lookup_id ? (char *)lookup_id : sub;
    user.username = lookup_user ? (char *)lookup_user : p.user;
  } else {
    user.id = (char *)TEST_SUB;
    user.username = "who";
  }
  user.ecdsa_pubkey = user_pem[0] ? user_pem : NULL;
  if (scram_salt[0]) {
    user.scram_salt = scram_salt;
    user.scram_iterations = scram_iters;
    user.scram_stored_key = scram_stored;
    user.scram_server_key = scram_server;
  }
  memset(&info, 0, sizeof(info));
  info.active = true;
  info.username = intro_user;
  info.sub = intro_sub;

  switch (p.kind) {
  case P_TOKEN:
    ((kc_token_cb)p.cb)(ok ? KC_SUCCESS : res == KC_ERROR ? KC_FORBIDDEN : res,
                        ok ? &tok : NULL, p.data);
    break;
  case P_USER:
    ((kc_user_cb)p.cb)(ok ? KC_SUCCESS : res == KC_ERROR ? KC_NOT_FOUND : res,
                       ok ? &user : NULL, p.data);
    break;
  case P_USERS:
    ((kc_users_cb)p.cb)(ok ? KC_SUCCESS : KC_NOT_FOUND, ok ? &user : NULL,
                        ok ? 1 : 0, p.data);
    break;
  case P_INTRO:
    ((kc_introspect_cb)p.cb)(ok ? KC_SUCCESS : res == KC_ERROR ? KC_FORBIDDEN : res,
                             ok ? &info : NULL, p.data);
    break;
  case P_RESULT:
    ((kc_result_cb)p.cb)(ok ? KC_SUCCESS : KC_ERROR, p.data);
    break;
  case P_CREATED:                  /* the id: the user's, as grants give it */
    user_sub(p.user, sub, sizeof(sub));
    ((kc_create_cb)p.cb)(res, ok && create_names_id ? sub : NULL, p.data);
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
  {
    int i;
    for (i = NPEND - 1; i >= 0; i--)
      if (pend[i].kind == kind && pend[i].data == data) {
        ircd_strncpy(pend[i].user, next_user, sizeof(pend[i].user));
        break;
      }
  }
  next_user[0] = '\0';
  if (kc_mode == KC_INLINE_OK || kc_mode == KC_INLINE_FAIL)
    pend_deliver(kc_mode == KC_INLINE_OK);
  in_kc_call--;
  return 0;
}

int kc_user_verify_password(const char *username, const char *password,
                            kc_token_cb cb, void *data)
{
  ircd_strncpy(next_user, username, sizeof(next_user));
  return kc_request(P_TOKEN, (void *)cb, data);
}
int kc_user_get(const char *username, kc_user_cb cb, void *data)
{
  ircd_strncpy(next_user, username, sizeof(next_user));
  return kc_request(P_USER, (void *)cb, data);
}
int kc_user_search(const char *query, bool exact, kc_users_cb cb, void *data)
{ return kc_request(P_USERS, (void *)cb, data); }
int kc_token_introspect(const char *token, kc_introspect_cb cb, void *data)
{ return kc_request(P_INTRO, (void *)cb, data); }
int kc_user_create_full(const struct kc_user_create_req *req,
                        kc_create_cb cb, void *data)
{
  ircd_strncpy(next_user, req->username, sizeof(next_user));
  return kc_request(P_CREATED, (void *)cb, data);
}
static char mail_id[64];              /**< the user the last mail went to */
int kc_user_send_verify_email(const char *id, kc_result_cb cb, void *data)
{
  ircd_strncpy(mail_id, id, sizeof(mail_id));
  return kc_request(P_RESULT, (void *)cb, data);
}
/* The health check's token: answered at once, as the case says (a case
 * that made Keycloak "unreachable" makes it reachable again with it). */
static int token_ensure_ok;
int kc_token_ensure(kc_token_cb cb, void *data)
{
  if (token_ensure_ok)
    cb(KC_SUCCESS, NULL, data);
  return 0;
}

/** Keycloak is reachable again (sasl_health_check()): after a case
 * answered a request "unavailable", which takes the local tier away. */
static void kc_healthy_again(void)
{
  token_ensure_ok = 1;
  sasl_health_check();
  token_ensure_ok = 0;
}
int kc_jwt_prime_cache(struct kc_realm realm) { return KC_SUCCESS; }

/* kc_url.c's UUID check (8-4-4-4-12 hex), which m_register.c asks. */
int kc_url_is_uuid(const char *s, size_t len)
{
  size_t i;
  if (!s || len != 36)
    return 0;
  for (i = 0; i < 36; i++)
    if ((i == 8 || i == 13 || i == 18 || i == 23) ? s[i] != '-'
        : !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')
            || (s[i] >= 'A' && s[i] <= 'F')))
      return 0;
  return 1;
}

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

  if (!grant_has_id)
    return 0;
  if (!a || !b || b - a - 1 >= (int)sizeof(user) || !strncmp(a + 1, "payload", 7)) {
    ircd_strncpy(out, TEST_SUB, out_size);
    return 1;
  }
  memcpy(user, a + 1, b - a - 1);
  user[b - a - 1] = '\0';
  user_sub(user, out, out_size);
  return 1;
}

/** OAUTHBEARER's local check: any token is jwt_user's (carol's unless the
 * case says otherwise), unless the test says the check cannot decide
 * (introspection then). */
static int jwt_local_undecided;
static int jwt_local_forbidden;   /**< the local check is sure: a bad token */
int kc_jwt_validate_local(struct kc_realm realm, const char *token,
                          struct kc_token_info **info_out)
{
  struct kc_token_info *info;
  if (jwt_local_forbidden)
    return KC_FORBIDDEN;
  if (jwt_local_undecided)
    return KC_ERROR;
  info = calloc(1, sizeof(*info));
  info->active = true;
  info->username = strdup(jwt_user);
  info->sub = jwt_sub ? strdup(jwt_sub) : NULL;
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
  in_kc_call = in_login = local_off = 0;
  abort_reply = -1;
  n_an = 0;
  iauth_on = iauth_starts = iauth_datas = iauth_aborts = 0;
  iauth_host_ip[0] = '\0';
  sendhost_on = 0;
  bed_features = 0;
  msgid_on = 0;
  reauth_setting = "refresh";
  max_failures = 0;
  jwt_local_forbidden = 0;
  in_session_too = NULL;
  ntlog = 0;
#ifdef USE_LIBKC
  kc_mode = KC_LATER;
  reap_ok = 0;
  kc_requests = 0;
  memset(pend, 0, sizeof(pend));
  jwt_local_undecided = 0;
  verify_email_on = 0;
  grant_has_id = 1;
  create_names_id = 1;
  lookup_user = lookup_id = NULL;
  next_user[0] = '\0';
  mail_id[0] = '\0';
  user_pem[0] = scram_salt[0] = '\0';
  jwt_user = "carol";
  jwt_sub = (char *)TEST_SUB;
  intro_user = "ian";
  intro_sub = (char *)TEST_SUB;
#endif
  memset(&fx, 0, sizeof(fx));
  memset(timers, 0, sizeof(timers));
  memset(&fsess, 0, sizeof(fsess));
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

/* ------------------------------------------------------------------ */
/* AC on an account change keeps its timestamp slot                     */
/* ------------------------------------------------------------------ */

/** The AC line \a c's account \a type sends the network. */
static const char *ac_line(struct Client *c, char type)
{
  int i;

  ntlog = 0;
  sasl_broadcast_account(c, type);
  for (i = 0; i < ntlog; i++)
    if (!strncmp(tlog[i], "servers AC ", 11))
      return tlog[i] + 11;
  fail_msg("no AC line");
  return "";
}

/** An account change ('M') always carries the timestamp slot, "0" when
 * the login brings none: a stock server keeps the PREVIOUS account's
 * timestamp on an M without one (m_account.c, master), where the fork
 * sets 0 -- the two would hold different values for the same user.  A
 * first login ('R') has no previous value and keeps its short form. */
static void ac_change_carries_the_timestamp_slot(void **state)
{
  struct Client *c = new_client(12, "xav", 1, REG_KEEPS);

  bed_features = 1;                         /* EXTENDED_ACCOUNTS */
  cli_status(c) = STAT_USER;
  ircd_strncpy(cli_user(c)->account, "yvonne", sizeof(cli_user(c)->account));
  SetAccount(c);

  cli_user(c)->acc_create = 0;              /* a local Keycloak login */
  cli_user(c)->kc_id[0] = '\0';
  assert_string_equal(ac_line(c, 'M'), "xav M yvonne 0");
  assert_string_equal(ac_line(c, 'R'), "xav R yvonne");

  cli_user(c)->acc_create = 1600000000;     /* X3's stamp, relayed */
  assert_string_equal(ac_line(c, 'M'), "xav M yvonne 1600000000");

  cli_user(c)->acc_create = 0;              /* with an id: as before */
  ircd_strncpy(cli_user(c)->kc_id, "AAAAAAAAAAAAAAAAAAAAAA",
               sizeof(cli_user(c)->kc_id));
  assert_string_equal(ac_line(c, 'M'), "xav M yvonne 0 AAAAAAAAAAAAAAAAAAAAAA");
  bed_features = 0;
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

static int tlog_has(const char *entry);
static void next_line(struct Client *c, const char *label);

/** labeled-response: a login completed inside its labeled AUTHENTICATE
 * line (here a positive-cache hit) is answered by 900 and 903 -- two
 * lines, so one labeled batch: the batch's start carries the label, the
 * numerics carry none, and the batch ends after the 903 (before the
 * registration the login lets run). */
static void inline_success_answers_in_one_labeled_batch(void **state)
{
  struct Client *c;
  char data[300];

  sasl_init_once();
  first_login(102, "anna", "annapw", 1);
  c = new_client(103, "anna2", 1, REG_KEEPS);
  plain_b64("anna", "annapw", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  next_line(c, "S1");
  ntlog = 0;
  assert_int_equal(authenticate(c, data), 0);
  {
    int i, i900 = -1, i903 = -1, iend = -1;

    assert_true(ntlog >= 4);
    assert_string_equal(tlog[0], "BATCH + labeled-response anna2 [label=S1]");
    for (i = 1; i < ntlog; i++) {
      if (!strncmp(tlog[i], "900 anna2 ", 10))
        i900 = i;
      else if (!strcmp(tlog[i], "903 anna2"))
        i903 = i;
      else if (!strcmp(tlog[i], "BATCH - anna2"))
        iend = i;
      assert_null(strstr(tlog[i], "[label="));   /* only the batch's start */
    }
    assert_true(i900 > 0 && i903 > i900 && iend == i903 + 1);
  }
  assert_int_equal(cli_labeled_batch(c), 0);

  /* Unlabeled: no batch, the numerics bare. */
  first_login(104, "anne", "annepw", 1);
  c = new_client(105, "anne2", 1, REG_KEEPS);
  plain_b64("anne", "annepw", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  next_line(c, "");
  ntlog = 0;
  assert_int_equal(authenticate(c, data), 0);
  assert_false(tlog_has("BATCH - anne2"));
  assert_true(!strncmp(tlog[0], "900 anne2 ", 10));
}

/** A Keycloak answer is the answer to the line that made its request.  It
 * can come inside a LATER line of the same client (libkc reaps finished
 * transfers inside any request call: a web push from a labeled PRIVMSG):
 * there it takes none of that line's label and opens no batch under it,
 * and that line's label is left as it was.  Inside the asking line it is
 * that line's, labeled. */
static void later_answer_inside_another_line_takes_none_of_its_label(void **state)
{
  struct Client *c;
  char data[300];
  int i;

  sasl_init_once();
  kc_mode = KC_LATER;

  /* the request's line A1; the answer comes inside a later line P9 */
  c = new_client(106, "kai", 1, REG_KEEPS);
  plain_b64("kai", "kaipw", data);
  cli_line_seq(c)++;
  next_line(c, "");
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  cli_line_seq(c)++;
  next_line(c, "A1");
  assert_int_equal(authenticate(c, data), 0);
  cli_line_seq(c)++;
  next_line(c, "P9");
  ntlog = 0;
  pend_deliver(1);
  assert_true(ntlog >= 2);
  for (i = 0; i < ntlog; i++) {
    assert_null(strstr(tlog[i], "[label="));
    assert_null(strstr(tlog[i], "BATCH +"));
  }
  assert_true(tlog_has("903 kai"));
  assert_string_equal(cli_label(c), "P9");          /* the later line's, kept */
  assert_int_equal(cli_label_responded(c), 0);
  assert_int_equal(cli_labeled_batch(c), 0);

  /* the same answer inside the asking line: that line's label */
  c = new_client(107, "kim", 1, REG_KEEPS);
  plain_b64("kim", "kimpw", data);
  cli_line_seq(c)++;
  next_line(c, "");
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  cli_line_seq(c)++;
  next_line(c, "A2");
  assert_int_equal(authenticate(c, data), 0);
  ntlog = 0;
  pend_deliver(1);
  assert_string_equal(tlog[0], "BATCH + labeled-response kim [label=A2]");
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

/** Logs nina in as liz (PLAIN, 903), then starts over with OAUTHBEARER (a
 * second exchange before registration: the login stands until it
 * succeeds). */
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

/** A second exchange before registration leaves the earlier login whole
 * while it runs (owner's ruling, 2026-11-15; until then the start undid
 * it): the flag, account, timestamp, Keycloak id and its live mark, with
 * the exchange marked in flight beside it. */
static void second_exchange_keeps_the_login(void **state)
{
  struct Client *c;
  char id[ACCOUNT_ID_LEN + 1];

  sasl_init_once();
  c = login_then_restart(56);
  assert_true(IsSASLComplete(c));
  assert_true(IsSASLReauth(c));
  assert_false(IsSASLExchangeDone(c));
  assert_string_equal(cli_saslaccount(c), "liz");
  assert_string_equal(cli_saslkcid(c), user_id("liz", id));
  assert_int_equal(cli_saslkcidlive(c), 1);
  assert_int_equal(cli_saslacccreate(c), 0);
}

/** The review's sequence: login, a second exchange abandoned (here
 * AUTHENTICATE *), then REGISTER -- refused: the earlier login stands
 * (ALREADY_AUTHENTICATED), so no new account's name can be parked beside
 * its id; Keycloak is asked nothing and the login is as it was. */
static void register_after_abandoned_exchange_is_refused(void **state)
{
  struct Client *c;
  struct fake *f;
  char id[ACCOUNT_ID_LEN + 1];
  int requests;

  sasl_init_once();
  c = login_then_restart(57);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "*"), 0);
  requests = kc_requests;
  assert_int_equal(register_line(c, "longpassword"), 0);
  assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
  assert_int_equal(kc_requests, requests);
  assert_true(IsSASLComplete(c));
  assert_string_equal(cli_saslaccount(c), "liz");
  assert_string_equal(cli_saslkcid(c), user_id("liz", id));
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

/** REGISTER answered: the lookup (the name is free) and the create; when
 * the create's answer names no id, the lookup for it; with verification on
 * the mail. */
static void register_through(struct Client *c, const char *account,
                             const char *email)
{
  kc_mode = KC_LATER;
  assert_int_equal(register_as(c, account, email, "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  pend_deliver_kind(P_CREATED, KC_SUCCESS);
  if (!create_names_id)
    pend_deliver_kind(P_USER, KC_SUCCESS);
  if (verify_email_on)
    pend_deliver_kind(P_RESULT, KC_SUCCESS);
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
 * account -- with its Keycloak id, which the create's answer names -- and
 * a second REGISTER is ALREADY_AUTHENTICATED. */
static void flow_register_logs_in(void **state)
{
  static const char *const names[2][2] = { { "na1", "nx1" }, { "na2", "nx2" } };
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(61, "fa2") : new_client(60, "fa1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char want[64], id[ACCOUNT_ID_LEN + 1];
    int n;

    register_through(c, names[post][0], "*");
    snprintf(want, sizeof(want), "REGISTER SUCCESS %s", names[post][0]);
    assert_non_null(strstr(f->raw, want));
    assert_identity(c, names[post][0], user_id(names[post][0], id), 1);
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
 * succeeds.  Before registration nothing is applied yet: the SASL account
 * with its id.  After registration REGISTER SUCCESS logged the client in
 * to the new account, and a login cannot change the account of a client
 * logged in (#223): the SASL login is refused (907) and the REGISTER
 * account stands -- as the first login stands when REGISTER's answer comes
 * second (flow_sasl_then_register_answer). */
static void flow_register_answer_mid_sasl_then_success(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(67, "fd2") : new_client(66, "fd1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1], rid[ACCOUNT_ID_LEN + 1];
    const char *acct = post ? "nd2" : "nd1", *user = post ? "dan2" : "dan1";

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);        /* the create goes out */
    plain_pending(c, user, "danpw");
    pend_deliver_kind(P_CREATED, KC_SUCCESS);        /* REGISTER SUCCESS */
    assert_identity(c, acct, user_id(acct, rid), 1);
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);         /* then the grant */
    if (post) {
      assert_true(has_numeric(f, ERR_SASLALREADY));
      assert_false(has_numeric(f, ERR_SASLFAIL));
      assert_false(has_numeric(f, RPL_SASLSUCCESS));
      assert_identity(c, acct, rid, 1);
    } else
      assert_identity(c, user, user_id(user, id), 1);
  }
}

/** ... which then fails: the REGISTER account, with its id. */
static void flow_register_answer_mid_sasl_then_failure(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(69, "fe2") : new_client(68, "fe1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char rid[ACCOUNT_ID_LEN + 1];
    const char *acct = post ? "ne2" : "ne1";

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    plain_pending(c, post ? "eve2" : "eve1", "evepw-bad");
    pend_deliver_kind(P_CREATED, KC_SUCCESS);
    pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);       /* 904 */
    assert_true(has_numeric(f, ERR_SASLFAIL));
    assert_identity(c, acct, user_id(acct, rid), 1);
  }
}

/** SASL finishes before REGISTER's answer.  Before registration the
 * REGISTER account, with its id, replaces the login (its answer is the
 * later success); after registration the login stays, and the client is
 * told the account was created but is not the one it is logged in to:
 * WARN REGISTER ALREADY_AUTHENTICATED -- a reply, never silence, never
 * REGISTER SUCCESS (which says "you are now logged in to it"). */
static void flow_sasl_then_register_answer(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(71, "fg2") : new_client(70, "fg1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1], rid[ACCOUNT_ID_LEN + 1];
    const char *acct = post ? "ng2" : "ng1", *user = post ? "gus2" : "gus1";

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    plain_pending(c, user, "guspw");
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);         /* 903 first */
    assert_identity(c, user, user_id(user, id), 1);
    f->n_numerics = 0;
    pend_deliver_kind(P_CREATED, KC_SUCCESS);        /* then REGISTER's */
    if (post) {
      char want[96];
      assert_identity(c, user, id, 1);
      assert_null(strstr(f->raw, "REGISTER"));
      snprintf(want, sizeof(want), "REGISTER ALREADY_AUTHENTICATED %s :", acct);
      assert_true(!strncmp(f->warn, want, strlen(want)));
      assert_non_null(strstr(f->warn, user));          /* names the login */
      assert_false(has_numeric(f, RPL_LOGGEDIN));
      assert_int_equal(cli_regcookie(c), 0);
    } else {
      assert_non_null(strstr(f->raw, "REGISTER SUCCESS"));
      assert_identity(c, acct, user_id(acct, rid), 1);
    }
  }
}


/** SASL logs in to the very account REGISTER is creating (the create
 * landed in Keycloak, and the grant was answered before the create's own
 * answer reached REGISTER): REGISTER SUCCESS is true then -- the client is
 * logged in to it -- and is all that is sent; the login stays as it is,
 * with no second 900. */
static void register_answer_after_login_to_the_same_account(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    const char *acct = post ? "nsame2" : "nsame1";
    struct Client *c = post ? new_registered(87, "sw") : new_client(87, "sw", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1], want[64];

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    plain_pending(c, acct, "longpassword");
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);         /* logged in to it */
    assert_identity(c, acct, user_id(acct, id), 1);
    f->n_numerics = 0;
    ntlog = 0;
    pend_deliver_kind(P_CREATED, KC_SUCCESS);       /* REGISTER's answer */
    snprintf(want, sizeof(want), "raw sw REGISTER SUCCESS %s ", acct);
    assert_int_equal(ntlog, 1);
    assert_true(!strncmp(tlog[0], want, strlen(want)));
    assert_false(has_numeric(f, RPL_LOGGEDIN));
    assert_identity(c, acct, id, 1);
    assert_string_equal(f->warn, "");
    assert_int_equal(cli_regcookie(c), 0);
  }
}

/* ------------------------------------------------------------------ */
/* REGISTER SUCCESS is a SASL login                                    */
/* ------------------------------------------------------------------ */

/* draft/account-registration: after REGISTER SUCCESS the client "is
 * assumed to be authenticated to the <account> as if it used SASL".  The
 * owner's ruling: a real login, as the spec shows.  So a REGISTER's
 * completion is compared with a SASL login's, entry by entry: what the
 * client is sent, what the network is sent, and the calls on the way. */

/** A completion's transcript (tlog), less the entries that name how the
 * login was proved. */
struct transcript {
  char e[TLOG_MAX][TLOG_LEN];
  int n;
};

/** Take the transcript so far into \a t, leaving out entries that begin
 * with \a drop (NULL: none), and start a new one. */
static void take_transcript(struct transcript *t, const char *drop)
{
  int i;

  t->n = 0;
  for (i = 0; i < ntlog; i++)
    if (!drop || strncmp(tlog[i], drop, strlen(drop)))
      strcpy(t->e[t->n++], tlog[i]);
  ntlog = 0;
}

static int transcript_has(const struct transcript *t, const char *prefix)
{
  int i;
  for (i = 0; i < t->n; i++)
    if (!strncmp(t->e[i], prefix, strlen(prefix)))
      return 1;
  return 0;
}

static void assert_same_transcript(const struct transcript *sasl,
                                   const struct transcript *reg)
{
  int i, same = (sasl->n == reg->n);

  for (i = 0; same && i < sasl->n; i++)
    same = !strcmp(sasl->e[i], reg->e[i]);
  if (same)
    return;
  for (i = 0; i < sasl->n || i < reg->n; i++)
    print_message("  %2d  SASL: %-58s  REGISTER: %s\n", i,
                  i < sasl->n ? sasl->e[i] : "", i < reg->n ? reg->e[i] : "");
  fail_msg("a REGISTER login differs from a SASL login");
}

/** Everything a login leaves on a connection. */
struct ident {
  int sasl_complete, account, hidden;
  char sasl_account[ACCOUNTLEN + 1], sasl_id[ACCOUNT_ID_LEN + 1];
  int sasl_live;
  time_t sasl_ts;
  char user_account[ACCOUNTLEN + 1], user_id[ACCOUNT_ID_LEN + 1];
  time_t user_ts;
};

static void ident_of(struct Client *c, struct ident *id)
{
  memset(id, 0, sizeof(*id));
  id->sasl_complete = !!IsSASLComplete(c);
  id->account = !!IsAccount(c);
  id->hidden = !!IsHiddenHost(c);
  ircd_strncpy(id->sasl_account, cli_saslaccount(c), sizeof(id->sasl_account));
  ircd_strncpy(id->sasl_id, cli_saslkcid(c), sizeof(id->sasl_id));
  id->sasl_live = cli_saslkcidlive(c);
  id->sasl_ts = cli_saslacccreate(c);
  ircd_strncpy(id->user_account, cli_user(c)->account, sizeof(id->user_account));
  ircd_strncpy(id->user_id, cli_user(c)->kc_id, sizeof(id->user_id));
  id->user_ts = cli_user(c)->acc_create;
}

static void assert_same_ident(const struct ident *a, const struct ident *b)
{
  assert_int_equal(a->sasl_complete, b->sasl_complete);
  assert_int_equal(a->account, b->account);
  assert_int_equal(a->hidden, b->hidden);
  assert_string_equal(a->sasl_account, b->sasl_account);
  assert_string_equal(a->sasl_id, b->sasl_id);
  assert_int_equal(a->sasl_live, b->sasl_live);
  assert_int_equal(a->sasl_ts, b->sasl_ts);
  assert_string_equal(a->user_account, b->user_account);
  assert_string_equal(a->user_id, b->user_id);
  assert_int_equal(a->user_ts, b->user_ts);
}

/** A SASL PLAIN login of \a acct on \a c, Keycloak's grant answering from
 * the event loop: its transcript in \a t, 903 left out. */
static void sasl_login_of(struct Client *c, const char *acct,
                          struct transcript *t)
{
  char drop[TLOG_LEN];

  plain_pending(c, acct, "samepw");
  ntlog = 0;
  pend_deliver_kind(P_TOKEN, KC_SUCCESS);
  snprintf(drop, sizeof(drop), "%03d %s", RPL_SASLSUCCESS, cli_name(c));
  assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
  take_transcript(t, drop);
}

/** A REGISTER of \a acct on \a c (verification off), Keycloak answering
 * from the event loop: the whole transcript of its completion in \a t. */
static void register_login_of(struct Client *c, const char *acct,
                              struct transcript *t)
{
  kc_mode = KC_LATER;
  assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);  /* the name is free */
  ntlog = 0;
  pend_deliver_kind(P_CREATED, KC_SUCCESS);  /* the account is created */
  take_transcript(t, NULL);
}

/** REGISTER SUCCESS (verification off) leaves the client where a SASL
 * login of that account leaves it, before and after connection
 * registration: the same lines to the client (900, in the same
 * nick!user@host form) and to the network (the AC, with the account's
 * Keycloak id), the same calls in the same order (IAuth told, metadata,
 * the account's modes, the hidden host, the bouncer aliases,
 * account-notify), the same identity -- the Keycloak id, confirmed by
 * Keycloak in this exchange as a grant's is -- and the same hidden host
 * (SASL_AUTOHIDEHOST), with REGISTER SUCCESS in place of 903 -- ahead of
 * the 900, where the spec's before-connect example puts VERIFY SUCCESS --
 * and registration checked from the event loop after either. */
static void register_success_is_a_sasl_login(void **state)
{
  int post;

  sasl_init_once();
  bed_features = 1;
  for (post = 0; post < 2; post++) {
    const char *acct = post ? "same2" : "same1";
    struct Client *s = post ? new_registered(74, "tw") : new_client(74, "tw", 0, REG_KEEPS);
    struct Client *r = post ? new_registered(75, "tw") : new_client(75, "tw", 0, REG_KEEPS);
    struct fake *fs = fake_of(s), *fr = fake_of(r);
    struct transcript ts, tr, rest;
    struct ident is, ir;
    char success[64], id[ACCOUNT_ID_LEN + 1], ac[96];
    int i;

    sasl_login_of(s, acct, &ts);
    register_login_of(r, acct, &tr);

    snprintf(success, sizeof(success), "raw tw REGISTER SUCCESS %s ", acct);
    rest.n = 0;
    for (i = 0; i < tr.n; i++)
      if (strncmp(tr.e[i], success, strlen(success)))
        strcpy(rest.e[rest.n++], tr.e[i]);
    assert_same_transcript(&ts, &rest);
    assert_int_equal(rest.n, tr.n - 1);                 /* one REGISTER SUCCESS */
    assert_true(!strncmp(tr.e[0], success, strlen(success)));
    assert_true(!strncmp(tr.e[1], "900 tw ", 7));       /* the 900 follows it */
    assert_false(has_numeric(fr, RPL_SASLSUCCESS));     /* no 903 */

    ident_of(s, &is);
    ident_of(r, &ir);
    assert_same_ident(&is, &ir);
    assert_true(ir.sasl_complete);
    assert_true(ir.hidden);
    assert_string_equal(ir.sasl_account, acct);
    assert_string_equal(ir.sasl_id, user_id(acct, id));
    assert_int_equal(ir.sasl_live, 1);
    assert_int_equal(ir.sasl_ts, 0);
    if (post) {           /* the network: the id in the AC's fifth place */
      snprintf(ac, sizeof(ac), "servers AC tw R %s 0 %s", acct, id);
      assert_true(transcript_has(&tr, ac));
      assert_string_equal(ir.user_id, id);
    }

    if (!post) {          /* CAP END: both register, from the event loop */
      fs->cap_done = fr->cap_done = 1;
      run_event_loop();
      assert_int_equal(fs->registered, 1);
      assert_int_equal(fr->registered, 1);
      assert_int_equal(fr->runs_inside_kc, 0);
    }
  }
}

/** REGISTER's success landing while the client's own SASL exchange is in
 * flight leaves that exchange alone, its hold on registration with it:
 * registration waits for the exchange, which then ends as it would have
 * (the overlaps pinned above). */
static void register_success_mid_sasl_keeps_the_exchange_hold(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(76, "hw", 0, REG_KEEPS);
  f = fake_of(c);
  kc_mode = KC_LATER;
  assert_int_equal(register_as(c, "nh1", "*", "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  plain_pending(c, "hold1", "holdpw");
  assert_true(f->hold);
  f->cap_done = 1;                           /* CAP END sent meanwhile */
  pend_deliver_kind(P_CREATED, KC_SUCCESS);  /* REGISTER SUCCESS */
  assert_non_null(strstr(f->raw, "REGISTER SUCCESS nh1"));
  assert_true(f->hold);
  assert_non_null(cli_saslsession(c));       /* the exchange goes on */
  run_event_loop();
  assert_int_equal(f->registered, 0);        /* and holds registration */
  pend_deliver_kind(P_TOKEN, KC_SUCCESS);    /* 903 */
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  run_event_loop();
  assert_int_equal(f->registered, 1);
  assert_string_equal(cli_saslaccount(c), "hold1");
}

/** AUTHENTICATE after REGISTER SUCCESS is answered as after 903: another
 * mechanism is refused (907) and the login stays; OAUTHBEARER, the one
 * re-authentication allowed, starts; before and after registration. */
static void authenticate_after_register_success_is_as_after_903(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    const char *acct = post ? "again2" : "again1";
    struct Client *s = post ? new_registered(77, "aw") : new_client(77, "aw", 0, REG_KEEPS);
    struct Client *r = post ? new_registered(78, "aw") : new_client(78, "aw", 0, REG_KEEPS);
    struct transcript ts, tr;
    struct ident is, ir;
    char refused[32];

    sasl_login_of(s, acct, &ts);
    register_login_of(r, acct, &tr);

    assert_int_equal(authenticate(s, "PLAIN"), 0);
    take_transcript(&ts, NULL);
    assert_int_equal(authenticate(r, "PLAIN"), 0);
    take_transcript(&tr, NULL);
    snprintf(refused, sizeof(refused), "%03d aw", ERR_SASLALREADY);
    assert_true(transcript_has(&ts, refused));
    assert_same_transcript(&ts, &tr);
    ident_of(s, &is);
    ident_of(r, &ir);
    assert_string_equal(ir.sasl_account, acct);
    assert_null(cli_saslsession(r));

    assert_int_equal(authenticate(s, "OAUTHBEARER"), 0);
    take_transcript(&ts, NULL);
    assert_int_equal(authenticate(r, "OAUTHBEARER"), 0);
    take_transcript(&tr, NULL);
    assert_same_transcript(&ts, &tr);
    assert_non_null(cli_saslsession(s));
    assert_non_null(cli_saslsession(r));
    ident_of(s, &is);
    ident_of(r, &ir);
    assert_same_ident(&is, &ir);
    assert_int_equal(authenticate(s, "*"), 0);
    assert_int_equal(authenticate(r, "*"), 0);
  }
}


/* ------------------------------------------------------------------ */
/* The new account's Keycloak id                                       */
/* ------------------------------------------------------------------ */

/** Keycloak's create answer names the new user (its Location header):
 * the id comes with it, no further request.  When an answer names none,
 * REGISTER asks for the user once and logs in with the id that names --
 * REGISTER SUCCESS only then, so the login is made and announced once,
 * whole. */
static void register_without_location_looks_up_the_id(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    const char *acct = post ? "nl2" : "nl1";
    struct Client *c = post ? new_registered(81, "lw") : new_client(81, "lw", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1];
    int n;

    create_names_id = 0;
    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    n = kc_requests;
    pend_deliver_kind(P_CREATED, KC_SUCCESS);   /* no Location */
    assert_int_equal(kc_requests, n + 1);       /* the lookup */
    assert_null(strstr(f->raw, "REGISTER"));    /* nothing yet */
    assert_false(has_numeric(f, RPL_LOGGEDIN));
    assert_false(IsSASLComplete(c));
    pend_deliver_kind(P_USER, KC_SUCCESS);
    assert_non_null(strstr(f->raw, "REGISTER SUCCESS"));
    assert_true(has_numeric(f, RPL_LOGGEDIN));
    assert_identity(c, acct, user_id(acct, id), 1);
    assert_int_equal(cli_regcookie(c), 0);      /* the REGISTER is over */

    /* With the id in the answer, nothing is asked after the create. */
    create_names_id = 1;
    c = post ? new_registered(82, "lx") : new_client(82, "lx", 0, REG_KEEPS);
    assert_int_equal(register_as(c, post ? "nm2" : "nm1", "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    n = kc_requests;
    pend_deliver_kind(P_CREATED, KC_SUCCESS);
    assert_int_equal(kc_requests, n);
    assert_identity(c, post ? "nm2" : "nm1", user_id(post ? "nm2" : "nm1", id), 1);
  }
}

/** A lookup that fails, times out or cannot be started does not undo a
 * created account: REGISTER SUCCESS and the login, without an id (as a
 * SASL login whose grant names none). */
static void register_id_lookup_failure_still_logs_in(void **state)
{
  static const int fails[3] = { KC_NOT_FOUND, KC_TIMEOUT, 0 /* refused */ };
  int post, i;

  sasl_init_once();
  for (i = 0; i < 3; i++)
    for (post = 0; post < 2; post++) {
      char acct[16];
      struct Client *c = post ? new_registered(83, "lf") : new_client(83, "lf", 0, REG_KEEPS);
      struct fake *f = fake_of(c);

      snprintf(acct, sizeof(acct), "nf%d%d", i, post);
      create_names_id = 0;
      kc_mode = KC_LATER;
      assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
      pend_deliver_kind(P_USER, KC_NOT_FOUND);
      if (!fails[i])
        kc_mode = KC_REFUSE;                    /* the lookup is not started */
      pend_deliver_kind(P_CREATED, KC_SUCCESS);
      kc_mode = KC_LATER;
      if (fails[i])
        pend_deliver_kind(P_USER, fails[i]);
      assert_int_equal(pend[0].kind, P_NONE);
      assert_non_null(strstr(f->raw, "REGISTER SUCCESS"));
      assert_true(has_numeric(f, RPL_LOGGEDIN));
      assert_identity(c, acct, "", 0);
      assert_int_equal(cli_regcookie(c), 0);
      if (!post) {
        f->cap_done = 1;
        run_event_loop();
        assert_int_equal(f->registered, 1);
        assert_int_equal(f->runs_inside_kc, 0);
      }
    }
}

/** A lookup that answers, but not with this account's UUID -- another
 * user's record, or an id that is not a UUID (a federated "f:..." id, or
 * anything a broken answer holds) -- gives no id: the login goes on
 * without one, and with verification on no mail is asked for (the id would
 * go into its URL); the client is still told VERIFICATION_REQUIRED. */
static void register_id_lookup_wrong_answer(void **state)
{
  static const char *const ids[2] = { "f:5b0d:abc", "../../x" };
  int i, post;

  sasl_init_once();
  for (i = 0; i < 3; i++)
    for (post = 0; post < 2; post++) {
      char acct[16];
      struct Client *c = post ? new_registered(88, "lw2") : new_client(88, "lw2", 0, REG_KEEPS);
      struct fake *f = fake_of(c);

      snprintf(acct, sizeof(acct), "nw%d%d", i, post);
      create_names_id = 0;
      lookup_user = i == 2 ? "someoneelse" : NULL;
      lookup_id = i < 2 ? ids[i] : NULL;
      kc_mode = KC_LATER;
      assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
      lookup_user = NULL;                         /* the name is free */
      lookup_id = NULL;
      pend_deliver_kind(P_USER, KC_NOT_FOUND);
      lookup_user = i == 2 ? "someoneelse" : NULL;
      lookup_id = i < 2 ? ids[i] : NULL;
      pend_deliver_kind(P_CREATED, KC_SUCCESS);
      pend_deliver_kind(P_USER, KC_SUCCESS);
      assert_non_null(strstr(f->raw, "REGISTER SUCCESS"));
      assert_identity(c, acct, "", 0);
      lookup_user = lookup_id = NULL;
    }

  verify_email_on = 1;
  for (i = 0; i < 2; i++) {
    struct Client *c = new_client(89, "lw3", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    int n;

    create_names_id = 0;
    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, i ? "nwv1" : "nwv0", "a@b.test", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    pend_deliver_kind(P_CREATED, KC_SUCCESS);
    lookup_id = ids[i];
    n = kc_requests;
    mail_id[0] = '\0';
    pend_deliver_kind(P_USER, KC_SUCCESS);
    lookup_id = NULL;
    assert_int_equal(kc_requests, n);             /* no mail asked for */
    assert_string_equal(mail_id, "");
    assert_non_null(strstr(f->raw, "REGISTER VERIFICATION_REQUIRED"));
    assert_false(IsSASLComplete(c));
  }
}

/** A client gone (or its fd reused) by the time the lookup answers is not
 * touched, and nothing is asked for it once the create answers. */
static void register_client_gone_before_the_id(void **state)
{
  struct Client *c;
  struct fake *f;
  int n;

  sasl_init_once();
  c = new_client(84, "gw", 0, REG_KEEPS);
  f = fake_of(c);
  create_names_id = 0;
  kc_mode = KC_LATER;
  assert_int_equal(register_as(c, "ngone", "*", "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  pend_deliver_kind(P_CREATED, KC_SUCCESS);   /* the lookup goes out */
  LocalClientArray[84] = NULL;                /* the client leaves */
  ntlog = 0;
  pend_deliver_kind(P_USER, KC_SUCCESS);
  assert_int_equal(ntlog, 0);
  assert_false(IsSASLComplete(c));

  c = new_client(85, "gx", 0, REG_KEEPS);     /* gone before the create */
  f = fake_of(c);
  assert_int_equal(register_as(c, "ngone2", "*", "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  LocalClientArray[85] = NULL;
  n = kc_requests;
  ntlog = 0;
  pend_deliver_kind(P_CREATED, KC_SUCCESS);
  assert_int_equal(kc_requests, n);
  assert_int_equal(ntlog, 0);
  (void)f;
}

/** e. Verification on is unchanged: VERIFICATION_REQUIRED, no login and
 * nothing kept, before and after registration.  The mail goes to the user
 * the create's answer names, with no lookup, or, when it names none, to
 * the one the lookup finds. */
static void verify_on_does_not_log_in(void **state)
{
  int post, named;

  sasl_init_once();
  verify_email_on = 1;
  for (named = 0; named < 2; named++)
    for (post = 0; post < 2; post++) {
      char acct[16], sub[40];
      struct Client *c = post ? new_registered(86, "vw") : new_client(86, "vw", 0, REG_KEEPS);
      struct fake *f = fake_of(c);
      int n;

      snprintf(acct, sizeof(acct), "nv%d%d", named, post);
      create_names_id = named;
      kc_mode = KC_LATER;
      assert_int_equal(register_as(c, acct, "user@example.test", "longpassword"), 0);
      pend_deliver_kind(P_USER, KC_NOT_FOUND);
      n = kc_requests;
      pend_deliver_kind(P_CREATED, KC_SUCCESS);
      assert_int_equal(kc_requests, n + 1);     /* the mail, or the lookup */
      if (!named) {
        assert_int_equal(pend[0].kind, P_USER);
        pend_deliver_kind(P_USER, KC_SUCCESS);
      }
      user_sub(acct, sub, sizeof(sub));
      assert_string_equal(mail_id, sub);
      pend_deliver_kind(P_RESULT, KC_SUCCESS);
      assert_non_null(strstr(f->raw, "REGISTER VERIFICATION_REQUIRED"));
      assert_false(has_numeric(f, RPL_LOGGEDIN));
      assert_false(IsSASLComplete(c));
      assert_false(IsAccount(c));
      assert_string_equal(cli_saslaccount(c), "");
      assert_string_equal(cli_saslkcid(c), "");
      assert_int_equal(cli_regcookie(c), 0);
    }
}

/* ------------------------------------------------------------------ */
/* A REGISTER login mid-exchange                                       */
/* ------------------------------------------------------------------ */

/** REGISTER SUCCESS landing while the client's own SASL exchange is in
 * flight completes no exchange: that exchange stays abortable.  Before,
 * the SASL-complete flag the REGISTER login set made AUTHENTICATE * a
 * silent no-op (and the relay tier's abort and timeout return early), so
 * before registration the hold lasted until the exchange's own end.  Now
 * the abort answers 906, drops the session and the hold -- registration
 * goes on, in the line -- and the REGISTER login stays; the grant's late
 * answer finds no exchange. */
static void register_success_mid_sasl_leaves_it_abortable(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    const char *acct = post ? "nab2" : "nab1";
    struct Client *c = post ? new_registered(93, "ab1") : new_client(93, "ab1", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char id[ACCOUNT_ID_LEN + 1];

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, acct, "*", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    plain_pending(c, post ? "abu2" : "abu1", "abupw");
    pend_deliver_kind(P_CREATED, KC_SUCCESS);       /* REGISTER SUCCESS */
    assert_non_null(cli_saslsession(c));
    f->cap_done = 1;
    f->n_numerics = 0;
    assert_int_equal(authenticate(c, "*"), 0);
    assert_true(has_numeric(f, ERR_SASLABORTED));
    assert_null(cli_saslsession(c));
    assert_int_equal(cli_saslcookie(c), 0);
    if (!post) {
      assert_int_equal(f->hold, 0);
      assert_int_equal(f->registered, 1);           /* in the line */
    }
    assert_identity(c, acct, user_id(acct, id), 1);
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);         /* the grant, too late */
    assert_identity(c, acct, id, 1);
    assert_false(has_numeric(f, RPL_SASLSUCCESS));
  }
}

/* ------------------------------------------------------------------ */
/* Names the ircd folds together; what Keycloak refused                */
/* ------------------------------------------------------------------ */

/** An account name is refused before Keycloak is asked when it holds a
 * character the ircd's casemapping folds together with another that is
 * not its letter case: with rfc1459's table, [ \ ] ^ and { | } ~ --
 * Keycloak's "is the name taken?" folds letter case only, so "victim{"
 * would be made beside "victim[" and the ircd would hold the two as one.
 * Every other nick character, letters in either case included, is asked
 * about. */
static void register_refuses_names_the_casemapping_folds(void **state)
{
  static const char folds[] = "[\\]^{|}~";
  struct Client *c;
  struct fake *f;
  int b, refused = 0;

  sasl_init_once();
  c = new_client(94, "fw", 0, REG_KEEPS);
  f = fake_of(c);
  kc_mode = KC_LATER;
  for (b = 1; b < 256; b++) {
    char name[8];
    int n;

    if (!IsNickChar((char)b))
      continue;
    snprintf(name, sizeof(name), "ab%c", (char)b);
    f->fail_code[0] = '\0';
    ntlog = 0;
    n = kc_requests;
    assert_int_equal(register_as(c, name, "*", "longpassword"), 0);
    if (strchr(folds, b)) {
      if (strcmp(f->fail_code, "BAD_ACCOUNT_NAME") || kc_requests != n)
        fail_msg("\"%s\" was not refused", name);
      refused++;
    } else {
      if (kc_requests != n + 1)
        fail_msg("\"%s\" was refused (%s)", name, f->fail_code);
      pend_deliver_kind(P_USER, KC_SUCCESS);     /* taken: the REGISTER ends */
      assert_string_equal(f->fail_code, "ACCOUNT_EXISTS");
    }
  }
  assert_int_equal(refused, 8);
}

/** What Keycloak refused the create for (kc_classify_create_error()) is
 * what the client is told: the draft/account-registration code for the
 * reason, INVALID_PARAMS for a refusal it named no reason for, and
 * TEMPORARILY_UNAVAILABLE only when Keycloak could not be used. */
static void register_tells_why_keycloak_refused(void **state)
{
  static const struct { int res; const char *code; } cases[] = {
    { KC_CONFLICT,       "ACCOUNT_EXISTS" },
    { KC_CONFLICT_EMAIL, "UNACCEPTABLE_EMAIL" },
    { KC_BAD_USERNAME,   "BAD_ACCOUNT_NAME" },
    { KC_BAD_EMAIL,      "INVALID_EMAIL" },
    { KC_BAD_PASSWORD,   "WEAK_PASSWORD" },
    { KC_REJECTED,       "INVALID_PARAMS" },
    { KC_ERROR,          "TEMPORARILY_UNAVAILABLE" },
    { KC_TIMEOUT,        "TEMPORARILY_UNAVAILABLE" },
    { KC_TOKEN_ERROR,    "TEMPORARILY_UNAVAILABLE" },
  };
  size_t i;

  sasl_init_once();
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    struct Client *c = new_client(95, "kw", 0, REG_KEEPS);
    struct fake *f = fake_of(c);

    kc_mode = KC_LATER;
    assert_int_equal(register_as(c, "nkw", "a@b.test", "longpassword"), 0);
    pend_deliver_kind(P_USER, KC_NOT_FOUND);
    pend_deliver_kind(P_CREATED, cases[i].res);
    assert_string_equal(f->fail_code, cases[i].code);
    assert_false(IsSASLComplete(c));
    assert_int_equal(cli_regcookie(c), 0);
  }
}

/* ------------------------------------------------------------------ */
/* labeled-response: the answer carries the REGISTER's own label       */
/* ------------------------------------------------------------------ */

/** The line \a c is on now: \a label ("" none), not yet answered. */
static void next_line(struct Client *c, const char *label)
{
  ircd_strncpy(cli_label(c), label, sizeof(cli_label(c)));
  cli_label_responded(c) = 0;
}

static int tlog_has(const char *entry)
{
  int i;
  for (i = 0; i < ntlog; i++)
    if (!strcmp(tlog[i], entry))
      return 1;
  return 0;
}

/** An entry of the transcript begins with \a prefix. */
static int tlog_has_prefix(const char *prefix)
{
  int i;
  for (i = 0; i < ntlog; i++)
    if (!strncmp(tlog[i], prefix, strlen(prefix)))
      return 1;
  return 0;
}

/** A REGISTER's answer comes from Keycloak, after its line: the REGISTER
 * is not ACKed meanwhile, and the answer goes out under its own label --
 * never the label of the line the client is on by then, nor none for a
 * labeled REGISTER -- a login (REGISTER SUCCESS, 900, ...) in a
 * labeled-response batch, a FAIL, WARN or VERIFICATION_REQUIRED on its
 * line; an unlabeled REGISTER's answer carries no label.  The line the
 * client is on keeps its own label state. */
static void register_answer_carries_its_own_label(void **state)
{
  struct Client *c;

  sasl_init_once();
  kc_mode = KC_LATER;

  /* a login: in a batch under L1, while the client is on line L2 */
  c = new_client(96, "lb", 0, REG_KEEPS);
  next_line(c, "L1");
  assert_int_equal(register_as(c, "nlab1", "*", "longpassword"), 0);
  assert_int_equal(cli_label_responded(c), 1);      /* no ACK now */
  next_line(c, "L2");
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  ntlog = 0;
  pend_deliver_kind(P_CREATED, KC_SUCCESS);
  assert_string_equal(tlog[0], "BATCH + labeled-response lb [label=L1]");
  assert_string_equal(tlog[1], "raw lb REGISTER SUCCESS nlab1 :Account registered");
  assert_true(!strncmp(tlog[2], "900 lb ", 7));
  assert_string_equal(tlog[ntlog - 1], "BATCH - lb");
  assert_string_equal(cli_label(c), "L2");          /* the line's own, back */
  assert_int_equal(cli_label_responded(c), 0);
  assert_int_equal(cli_labeled_batch(c), 0);

  /* a FAIL, under L3 */
  c = new_client(97, "lc", 0, REG_KEEPS);
  next_line(c, "L3");
  assert_int_equal(register_as(c, "nlab2", "*", "longpassword"), 0);
  next_line(c, "L4");
  ntlog = 0;
  pend_deliver_kind(P_USER, KC_SUCCESS);            /* the name is taken */
  assert_true(tlog_has("FAIL REGISTER ACCOUNT_EXISTS nlab2 [label=L3]"));
  assert_string_equal(cli_label(c), "L4");
  assert_int_equal(cli_label_responded(c), 0);

  /* an unlabeled REGISTER answered while the client is on line L5 */
  c = new_client(98, "ld", 0, REG_KEEPS);
  next_line(c, "");
  assert_int_equal(register_as(c, "nlab3", "*", "longpassword"), 0);
  assert_int_equal(cli_label_responded(c), 0);
  next_line(c, "L5");
  ntlog = 0;
  pend_deliver_kind(P_USER, KC_SUCCESS);
  assert_true(tlog_has("FAIL REGISTER ACCOUNT_EXISTS nlab3"));
  assert_string_equal(cli_label(c), "L5");
  assert_int_equal(cli_label_responded(c), 0);      /* L5 still unanswered */

  /* answered inside its own line (libkc answered at once): labeled, and
   * the line is answered (no ACK) */
  c = new_client(99, "le", 0, REG_KEEPS);
  next_line(c, "L6");
  kc_mode = KC_INLINE_FAIL;
  ntlog = 0;
  assert_int_equal(register_as(c, "nlab4", "*", "longpassword"), 0);
  kc_mode = KC_LATER;
  assert_true(tlog_has("FAIL REGISTER TEMPORARILY_UNAVAILABLE nlab4 [label=L6]"));
  assert_string_equal(cli_label(c), "L6");
  assert_int_equal(cli_label_responded(c), 1);

  /* the WARN of a late answer, under L7 */
  c = new_registered(100, "lf");
  next_line(c, "L7");
  assert_int_equal(register_as(c, "nlab5", "*", "longpassword"), 0);
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  next_line(c, "");
  plain_pending(c, "labu", "labpw");
  pend_deliver_kind(P_TOKEN, KC_SUCCESS);           /* logged in meanwhile */
  next_line(c, "L8");
  ntlog = 0;
  pend_deliver_kind(P_CREATED, KC_SUCCESS);
  assert_true(tlog_has("WARN REGISTER ALREADY_AUTHENTICATED nlab5 [label=L7]"));
  assert_string_equal(cli_label(c), "L8");

  /* VERIFICATION_REQUIRED, under L9 */
  verify_email_on = 1;
  c = new_client(101, "lg", 0, REG_KEEPS);
  next_line(c, "L9");
  assert_int_equal(register_as(c, "nlab6", "a@b.test", "longpassword"), 0);
  next_line(c, "");
  pend_deliver_kind(P_USER, KC_NOT_FOUND);
  pend_deliver_kind(P_CREATED, KC_SUCCESS);
  ntlog = 0;
  pend_deliver_kind(P_RESULT, KC_SUCCESS);          /* the mail */
  assert_true(tlog_has("raw lg REGISTER VERIFICATION_REQUIRED nlab6 :Account created - "
                       "check your email for a verification link, then log in "
                       "normally (SASL) [label=L9]"));
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

/* ------------------------------------------------------------------ */
/* A logged-in client's re-authentication never changes its account    */
/* ------------------------------------------------------------------ */

/* OAUTHBEARER after registration exists so that a CAP 302 client can
 * refresh a token about to expire.  A token naming another account is
 * refused with 907 (the client is already authenticated), the same name
 * under another Keycloak id with 904, and the login stays exactly as it
 * was; a token for the same account refreshes it.  "Logged
 * in" is an account the ircd has applied (registration did, or a login
 * after it), not a login still waiting for registration to apply it:
 * before registration a client may authenticate again, as anyone. */

/** A client registered and logged in to \a account with Keycloak id \a
 * kc_id ("" for none): through SASL before registration when \a by_sasl
 * (the SASL-complete flag and that login's own record, its id confirmed by
 * Keycloak, as registration leaves them), else through services (the
 * account with X3's timestamp, no SASL record).  standard-replies on. */
static struct Client *new_logged_in(int fd, const char *nick,
                                    const char *account, const char *kc_id,
                                    int by_sasl)
{
  struct Client *c = new_registered(fd, nick);

  ircd_strncpy(cli_user(c)->account, account, sizeof(cli_user(c)->account));
  ircd_strncpy(cli_user(c)->kc_id, kc_id, sizeof(cli_user(c)->kc_id));
  cli_user(c)->acc_create = by_sasl ? 0 : 1700000000;
  SetAccount(c);
  SetHiddenHost(c);
  if (by_sasl) {
    sasl_identity_set(c, account, 0, kc_id, 1);
    SetSASLComplete(c);
  }
  CapSet(cli_active(c), CAP_STANDARDREPLIES);
  return c;
}

/** Everything a login is: the account with its timestamp and Keycloak id,
 * the login's own record (name, timestamp, id, id-live), and the flags. */
struct login_snap {
  int registered, is_account, sasl_complete, hidden;
  char account[ACCOUNTLEN + 1], kc_id[ACCOUNT_ID_LEN + 1];
  time_t acc_create;
  char saslaccount[ACCOUNTLEN + 1], saslkcid[ACCOUNT_ID_LEN + 1];
  time_t saslacccreate;
  int saslkcidlive;
};

static void snap(struct Client *c, struct login_snap *s)
{
  memset(s, 0, sizeof(*s));
  s->registered = IsRegistered(c) ? 1 : 0;
  s->is_account = IsAccount(c) ? 1 : 0;
  s->sasl_complete = IsSASLComplete(c) ? 1 : 0;
  s->hidden = IsHiddenHost(c) ? 1 : 0;
  ircd_strncpy(s->account, cli_user(c)->account, sizeof(s->account));
  ircd_strncpy(s->kc_id, cli_user(c)->kc_id, sizeof(s->kc_id));
  s->acc_create = cli_user(c)->acc_create;
  ircd_strncpy(s->saslaccount, cli_saslaccount(c), sizeof(s->saslaccount));
  ircd_strncpy(s->saslkcid, cli_saslkcid(c), sizeof(s->saslkcid));
  s->saslacccreate = cli_saslacccreate(c);
  s->saslkcidlive = cli_saslkcidlive(c);
}

static void assert_login_unchanged(struct Client *c, const struct login_snap *was)
{
  struct login_snap now;

  snap(c, &now);
  assert_int_equal(now.registered, was->registered);
  assert_int_equal(now.is_account, was->is_account);
  assert_int_equal(now.sasl_complete, was->sasl_complete);
  assert_int_equal(now.hidden, was->hidden);
  assert_string_equal(now.account, was->account);
  assert_string_equal(now.kc_id, was->kc_id);
  assert_int_equal(now.acc_create, was->acc_create);
  assert_string_equal(now.saslaccount, was->saslaccount);
  assert_string_equal(now.saslkcid, was->saslkcid);
  assert_int_equal(now.saslacccreate, was->saslacccreate);
  assert_int_equal(now.saslkcidlive, was->saslkcidlive);
}

/** Nothing was announced since \a was: no alias, server or channel told,
 * no metadata, modes, host or presence touched, no id adopted. */
static void assert_nothing_announced(const struct effects *was)
{
  assert_int_equal(fx.alias_updates, was->alias_updates);
  assert_int_equal(fx.alias_syncs, was->alias_syncs);
  assert_int_equal(fx.adopts, was->adopts);
  assert_int_equal(fx.broadcasts, was->broadcasts);
  assert_int_equal(fx.notifies, was->notifies);
  assert_int_equal(fx.metadata_loads, was->metadata_loads);
  assert_int_equal(fx.mode_syncs, was->mode_syncs);
  assert_int_equal(fx.hostmasks, was->hostmasks);
  assert_int_equal(fx.account_adjusts, was->account_adjusts);
  assert_int_equal(fx.anchors, was->anchors);
}

/** The next OAUTHBEARER token is \a user's, its sub the Keycloak id of \a
 * sub_of (NULL: a token without one), for both validation strategies. */
static void token_for(const char *user, const char *sub_of)
{
  ircd_strncpy(tok_user, user, sizeof(tok_user));
  jwt_user = intro_user = tok_user;
  if (sub_of) {
    user_sub(sub_of, tok_sub, sizeof(tok_sub));
    jwt_sub = intro_sub = tok_sub;
  } else
    jwt_sub = intro_sub = NULL;
}

/** How the token is checked: OAUTHBEARER's local check (the exchange ends
 * inside the client's line), or introspection (Keycloak answers it active,
 * from the event loop). */
enum strategy { LOCAL, INTROSPECT };

static void oauth_exchange(struct Client *c, enum strategy how)
{
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char data[300];

  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  jwt_local_undecided = (how == INTROSPECT);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  assert_int_equal(authenticate(c, data), 0);
  if (how == INTROSPECT) {
    pend_deliver_kind(P_INTRO, KC_SUCCESS);
    run_event_loop();
  }
}

/** \a c's re-authentication was refused with \a numeric -- 907 for
 * another account, 904 (its reason \a reason) for the same name under
 * another Keycloak id -- and not the other one; the FAIL before it, as
 * ever, with \a reason in its description; no 900/903, the exchange over,
 * the login exactly \a was, nothing announced, the opers told; and the
 * gate still stands (PLAIN: 907, the login untouched). */
static void assert_refused(struct Client *c, const struct login_snap *was,
                           const struct effects *fx_was, int numeric,
                           const char *reason)
{
  struct fake *f = fake_of(c);

  assert_true(numeric == ERR_SASLALREADY || numeric == ERR_SASLFAIL);
  assert_true(has_numeric(f, numeric));
  assert_false(has_numeric(f, numeric == ERR_SASLFAIL ? ERR_SASLALREADY
                                                      : ERR_SASLFAIL));
  assert_false(has_numeric(f, RPL_LOGGEDIN));
  assert_false(has_numeric(f, RPL_SASLSUCCESS));
  if (numeric == ERR_SASLFAIL)
    assert_non_null(strstr(f->saslfail, reason));
  assert_non_null(strstr(f->fail_desc, reason));
  assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
  assert_string_equal(f->fail_context, "");    /* as with 907: no context */
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_login_unchanged(c, was);
  assert_nothing_announced(fx_was);
  if (!strstr(reason, "already completed"))     /* a change of account */
    assert_true(fx.oper_notices_tried > fx_was->oper_notices_tried);
  assert_false(IsSASLReauth(c));                /* the exchange's mark went */
  assert_int_equal(f->registered, 0);           /* no registration ran */

  /* The gate still stands: under refresh PLAIN is 907 at once; under same
   * and any it starts (and is ended here). */
  f->n_numerics = 0;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  if (sasl_reauth_mode() == SASL_REAUTH_REFRESH)
    assert_true(has_numeric(f, ERR_SASLALREADY));
  else {
    assert_non_null(cli_saslsession(c));
    assert_int_equal(authenticate(c, "*"), 0);
    assert_null(cli_saslsession(c));
  }
  assert_login_unchanged(c, was);
}

/** \a c's re-authentication refreshed its login: 900 and 903, the account
 * and its id as before, nothing announced to anyone. */
static void assert_refreshed(struct Client *c, const struct login_snap *was,
                             const struct effects *fx_was)
{
  struct fake *f = fake_of(c);

  assert_true(has_numeric(f, RPL_LOGGEDIN));
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_false(has_numeric(f, ERR_SASLFAIL));
  assert_true(IsAccount(c));
  assert_true(IsSASLComplete(c));
  assert_string_equal(cli_user(c)->account, was->account);
  assert_int_equal(cli_user(c)->acc_create, was->acc_create);
  assert_string_equal(f->loggedin_as, was->account);   /* its own spelling */
  assert_string_equal(cli_saslaccount(c), was->account);
  assert_int_equal(IsHiddenHost(c) ? 1 : 0, was->hidden);
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_int_equal(fx.alias_updates, fx_was->alias_updates);
  assert_int_equal(fx.broadcasts, fx_was->broadcasts);
  assert_int_equal(fx.notifies, fx_was->notifies);
  assert_int_equal(fx.metadata_loads, fx_was->metadata_loads);
  assert_int_equal(fx.account_adjusts, fx_was->account_adjusts);
}

/** #223: logged in as xavier, a valid token for yvonne -- by either
 * strategy -- is refused and changes nothing; a refresh for xavier still
 * works after it. */
static void reauth_other_account_refused(void **state)
{
  enum strategy how;

  sasl_init_once();
  for (how = LOCAL; how <= INTROSPECT; how++) {
    char xid[ACCOUNT_ID_LEN + 1];
    struct Client *c = new_logged_in(80 + how, "xav", "xavier",
                                     user_id("xavier", xid), 1);
    struct fake *f = fake_of(c);
    struct login_snap was;
    struct effects fx_was;

    snap(c, &was);
    fx_was = fx;
    token_for("yvonne", "yvonne");
    oauth_exchange(c, how);
    assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");

    f->n_numerics = 0;                     /* then a refresh of its own */
    token_for("xavier", "xavier");
    oauth_exchange(c, how);
    assert_refreshed(c, &was, &fx_was);
    assert_string_equal(cli_user(c)->kc_id, xid);
  }
}

/** The same name under another Keycloak id (the account deleted and made
 * again) is not the same account: refused, by either strategy. */
static void reauth_same_name_other_id_refused(void **state)
{
  enum strategy how;

  sasl_init_once();
  for (how = LOCAL; how <= INTROSPECT; how++) {
    char xid[ACCOUNT_ID_LEN + 1];
    struct Client *c = new_logged_in(82 + how, "xav", "xavier",
                                     user_id("xavier", xid), 1);
    struct login_snap was;
    struct effects fx_was;

    snap(c, &was);
    fx_was = fx;
    token_for("xavier", "xavier-recreated");
    oauth_exchange(c, how);
    assert_refused(c, &was, &fx_was, ERR_SASLFAIL, "previous Keycloak user");
  }
}

/** A token for the same account refreshes the login, by either strategy;
 * the name is compared as the ircd compares account names (letter case
 * folded), and the account keeps its own spelling. */
static void reauth_same_account_refreshes(void **state)
{
  enum strategy how;

  sasl_init_once();
  for (how = LOCAL; how <= INTROSPECT; how++) {
    char xid[ACCOUNT_ID_LEN + 1];
    struct Client *c = new_logged_in(84 + how, "xav", "xavier",
                                     user_id("xavier", xid), 1);
    struct fake *f = fake_of(c);
    struct login_snap was;
    struct effects fx_was;

    snap(c, &was);
    fx_was = fx;
    token_for("xavier", "xavier");
    oauth_exchange(c, how);
    assert_refreshed(c, &was, &fx_was);
    assert_string_equal(cli_user(c)->kc_id, xid);

    f->n_numerics = 0;
    token_for("XAVIER", "xavier");
    oauth_exchange(c, how);
    assert_refreshed(c, &was, &fx_was);
    assert_string_equal(cli_user(c)->account, "xavier");
  }
}

/** The names decide whenever either side has no Keycloak id, and a
 * missing id is never a way to another account:
 *   current id  token id   same name   other name
 *   known       present    ids decide  refused
 *   known       absent     refresh     refused
 *   unknown     present    refresh     refused   (refresh adopts the id)
 *   unknown     absent     refresh     refused
 * (the first row's cases are above). */
static void reauth_id_table(void **state)
{
  static const struct {
    int cur_id;                 /**< the login carries an id (SASL) or not
                                     (services) */
    int tok_id;                 /**< the token carries a sub */
    int same;                   /**< the token names the same account */
  } rows[] = {
    { 1, 0, 1 }, { 1, 0, 0 },
    { 0, 1, 1 }, { 0, 1, 0 },
    { 0, 0, 1 }, { 0, 0, 0 },
  };
  size_t i;

  sasl_init_once();
  for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
    char xid[ACCOUNT_ID_LEN + 1];
    struct Client *c;
    struct login_snap was;
    struct effects fx_was;
    const char *name = rows[i].same ? "xavier" : "yvonne";

    user_id("xavier", xid);
    c = new_logged_in(86 + (int)(i % 2), "xav", "xavier",
                      rows[i].cur_id ? xid : "", rows[i].cur_id);
    snap(c, &was);
    fx_was = fx;
    token_for(name, rows[i].tok_id ? name : NULL);
    oauth_exchange(c, LOCAL);
    if (!rows[i].same) {
      assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");
      continue;
    }
    assert_refreshed(c, &was, &fx_was);
    if (rows[i].cur_id)
      assert_string_equal(cli_user(c)->kc_id, xid);   /* kept */
    else if (rows[i].tok_id) {
      assert_string_equal(cli_user(c)->kc_id, xid);   /* adopted */
      assert_int_equal(fx.alias_syncs, fx_was.alias_syncs + 1);
    } else
      assert_string_equal(cli_user(c)->kc_id, "");
  }
}

/** #218 and #219: a bouncer session's alias and its primary are logged in
 * like any client.  A token for another account is refused for either, and
 * neither the session nor its other members hear of it; the session's
 * Keycloak id speaks for a member whose own is unknown; a refresh for the
 * session's account works for both and announces nothing, as before. */
static void reauth_session_members(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *p, *a, *who[2];
  int m;

  sasl_init_once();
  user_id("xavier", xid);
  p = new_logged_in(88, "nn", "xavier", xid, 1);
  a = new_logged_in(89, "nn", "xavier", xid, 1);
  fsess.members[0] = p;
  fsess.members[1] = a;
  ircd_strncpy(fsess.kc_id, xid, sizeof(fsess.kc_id));
  who[0] = a;                                 /* #218: the alias */
  who[1] = p;                                 /* #219: the primary */

  for (m = 0; m < 2; m++) {
    struct Client *c = who[m];
    struct fake *f = fake_of(c);
    struct login_snap was;
    struct effects fx_was;

    snap(c, &was);
    fx_was = fx;
    token_for("yvonne", "yvonne");
    oauth_exchange(c, m ? INTROSPECT : LOCAL);
    assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");

    f->n_numerics = 0;
    fx_was = fx;
    token_for("xavier", "xavier");
    oauth_exchange(c, m ? LOCAL : INTROSPECT);
    assert_refreshed(c, &was, &fx_was);
    assert_int_equal(fx.adopts, fx_was.adopts);
  }

  {                     /* the alias knows no id of its own: the session's */
    struct login_snap was;
    struct effects fx_was;

    fake_of(a)->n_numerics = 0;
    cli_user(a)->kc_id[0] = '\0';
    snap(a, &was);
    fx_was = fx;
    token_for("xavier", "xavier-recreated");
    oauth_exchange(a, LOCAL);
    assert_refused(a, &was, &fx_was, ERR_SASLFAIL, "previous Keycloak user");
  }
}

/** A login registration has applied, waiting before registration is done
 * (a bouncer login held for burst convergence): logged in already.  Its
 * record stays whole -- a refused introspection's Keycloak-confirmed id
 * must not be what registration then reads (it lets a login end another
 * user's held session). */
static void reauth_while_registration_waits(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *c;
  int other;

  sasl_init_once();
  user_id("xavier", xid);
  for (other = 0; other < 2; other++) {
    struct login_snap was;
    struct effects fx_was;

    c = new_client(90 + other, "wai", 1, REG_KEEPS);
    cli_auth(c) = NULL;                     /* auth_complete_sasl() ran */
    ircd_strncpy(cli_user(c)->account, "xavier", sizeof(cli_user(c)->account));
    ircd_strncpy(cli_user(c)->kc_id, xid, sizeof(cli_user(c)->kc_id));
    SetAccount(c);
    sasl_identity_set(c, "xavier", 0, xid, 0);   /* a cached login */
    SetSASLComplete(c);
    CapSet(cli_active(c), CAP_STANDARDREPLIES);
    assert_false(IsRegistered(c));

    snap(c, &was);
    fx_was = fx;
    if (other)
      token_for("yvonne", "yvonne");
    else
      token_for("xavier", "xavier-recreated");
    oauth_exchange(c, INTROSPECT);
    assert_refused(c, &was, &fx_was,
                   other ? ERR_SASLALREADY : ERR_SASLFAIL,
                   other ? "logged in as xavier" : "previous Keycloak user");
    assert_int_equal(cli_saslkcidlive(c), 0);
  }
}

/** A client logged in through services (no SASL record, no id): another
 * account is refused, and its state stays: no SASL-complete flag, X3's
 * timestamp. */
static void reauth_after_services_login_refused(void **state)
{
  struct Client *c;
  struct login_snap was;
  struct effects fx_was;

  sasl_init_once();
  c = new_logged_in(92, "svc", "xavier", "", 0);
  snap(c, &was);
  fx_was = fx;
  token_for("yvonne", "yvonne");
  oauth_exchange(c, INTROSPECT);
  assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");
  assert_false(IsSASLComplete(c));
  assert_int_equal(cli_user(c)->acc_create, 1700000000);
}

/** A re-authentication that ends without a login -- aborted, or a token
 * Keycloak refuses -- leaves the login as it was, the SASL-complete flag
 * and the record included; the gate still stands after it. */
static void reauth_failed_or_aborted_keeps_login(void **state)
{
  const char msg[] = "n,,\001auth=Bearer opaque-token\001\001";
  char xid[ACCOUNT_ID_LEN + 1], data[300];
  struct Client *c;
  struct fake *f;
  struct login_snap was;
  struct effects fx_was;

  sasl_init_once();
  user_id("xavier", xid);

  c = new_logged_in(93, "xav", "xavier", xid, 1);    /* aborted */
  f = fake_of(c);
  snap(c, &was);
  fx_was = fx;
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  assert_int_equal(authenticate(c, "*"), 0);
  assert_true(has_numeric(f, ERR_SASLABORTED));
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_false(IsSASLReauth(c));
  assert_login_unchanged(c, &was);
  assert_nothing_announced(&fx_was);
  f->n_numerics = 0;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_true(has_numeric(f, ERR_SASLALREADY));

  c = new_logged_in(94, "xav", "xavier", xid, 1);    /* refused by Keycloak */
  f = fake_of(c);
  snap(c, &was);
  fx_was = fx;
  jwt_local_undecided = 1;
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver_kind(P_INTRO, KC_FORBIDDEN);          /* the error challenge */
  assert_int_equal(authenticate(c, "AQ=="), 0);
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_false(IsSASLReauth(c));
  assert_login_unchanged(c, &was);
  assert_nothing_announced(&fx_was);
  f->n_numerics = 0;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_true(has_numeric(f, ERR_SASLALREADY));
}

/** A REGISTER login is a login like a SASL one (draft/account-
 * registration: "as if it used SASL").  After registration a client
 * logged in by REGISTER SUCCESS refreshes with OAUTHBEARER like any other,
 * and a token for another account is refused -- the REGISTER login, its
 * REGISTER mark (FLAG_REGLOGIN) included, stays as it was.  Before
 * registration nothing is applied yet: OAUTHBEARER for another account
 * replaces the REGISTER login, as a second SASL login would. */
static void reauth_after_register_login(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    const char *acct = post ? "regb" : "rega";
    struct Client *c = post ? new_registered(96, "rg") : new_client(96, "rg", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char rid[ACCOUNT_ID_LEN + 1], yid[ACCOUNT_ID_LEN + 1];
    struct login_snap was;
    struct effects fx_was;

    CapSet(cli_active(c), CAP_STANDARDREPLIES);
    register_through(c, acct, "*");
    assert_identity(c, acct, user_id(acct, rid), 1);
    assert_true(HasFlag(c, FLAG_REGLOGIN));
    snap(c, &was);
    fx_was = fx;
    f->n_numerics = 0;
    token_for("yvonne", "yvonne");
    oauth_exchange(c, post ? LOCAL : INTROSPECT);
    if (!post) {
      assert_true(has_numeric(f, RPL_SASLSUCCESS));
      assert_identity(c, "yvonne", user_id("yvonne", yid), 1);
      assert_false(HasFlag(c, FLAG_REGLOGIN));
      continue;
    }
    assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as regb");
    assert_true(HasFlag(c, FLAG_REGLOGIN));

    f->n_numerics = 0;                     /* its own account: a refresh */
    token_for(acct, acct);
    oauth_exchange(c, LOCAL);
    assert_refreshed(c, &was, &fx_was);
    assert_string_equal(cli_user(c)->kc_id, rid);
    assert_false(HasFlag(c, FLAG_REGLOGIN));   /* now a SASL login's */
  }
}

/** A logged-in client's re-authentication that times out: 904, the
 * exchange gone with its re-authentication mark, the login as it was. */
static void reauth_timeout_keeps_login(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *c;
  struct fake *f;
  struct login_snap was;

  sasl_init_once();
  c = new_logged_in(97, "xav", "xavier", user_id("xavier", xid), 1);
  f = fake_of(c);
  snap(c, &was);
  assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
  assert_true(IsSASLReauth(c));
  assert_false(IsSASLExchangeDone(c));
  fire_timer(&cli_sasltimeout(c));
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_non_null(strstr(f->saslfail, "timed out"));
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_false(IsSASLReauth(c));
  assert_true(IsSASLExchangeDone(c));
  assert_login_unchanged(c, &was);
}

/** The two refusal notices are rate-limited apart: a client repeating the
 * "another account" refusal with a token of its own does not keep the
 * "previous Keycloak user" notice (the name-reuse signal) from the opers. */
static void reauth_notice_rates_apart(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *c;
  int sent;

  sasl_init_once();
  CurrentTime += 1000;                    /* past every earlier case's notice */
  c = new_logged_in(98, "xav", "xavier", user_id("xavier", xid), 1);
  sent = fx.oper_notices;
  token_for("yvonne", "yvonne");
  oauth_exchange(c, LOCAL);
  assert_int_equal(fx.oper_notices, sent + 1);
  oauth_exchange(c, LOCAL);                /* the same kind again: held back */
  assert_int_equal(fx.oper_notices, sent + 1);
  token_for("xavier", "xavier-recreated");
  oauth_exchange(c, LOCAL);                /* the other kind: told */
  assert_int_equal(fx.oper_notices, sent + 2);
}

/** A services success with no L before it, for a client logged in
 * through services (no login record): it completes as no account, and the
 * rule refuses it -- a success naming nothing is not the client's own
 * account. */
static void reauth_ds_without_l_refused(void **state)
{
  struct Client *c;
  struct login_snap was;
  struct effects fx_was;

  sasl_init_once();
  c = new_logged_in(99, "svc", "xavier", "", 0);
  snap(c, &was);
  fx_was = fx;
  cli_saslcookie(c) = 4242;                /* the relayed exchange */
  cli_saslstart(c) = CurrentTime;
  SetSASLReauth(c);
  assert_int_equal(sasl_complete_login(c, cli_saslaccount(c), 0, NULL, 0), 0);
  assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");
}

/** A refresh's login record is the login it refreshes, never downgraded
 * by the token: the client's own spelling (in the 900 too), the id kept
 * when the token has none, the timestamp kept unless the login brings one
 * (X3's stamp), the id-live mark kept when the token was only checked
 * locally and set when Keycloak confirms the same id now; an id the login
 * lacked is taken from the token (the transition). */
static void reauth_refresh_record(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  user_id("xavier", xid);

  /* SASL login, id confirmed (live): a token in another letter case,
   * checked locally, then one without a sub. */
  c = new_logged_in(100, "xav", "xavier", xid, 1);
  f = fake_of(c);
  token_for("XAVIER", "xavier");
  oauth_exchange(c, LOCAL);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_string_equal(f->loggedin_as, "xavier");
  assert_string_equal(cli_saslaccount(c), "xavier");
  assert_string_equal(cli_saslkcid(c), xid);
  assert_int_equal(cli_saslkcidlive(c), 1);          /* not cleared */
  assert_int_equal(cli_saslacccreate(c), 0);
  f->n_numerics = 0;
  token_for("xavier", NULL);
  oauth_exchange(c, LOCAL);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_string_equal(cli_saslkcid(c), xid);         /* not downgraded */
  assert_int_equal(cli_saslkcidlive(c), 1);
  assert_string_equal(cli_user(c)->kc_id, xid);

  /* A cached login (not live): Keycloak confirming the same id now sets
   * the mark; X3's stamp on a relayed refresh is taken, its missing id
   * is not a downgrade. */
  c = new_logged_in(101, "xav", "xavier", xid, 1);
  f = fake_of(c);
  cli_saslkcidlive(c) = 0;
  token_for("xavier", "xavier");
  oauth_exchange(c, INTROSPECT);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_int_equal(cli_saslkcidlive(c), 1);
  cli_saslcookie(c) = 4343;                         /* a relayed refresh */
  SetSASLReauth(c);
  SetFlag(c, FLAG_SASLREAUTHTOKEN);                 /* begun with OAUTHBEARER */
  assert_int_equal(sasl_complete_login(c, "xavier", 1600000000, NULL, 0), 0);
  assert_int_equal(cli_saslacccreate(c), 1600000000);
  assert_string_equal(cli_saslkcid(c), xid);
  assert_int_equal(cli_saslkcidlive(c), 1);
  assert_int_equal(cli_user(c)->acc_create, 0);      /* the login's own, as before */

  /* A services login (X3's spelling and stamp, no id): a token in
   * Keycloak's letter case refreshes it, keeps the name and the stamp,
   * and adopts the token's id, confirmed by introspection. */
  c = new_logged_in(102, "svc", "Xavier", "", 0);
  f = fake_of(c);
  token_for("xavier", "xavier");
  oauth_exchange(c, INTROSPECT);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_string_equal(f->loggedin_as, "Xavier");
  assert_string_equal(cli_user(c)->account, "Xavier");
  assert_string_equal(cli_saslaccount(c), "Xavier");
  assert_int_equal(cli_saslacccreate(c), 1700000000);
  assert_string_equal(cli_saslkcid(c), xid);
  assert_int_equal(cli_saslkcidlive(c), 1);
  assert_string_equal(cli_user(c)->kc_id, xid);       /* adopted, as before */
}

/** Names the ircd's casemapping folds together but Keycloak does not
 * (rfc1459: [ and {) are different accounts: refused whatever the ids
 * say, and no id is adopted onto the login or its session. */
static void reauth_casemapping_only_names_refused(void **state)
{
  char aid[ACCOUNT_ID_LEN + 1];
  int with_id;

  sasl_init_once();
  user_id("a[b", aid);
  for (with_id = 0; with_id < 2; with_id++) {
    struct Client *c = new_logged_in(103 + with_id, "ab", "a[b",
                                     with_id ? aid : "", with_id);
    struct login_snap was;
    struct effects fx_was;

    snap(c, &was);
    fx_was = fx;
    /* the token's sub: a{b's own, or (with ids) the very same id */
    token_for("a{b", with_id ? "a[b" : "a{b");
    oauth_exchange(c, with_id ? LOCAL : INTROSPECT);
    assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as a[b");
    assert_string_equal(cli_user(c)->kc_id, with_id ? aid : "");
    assert_int_equal(fx.alias_syncs, fx_was.alias_syncs);
  }
}

/** A refresh leaves the host as the client has it: a client that did -x
 * keeps its real host (the login's hidden-host step is a first login's). */
static void reauth_refresh_keeps_minus_x(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *c;

  sasl_init_once();
  bed_features = 1;                        /* host hiding style 1, autohide */
  c = new_logged_in(105, "xav", "xavier", user_id("xavier", xid), 1);
  ClearHiddenHost(c);                      /* MODE -x */
  token_for("xavier", "xavier");
  oauth_exchange(c, LOCAL);
  assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
  assert_false(IsHiddenHost(c));
  bed_features = 0;
}

/** A logged-in client's OAUTHBEARER that went to services (Keycloak was
 * unhealthy: a cookie, no local session), then Keycloak back: its next
 * AUTHENTICATE line is that exchange's data, never a new local exchange
 * -- "PLAIN" there passed the OAUTHBEARER-only check, which reads only a
 * line with no cookie.  The account cannot change either way: credentials
 * for another account, had they reached a local login, are refused by
 * the rule (reauth_other_account_refused). */
static void reauth_relayed_exchange_takes_no_local_exchange(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1], data[300];
  struct Client *c;
  struct fake *f;
  struct login_snap was;
  int requests;

  sasl_init_once();
  c = new_logged_in(106, "xav", "xavier", user_id("xavier", xid), 1);
  f = fake_of(c);
  snap(c, &was);
  cli_saslcookie(c) = 5151;                /* the relayed exchange */
  cli_saslstart(c) = CurrentTime;
  SetSASLReauth(c);
  requests = kc_requests;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_null(cli_saslsession(c));         /* no local exchange */
  assert_false(has_numeric(f, ERR_SASLALREADY));
  plain_b64("yvonne", "yvonnepw", data);
  assert_int_equal(authenticate(c, data), 0);
  assert_null(cli_saslsession(c));
  assert_int_equal(kc_requests, requests); /* Keycloak never asked */
  assert_false(has_numeric(f, RPL_LOGGEDIN));
  assert_int_equal(cli_saslcookie(c), 5151);
  assert_login_unchanged(c, &was);
}

/** Before registration a login is not applied yet: a client may log in
 * again with OAUTHBEARER, as another account, and registration takes the
 * last login (SASL 3.1; the REGISTER cases above pin the rest). */
static void pre_registration_switch_allowed(void **state)
{
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char yid[ACCOUNT_ID_LEN + 1], data[300];
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = login_then_restart(95);              /* liz, then OAUTHBEARER */
  f = fake_of(c);
  token_for("yvonne", "yvonne");
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  assert_int_equal(authenticate(c, data), 0);
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_identity(c, "yvonne", user_id("yvonne", yid), 0);   /* a local check */
  f->cap_done = 1;                         /* CAP END: it registers as yvonne */
  assert_int_equal(auth_sasl_done(cli_auth(c)), 0);
  assert_int_equal(f->registered, 1);
}

/* ------------------------------------------------------------------ */
/* 905: an over-long line ends the exchange, as 904 does (#221)         */
/* ------------------------------------------------------------------ */

/** A parameter longer than 400 bytes. */
static const char *too_long(void)
{
  static char line[402];
  memset(line, 'A', 401);
  line[401] = '\0';
  return line;
}

/** The exchange is gone: no local session, no cookie, no hold. */
static void assert_no_exchange(struct Client *c)
{
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_int_equal(fake_of(c)->hold, 0);
}

/** Local tier: 905, the exchange ended (no 906 then or later), and the
 * client's next AUTHENTICATE <mechanism> starts a new one. */
static void toolong_ends_local_exchange(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(40, "tl", 0, REG_KEEPS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_non_null(cli_saslsession(c));
  f->raw[0] = '\0';

  assert_int_equal(authenticate(c, too_long()), 0);
  assert_true(has_numeric(f, ERR_SASLTOOLONG));
  assert_false(has_numeric(f, ERR_SASLABORTED));
  assert_false(has_numeric(f, ERR_SASLFAIL));
  assert_no_exchange(c);

  assert_int_equal(authenticate(c, "PLAIN"), 0);   /* a new exchange */
  assert_non_null(cli_saslsession(c));
  assert_string_equal(f->raw, "AUTHENTICATE +");
}

/** Local tier, CAP END already sent: the end lets registration go on
 * inside the line, and the handler hands the parser what it did. */
static void toolong_local_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(41, "tx", 1, REG_EXITS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, too_long()), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** ... and a client registration keeps is registered once. */
static void toolong_local_registration_keeps(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(42, "tk", 1, REG_KEEPS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(f->registered, 0);              /* held by the exchange */
  assert_int_equal(authenticate(c, too_long()), 0);
  assert_int_equal(f->registered, 1);
  assert_no_exchange(c);
}

/** The total-length limit (the local tier's): 905, and the exchange ends
 * there too; the client can start again. */
static void total_limit_ends_local_exchange(void **state)
{
  struct Client *c;
  struct fake *f;
  char chunk[401];
  int i, rc = 0;

  sasl_init_once();
  c = new_client(43, "tt", 0, REG_KEEPS);
  f = fake_of(c);
  memset(chunk, 'A', 400);
  chunk[400] = '\0';
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  for (i = 0; i < 64 && !has_numeric(f, ERR_SASLTOOLONG); i++)
    rc = authenticate(c, chunk);
  assert_int_equal(rc, 0);
  assert_true(has_numeric(f, ERR_SASLTOOLONG));
  assert_false(has_numeric(f, ERR_SASLABORTED));
  assert_no_exchange(c);
  f->raw[0] = '\0';
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_string_equal(f->raw, "AUTHENTICATE +");
}

/** No exchange in progress: 905 and nothing else. */
static void toolong_without_exchange(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  c = new_client(44, "tn", 0, REG_KEEPS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, too_long()), 0);
  assert_int_equal(f->n_numerics, 1);
  assert_int_equal(f->numerics[0], ERR_SASLTOOLONG);
  assert_int_equal(abort_reply, -1);
  assert_no_exchange(c);
}

/** Services (P10) tier: services are told to drop it (abort_sasl()) with
 * no further reply to the client, registration goes on, and the next
 * AUTHENTICATE starts a new exchange (a new cookie). */
static void toolong_ends_services_exchange(void **state)
{
  struct Client *c;
  struct fake *f;
  unsigned int first;

  sasl_init_once();
  local_off = 1;
  c = new_client(45, "ts", 1, REG_KEEPS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_null(cli_saslsession(c));
  first = cli_saslcookie(c);
  assert_true(first != 0);
  assert_int_equal(f->registered, 0);

  assert_int_equal(authenticate(c, too_long()), 0);
  assert_true(has_numeric(f, ERR_SASLTOOLONG));
  assert_int_equal(abort_reply, SASL_ABORT_REPLY_NONE);
  assert_no_exchange(c);
  assert_int_equal(f->registered, 1);

  cli_auth(c) = (struct AuthRequest *)&f->auth;    /* a later exchange */
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_true(cli_saslcookie(c) != 0 && cli_saslcookie(c) != first);
}

/** ... and an exit there is handed to the parser. */
static void toolong_services_registration_exits(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  local_off = 1;
  c = new_client(46, "tz", 1, REG_EXITS);
  f = fake_of(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, too_long()), CPTR_KILLED);
  assert_true(f->freed);
  assert_int_equal(f->touched_after_free, 0);
}

/** IAuth tier: the program is told A X, no further reply goes to the
 * client, registration goes on (and an exit is handed to the parser), and
 * the next AUTHENTICATE starts a new exchange with a new A S. */
static void toolong_ends_iauth_exchange(void **state)
{
  struct Client *c;
  struct fake *f;
  int keep;

  sasl_init_once();
  for (keep = 1; keep >= 0; keep--) {
    local_off = 1;
    iauth_on = 1;
    iauth_starts = iauth_aborts = 0;
    abort_reply = -1;
    c = new_client(48 + keep, keep ? "ik" : "ix", 1, keep ? REG_KEEPS : REG_EXITS);
    f = fake_of(c);
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(iauth_starts, 1);
    assert_true(cli_saslcookie(c) != 0);
    assert_int_equal(f->registered, 0);
    if (!keep) {
      assert_int_equal(authenticate(c, too_long()), CPTR_KILLED);
      assert_true(f->freed);
      assert_int_equal(f->touched_after_free, 0);
      assert_int_equal(iauth_aborts, 1);
      continue;
    }
    assert_int_equal(authenticate(c, too_long()), 0);
    assert_true(has_numeric(f, ERR_SASLTOOLONG));
    assert_false(has_numeric(f, ERR_SASLABORTED));
    assert_int_equal(iauth_aborts, 1);
    assert_int_equal(abort_reply, SASL_ABORT_REPLY_NONE);
    assert_no_exchange(c);
    assert_int_equal(f->registered, 1);
    cli_auth(c) = (struct AuthRequest *)&f->auth;   /* a later exchange */
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(iauth_starts, 2);
  }
}

/** AUTHENTICATE * still answers 906 in the services tier (the shared end). */
static void star_abort_services_exchange(void **state)
{
  struct Client *c;

  sasl_init_once();
  local_off = 1;
  c = new_client(47, "ta", 0, REG_KEEPS);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, "*"), 0);
  assert_int_equal(abort_reply, SASL_ABORT_REPLY_ABORTED);
  assert_no_exchange(c);
}

/** e. account-notify (#220): a login after connection registration -- a
 * SASL PLAIN, a REGISTER -- tells the user itself ("including
 * themselves"), once; before registration nothing is sent (the
 * registration burst says who the client is). */
static void flow_login_tells_the_user(void **state)
{
  int post;

  sasl_init_once();
  for (post = 0; post < 2; post++) {
    struct Client *c = post ? new_registered(69, "fe2") : new_client(68, "fe1", 0, REG_KEEPS);
    struct Client *r = post ? new_registered(71, "ff2") : new_client(70, "ff1", 0, REG_KEEPS);

    n_an = 0;
    plain_pending(c, post ? "eve2" : "eve1", "evepw");
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    register_through(r, post ? "nf2" : "nf1", "*");
    assert_non_null(strstr(fake_of(r)->raw, "REGISTER SUCCESS"));
    if (!post) {
      assert_int_equal(n_an, 0);
      continue;
    }
    assert_int_equal(n_an, 2);
    assert_ptr_equal(an_about[0], c);
    assert_true(an_self[0]);
    assert_ptr_equal(an_about[1], r);
    assert_true(an_self[1]);
  }
}

/** #220 with #223: a logged-in client's re-authentication that is
 * REFUSED (another account) changes no account, so no account-notify goes
 * to anyone -- the user included (the session form would reach it); a
 * same-account refresh changes nothing either, and says nothing. */
static void reauth_tells_nobody_account(void **state)
{
  enum strategy how;

  sasl_init_once();
  for (how = LOCAL; how <= INTROSPECT; how++) {
    char xid[ACCOUNT_ID_LEN + 1];
    struct Client *c = new_logged_in(86 + how, "xav", "xavier",
                                     user_id("xavier", xid), 1);

    n_an = 0;
    token_for("yvonne", "yvonne");
    oauth_exchange(c, how);
    assert_false(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_string_equal(cli_user(c)->account, "xavier");
    assert_int_equal(n_an, 0);

    token_for("xavier", "xavier");
    oauth_exchange(c, how);
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_int_equal(n_an, 0);
  }
}

/* ------------------------------------------------------------------ */
/* SASL 3.1 for a connection that never sent CAP LS 302                */
/* ------------------------------------------------------------------ */

/* sasl-3.1: AUTHENTICATE "MUST be used before registration is complete",
 * and after a successful authentication the server "MUST reject it with a
 * 907 numeric".  SASL 3.2 (SASL on CAP 302) adds re-authentication at any
 * time.  A connection is a 3.2 client only once it has sent CAP LS with a
 * version of 302 or more (a later CAP LS never lowers it,
 * cap_version_after_ls()); any other gets stock master's 3.1 answers:
 *   after registration: 462 for every line, as master's command table
 *     answers (m_registered()) -- logged in or not, every mechanism,
 *     nothing reaches any tier and nothing changes;
 *   before registration, after a login (903, or an account it holds):
 *     907 for every mechanism, OAUTHBEARER included;
 *   before registration with nothing done: an exchange starts. */

/** The CAP LS lines a connection sent. */
enum cap_row { ROW_NO_LS, ROW_LS, ROW_LS301, ROW_LS302, ROW_LS302_THEN_LS, NROWS };

static const char *const row_name[NROWS] = {
  "no CAP LS", "CAP LS", "CAP LS 301", "CAP LS 302", "CAP LS 302, then CAP LS"
};

/** \a c, a new connection, sends the CAP LS lines of \a row: its
 * version, as cap_ls() keeps it. */
static void cap_ls_lines(struct Client *c, enum cap_row row)
{
  cli_capab_version(c) = 0;                    /* none sent yet */
  switch (row) {
  case ROW_NO_LS:
    break;
  case ROW_LS:
    cli_capab_version(c) = cap_version_after_ls(cli_capab_version(c), NULL);
    break;
  case ROW_LS301:
    cli_capab_version(c) = cap_version_after_ls(cli_capab_version(c), "301");
    break;
  case ROW_LS302:
    cli_capab_version(c) = cap_version_after_ls(cli_capab_version(c), "302");
    break;
  case ROW_LS302_THEN_LS:
    cli_capab_version(c) = cap_version_after_ls(cli_capab_version(c), "302");
    cli_capab_version(c) = cap_version_after_ls(cli_capab_version(c), NULL);
    break;
  default:
    fail();
  }
}

/** The state the connection is in when it sends AUTHENTICATE. */
enum sasl_col { COL_PRE_NOTHING, COL_PRE_AFTER_903, COL_POST_LOGGED_IN,
                COL_POST_NO_LOGIN, NCOLS };

static const char *const col_name[NCOLS] = {
  "before registration, nothing done", "before registration, after 903",
  "after registration, logged in", "after registration, not logged in"
};

/** A connection on \a fd in state \a col, having sent \a row's CAP LS
 * lines, standard-replies on. */
static struct Client *sasl31_client(int fd, enum cap_row row, enum sasl_col col)
{
  static int pwn;
  struct Client *c = NULL;
  char data[300], pw[16], xid[ACCOUNT_ID_LEN + 1];

  switch (col) {
  case COL_PRE_NOTHING:
    c = new_client(fd, "tc", 0, REG_KEEPS);
    break;
  case COL_PRE_AFTER_903:
    c = new_client(fd, "tc", 0, REG_KEEPS);
    cap_ls_lines(c, row);
    snprintf(pw, sizeof(pw), "t31pw%d", ++pwn);   /* uncached: Keycloak answers */
    plain_b64("liz", pw, data);
    kc_mode = KC_LATER;
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, data), 0);
    pend_deliver(1);
    run_event_loop();
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_true(IsSASLComplete(c));
    assert_false(IsRegistered(c));
    break;
  case COL_POST_LOGGED_IN:
    c = new_logged_in(fd, "tc", "xavier", user_id("xavier", xid), 1);
    break;
  case COL_POST_NO_LOGIN:
    c = new_registered(fd, "tc");
    break;
  default:
    fail();
  }
  CapSet(cli_active(c), CAP_STANDARDREPLIES);
  if (col != COL_PRE_AFTER_903)
    cap_ls_lines(c, row);
  fake_of(c)->n_numerics = 0;
  fake_of(c)->fail_code[0] = '\0';
  fake_of(c)->raw[0] = '\0';
  return c;
}

/** What one AUTHENTICATE <mechanism> got. */
enum sasl_answer { ANS_STARTED, ANS_907, ANS_462 };

/** What \a row x \a col x \a mech must get. */
static enum sasl_answer sasl31_expected(enum cap_row row, enum sasl_col col,
                                        int oauth)
{
  int v302 = (row == ROW_LS302 || row == ROW_LS302_THEN_LS);

  switch (col) {
  case COL_PRE_NOTHING:
    return ANS_STARTED;
  case COL_PRE_AFTER_903:
    return (v302 && oauth) ? ANS_STARTED : ANS_907;
  case COL_POST_LOGGED_IN:
    if (!v302)
      return ANS_462;
    return oauth ? ANS_STARTED : ANS_907;
  case COL_POST_NO_LOGIN:
  default:
    return v302 ? ANS_STARTED : ANS_462;
  }
}

/** The whole matrix: every CAP LS row, every state, PLAIN and
 * OAUTHBEARER, through the local tier. */
static void sasl31_matrix(void **state)
{
  int row, col, oauth, fd = 110;

  sasl_init_once();
  for (row = 0; row < NROWS; row++)
    for (col = 0; col < NCOLS; col++)
      for (oauth = 0; oauth < 2; oauth++) {
        const char *mech = oauth ? "OAUTHBEARER" : "PLAIN";
        enum sasl_answer want = sasl31_expected(row, col, oauth);
        struct Client *c = sasl31_client(fd, row, col);
        struct fake *f = fake_of(c);
        struct login_snap was;
        struct effects fx_was;
        int requests = kc_requests, ntimers_was;

        fd = fd < 117 ? fd + 1 : 110;
        print_message("  %s / %s / %s\n", row_name[row], col_name[col], mech);
        ntlog = 0;
        snap(c, &was);
        fx_was = fx;
        ntimers_was = t_active(&cli_sasltimeout(c)) ? 1 : 0;
        assert_int_equal(authenticate(c, mech), 0);
        assert_int_equal(kc_requests, requests);       /* none at a start */
        switch (want) {
        case ANS_STARTED:
          assert_int_equal(f->n_numerics, 0);
          assert_non_null(cli_saslsession(c));
          assert_true(cli_saslcookie(c) != 0);
          assert_string_equal(f->raw, "AUTHENTICATE +");
          /* in flight beside a login it keeps until it succeeds */
          assert_int_equal(IsSASLReauth(c) ? 1 : 0,
                           col == COL_POST_LOGGED_IN || col == COL_PRE_AFTER_903);
          /* end it, so the next case starts clean */
          assert_int_equal(authenticate(c, "*"), 0);
          assert_true(has_numeric(f, ERR_SASLABORTED));
          assert_null(cli_saslsession(c));
          break;
        case ANS_907:
          assert_int_equal(f->n_numerics, 1);
          assert_int_equal(f->numerics[0], ERR_SASLALREADY);
          assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
          assert_null(cli_saslsession(c));
          assert_int_equal(cli_saslcookie(c), 0);
          assert_false(IsSASLReauth(c));
          assert_login_unchanged(c, &was);
          assert_nothing_announced(&fx_was);
          break;
        case ANS_462:
          assert_int_equal(f->n_numerics, 1);
          assert_int_equal(f->numerics[0], ERR_ALREADYREGISTRED);
          assert_string_equal(f->fail_code, "");     /* master sends no FAIL */
          assert_string_equal(f->raw, "");
          assert_null(cli_saslsession(c));
          assert_int_equal(cli_saslcookie(c), 0);
          assert_false(IsSASLReauth(c));
          assert_int_equal(t_active(&cli_sasltimeout(c)) ? 1 : 0, ntimers_was);
          assert_login_unchanged(c, &was);
          assert_nothing_announced(&fx_was);
          break;
        }
      }
}

/** After registration a non-302 connection gets 462 for every line --
 * the mechanism, its data, "*", a line with no parameter, a line from a
 * connection that never negotiated sasl -- and nothing reaches any tier:
 * not Keycloak (a whole same-account OAUTHBEARER refresh), not IAuth, not
 * services. */
static void sasl31_registered_every_line_462(void **state)
{
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char xid[ACCOUNT_ID_LEN + 1], data[300];
  char *parv[2];
  struct Client *c;
  struct fake *f;
  struct login_snap was;
  struct effects fx_was;
  int tier, requests, i;

  sasl_init_once();
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  for (tier = 0; tier < 3; tier++) {          /* local, IAuth, services */
    local_off = tier > 0;
    iauth_on = tier == 1;
    iauth_starts = iauth_datas = iauth_aborts = 0;
    c = new_logged_in(120 + tier, "xav", "xavier", user_id("xavier", xid), 1);
    f = fake_of(c);
    cap_ls_lines(c, ROW_LS);
    snap(c, &was);
    fx_was = fx;
    requests = kc_requests;
    ntlog = 0;
    token_for("xavier", "xavier");              /* its own account */
    jwt_local_undecided = 0;
    kc_mode = KC_LATER;
    assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
    assert_int_equal(authenticate(c, data), 0);
    assert_int_equal(authenticate(c, "+"), 0);
    assert_int_equal(authenticate(c, "*"), 0);
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    parv[0] = cli_name(c);
    parv[1] = NULL;
    assert_int_equal(m_authenticate(c, c, 1, parv), 0);  /* no parameter */
    CapClr(cli_active(c), CAP_SASL);
    assert_int_equal(authenticate(c, "PLAIN"), 0);       /* no sasl cap */

    assert_int_equal(f->n_numerics, 7);
    for (i = 0; i < 7; i++)
      assert_int_equal(f->numerics[i], ERR_ALREADYREGISTRED);
    assert_string_equal(f->fail_code, "");
    assert_int_equal(kc_requests, requests);     /* Keycloak never asked */
    assert_int_equal(iauth_starts + iauth_datas + iauth_aborts, 0);
    assert_false(tlog_has_prefix("servers"));    /* nothing to services */
    assert_null(cli_saslsession(c));
    assert_int_equal(cli_saslcookie(c), 0);
    assert_false(IsSASLReauth(c));
    assert_login_unchanged(c, &was);
    assert_nothing_announced(&fx_was);
    assert_int_equal(fx.oper_notices_tried, fx_was.oper_notices_tried);
  }
  local_off = iauth_on = 0;
}

/** The same through the IAuth and services tiers, not logged in: 462, no
 * exchange started anywhere.  A 302 connection there starts one, as
 * before. */
static void sasl31_registered_other_tiers(void **state)
{
  int tier, v302;

  for (tier = 1; tier < 3; tier++)
    for (v302 = 0; v302 < 2; v302++) {
      struct Client *c = new_registered(124 + 2 * (tier - 1) + v302, "rr");
      struct fake *f = fake_of(c);

      local_off = 1;
      iauth_on = tier == 1;
      iauth_starts = 0;
      ntlog = 0;
      cap_ls_lines(c, v302 ? ROW_LS302 : ROW_LS301);
      assert_int_equal(authenticate(c, "PLAIN"), 0);
      if (!v302) {
        assert_int_equal(f->n_numerics, 1);
        assert_int_equal(f->numerics[0], ERR_ALREADYREGISTRED);
        assert_int_equal(iauth_starts, 0);
        assert_false(tlog_has_prefix("servers"));
        assert_int_equal(cli_saslcookie(c), 0);
        continue;
      }
      assert_int_equal(f->n_numerics, 0);
      assert_true(cli_saslcookie(c) != 0);       /* the exchange started */
      if (tier == 1)
        assert_int_equal(iauth_starts, 1);
      else
        assert_true(tlog_has_prefix("servers SASL"));
      assert_int_equal(authenticate(c, "*"), 0);  /* ended */
      assert_int_equal(cli_saslcookie(c), 0);
    }
  local_off = iauth_on = 0;
}

/** Before registration, a non-302 connection that holds an account
 * without a SASL login -- an account set before registration (WEBIRC, a
 * services login-on-connect) or a REGISTER login -- gets 907 for
 * OAUTHBEARER too; a 302 connection may still start one, as before. */
static void sasl31_pre_registration_account_held(void **state)
{
  int how, v302;

  sasl_init_once();
  for (how = 0; how < 2; how++)
    for (v302 = 0; v302 < 2; v302++) {
      struct Client *c = new_client(126 + 2 * how + v302, "ah", 0, REG_KEEPS);
      struct fake *f = fake_of(c);
      char rid[ACCOUNT_ID_LEN + 1];

      CapSet(cli_active(c), CAP_STANDARDREPLIES);
      cap_ls_lines(c, v302 ? ROW_LS302 : ROW_NO_LS);
      if (how == 0) {                        /* an account given before */
        ircd_strncpy(cli_user(c)->account, "webacct", sizeof(cli_user(c)->account));
        SetAccount(c);
      } else {                               /* REGISTER SUCCESS */
        register_through(c, "rga", "*");
        assert_identity(c, "rga", user_id("rga", rid), 1);
      }
      f->n_numerics = 0;
      f->fail_code[0] = '\0';
      assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
      if (!v302) {
        assert_int_equal(f->n_numerics, 1);
        assert_int_equal(f->numerics[0], ERR_SASLALREADY);
        assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
        assert_null(cli_saslsession(c));
        assert_int_equal(cli_saslcookie(c), 0);
        if (how == 0)
          assert_true(IsAccount(c));
        else
          assert_identity(c, "rga", rid, 1);  /* the login untouched */
        continue;
      }
      assert_int_equal(f->n_numerics, 0);
      assert_non_null(cli_saslsession(c));
      assert_int_equal(authenticate(c, "*"), 0);
      assert_null(cli_saslsession(c));
    }
}

/** sasl-3.1: "If authentication fails, a 904 or 905 numeric will be sent
 * and the client MAY retry".  A non-302 connection whose exchange failed
 * (904) or was aborted (906) starts another; once one succeeds (903), any
 * further AUTHENTICATE is 907. */
static void sasl31_retry_after_failure_then_907(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];
  const char *mechs[2] = { "PLAIN", "OAUTHBEARER" };
  int m;

  sasl_init_once();
  c = new_client(127, "rt", 0, REG_KEEPS);
  f = fake_of(c);
  cap_ls_lines(c, ROW_LS);

  plain_b64("liz", "t31bad", data);           /* 904 */
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(0);
  run_event_loop();
  assert_true(has_numeric(f, ERR_SASLFAIL));
  assert_false(IsSASLComplete(c));

  f->n_numerics = 0;                          /* a retry, then 906 */
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(f->n_numerics, 0);
  assert_non_null(cli_saslsession(c));
  assert_int_equal(authenticate(c, "*"), 0);
  assert_true(has_numeric(f, ERR_SASLABORTED));

  f->n_numerics = 0;                          /* another retry: 903 */
  plain_b64("liz", "t31good", data);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(f->n_numerics, 0);
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver(1);
  run_event_loop();
  assert_true(has_numeric(f, RPL_SASLSUCCESS));

  for (m = 0; m < 2; m++) {                   /* then 907, any mechanism */
    f->n_numerics = 0;
    assert_int_equal(authenticate(c, mechs[m]), 0);
    assert_int_equal(f->n_numerics, 1);
    assert_int_equal(f->numerics[0], ERR_SASLALREADY);
    assert_true(IsSASLComplete(c));
    assert_string_equal(cli_saslaccount(c), "liz");
  }
}

/* ------------------------------------------------------------------ */
/* SASL_REAUTH: refresh, same, any                                      */
/* ------------------------------------------------------------------ */

/* For a REGISTERED, LOGGED-IN SASL 3.2 client (owner's rulings,
 * 2026-11-15):
 *   setting  mechanism    proves            outcome
 *   refresh  not a token  --                907 at the start
 *   refresh  OAUTHBEARER  its own account   a refresh
 *   refresh  OAUTHBEARER  another account   907
 *   same     any          its own account   a refresh
 *   same     any          another account   907
 *   any      any          its own account   a refresh
 *   any      any          another account   the account CHANGES -- not for
 *                                           a bouncer session's connection
 *   every    any          its name, another Keycloak id   904
 *   every    any          (fails)           the login stands
 * The setting is read at the start and again at the completion (a REHASH
 * between: the completion decides). */

static const char *const settings[] = { "refresh", "same", "any" };

/** A registered client logged in to xavier (its Keycloak id), CAP 302,
 * standard-replies, in no bouncer session, on a server with the bed's
 * account features (EXTENDED_ACCOUNTS: an account change is carried). */
static struct Client *xavier_client(int fd)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *c = new_logged_in(fd, "xav", "xavier", user_id("xavier", xid), 1);

  bed_features = 1;
  ircd_strncpy(cli_active_profile(c), "laptop",       /* PERSISTENCE ATTACH */
               sizeof(con_active_profile(cli_connect(c))));
  fake_of(c)->n_numerics = 0;
  fake_of(c)->fail_code[0] = fake_of(c)->fail_desc[0] = '\0';
  ntlog = 0;
  return c;
}

/** A PLAIN re-authentication of \a c as \a user, Keycloak answering it (a
 * fresh password each time: no cache).  0 when the start was refused. */
static int plain_exchange(struct Client *c, const char *user, int ok)
{
  static int n;
  char data[300], pw[24];

  snprintf(pw, sizeof(pw), "ra%d", ++n);
  plain_b64(user, pw, data);
  kc_mode = KC_LATER;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  if (!cli_saslsession(c))
    return 0;
  assert_int_equal(authenticate(c, data), 0);
  pend_deliver_kind(P_TOKEN, ok ? KC_SUCCESS : KC_ERROR);
  run_event_loop();
  return 1;
}

/** One re-authentication of \a c, by \a mech, proving \a user (Keycloak
 * id of \a sub_of). */
static int reauth_as(struct Client *c, const char *mech, const char *user,
                     const char *sub_of)
{
  if (!strcmp(mech, "PLAIN")) {
    assert_string_equal(user, sub_of);      /* a grant's id is the user's */
    return plain_exchange(c, user, 1);
  }
  token_for(user, sub_of);
  oauth_exchange(c, LOCAL);
  return 1;
}

/** \a c's account changed from \a was to \a account (Keycloak id of
 * \a account): 900/903, the network told "AC <nick> M <account> 0 <id>"
 * (the slot always there), the channels and the user told, the new
 * account's metadata loaded, presence moved without carrying the old
 * window, the hidden host recomputed, the record the new login's. */
static void assert_switched(struct Client *c, const struct login_snap *was,
                            const struct effects *fx_was, const char *account)
{
  struct fake *f = fake_of(c);
  char id[ACCOUNT_ID_LEN + 1], line[TLOG_LEN], meta[TLOG_LEN], pres[TLOG_LEN];

  user_id(account, id);
  assert_true(has_numeric(f, RPL_LOGGEDIN));
  assert_true(has_numeric(f, RPL_SASLSUCCESS));
  assert_false(has_numeric(f, ERR_SASLFAIL));
  assert_false(has_numeric(f, ERR_SASLALREADY));
  assert_string_equal(f->loggedin_as, account);
  assert_true(IsAccount(c));
  assert_string_equal(cli_user(c)->account, account);
  assert_string_equal(cli_user(c)->kc_id, id);
  assert_int_equal(cli_user(c)->acc_create, 0);
  assert_string_equal(cli_saslaccount(c), account);
  assert_string_equal(cli_saslkcid(c), id);
  assert_true(IsSASLComplete(c));
  assert_false(IsSASLReauth(c));
  assert_null(cli_saslsession(c));
  assert_int_equal(cli_saslcookie(c), 0);
  snprintf(line, sizeof(line), "servers AC %s M %s 0 %s", cli_name(c), account, id);
  assert_true(tlog_has(line));
  snprintf(meta, sizeof(meta), "metadata load %s %s", cli_name(c), account);
  assert_true(tlog_has(meta));
  snprintf(pres, sizeof(pres), "presence %s %s/0 -> %s/0 (no carry)", cli_name(c),
           was->account, account);
  assert_true(tlog_has(pres));
  assert_int_equal(fx.notifies, fx_was->notifies + 1);
  assert_int_equal(fx.broadcasts, fx_was->broadcasts + 1);
  assert_int_equal(fx.hostmasks, fx_was->hostmasks + (was->hidden ? 1 : 0));
  assert_int_equal(fx.account_adjusts, fx_was->account_adjusts);  /* counted */
  assert_int_equal(IsHiddenHost(c) ? 1 : 0, was->hidden);
  /* The connection's mode-synced state is the new account's, derived as
   * for a connection that had no account (no flag kept from the old
   * account's rows), and its persistence profile is no longer the old
   * account's. */
  snprintf(line, sizeof(line), "mode rederive %s", cli_name(c));
  assert_true(tlog_has(line));
  /* What account bans (~a:) match changed: the cached verdicts go. */
  snprintf(line, sizeof(line), "ban cache %s", cli_name(c));
  assert_true(tlog_has(line));
  snprintf(line, sizeof(line), "mode restore %s 1", cli_name(c));
  assert_false(tlog_has(line));
  assert_string_equal(cli_active_profile(c), "");
}

/** The whole table for a registered, logged-in client not in a session:
 * {refresh, same, any} x {PLAIN, OAUTHBEARER} x {its own account,
 * another}. */
static void reauth_setting_table(void **state)
{
  int s, m, other, fd = 130;
  const char *mechs[2] = { "PLAIN", "OAUTHBEARER" };

  sasl_init_once();
  for (s = 0; s < 3; s++)
    for (m = 0; m < 2; m++)
      for (other = 0; other < 2; other++) {
        struct Client *c;
        struct login_snap was;
        struct effects fx_was;
        int started;

        reauth_setting = settings[s];
        c = xavier_client(fd);
        fd = fd < 137 ? fd + 1 : 130;
        print_message("  SASL_REAUTH %s / %s / %s\n", settings[s], mechs[m],
                      other ? "another account" : "its own account");
        snap(c, &was);
        fx_was = fx;
        started = reauth_as(c, mechs[m], other ? "yvonne" : "xavier",
                            other ? "yvonne" : "xavier");
        if (s == 0 && m == 0) {             /* refresh, PLAIN: refused at the start */
          assert_false(started);
          assert_int_equal(fake_of(c)->n_numerics, 1);
          assert_int_equal(fake_of(c)->numerics[0], ERR_SASLALREADY);
          assert_string_equal(fake_of(c)->fail_code, "ALREADY_AUTHENTICATED");
          assert_login_unchanged(c, &was);
          assert_nothing_announced(&fx_was);
          continue;
        }
        if (!other) {
          assert_refreshed(c, &was, &fx_was);
          assert_false(tlog_has_prefix("servers AC"));   /* no AC line */
          assert_false(tlog_has_prefix("ban cache"));    /* nothing changed */
          assert_string_equal(cli_user(c)->kc_id, was.kc_id);
          continue;
        }
        if (s < 2) {
          assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");
          continue;
        }
        assert_switched(c, &was, &fx_was, "yvonne");
      }
}

/** The same name under ANOTHER Keycloak id is refused with 904 under every
 * setting, by either mechanism; a re-authentication that fails leaves the
 * login as it was under every setting. */
static void reauth_setting_other_id_and_failure(void **state)
{
  int s;

  sasl_init_once();
  for (s = 0; s < 3; s++) {
    struct Client *c;
    struct login_snap was;
    struct effects fx_was;
    char oid[ACCOUNT_ID_LEN + 1];

    reauth_setting = settings[s];
    c = xavier_client(140);               /* OAUTHBEARER, xavier made again */
    snap(c, &was);
    fx_was = fx;
    token_for("xavier", "xavier-recreated");
    oauth_exchange(c, LOCAL);
    assert_refused(c, &was, &fx_was, ERR_SASLFAIL, "previous Keycloak user");

    if (s > 0) {                          /* PLAIN, the same (refresh: no PLAIN) */
      c = new_logged_in(141, "xav", "xavier", user_id("xavier-old", oid), 1);
      fake_of(c)->n_numerics = 0;
      ntlog = 0;
      snap(c, &was);
      fx_was = fx;
      assert_int_equal(plain_exchange(c, "xavier", 1), 1);
      assert_refused(c, &was, &fx_was, ERR_SASLFAIL, "previous Keycloak user");
    }

    c = xavier_client(142);               /* a failure: Keycloak refuses */
    snap(c, &was);
    fx_was = fx;
    if (s > 0)
      assert_int_equal(plain_exchange(c, "yvonne", 0), 1);
    else {
      const char msg[] = "n,,\001auth=Bearer opaque-token\001\001";
      char data[300];

      jwt_local_undecided = 1;
      b64((const unsigned char *)msg, sizeof(msg) - 1, data);
      assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
      assert_int_equal(authenticate(c, data), 0);
      pend_deliver_kind(P_INTRO, KC_FORBIDDEN);
      assert_int_equal(authenticate(c, "AQ=="), 0);
    }
    assert_true(has_numeric(fake_of(c), ERR_SASLFAIL));
    assert_false(has_numeric(fake_of(c), RPL_LOGGEDIN));
    assert_null(cli_saslsession(c));
    assert_int_equal(cli_saslcookie(c), 0);
    assert_false(IsSASLReauth(c));
    assert_login_unchanged(c, &was);
    assert_nothing_announced(&fx_was);
  }
}

/** A connection of a bouncer session -- the primary or an alias -- never
 * changes the account, under any either (907, its FAIL saying why); its
 * own account refreshes as for anyone. */
static void reauth_setting_bouncer_member(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1];
  struct Client *p, *a, *who[2];
  int i;

  sasl_init_once();
  reauth_setting = "any";
  bed_features = 1;
  user_id("xavier", xid);
  p = new_logged_in(143, "nn", "xavier", xid, 1);
  a = new_logged_in(144, "nn", "xavier", xid, 1);
  fsess.members[0] = p;
  fsess.members[1] = a;
  ircd_strncpy(fsess.kc_id, xid, sizeof(fsess.kc_id));
  who[0] = p;
  who[1] = a;
  for (i = 0; i < 2; i++) {
    struct Client *c = who[i];
    struct login_snap was;
    struct effects fx_was;

    fake_of(c)->n_numerics = 0;
    snap(c, &was);
    fx_was = fx;
    assert_int_equal(plain_exchange(c, "yvonne", 1), 1);
    assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "bouncer session");

    fake_of(c)->n_numerics = 0;
    fx_was = fx;
    assert_int_equal(plain_exchange(c, "xavier", 1), 1);
    assert_refreshed(c, &was, &fx_was);
  }
}

/** A session's primary that services renamed (AC M from X3): its session
 * stays filed under the old name, so bounce_get_session() -- which looks
 * through the client's CURRENT account -- does not find it.  It is a
 * session's connection all the same (bounce_client_in_session() walks
 * every session): under any its re-authentication to another account is
 * refused (907, the bouncer-session reason), nothing changes. */
static void reauth_setting_renamed_primary(void **state)
{
  struct Client *c;
  struct login_snap was;
  struct effects fx_was;

  sasl_init_once();
  reauth_setting = "any";
  c = xavier_client(158);
  in_session_too = c;                       /* filed under a former name */
  assert_null(bounce_get_session(c));
  snap(c, &was);
  fx_was = fx;
  assert_int_equal(plain_exchange(c, "yvonne", 1), 1);
  assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "bouncer session");
  assert_false(tlog_has_prefix("servers AC"));
}

/** The setting is read again when the exchange completes: a REHASH in
 * between decides by its new value. */
static void reauth_setting_rehash_between(void **state)
{
  static const struct {
    const char *start, *end, *mech, *user;
    int outcome;                  /* 0 refresh, 1 refused 907, 2 switched */
  } rows[] = {
    { "any",     "refresh", "PLAIN",       "xavier", 1 },  /* PLAIN no longer refreshes */
    { "any",     "same",    "PLAIN",       "yvonne", 1 },
    { "same",    "any",     "PLAIN",       "yvonne", 2 },
    { "refresh", "any",     "OAUTHBEARER", "yvonne", 2 },
    { "any",     "refresh", "OAUTHBEARER", "yvonne", 1 },
    { "any",     "refresh", "OAUTHBEARER", "xavier", 0 },
  };
  size_t i;

  sasl_init_once();
  for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
    struct Client *c;
    struct login_snap was;
    struct effects fx_was;
    char data[300];

    reauth_setting = rows[i].start;
    c = xavier_client(145 + (int)(i % 2));
    snap(c, &was);
    fx_was = fx;
    kc_mode = KC_LATER;
    if (!strcmp(rows[i].mech, "PLAIN")) {
      char pw[16];

      snprintf(pw, sizeof(pw), "rb%d", (int)i);
      plain_b64(rows[i].user, pw, data);
      assert_int_equal(authenticate(c, "PLAIN"), 0);
      assert_int_equal(authenticate(c, data), 0);
      reauth_setting = rows[i].end;                 /* the REHASH */
      pend_deliver_kind(P_TOKEN, KC_SUCCESS);
      run_event_loop();
    } else {
      const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";

      token_for(rows[i].user, rows[i].user);
      jwt_local_undecided = 1;                      /* introspected: later */
      b64((const unsigned char *)msg, sizeof(msg) - 1, data);
      assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
      assert_int_equal(authenticate(c, data), 0);
      reauth_setting = rows[i].end;                 /* the REHASH */
      pend_deliver_kind(P_INTRO, KC_SUCCESS);
      run_event_loop();
    }
    if (rows[i].outcome == 0)
      assert_refreshed(c, &was, &fx_was);
    else if (rows[i].outcome == 1)
      assert_refused(c, &was, &fx_was, ERR_SASLALREADY,
                     strcmp(rows[i].user, "xavier") ? "logged in as xavier"
                                                    : "already completed");
    else
      assert_switched(c, &was, &fx_was, "yvonne");
  }
}

/** Under any, what an account change cannot be: a client registration
 * has not applied yet (a login held for burst convergence), a name only
 * the casemapping tells apart, a network without EXTENDED_ACCOUNTS (an AC M
 * cannot be sent).  Each is refused as before (907). */
static void reauth_setting_any_not_a_change(void **state)
{
  char xid[ACCOUNT_ID_LEN + 1], aid[ACCOUNT_ID_LEN + 1];
  struct Client *c;
  struct login_snap was;
  struct effects fx_was;

  sasl_init_once();
  reauth_setting = "any";
  user_id("xavier", xid);

  c = new_client(147, "wai", 1, REG_KEEPS);          /* registration waits */
  cli_auth(c) = NULL;
  ircd_strncpy(cli_user(c)->account, "xavier", sizeof(cli_user(c)->account));
  ircd_strncpy(cli_user(c)->kc_id, xid, sizeof(cli_user(c)->kc_id));
  SetAccount(c);
  sasl_identity_set(c, "xavier", 0, xid, 0);
  SetSASLComplete(c);
  CapSet(cli_active(c), CAP_STANDARDREPLIES);
  bed_features = 1;
  snap(c, &was);
  fx_was = fx;
  assert_int_equal(plain_exchange(c, "yvonne", 1), 1);
  assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");

  user_id("a[b", aid);                                /* a[b -> a{b */
  c = new_logged_in(148, "ab", "a[b", aid, 1);
  bed_features = 1;
  snap(c, &was);
  fx_was = fx;
  token_for("a{b", "a{b");
  oauth_exchange(c, LOCAL);
  assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as a[b");

  c = xavier_client(149);                             /* no EXTENDED_ACCOUNTS */
  bed_features = 0;
  snap(c, &was);
  fx_was = fx;
  assert_int_equal(plain_exchange(c, "yvonne", 1), 1);
  assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");
}

/** Through services (D S after an L): the account changes under any, with
 * X3's timestamp on the AC M; under same it is refused. */
static void reauth_setting_services_switch(void **state)
{
  int s;

  sasl_init_once();
  for (s = 1; s < 3; s++) {
    struct Client *c;
    struct login_snap was;
    struct effects fx_was;

    reauth_setting = settings[s];
    c = xavier_client(150 + s);
    snap(c, &was);
    fx_was = fx;
    cli_saslcookie(c) = 4646;                /* the relayed exchange */
    cli_saslstart(c) = CurrentTime;
    SetSASLReauth(c);
    assert_int_equal(sasl_complete_login(c, "yvonne", 1600000000, NULL, 0), 0);
    if (s == 1) {
      assert_refused(c, &was, &fx_was, ERR_SASLALREADY, "logged in as xavier");
      continue;
    }
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_string_equal(cli_user(c)->account, "yvonne");
    assert_int_equal(cli_user(c)->acc_create, 1600000000);
    assert_string_equal(cli_user(c)->kc_id, "");      /* X3's wire has no id */
    assert_true(tlog_has("servers AC xav M yvonne 1600000000"));
  }
}

/** A SASL 3.2 client BEFORE registration that already logged in: under
 * refresh only OAUTHBEARER may go again (as before); under same and any
 * any mechanism may, and may log in as anyone -- registration then applies
 * the last login.  (The orchestrator's choice: sasl_restart_mechanism_
 * allowed().) */
static void reauth_setting_before_registration(void **state)
{
  int s;

  sasl_init_once();
  for (s = 0; s < 3; s++) {
    struct Client *c = new_client(153, "pre", 0, REG_KEEPS);
    struct fake *f = fake_of(c);
    char data[300], yid[ACCOUNT_ID_LEN + 1], pw[16];

    reauth_setting = settings[s];
    CapSet(cli_active(c), CAP_STANDARDREPLIES);
    snprintf(pw, sizeof(pw), "t32pw%d", s);
    plain_pending(c, "liz", pw);
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    run_event_loop();
    assert_true(IsSASLComplete(c));
    f->n_numerics = 0;
    snprintf(pw, sizeof(pw), "t32yv%d", s);
    plain_b64("yvonne", pw, data);
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    if (s == 0) {
      assert_int_equal(f->n_numerics, 1);
      assert_int_equal(f->numerics[0], ERR_SASLALREADY);
      assert_string_equal(cli_saslaccount(c), "liz");
      assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);   /* as before */
      assert_non_null(cli_saslsession(c));
      assert_int_equal(authenticate(c, "*"), 0);
      continue;
    }
    assert_non_null(cli_saslsession(c));
    assert_int_equal(authenticate(c, data), 0);
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    run_event_loop();
    assert_true(has_numeric(f, RPL_SASLSUCCESS));
    assert_identity(c, "yvonne", user_id("yvonne", yid), 1);
    f->cap_done = 1;                                 /* CAP END */
    assert_int_equal(auth_sasl_done(cli_auth(c)), 0);
    assert_int_equal(f->registered, 1);
  }
}

/** A registered 3.2 client with no account: a first login, any mechanism,
 * under every setting (unchanged). */
static void reauth_setting_first_login_unchanged(void **state)
{
  int s;

  sasl_init_once();
  for (s = 0; s < 3; s++) {
    struct Client *c = new_registered(154 + s, "nolog");

    reauth_setting = settings[s];
    bed_features = 1;
    ntlog = 0;
    assert_int_equal(plain_exchange(c, "zoe", 1), 1);
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_string_equal(cli_user(c)->account, "zoe");
    assert_true(tlog_has_prefix("servers AC nolog R zoe"));
    assert_true(tlog_has("ban cache nolog"));        /* account bans now match */
  }
}

/** N067: a login's account change is one event on every server: the
 * account-notify lines go out under a msgid minted here, and the AC relay
 * carries the same one, which every receiver (ms_account()) adopts. */
static void login_account_change_is_one_event(void **state)
{
  struct Client *c;
  int i, ev = -1, notify = -1, s2s = -1, ac = -1;

  sasl_init_once();
  c = new_registered(160, "evt");
  bed_features = 1;
  msgid_on = 1;
  ntlog = 0;
  assert_int_equal(plain_exchange(c, "zoe", 1), 1);
  for (i = 0; i < ntlog; i++) {
    if (ev < 0 && !strcmp(tlog[i], "event ABAAAAAAEVENT1"))
      ev = i;
    else if (notify < 0 && !strncmp(tlog[i], "channels evt AC", 15))
      notify = i;
    else if (s2s < 0 && !strcmp(tlog[i], "s2s ABAAAAAAEVENT1"))
      s2s = i;
    else if (ac < 0 && !strncmp(tlog[i], "servers AC evt R zoe", 20))
      ac = i;
  }
  assert_true(ev >= 0 && notify > ev);   /* the notify under the event */
  assert_true(s2s > notify && ac > s2s); /* the relay carries it */
  msgid_on = 0;
}

/* ------------------------------------------------------------------ */
/* Before registration, an earlier login stands until another succeeds */
/* ------------------------------------------------------------------ */

/* Owner's ruling (2026-11-15), uniform with registered clients: a SASL 3.2
 * client before registration that holds a login -- a 903, a REGISTER
 * login, an account from login-on-connect or WEBIRC -- and starts another
 * exchange keeps that login, whole, until the new exchange SUCCEEDS; only
 * then is it replaced, as a whole.  Every other end -- a mechanism the
 * tier does not offer, bad credentials, an abort, the SASL timeout, the
 * services agent going away, registration waiting on the exchange --
 * leaves it exactly as it was, and registration applies it. */

/** Everything an unregistered client's login is. */
struct prereg_snap {
  int complete, reglogin, is_account;
  char account[ACCOUNTLEN + 1], saslaccount[ACCOUNTLEN + 1];
  char saslkcid[ACCOUNT_ID_LEN + 1];
  time_t saslacccreate;
  int saslkcidlive;
};

static void prereg_snap_of(struct Client *c, struct prereg_snap *s)
{
  memset(s, 0, sizeof(*s));
  s->complete = IsSASLComplete(c) ? 1 : 0;
  s->reglogin = HasFlag(c, FLAG_REGLOGIN) ? 1 : 0;
  s->is_account = IsAccount(c) ? 1 : 0;
  ircd_strncpy(s->account, cli_user(c)->account, sizeof(s->account));
  ircd_strncpy(s->saslaccount, cli_saslaccount(c), sizeof(s->saslaccount));
  ircd_strncpy(s->saslkcid, cli_saslkcid(c), sizeof(s->saslkcid));
  s->saslacccreate = cli_saslacccreate(c);
  s->saslkcidlive = cli_saslkcidlive(c);
}

static void assert_prereg_unchanged(struct Client *c, const struct prereg_snap *was)
{
  struct prereg_snap now;

  prereg_snap_of(c, &now);
  assert_int_equal(now.complete, was->complete);
  assert_int_equal(now.reglogin, was->reglogin);
  assert_int_equal(now.is_account, was->is_account);
  assert_string_equal(now.account, was->account);
  assert_string_equal(now.saslaccount, was->saslaccount);
  assert_string_equal(now.saslkcid, was->saslkcid);
  assert_int_equal(now.saslacccreate, was->saslacccreate);
  assert_int_equal(now.saslkcidlive, was->saslkcidlive);
}

/** How the earlier login came. */
enum earlier { EARLIER_SASL, EARLIER_REGISTER, EARLIER_LOC, NEARLIER };
static const char *const earlier_name[NEARLIER] = { "SASL", "REGISTER", "LOC/WEBIRC" };
static const char *const earlier_acct[NEARLIER] = { "liz", "rega", "locacct" };

/** An unregistered CAP 302 client on \a fd holding a login from \a how. */
static struct Client *prereg_logged_in(int fd, enum earlier how)
{
  static int n;
  struct Client *c = new_client(fd, "pr", 0, REG_KEEPS);
  char pw[24], rid[ACCOUNT_ID_LEN + 1];

  CapSet(cli_active(c), CAP_STANDARDREPLIES);
  switch (how) {
  case EARLIER_SASL:
    snprintf(pw, sizeof(pw), "prpw%d", ++n);
    plain_pending(c, "liz", pw);
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    run_event_loop();
    assert_identity(c, "liz", user_id("liz", rid), 1);
    break;
  case EARLIER_REGISTER:
    register_through(c, "rega", "*");
    assert_identity(c, "rega", user_id("rega", rid), 1);
    assert_true(HasFlag(c, FLAG_REGLOGIN));
    break;
  case EARLIER_LOC:                     /* login-on-connect / WEBIRC */
    ircd_strncpy(cli_user(c)->account, "locacct", sizeof(cli_user(c)->account));
    SetAccount(c);
    break;
  default:
    fail();
  }
  assert_false(IsRegistered(c));
  fake_of(c)->n_numerics = 0;
  fake_of(c)->fail_code[0] = '\0';
  return c;
}

/** The ways a second exchange can end. */
enum second_end { END_UNSUPPORTED, END_BAD_CREDS, END_ABORT, END_TIMEOUT,
                  END_AGENT_GONE, END_CAP_END_TIMEOUT, END_SAME, END_OTHER,
                  NENDS };
static const char *const end_name[NENDS] = {
  "a mechanism the tier does not offer", "bad credentials", "abort",
  "the SASL timeout", "the services agent gone", "CAP END, then the timeout",
  "success as the same account", "success as another account"
};

/** The whole grid: every end of a second exchange x every earlier login. */
static void prereg_earlier_login_stands(void **state)
{
  int how, end, fd = 160;

  sasl_init_once();
  reauth_setting = "any";
  for (how = 0; how < NEARLIER; how++)
    for (end = 0; end < NENDS; end++) {
      static int n;
      struct Client *c = prereg_logged_in(fd, (enum earlier)how);
      struct fake *f = fake_of(c);
      struct prereg_snap was;
      char data[300], pw[24], id[ACCOUNT_ID_LEN + 1];
      const char *acct = earlier_acct[how];

      fd = fd < 167 ? fd + 1 : 160;
      ntlog = 0;
      print_message("  earlier %s / %s\n", earlier_name[how], end_name[end]);
      prereg_snap_of(c, &was);
      snprintf(pw, sizeof(pw), "pe%d", ++n);

      if (end == END_UNSUPPORTED) {
        /* Not a local mechanism: the exchange goes to services, which
         * answer 908 and 904 and end it (ms_sasl() M, D F: their own
         * suite); here the services end of it. */
        local_off = 0;
        assert_int_equal(authenticate(c, "FOOBAR-MECH"), 0);
        assert_true(cli_saslcookie(c) != 0);
        assert_true(IsSASLReauth(c));        /* in flight beside the login */
        assert_prereg_unchanged(c, &was);
        abort_sasl(c, SASL_ABORT_REPLY_NONE);
      } else if (end == END_BAD_CREDS) {
        plain_b64("yvonne", pw, data);
        kc_mode = KC_LATER;
        assert_int_equal(authenticate(c, "PLAIN"), 0);
        assert_int_equal(authenticate(c, data), 0);
        pend_deliver_kind(P_TOKEN, KC_ERROR);
        run_event_loop();
        assert_true(has_numeric(f, ERR_SASLFAIL));
      } else if (end == END_ABORT) {
        assert_int_equal(authenticate(c, "PLAIN"), 0);
        assert_true(IsSASLReauth(c));
        /* REGISTER stays refused while the earlier login stands */
        f->fail_code[0] = '\0';
        assert_int_equal(register_line(c, "longpassword"), 0);
        assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
        assert_int_equal(authenticate(c, "*"), 0);
        assert_true(has_numeric(f, ERR_SASLABORTED));
        f->fail_code[0] = '\0';                 /* and after it failed */
        assert_int_equal(register_line(c, "longpassword"), 0);
        assert_string_equal(f->fail_code, "ALREADY_AUTHENTICATED");
      } else if (end == END_TIMEOUT) {
        assert_int_equal(authenticate(c, "PLAIN"), 0);
        fire_timer(&cli_sasltimeout(c));
        assert_true(has_numeric(f, ERR_SASLFAIL));
      } else if (end == END_AGENT_GONE) {
        local_off = 1;                           /* the services tier */
        assert_int_equal(authenticate(c, "PLAIN"), 0);
        assert_true(cli_saslcookie(c) != 0);
        abort_sasl(c, SASL_ABORT_REPLY_NONE);    /* its agent split */
        local_off = 0;
      } else if (end == END_CAP_END_TIMEOUT) {
        assert_int_equal(authenticate(c, "PLAIN"), 0);
        f->cap_done = 1;                         /* CAP END: registration waits */
        assert_int_equal(f->registered, 0);
        fire_timer(&cli_sasltimeout(c));         /* then lets it go on */
        assert_int_equal(f->registered, 1);
      } else {
        const char *as = end == END_SAME ? acct : "yvonne";

        plain_b64(as, pw, data);
        kc_mode = KC_LATER;
        assert_int_equal(authenticate(c, "PLAIN"), 0);
        assert_int_equal(authenticate(c, data), 0);
        pend_deliver_kind(P_TOKEN, KC_SUCCESS);
        run_event_loop();
        assert_true(has_numeric(f, RPL_SASLSUCCESS));
        /* Replaced as a whole: the new login's name, id and mark, never
         * one beside the other's. */
        assert_identity(c, as, user_id(as, id), 1);
        assert_false(HasFlag(c, FLAG_REGLOGIN));
        assert_false(IsSASLReauth(c));
        continue;
      }
      assert_null(cli_saslsession(c));
      assert_int_equal(cli_saslcookie(c), 0);
      assert_false(IsSASLReauth(c));
      assert_prereg_unchanged(c, &was);
    }
  local_off = 0;
}

/* ------------------------------------------------------------------ */
/* SASL_MAX_FAILURES                                                   */
/* ------------------------------------------------------------------ */

/* Owner's rulings (2026-11-15): a connection counts its failed SASL
 * exchanges -- one that reached a backend and ended without a login:
 * bad credentials or a refused token (904), an over-long response (905),
 * a services or IAuth failure answer, a proven account refused by policy
 * at the end (907/904) -- and not a client abort (906), an unsupported
 * mechanism (908 + 904), the server's own unavailability (service
 * unavailable, the timeout, the agent or IAuth gone) or a refusal before
 * an exchange starts.  A login resets it.  At SASL_MAX_FAILURES (0: no
 * limit) before registration the failure that reaches it is answered,
 * then the connection is closed ("Too many SASL failures"); after
 * registration every new exchange is refused with 904. */

/** The ends of an exchange this suite can drive, and whether each counts. */
enum fail_end { FE_BAD_PASSWORD, FE_UNVERIFIED, FE_UNAVAILABLE, FE_NEGCACHE,
                FE_MALFORMED, FE_TOOLONG, FE_BAD_TOKEN, FE_ERRCHAL_DATA,
                FE_ERRCHAL_STAR, FE_INTRO_UNAVAIL, FE_INTRO_NOT_STARTED,
                FE_ABORT, FE_TIMEOUT, FE_NOT_STARTED, FE_POLICY_END, NFE };
static const struct { const char *name; int counted; } fe[NFE] = {
  { "bad password (904)", 1 },
  { "account not set up (904, policy)", 1 },
  { "Keycloak unavailable (904)", 0 },
  { "known-bad credentials, negative cache (904)", 1 },
  { "malformed PLAIN data (904)", 1 },
  { "over-long response (905)", 1 },
  { "token refused by the local check (904)", 1 },
  { "token refused by introspection, then data (904)", 1 },
  { "token refused by introspection, then * (904)", 1 },
  { "introspection unavailable, then * (904)", 0 },
  { "introspection request not started (904)", 0 },
  { "client abort (906)", 0 },
  { "the SASL timeout (904)", 0 },
  { "Keycloak request not started (904)", 0 },
  { "another account refused at the end (907)", 1 },
};

/** Drive one exchange of \a c ending as \a end. */
static void fail_exchange(struct Client *c, enum fail_end end)
{
  static int n;
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char data[300], pw[24];

  snprintf(pw, sizeof(pw), "fe%d", ++n);
  kc_mode = KC_LATER;
  switch (end) {
  case FE_BAD_PASSWORD:
  case FE_UNVERIFIED:
  case FE_UNAVAILABLE:
    plain_pending(c, "liz", pw);
    pend_deliver_kind(P_TOKEN, end == FE_BAD_PASSWORD ? KC_FORBIDDEN
                               : end == FE_UNVERIFIED ? KC_UNVERIFIED
                               : KC_UNAVAILABLE);
    run_event_loop();
    if (end == FE_UNAVAILABLE)
      kc_healthy_again();
    break;
  case FE_NEGCACHE:                           /* the same bad pair again */
    plain_pending(c, "negu", "negpw");
    if (pend[0].kind != P_NONE) {
      pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);
      run_event_loop();
      cli_sasl_failures(c) = 0;               /* count the hit alone */
      plain_pending(c, "negu", "negpw");      /* answered inline */
    }
    break;
  case FE_MALFORMED:
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    b64((const unsigned char *)"nonuls", 6, data);
    assert_int_equal(authenticate(c, data), 0);
    break;
  case FE_TOOLONG: {
    char line[402];
    memset(line, 'A', 401);
    line[401] = '\0';
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, line), 0);
    break;
  }
  case FE_BAD_TOKEN:
    jwt_local_forbidden = 1;
    b64((const unsigned char *)msg, sizeof(msg) - 1, data);
    assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
    assert_int_equal(authenticate(c, data), 0);
    jwt_local_forbidden = 0;
    break;
  case FE_ERRCHAL_DATA:
  case FE_ERRCHAL_STAR:
  case FE_INTRO_UNAVAIL:
    jwt_local_undecided = 1;
    b64((const unsigned char *)msg, sizeof(msg) - 1, data);
    assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
    assert_int_equal(authenticate(c, data), 0);
    pend_deliver_kind(P_INTRO, end == FE_INTRO_UNAVAIL ? KC_UNAVAILABLE
                                                       : KC_FORBIDDEN);
    assert_int_equal(authenticate(c, end == FE_ERRCHAL_DATA ? "AQ==" : "*"), 0);
    jwt_local_undecided = 0;
    if (end == FE_INTRO_UNAVAIL)
      kc_healthy_again();
    break;
  case FE_INTRO_NOT_STARTED:
    jwt_local_undecided = 1;
    b64((const unsigned char *)msg, sizeof(msg) - 1, data);
    assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
    kc_mode = KC_REFUSE;
    assert_int_equal(authenticate(c, data), 0);
    jwt_local_undecided = 0;
    break;
  case FE_ABORT:
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "*"), 0);
    break;
  case FE_TIMEOUT:
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    fire_timer(&cli_sasltimeout(c));
    break;
  case FE_NOT_STARTED:
    plain_b64("liz", pw, data);
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    kc_mode = KC_REFUSE;
    assert_int_equal(authenticate(c, data), 0);
    break;
  case FE_POLICY_END:                         /* registered, refresh */
    token_for("yvonne", "yvonne");
    oauth_exchange(c, LOCAL);
    break;
  default:
    fail();
  }
  kc_mode = KC_LATER;
}

/** Each end x counted or not; and a login resets the count. */
static void max_failures_count_table(void **state)
{
  int e, fd = 170;

  sasl_init_once();
  for (e = 0; e < NFE; e++) {
    struct Client *c;
    struct fake *f;

    if (e == FE_POLICY_END)
      c = xavier_client(fd);                  /* logged in, refresh */
    else
      c = new_client(fd, "fc", 0, REG_KEEPS);
    fd = fd < 177 ? fd + 1 : 170;
    f = fake_of(c);
    print_message("  %s: %s\n", fe[e].name, fe[e].counted ? "counted" : "not counted");
    fail_exchange(c, (enum fail_end)e);
    assert_false(f->freed);
    assert_null(cli_saslsession(c));
    assert_int_equal(cli_saslcookie(c), 0);
    assert_false(has_numeric(f, RPL_SASLSUCCESS));
    assert_int_equal(cli_sasl_failures(c), fe[e].counted);
  }

  {                                           /* a login resets it */
    struct Client *c = new_client(178, "rs", 0, REG_KEEPS);

    cli_sasl_failures(c) = 3;
    plain_pending(c, "liz", "resetpw");
    pend_deliver_kind(P_TOKEN, KC_SUCCESS);
    run_event_loop();
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_int_equal(cli_sasl_failures(c), 0);
  }
  {                                           /* and so does a refresh */
    struct Client *c = xavier_client(179);

    cli_sasl_failures(c) = 3;
    token_for("xavier", "xavier");
    oauth_exchange(c, LOCAL);
    assert_true(has_numeric(fake_of(c), RPL_SASLSUCCESS));
    assert_int_equal(cli_sasl_failures(c), 0);
  }
}

/** Before registration: the failure that reaches the limit is answered
 * (904), then the connection is closed with the reason -- from the event
 * loop after a Keycloak answer, inside the client's own line (the handler
 * returns CPTR_KILLED) after an answer given at once.  Until then nothing
 * closes it, and CAP END is not needed for it. */
static void max_failures_before_registration(void **state)
{
  struct Client *c;
  struct fake *f;
  int i;

  sasl_init_once();
  max_failures = 3;
  c = new_client(180, "pre", 0, REG_KEEPS);
  f = fake_of(c);
  for (i = 0; i < 3; i++) {
    assert_false(f->freed);
    fail_exchange(c, FE_BAD_PASSWORD);
  }
  assert_true(f->freed);
  assert_string_equal(f->exit_reason, "Too many SASL failures");
  assert_int_equal(f->n_numerics, 3);
  for (i = 0; i < 3; i++)
    assert_int_equal(f->numerics[i], ERR_SASLFAIL);
  assert_int_equal(f->touched_after_free, 0);

  /* An answer given inside the line: the line's handler returns
   * CPTR_KILLED, nothing touches the client after it. */
  max_failures = 2;
  c = new_client(181, "pre2", 0, REG_KEEPS);
  f = fake_of(c);
  fail_exchange(c, FE_BAD_PASSWORD);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  {
    char data[300];
    b64((const unsigned char *)"nonuls", 6, data);   /* malformed: at once */
    assert_int_equal(authenticate(c, data), CPTR_KILLED);
  }
  assert_true(f->freed);
  assert_string_equal(f->exit_reason, "Too many SASL failures");
  assert_int_equal(f->touched_after_free, 0);

  /* Not-counted ends never close it. */
  max_failures = 2;
  c = new_client(182, "pre3", 0, REG_KEEPS);
  f = fake_of(c);
  for (i = 0; i < 4; i++) {
    fail_exchange(c, FE_ABORT);
    fail_exchange(c, FE_UNAVAILABLE);     /* (Keycloak reachable again after) */
  }
  assert_false(f->freed);
  assert_int_equal(cli_sasl_failures(c), 0);
}

/** After registration: no disconnect.  At the limit every AUTHENTICATE that
 * would start a new exchange is refused with 904 and the reason, nothing
 * reaches Keycloak, the login and everything else stay; a success before
 * the limit resets the count. */
static void max_failures_after_registration(void **state)
{
  struct Client *c;
  struct fake *f;
  int requests, i;

  sasl_init_once();
  max_failures = 2;
  reauth_setting = "any";
  c = new_registered(183, "reg");
  f = fake_of(c);
  bed_features = 1;
  fail_exchange(c, FE_BAD_PASSWORD);
  assert_int_equal(cli_sasl_failures(c), 1);
  plain_pending(c, "zoe", "zoepwreset");             /* a success: reset */
  pend_deliver_kind(P_TOKEN, KC_SUCCESS);
  run_event_loop();
  assert_string_equal(cli_user(c)->account, "zoe");
  assert_int_equal(cli_sasl_failures(c), 0);
  fail_exchange(c, FE_BAD_PASSWORD);
  fail_exchange(c, FE_BAD_PASSWORD);
  assert_int_equal(cli_sasl_failures(c), 2);
  assert_false(f->freed);

  for (i = 0; i < 2; i++) {                           /* refused, each time */
    f->n_numerics = 0;
    requests = kc_requests;
    assert_int_equal(authenticate(c, i ? "OAUTHBEARER" : "PLAIN"), 0);
    assert_int_equal(f->n_numerics, 1);
    assert_int_equal(f->numerics[0], ERR_SASLFAIL);
    assert_non_null(strstr(f->saslfail, "too many failed attempts on this connection"));
    assert_null(cli_saslsession(c));
    assert_int_equal(cli_saslcookie(c), 0);
    assert_false(IsSASLReauth(c));
    assert_int_equal(kc_requests, requests);
    assert_false(f->freed);
    assert_string_equal(f->exit_reason, "");
    assert_string_equal(cli_user(c)->account, "zoe");
    assert_int_equal(cli_sasl_failures(c), 2);       /* a refusal is no failure */
  }
}

/** SASL_MAX_FAILURES 0 is no limit; a lowered value applies from the
 * next failure or the next new exchange; once reached, the mark is final
 * (a raised value does not lift it). */
static void max_failures_zero_and_changed(void **state)
{
  struct Client *c;
  struct fake *f;
  int i;

  sasl_init_once();
  max_failures = 0;                                   /* no limit */
  c = new_client(184, "nl", 0, REG_KEEPS);
  f = fake_of(c);
  for (i = 0; i < 7; i++)
    fail_exchange(c, FE_BAD_PASSWORD);
  assert_false(f->freed);
  assert_int_equal(cli_sasl_failures(c), 7);

  /* Lowered below the count: the next new exchange closes it. */
  max_failures = 5;
  assert_int_equal(authenticate(c, "PLAIN"), CPTR_KILLED);
  assert_string_equal(f->exit_reason, "Too many SASL failures");

  /* After registration: lowered, then raised again. */
  max_failures = 5;
  c = new_registered(185, "ch");
  f = fake_of(c);
  fail_exchange(c, FE_BAD_PASSWORD);
  fail_exchange(c, FE_BAD_PASSWORD);
  max_failures = 2;                                   /* a SET / REHASH */
  f->n_numerics = 0;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_non_null(strstr(f->saslfail, "too many failed attempts"));
  assert_null(cli_saslsession(c));
  max_failures = 3;                                   /* raised: the mark */
  f->n_numerics = 0;                                  /* is final, refused */
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_non_null(strstr(f->saslfail, "too many failed attempts"));
  assert_null(cli_saslsession(c));

  /* Lowered, reached at the next failure: the count reaching the new
   * value closes it then (before registration). */
  max_failures = 10;
  c = new_client(186, "lw", 0, REG_KEEPS);
  f = fake_of(c);
  fail_exchange(c, FE_BAD_PASSWORD);
  fail_exchange(c, FE_BAD_PASSWORD);
  assert_int_equal(authenticate(c, "PLAIN"), 0);      /* under the limit */
  max_failures = 3;
  {
    char data[300];
    plain_b64("liz", "lowpw", data);
    assert_int_equal(authenticate(c, data), 0);
    pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);
    run_event_loop();
  }
  assert_true(f->freed);
  assert_string_equal(f->exit_reason, "Too many SASL failures");
}

/** An exchange whose request has gone out to a backend and that the client
 * then ends without a login -- an abort, letting it time out, registering
 * mid-exchange -- counts, once.  The reviewer's run: credentials and
 * AUTHENTICATE * in one write, again and again: the fifth such guess
 * closes the connection.  An abort before anything went out does not
 * count. */
static void max_failures_aborted_guesses_count(void **state)
{
  struct Client *c;
  struct fake *f;
  char data[300];
  int i, requests;

  sasl_init_once();
  max_failures = 5;
  c = new_client(187, "ab", 0, REG_KEEPS);
  f = fake_of(c);
  requests = kc_requests;
  for (i = 0; i < 5; i++) {
    char pw[16];
    int rc;

    snprintf(pw, sizeof(pw), "abg%d", i);
    plain_b64("liz", pw, data);
    kc_mode = KC_LATER;
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, data), 0);      /* the grant goes out */
    rc = authenticate(c, "*");                        /* and is abandoned */
    pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);         /* its late answer */
    run_event_loop();                                 /* reaches nobody */
    if (i < 4) {
      assert_int_equal(rc, 0);
      assert_int_equal(cli_sasl_failures(c), i + 1);
    } else {
      assert_int_equal(rc, CPTR_KILLED);              /* the fifth closes it */
      assert_true(f->freed);
      assert_string_equal(f->exit_reason, "Too many SASL failures");
    }
  }
  assert_int_equal(kc_requests, requests + 5);        /* five grants went out */
  assert_int_equal(f->touched_after_free, 0);

  /* Aborted before anything went out: never counted. */
  c = new_client(188, "ab2", 0, REG_KEEPS);
  f = fake_of(c);
  for (i = 0; i < 8; i++) {
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "*"), 0);
  }
  assert_false(f->freed);
  assert_int_equal(cli_sasl_failures(c), 0);
}

/** A refused token is counted when the refusal is known (the error
 * challenge), whatever the client does next -- data, *, nothing (the
 * timeout) -- and only once.  A timeout while the request is still with
 * the backend is the backend's, not the client's: not counted. */
static void max_failures_refusal_known_and_timeouts(void **state)
{
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char data[300];
  int how;

  sasl_init_once();
  max_failures = 0;
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  for (how = 0; how < 3; how++) {             /* then data, *, the timeout */
    struct Client *c = new_client(189 + how, "tk", 0, REG_KEEPS);

    jwt_local_undecided = 1;
    assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
    assert_int_equal(authenticate(c, data), 0);
    pend_deliver_kind(P_INTRO, KC_FORBIDDEN);   /* the error challenge */
    assert_int_equal(cli_sasl_failures(c), 1);  /* known: counted now */
    if (how == 0)
      assert_int_equal(authenticate(c, "AQ=="), 0);
    else if (how == 1)
      assert_int_equal(authenticate(c, "*"), 0);
    else
      fire_timer(&cli_sasltimeout(c));
    assert_int_equal(cli_sasl_failures(c), 1);  /* once */
    jwt_local_undecided = 0;
  }

  {                     /* the grant still out at the timeout: not counted */
    struct Client *c = new_client(193, "to", 0, REG_KEEPS);

    plain_pending(c, "liz", "topw");
    fire_timer(&cli_sasltimeout(c));
    assert_int_equal(cli_sasl_failures(c), 0);
  }
  {                     /* services: the credentials out, no answer yet */
    struct Client *c = new_client(194, "sv", 0, REG_KEEPS);

    local_off = 1;
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "AGxpegBwdw=="), 0);
    fire_timer(&cli_sasltimeout(c));
    assert_int_equal(cli_sasl_failures(c), 0);
    /* ... a challenge back from services: the client's turn, and its
     * timeout counts */
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "AGxpegBwdw=="), 0);
    con_sasl_xflags(cli_connect(c)) |= SASLX_CLIENTTURN;   /* ms_sasl() C */
    fire_timer(&cli_sasltimeout(c));
    assert_int_equal(cli_sasl_failures(c), 1);
    /* ... and an abort after the credentials went out counts */
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "AGxpegBwdw=="), 0);
    assert_int_equal(authenticate(c, "*"), 0);
    assert_int_equal(cli_sasl_failures(c), 2);
    assert_int_equal(authenticate(c, "PLAIN"), 0);         /* before: not */
    assert_int_equal(authenticate(c, "*"), 0);
    assert_int_equal(cli_sasl_failures(c), 2);
    local_off = 0;
  }
  {                     /* IAuth: the same */
    struct Client *c = new_client(195, "ia", 0, REG_KEEPS);

    local_off = 1;
    iauth_on = 1;
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "AGxpegBwdw=="), 0);
    assert_int_equal(authenticate(c, "*"), 0);
    assert_int_equal(cli_sasl_failures(c), 1);
    assert_int_equal(authenticate(c, "PLAIN"), 0);
    assert_int_equal(authenticate(c, "*"), 0);
    assert_int_equal(cli_sasl_failures(c), 1);
    local_off = iauth_on = 0;
  }
}

/** The limit's mark is final for the connection: raising SASL_MAX_FAILURES
 * never revives it.  Before registration, a limit reached in a Keycloak
 * answer closes the connection at the next check; a new exchange before
 * that check closes it too, whatever the value is now.  After
 * registration the refusal stays. */
static void max_failures_mark_is_final(void **state)
{
  struct Client *c;
  struct fake *f;

  sasl_init_once();
  max_failures = 2;
  c = new_client(196, "fi", 0, REG_KEEPS);
  f = fake_of(c);
  plain_pending(c, "liz", "fipw1");
  pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);
  run_event_loop();
  plain_pending(c, "liz", "fipw2");
  pend_deliver_kind(P_TOKEN, KC_FORBIDDEN);    /* the limit: marked ... */
  assert_false(f->freed);                      /* ... the check not run yet */
  max_failures = 10;                           /* a SET raises it */
  assert_int_equal(authenticate(c, "PLAIN"), CPTR_KILLED);
  assert_string_equal(f->exit_reason, "Too many SASL failures");
  assert_null(cli_saslsession(c));

  max_failures = 2;
  c = new_registered(197, "fr");
  f = fake_of(c);
  fail_exchange(c, FE_BAD_PASSWORD);
  fail_exchange(c, FE_BAD_PASSWORD);
  max_failures = 10;
  f->n_numerics = 0;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_non_null(strstr(f->saslfail, "too many failed attempts"));
  assert_null(cli_saslsession(c));
  max_failures = 0;                            /* no limit: still refused */
  f->n_numerics = 0;
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_non_null(strstr(f->saslfail, "too many failed attempts"));
}

/** Keycloak could not be asked: the client gets an error challenge, and
 * nothing it does next -- silence until the SASL timeout, an abort, the
 * acknowledgement -- counts: the server's own unavailability.  A real
 * refusal followed by silence still counts, once. */
static void max_failures_unavailable_never_counts(void **state)
{
  const char msg[] = "n,,\001auth=Bearer some.jwt.token\001\001";
  char data[300];
  int how;

  sasl_init_once();
  max_failures = 0;
  b64((const unsigned char *)msg, sizeof(msg) - 1, data);
  for (how = 0; how < 4; how++) {     /* silence, *, data; then a refusal */
    struct Client *c = new_client(198 + how, "un", 0, REG_KEEPS);

    print_message("  %s\n", how == 0 ? "unavailable, then silence" :
                  how == 1 ? "unavailable, then *" :
                  how == 2 ? "unavailable, then the acknowledgement" :
                  "refused, then silence");
    jwt_local_undecided = 1;
    assert_int_equal(authenticate(c, "OAUTHBEARER"), 0);
    assert_int_equal(authenticate(c, data), 0);
    pend_deliver_kind(P_INTRO, how == 3 ? KC_FORBIDDEN : KC_UNAVAILABLE);
    if (how == 1)
      assert_int_equal(authenticate(c, "*"), 0);
    else if (how == 2)
      assert_int_equal(authenticate(c, "AQ=="), 0);
    else
      fire_timer(&cli_sasltimeout(c));
    /* With Keycloak marked unreachable the local tier is not offered, and
     * the acknowledgement does not reach the local session (it ends at
     * the timeout): not counted either way. */
    if (cli_saslsession(c))
      fire_timer(&cli_sasltimeout(c));
    assert_null(cli_saslsession(c));
    assert_int_equal(cli_sasl_failures(c), how == 3 ? 1 : 0);
    jwt_local_undecided = 0;
    if (how < 3)
      kc_healthy_again();
  }
}
#endif /* USE_LIBKC */

/* ------------------------------------------------------------------ */
/* A WEBIRC check out: no exchange starts on the gateway's address     */
/* ------------------------------------------------------------------ */

/* list.c: the held lines' links. */
struct SLink *make_link(void) { return calloc(1, sizeof(struct SLink)); }
void free_link(struct SLink *lp) { free(lp); }

/** While the check is out, AUTHENTICATE and its data are held (nothing
 * reaches any tier, no exchange); replayed when the check has applied the
 * real address, they start the exchange there, told that address. */
static void held_during_webirc_check_then_replayed(void **state)
{
  struct Client *c;

  local_off = 1;
  iauth_on = 1;
  sendhost_on = 1;
  c = new_client(60, "wb", 1, REG_KEEPS);
  ircd_strncpy(cli_sock_ip(c), "127.0.0.1", SOCKIPLEN + 1);   /* the gateway */
  SetWebIRCPending(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, "AGFjY3QAcHc="), 0);
  assert_int_equal(iauth_starts + iauth_datas, 0);
  assert_no_exchange(c);
  assert_non_null(cli_saslheld(c));

  ClearWebIRCPending(c);                                       /* the check */
  ircd_strncpy(cli_sock_ip(c), "192.0.2.77", SOCKIPLEN + 1);
  assert_int_equal(authenticate_replay(c), 0);
  assert_null(cli_saslheld(c));
  assert_int_equal(iauth_starts, 1);
  assert_int_equal(iauth_datas, 1);
  assert_string_equal(iauth_host_ip, "192.0.2.77");
  assert_true(cli_saslcookie(c) != 0);
}

/** AUTHENTICATE * while lines are held drops them and answers 906; the
 * replay then starts nothing. */
static void abort_during_webirc_check_drops_held_lines(void **state)
{
  struct Client *c;
  struct fake *f;

  local_off = 1;
  iauth_on = 1;
  c = new_client(61, "wa", 1, REG_KEEPS);
  f = fake_of(c);
  SetWebIRCPending(c);
  assert_int_equal(authenticate(c, "PLAIN"), 0);
  assert_int_equal(authenticate(c, "*"), 0);
  assert_null(cli_saslheld(c));
  assert_true(has_numeric(f, ERR_SASLABORTED));
  ClearWebIRCPending(c);
  assert_int_equal(authenticate_replay(c), 0);
  assert_int_equal(iauth_starts, 0);
  assert_no_exchange(c);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(complete_login_holds_registration_to_its_end, setup),
    cmocka_unit_test_setup(complete_login_keeps, setup),
    cmocka_unit_test_setup(ac_change_carries_the_timestamp_slot, setup),
#ifdef USE_LIBKC
    cmocka_unit_test_setup(poscache_hit_registration_exits, setup),
    cmocka_unit_test_setup(poscache_hit_registration_keeps, setup),
    cmocka_unit_test_setup(inline_success_answers_in_one_labeled_batch, setup),
    cmocka_unit_test_setup(later_answer_inside_another_line_takes_none_of_its_label, setup),
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
    cmocka_unit_test_setup(second_exchange_keeps_the_login, setup),
    cmocka_unit_test_setup(register_after_abandoned_exchange_is_refused, setup),
    cmocka_unit_test_setup(flow_register_logs_in, setup),
    cmocka_unit_test_setup(flow_verify_then_sasl, setup),
    cmocka_unit_test_setup(flow_verify_then_other_account, setup),
    cmocka_unit_test_setup(flow_register_answer_mid_sasl_then_success, setup),
    cmocka_unit_test_setup(flow_register_answer_mid_sasl_then_failure, setup),
    cmocka_unit_test_setup(flow_sasl_then_register_answer, setup),
    cmocka_unit_test_setup(register_answer_after_login_to_the_same_account, setup),
    cmocka_unit_test_setup(register_success_is_a_sasl_login, setup),
    cmocka_unit_test_setup(register_success_mid_sasl_keeps_the_exchange_hold, setup),
    cmocka_unit_test_setup(authenticate_after_register_success_is_as_after_903, setup),
    cmocka_unit_test_setup(register_without_location_looks_up_the_id, setup),
    cmocka_unit_test_setup(register_id_lookup_failure_still_logs_in, setup),
    cmocka_unit_test_setup(register_id_lookup_wrong_answer, setup),
    cmocka_unit_test_setup(register_client_gone_before_the_id, setup),
    cmocka_unit_test_setup(verify_on_does_not_log_in, setup),
    cmocka_unit_test_setup(register_success_mid_sasl_leaves_it_abortable, setup),
    cmocka_unit_test_setup(register_refuses_names_the_casemapping_folds, setup),
    cmocka_unit_test_setup(register_tells_why_keycloak_refused, setup),
    cmocka_unit_test_setup(register_answer_carries_its_own_label, setup),
    cmocka_unit_test_setup(reauth_other_account_refused, setup),
    cmocka_unit_test_setup(reauth_same_name_other_id_refused, setup),
    cmocka_unit_test_setup(reauth_same_account_refreshes, setup),
    cmocka_unit_test_setup(reauth_id_table, setup),
    cmocka_unit_test_setup(reauth_session_members, setup),
    cmocka_unit_test_setup(reauth_while_registration_waits, setup),
    cmocka_unit_test_setup(reauth_after_services_login_refused, setup),
    cmocka_unit_test_setup(reauth_failed_or_aborted_keeps_login, setup),
    cmocka_unit_test_setup(pre_registration_switch_allowed, setup),
    cmocka_unit_test_setup(reauth_after_register_login, setup),
    cmocka_unit_test_setup(reauth_timeout_keeps_login, setup),
    cmocka_unit_test_setup(reauth_notice_rates_apart, setup),
    cmocka_unit_test_setup(reauth_ds_without_l_refused, setup),
    cmocka_unit_test_setup(reauth_refresh_record, setup),
    cmocka_unit_test_setup(reauth_casemapping_only_names_refused, setup),
    cmocka_unit_test_setup(reauth_refresh_keeps_minus_x, setup),
    cmocka_unit_test_setup(reauth_relayed_exchange_takes_no_local_exchange, setup),
    cmocka_unit_test_setup(flow_login_tells_the_user, setup),
    cmocka_unit_test_setup(reauth_tells_nobody_account, setup),
    cmocka_unit_test_setup(sasl31_matrix, setup),
    cmocka_unit_test_setup(sasl31_registered_every_line_462, setup),
    cmocka_unit_test_setup(sasl31_registered_other_tiers, setup),
    cmocka_unit_test_setup(sasl31_pre_registration_account_held, setup),
    cmocka_unit_test_setup(sasl31_retry_after_failure_then_907, setup),
    cmocka_unit_test_setup(reauth_setting_table, setup),
    cmocka_unit_test_setup(reauth_setting_other_id_and_failure, setup),
    cmocka_unit_test_setup(reauth_setting_bouncer_member, setup),
    cmocka_unit_test_setup(reauth_setting_renamed_primary, setup),
    cmocka_unit_test_setup(reauth_setting_rehash_between, setup),
    cmocka_unit_test_setup(reauth_setting_any_not_a_change, setup),
    cmocka_unit_test_setup(reauth_setting_services_switch, setup),
    cmocka_unit_test_setup(reauth_setting_before_registration, setup),
    cmocka_unit_test_setup(reauth_setting_first_login_unchanged, setup),
    cmocka_unit_test_setup(login_account_change_is_one_event, setup),
    cmocka_unit_test_setup(prereg_earlier_login_stands, setup),
    cmocka_unit_test_setup(max_failures_count_table, setup),
    cmocka_unit_test_setup(max_failures_before_registration, setup),
    cmocka_unit_test_setup(max_failures_after_registration, setup),
    cmocka_unit_test_setup(max_failures_zero_and_changed, setup),
    cmocka_unit_test_setup(max_failures_aborted_guesses_count, setup),
    cmocka_unit_test_setup(max_failures_refusal_known_and_timeouts, setup),
    cmocka_unit_test_setup(max_failures_mark_is_final, setup),
    cmocka_unit_test_setup(max_failures_unavailable_never_counts, setup),
    cmocka_unit_test_setup(toolong_ends_local_exchange, setup),
    cmocka_unit_test_setup(toolong_local_registration_exits, setup),
    cmocka_unit_test_setup(toolong_local_registration_keeps, setup),
    cmocka_unit_test_setup(total_limit_ends_local_exchange, setup),
    cmocka_unit_test_setup(toolong_without_exchange, setup),
    cmocka_unit_test_setup(toolong_ends_services_exchange, setup),
    cmocka_unit_test_setup(toolong_services_registration_exits, setup),
    cmocka_unit_test_setup(star_abort_services_exchange, setup),
    cmocka_unit_test_setup(toolong_ends_iauth_exchange, setup),
#endif
    cmocka_unit_test_setup(held_during_webirc_check_then_replayed, setup),
    cmocka_unit_test_setup(abort_during_webirc_check_drops_held_lines, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
