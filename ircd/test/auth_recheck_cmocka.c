/*
 * auth_recheck_cmocka.c - the registration checks a Keycloak answer owes
 * run from the event loop, once, for requests still there.
 *
 * A libkc completion never runs registration in its own stack: it queues
 * the client's AuthRequest (auth_recheck_later()), and one 0-second timer
 * drains the queue in the event loop's timer pass, which follows the
 * current dispatch in the same pass (engine loop: dispatch, then
 * timer_run()).  This drives the REAL code:
 *
 * - s_auth.c is included, compiled with -ffunction-sections and linked
 *   with --gc-sections, so the program keeps auth_recheck_later(), the
 *   timer callback, check_auth_finished(), destroy_auth_request(),
 *   auth_detach_client() and what they call, and nothing else of s_auth.c;
 *   only that needs the ircd around it here;
 * - the real event core (ircd_events.c: timers, sockets) and the engines
 *   this build has (@ENGINE_C@), so the timer pass and the engine loop's
 *   order are the server's own;
 * - register_user() is the fake: it registers, exits the client (as
 *   free_client() does: the real destroy_auth_request(), then the client
 *   poisoned), exits ANOTHER queued client, or queues one more, per case.
 *
 * timer_add() is wrapped (-Wl,--wrap=timer_add) to count how often the
 * queue's timer is armed.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#include "../s_auth.c"

/* ------------------------------------------------------------------ */
/* The ircd around the queue                                           */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int running = 1;
int log_inassert;
struct Client me;
static struct ServerStatistics server_stats;
struct ServerStatistics *ServerStats = &server_stats;

static int errors_logged;      /**< log_write() at L_ERROR */
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  if (severity == L_ERROR)
    errors_logged++;
}
void debug(int level, const char *form, ...) {}
int feature_int(enum Feature feat) { return 20; }   /* FEAT_POLLS_PER_LOOP */
int feature_bool(enum Feature feat) { return 0; }
const char *feature_str(enum Feature feat) { return ""; }
void server_restart(const char *message) { fail_msg("server_restart: %s", message); }
void thread_pool_poll(void) {}

/** Arms of any timer, counted (the queue's is the only one armed here
 * outside the engine-loop case's own). */
static int timer_arms;
void __real_timer_add(struct Timer *timer, EventCallBack call, void *data,
                      enum TimerType type, time_t value);
void __wrap_timer_add(struct Timer *timer, EventCallBack call, void *data,
                      enum TimerType type, time_t value)
{
  if (timer == &auth_recheck_timer)
    timer_arms++;
  __real_timer_add(timer, call, data, type, value);
}

/* ------------------------------------------------------------------ */
/* Clients and their registration                                      */
/* ------------------------------------------------------------------ */

enum outcome { KEEPS, EXITS };

struct fake {
  struct Client cli;
  struct Connection con;
  struct User user;
  struct AuthRequest *auth;    /**< its request (the real struct) */
  enum outcome outcome;
  struct fake *exits_other;    /**< its registration exits this one too */
  struct fake *queues_other;   /**< its registration queues this one */
  int checks;                  /**< register_user() calls for it */
  int registered;
  int freed;
};

#define NFAKE 4
static struct fake fakes[NFAKE];
static int in_dispatch;        /**< a socket callback (a handler) is running */
static int ran_in_dispatch;    /**< register_user() ran inside one */

static struct fake *fake_of(struct Client *cptr)
{
  int i;
  for (i = 0; i < NFAKE; i++)
    if (&fakes[i].cli == cptr)
      return &fakes[i];
  return NULL;
}

/** A connecting client past NICK and USER whose request waits on nothing
 * but its owed check. */
static struct fake *new_client(int i, enum outcome outcome)
{
  struct fake *f = &fakes[i];
  struct AuthRequest *auth = calloc(1, sizeof(*auth));

  memset(f, 0, sizeof(*f));
  f->outcome = outcome;
  cli_magic(&f->cli) = CLIENT_MAGIC;
  con_magic(&f->con) = CONNECTION_MAGIC;
  cli_connect(&f->cli) = &f->con;
  con_client(&f->con) = &f->cli;
  s_fd(&con_socket(&f->con)) = 100 + i;
  cli_status(&f->cli) = STAT_UNKNOWN_USER;
  cli_user(&f->cli) = &f->user;
  ircd_strncpy(cli_name(&f->cli), "nick", sizeof(cli_name(&f->cli)));
  ircd_strncpy(f->user.username, "user", sizeof(f->user.username));
  ircd_strncpy(cli_sockhost(&f->cli), "host.test", sizeof(cli_sockhost(&f->cli)));

  auth->client = &f->cli;
  s_fd(&auth->socket) = -1;
  timer_init(&auth->timeout);
  timer_init(&auth->loctimeout);
  FlagSet(&auth->flags, AR_PASSWORD_CHECKED);   /* no Client block here */
  cli_auth(&f->cli) = auth;
  f->auth = auth;
  return f;
}

/** free_client() of a local client: its request destroyed (the real
 * destroy_auth_request()), then the client poisoned. */
static void free_fake(struct fake *f)
{
  if (cli_auth(&f->cli))
    destroy_auth_request(cli_auth(&f->cli));
  f->freed = 1;
  memset(&f->cli, 0xA5, sizeof(f->cli));
  memset(&f->con, 0xA5, sizeof(f->con));
}

/* s_user.c: registration as each case wants it. */
int register_user(struct Client *cptr, struct Client *sptr)
{
  struct fake *f = fake_of(cptr);

  assert_non_null(f);
  assert_false(f->freed);
  f->checks++;
  if (in_dispatch)
    ran_in_dispatch++;
  if (f->queues_other)
    auth_recheck_later(f->queues_other->auth);
  if (f->exits_other)
    free_fake(f->exits_other);
  if (f->outcome == KEEPS) {
    f->registered++;
    return 0;
  }
  free_fake(f);
  return CPTR_KILLED;
}

/* What check_auth_finished() and destroy_auth_request() reach on the way,
 * and what the rest of the code kept with them names (IAuth's queue, the
 * replies), none of which runs in these cases. */
int HighestFd;
struct Client *LocalClientArray[MAXCONNECTIONS];
int abort_sasl(struct Client *cptr, int timeout) { return 0; }
void geoip_apply(struct Client *cptr) {}
int find_kill(struct Client *cptr) { return 0; }
void authtoken_note_pass(struct Client *cptr) {}
int bounce_enabled_for(struct Client *cptr) { return 0; }
int bounce_burst_in_progress(void) { return 0; }
int bounce_defer_registration(struct Client *cli) { fail(); return -1; }
struct BouncerSession *bounce_get_session(struct Client *cptr) { return NULL; }
int bounce_has_sessions(const char *account) { return 0; }
enum AuthorizationCheckResult conf_check_client(struct Client *cptr) { return ACR_OK; }
int verify_sslclifp(struct Client *cptr, struct ConfItem *aconf) { return 1; }
void delete_resolver_queries(const void *vptr) {}
/* The native DNSBL: lookups started and cancelled, by request. */
static struct DNSBLRequest dnsbl_reqs[4];
static int dnsbl_checks, dnsbl_cancels;
static struct DNSBLRequest *dnsbl_cancelled;
void dnsbl_cancel(struct DNSBLRequest *request)
{
  dnsbl_cancels++;
  dnsbl_cancelled = request;
}
int dnsbl_check(struct Client *cptr, struct DNSBLRequest **request)
{
  *request = &dnsbl_reqs[++dnsbl_checks % 4];
  return 1;
}
static int exits;             /**< exits the cases expected */

/* The native DNSBL's verdict, as a case sets it (-1: none expected), and
 * what was applied of it. */
static int verdict_blocked = -1;
static enum DNSBLAction verdict_action;
static int verdicts, marks_applied, marks_unapplied;
int dnsbl_result(struct Client *cptr, struct DNSBLRequest *request,
                 enum DNSBLAction *action, const char **mark)
{
  if (verdict_blocked < 0)
    fail_msg("dnsbl_result: no verdict expected");
  verdicts++;
  *action = verdict_action;
  *mark = NULL;
  return verdict_blocked;
}
int add_mark(struct Client *sptr, const char *dnsbl) { return 0; }
void dnsbl_apply_marks(struct Client *cptr, struct DNSBLRequest *request)
{ marks_applied++; }
void dnsbl_unapply_marks(struct Client *cptr, const struct DNSBLRequest *request)
{ marks_unapplied++; }
/* class= of the verdict, and the connection class it puts the client in
 * (auth_assign_class(), as IAuth's D line). */
static const char *verdict_class;
const char *dnsbl_class(const struct DNSBLRequest *request) { return verdict_class; }
static struct ConnectionClass vip_class;
static struct ConfItem vip_conf, *attached_conf;
struct ConfItem *GlobalConfList;
struct ConnectionClass *do_find_class(const char *name, int extras)
{
  return strcmp(name, "vip") ? NULL : &vip_class;
}
struct ConfItem *make_conf(int type)
{
  memset(&vip_conf, 0, sizeof(vip_conf));
  vip_conf.status = type;
  return &vip_conf;
}
static enum AuthorizationCheckResult attach_result = ACR_OK;
enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf)
{
  if (attach_result == ACR_OK)
    attached_conf = aconf;
  return attach_result;
}
static int detached;
void conf_detach(struct Client *cptr, struct ConfItem *aconf)
{
  if (aconf == attached_conf)
    attached_conf = NULL;
  detached++;
}
char *get_client_class(struct Client *acptr) { return "class"; }
const char *get_client_name(const struct Client *sptr, int showip) { return "name"; }
int hAddClient(struct Client *cptr) { return 0; }
struct Client *hSeekClient(const char *name, int TMask) { return NULL; }
void IPcheck_connect_fail(const struct Client *cptr, int disconnect) {}
int IPcheck_remote_connect(struct Client *cptr, int is_burst) { return 1; }
int find_except_conf(struct Client *cptr, int flags) { return 0; }
unsigned int ircrandom(void) { return 4; }
static const char *expect_exit;   /**< the exit_client() a case expects */
int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{
  if (!expect_exit || strcmp(comment, expect_exit))
    fail_msg("exit_client: %s", comment);
  exits++;
  return CPTR_KILLED;
}
int ircd_snprintf(struct Client *dest, char *buf, size_t len,
                  const char *format, ...) { if (len) buf[0] = '\0'; return 0; }
int ircd_vsnprintf(struct Client *dest, char *buf, size_t len,
                   const char *format, va_list args) { if (len) buf[0] = '\0'; return 0; }
/** The exit a case expects (exit_client_msg()'s pattern), or NULL: any
 * other exit fails the case. */
static const char *expect_exit_msg;
int exit_client_msg(struct Client *cptr, struct Client *bcptr,
                    struct Client *sptr, const char *pattern, ...)
{
  if (!expect_exit_msg || strcmp(pattern, expect_exit_msg))
    fail_msg("exit_client_msg: %s", pattern);
  exits++;
  return CPTR_KILLED;
}
void send_queued(struct Client *to) {}
static int successes;          /**< RPL_SASLSUCCESS sent */
static int failures;           /**< ERR_SASLFAIL sent */
static int mechlists;          /**< ERR_SASLMECHS sent */
static int last_reply;         /**< the last numeric sent */
int send_reply(struct Client *to, int reply, ...)
{
  if ((reply & ~SND_EXPLICIT) == RPL_SASLSUCCESS)
    successes++;
  if ((reply & ~SND_EXPLICIT) == ERR_SASLFAIL)
    failures++;
  if ((reply & ~SND_EXPLICIT) == ERR_SASLMECHS)
    mechlists++;
  last_reply = reply & ~SND_EXPLICIT;
  return 0;
}
/* sasl_auth.c (not linked): a failed exchange counted toward
 * SASL_MAX_FAILURES. */
static int counted_failures;
void sasl_failure_count(struct Client *cptr) { counted_failures++; }
/* ... and an exchange the client abandoned (sasl_auth.c): whom. */
static struct Client *abandoned;
void sasl_exchange_abandoned(struct Client *cptr, int timeout) { abandoned = cptr; }
/* m_cap.c: what the sasl capability advertises (none here). */
const char *cap_sasl_mechanisms(void) { return NULL; }
void sendrawto_one(struct Client *to, const char *pattern, ...) {}
void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description) {}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...) {}
void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...) {}
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
                                      time_t *rate, const char *pattern, ...) {}
struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{ fail(); return NULL; }
void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio) {}
void msgq_clean(struct MsgBuf *mb) {}
void msgq_delete(struct MsgQ *mq, unsigned int length) {}
IOResult os_sendv_nonb(int fd, struct MsgQ *buf, unsigned int *len_in,
                       unsigned int *len_out) { return IO_FAILURE; }

/* sasl_auth.c (not linked): the login record IAuth's L writes, and the
 * account rule's verdict -- a client the ircd has logged in may not be
 * logged in to another account (its own cases: sasl_handler_cmocka). */
static int identity_sets, refusals;
void sasl_identity_set(struct Client *cptr, const char *account,
                       time_t acc_create, const char *kc_id, int id_live)
{
  identity_sets++;
  ircd_strncpy(cli_saslaccount(cptr), account ? account : "", ACCOUNTLEN + 1);
}
int sasl_reauth_refused(struct Client *sptr, const char *account,
                        const char *kc_id)
{
  if (!IsAccount(sptr) || cli_auth(sptr)
      || 0 == ircd_strcmp(cli_user(sptr)->account, account))
    return 0;
  refusals++;
  return 1;
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

static int setup(void **state)
{
  memset(fakes, 0, sizeof(fakes));
  timer_arms = 0;
  in_dispatch = ran_in_dispatch = 0;
  successes = failures = identity_sets = refusals = 0;
  mechlists = last_reply = 0;
  counted_failures = 0;
  abandoned = NULL;
  expect_exit_msg = NULL;
  exits = 0;
  dnsbl_checks = dnsbl_cancels = 0;
  dnsbl_cancelled = NULL;
  verdict_blocked = -1;
  verdict_action = DNSBL_ACT_NONE;
  verdicts = marks_applied = marks_unapplied = 0;
  verdict_class = NULL;
  attached_conf = NULL;
  detached = 0;
  attach_result = ACR_OK;
  errors_logged = 0;
  vip_class.valid = 1;
  expect_exit = NULL;
  CurrentTime = time(NULL);
  return 0;
}

/** A check is owed once however often it is queued, its timer armed once,
 * and the timer pass runs each owed check once, then disarms. */
static void queued_once_checked_once(void **state)
{
  struct fake *a = new_client(0, KEEPS), *b = new_client(1, KEEPS);

  auth_recheck_later(a->auth);
  auth_recheck_later(b->auth);
  auth_recheck_later(a->auth);                 /* AR_RECHECK: no second entry */
  assert_true(FlagHas(&a->auth->flags, AR_RECHECK));
  assert_int_equal(timer_arms, 1);
  assert_true(t_active(&auth_recheck_timer));
  assert_int_equal(a->checks + b->checks, 0);  /* nothing in this stack */

  timer_run();                                 /* the loop's timer pass */
  assert_int_equal(a->checks, 1);
  assert_int_equal(b->checks, 1);
  assert_int_equal(a->registered + b->registered, 2);
  assert_null(cli_auth(&a->cli));              /* registered: request gone */
  assert_null(auth_recheck_list);
  assert_false(t_active(&auth_recheck_timer));

  auth_recheck_later(new_client(2, KEEPS)->auth);   /* armed again */
  assert_int_equal(timer_arms, 2);
  timer_run();
  assert_int_equal(fakes[2].checks, 1);
}

/** A request destroyed while its check is queued (the client exited by
 * another route: QUIT, a ping timeout) leaves the queue; the others run. */
static void destroyed_request_leaves_the_queue(void **state)
{
  struct fake *a = new_client(0, KEEPS), *b = new_client(1, KEEPS);

  auth_recheck_later(a->auth);
  auth_recheck_later(b->auth);
  free_fake(a);
  timer_run();
  assert_int_equal(a->checks, 0);
  assert_int_equal(b->checks, 1);
  assert_null(auth_recheck_list);
}

/** A request detached from its client while queued (a bouncer revive frees
 * the connecting client and keeps the request: auth_detach_client()) leaves
 * the queue and is never checked. */
static void detached_request_leaves_the_queue(void **state)
{
  struct fake *a = new_client(0, KEEPS);
  struct AuthRequest *auth = a->auth;

  auth_recheck_later(auth);
  auth_detach_client(auth);
  assert_false(FlagHas(&auth->flags, AR_RECHECK));
  assert_null(auth_recheck_list);
  timer_run();
  assert_int_equal(a->checks, 0);
  destroy_auth_request(auth);                  /* its own timeout's job */
}

/** Draining: the check that runs first exits the OTHER queued client (its
 * request destroyed on the way): that one is never checked, and nothing
 * reads it. */
static void a_check_that_exits_another_queued_client(void **state)
{
  struct fake *a = new_client(0, EXITS), *b = new_client(1, EXITS);

  a->exits_other = b;
  b->exits_other = a;
  auth_recheck_later(a->auth);
  auth_recheck_later(b->auth);
  timer_run();
  assert_int_equal(a->checks + b->checks, 1);  /* whichever ran first */
  assert_true(a->freed);
  assert_true(b->freed);
  assert_null(auth_recheck_list);
}

/** A check queued from inside the timer pass (a registration that leads to
 * another owed check) finds the timer active, arms nothing, and is run in
 * the same pass. */
static void queued_during_the_pass_runs_in_it(void **state)
{
  struct fake *a = new_client(0, KEEPS), *b = new_client(1, KEEPS);

  a->queues_other = b;
  auth_recheck_later(a->auth);
  assert_int_equal(timer_arms, 1);
  timer_run();
  assert_int_equal(timer_arms, 1);             /* found active: not re-armed */
  assert_int_equal(a->checks, 1);
  assert_int_equal(b->checks, 1);
  assert_null(auth_recheck_list);
  assert_false(t_active(&auth_recheck_timer));
}

/* The engine loop: a socket callback (a handler, or libkc's adapter) owes a
 * check; the check runs after the callback returns, in the same pass. */
static struct Socket handler_sock;
static int handler_peer;
static struct Timer stop_timer;

/* Ends the loop after this pass's timers.  Not running = 0 from the
 * callback: the engines take that as server_die() and run nothing more
 * of the pass. */
static void stop_after_timers(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE)
    running = 0;
}

static void handler_cb(struct Event *ev)
{
  if (ev_type(ev) == ET_READ) {
    char c;
    struct fake *f = s_data(ev_socket(ev));

    assert_int_equal(read(s_fd(ev_socket(ev)), &c, 1), 1);
    in_dispatch = 1;
    auth_recheck_later(f->auth);               /* a Keycloak answer, here */
    assert_int_equal(f->checks, 0);            /* not in this stack */
    in_dispatch = 0;
    timer_add(timer_init(&stop_timer), stop_after_timers, NULL,
              TT_RELATIVE, 0);                 /* this pass is the last */
  }
}

static void check_runs_in_the_same_engine_pass(void **state)
{
  struct fake *a = new_client(0, KEEPS);
  int sv[2];

  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  handler_peer = sv[1];
  assert_true(socket_add(&handler_sock, handler_cb, a, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  assert_int_equal(write(sv[1], "x", 1), 1);

  running = 1;
  event_loop();          /* one pass: dispatch (the callback), then timers */
  running = 1;

  assert_int_equal(a->checks, 1);              /* ran before the loop ended */
  assert_int_equal(ran_in_dispatch, 0);        /* and after the dispatch */
  assert_int_equal(a->registered, 1);
  socket_del(&handler_sock);
  close(sv[0]);
  close(sv[1]);
}

/* IAuth's SASL answers: L (logged in as) and Z (done). */

static int iauth_line(int (*handler)(struct IAuth *, struct Client *, int, char **),
                      struct fake *f, const char *arg)
{
  char buf[64];
  char *params[2];

  ircd_strncpy(buf, arg ? arg : "", sizeof(buf));
  params[0] = buf;
  params[1] = NULL;
  return handler(NULL, &f->cli, arg ? 1 : 0, params);
}

/** Z ends the exchange: success, and no cookie left -- one left behind
 * reads as an exchange still in flight, and the client's next AUTHENTICATE
 * goes to IAuth as its data, past the check that lets a client with a
 * login use only OAUTHBEARER. */
static void iauth_done_ends_the_exchange(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  FlagSet(&a->auth->flags, AR_NEEDS_USER);     /* registration waits */
  cli_saslcookie(&a->cli) = 9;
  iauth_line(iauth_cmd_sasl_loggedin, a, "alice:1700000000");
  assert_string_equal(cli_saslnamed(&a->cli), "alice");
  iauth_line(iauth_cmd_sasl_done, a, NULL);
  assert_int_equal(identity_sets, 1);        /* the success sets it */
  assert_string_equal(cli_saslaccount(&a->cli), "alice");
  assert_true(IsSASLComplete(&a->cli));
  assert_int_equal(successes, 1);
  assert_int_equal(cli_saslcookie(&a->cli), 0);
  destroy_auth_request(a->auth);
}

/** An L or Z with no exchange in flight (it failed, was aborted, timed
 * out) logs nobody in and tells the client nothing. */
static void iauth_answers_without_an_exchange_are_dropped(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  FlagSet(&a->auth->flags, AR_NEEDS_USER);
  iauth_line(iauth_cmd_sasl_loggedin, a, "alice");
  assert_string_equal(cli_saslnamed(&a->cli), "");
  iauth_line(iauth_cmd_sasl_done, a, NULL);
  assert_int_equal(identity_sets, 0);
  assert_false(IsSASLComplete(&a->cli));
  assert_int_equal(successes, 0);
  iauth_line(iauth_cmd_sasl_fail, a, NULL);   /* a late f: nothing told */
  assert_int_equal(failures, 0);
  destroy_auth_request(a->auth);
}

/** #223 through IAuth: an L naming another account for a client the ircd
 * has logged in is refused before anything of it is stored, the exchange
 * ends, and the Z after it gives no success. */
static void iauth_login_of_a_logged_in_client_refused(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  destroy_auth_request(a->auth);               /* registered */
  cli_status(&a->cli) = STAT_USER;
  ircd_strncpy(a->user.account, "xavier", sizeof(a->user.account));
  SetAccount(&a->cli);
  ircd_strncpy(cli_saslaccount(&a->cli), "xavier", ACCOUNTLEN + 1);
  SetSASLComplete(&a->cli);
  cli_saslcookie(&a->cli) = 5;

  SetSASLReauth(&a->cli);
  iauth_line(iauth_cmd_sasl_loggedin, a, "yvonne");
  assert_int_equal(refusals, 1);
  assert_false(IsSASLReauth(&a->cli));
  assert_string_equal(cli_saslnamed(&a->cli), "");
  assert_int_equal(identity_sets, 0);
  assert_string_equal(cli_saslaccount(&a->cli), "xavier");
  assert_int_equal(cli_saslcookie(&a->cli), 0);
  iauth_line(iauth_cmd_sasl_done, a, NULL);
  assert_int_equal(successes, 0);
  assert_string_equal(a->user.account, "xavier");
}

/** IAuth's other ends of an exchange -- its f (failed), and the failure
 * when IAuth can no longer be told (auth_iauth_sasl_fail()) -- end it
 * whole: no cookie, no re-authentication mark. */
static void iauth_fail_ends_clear_the_reauth_mark(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  FlagSet(&a->auth->flags, AR_NEEDS_USER);
  SetSASLComplete(&a->cli);
  cli_saslcookie(&a->cli) = 11;
  SetSASLReauth(&a->cli);
  iauth_line(iauth_cmd_sasl_fail, a, NULL);
  assert_int_equal(cli_saslcookie(&a->cli), 0);
  assert_false(IsSASLReauth(&a->cli));

  cli_saslcookie(&a->cli) = 12;
  SetSASLReauth(&a->cli);
  assert_int_equal(auth_iauth_sasl_fail(&a->cli), 1);
  assert_int_equal(cli_saslcookie(&a->cli), 0);
  assert_false(IsSASLReauth(&a->cli));
  destroy_auth_request(a->auth);
}

/** IAuth's l (908: the mechanism is not offered) ends the exchange at once
 * with its 904, as f does -- no cookie, registration let go on -- rather
 * than at the SASL timeout (iauthd-ts sends l and nothing after it).  An l
 * with no exchange tells the list only. */
static void iauth_mechs_end_the_exchange(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  FlagSet(&a->auth->flags, AR_NEEDS_USER);     /* registration waits */
  cli_saslcookie(&a->cli) = 13;
  auth_sasl_start(a->auth);                    /* the exchange's hold */
  iauth_line(iauth_cmd_sasl_mechs, a, "PLAIN");
  assert_int_equal(mechlists, 1);
  assert_int_equal(failures, 1);
  assert_int_equal(last_reply, ERR_SASLFAIL);  /* 908, then 904 */
  assert_int_equal(cli_saslcookie(&a->cli), 0);
  assert_false(FlagHas(&a->auth->flags, AR_SASL_PENDING));  /* let go on */

  iauth_line(iauth_cmd_sasl_mechs, a, "PLAIN");  /* no exchange now */
  assert_int_equal(mechlists, 2);
  assert_int_equal(failures, 1);
  destroy_auth_request(a->auth);
}

/** Before registration, a second exchange beside a completed login (the
 * re-authentication mark, m_authenticate()) that IAuth ends without a
 * success -- 908 (l), a failure (f), IAuth unreachable -- leaves the
 * earlier login exactly as it was: the flag and the identity
 * registration will apply.  Only Z replaces it. */
static void iauth_failed_second_exchange_keeps_the_login(void **state)
{
  int how;

  for (how = 0; how < 3; how++) {
    struct fake *a = new_client(0, KEEPS);

    FlagSet(&a->auth->flags, AR_NEEDS_USER);     /* registration waits */
    ircd_strncpy(cli_saslaccount(&a->cli), "liz", ACCOUNTLEN + 1);
    SetSASLComplete(&a->cli);
    cli_saslcookie(&a->cli) = 20 + how;
    SetSASLReauth(&a->cli);
    auth_sasl_start(a->auth);
    if (how == 0)
      iauth_line(iauth_cmd_sasl_mechs, a, "PLAIN");
    else if (how == 1)
      iauth_line(iauth_cmd_sasl_fail, a, NULL);
    else
      assert_int_equal(auth_iauth_sasl_fail(&a->cli), 1);
    assert_int_equal(cli_saslcookie(&a->cli), 0);
    assert_false(IsSASLReauth(&a->cli));
    assert_true(IsSASLComplete(&a->cli));
    assert_string_equal(cli_saslaccount(&a->cli), "liz");
    assert_int_equal(identity_sets, 0);
    destroy_auth_request(a->auth);
  }
}

/** SASL_MAX_FAILURES on the IAuth tier: its f counts, its l (908) and
 * IAuth unreachable do not, its Z (a login) resets the count; a
 * connection that reached the limit before registration is closed by
 * registration's check, before anything else it waits for. */
static void iauth_sasl_failures_and_the_limit(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  FlagSet(&a->auth->flags, AR_NEEDS_USER);     /* registration waits */
  cli_saslcookie(&a->cli) = 31;
  iauth_line(iauth_cmd_sasl_fail, a, NULL);
  assert_int_equal(counted_failures, 1);
  cli_saslcookie(&a->cli) = 32;
  iauth_line(iauth_cmd_sasl_mechs, a, "PLAIN");
  assert_int_equal(counted_failures, 1);
  cli_saslcookie(&a->cli) = 33;
  assert_int_equal(auth_iauth_sasl_fail(&a->cli), 1);
  assert_int_equal(counted_failures, 1);

  cli_sasl_failures(&a->cli) = 4;               /* a Z: a login */
  cli_saslcookie(&a->cli) = 34;
  iauth_line(iauth_cmd_sasl_loggedin, a, "alice");
  iauth_line(iauth_cmd_sasl_done, a, NULL);
  assert_int_equal(cli_sasl_failures(&a->cli), 0);
  destroy_auth_request(a->auth);

  a = new_client(1, KEEPS);                     /* the limit reached */
  FlagSet(&a->auth->flags, AR_NEEDS_USER);      /* still waits for USER */
  con_sasl_limited(cli_connect(&a->cli)) = 1;
  /* never under an exchange's hold: a login completing holds it while it
   * uses the client (sasl_login_apply() step 3 runs the check) */
  auth_sasl_start(a->auth);
  assert_int_equal(auth_set_account(a->auth, "alice"), 0);
  expect_exit = "Too many SASL failures";
  assert_int_equal(auth_sasl_done(a->auth), CPTR_KILLED);
  expect_exit = NULL;
}

/** Registration completing with an exchange in flight aborts it: one whose
 * credentials went out is abandoned by the client (counted). */
static void registration_mid_exchange_is_abandoned(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  cli_saslcookie(&a->cli) = 41;
  auth_complete_sasl(&a->cli);
  assert_ptr_equal(abandoned, &a->cli);
  destroy_auth_request(a->auth);
}

/* A WEBIRC password check out (m_webirc.c): registration waits for it --
 * the client's address is the gateway's until it finishes. */

/** Held, a client with nothing else outstanding is not registered by any
 * check; the check's end owes one from the event loop (not in the
 * completion's own stack), and that registers it. */
static void webirc_check_holds_registration(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  auth_webirc_hold(a->auth);
  assert_int_equal(check_auth_finished(a->auth), 0);   /* NICK/USER/CAP END */
  auth_recheck_later(a->auth);                         /* any owed check */
  timer_run();
  assert_int_equal(a->checks, 0);
  assert_non_null(cli_auth(&a->cli));

  auth_webirc_release_later(a->auth);                  /* the completion */
  assert_int_equal(a->checks, 0);                      /* not in its stack */
  assert_true(FlagHas(&a->auth->flags, AR_RECHECK));
  timer_run();
  assert_int_equal(a->checks, 1);
  assert_int_equal(a->registered, 1);
}

/** The end of a hold that is not there (a second completion, a client
 * whose check was never held) owes nothing. */
static void webirc_release_without_hold_owes_nothing(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  FlagSet(&a->auth->flags, AR_NEEDS_USER);
  auth_webirc_release_later(a->auth);
  assert_false(FlagHas(&a->auth->flags, AR_RECHECK));
  assert_int_equal(timer_arms, 0);
  destroy_auth_request(a->auth);
}

/** The registration timeout bounds the wait: a client still held when it
 * fires is refused (Registration Timeout), never registered. */
static void webirc_hold_ends_at_the_registration_timeout(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  auth_webirc_hold(a->auth);
  expect_exit_msg = "Registration Timeout";
  assert_int_equal(auth_ping_timeout(&a->cli), CPTR_KILLED);
  assert_int_equal(exits, 1);
  assert_int_equal(a->checks, 0);
  destroy_auth_request(a->auth);
}

/** A WEBIRC applied (its real address in place): the DNSBL lookup made at
 * connect, for the gateway's address, is cancelled and one made for the
 * client's; registration waits for that one. */
static void webirc_restarts_the_dnsbl_lookup(void **state)
{
  struct fake *a = new_client(0, KEEPS);
  struct DNSBLRequest *gateway_req = &dnsbl_reqs[0];

  a->auth->dnsbl_request = gateway_req;          /* answered or not */
  auth_dnsbl_restart(a->auth);
  assert_int_equal(dnsbl_cancels, 1);
  assert_ptr_equal(dnsbl_cancelled, gateway_req);
  assert_int_equal(dnsbl_checks, 1);
  assert_ptr_not_equal(a->auth->dnsbl_request, gateway_req);
  assert_true(FlagHas(&a->auth->flags, AR_DNSBL_PENDING));

  auth_recheck_later(a->auth);
  timer_run();
  assert_int_equal(a->checks, 0);                /* waits for the new one */
  destroy_auth_request(a->auth);
  assert_int_equal(dnsbl_cancels, 2);            /* the new one goes too */
}

/** IAuth gives the client another address (its I line): the DNSBL lookup
 * made for the old one is cancelled and one made for the new one, which
 * registration waits for -- as a WEBIRC does (auth_dnsbl_restart()). */
static void iauth_new_address_restarts_the_dnsbl_lookup(void **state)
{
  struct fake *a = new_client(0, KEEPS);
  struct DNSBLRequest *old_req = &dnsbl_reqs[0];
  char ip[] = "192.0.2.99";
  char *params[] = { ip, NULL };

  a->auth->dnsbl_request = old_req;
  assert_int_equal(iauth_cmd_ip_address(NULL, &a->cli, 1, params), 0);
  assert_int_equal(dnsbl_cancels, 1);
  assert_ptr_equal(dnsbl_cancelled, old_req);
  assert_int_equal(dnsbl_checks, 1);
  assert_true(FlagHas(&a->auth->flags, AR_DNSBL_PENDING));
  assert_string_equal(ircd_ntoa(&cli_ip(&a->cli)), "192.0.2.99");
  destroy_auth_request(a->auth);
}

/** While IAuth is still checking the client, the DNSBL verdict is not
 * acted on: IAuth may still give the client another address (an
 * IAuth-handled WEBIRC).  Once IAuth is done, the verdict is. */
static void dnsbl_verdict_waits_for_iauth(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  FlagSet(&a->auth->flags, AR_IAUTH_PENDING);
  verdict_blocked = 1;
  verdict_action = DNSBL_ACT_BLOCK_ALL;
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_int_equal(verdicts, 0);
  assert_int_equal(exits, 0);

  FlagClr(&a->auth->flags, AR_IAUTH_PENDING);              /* IAuth's D */
  expect_exit = "DNSBL blocked";
  assert_int_equal(check_auth_finished(a->auth), CPTR_KILLED);
  assert_int_equal(verdicts, 1);
  assert_int_equal(exits, 1);
  destroy_auth_request(a->auth);
}

/** IAuth gives another address after the gateway's lookup finished (but
 * before its D): the gateway's marks are never applied; the new
 * address's verdict is, once. */
static void late_iauth_address_gateway_marks_never_applied(void **state)
{
  struct fake *a = new_client(0, KEEPS);
  char ip[] = "192.0.2.99";
  char *params[] = { ip, NULL };

  a->auth->dnsbl_request = &dnsbl_reqs[0];          /* the gateway's, done */
  FlagSet(&a->auth->flags, AR_IAUTH_PENDING);
  verdict_blocked = 0;
  verdict_action = DNSBL_ACT_MARK;
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_int_equal(marks_applied, 0);
  iauth_cmd_ip_address(NULL, &a->cli, 1, params);   /* the I line, late */
  assert_int_equal(marks_unapplied, 0);              /* nothing to undo */
  FlagClr(&a->auth->flags, AR_DNSBL_PENDING);        /* the new answer */
  FlagClr(&a->auth->flags, AR_IAUTH_PENDING);        /* D */
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_int_equal(marks_applied, 1);
  assert_int_equal(a->registered, 1);
}

/** A verdict already applied when the address changes (a WEBIRC on a
 * client whose registration waits elsewhere) is undone: its marks and
 * the whitelist's exemption go before the new address is looked up. */
static void address_change_undoes_an_applied_verdict(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  FlagSet(&a->auth->flags, AR_DNSBL_APPLIED);
  SetDNSBLExempt(&a->cli);
  auth_dnsbl_restart(a->auth);
  assert_int_equal(marks_unapplied, 1);
  assert_false(IsDNSBLExempt(&a->cli));
  assert_false(FlagHas(&a->auth->flags, AR_DNSBL_APPLIED));
  assert_int_equal(dnsbl_checks, 1);
  destroy_auth_request(a->auth);
}

/* IAuth kills (k / K) and the native DNSBL whitelist: a native whitelist
 * hit overrides native DNSBL blocks only.  An IAuth program that checks
 * DNSBLs (the iauthd scripts) has applied its own whitelist before it
 * kills; its kill is carried out at once. */

static int iauth_kill_line(struct fake *f, const char *reason)
{
  char buf[64];
  char *params[2];

  ircd_strncpy(buf, reason, sizeof(buf));
  params[0] = buf;
  params[1] = NULL;
  return iauth_cmd_kill(NULL, &f->cli, 1, params);
}

/** An IAuth kill for a client the native DNSBL whitelists (its verdict
 * in, or still to come): the client is exited at once. */
static void iauth_kill_of_a_natively_whitelisted_client_at_once(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  FlagSet(&a->auth->flags, AR_IAUTH_PENDING);
  SetDNSBLExempt(&a->cli);
  expect_exit = "rbl listed";
  assert_int_equal(iauth_kill_line(a, "rbl listed"), 0);
  assert_int_equal(exits, 1);
  assert_int_equal(a->registered, 0);
  destroy_auth_request(a->auth);
}

/** A native whitelist hit, whatever native block also matched (the
 * verdict says whitelisted, not blocked): admitted. */
static void native_whitelist_admits(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  verdict_blocked = 0;
  verdict_action = DNSBL_ACT_WHITELIST;
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_int_equal(exits, 0);
  assert_int_equal(a->registered, 1);
}

/** A verdict with class=: the client is put in that connection class, by
 * the code IAuth's D line uses, before it registers. */
static void dnsbl_class_assigned_as_iauth_does(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  verdict_blocked = 0;
  verdict_action = DNSBL_ACT_MARK;
  verdict_class = "vip";
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_non_null(attached_conf);
  assert_ptr_equal(attached_conf->conn_class, &vip_class);
  assert_int_equal(a->registered, 1);
}

/** The gateway listed on a class= entry, IAuth's I to a clean address
 * (after the gateway's verdict was in, before IAuth's D): the client is
 * not put in that class.  The reverse -- a clean gateway, a listed client
 * address -- puts it there. */
static void dnsbl_class_follows_the_final_address(void **state)
{
  struct fake *a = new_client(0, KEEPS);
  char ip[] = "192.0.2.99";
  char *params[] = { ip, NULL };
  int listed_gateway;

  for (listed_gateway = 1; listed_gateway >= 0; listed_gateway--) {
    a = new_client(0, KEEPS);
    attached_conf = NULL;
    a->auth->dnsbl_request = &dnsbl_reqs[0];          /* the gateway's */
    FlagSet(&a->auth->flags, AR_IAUTH_PENDING);
    verdict_blocked = 0;
    verdict_action = DNSBL_ACT_MARK;
    verdict_class = listed_gateway ? "vip" : NULL;
    assert_int_equal(check_auth_finished(a->auth), 0);
    assert_null(attached_conf);                       /* not yet */
    iauth_cmd_ip_address(NULL, &a->cli, 1, params);   /* the I line */
    verdict_class = listed_gateway ? NULL : "vip";    /* the new address's */
    FlagClr(&a->auth->flags, AR_DNSBL_PENDING);
    FlagClr(&a->auth->flags, AR_IAUTH_PENDING);
    assert_int_equal(check_auth_finished(a->auth), 0);
    if (listed_gateway)
      assert_null(attached_conf);
    else
      assert_non_null(attached_conf);
  }
}

/** A class a verdict already attached is detached when the address
 * changes anyway (auth_dnsbl_restart()), with the marks. */
static void address_change_detaches_the_dnsbl_class(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  FlagSet(&a->auth->flags, AR_DNSBL_APPLIED);
  attached_conf = &vip_conf;
  a->auth->dnsbl_conf = &vip_conf;
  auth_dnsbl_restart(a->auth);
  assert_int_equal(detached, 1);
  assert_null(attached_conf);
  assert_null(a->auth->dnsbl_conf);
  destroy_auth_request(a->auth);
}

/** The DNSBL's class= names the class the client is in already: no
 * error, registration goes on. */
static void dnsbl_class_already_held_is_no_error(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  verdict_blocked = 0;
  verdict_action = DNSBL_ACT_MARK;
  verdict_class = "vip";
  attach_result = ACR_ALREADY_AUTHORIZED;
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_int_equal(errors_logged, 0);
  assert_int_equal(a->registered, 1);
}

/** IAuth's D gave a class: the native DNSBL's class= does not replace it. */
static void iauth_class_stands_over_dnsbl_class(void **state)
{
  struct fake *a = new_client(0, KEEPS);

  a->auth->dnsbl_request = &dnsbl_reqs[0];
  FlagSet(&a->auth->flags, AR_IAUTH_CLASS);
  verdict_blocked = 0;
  verdict_action = DNSBL_ACT_MARK;
  verdict_class = "vip";
  assert_int_equal(check_auth_finished(a->auth), 0);
  assert_null(attached_conf);
  assert_int_equal(a->registered, 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(queued_once_checked_once, setup),
    cmocka_unit_test_setup(destroyed_request_leaves_the_queue, setup),
    cmocka_unit_test_setup(detached_request_leaves_the_queue, setup),
    cmocka_unit_test_setup(a_check_that_exits_another_queued_client, setup),
    cmocka_unit_test_setup(queued_during_the_pass_runs_in_it, setup),
    cmocka_unit_test_setup(check_runs_in_the_same_engine_pass, setup),
    cmocka_unit_test_setup(iauth_done_ends_the_exchange, setup),
    cmocka_unit_test_setup(iauth_answers_without_an_exchange_are_dropped, setup),
    cmocka_unit_test_setup(iauth_login_of_a_logged_in_client_refused, setup),
    cmocka_unit_test_setup(iauth_fail_ends_clear_the_reauth_mark, setup),
    cmocka_unit_test_setup(iauth_mechs_end_the_exchange, setup),
    cmocka_unit_test_setup(iauth_failed_second_exchange_keeps_the_login, setup),
    cmocka_unit_test_setup(iauth_sasl_failures_and_the_limit, setup),
    cmocka_unit_test_setup(registration_mid_exchange_is_abandoned, setup),
    cmocka_unit_test_setup(webirc_check_holds_registration, setup),
    cmocka_unit_test_setup(webirc_release_without_hold_owes_nothing, setup),
    cmocka_unit_test_setup(webirc_hold_ends_at_the_registration_timeout, setup),
    cmocka_unit_test_setup(webirc_restarts_the_dnsbl_lookup, setup),
    cmocka_unit_test_setup(iauth_new_address_restarts_the_dnsbl_lookup, setup),
    cmocka_unit_test_setup(dnsbl_verdict_waits_for_iauth, setup),
    cmocka_unit_test_setup(late_iauth_address_gateway_marks_never_applied, setup),
    cmocka_unit_test_setup(address_change_undoes_an_applied_verdict, setup),
    cmocka_unit_test_setup(iauth_kill_of_a_natively_whitelisted_client_at_once, setup),
    cmocka_unit_test_setup(native_whitelist_admits, setup),
    cmocka_unit_test_setup(dnsbl_class_assigned_as_iauth_does, setup),
    cmocka_unit_test_setup(dnsbl_class_follows_the_final_address, setup),
    cmocka_unit_test_setup(address_change_detaches_the_dnsbl_class, setup),
    cmocka_unit_test_setup(dnsbl_class_already_held_is_no_error, setup),
    cmocka_unit_test_setup(iauth_class_stands_over_dnsbl_class, setup),
  };

  event_init(64);
  return cmocka_run_group_tests(tests, NULL, NULL);
}
