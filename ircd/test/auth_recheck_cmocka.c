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

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
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
void dnsbl_cancel(struct DNSBLRequest *request) {}
int dnsbl_result(struct Client *cptr, struct DNSBLRequest *request,
                 enum DNSBLAction *action, const char **mark) { fail(); return 0; }
int add_mark(struct Client *sptr, const char *dnsbl) { return 0; }
char *get_client_class(struct Client *acptr) { return "class"; }
const char *get_client_name(const struct Client *sptr, int showip) { return "name"; }
int hAddClient(struct Client *cptr) { return 0; }
struct Client *hSeekClient(const char *name, int TMask) { return NULL; }
void IPcheck_connect_fail(const struct Client *cptr, int disconnect) {}
unsigned int ircrandom(void) { return 4; }
int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{ fail_msg("exit_client: %s", comment); return 0; }
int ircd_snprintf(struct Client *dest, char *buf, size_t len,
                  const char *format, ...) { if (len) buf[0] = '\0'; return 0; }
static int successes;          /**< RPL_SASLSUCCESS sent */
int send_reply(struct Client *to, int reply, ...)
{
  if ((reply & ~SND_EXPLICIT) == RPL_SASLSUCCESS)
    successes++;
  return 0;
}
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
  successes = identity_sets = refusals = 0;
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
    running = 0;                               /* this pass is the last */
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

  iauth_line(iauth_cmd_sasl_loggedin, a, "yvonne");
  assert_int_equal(refusals, 1);
  assert_string_equal(cli_saslnamed(&a->cli), "");
  assert_int_equal(identity_sets, 0);
  assert_string_equal(cli_saslaccount(&a->cli), "xavier");
  assert_int_equal(cli_saslcookie(&a->cli), 0);
  iauth_line(iauth_cmd_sasl_done, a, NULL);
  assert_int_equal(successes, 0);
  assert_string_equal(a->user.account, "xavier");
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
  };

  event_init(64);
  return cmocka_run_group_tests(tests, NULL, NULL);
}
