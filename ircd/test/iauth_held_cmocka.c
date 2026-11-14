/*
 * iauth_held_cmocka.c - what becomes of an IAuth instance's program and of
 * the clients it was still checking when the instance goes away (it exited,
 * a write to it failed, "REHASH a" restarted it, its program changed or its
 * block was removed).
 *
 * This drives the REAL code, as auth_recheck_cmocka does:
 *
 * - s_auth.c is included, compiled with -ffunction-sections and linked
 *   with --gc-sections, so the program keeps iauth_disconnect(),
 *   sendto_iauth(), the registration check queue and what they call, and
 *   nothing else of s_auth.c; only that needs the ircd around it here;
 * - the real event core (ircd_events.c: timers, sockets) and the engines
 *   this build has (@ENGINE_C@): a running instance is a real socket, and
 *   the event loop's timer pass is the server's own;
 * - the message queue to the program is a fake that records each line
 *   (what the program is told), and can be made to fail the write;
 * - register_user() and exit_client_msg() are fakes that record what
 *   became of a client, and free it as free_client() does.
 *
 * kill() is wrapped (-Wl,--wrap=kill) to see which process is signalled.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#include "../s_auth.c"

/* ------------------------------------------------------------------ */
/* The ircd around the code under test                                 */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int running = 1;
int log_inassert;
struct Client me;
static struct ServerStatistics server_stats;
struct ServerStatistics *ServerStats = &server_stats;
int HighestFd;
struct Client *LocalClientArray[MAXCONNECTIONS];

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
void debug(int level, const char *form, ...) {}
int feature_int(enum Feature feat) { return 20; }   /* FEAT_POLLS_PER_LOOP */
int feature_bool(enum Feature feat) { return 0; }
const char *feature_str(enum Feature feat) { return ""; }
void server_restart(const char *message) { fail_msg("server_restart: %s", message); }
void thread_pool_poll(void) {}

/** Signals sent, through the real kill(). */
static int kills;
static pid_t killed_pid;
static int killed_sig;
int __real_kill(pid_t pid, int sig);
int __wrap_kill(pid_t pid, int sig)
{
  kills++;
  killed_pid = pid;
  killed_sig = sig;
  return __real_kill(pid, sig);
}

/* ------------------------------------------------------------------ */
/* What the program is told                                            */
/* ------------------------------------------------------------------ */

#define NTOLD 64
static char told[NTOLD][BUFSIZE];    /**< lines handed to the queue */
static int ntold;
static int write_fails;              /**< the next write to the program fails */
static struct MsgBuf *fake_mb = (struct MsgBuf *) &told;   /* never read */

struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{
  va_list vl;

  assert_true(ntold < NTOLD);
  va_start(vl, format);
  ircd_vsnprintf(0, told[ntold++], BUFSIZE, format, vl);
  va_end(vl);
  return fake_mb;
}
void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio) { mq->length++; }
void msgq_clean(struct MsgBuf *mb) {}
void msgq_delete(struct MsgQ *mq, unsigned int length)
{
  mq->length -= length > mq->length ? mq->length : length;
}
IOResult os_sendv_nonb(int fd, struct MsgQ *buf, unsigned int *len_in,
                       unsigned int *len_out)
{
  if (write_fails) {
    write_fails = 0;
    return IO_FAILURE;
  }
  *len_in = *len_out = buf->length;
  return IO_SUCCESS;
}

/** Index of the first line told since \a from that starts with \a text,
 * or -1. */
static int told_index(int from, const char *text)
{
  int i;
  for (i = from; i < ntold; i++)
    if (0 == strncmp(told[i], text, strlen(text)))
      return i;
  return -1;
}

/* ------------------------------------------------------------------ */
/* Clients and what becomes of them                                    */
/* ------------------------------------------------------------------ */

struct fake {
  struct Client cli;
  struct Connection con;
  struct User user;
  struct AuthRequest *auth;    /**< its request (the real struct) */
  int registered;              /**< register_user() calls */
  char exited[64];             /**< exit reason, when it was exited */
  int freed;
};

#define NFAKE 4
static struct fake fakes[NFAKE];

static struct fake *fake_of(struct Client *cptr)
{
  int i;
  for (i = 0; i < NFAKE; i++)
    if (&fakes[i].cli == cptr)
      return &fakes[i];
  return NULL;
}

/** A connecting client on descriptor 10 + \a i, past NICK and USER, whose
 * request waits on nothing but IAuth (none is asked yet). */
static struct fake *new_client(int i)
{
  struct fake *f = &fakes[i];
  struct AuthRequest *auth = calloc(1, sizeof(*auth));
  int fd = 10 + i;

  memset(f, 0, sizeof(*f));
  cli_magic(&f->cli) = CLIENT_MAGIC;
  con_magic(&f->con) = CONNECTION_MAGIC;
  cli_connect(&f->cli) = &f->con;
  con_client(&f->con) = &f->cli;
  s_fd(&con_socket(&f->con)) = fd;
  cli_status(&f->cli) = STAT_UNKNOWN_USER;
  cli_user(&f->cli) = &f->user;
  ircd_strncpy(cli_name(&f->cli), "nick", sizeof(cli_name(&f->cli)));
  ircd_strncpy(f->user.username, "user", sizeof(f->user.username));
  ircd_strncpy(cli_sockhost(&f->cli), "host.test", sizeof(cli_sockhost(&f->cli)));
  ircd_strncpy(cli_sock_ip(&f->cli), "192.0.2.1", sizeof(cli_sock_ip(&f->cli)));

  auth->client = &f->cli;
  auth->port = 40000 + i;
  auth->cookie = 1;                             /* its PING answered */
  s_fd(&auth->socket) = -1;
  timer_init(&auth->timeout);
  timer_init(&auth->loctimeout);
  FlagSet(&auth->flags, AR_PASSWORD_CHECKED);   /* no Client block here */
  cli_auth(&f->cli) = auth;
  f->auth = auth;
  LocalClientArray[fd] = &f->cli;
  if (fd > HighestFd)
    HighestFd = fd;
  return f;
}

/** free_client() of a local client: its socket closed (the "D" line,
 * close_connection()), its request destroyed (the real
 * destroy_auth_request()), its descriptor free, then the client poisoned. */
static void free_fake(struct fake *f)
{
  int fd = s_fd(&con_socket(&f->con));

  auth_send_exit(&f->cli);
  if (cli_auth(&f->cli))
    destroy_auth_request(cli_auth(&f->cli));
  LocalClientArray[fd] = NULL;
  f->freed = 1;
  memset(&f->cli, 0xA5, sizeof(f->cli));
  memset(&f->con, 0xA5, sizeof(f->con));
}

/* s_user.c: the client registers. */
int register_user(struct Client *cptr, struct Client *sptr)
{
  struct fake *f = fake_of(cptr);

  assert_non_null(f);
  assert_false(f->freed);
  f->registered++;
  return 0;
}

/* s_misc.c: the client is refused. */
int exit_client_msg(struct Client *cptr, struct Client *bcptr,
                    struct Client *sptr, const char *pattern, ...)
{
  struct fake *f = fake_of(bcptr);

  assert_non_null(f);
  assert_false(f->freed);
  ircd_strncpy(f->exited, pattern, sizeof(f->exited));
  free_fake(f);
  return CPTR_KILLED;
}

/* What the code under test reaches on the way, none of it of interest. */
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
static int sasl_fails;          /**< ERR_SASLFAIL sent */
int send_reply(struct Client *to, int reply, ...)
{
  if ((reply & ~SND_EXPLICIT) == ERR_SASLFAIL)
    sasl_fails++;
  return 0;
}
void sendrawto_one(struct Client *to, const char *pattern, ...) {}
void send_queued(struct Client *to) {}
void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description) {}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...) {}
void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...) {}
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
                                      time_t *rate, const char *pattern, ...) {}
void sasl_identity_set(struct Client *cptr, const char *account,
                       time_t acc_create, const char *kc_id, int id_live) {}
int sasl_reauth_refused(struct Client *sptr, const char *account,
                        const char *kc_id) { return 0; }
void register_child(pid_t child, SigChldCallBack call, void *datum) {}
/* An approval naming a class (none does here). */
struct ConfItem *GlobalConfList;
struct ConfItem *make_conf(int type) { fail(); return NULL; }
struct ConnectionClass *do_find_class(const char *name, int extras)
{ fail(); return NULL; }
enum AuthorizationCheckResult attach_conf(struct Client *cptr,
                                          struct ConfItem *aconf)
{ fail(); return ACR_OK; }

/* ------------------------------------------------------------------ */
/* IAuth instances                                                     */
/* ------------------------------------------------------------------ */

static int peer_fd = -1;       /**< the program's end of a running instance */

static void sock_cb(struct Event *ev) {}

/** An instance, not running (no program: it went away, or never started). */
static struct IAuth *new_instance(void)
{
  struct IAuth *ia = calloc(1, sizeof(*ia));

  s_fd(i_socket(ia)) = -1;
  s_fd(i_stderr(ia)) = -1;
  timer_init(&ia->i_respawn);
  return ia;
}

/** Make \a ia running: its main socket is a real one, to a program that
 * reads nothing (what it is told is recorded by the fake queue).  Its
 * teardown calls sock_cb(), which respawns nothing. */
static void run_instance(struct IAuth *ia)
{
  int sv[2];

  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  assert_true(socket_add(i_socket(ia), sock_cb, ia, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  peer_fd = sv[1];
}

/** Let instance \a ia go and free it, after the case's checks: the case's
 * clients are forgotten first, so that none is held by it. */
static void drop_instance(struct IAuth *ia)
{
  if (iauth == ia)
    iauth = NULL;
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  iauth_disconnect(ia);
  if (peer_fd >= 0)
    close(peer_fd);
  peer_fd = -1;
  free(ia);
}

/** The O line: \a ia announces policy \a policy. */
static void announce(struct IAuth *ia, const char *policy)
{
  char buf[16];
  char *params[2];

  ircd_strncpy(buf, policy, sizeof(buf));
  params[0] = buf;
  params[1] = NULL;
  iauth_cmd_policy(ia, NULL, 1, params);
}

/** A client line from \a ia (d, D) for \a f; the check it asks for. */
static void answer(struct IAuth *ia, struct fake *f,
                   int (*handler)(struct IAuth *, struct Client *, int, char **))
{
  char *params[2] = { NULL, NULL };

  if (handler(ia, &f->cli, 0, params) > 0)
    check_auth_finished(f->auth);
}

/** A new client whose check \a ia (running, the current instance) is
 * asked for: its C line. */
static struct fake *pending_client(int i)
{
  struct fake *f = new_client(i);

  start_iauth_query(f->auth);
  assert_true(FlagHas(&f->auth->flags, AR_IAUTH_PENDING));
  return f;
}

/** The instance goes away under its clients (its program exited, or it is
 * let go), with no instance after it: the current instance is \a ia, not
 * running, as while it waits out a retry delay. */
static void instance_goes_away(struct IAuth *ia)
{
  iauth_disconnect(ia);
  if (peer_fd >= 0)
    close(peer_fd);
  peer_fd = -1;
}

/* ------------------------------------------------------------------ */
/* Cases: the program is signalled                                     */
/* ------------------------------------------------------------------ */

static int setup(void **state)
{
  memset(fakes, 0, sizeof(fakes));
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  HighestFd = 0;
  ntold = 0;
  write_fails = 0;
  kills = 0;
  killed_pid = 0;
  killed_sig = 0;
  sasl_fails = 0;
  memset(&server_stats, 0, sizeof(server_stats));
  CurrentTime = time(NULL);
  iauth = NULL;
  auth_recheck_list = NULL;                     /* no case's check left */
  if (t_active(&auth_recheck_timer))
    timer_del(&auth_recheck_timer);
  return 0;
}

/** The instance let go sends its program SIGTERM, once its sockets are
 * closed: a program that ignores end of file does not outlive it. */
static void disconnect_signals_the_program(void **state)
{
  struct IAuth *ia = new_instance();
  int status;
  pid_t child = fork();

  assert_true(child >= 0);
  if (child == 0) {            /* a program that reads nothing */
    alarm(10);
    for (;;)
      pause();
  }
  iauth = ia;
  run_instance(ia);
  ia->i_pid = child;
  iauth_disconnect(ia);
  assert_int_equal(kills, 1);
  assert_int_equal(killed_pid, child);
  assert_int_equal(killed_sig, SIGTERM);
  assert_int_equal(ia->i_pid, 0);             /* signalled once, forgotten */
  assert_int_equal(s_fd(i_socket(ia)), -1);   /* after its sockets closed */
  assert_int_equal(waitpid(child, &status, 0), child);
  assert_true(WIFSIGNALED(status));
  assert_int_equal(WTERMSIG(status), SIGTERM);

  iauth_disconnect(ia);                       /* again: nothing to signal */
  assert_int_equal(kills, 1);
  close(peer_fd);
  peer_fd = -1;
  free(ia);
  iauth = NULL;
}

/** An instance with no process of its own to signal (never started, or
 * its program already reaped) signals nothing. */
static void no_process_no_signal(void **state)
{
  struct IAuth *ia = new_instance();

  iauth = ia;
  iauth_disconnect(ia);
  assert_int_equal(kills, 0);
  free(ia);
  iauth = NULL;
}

/** A reaped program is forgotten, so a process number the kernel gives to
 * another process is never signalled; another child's reaping changes
 * nothing. */
static void a_reaped_program_is_forgotten(void **state)
{
  struct IAuth *ia = new_instance();

  iauth = ia;
  ia->i_pid = 4242;
  iauth_child_reaped(4243, NULL, 0);
  assert_int_equal(ia->i_pid, 4242);
  iauth_child_reaped(4242, NULL, 0);
  assert_int_equal(ia->i_pid, 0);
  iauth_disconnect(ia);
  assert_int_equal(kills, 0);
  iauth = NULL;
  iauth_child_reaped(4242, NULL, 0);          /* no instance at all */
  free(ia);
}


/* ------------------------------------------------------------------ */
/* Cases: the clients the instance was checking                        */
/* ------------------------------------------------------------------ */

/** Under R, a client the instance was checking is not let in when the
 * instance goes away with none after it: refused, from the event loop
 * (never in the stack that let the instance go), "Authorization
 * Unavailable". */
static void required_and_no_instance_refuses(void **state)
{
  struct IAuth *ia = new_instance();
  struct fake *f;

  iauth = ia;
  run_instance(ia);
  announce(ia, "R");
  f = pending_client(0);
  instance_goes_away(ia);
  assert_int_equal(f->registered, 0);         /* nothing decided here */
  assert_string_equal(f->exited, "");
  timer_run();
  assert_int_equal(f->registered, 0);
  assert_string_equal(f->exited, "Authorization Unavailable");
  assert_int_equal(ServerStats->is_ref, 1);
  drop_instance(ia);
}

/** Without R, such a client is released: it registers without IAuth. */
static void optional_and_no_instance_releases(void **state)
{
  struct IAuth *ia = new_instance();
  struct fake *f;

  iauth = ia;
  run_instance(ia);
  announce(ia, "AU");
  f = pending_client(0);
  instance_goes_away(ia);
  assert_int_equal(f->registered, 0);
  timer_run();
  assert_int_equal(f->registered, 1);
  assert_string_equal(f->exited, "");
  drop_instance(ia);
}

/** Under R, a client IAuth had tentatively accepted (d) is released, as at
 * a registration timeout. */
static void tentatively_accepted_is_released(void **state)
{
  struct IAuth *ia = new_instance();
  struct fake *f;

  iauth = ia;
  run_instance(ia);
  announce(ia, "R");
  f = pending_client(0);
  answer(ia, f, iauth_cmd_soft_done);
  instance_goes_away(ia);
  timer_run();
  assert_int_equal(f->registered, 1);
  assert_string_equal(f->exited, "");
  drop_instance(ia);
}

/** An instance running by the time the server decides (REHASH a, a changed
 * program, a restart after a good run) is told about the client again: C
 * first, then the latest line of each kind in the order last told, never
 * the SASL exchange; the client waits for it, and registers when it
 * approves. */
static void handed_to_the_new_instance(void **state)
{
  struct IAuth *old = new_instance(), *ia;
  struct fake *f;
  char line[64];
  int mark, c, i;

  iauth = old;
  run_instance(old);
  announce(old, "RAUS");
  f = pending_client(0);
  auth_set_password(f->auth, "first");
  auth_set_nick(f->auth, "nick1");
  auth_set_password(f->auth, "second");        /* supersedes the first */
  cli_saslcookie(&f->cli) = 7;                  /* AUTHENTICATE PLAIN */
  auth_sasl_start(f->auth);
  assert_true(auth_send_sasl_start(&f->cli, "PLAIN", NULL));
  assert_true(auth_send_sasl_data(&f->cli, "AAAA"));
  instance_goes_away(old);
  assert_int_equal(sasl_fails, 1);              /* the exchange fails: 904 */
  assert_int_equal(cli_saslcookie(&f->cli), 0);

  ia = new_instance();                          /* started in the same step */
  iauth = ia;
  run_instance(ia);
  mark = ntold;
  timer_run();
  assert_int_equal(f->registered, 0);
  assert_string_equal(f->exited, "");
  c = told_index(mark, "10 C 192.0.2.1 40000 ");
  assert_int_equal(c, mark);                     /* introduced first */
  assert_true(told_index(mark, "10 H class") > c);   /* its hurry-up */
  assert_true(told_index(mark, "10 n nick1") > told_index(mark, "10 H class"));
  assert_true(told_index(mark, "10 P :second") > told_index(mark, "10 n nick1"));
  assert_int_equal(ntold - mark, 4);             /* each kind once */
  assert_int_equal(told_index(mark, "10 P :first"), -1);
  assert_int_equal(told_index(mark, "10 A"), -1);
  assert_int_equal(told_index(mark, "10 a"), -1);
  for (i = mark; i < ntold; i++)
    assert_true(0 == strncmp(told[i], "10 ", 3));
  /* it is pending on the new instance: told what it says next */
  ircd_snprintf(0, line, sizeof(line), "10 n nick2");
  IAuthSet(ia, IAUTH_UNDERNET);
  auth_set_nick(f->auth, "nick2");
  assert_true(told_index(mark, line) > c);
  answer(ia, f, iauth_cmd_done_client);         /* the new instance's D */
  assert_int_equal(f->registered, 1);
  free(old);
  drop_instance(ia);
}

/** What a held client says before the decision is kept, told to no one,
 * and told to the instance it is handed to. */
static void a_line_while_held_is_kept(void **state)
{
  struct IAuth *old = new_instance(), *ia;
  struct fake *f;
  int mark;

  iauth = old;
  run_instance(old);
  announce(old, "RA");
  f = pending_client(0);
  instance_goes_away(old);
  ia = new_instance();
  iauth = ia;
  run_instance(ia);
  IAuthSet(ia, IAUTH_ADDLINFO);
  mark = ntold;
  auth_set_password(f->auth, "late");           /* PASS in the window */
  assert_int_equal(ntold, mark);                /* sent to no one */
  timer_run();
  assert_true(told_index(mark, "10 C ") >= 0);
  assert_true(told_index(mark, "10 P :late") > told_index(mark, "10 C "));
  free(old);
  drop_instance(ia);
}

/** A held client that leaves before the decision is never handed over,
 * and the next client on its descriptor is introduced once. */
static void a_held_client_that_quits(void **state)
{
  struct IAuth *old = new_instance(), *ia;
  struct fake *f, *g;
  int mark, i, cs = 0;

  iauth = old;
  run_instance(old);
  announce(old, "R");
  f = pending_client(0);
  instance_goes_away(old);
  ia = new_instance();
  iauth = ia;
  run_instance(ia);
  mark = ntold;
  free_fake(f);                                 /* QUIT in the window */
  g = pending_client(0);                        /* same descriptor */
  timer_run();
  for (i = mark; i < ntold; i++)
    if (0 == strncmp(told[i], "10 C ", 5))
      cs++;
  assert_int_equal(cs, 1);
  assert_int_equal(g->registered, 0);           /* g waits for ia */
  assert_string_equal(g->exited, "");
  free(old);
  drop_instance(ia);
}

/** The new instance goes away as it is told (its write fails): the
 * clients are held again, not handed twice, and decided with no instance:
 * still required -- the new instance announced no policy -- so refused,
 * each once. */
static void the_new_instance_fails_while_told(void **state)
{
  struct IAuth *old = new_instance(), *ia;
  struct fake *f, *g;

  iauth = old;
  run_instance(old);
  announce(old, "R");
  f = pending_client(0);
  g = pending_client(1);
  instance_goes_away(old);
  ia = new_instance();
  iauth = ia;
  run_instance(ia);
  write_fails = 1;
  timer_run();
  assert_false(i_GetConnected(ia));
  assert_string_equal(f->exited, "Authorization Unavailable");
  assert_string_equal(g->exited, "Authorization Unavailable");
  assert_int_equal(f->registered + g->registered, 0);
  assert_int_equal(ServerStats->is_ref, 2);
  free(old);
  drop_instance(ia);
}

/** A tentatively accepted client under R whose T line, at its
 * registration timeout, cannot be written: the write takes the program
 * away under it, and it is still finished there -- it registers, it is
 * not refused. */
static void t_write_failure_finishes_the_client(void **state)
{
  struct IAuth *ia = new_instance();
  struct fake *f;

  iauth = ia;
  run_instance(ia);
  announce(ia, "R");
  f = pending_client(0);
  answer(ia, f, iauth_cmd_soft_done);
  write_fails = 1;
  assert_int_equal(auth_ping_timeout(&f->cli), 0);
  assert_false(i_GetConnected(ia));
  assert_int_equal(f->registered, 1);
  assert_string_equal(f->exited, "");
  timer_run();                                  /* nothing more */
  assert_int_equal(f->registered, 1);
  drop_instance(ia);
}

/** A held client whose registration times out before the decision is
 * decided there, as a pending one is: refused under R. */
static void a_held_client_times_out(void **state)
{
  struct IAuth *ia = new_instance();
  struct fake *f;

  iauth = ia;
  run_instance(ia);
  announce(ia, "R");
  f = pending_client(0);
  instance_goes_away(ia);
  assert_int_equal(auth_ping_timeout(&f->cli), CPTR_KILLED);
  assert_string_equal(f->exited, "Authorization Timeout");
  timer_run();                                  /* nothing left to do */
  assert_int_equal(f->registered, 0);
  drop_instance(ia);
}

/** A client handed to an instance that has announced no policy yet stays
 * as required as it was: its registration timeout refuses it; once the
 * instance announces a policy without R, it lets it in. */
static void handed_client_times_out_by_the_old_policy(void **state)
{
  struct IAuth *old = new_instance(), *ia;
  struct fake *f, *g;

  iauth = old;
  run_instance(old);
  announce(old, "R");
  f = pending_client(0);
  g = pending_client(1);
  instance_goes_away(old);
  ia = new_instance();
  iauth = ia;
  run_instance(ia);
  timer_run();
  assert_int_equal(auth_ping_timeout(&f->cli), CPTR_KILLED);
  assert_string_equal(f->exited, "Authorization Timeout");
  announce(ia, "A");
  assert_int_equal(auth_ping_timeout(&g->cli), 0);
  assert_int_equal(g->registered, 1);
  free(old);
  drop_instance(ia);
}

/** IAuth's circuit breaker open (R bypassed after repeated timeouts): a
 * held client is let in as a timed-out one is, not refused. */
static void an_open_circuit_breaker_releases(void **state)
{
  struct IAuth *ia = new_instance();
  struct fake *f;

  iauth = ia;
  run_instance(ia);
  announce(ia, "R");
  ia->i_timeout_count = IAUTH_CIRCUIT_BREAKER_THRESHOLD;
  ia->i_circuit_open = 1;
  f = pending_client(0);
  instance_goes_away(ia);
  timer_run();
  assert_int_equal(f->registered, 1);
  assert_string_equal(f->exited, "");
  drop_instance(ia);
}

/* ------------------------------------------------------------------ */
/* Cases: the rule (include/iauth_held.h) and the kept lines           */
/* ------------------------------------------------------------------ */

/** master's iauth_held_t table: a running instance takes every held
 * client; without one a required check refuses unless IAuth had
 * tentatively accepted the client; an optional one releases. */
static void the_rule(void **state)
{
  assert_int_equal(iauth_held_fate(1, 0, 0), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(1, 1, 0), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(1, 1, 1), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(1, 0, 1), IAUTH_HELD_HAND_OVER);
  assert_int_equal(iauth_held_fate(0, 1, 0), IAUTH_HELD_REFUSE);
  assert_int_equal(iauth_held_fate(0, 1, 1), IAUTH_HELD_RELEASE);
  assert_int_equal(iauth_held_fate(0, 0, 0), IAUTH_HELD_RELEASE);
  assert_int_equal(iauth_held_fate(0, 0, 1), IAUTH_HELD_RELEASE);
  /* the announced policy decides required ... */
  assert_int_equal(iauth_held_required(1, 1, 0), 1);
  assert_int_equal(iauth_held_required(1, 0, 1), 0);
  assert_int_equal(iauth_held_required(1, 1, 1), 1);
  assert_int_equal(iauth_held_required(1, 0, 0), 0);
  /* ... and none keeps what the client carried */
  assert_int_equal(iauth_held_required(0, 0, 1), 1);
  assert_int_equal(iauth_held_required(0, 0, 0), 0);
  /* R counts unless the circuit breaker bypasses it */
  assert_int_equal(iauth_held_policy_r(1, 0), 1);
  assert_int_equal(iauth_held_policy_r(1, 1), 0);
  assert_int_equal(iauth_held_policy_r(0, 0), 0);
  assert_int_equal(iauth_held_policy_r(0, 1), 0);
}

/** One line is kept per command letter, the latest, last; a SASL
 * exchange, T, D and E are never kept. */
static void kept_lines_are_bounded(void **state)
{
  struct AuthRequest auth;
  struct IAuthSaid *said;
  const char *want[] = { "C 192.0.2.1 1 192.0.2.2 2", "U u 0 * :r", "n c",
                         "P :pw9" };
  int i, n;

  memset(&auth, 0, sizeof(auth));
  iauth_said_record(&auth, "C 192.0.2.1 1 192.0.2.2 2");
  iauth_said_record(&auth, "n a");
  iauth_said_record(&auth, "U u 0 * :r");
  for (i = 0; i < 10; i++) {
    char pw[16];
    ircd_snprintf(0, pw, sizeof(pw), "P :pw%d", i);
    iauth_said_record(&auth, pw);
  }
  iauth_said_record(&auth, "n b");
  iauth_said_record(&auth, "A S :PLAIN");
  iauth_said_record(&auth, "a :AAAA");
  iauth_said_record(&auth, "T");
  iauth_said_record(&auth, "D");
  iauth_said_record(&auth, "E Done :x");
  iauth_said_record(&auth, "n c");
  iauth_said_record(&auth, "P :pw9");
  for (n = 0, said = auth.iauth_said; said; said = said->next, n++) {
    assert_true(n < 4);
    assert_string_equal(said->text, want[n]);
  }
  assert_int_equal(n, 4);
  iauth_said_free(&auth);
  assert_null(auth.iauth_said);
}

/** The wipe of a line that may carry a password zeroes every byte. */
static void a_line_is_wiped(void **state)
{
  char buf[32];
  size_t i;

  strcpy(buf, "W secret u h 192.0.2.1");
  iauth_line_wipe(buf, sizeof(buf));
  for (i = 0; i < sizeof(buf); i++)
    assert_int_equal(buf[i], 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(disconnect_signals_the_program, setup),
    cmocka_unit_test_setup(no_process_no_signal, setup),
    cmocka_unit_test_setup(a_reaped_program_is_forgotten, setup),
    cmocka_unit_test_setup(required_and_no_instance_refuses, setup),
    cmocka_unit_test_setup(optional_and_no_instance_releases, setup),
    cmocka_unit_test_setup(tentatively_accepted_is_released, setup),
    cmocka_unit_test_setup(handed_to_the_new_instance, setup),
    cmocka_unit_test_setup(a_line_while_held_is_kept, setup),
    cmocka_unit_test_setup(a_held_client_that_quits, setup),
    cmocka_unit_test_setup(the_new_instance_fails_while_told, setup),
    cmocka_unit_test_setup(t_write_failure_finishes_the_client, setup),
    cmocka_unit_test_setup(a_held_client_times_out, setup),
    cmocka_unit_test_setup(handed_client_times_out_by_the_old_policy, setup),
    cmocka_unit_test_setup(an_open_circuit_breaker_releases, setup),
    cmocka_unit_test(the_rule),
    cmocka_unit_test(kept_lines_are_bounded),
    cmocka_unit_test(a_line_is_wiped),
  };

  event_init(64);
  return cmocka_run_group_tests(tests, NULL, NULL);
}
