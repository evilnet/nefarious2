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
  IAuthSet(ia, IAUTH_CLOSING);    /* its sockets' teardown respawns nothing */
  return ia;
}

/** Make \a ia running: its main socket is a real one, to a program that
 * reads nothing (what it is told is recorded by the fake queue). */
static void run_instance(struct IAuth *ia)
{
  int sv[2];

  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  assert_true(socket_add(i_socket(ia), sock_cb, ia, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  peer_fd = sv[1];
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

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(disconnect_signals_the_program, setup),
    cmocka_unit_test_setup(no_process_no_signal, setup),
    cmocka_unit_test_setup(a_reaped_program_is_forgotten, setup),
  };

  event_init(64);
  return cmocka_run_group_tests(tests, NULL, NULL);
}
