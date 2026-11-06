/*
 * close_connection_cmocka.c - a closed user socket tells iauth the client
 * is gone, while the descriptor is still the client's
 *
 * iauth knows a client by its descriptor number: ircd introduces a
 * connection on a user port as "<fd> C ..." and owes "<fd> D" when it
 * goes.  iauthd-ts and iauthd.pl both exit on a C for a number they still
 * hold, and the number is free for the next accept() once close() returns.
 *
 * The D used to go from exit_client() alone.  Two closes do not run
 * through it: the bouncer hold (the primary's socket closes, the client
 * stays as a held ghost) and BX X's close of a device of ours.  Neither
 * told iauth, and a held ghost's own exit later sent "-1 D".  So the D
 * goes from close_connection(), which every close of a user socket runs
 * through, before the descriptor is touched: socket_del_keepfd() sets
 * cli_fd to -1, and the number is gone after the close().  A revive does
 * not close the socket (bounce_revive() moves the descriptor onto the
 * held ghost, whose close later owes the D), so it sends nothing.
 *
 * This includes the real s_bsd.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps close_connection() and
 * what it calls and nothing else of s_bsd.c: only those need the ircd
 * around them here.  The connections are socketpairs.
 */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cmocka.h>

#include "../s_bsd.c"

/* ------------------------------------------------------------------ */
/* The ircd around close_connection()                                  */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;
static struct ServerStatistics server_stats;
struct ServerStatistics *ServerStats = &server_stats;

/** One auth_send_exit() call, as close_connection() made it. */
static struct {
  int calls;              /**< auth_send_exit() calls */
  struct Client *cptr;    /**< the client of the last call */
  int fd;                 /**< cli_fd() at the last call */
  int fd_open;            /**< the descriptor was still open then */
} exit_seen;

/* s_auth.c: sends "<cli_fd> D" to iauth.  Records what that line would
 * name, and whether the descriptor it names was still open. */
void auth_send_exit(struct Client *cptr)
{
  exit_seen.calls++;
  exit_seen.cptr = cptr;
  exit_seen.fd = cli_fd(cptr);
  exit_seen.fd_open = exit_seen.fd >= 0 && fcntl(exit_seen.fd, F_GETFD) != -1;
}

/* ircd_events.c: takes the socket off the engine and leaves it no
 * descriptor (s_fd, which is cli_fd, becomes -1); the caller closes it. */
void socket_del_keepfd(struct Socket *sock)
{
  sock->s_fd = -1;
  sock->s_header.gh_flags |= GEN_DESTROY;
}

void flush_connections(struct Client *cptr)
{
  (void)cptr;
}

void websocket_close_flush(struct Client *cptr)
{
  (void)cptr;
}

#ifdef USE_SSL
void ssl_free(struct Socket *socketh)
{
  (void)socketh;
}
#endif

struct ConfItem *find_conf_exact(const char *name, struct Client *cptr,
                                 int statmask)
{
  (void)name; (void)cptr; (void)statmask;
  return NULL;
}

int feature_int(enum Feature feat)
{
  (void)feat;
  return 0;
}

void msgq_delete(struct MsgQ *mq, unsigned int length)
{
  (void)mq; (void)length;
}

void dbuf_delete(struct DBuf *dyn, unsigned int length)
{
  (void)dyn; (void)length;
}

void client_drop_sendq(struct Connection *con)
{
  (void)con;
}

void set_snomask(struct Client *cptr, unsigned int newmask, int what)
{
  (void)cptr; (void)newmask; (void)what;
}

void det_confs_butmask(struct Client *cptr, int mask)
{
  (void)cptr; (void)mask;
}

void release_listener(struct Listener *listener)
{
  (void)listener;
}

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

/* ------------------------------------------------------------------ */
/* A connection on a socketpair                                        */
/* ------------------------------------------------------------------ */

static struct Client client;
static struct Connection connection;
static int peer = -1;           /* the far end of the socketpair */

/** Make the test's one connection, in @a status, on a fresh socketpair
 * (@a with_fd) or with no descriptor (cli_fd -1: a held ghost, whose
 * socket the hold closed).  @return its descriptor, or -1. */
static int connect_client(unsigned int status, int with_fd)
{
  int sv[2];
  int fd = -1;

  memset(&client, 0, sizeof(client));
  memset(&connection, 0, sizeof(connection));
  memset(&exit_seen, 0, sizeof(exit_seen));
  exit_seen.fd = -2;
  cli_connect(&client) = &connection;
  con_client(&connection) = &client;
  cli_from(&client) = &client;
  cli_status(&client) = status;
  s_fd(&cli_socket(&client)) = -1;

  if (with_fd) {
    assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    fd = sv[0];
    peer = sv[1];
    assert_true(fd < MAXCONNECTIONS);
    s_fd(&cli_socket(&client)) = fd;
    LocalClientArray[fd] = &client;
    if (fd > HighestFd)
      HighestFd = fd;
  }
  return fd;
}

static int teardown(void **state)
{
  (void)state;
  if (peer >= 0)
    close(peer);
  peer = -1;
  return 0;
}

/** close_connection() closed @a fd: the descriptor is no longer open and
 * the client no longer names it. */
static void assert_closed(int fd)
{
  assert_int_equal(cli_fd(&client), -1);
  assert_null(LocalClientArray[fd]);
  errno = 0;
  assert_int_equal(fcntl(fd, F_GETFD), -1);
  assert_int_equal(errno, EBADF);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/* A registered user's close -- exit_client(), a bouncer hold, BX X's
 * close of a device of ours all come here -- tells iauth once, naming
 * the descriptor while it is still open. */
static void test_registered_user_tells_iauth(void **state)
{
  int fd = connect_client(STAT_USER, 1);

  (void)state;
  close_connection(&client);

  assert_int_equal(exit_seen.calls, 1);
  assert_ptr_equal(exit_seen.cptr, &client);
  assert_int_equal(exit_seen.fd, fd);
  assert_true(exit_seen.fd_open);
  assert_closed(fd);
}

/* A connection on a user port that never registered got its C too
 * (start_auth(), a user port): its close owes the D as well. */
static void test_unregistered_user_port_tells_iauth(void **state)
{
  int fd = connect_client(STAT_UNKNOWN_USER, 1);

  (void)state;
  close_connection(&client);

  assert_int_equal(exit_seen.calls, 1);
  assert_int_equal(exit_seen.fd, fd);
  assert_true(exit_seen.fd_open);
  assert_closed(fd);
}

/* A dead socket (a write error, an EOF) still had its C: the D goes
 * whatever the socket's state. */
static void test_dead_user_socket_tells_iauth(void **state)
{
  int fd = connect_client(STAT_USER, 1);

  (void)state;
  SetFlag(&client, FLAG_DEADSOCKET);
  close_connection(&client);

  assert_int_equal(exit_seen.calls, 1);
  assert_int_equal(exit_seen.fd, fd);
  assert_true(exit_seen.fd_open);
  assert_closed(fd);
}

/* A held ghost has no socket: its hold's close told iauth already.  Its
 * own exit later (the hold expires, a KILL) closes nothing and names no
 * descriptor, so nothing goes -- never "-1 D". */
static void test_held_ghost_sends_nothing(void **state)
{
  (void)state;
  connect_client(STAT_USER, 0);
  close_connection(&client);

  assert_int_equal(exit_seen.calls, 0);
  assert_int_equal(cli_fd(&client), -1);
}

/* A server link was never introduced to iauth (C goes to user ports
 * only): its close sends nothing. */
static void test_server_link_sends_nothing(void **state)
{
  int fd = connect_client(STAT_SERVER, 1);

  (void)state;
  close_connection(&client);

  assert_int_equal(exit_seen.calls, 0);
  assert_closed(fd);
}

/* Nor does a connection on a server port that never registered. */
static void test_unknown_server_sends_nothing(void **state)
{
  int fd = connect_client(STAT_UNKNOWN_SERVER, 1);

  (void)state;
  close_connection(&client);

  assert_int_equal(exit_seen.calls, 0);
  assert_closed(fd);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_teardown(test_registered_user_tells_iauth, teardown),
    cmocka_unit_test_teardown(test_unregistered_user_port_tells_iauth,
                              teardown),
    cmocka_unit_test_teardown(test_dead_user_socket_tells_iauth, teardown),
    cmocka_unit_test_teardown(test_held_ghost_sends_nothing, teardown),
    cmocka_unit_test_teardown(test_server_link_sends_nothing, teardown),
    cmocka_unit_test_teardown(test_unknown_server_sends_nothing, teardown),
  };

  return cmocka_run_group_tests_name("close_connection", tests, NULL, NULL);
}
