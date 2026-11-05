/*
 * bouncer_transplant_cmocka.c - the revive's one fallible step leaves the
 * ghost's socket as it was when the engine refuses it
 *
 * bounce_revive() takes a new login's descriptor off the engine
 * (socket_del_keepfd) and registers it for the held ghost's socket
 * (bounce_transplant_register: socket_add() for a socket that is not
 * active, socket_reattach() for one that is).  Only that registration can
 * fail.  When it does, the ghost's socket must be left as it was, or the
 * next revive of the same ghost picks the wrong call (#138's F6-b): the
 * event core's refused socket_add() leaves GEN_ACTIVE set, so the ghost
 * would read as registered and go down socket_reattach().
 *
 * This links the real event core with a fake engine that keeps a table of
 * registered descriptors (a second registration of one is refused with
 * EEXIST, as epoll does) and refuses the next registration on demand with
 * ENOMEM.  The engine is defined under every name ircd_events.c may look
 * for, so the suite does not depend on the configured engine.
 */
#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#include "bouncer_transplant.h"
#include "ircd_events.h"
#include "ircd_features.h"

/* ------------------------------------------------------------------ */
/* The ircd around the event core                                      */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int running = 1;

int feature_int(enum Feature feat)
{
  (void)feat;
  return 20;                    /* FEAT_POLLS_PER_LOOP */
}

void server_restart(const char *message)
{
  fail_msg("server_restart: %s", message);
}

void thread_pool_poll(void)
{
}

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
}

void *DoRealloc(void *p, size_t len, const char *file, int line)
{
  (void)file; (void)line;
  p = realloc(p, len);
  assert_non_null(p);
  return p;
}

struct Client;
int ircd_snprintf(struct Client *dest, char *buf, size_t buf_len,
                  const char *format, ...)
{
  va_list args;
  int n;

  (void)dest;
  va_start(args, format);
  n = vsnprintf(buf, buf_len, format, args);
  va_end(args);
  return n;
}

/* ------------------------------------------------------------------ */
/* The fake engine                                                     */
/* ------------------------------------------------------------------ */

#define MAXFD 1024

static struct Socket *registered[MAXFD]; /* fd -> the socket registered */
static int refuse_next;                  /* refuse the next registration */
static int fail_events;                  /* fail interest changes (ENOENT) */

static int fake_init(int max_sockets)
{
  (void)max_sockets;
  return 1;
}

static int fake_add(struct Socket *sock)
{
  int fd = s_fd(sock);

  assert_true(fd >= 0 && fd < MAXFD);
  if (refuse_next) {
    refuse_next = 0;
    errno = ENOMEM;
    return 0;
  }
  if (registered[fd]) {
    errno = EEXIST;
    return 0;
  }
  registered[fd] = sock;
  return 1;
}

static void fake_state(struct Socket *sock, enum SocketState state)
{
  (void)sock; (void)state;
}

static void fake_events(struct Socket *sock, unsigned int events)
{
  (void)events;
  if (fail_events)
    socket_error(sock, ENOENT);
}

static void fake_closing(struct Socket *sock)
{
  int fd = s_fd(sock);

  if (fd >= 0 && fd < MAXFD && registered[fd] == sock)
    registered[fd] = 0;
}

static void fake_loop(struct Generators *gens)
{
  (void)gens;
  fail_msg("the suite runs no event loop");
}

#define FAKE_ENGINE { "fake", fake_init, 0, fake_add, fake_state, \
                      fake_events, fake_closing, fake_loop }
#ifdef USE_KQUEUE
struct Engine engine_kqueue = FAKE_ENGINE;
#endif
#ifdef USE_DEVPOLL
struct Engine engine_devpoll = FAKE_ENGINE;
#endif
#ifdef USE_EPOLL
struct Engine engine_epoll = FAKE_ENGINE;
#endif
#ifdef USE_POLL
struct Engine engine_poll = FAKE_ENGINE;
#else
struct Engine engine_select = FAKE_ENGINE;
#endif

/* ------------------------------------------------------------------ */
/* Sockets under test                                                  */
/* ------------------------------------------------------------------ */

struct probe {
  struct Socket sock;
  int destroyed;
  int errors;
};

static void probe_cb(struct Event *ev)
{
  struct probe *p = (struct probe *) s_data(ev_socket(ev));

  if (!p)
    return;
  if (ev_type(ev) == ET_DESTROY)
    p->destroyed++;
  else if (ev_type(ev) == ET_ERROR)
    p->errors++;
}

/** The reviving login: a registered socket holding one end of a pair. */
static int login_open(struct probe *login, int *peer)
{
  int sv[2];

  memset(login, 0, sizeof(*login));
  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  *peer = sv[1];
  assert_true(socket_add(&login->sock, probe_cb, login, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  return sv[0];
}

/** The revive's take: the login's registration goes, the fd stays open. */
static int login_take(struct probe *login)
{
  int fd = s_fd(&login->sock);

  socket_del_keepfd(&login->sock);
  assert_int_equal(login->destroyed, 1);
  return fd;
}

/** A ghost restored from the DB: a zeroed Connection, never registered. */
static void ghost_restored(struct probe *g)
{
  memset(g, 0, sizeof(*g));
  s_fd(&g->sock) = -1;
}

/** A ghost held through close_connection(): registered once, then
 * unregistered with socket_del_keepfd() (its ET_DESTROY ran). */
static void ghost_held(struct probe *g)
{
  int sv[2];

  memset(g, 0, sizeof(*g));
  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  assert_true(socket_add(&g->sock, probe_cb, g, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  socket_del_keepfd(&g->sock);
  close(sv[0]);
  close(sv[1]);
  assert_int_equal(g->destroyed, 1);
  assert_false(s_active(&g->sock));
  assert_int_equal(s_fd(&g->sock), -1);
}

/** A ghost whose header is still active with no descriptor (a relay-only
 * ACTIVE session's primary): registered, then its fd went without a
 * socket_del. */
static void ghost_active_fdless(struct probe *g)
{
  int sv[2];

  memset(g, 0, sizeof(*g));
  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  assert_true(socket_add(&g->sock, probe_cb, g, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  registered[sv[0]] = 0;        /* closing the fd ends its registration */
  close(sv[0]);
  close(sv[1]);
  s_fd(&g->sock) = -1;
  assert_true(s_active(&g->sock));
}

static void sock_release(struct probe *p, int peer)
{
  int fd = s_fd(&p->sock);

  if (s_active(&p->sock) && !(p->sock.s_header.gh_flags & GEN_DESTROY))
    socket_del(&p->sock);
  if (fd >= 0)
    close(fd);
  if (peer >= 0)
    close(peer);
}

static int group_setup(void **state)
{
  (void)state;
  CurrentTime = time(NULL);
  event_init(64);
  return 0;
}

/* The login and the ghost of a case.  File-static, so a case that fails
 * part-way leaves nothing on the event core's list pointing into a dead
 * stack frame: the teardown unlinks what is still listed. */
static struct probe login, g;

static int test_setup(void **state)
{
  (void)state;
  refuse_next = 0;
  fail_events = 0;
  return 0;
}

static int test_teardown(void **state)
{
  int fd;

  (void)state;
  for (fd = 0; fd < MAXFD; fd++)
    if (registered[fd] == &login.sock || registered[fd] == &g.sock)
      registered[fd] = 0;
  if (login.sock.s_header.gh_prev_p)
    gen_dequeue(&login.sock);
  if (g.sock.s_header.gh_prev_p)
    gen_dequeue(&g.sock);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* The take must come first: while the login still holds the descriptor's
 * registration, the ghost's is refused (EEXIST); after socket_del_keepfd()
 * it goes through, and the ghost's socket is registered and listed. */
static void registers_a_descriptor_the_login_gave_up(void **state)
{
  int peer, fd, fresh = -1;

  (void)state;
  fd = login_open(&login, &peer);
  ghost_held(&g);

  assert_false(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(errno, EEXIST);
  fd = login_take(&login);

  assert_true(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(fresh, 1);
  assert_true(s_active(&g.sock));
  assert_non_null(g.sock.s_header.gh_prev_p);
  assert_int_equal(s_fd(&g.sock), fd);
  assert_ptr_equal(registered[fd], &g.sock);
  sock_release(&g, peer);
}

/* A ghost restored from the DB, refused: left as it was (no flags, no
 * fd, on no list), and the next revive registers it afresh. */
static void refused_add_leaves_a_restored_ghost_as_it_was(void **state)
{
  unsigned int flags;
  int peer, fd, fresh = -1;

  (void)state;
  fd = login_open(&login, &peer);
  ghost_restored(&g);
  flags = g.sock.s_header.gh_flags;
  fd = login_take(&login);

  refuse_next = 1;
  assert_false(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(errno, ENOMEM);
  assert_int_equal(fresh, 1);
  assert_int_equal(g.sock.s_header.gh_flags, flags);
  assert_false(s_active(&g.sock));
  assert_null(g.sock.s_header.gh_prev_p);
  assert_int_equal(s_fd(&g.sock), -1);
  assert_null(registered[fd]);

  /* The next revive: socket_add(), and it is registered. */
  assert_true(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(fresh, 1);
  assert_true(s_active(&g.sock));
  assert_non_null(g.sock.s_header.gh_prev_p);
  sock_release(&g, peer);
}

/* A ghost held through close_connection(), refused: its flags are the
 * ones its destroy left, its fd is -1, and the next revive registers it
 * afresh -- not socket_reattach() on a socket on no list. */
static void refused_add_leaves_a_held_ghost_as_it_was(void **state)
{
  unsigned int flags;
  int peer, fd, fresh = -1;

  (void)state;
  fd = login_open(&login, &peer);
  ghost_held(&g);
  flags = g.sock.s_header.gh_flags;
  fd = login_take(&login);

  refuse_next = 1;
  assert_false(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(fresh, 1);
  assert_int_equal(g.sock.s_header.gh_flags, flags);
  assert_false(s_active(&g.sock));
  assert_null(g.sock.s_header.gh_prev_p);
  assert_int_equal(s_fd(&g.sock), -1);

  assert_true(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(fresh, 1);
  assert_true(s_active(&g.sock));
  assert_non_null(g.sock.s_header.gh_prev_p);
  assert_int_equal(g.destroyed, 1);     /* the hold's, once */
  sock_release(&g, peer);
}

/* An active ghost socket with no fd, refused: still active and listed,
 * fd -1, and the next revive reattaches it.  An engine error that was
 * waiting for the loop is still waiting, and counted: socket_reattach()
 * drops it with its count (it belongs to the old descriptor), so the
 * refusal puts it back, and the loop delivers it once, as it would have. */
static void refused_reattach_leaves_an_active_ghost_as_it_was(void **state)
{
  unsigned int flags;
  int peer, fd, err, fresh = -1;

  (void)state;
  fd = login_open(&login, &peer);
  ghost_active_fdless(&g);
  fail_events = 1;              /* an error awaits the loop */
  socket_events(&g.sock, SOCK_ACTION_ADD | SOCK_EVENT_WRITABLE);
  fail_events = 0;
  assert_true(g.sock.s_header.gh_flags & GEN_ERR_PENDING);
  flags = g.sock.s_header.gh_flags;
  err = g.sock.s_error;
  fd = login_take(&login);

  refuse_next = 1;
  assert_false(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(errno, ENOMEM);
  assert_int_equal(fresh, 0);
  assert_int_equal(g.sock.s_header.gh_flags, flags);
  assert_int_equal(g.sock.s_error, err);
  assert_true(s_active(&g.sock));
  assert_non_null(g.sock.s_header.gh_prev_p);
  assert_int_equal(s_fd(&g.sock), -1);
  socket_run_errors();
  assert_int_equal(g.errors, 1);        /* delivered, once */
  socket_run_errors();
  assert_int_equal(g.errors, 1);

  /* The next revive: socket_reattach(), and it is registered. */
  assert_true(bounce_transplant_register(&g.sock, probe_cb, &g, fd, &fresh));
  assert_int_equal(fresh, 0);
  assert_int_equal(s_fd(&g.sock), fd);
  assert_ptr_equal(registered[fd], &g.sock);
  assert_false(g.sock.s_header.gh_flags & GEN_ERROR);
  sock_release(&g, peer);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(registers_a_descriptor_the_login_gave_up, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(refused_add_leaves_a_restored_ghost_as_it_was, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(refused_add_leaves_a_held_ghost_as_it_was, test_setup, test_teardown),
    cmocka_unit_test_setup_teardown(refused_reattach_leaves_an_active_ghost_as_it_was, test_setup, test_teardown),
  };

  return cmocka_run_group_tests(tests, group_setup, NULL);
}
