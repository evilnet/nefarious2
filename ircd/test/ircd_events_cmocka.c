/*
 * ircd_events_cmocka.c - an engine error never runs a socket's callback
 * inside the call that caused it
 *
 * The event model is synchronous: event_generate() runs the callback on
 * the spot.  When an engine operation made on a caller's behalf failed --
 * the EPOLL_CTL_MOD behind socket_events(), the registration behind
 * socket_add() -- the engine used to raise ET_ERROR right there, so the
 * socket's callback ran inside the caller.  For a client that meant
 * exit_client() in the middle of send_buffer(), or of a walk over a
 * channel's members, and the caller then used the freed client.
 *
 * Now a failed interest or state change flags the socket in error and
 * leaves the ET_ERROR to socket_run_errors(), which every engine loop
 * calls once per pass, where no callback is on the stack.  A refused
 * registration is reported by socket_add()'s return value alone, and
 * leaves the socket as it was: unlinked and inactive.  socket_del() of a
 * socket that is not active (refused, or never added) asserts, and in a
 * release build does nothing.
 *
 * This links the real event core and the real epoll engine.  A failure is
 * produced the way it happens in production: the file behind a registered
 * descriptor is replaced (dup2), so EPOLL_CTL_MOD on it fails with ENOENT.
 * The event core's assert() comes here (events_assert.h), so a case can
 * see one fire, or run past it as a release build does.
 */
#include "config.h"

#include <errno.h>
#include <fcntl.h>
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

/* The configured fallback engine; epoll is chosen ahead of it. */
static int no_engine_init(int max_sockets)
{
  (void)max_sockets;
  return 0;
}
struct Engine engine_poll = { "unused", no_engine_init, 0, 0, 0, 0, 0, 0 };

/* The event core's assert() (events_assert.h).  A failed one fails the
 * case, through mock_assert() so expect_assert_failure() can catch it --
 * unless the case runs the core as a release build does (assert() compiled
 * out): then it is only counted, and the code goes on past it. */
static int release_build;       /* go on past a failed assert */
static int assert_hits;         /* failed asserts in the event core */

void events_assert(int ok, const char *expression, const char *file, int line)
{
  if (ok)
    return;
  assert_hits++;
  if (!release_build)
    mock_assert(0, expression, file, line);
}

/* ------------------------------------------------------------------ */
/* Sockets under test                                                  */
/* ------------------------------------------------------------------ */

struct probe {
  struct Socket sock;
  int peer;                     /* other end of the socketpair */
  int in_call;                  /* the test is inside an event-core call */
  int calls, inline_calls;      /* events other than ET_DESTROY */
  int destroyed;
  enum EventType last;
  int last_data;
  struct probe *other;          /* for the cascade case */
  int free_on_destroy;
};

static void probe_cb(struct Event *ev)
{
  struct probe *p = (struct probe *) s_data(ev_socket(ev));

  if (ev_type(ev) == ET_DESTROY) {
    p->destroyed++;
    if (p->free_on_destroy)
      free(p);
    return;
  }
  p->calls++;
  if (p->in_call)
    p->inline_calls++;
  p->last = ev_type(ev);
  p->last_data = ev_data(ev);

  /* An error callback that touches another socket, as exit_client()
   * sends to everyone it shares a channel with. */
  if (ev_type(ev) == ET_ERROR && p->other) {
    struct probe *o = p->other;

    p->other = NULL;
    socket_events(&o->sock, SOCK_ACTION_ADD | SOCK_EVENT_WRITABLE);
  }
}

/** A connected socket registered for reading. */
static void probe_open(struct probe *p)
{
  int sv[2];

  memset(p, 0, sizeof(*p));
  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  p->peer = sv[1];
  assert_true(socket_add(&p->sock, probe_cb, p, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
}

/** Replace the file behind the descriptor: its registration goes with the
 * old file, so the next EPOLL_CTL_MOD on the number fails with ENOENT. */
static void probe_lose_registration(struct probe *p)
{
  int fresh = socket(AF_UNIX, SOCK_STREAM, 0);

  assert_true(fresh >= 0);
  assert_int_equal(dup2(fresh, s_fd(&p->sock)), s_fd(&p->sock));
  close(fresh);
}

/** The next send: arm writable interest, as update_write() does. */
static void probe_arm_write(struct probe *p)
{
  p->in_call = 1;
  socket_events(&p->sock, SOCK_ACTION_ADD | SOCK_EVENT_WRITABLE);
  p->in_call = 0;
}

static void probe_close(struct probe *p)
{
  int fd = s_fd(&p->sock);

  if (!(p->sock.s_header.gh_flags & GEN_DESTROY))
    socket_del(&p->sock);
  close(fd);
  close(p->peer);
}

static int group_setup(void **state)
{
  (void)state;
  CurrentTime = time(NULL);
  event_init(64);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* The crash shape: a send arms writable interest on a socket whose
 * registration is gone.  Nothing runs inside the call; the loop's pass
 * delivers one ET_ERROR carrying the engine's errno. */
static void failed_interest_change_runs_nothing_inside_the_caller(void **state)
{
  struct probe p;

  (void)state;
  probe_open(&p);
  probe_lose_registration(&p);

  probe_arm_write(&p);
  assert_int_equal(p.inline_calls, 0);
  assert_int_equal(p.calls, 0);
  assert_true(p.sock.s_header.gh_flags & GEN_ERROR);  /* flagged at once */

  probe_arm_write(&p);          /* in error: no second engine call */
  socket_run_errors();
  assert_int_equal(p.calls, 1);
  assert_int_equal(p.last, ET_ERROR);
  assert_int_equal(p.last_data, ENOENT);

  socket_run_errors();          /* delivered once */
  assert_int_equal(p.calls, 1);
  probe_close(&p);
}

/* The engine loop itself delivers the deferred error on its next pass. */
static void stop_loop(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE)
    running = 0;
}

static void engine_loop_delivers_deferred_errors(void **state)
{
  struct probe p;
  struct Timer stop;

  (void)state;
  probe_open(&p);
  probe_lose_registration(&p);
  probe_arm_write(&p);
  assert_int_equal(p.calls, 0);

  CurrentTime = time(NULL);
  timer_add(timer_init(&stop), stop_loop, NULL, TT_RELATIVE, 0);
  running = 1;
  event_loop();                 /* one pass: timers, then deferred errors */
  running = 1;

  assert_int_equal(p.calls, 1);
  assert_int_equal(p.last, ET_ERROR);
  probe_close(&p);
}

/* A socket deleted before the loop gets to it hears nothing more -- and
 * its memory, freed on ET_DESTROY, is never touched again. */
static void deleted_socket_gets_no_deferred_error(void **state)
{
  struct probe *p = malloc(sizeof(*p));
  int fd, peer;

  (void)state;
  assert_non_null(p);
  probe_open(p);
  p->free_on_destroy = 1;
  probe_lose_registration(p);
  probe_arm_write(p);
  assert_int_equal(p->calls, 0);

  fd = s_fd(&p->sock);
  peer = p->peer;
  socket_del(&p->sock);         /* ET_DESTROY frees p */
  socket_run_errors();          /* must not reach the freed socket */
  close(fd);
  close(peer);
}

/* A registration the engine refuses is reported by socket_add()'s return
 * value alone: no callback, nothing left linked, nothing deferred -- and
 * the socket is not active, as it was before the call. */
static void refused_registration_reports_by_return_value_only(void **state)
{
  struct probe p;
  int fd, added;

  (void)state;
  memset(&p, 0, sizeof(p));
  fd = open("/dev/null", O_RDONLY);   /* epoll refuses it: EPERM */
  assert_true(fd >= 0);

  p.in_call = 1;
  added = socket_add(&p.sock, probe_cb, &p, SS_CONNECTED,
                     SOCK_EVENT_READABLE, fd);
  p.in_call = 0;

  assert_int_equal(added, 0);
  assert_int_equal(p.calls, 0);
  assert_null(p.sock.s_header.gh_prev_p);   /* not left in the list */
  assert_false(s_active(&p.sock));          /* nor read as registered */
  socket_run_errors();
  assert_int_equal(p.calls, 0);
  close(fd);
}

/* The bouncer's revive moves a connection's descriptor onto another
 * Socket: socket_del_keepfd() drops the first registration while the fd
 * is still open, so registering the same number for the second socket is
 * not refused (EEXIST).  The first socket is destroyed once; the fd stays
 * open. */
static void transplant_moves_a_descriptor_to_another_socket(void **state)
{
  struct probe a, b;
  int fd;

  (void)state;
  probe_open(&a);
  fd = s_fd(&a.sock);

  socket_del_keepfd(&a.sock);
  assert_int_equal(a.destroyed, 1);
  assert_int_equal(s_fd(&a.sock), -1);
  assert_true(fcntl(fd, F_GETFD) >= 0);     /* not closed */

  memset(&b, 0, sizeof(b));
  b.peer = a.peer;
  assert_true(socket_add(&b.sock, probe_cb, &b, SS_CONNECTED,
                         SOCK_EVENT_READABLE, fd));
  assert_true(s_active(&b.sock));
  assert_int_equal(b.calls + b.destroyed, 0);
  assert_int_equal(a.destroyed, 1);
  probe_close(&b);
}

/* The same move, refused: the engine will not take the descriptor (here
 * the file behind the number is one epoll refuses, EPERM; in production
 * ENOMEM or ENOSPC).  The target socket is left as it was -- inactive,
 * unlinked, no callback -- so the caller can hand the descriptor back,
 * and a later attempt registers the socket afresh instead of taking it
 * for a registered one (bounce_transplant_register() picks socket_add() or
 * socket_reattach() by GEN_ACTIVE). */
static void refused_transplant_leaves_the_target_inactive(void **state)
{
  struct probe a, b;
  int fd, devnull, added, err, sv[2];

  (void)state;
  probe_open(&a);
  fd = s_fd(&a.sock);
  socket_del_keepfd(&a.sock);
  assert_int_equal(a.destroyed, 1);

  devnull = open("/dev/null", O_RDONLY);
  assert_true(devnull >= 0);
  assert_int_equal(dup2(devnull, fd), fd);
  close(devnull);

  memset(&b, 0, sizeof(b));
  b.in_call = 1;
  errno = 0;
  added = socket_add(&b.sock, probe_cb, &b, SS_CONNECTED,
                     SOCK_EVENT_READABLE, fd);
  err = errno;
  b.in_call = 0;

  assert_int_equal(added, 0);
  assert_int_equal(err, EPERM);             /* the caller can log why */
  assert_false(s_active(&b.sock));
  assert_null(b.sock.s_header.gh_prev_p);
  assert_int_equal(b.calls + b.destroyed, 0);
  assert_int_equal(a.destroyed, 1);         /* the source's, once */
  socket_run_errors();
  assert_int_equal(b.calls, 0);
  close(fd);
  close(a.peer);

  /* The next attempt registers it afresh. */
  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  b.peer = sv[1];
  assert_true(socket_add(&b.sock, probe_cb, &b, SS_CONNECTED,
                         SOCK_EVENT_READABLE, sv[0]));
  assert_true(s_active(&b.sock));
  assert_non_null(b.sock.s_header.gh_prev_p);
  probe_close(&b);
}

/* What a socket_del() of an inactive socket must leave: the socket's flags
 * as they were, no callback run, and the descriptor number's owner still
 * registered -- an interest change on it reaches the engine and succeeds
 * (after an EPOLL_CTL_DEL of the number it fails with ENOENT). */
static void assert_nothing_deleted(struct probe *p, unsigned int flags,
                                   struct probe *owner)
{
  assert_int_equal(p->sock.s_header.gh_flags, flags);
  assert_int_equal(p->calls + p->destroyed, 0);
  probe_arm_write(owner);
  assert_false(owner->sock.s_header.gh_flags & GEN_ERROR);
  socket_events(&owner->sock, SOCK_ACTION_DEL | SOCK_EVENT_WRITABLE);
}

/* socket_del() of a socket that is not active, as a release build runs it
 * (it returns) and as a debug build does (the assert stops it before
 * anything is done).  Either way nothing is deleted. */
static void del_inactive(struct probe *p, struct probe *owner)
{
  unsigned int flags = p->sock.s_header.gh_flags;

  assert_hits = 0;
  release_build = 1;
  socket_del(&p->sock);                                 /* release build */
  release_build = 0;
  assert_nothing_deleted(p, flags, owner);
  assert_int_equal(assert_hits, 1);

  expect_assert_failure(socket_del(&p->sock));          /* debug build */
  assert_int_equal(assert_hits, 2);
  assert_nothing_deleted(p, flags, owner);
}

/* The probes of the two cases below.  File-static, so a case that fails
 * part-way leaves nothing on the event core's list pointing into a dead
 * stack frame. */
static struct probe inactive, owner;

/* A socket the engine refused is not registered, so there is nothing to
 * delete: no ET_DESTROY is owed, and its s_fd names a descriptor the
 * caller has closed, which someone else may hold by now.  socket_del()
 * must neither unregister that owner (EPOLL_CTL_DEL of the number) nor run
 * the socket's callback. */
static void deleting_a_refused_socket_does_nothing(void **state)
{
  int fd;

  (void)state;
  memset(&inactive, 0, sizeof(inactive));
  fd = open("/dev/null", O_RDONLY);   /* epoll refuses it: EPERM */
  assert_true(fd >= 0);
  assert_false(socket_add(&inactive.sock, probe_cb, &inactive, SS_CONNECTED,
                          SOCK_EVENT_READABLE, fd));
  close(fd);                          /* as the caller does */

  probe_open(&owner);                 /* the number's next owner */
  assert_int_equal(s_fd(&owner.sock), fd);
  assert_int_equal(s_fd(&inactive.sock), fd);

  del_inactive(&inactive, &owner);
  probe_close(&owner);
}

/* A socket never added: a zeroed struct, as a freshly allocated IAuth's
 * or the resolver's before it opens one.  It has no callback, and its s_fd
 * (0, or a number left from before) belongs to someone else.  socket_del()
 * must not unregister that owner, nor run a destroy through a NULL
 * callback. */
static void deleting_a_socket_never_added_does_nothing(void **state)
{
  (void)state;
  probe_open(&owner);
  memset(&inactive, 0, sizeof(inactive));
  s_fd(&inactive.sock) = s_fd(&owner.sock);

  del_inactive(&inactive, &owner);
  probe_close(&owner);
}

/* Moving a socket to a new descriptor drops the old descriptor's pending
 * error, and interest changes reach the engine again. */
static void reattach_starts_clean(void **state)
{
  struct probe p;
  int sv[2], oldfd;

  (void)state;
  probe_open(&p);
  probe_lose_registration(&p);
  probe_arm_write(&p);
  assert_int_equal(p.calls, 0);

  oldfd = s_fd(&p.sock);
  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  assert_true(socket_reattach(&p.sock, sv[0]));
  close(oldfd);
  close(p.peer);
  p.peer = sv[1];

  socket_run_errors();
  assert_int_equal(p.calls, 0);
  assert_false(p.sock.s_header.gh_flags & GEN_ERROR);

  probe_arm_write(&p);          /* reaches the engine: the fd is writable */
  assert_int_equal(p.sock.s_events, SOCK_EVENT_READABLE | SOCK_EVENT_WRITABLE);
  socket_run_errors();
  assert_int_equal(p.calls, 0);
  probe_close(&p);
}

/* An error callback whose work makes another socket's interest change
 * fail: that error is deferred too, and delivered in the same run. */
static void errors_raised_while_delivering_are_delivered_too(void **state)
{
  struct probe a, b;

  (void)state;
  probe_open(&a);
  probe_open(&b);
  probe_lose_registration(&a);
  probe_lose_registration(&b);
  a.other = &b;

  probe_arm_write(&a);
  assert_int_equal(a.calls + b.calls, 0);

  socket_run_errors();
  assert_int_equal(a.calls, 1);
  assert_int_equal(b.calls, 1);
  assert_int_equal(b.inline_calls, 0);
  probe_close(&a);
  probe_close(&b);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(failed_interest_change_runs_nothing_inside_the_caller),
    cmocka_unit_test(engine_loop_delivers_deferred_errors),
    cmocka_unit_test(deleted_socket_gets_no_deferred_error),
    cmocka_unit_test(refused_registration_reports_by_return_value_only),
    cmocka_unit_test(transplant_moves_a_descriptor_to_another_socket),
    cmocka_unit_test(refused_transplant_leaves_the_target_inactive),
    cmocka_unit_test(deleting_a_refused_socket_does_nothing),
    cmocka_unit_test(deleting_a_socket_never_added_does_nothing),
    cmocka_unit_test(reattach_starts_clean),
    cmocka_unit_test(errors_raised_while_delivering_are_delivered_too),
  };

  return cmocka_run_group_tests(tests, group_setup, NULL);
}
