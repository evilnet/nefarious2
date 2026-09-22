/*
 * ircd_kc_adapter_cmocka.c - the libkc event adapter against fd reuse
 *
 * The adapter bridges libkc (curl_multi, the webhook listener) onto the
 * ircd's event engine.  libkc owns its file descriptors: it calls
 * socket_remove(fd) and then close(fd), and the kernel hands the freed
 * number to the next open() or accept() -- a client, an ident query, a
 * server link.  epoll registrations are keyed by that number.  So once
 * socket_remove() has returned, any engine call the adapter still makes
 * with the old number reaches whoever owns it now: a stale EPOLL_CTL_DEL
 * silently de-registers the new owner (the 2026-09-22 bed crashes), a
 * stale EPOLL_CTL_MOD takes its registration over.
 *
 * The event layer below is a fake with the kernel's fd semantics: open()
 * returns the lowest free number, close() drops that number's
 * registration, and ADD/DEL/MOD act on whatever holds the number.
 * Dispatch mirrors engine_loop + event_generate + event_execute: a
 * reference is held across each callback, ET_DESTROY waits for the last
 * one, and a socket's unprocessed events are purged when it is deleted.
 */
#include "config.h"

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>

#include "ircd_events.h"
#include "ircd_kc_adapter.h"
#include "kc/kc_event.h"

time_t CurrentTime;

/* ------------------------------------------------------------------ */
/* Fake kernel + event engine                                          */
/* ------------------------------------------------------------------ */

#define FAKE_FDS    1024
#define FAKE_TIMERS 64
#define FAKE_BATCH  16
#define FAKE_LOG    256

static int            fd_open[FAKE_FDS];   /* number is allocated */
static struct Socket *ep[FAKE_FDS];        /* epoll registration, by number */
static struct GenHeader *g_socket;         /* live socket generators */

static struct Timer  *timers[FAKE_TIMERS]; /* queued timers, in order */
static int            ntimers;

static struct Socket *batch[FAKE_BATCH];   /* one epoll_wait's worth */
static int            nbatch;

static int add_fail_next;   /* make the next engine ADD fail (ENOSPC) */
static int foreign_dels;    /* DEL that removed another socket's registration */
static int enoent_mods;     /* MOD of a number with no registration */
static int hijacked_mods;   /* MOD that landed on another socket's registration */

/* Sockets the adapter handed the engine and that are not yet destroyed,
 * by address (compared, never dereferenced after ET_DESTROY). */
static struct GenHeader *adapter_live[FAKE_LOG];
static int nadapter_live;
static int adapter_adds;    /* sockets the adapter handed the engine */
static int adapter_destroys;/* ... and that were destroyed again */

/* The unrelated owner of a recycled number: a client connection. */
static struct Socket client_sock;
static int client_reads, client_errors;

static void client_cb(struct Event *ev)
{
  if (ev_type(ev) == ET_READ)
    client_reads++;
  else if (ev_type(ev) == ET_ERROR)
    client_errors++;
}

/** Lowest free descriptor, as open()/accept() would return. */
static int fake_open(void)
{
  int fd;

  for (fd = 3; fd < FAKE_FDS; fd++)
    if (!fd_open[fd]) {
      fd_open[fd] = 1;
      return fd;
    }
  fail_msg("fake fd table exhausted");
  return -1;
}

/** close(): the kernel drops the number's epoll registration with it. */
static void fake_close(int fd)
{
  assert_true(fd_open[fd]);
  fd_open[fd] = 0;
  ep[fd] = NULL;
}

void gen_dequeue(void *arg)
{
  struct GenHeader *gen = (struct GenHeader *) arg;

  if (gen->gh_next)
    gen->gh_next->gh_prev_p = gen->gh_prev_p;
  if (gen->gh_prev_p)
    *gen->gh_prev_p = gen->gh_next;
  gen->gh_next = 0;
  gen->gh_prev_p = 0;
}

static void ref_dec(struct GenHeader *gen);

/** event_generate + event_execute, synchronous as in the ircd. */
static void deliver(struct GenHeader *gen, enum EventType type, int data)
{
  struct Event ev;

  if (type != ET_DESTROY && (gen->gh_flags & GEN_DESTROY))
    return;

  memset(&ev, 0, sizeof(ev));
  ev.ev_type = type;
  ev.ev_data = data;
  ev.ev_gen.gen_header = gen;

  gen->gh_ref++;
  if (type == ET_DESTROY) {
    int ii;

    gen->gh_flags &= ~GEN_ACTIVE;
    for (ii = 0; ii < nadapter_live; ii++)
      if (adapter_live[ii] == gen) {
        adapter_live[ii] = adapter_live[--nadapter_live];
        adapter_destroys++;
        break;
      }
  }
  if (type == ET_ERROR)
    gen->gh_flags |= GEN_ERROR;

  gen->gh_call(&ev);          /* for ET_DESTROY, gen may be freed now */

  if (type != ET_DESTROY)
    ref_dec(gen);
}

static void ref_dec(struct GenHeader *gen)
{
  if (!--gen->gh_ref && (gen->gh_flags & GEN_DESTROY)) {
    gen_dequeue(gen);
    deliver(gen, ET_DESTROY, 0);
  }
}

/** engine_delete: DEL by number, then drop the socket's pending events. */
static void engine_delete(struct Socket *sock)
{
  int fd = s_fd(sock), ii;

  if (fd >= 0 && fd < FAKE_FDS && fd_open[fd] && ep[fd]) {
    if (ep[fd] != sock)
      foreign_dels++;
    ep[fd] = NULL;
  }
  for (ii = 0; ii < nbatch; ii++)
    if (batch[ii] == sock) {
      batch[ii] = batch[--nbatch];
      ii--;
    }
}

int socket_add(struct Socket *sock, EventCallBack call, void *data,
               enum SocketState state, unsigned int events, int fd)
{
  int ii;

  assert_non_null(sock);
  assert_non_null(call);
  assert_true(fd >= 0 && fd < FAKE_FDS);
  for (ii = 0; ii < nadapter_live; ii++)     /* re-initialising a live one */
    assert_ptr_not_equal(adapter_live[ii], &sock->s_header);

  /* gen_init, linked at the head of the socket list */
  sock->s_header.gh_next = g_socket;
  sock->s_header.gh_prev_p = &g_socket;
  if (g_socket)
    g_socket->gh_prev_p = &sock->s_header.gh_next;
  g_socket = &sock->s_header;
  sock->s_header.gh_flags = GEN_ACTIVE;
  sock->s_header.gh_ref = 0;
  sock->s_header.gh_call = call;
  sock->s_header.gh_data = data;
  sock->s_header.gh_engdata.ed_int = 0;

  sock->s_state = state;
  sock->s_events = events & SOCK_EVENT_MASK;
  sock->s_fd = fd;

  /* engine_add: EPOLL_CTL_ADD */
  if (add_fail_next || !fd_open[fd] || ep[fd]) {
    add_fail_next = 0;
    deliver(&sock->s_header, ET_ERROR, ENOSPC);
    return 0;           /* still linked: unlinking it is the caller's job */
  }
  ep[fd] = sock;

  if (call != client_cb) {
    assert_true(nadapter_live < FAKE_LOG);
    adapter_live[nadapter_live++] = &sock->s_header;
    adapter_adds++;
  }
  return 1;
}

void socket_del(struct Socket *sock)
{
  assert_false(sock->s_header.gh_flags & GEN_DESTROY);

  engine_delete(sock);
  sock->s_header.gh_flags |= GEN_DESTROY;
  if (!sock->s_header.gh_ref) {
    gen_dequeue(sock);
    deliver(&sock->s_header, ET_DESTROY, 0);
  }
}

/* Only the pre-fix adapter calls this; kept so it links for the red run. */
int socket_reattach(struct Socket *sock, int fd)
{
  engine_delete(sock);
  sock->s_fd = fd;
  if (!fd_open[fd] || ep[fd]) {
    deliver(&sock->s_header, ET_ERROR, EEXIST);
    return 0;
  }
  ep[fd] = sock;
  return 1;
}

void socket_events(struct Socket *sock, unsigned int events)
{
  unsigned int new_events = 0;
  int fd = s_fd(sock);

  if (sock->s_header.gh_flags & (GEN_DESTROY | GEN_ERROR))
    return;

  switch (events & SOCK_ACTION_MASK) {
  case SOCK_ACTION_SET: new_events = events & SOCK_EVENT_MASK; break;
  case SOCK_ACTION_ADD: new_events = sock->s_events | (events & SOCK_EVENT_MASK); break;
  case SOCK_ACTION_DEL: new_events = sock->s_events & ~(events & SOCK_EVENT_MASK); break;
  }
  if (sock->s_events == new_events)
    return;

  /* engine_set_events: EPOLL_CTL_MOD by number */
  if (fd < 0 || fd >= FAKE_FDS || !fd_open[fd] || !ep[fd]) {
    enoent_mods++;
    deliver(&sock->s_header, ET_ERROR, ENOENT);
  } else if (ep[fd] != sock) {
    hijacked_mods++;
    ep[fd] = sock;      /* the kernel re-points the registration at us */
  }
  sock->s_events = new_events;
}

struct Timer *timer_init(struct Timer *timer)
{
  memset(&timer->t_header, 0, sizeof(timer->t_header));
  return timer;
}

static void timer_unqueue(struct Timer *timer)
{
  int ii;

  for (ii = 0; ii < ntimers; ii++)
    if (timers[ii] == timer) {
      memmove(&timers[ii], &timers[ii + 1], (ntimers - ii - 1) * sizeof(timers[0]));
      ntimers--;
      return;
    }
}

void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{
  timer->t_header.gh_flags |= GEN_ACTIVE;
  if (timer->t_header.gh_flags & GEN_MARKED)
    timer->t_header.gh_flags |= GEN_READD;
  timer->t_header.gh_ref = 0;
  timer->t_header.gh_call = call;
  timer->t_header.gh_data = data;
  timer->t_type = type;
  timer->t_value = value;
  timer->t_expire = (type == TT_ABSOLUTE) ? value : CurrentTime + value;

  if (!(timer->t_header.gh_flags & GEN_MARKED)) {
    assert_true(ntimers < FAKE_TIMERS);
    timers[ntimers++] = timer;
  }
}

void timer_del(struct Timer *timer)
{
  timer->t_header.gh_flags &= ~GEN_READD;
  if (timer->t_header.gh_flags & GEN_MARKED)
    return;
  timer_unqueue(timer);
  deliver(&timer->t_header, ET_DESTROY, 0);
}

/** timer_run: the tail of every event-loop pass. */
static void run_timers(void)
{
  for (;;) {
    struct Timer *timer = NULL;
    int ii;

    for (ii = 0; ii < ntimers; ii++)
      if (timers[ii]->t_expire <= CurrentTime) {
        timer = timers[ii];
        break;
      }
    if (!timer)
      break;

    timer_unqueue(timer);
    timer->t_header.gh_flags |= GEN_MARKED |
      (timer->t_type == TT_PERIODIC ? GEN_READD : 0);
    deliver(&timer->t_header, ET_EXPIRE, 0);
    timer->t_header.gh_flags &= ~GEN_MARKED;
    if (!(timer->t_header.gh_flags & GEN_READD))
      deliver(&timer->t_header, ET_DESTROY, 0);
    else {
      timer->t_header.gh_flags &= ~GEN_READD;
      timer->t_expire = CurrentTime + timer->t_value;
      timers[ntimers++] = timer;
    }
  }
}

/** Capture a ready descriptor into the batch, as epoll_wait() would. */
static void batch_ready(int fd)
{
  assert_non_null(ep[fd]);
  assert_true(nbatch < FAKE_BATCH);
  batch[nbatch++] = ep[fd];
}

/** engine_loop over the batch: last-ready first, a reference held across. */
static void run_batch(enum EventType type)
{
  while (nbatch > 0) {
    struct Socket *sock = batch[--nbatch];

    sock->s_header.gh_ref++;
    deliver(&sock->s_header, type, 0);
    ref_dec(&sock->s_header);
  }
}

/** One ready descriptor, dispatched on its own. */
static void dispatch(int fd, enum EventType type)
{
  if (!ep[fd])
    return;             /* not registered: epoll never reports it */
  batch_ready(fd);
  run_batch(type);
}

/** The next accept(): takes the lowest free number and registers it. */
static int client_connects(void)
{
  int fd = fake_open();

  assert_true(socket_add(&client_sock, client_cb, NULL, SS_CONNECTED,
                         SOCK_EVENT_READABLE, fd));
  return fd;
}

/* ------------------------------------------------------------------ */
/* libkc's side                                                        */
/* ------------------------------------------------------------------ */

struct kc_side {
  int reads, writes;
  int fd;
  struct kc_side *next_owner;             /* for the recycle script */
  void (*script)(struct kc_side *self);   /* runs inside the callback */
};

static void kc_cb(int fd, int events, void *data)
{
  struct kc_side *k = data;

  assert_int_equal(fd, k->fd);
  if (events & KC_EVENT_READ)
    k->reads++;
  if (events & KC_EVENT_WRITE)
    k->writes++;
  if (k->script) {
    void (*script)(struct kc_side *) = k->script;

    k->script = NULL;
    script(k);
  }
}

static const struct kc_event_ops *ops;

/** What conn_close() does: remove, then close. */
static void close_self(struct kc_side *k)
{
  ops->socket_remove(k->fd);
  fake_close(k->fd);
}

/** A callback that closes a different libkc socket. */
static void close_other(struct kc_side *k)
{
  close_self(k->next_owner);
}

/** curl inside one callback: the resolver socket closes, the TCP socket
 * opens on the same number. */
static void recycle_self(struct kc_side *k)
{
  close_self(k);
  k->next_owner->fd = fake_open();
  assert_int_equal(k->next_owner->fd, k->fd);
  assert_int_equal(ops->socket_add(k->next_owner->fd, KC_EVENT_WRITE, kc_cb,
                                   k->next_owner), 0);
}

static int kc_open(struct kc_side *k, int events)
{
  k->fd = fake_open();
  assert_int_equal(ops->socket_add(k->fd, events, kc_cb, k), 0);
  return k->fd;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static int setup(void **state)
{
  (void)state;
  memset(fd_open, 0, sizeof(fd_open));
  memset(ep, 0, sizeof(ep));
  memset(&client_sock, 0, sizeof(client_sock));
  g_socket = NULL;
  ntimers = nbatch = 0;
  add_fail_next = foreign_dels = enoent_mods = hijacked_mods = 0;
  nadapter_live = adapter_adds = adapter_destroys = 0;
  client_reads = client_errors = 0;
  CurrentTime = 1790000000;
  ircd_kc_adapter_init();
  ops = ircd_kc_get_event_ops();
  return 0;
}

static int teardown(void **state)
{
  (void)state;
  ircd_kc_adapter_cleanup();
  run_timers();
  return 0;
}

/** The client that inherited a number libkc gave back is still heard. */
static void assert_client_intact(int cfd)
{
  assert_int_equal(foreign_dels, 0);
  assert_ptr_equal(ep[cfd], &client_sock);

  /* its next send arms writable interest ... */
  socket_events(&client_sock, SOCK_ACTION_ADD | SOCK_EVENT_WRITABLE);
  assert_int_equal(enoent_mods, 0);
  assert_int_equal(hijacked_mods, 0);
  assert_int_equal(client_errors, 0);

  /* ... and its input still arrives */
  dispatch(cfd, ET_READ);
  assert_int_equal(client_reads, 1);
}

/* 2026-09-22: libkc returns a number, the listener's accept() reuses it,
 * and the end of the loop pass must not unregister the new owner. */
static void reused_number_keeps_new_owner_registered(void **state)
{
  struct kc_side k = { 0 };
  int fd, cfd;

  (void)state;
  fd = kc_open(&k, KC_EVENT_READ);
  close_self(&k);

  cfd = client_connects();
  assert_int_equal(cfd, fd);

  run_timers();
  assert_client_intact(cfd);
}

/* The same, closed from inside the socket's own callback -- the webhook
 * path (conn_readable -> conn_close), where the accept lands in the same
 * loop pass. */
static void reused_number_after_close_in_own_callback(void **state)
{
  struct kc_side k = { 0 };
  int fd, cfd;

  (void)state;
  fd = kc_open(&k, KC_EVENT_READ);
  k.script = close_self;
  dispatch(fd, ET_READ);
  assert_int_equal(k.reads, 1);

  cfd = client_connects();
  assert_int_equal(cfd, fd);

  run_timers();
  assert_client_intact(cfd);
  assert_int_equal(adapter_destroys, adapter_adds);
}

/* An interest change for a number libkc already gave back must not reach
 * the engine: EPOLL_CTL_MOD would take over the new owner's registration. */
static void update_after_remove_leaves_new_owner_alone(void **state)
{
  struct kc_side k = { 0 };
  int fd, cfd;

  (void)state;
  fd = kc_open(&k, KC_EVENT_READ);
  close_self(&k);
  cfd = client_connects();
  assert_int_equal(cfd, fd);

  assert_int_equal(ops->socket_update(fd, KC_EVENT_READ | KC_EVENT_WRITE), -1);
  assert_int_equal(hijacked_mods, 0);
  assert_ptr_equal(ep[cfd], &client_sock);
}

/* curl recycles a number inside one callback.  Events on it go to the new
 * owner, and neither registration outlives its removal. */
static void recycled_number_in_same_callback_reaches_new_owner(void **state)
{
  struct kc_side first = { 0 }, second = { 0 };
  int fd;

  (void)state;
  fd = kc_open(&first, KC_EVENT_READ);
  first.script = recycle_self;
  first.next_owner = &second;
  dispatch(fd, ET_READ);
  run_timers();

  dispatch(fd, ET_WRITE);
  assert_int_equal(first.reads, 1);
  assert_int_equal(first.writes, 0);
  assert_int_equal(second.writes, 1);

  close_self(&second);
  run_timers();
  assert_int_equal(adapter_destroys, adapter_adds);
  assert_null(g_socket);
}

/* libkc may be handed any descriptor the process can open. */
static void accepts_descriptors_above_256(void **state)
{
  struct kc_side k = { 0 };
  int fd;

  (void)state;
  for (fd = 3; fd < 300; fd++)
    fd_open[fd] = 1;          /* a busy server */
  fd = kc_open(&k, KC_EVENT_READ);
  assert_int_equal(fd, 300);

  dispatch(fd, ET_READ);
  assert_int_equal(k.reads, 1);
  close_self(&k);
  run_timers();
  assert_int_equal(adapter_destroys, adapter_adds);
}

/* An engine refusal is libkc's failure too, and leaves nothing behind:
 * a retry on the same descriptor gets a working registration. */
static void engine_refusal_is_reported_and_retryable(void **state)
{
  struct kc_side k = { 0 };

  (void)state;
  k.fd = fake_open();
  add_fail_next = 1;
  assert_int_equal(ops->socket_add(k.fd, KC_EVENT_READ, kc_cb, &k), -1);
  assert_null(ep[k.fd]);
  assert_null(g_socket);    /* the refused generator is not left linked */
  assert_int_equal(ops->socket_update(k.fd, KC_EVENT_WRITE), -1);

  assert_int_equal(ops->socket_add(k.fd, KC_EVENT_READ, kc_cb, &k), 0);
  dispatch(k.fd, ET_READ);
  assert_int_equal(k.reads, 1);
}

/* One socket's callback removes another whose event is pending in the
 * same batch: that event is dropped, not delivered to freed state. */
static void removed_socket_misses_its_pending_event(void **state)
{
  struct kc_side a = { 0 }, b = { 0 };

  (void)state;
  kc_open(&b, KC_EVENT_READ);
  kc_open(&a, KC_EVENT_READ);
  a.script = close_other;
  a.next_owner = &b;
  batch_ready(b.fd);
  batch_ready(a.fd);          /* last ready runs first: a, then b */

  run_batch(ET_READ);
  run_timers();

  assert_int_equal(a.reads, 1);
  assert_int_equal(b.reads, 0);
  assert_int_equal(adapter_destroys, 1);    /* b, once; a is still open */
}

/* Shutdown releases every registration; libkc's own later removals are
 * then harmless. */
static void cleanup_releases_every_registration(void **state)
{
  struct kc_side a = { 0 }, b = { 0 }, c = { 0 };

  (void)state;
  kc_open(&a, KC_EVENT_READ);
  kc_open(&b, KC_EVENT_WRITE);
  kc_open(&c, KC_EVENT_READ | KC_EVENT_WRITE);

  ircd_kc_adapter_cleanup();
  run_timers();
  assert_null(ep[a.fd]);
  assert_null(ep[b.fd]);
  assert_null(ep[c.fd]);
  assert_int_equal(adapter_destroys, adapter_adds);

  close_self(&a);
  close_self(&b);
  close_self(&c);
  assert_int_equal(foreign_dels, 0);
}

/* A descriptor the adapter never saw: removal and updates are no-ops. */
static void unknown_descriptor_is_ignored(void **state)
{
  int cfd;

  (void)state;
  cfd = client_connects();
  ops->socket_remove(cfd);
  assert_int_equal(ops->socket_update(cfd, KC_EVENT_WRITE), -1);
  run_timers();
  assert_client_intact(cfd);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(reused_number_keeps_new_owner_registered, setup, teardown),
    cmocka_unit_test_setup_teardown(reused_number_after_close_in_own_callback, setup, teardown),
    cmocka_unit_test_setup_teardown(update_after_remove_leaves_new_owner_alone, setup, teardown),
    cmocka_unit_test_setup_teardown(recycled_number_in_same_callback_reaches_new_owner, setup, teardown),
    cmocka_unit_test_setup_teardown(accepts_descriptors_above_256, setup, teardown),
    cmocka_unit_test_setup_teardown(engine_refusal_is_reported_and_retryable, setup, teardown),
    cmocka_unit_test_setup_teardown(removed_socket_misses_its_pending_event, setup, teardown),
    cmocka_unit_test_setup_teardown(cleanup_releases_every_registration, setup, teardown),
    cmocka_unit_test_setup_teardown(unknown_descriptor_is_ignored, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
