/*
 * listener_rehash_cmocka.c - a listener that a REHASH leaves with no
 * socket is never freed while it is still on ListenerPollList.
 *
 * add_listener() reuses the Listener a port already has.  When the new
 * Port block leaves it no socket (it moves to an address family that
 * cannot be bound), it used to be freed on the spot, while still linked
 * and while clients that came in on it still held references: the next
 * close_listeners() and every release_listener() then touched freed
 * memory.  It must instead be marked inactive and closed by
 * close_listeners() or by the last release_listener().
 *
 * Includes ../listener.c; the sockets, the event engine and the rest of
 * the server are stubs.  IPv6 sockets cannot be opened in this test.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

#include "../listener.c"

/* ---- free() watch ---- */
void __real_free(void *p);
static const void *watched;
static int watched_freed;
void __wrap_free(void *p)
{
  if (p && p == watched)
    watched_freed++;
  __real_free(p);
}

/* ---- stubs ---- */
struct Client me;
time_t CurrentTime;
struct ServerStatistics *ServerStats;
int server_boot_complete = 1;
int log_inassert;
const char* const LISTEN_ERROR_MSG = "listen";
const char* const SETBUFS_ERROR_MSG = "setbufs";
const char* const TOS_ERROR_MSG = "tos";
static int next_fd = 100;
static int sockets_open;

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{ (void)type; (void)file; (void)line; return malloc(len); }
int os_socket(const struct irc_sockaddr *local, int type, const char *port_name, int family)
{ (void)local; (void)type; (void)port_name; return family == AF_INET6 ? -1 : next_fd++; }
int os_set_listen(int fd, int backlog) { (void)fd; (void)backlog; return 1; }
int os_set_sockbufs(int fd, unsigned int s, unsigned int r) { (void)fd; (void)s; (void)r; return 1; }
int os_set_tos(int fd, int tos, int family) { (void)fd; (void)tos; (void)family; return 1; }
int os_accept(int fd, struct irc_sockaddr *peer) { (void)fd; (void)peer; return -1; }
int socket_add(struct Socket *sock, EventCallBack call, void *data,
               enum SocketState state, unsigned int events, int fd)
{ (void)sock; (void)call; (void)data; (void)state; (void)events; (void)fd; sockets_open++; return 1; }
void socket_del(struct Socket *sock) { (void)sock; sockets_open--; }
int close(int fd) { (void)fd; return 0; }
void report_error(const char *text, const char *who, int err) { (void)text; (void)who; (void)err; }
void add_connection(struct Listener *l, int fd, void *ssl) { (void)l; (void)fd; (void)ssl; }
void ssl_add_connection(struct Listener *l, int fd) { (void)l; (void)fd; }
void paste_accept_connection(struct Listener *l, int fd) { (void)l; (void)fd; }
int feature_int(enum Feature feat) { (void)feat; return 0; }
/* listener.c asks this once a configuration check opens no listener
 * (#238); harmless before that. */
int conf_is_check_only(void) { return 0; }
int ipmask_check(const struct irc_in_addr *a, const struct irc_in_addr *m, unsigned char b)
{ (void)a; (void)m; (void)b; return 1; }
int ipmask_parse(const char *in, struct irc_in_addr *mask, unsigned char *bits)
{ (void)in; memset(mask, 0, sizeof(*mask)); if (bits) *bits = 0; return 1; }
int ircd_snprintf(struct Client *dest, char *buf, size_t len, const char *fmt, ...)
{ (void)dest; (void)fmt; if (len) buf[0] = '\0'; return 0; }
void log_write(enum LogSys s, enum LogLevel l, unsigned int f, const char *fmt, ...)
{ (void)s; (void)l; (void)f; (void)fmt; }
void sendto_opmask_butone(struct Client *one, unsigned int mask, const char *pattern, ...)
{ (void)one; (void)mask; (void)pattern; }

/* ---- helpers ---- */
static struct ListenerFlags fam(int v4, int v6)
{
  struct ListenerFlags f;
  memset(&f, 0, sizeof(f));
  if (v4) FlagSet(&f, LISTEN_IPV4);
  if (v6) FlagSet(&f, LISTEN_IPV6);
  return f;
}

static int linked(const struct Listener *l)
{
  const struct Listener *p;
  for (p = ListenerPollList; p; p = p->next)
    if (p == l)
      return 1;
  return 0;
}

static int setup(void **state)
{
  (void)state;
  ListenerPollList = NULL;
  watched = NULL;
  watched_freed = 0;
  sockets_open = 0;
  return 0;
}

static struct Listener *open_v4(int port)
{
  struct ListenerFlags f = fam(1, 0);
  struct Listener *l;
  add_listener(port, "*", NULL, &f);
  l = ListenerPollList;
  assert_non_null(l);
  assert_true(l->fd_v4 >= 0);
  watched = l;
  return l;
}

/* A REHASH moves a port that has a client to IPv6 only, which cannot be
 * bound: the listener stays (inactive) until the client leaves. */
static void unbindable_rehash_with_client_keeps_listener(void **state)
{
  struct ListenerFlags v6 = fam(0, 1);
  struct Listener *l;
  (void)state;

  l = open_v4(16678);
  l->ref_count++;               /* a client came in on it */

  mark_listeners_closing();     /* rehash() */
  add_listener(16678, "*", NULL, &v6);
  assert_int_equal(watched_freed, 0);
  assert_true(linked(l));
  assert_false(listener_active(l));
  assert_int_equal(l->fd_v4, -1);
  assert_int_equal(sockets_open, 0);

  close_listeners();            /* end of rehash(): still referenced */
  assert_int_equal(watched_freed, 0);
  assert_true(linked(l));

  release_listener(l);          /* the client leaves */
  assert_int_equal(watched_freed, 1);
  assert_null(ListenerPollList);
}

/* The same with no client: close_listeners() closes it. */
static void unbindable_rehash_without_client_closes_it(void **state)
{
  struct ListenerFlags v6 = fam(0, 1);
  struct Listener *l;
  (void)state;

  l = open_v4(16679);
  mark_listeners_closing();
  add_listener(16679, "*", NULL, &v6);
  assert_int_equal(watched_freed, 0);
  assert_true(linked(l));

  close_listeners();
  assert_int_equal(watched_freed, 1);
  assert_null(ListenerPollList);
}

/* A new Port that cannot be bound is freed at once and never linked. */
static void unbindable_new_port_is_not_linked(void **state)
{
  struct ListenerFlags v6 = fam(0, 1);
  (void)state;

  add_listener(16680, "*", NULL, &v6);
  assert_null(ListenerPollList);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(unbindable_rehash_with_client_keeps_listener, setup),
    cmocka_unit_test_setup(unbindable_rehash_without_client_closes_it, setup),
    cmocka_unit_test_setup(unbindable_new_port_is_not_linked, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
