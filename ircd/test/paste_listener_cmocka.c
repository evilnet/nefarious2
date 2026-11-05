/*
 * paste_listener_cmocka.c - a paste connection is freed only once every
 * event generator inside it has let go of it
 *
 * A paste_conn embeds two event generators, its Socket and its request
 * Timer.  The event core still touches a generator after its callback
 * returns: event_execute() drops the reference the event held, and
 * timer_run() clears an expired timer's GEN_MARKED bit and then raises the
 * timer's ET_DESTROY through its callback pointer.  So the struct may be
 * freed only by the last of the two ET_DESTROYs.
 *
 * A request timeout broke that.  The expiry callback deleted the socket;
 * the socket was in no callback, so its ET_DESTROY ran at once and freed
 * the conn while the timer was still inside its own expiry, and timer_run()
 * then wrote into the freed timer and called through it.
 *
 * This includes the real paste_listener.c and links the real event core
 * and epoll engine.  Connections are socketpairs; the TLS cases run a real
 * handshake against a throwaway self-signed certificate.  The paste
 * listener's MyMalloc() and MyFree() come here: watch_malloc() knows the
 * conn by its allocation, and watch_free() checks the conn as it is freed:
 * neither generator may still be active, i.e. both have had their
 * ET_DESTROY or were never registered.  It then poisons the block, so a
 * later read of the conn through the event core trips one of the core's
 * asserts here, not only under valgrind.  Under valgrind the old timeout
 * path also shows as invalid writes in timer_run().
 *
 * A conn also holds a reference on the Listener that accepted it, as a
 * client does: a rehash that drops the port frees the Listener only once
 * nothing refers to it, and a WebSocket upgrade still reads it (the
 * websocket flag) and hands it to add_connection().  The Listener here is
 * on the heap and freed, poisoned, the way close_listener() frees it.
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
#include <time.h>
#include <unistd.h>
#include <cmocka.h>

#ifdef USE_SSL

/* The paste listener's MyMalloc() comes to watch_malloc() with the text
 * of its size argument, which names the conn's allocation
 * ("sizeof(*conn)", paste_conn_new()) whatever its size; and its MyFree()
 * comes to watch_free().  ircd_alloc.h is guarded, so its include in
 * paste_listener.c keeps these. */
#include "ircd_alloc.h"
static void *watch_malloc(size_t len, const char *what);
static void watch_free(void *p);
#undef MyMalloc
#define MyMalloc(size) watch_malloc((size), #size)
#undef DoFree
#define DoFree(x, file, line) do { watch_free((x)); (x) = 0; } while (0)

#include "../paste_listener.c"

#include <openssl/evp.h>
#include <openssl/x509.h>

/** The request timeout the cases run with (FEAT_PASTE_REQUEST_TIMEOUT). */
#define REQUEST_TIMEOUT 30

/* ------------------------------------------------------------------ */
/* The ircd around the paste listener and the event core               */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int running = 1;
int log_inassert;
struct Client me;
struct Listener *ListenerPollList;
struct Client *LocalClientArray[MAXCONNECTIONS];
SSL_CTX *ssl_server_ctx;

static int websocket_on;        /* FEAT_WEBSOCKET */
static int timeouts;            /* "Paste connection timeout" log lines */

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_PASTE_MAX_CONNECTIONS:
    return 64;
  case FEAT_PASTE_REQUEST_TIMEOUT:
    return REQUEST_TIMEOUT;
  default:
    return 20;                  /* FEAT_POLLS_PER_LOOP */
  }
}

int feature_bool(enum Feature feat)
{
  return feat == FEAT_WEBSOCKET ? websocket_on : 0;
}

const char *feature_str(enum Feature feat)
{
  (void)feat;
  return "";
}

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  char buf[512];
  va_list args;

  (void)subsys; (void)severity; (void)flags;
  va_start(args, fmt);
  vsnprintf(buf, sizeof(buf), fmt, args);
  va_end(args);
  if (strstr(buf, "Paste connection timeout"))
    timeouts++;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

void server_restart(const char *message)
{
  fail_msg("server_restart: %s", message);
}

void thread_pool_poll(void)
{
}

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

void ssl_clear_errors(const char *where)
{
  (void)where;
  ERR_clear_error();
}

int exit_client(struct Client *cptr, struct Client *bcptr,
                struct Client *sptr, const char *comment)
{
  (void)cptr; (void)bcptr; (void)sptr;
  fail_msg("exit_client: %s", comment);
  return 0;
}

void send_queued(struct Client *to)
{
  (void)to;
}

#ifdef USE_ROCKSDB
const char *ml_content_paste_lookup(const char *paste_id)
{
  (void)paste_id;
  return NULL;
}

char *ml_content_get(const char *msgid, size_t *content_len_out,
                     const char **sender_out, const char **target_out)
{
  (void)msgid; (void)content_len_out; (void)sender_out; (void)target_out;
  return NULL;
}
#endif

/* The configured fallback engine; epoll is chosen ahead of it. */
static int no_engine_init(int max_sockets)
{
  (void)max_sockets;
  return 0;
}
struct Engine engine_poll = { "unused", no_engine_init, 0, 0, 0, 0, 0, 0 };

/* The event core's assert() (events_assert.h, as in ircd_events_cmocka):
 * a failed one fails the case. */
void events_assert(int ok, const char *expression, const char *file, int line)
{
  if (!ok)
    mock_assert(0, expression, file, line);
}

/* ------------------------------------------------------------------ */
/* The conn under watch                                                */
/* ------------------------------------------------------------------ */

static void *conn_mem;          /* the paste_conn allocated last */
static int conn_frees;          /* times it was freed */
static int freed_in_use;        /* ...while a generator in it was active */

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
}

/** Room left in front of the conn in its block.  free() writes its own
 * bookkeeping into the first 32 bytes of a large freed block (glibc: the
 * bin links), which would wipe the poison off the conn's first fields
 * (fd, ssl, state, dying, freeflag); the conn sits after them. */
#define CONN_PAD 64

/** The paste listener's MyMalloc(): \a what is the text of its size
 * argument. */
static void *watch_malloc(size_t len, const char *what)
{
  if (0 == strcmp(what, "sizeof(*conn)")) {
    char *base = DoMalloc(CONN_PAD + len, "malloc", __FILE__, __LINE__);

    conn_mem = base + CONN_PAD;
    return conn_mem;
  }
  return DoMalloc(len, "malloc", __FILE__, __LINE__);
}

void *DoRealloc(void *p, size_t len, const char *file, int line)
{
  (void)file; (void)line;
  p = realloc(p, len);
  assert_non_null(p);
  return p;
}

/** The paste listener's MyFree().  The conn may go only when neither of
 * its generators is still active: each has had its ET_DESTROY (which
 * clears GEN_ACTIVE before the callback runs), or was never registered.
 * A timer inside its own expiry is still active.  The conn is then
 * poisoned before it goes: every generator flag set (GEN_DESTROY,
 * GEN_MARKED and GEN_READD among them), every pointer wild, every
 * PASTE_FREE_* bit set.  A generator read from it trips one of the event
 * core's asserts, and a stale PASTE_FREE_* bit sends the paste code into
 * one (socket_del() of a socket marked destroyed). */
static void watch_free(void *p)
{
  if (p && p == conn_mem) {
    struct paste_conn *conn = p;

    conn_frees++;
    if (t_active(&conn->timeout) || s_active(&conn->socket))
      freed_in_use++;
    memset(conn, 0xff, sizeof(*conn));
    conn_mem = NULL;
    p = (char *)p - CONN_PAD;
  }
  free(p);
}

/* ------------------------------------------------------------------ */
/* Connections                                                         */
/* ------------------------------------------------------------------ */

/* The accepting Listener, made as add_listener() makes it and closed as
 * listener.c closes it.  A closed one is only ever compared, never read. */
static struct Listener *listener;
static struct Listener *closed_listener;
static int listener_closes;
static int bad_releases;        /* release_listener() with no reference */

/** close_listener(): the Listener goes, poisoned first. */
static void listener_close(struct Listener *l)
{
  listener_closes++;
  closed_listener = l;
  if (l == listener)
    listener = NULL;
  memset(l, 0xff, sizeof(*l));
  free(l);
}

/** listener.c's release_listener(): the last reference on a port the
 * configuration no longer has closes it. */
void release_listener(struct Listener *l)
{
  if (l == closed_listener || l->ref_count <= 0) {
    bad_releases++;
    return;
  }
  if (0 == --l->ref_count && !listener_active(l))
    listener_close(l);
}

/** A rehash whose configuration no longer has the port:
 * mark_listeners_closing(), then close_listeners(), which closes it unless
 * something still holds a reference. */
static void rehash_drops_the_port(void)
{
  FlagClr(&listener->flags, LISTEN_ACTIVE);
  if (0 == listener->ref_count)
    listener_close(listener);
}

static int peer = -1;           /* the client's end of the socketpair */
static SSL_CTX *client_ctx;
static SSL *client;

/* The WebSocket promote: the client add_connection() makes, and the
 * request the paste conn had buffered, as the handshake feed is handed
 * it. */
static struct Client promoted;
static int promoted_fd = -1;
static SSL *promoted_ssl;
static int refuse_promote;      /* add_connection() refuses the client */
static int refused_promotes;
static int promoted_on_closed;  /* add_connection() given a closed Listener */
static char fed[PASTE_MAX_REQUEST_SIZE];
static int fed_len = -1;
static int fed_frees = -1;      /* conn_frees when the request was fed */

/** A paste connection on a socketpair: the server's end goes to the
 * listener, as accept_connection() hands it over. */
static int paste_open(void)
{
  int sv[2];

  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  peer = sv[1];
  paste_accept_connection(listener, sv[0]);
  assert_non_null(conn_mem);
  assert_ptr_equal(paste_conn_list, conn_mem);
  assert_int_equal(paste_conn_count, 1);
  return sv[0];
}

static void stop_loop(struct Event *ev)
{
  if (ev_type(ev) == ET_EXPIRE)
    running = 0;
}

/** One pass of the engine loop: socket events, then the timers. */
static void engine_pass(void)
{
  struct Timer stop;

  timer_add(timer_init(&stop), stop_loop, NULL, TT_RELATIVE, 0);
  running = 1;
  event_loop();
  running = 1;
}

/** The server closed its end: everything it sent, then end of file -- or
 * a reset, when it closed with bytes of ours still unread. */
static void assert_peer_closed(void)
{
  char buf[256];
  ssize_t n;

  while ((n = read(peer, buf, sizeof(buf))) > 0)
    ;
  if (n < 0)
    assert_int_equal(errno, ECONNRESET);
  else
    assert_int_equal(n, 0);
}

/** The conn is gone, freed once, with nothing of it left behind: no list
 * entry, no reference on its Listener (a promoted client holds its own),
 * and no timer that could still fire for it. */
static void assert_conn_gone(void)
{
  int timed_out = timeouts;

  assert_int_equal(conn_frees, 1);
  assert_int_equal(freed_in_use, 0);
  assert_null(paste_conn_list);
  assert_int_equal(paste_conn_count, 0);
  assert_int_equal(bad_releases, 0);
  if (listener)
    assert_int_equal(listener->ref_count, promoted_fd >= 0 ? 1 : 0);

  CurrentTime += REQUEST_TIMEOUT;
  timer_run();
  assert_int_equal(timeouts, timed_out);
}

/** The client side of a TLS handshake, the server's side run by the
 * engine between steps. */
static void tls_connect(void)
{
  int i, rc, err;

  assert_int_equal(fcntl(peer, F_SETFL, O_NONBLOCK), 0);
  client = SSL_new(client_ctx);
  assert_non_null(client);
  assert_int_equal(SSL_set_fd(client, peer), 1);
  for (i = 0; i < 10; i++) {
    rc = SSL_connect(client);
    if (rc == 1)
      return;
    err = SSL_get_error(client, rc);
    assert_true(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE);
    engine_pass();
  }
  fail_msg("the TLS handshake did not complete");
}

static void tls_send(const char *text)
{
  assert_int_equal(SSL_write(client, text, strlen(text)), (int)strlen(text));
}

/** Everything the server sent before it closed. */
static void tls_read_all(char *buf, size_t size)
{
  size_t n = 0;
  int rc;

  while (n < size - 1 && (rc = SSL_read(client, buf + n, size - 1 - n)) > 0)
    n += rc;
  buf[n] = '\0';
}

/** add_connection(): it takes the stolen descriptor and TLS session, as
 * s_bsd.c does, and the client's own reference on the Listener -- or, when
 * refusing (throttled, z-lined), closes both and takes nothing. */
void add_connection(struct Listener *lptr, int fd, void *ssl)
{
  if (lptr == closed_listener)
    promoted_on_closed++;       /* the real one writes into it */
  if (refuse_promote) {
    SSL_free(ssl);
    close(fd);
    refused_promotes++;
    return;
  }
  if (lptr != closed_listener)
    ++lptr->ref_count;
  promoted_fd = fd;
  promoted_ssl = ssl;
  LocalClientArray[fd] = &promoted;
}

int websocket_handshake_feed(struct Client *cptr, const char *data, int len,
                             int *consumed)
{
  assert_ptr_equal(cptr, &promoted);
  assert_true(len >= 0 && len < (int)sizeof(fed));
  fed_frees = conn_frees;
  memcpy(fed, data, len);
  fed_len = len;
  *consumed = len;
  return 0;                     /* more to come: nothing else happens */
}

static int case_setup(void **state)
{
  (void)state;
  CurrentTime = time(NULL);
  conn_mem = NULL;
  conn_frees = freed_in_use = timeouts = websocket_on = 0;
  listener = calloc(1, sizeof(*listener));
  assert_non_null(listener);
  FlagSet(&listener->flags, LISTEN_ACTIVE);
  closed_listener = NULL;
  listener_closes = bad_releases = 0;
  peer = -1;
  client = NULL;
  promoted_fd = fed_len = fed_frees = -1;
  promoted_ssl = NULL;
  refuse_promote = refused_promotes = promoted_on_closed = 0;
  return 0;
}

static int case_teardown(void **state)
{
  (void)state;
  paste_listener_shutdown();    /* a conn a failed case left behind */
  if (client)
    SSL_free(client);
  if (peer >= 0)
    close(peer);
  if (promoted_ssl)
    SSL_free(promoted_ssl);
  if (promoted_fd >= 0) {
    LocalClientArray[promoted_fd] = NULL;
    close(promoted_fd);
  }
  free(listener);
  listener = NULL;
  return 0;
}

static int group_setup(void **state)
{
  EVP_PKEY *key;
  X509 *cert;
  X509_NAME *name;
  int ok;

  (void)state;
  CurrentTime = time(NULL);
  event_init(64);

  /* A throwaway self-signed certificate for the server's side. */
  if (!(key = EVP_EC_gen("P-256")) || !(cert = X509_new()))
    return -1;
  name = X509_get_subject_name(cert);
  ok = ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
    && X509_gmtime_adj(X509_getm_notBefore(cert), 0)
    && X509_gmtime_adj(X509_getm_notAfter(cert), 3600)
    && X509_set_pubkey(cert, key)
    && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                  (const unsigned char *)"paste.test",
                                  -1, -1, 0)
    && X509_set_issuer_name(cert, name)
    && X509_sign(cert, key, EVP_sha256())
    && (ssl_server_ctx = SSL_CTX_new(TLS_server_method()))
    && SSL_CTX_use_certificate(ssl_server_ctx, cert) == 1
    && SSL_CTX_use_PrivateKey(ssl_server_ctx, key) == 1
    && (client_ctx = SSL_CTX_new(TLS_client_method()));
  X509_free(cert);
  EVP_PKEY_free(key);
  if (!ok)
    return -1;
  SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, NULL);
  return 0;
}

static int group_teardown(void **state)
{
  (void)state;
  SSL_CTX_free(client_ctx);
  SSL_CTX_free(ssl_server_ctx);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* The defect: a request that never completes times out.  The expiry
 * callback runs inside timer_run(), which touches the timer again after
 * it returns, so the conn that embeds the timer must outlive the callback
 * and be freed by the timer's ET_DESTROY. */
static void request_timeout_frees_the_conn_after_its_timer(void **state)
{
  (void)state;
  paste_open();

  CurrentTime += REQUEST_TIMEOUT;
  timer_run();

  assert_int_equal(timeouts, 1);
  assert_int_equal(conn_frees, 1);
  assert_int_equal(freed_in_use, 0);
  assert_null(paste_conn_list);
  assert_int_equal(paste_conn_count, 0);
  assert_peer_closed();
}

/* A handshake that fails is freed from the socket's own callback: the
 * timer is idle, so it is deleted at once, and the conn goes when the
 * engine lets go of the socket, within the same pass. */
static void failed_handshake_frees_the_conn_in_the_same_pass(void **state)
{
  static const char plain[] = "GET / HTTP/1.1\r\n\r\n";

  (void)state;
  paste_open();
  assert_int_equal(write(peer, plain, sizeof(plain) - 1), sizeof(plain) - 1);

  engine_pass();
  assert_peer_closed();
  assert_conn_gone();
}

/* The client hangs up before its request: the same, through ET_EOF or a
 * failed read. */
static void hangup_frees_the_conn_in_the_same_pass(void **state)
{
  (void)state;
  paste_open();
  close(peer);
  peer = -1;

  engine_pass();
  assert_conn_gone();
}

/* A registration the engine refuses: the socket was never active, the
 * timer is idle, and the conn is freed at once, its descriptor closed. */
static void refused_registration_frees_the_conn_at_once(void **state)
{
  int fd;

  (void)state;
  fd = open("/dev/null", O_RDWR);       /* epoll refuses it: EPERM */
  assert_true(fd >= 0);

  paste_accept_connection(listener, fd);
  assert_int_equal(fcntl(fd, F_GETFD), -1);
  assert_int_equal(errno, EBADF);
  assert_conn_gone();
}

/* Shutdown frees each conn from outside any callback: both generators
 * are idle, so both are destroyed at once, and the conn with them. */
static void shutdown_frees_the_conn_at_once(void **state)
{
  (void)state;
  paste_open();

  paste_listener_shutdown();
  assert_peer_closed();
  assert_conn_gone();
}

/* A request served in full: the conn is freed from the socket's callback
 * once the reply is written, and the client has all of the reply. */
static void served_request_frees_the_conn_after_its_reply(void **state)
{
  char reply[2048];
  int i;

  (void)state;
  paste_open();
  tls_connect();
  tls_send("GET / HTTP/1.1\r\nHost: paste.test\r\n\r\n");

  for (i = 0; i < 10 && !conn_frees; i++)
    engine_pass();

  tls_read_all(reply, sizeof(reply));
  assert_non_null(strstr(reply, "HTTP/1.1 404 Not Found\r\n"));
  assert_conn_gone();
}

/* A WebSocket upgrade on a paste port becomes an IRC client on the same
 * descriptor and TLS session.  The paste conn is released first, but its
 * buffered request is replayed afterwards, so the husk must live until the
 * socket's deferred ET_DESTROY, after the callback. */
static void websocket_upgrade_replays_the_request_before_the_free(void **state)
{
  static const char upgrade[] =
    "GET / HTTP/1.1\r\nHost: paste.test\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\n\r\n";
  int fd, i;

  (void)state;
  websocket_on = 1;
  FlagSet(&listener->flags, LISTEN_WEBSOCKET);
  fd = paste_open();
  tls_connect();
  tls_send(upgrade);

  for (i = 0; i < 10 && promoted_fd < 0; i++)
    engine_pass();

  assert_int_equal(promoted_fd, fd);
  assert_non_null(promoted_ssl);
  assert_int_equal(fed_frees, 0);       /* the husk was still alive */
  assert_int_equal(fed_len, (int)sizeof(upgrade) - 1);
  assert_memory_equal(fed, upgrade, sizeof(upgrade) - 1);
  assert_true(fcntl(fd, F_GETFD) >= 0); /* the client's now, still open */
  assert_conn_gone();
}

/* A conn holds a reference on its Listener from its accept to its close,
 * as a client does (STATS P counts it). */
static void conn_holds_a_reference_on_its_listener(void **state)
{
  (void)state;
  paste_open();
  assert_int_equal(listener->ref_count, 1);

  CurrentTime += REQUEST_TIMEOUT;
  timer_run();
  assert_int_equal(listener->ref_count, 0);
  assert_conn_gone();
  assert_int_equal(listener_closes, 0);
}

/* A rehash that drops the port while a request is in flight: the Listener
 * stays until the conn closes, and the conn's close then closes it. */
static void removed_port_lasts_until_its_conn_closes(void **state)
{
  (void)state;
  paste_open();

  rehash_drops_the_port();
  assert_int_equal(listener_closes, 0);
  assert_non_null(listener);

  CurrentTime += REQUEST_TIMEOUT;
  timer_run();
  assert_int_equal(listener_closes, 1);
  assert_null(listener);
  assert_conn_gone();
}

/* The port is dropped, then the conn sends a WebSocket upgrade: the
 * promote reads the Listener and hands it to add_connection(), which takes
 * the client's own reference.  Only then does the conn's go, so the
 * Listener lasts until the client leaves. */
static void websocket_upgrade_on_a_removed_port(void **state)
{
  static const char upgrade[] =
    "GET / HTTP/1.1\r\nHost: paste.test\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\n\r\n";
  int fd, i;

  (void)state;
  websocket_on = 1;
  FlagSet(&listener->flags, LISTEN_WEBSOCKET);
  fd = paste_open();
  tls_connect();

  rehash_drops_the_port();
  tls_send(upgrade);
  for (i = 0; i < 10 && promoted_fd < 0 && !conn_frees; i++)
    engine_pass();

  assert_int_equal(promoted_on_closed, 0);
  assert_int_equal(listener_closes, 0);
  assert_int_equal(promoted_fd, fd);
  assert_int_equal(fed_len, (int)sizeof(upgrade) - 1);
  assert_conn_gone();           /* the client's reference alone */

  release_listener(listener);   /* the client leaves */
  assert_int_equal(listener_closes, 1);
  assert_int_equal(bad_releases, 0);
}

/* The same, but add_connection() refuses the client: it takes no
 * reference, so the conn's, given up after it, is the last, and closes
 * the Listener. */
static void refused_upgrade_on_a_removed_port_closes_it(void **state)
{
  static const char upgrade[] =
    "GET / HTTP/1.1\r\nHost: paste.test\r\nUpgrade: websocket\r\n"
    "Connection: Upgrade\r\n\r\n";
  int i;

  (void)state;
  websocket_on = 1;
  refuse_promote = 1;
  FlagSet(&listener->flags, LISTEN_WEBSOCKET);
  paste_open();
  tls_connect();

  rehash_drops_the_port();
  tls_send(upgrade);
  for (i = 0; i < 10 && !conn_frees; i++)
    engine_pass();

  assert_int_equal(promoted_on_closed, 0);
  assert_int_equal(refused_promotes, 1);
  assert_int_equal(listener_closes, 1);
  assert_conn_gone();
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(
      request_timeout_frees_the_conn_after_its_timer,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      failed_handshake_frees_the_conn_in_the_same_pass,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      hangup_frees_the_conn_in_the_same_pass,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      refused_registration_frees_the_conn_at_once,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      shutdown_frees_the_conn_at_once,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      served_request_frees_the_conn_after_its_reply,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      websocket_upgrade_replays_the_request_before_the_free,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      conn_holds_a_reference_on_its_listener,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      removed_port_lasts_until_its_conn_closes,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      websocket_upgrade_on_a_removed_port,
      case_setup, case_teardown),
    cmocka_unit_test_setup_teardown(
      refused_upgrade_on_a_removed_port_closes_it,
      case_setup, case_teardown),
  };

  return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

#else /* !USE_SSL */

int main(void)
{
  puts("paste_listener_cmocka: built without SSL, no paste listener to test");
  return 0;
}

#endif /* USE_SSL */
