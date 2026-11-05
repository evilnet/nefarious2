/*
 * ssl_teardown_cmocka.c - a TLS teardown writes only to a descriptor its
 * socket still owns
 *
 * The SSL object's BIO caches the descriptor NUMBER it was given.  Once
 * the socket has let that number go -- closed by someone else, which an
 * ET_ERROR with EBADF reports, after which client_sock_callback() sets
 * cli_fd to -1 -- the number may already belong to a file another thread
 * opened (a RocksDB SST, a log), and an SSL_shutdown() writes its
 * close_notify into that file.  ssl_free() has refused to since 4b658482;
 * ssl_abort(), the ET_ERROR/ET_EOF teardown, did not.
 *
 * This links the real ssl.o.  The connections are socketpairs and the
 * handshake is real, against a throwaway self-signed certificate.
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
#include <sys/stat.h>
#include <unistd.h>
#include <cmocka.h>

#ifdef USE_SSL

#include "client.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "listener.h"
#include "msgq.h"
#include "s_conf.h"
#include "ssl.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

/* ------------------------------------------------------------------ */
/* The ircd around ssl.o                                               */
/* ------------------------------------------------------------------ */

int log_inassert;
struct SSLCertConf *sslCertConfList;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

int feature_bool(enum Feature feat) { (void)feat; return 0; }
const char *feature_str(enum Feature feat) { (void)feat; return ""; }

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  (void)one; (void)mask; (void)pattern;
}

void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  (void)to; (void)pattern;
}

void send_queued(struct Client *to) { (void)to; }

int msgq_mapiov(const struct MsgQ *mq, struct iovec *iov, int count,
                unsigned int *len)
{
  (void)mq; (void)iov; (void)count; (void)len;
  return 0;
}

void add_connection(struct Listener *listener, int fd, void *ssl)
{
  (void)listener; (void)fd; (void)ssl;
}

/* ------------------------------------------------------------------ */
/* A TLS session over a socketpair                                     */
/* ------------------------------------------------------------------ */

static SSL_CTX *server_ctx, *client_ctx;

static int sv[2] = { -1, -1 };     /* [0] the server's end, [1] the peer's */
static SSL *server, *peer;
static struct Client cli;
static struct Connection con;

/** Handshake a fresh session, the server's side as ssl.c would hold it:
 * on the client's Connection socket, non-blocking. */
static void session_open(SSL_CTX *sctx)
{
  int i, done = 0;
  char buf[256];

  assert_int_equal(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  assert_int_equal(fcntl(sv[0], F_SETFL, O_NONBLOCK), 0);
  assert_int_equal(fcntl(sv[1], F_SETFL, O_NONBLOCK), 0);
  server = SSL_new(sctx);
  peer = SSL_new(client_ctx);
  assert_non_null(server);
  assert_non_null(peer);
  assert_int_equal(SSL_set_fd(server, sv[0]), 1);
  assert_int_equal(SSL_set_fd(peer, sv[1]), 1);
  SSL_set_accept_state(server);
  SSL_set_connect_state(peer);
  for (i = 0; i < 20 && !done; i++) {
    SSL_do_handshake(peer);
    SSL_do_handshake(server);
    done = SSL_is_init_finished(server) && SSL_is_init_finished(peer);
  }
  assert_true(done);
  /* Let each side take what the other sent after the handshake (TLS 1.3
   * session tickets), so the sockets start empty. */
  for (i = 0; i < 3; i++) {
    SSL_read(peer, buf, sizeof(buf));
    SSL_read(server, buf, sizeof(buf));
  }
  ERR_clear_error();

  memset(&cli, 0, sizeof(cli));
  memset(&con, 0, sizeof(con));
  cli_connect(&cli) = &con;
  s_fd(&(cli_socket(&cli))) = sv[0];
  cli_socket(&cli).ssl = server;
}

static void session_close(void)
{
  if (cli_socket(&cli).ssl)
    SSL_free(cli_socket(&cli).ssl);
  cli_socket(&cli).ssl = NULL;
  server = NULL;
  if (peer)
    SSL_free(peer);
  peer = NULL;
  if (sv[0] >= 0)
    close(sv[0]);
  if (sv[1] >= 0)
    close(sv[1]);
  sv[0] = sv[1] = -1;
  ERR_clear_error();
}

/** Bytes waiting in a socket, unread. */
static int pending_bytes(int fd)
{
  char buf[65536];
  ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);

  return n < 0 ? 0 : (int)n;
}

/** The peer got the server's close_notify and nothing after it. */
static void peer_sees_one_close_notify(void)
{
  char buf[256];
  int rc = SSL_read(peer, buf, sizeof(buf));

  assert_int_equal(rc, 0);
  assert_int_equal(SSL_get_error(peer, rc), SSL_ERROR_ZERO_RETURN);
  /* Anything after the close_notify -- a fatal alert from a desynced
   * read -- would still be in the peer's socket. */
  assert_int_equal(pending_bytes(sv[1]), 0);
  ERR_clear_error();
}

/** A file to stand where a descriptor number used to be. */
static int scratch_file(void)
{
  char path[] = "/tmp/ssl_teardown_XXXXXX";
  int fd = mkstemp(path);

  assert_true(fd >= 0);
  unlink(path);
  return fd;
}

static off_t file_size(int fd)
{
  struct stat st;

  assert_int_equal(fstat(fd, &st), 0);
  return st.st_size;
}

/* ------------------------------------------------------------------ */
/* ssl_abort(): ET_ERROR / ET_EOF                                       */
/* ------------------------------------------------------------------ */

/** ET_ERROR with EBADF: something else closed the socket's descriptor and
 * a file now has the number; client_sock_callback() sets cli_fd to -1 and
 * falls through to ssl_abort().  It must free the session without a word:
 * the BIO would write the close_notify into the file. */
static void abort_after_the_fd_is_gone_writes_nothing(void **state)
{
  int file;

  (void)state;
  session_open(server_ctx);

  /* The stray close and the reuse: the number now names a file. */
  file = scratch_file();
  assert_int_equal(dup2(file, sv[0]), sv[0]);
  close(file);
  file = sv[0];
  sv[0] = -1;                       /* the test's copy, closed below */
  cli_fd(&cli) = -1;                /* what the ET_ERROR EBADF branch does */

  ssl_abort(&cli);

  assert_null(cli_socket(&cli).ssl);
  assert_int_equal(file_size(file), 0);
  close(file);
  session_close();
}

/** ssl_abort() on a socket that still owns its descriptor (ET_EOF, a
 * failed accept after the handshake) still sends the close_notify. */
static void abort_with_its_fd_sends_close_notify(void **state)
{
  (void)state;
  session_open(server_ctx);

  ssl_abort(&cli);

  assert_null(cli_socket(&cli).ssl);
  peer_sees_one_close_notify();
  session_close();
}

/* ------------------------------------------------------------------ */
/* ssl_free(): close_connection()'s teardown                           */
/* ------------------------------------------------------------------ */

/** A socket that has let its descriptor go (s_fd -1) frees the session
 * silently (4b658482; pinned here beside ssl_abort()). */
static void free_without_an_fd_writes_nothing(void **state)
{
  int file;

  (void)state;
  session_open(server_ctx);
  file = scratch_file();
  assert_int_equal(dup2(file, sv[0]), sv[0]);
  close(file);
  file = sv[0];
  sv[0] = -1;
  s_fd(&(cli_socket(&cli))) = -1;

  ssl_free(&(cli_socket(&cli)));

  assert_null(cli_socket(&cli).ssl);
  assert_int_equal(file_size(file), 0);
  close(file);
  session_close();
}

/* ------------------------------------------------------------------ */
/* Setup                                                               */
/* ------------------------------------------------------------------ */

static SSL_CTX *server_ctx_new(EVP_PKEY *key, X509 *cert)
{
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

  if (!ctx || SSL_CTX_use_certificate(ctx, cert) != 1
      || SSL_CTX_use_PrivateKey(ctx, key) != 1) {
    SSL_CTX_free(ctx);
    return NULL;
  }
  return ctx;
}

static int group_setup(void **state)
{
  EVP_PKEY *key;
  X509 *cert;
  X509_NAME *name;
  int ok;

  (void)state;
  if (!(key = EVP_EC_gen("P-256")) || !(cert = X509_new()))
    return -1;
  name = X509_get_subject_name(cert);
  ok = ASN1_INTEGER_set(X509_get_serialNumber(cert), 1)
    && X509_gmtime_adj(X509_getm_notBefore(cert), 0)
    && X509_gmtime_adj(X509_getm_notAfter(cert), 3600)
    && X509_set_pubkey(cert, key)
    && X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                  (const unsigned char *)"teardown.test",
                                  -1, -1, 0)
    && X509_set_issuer_name(cert, name)
    && X509_sign(cert, key, EVP_sha256())
    && (server_ctx = server_ctx_new(key, cert))
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
  SSL_CTX_free(server_ctx);
  return 0;
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(abort_after_the_fd_is_gone_writes_nothing),
    cmocka_unit_test(abort_with_its_fd_sends_close_notify),
    cmocka_unit_test(free_without_an_fd_writes_nothing),
  };

  return cmocka_run_group_tests(tests, group_setup, group_teardown);
}

#else /* !USE_SSL */

int main(void)
{
  puts("ssl_teardown_cmocka: built without SSL, no TLS teardown to test");
  return 0;
}

#endif /* USE_SSL */
