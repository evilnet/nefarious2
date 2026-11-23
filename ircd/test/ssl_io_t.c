/*
 * ssl_io_t.c - the OpenSSL error queue around TLS I/O.
 *
 * SSL_get_error() reports any error already queued on the thread as
 * SSL_ERROR_SSL (SSL_ERROR_SYSCALL for a system-library one) before it
 * looks at the would-block state, so an error some earlier OpenSSL call
 * left behind turns an ordinary SSL_ERROR_WANT_WRITE into a fatal write
 * error.  The queue must be empty before every TLS I/O or handshake call
 * whose result goes to SSL_get_error(), and a teardown or a failed setup
 * must not leave errors behind.
 *
 * This drives the real ssl_connect(), ssl_accept(), ssl_sendv(),
 * ssl_recv(), ssl_murder(), ssl_doerror() and sslfail() over a socketpair:
 * ssl.c is included, compiled with -ffunction-sections and linked with
 * --gc-sections, so the program keeps those and what they call; the rest
 * of the server they reach is stubbed below.
 */
#include "../ssl.c"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef USE_SSL

#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

/* ---------- checks ---------- */

static int checks;              /**< checks evaluated */
static int failures;            /**< checks that did not hold */

static void check(int ok, int line, const char *what)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED line %d: %s\n", line, what);
  }
}

#define CHECK(cond, what) check((cond) ? 1 : 0, __LINE__, (what))

/* ---------- stubs ---------- */

static int notices;             /**< operator notices sent */

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  va_list args;

  notices++;
  printf("notice: ");
  va_start(args, pattern);
  vprintf(pattern, args);
  va_end(args);
  putchar('\n');
}

/* ssl_sendv() writes what msgq_mapiov() maps: one line, always the same
 * buffer (a blocked SSL_write() must be retried with the same one). */
static char line[512];
static struct MsgQ mq;          /**< what ssl_sendv() is handed */

int msgq_mapiov(const struct MsgQ *mq, struct iovec *iov, int count,
                unsigned int *len)
{
  iov[0].iov_base = line;
  iov[0].iov_len = sizeof(line);
  *len += sizeof(line);
  return 1;
}

/* ---------- helpers ---------- */

/** Leave an unrelated error on the thread's OpenSSL error queue, as some
 * earlier OpenSSL user might have. */
static void stale_error(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  ERR_raise(ERR_LIB_EVP, EVP_R_BAD_DECRYPT);
#else
  ERR_put_error(ERR_LIB_EVP, 0, EVP_R_BAD_DECRYPT, __FILE__, __LINE__);
#endif
}

/** A self-signed certificate for the accepting side. */
static SSL_CTX *server_ctx_new(void)
{
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  EVP_PKEY *pkey = EVP_EC_gen("P-256");
  X509 *x = X509_new();

  if (!ctx || !pkey || !x)
    return NULL;
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), 0);
  X509_gmtime_adj(X509_getm_notAfter(x), 3600);
  X509_set_pubkey(x, pkey);
  X509_NAME_add_entry_by_txt(X509_get_subject_name(x), "CN", MBSTRING_ASC,
                             (const unsigned char *)"ssl-io-t", -1, -1, 0);
  X509_set_issuer_name(x, X509_get_subject_name(x));
  if (!X509_sign(x, pkey, EVP_sha256())
      || SSL_CTX_use_certificate(ctx, x) != 1
      || SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
    return NULL;
  X509_free(x);
  EVP_PKEY_free(pkey);
  return ctx;
}

/* The connecting side (a server link we open) and the accepting side
 * (the peer), each a Client with its Connection on one end of a
 * socketpair. */
static struct Client conn_cli, acc_cli;
static struct Connection conn_con, acc_con;
static struct ConfItem link_conf;

static int pair_new(void)
{
  int sv[2];

  memset(&conn_cli, 0, sizeof(conn_cli));
  memset(&acc_cli, 0, sizeof(acc_cli));
  memset(&conn_con, 0, sizeof(conn_con));
  memset(&acc_con, 0, sizeof(acc_con));
  cli_connect(&conn_cli) = &conn_con;
  cli_connect(&acc_cli) = &acc_con;
  ircd_strncpy(cli_name(&conn_cli), "hub.example", sizeof(cli_name(&conn_cli)));
  ircd_strncpy(cli_name(&acc_cli), "leaf.example", sizeof(cli_name(&acc_cli)));

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
    return -1;
  fcntl(sv[0], F_SETFL, O_NONBLOCK);
  fcntl(sv[1], F_SETFL, O_NONBLOCK);
  cli_socket(&conn_cli).s_fd = sv[0];
  cli_socket(&acc_cli).s_fd = sv[1];

  cli_socket(&acc_cli).ssl = SSL_new(ssl_server_ctx);
  SSL_set_fd(cli_socket(&acc_cli).ssl, sv[1]);
  ssl_set_nonblocking(cli_socket(&acc_cli).ssl);
  SetSSLNeedAccept(&acc_cli);
  return 0;
}

static void pair_free(void)
{
  if (cli_socket(&conn_cli).ssl)
    SSL_free(cli_socket(&conn_cli).ssl);
  if (cli_socket(&acc_cli).ssl)
    SSL_free(cli_socket(&acc_cli).ssl);
  cli_socket(&conn_cli).ssl = cli_socket(&acc_cli).ssl = NULL;
  close(cli_socket(&conn_cli).s_fd);
  close(cli_socket(&acc_cli).s_fd);
  ERR_clear_error();
}

/** Run both handshakes to completion, a stale error queued before every
 * step.  @return 1 when both sides finished. */
static int handshake(void)
{
  int c = 0, a = 1, i;

  for (i = 0; i < 50 && (c != 1 || a != -1); i++) {
    if (c != 1) {
      stale_error();
      c = ssl_connect(&cli_socket(&conn_cli), &link_conf);
      if (c < 0)
        return 0;
    }
    if (a != -1) {
      stale_error();
      a = ssl_accept(&acc_cli);
      if (a == 0)
        return 0;
    }
  }
  return c == 1 && a == -1;
}

/* ---------- tests ---------- */

int main(void)
{
  unsigned int in, out;
  char buf[4096];
  IOResult r;
  int i, n;

  signal(SIGPIPE, SIG_IGN);
  memset(line, 'x', sizeof(line));

  ssl_server_ctx = server_ctx_new();
  ssl_client_ctx = SSL_CTX_new(TLS_client_method());
  if (!ssl_server_ctx || !ssl_client_ctx) {
    printf("cannot set up the TLS contexts\n");
    return 1;
  }
  SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_NONE, NULL);

  /* 1. Both handshakes complete although a stale error sits on the queue
   * before every SSL_connect() and SSL_accept(). */
  if (pair_new() < 0) {
    printf("socketpair: %s\n", strerror(errno));
    return 1;
  }
  CHECK(handshake(), "handshakes complete with a stale error queued");

  /* 2. A write that blocks is a blocked write, not a failure.  Fill the
   * link (the peer reads nothing) until SSL_write() would block. */
  for (i = 0; i < 10000; i++) {
    ERR_clear_error();
    n = SSL_write(cli_socket(&conn_cli).ssl, line, sizeof(line));
    if (n <= 0)
      break;
  }
  CHECK(n <= 0 && SSL_get_error(cli_socket(&conn_cli).ssl, n)
                  == SSL_ERROR_WANT_WRITE,
        "the link fills up and SSL_write() would block");

  stale_error();
  notices = 0;
  r = ssl_sendv(&cli_socket(&conn_cli), &conn_cli, &mq, &in, &out);
  CHECK(r == IO_BLOCKED, "a blocked write with a stale error queued is IO_BLOCKED");
  CHECK(out == 0, "a blocked write wrote nothing");
  CHECK(notices == 0, "a blocked write sends no TLS error notice");

  /* 3. The peer reads the backlog; the retried write then goes out. */
  for (i = 0; i < 10000; i++) {
    r = ssl_recv(&cli_socket(&acc_cli), &acc_cli, buf, sizeof(buf), &in);
    if (r != IO_SUCCESS)
      break;
  }
  CHECK(r == IO_BLOCKED, "the peer reads the backlog, then would block");
  stale_error();
  r = ssl_sendv(&cli_socket(&conn_cli), &conn_cli, &mq, &in, &out);
  CHECK(r == IO_SUCCESS && out == sizeof(line), "the retried write goes out");

  /* 4. A read with nothing to read is a blocked read. */
  for (i = 0; i < 10000; i++)
    if (ssl_recv(&cli_socket(&acc_cli), &acc_cli, buf, sizeof(buf), &in) != IO_SUCCESS)
      break;
  stale_error();
  r = ssl_recv(&cli_socket(&acc_cli), &acc_cli, buf, sizeof(buf), &in);
  CHECK(r == IO_BLOCKED && in == 0, "a read with a stale error queued and nothing to read is IO_BLOCKED");

  /* 5. ssl_murder()'s unchecked write to a peer that is gone leaves
   * nothing queued. */
  close(cli_socket(&acc_cli).s_fd);
  cli_socket(&acc_cli).s_fd = -1;
  ERR_clear_error();
  ssl_murder(cli_socket(&conn_cli).ssl, cli_socket(&conn_cli).s_fd,
             "ERROR :Closing Link\r\n");
  cli_socket(&conn_cli).ssl = NULL;
  cli_socket(&conn_cli).s_fd = -1;
  CHECK(ERR_peek_error() == 0, "ssl_murder() leaves no error queued");
  pair_free();

  /* 6. A cipher list that selects nothing fails the connect and leaves no
   * error queued. */
  if (pair_new() < 0)
    return 1;
  link_conf.sslciphers = "NO-SUCH-CIPHER";
  ERR_clear_error();
  CHECK(ssl_connect(&cli_socket(&conn_cli), &link_conf) == -2,
        "a bad cipher list fails the connect");
  CHECK(ERR_peek_error() == 0, "a bad cipher list leaves no error queued");
  link_conf.sslciphers = NULL;
  pair_free();

  /* 7. A handshake the peer fails (plain text, not TLS) leaves no error
   * queued. */
  if (pair_new() < 0)
    return 1;
  n = write(cli_socket(&conn_cli).s_fd, "NICK plain\r\nUSER a b c d\r\n", 26);
  CHECK(n == 26, "plain text written to the TLS listener");
  ERR_clear_error();
  CHECK(ssl_accept(&acc_cli) == 0, "SSL_accept() of plain text fails");
  CHECK(ERR_peek_error() == 0, "a failed SSL_accept() leaves no error queued");
  pair_free();

  /* 8. Reporting an error reports it and empties the queue. */
  stale_error();
  stale_error();
  notices = 0;
  ssl_doerror(&conn_cli);
  CHECK(notices == 1, "ssl_doerror() sends one notice");
  CHECK(ERR_peek_error() == 0, "ssl_doerror() leaves no error queued");
  stale_error();
  stale_error();
  sslfail("test");
  CHECK(ERR_peek_error() == 0, "sslfail() leaves no error queued");

  SSL_CTX_free(ssl_server_ctx);
  SSL_CTX_free(ssl_client_ctx);
  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}

#else /* !USE_SSL */

int main(void)
{
  printf("0 checks, 0 failed (built without OpenSSL)\n");
  return 0;
}

#endif /* USE_SSL */
