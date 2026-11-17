/*
 * sethost_verify_cmocka.c - SETHOST's asynchronous password check
 *
 * m_sethost() / mo_sethost() hand a Spoofhost block's password check to
 * the thread pool and keep only the requested host, the password (hash)
 * checked against and a refind cookie (cli_checkcookie(), shared with
 * WEBIRC's check before registration); sethost_password_verified() runs a
 * loop pass or more later and judges the result by the configuration in
 * force then.
 *
 * This includes the real m_sethost.c, compiled with -ffunction-sections
 * and linked with --gc-sections; the conf lookups, the thread pool and the
 * replies are stubs.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../m_sethost.c"

/* ------------------------------------------------------------------ */
/* The ircd around SETHOST                                             */
/* ------------------------------------------------------------------ */

struct Client *LocalClientArray[MAXCONNECTIONS];
struct Client me;
int log_inassert;

void debug(int level, const char *form, ...) {}
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
int feature_bool(enum Feature feat) { return 1; }            /* FEAT_SETHOST */
int feature_int(enum Feature feat) { return 0; }
unsigned int ircrandom(void) { static unsigned int r = 40; return r += 2; }
int hide_hostmask(struct Client *cptr) { return 0; }
void bounce_emit_alias_update(struct Client *sptr, const char *what, const char *value) {}

/* s_bsd.c: the client's later lines, held while the check was out, are
 * parsed again once it answers. */
static struct Client *resumed;
void client_input_resume(struct Client *cptr) { resumed = cptr; }

static int umodes_sent;
void send_umode_out(struct Client *cptr, struct Client *sptr, struct Flags *old,
                    int prop) { umodes_sent++; }

/** Replies sent, by numeric (the last one). */
static int last_reply, replies;
int send_reply(struct Client *to, int reply, ...)
{
  last_reply = reply & ~SND_EXPLICIT;
  replies++;
  return 0;
}
int need_more_params(struct Client *cptr, const char *cmd)
{ fail_msg("need_more_params: %s", cmd); return 0; }

/* The thread pool: a submitted check is kept, and finishes when the case
 * says so. */
static int submitted;
static crypt_verify_callback pending_cb;
static void *pending_ctx;
int ircd_crypt_async_available(void) { return 1; }
int ircd_crypt_verify_async(const char *password, const char *hash,
                            crypt_verify_callback callback, void *ctx)
{
  submitted++;
  pending_cb = callback;
  pending_ctx = ctx;
  return 0;
}
static void finish_check(int result)
{
  crypt_verify_callback cb = pending_cb;

  assert_non_null(cb);
  pending_cb = NULL;
  cb(result, pending_ctx);
}

/* The Spoofhost blocks in force (a rehash replaces them). */
static struct SHostConf blocks[2];
static int nblocks;

struct SHostConf *find_shost_conf_by_host(struct Client *cptr, const char *host)
{
  int i;
  const char *h = strchr(host, '@') ? strchr(host, '@') + 1 : host;

  for (i = 0; i < nblocks; i++)
    if (!strcmp(blocks[i].spoofhost, h))
      return &blocks[i];
  return NULL;
}
struct SHostConf *find_shost_conf(struct Client *cptr, char *host, char *passwd,
                                  int *status)
{ fail_msg("synchronous check"); return NULL; }

static void add_block(char *host, char *passwd)
{
  memset(&blocks[nblocks], 0, sizeof(blocks[nblocks]));
  blocks[nblocks].spoofhost = host;
  blocks[nblocks].passwd = passwd;
  nblocks++;
}

/* ------------------------------------------------------------------ */
/* A registered local client                                           */
/* ------------------------------------------------------------------ */

static struct Client client, other;
static struct Connection con, other_con;
static struct User user, other_user;

static void make_client(struct Client *c, struct Connection *cn, struct User *u,
                        int fd)
{
  memset(c, 0, sizeof(*c));
  memset(cn, 0, sizeof(*cn));
  memset(u, 0, sizeof(*u));
  cli_connect(c) = cn;
  con_client(cn) = c;
  s_fd(&con_socket(cn)) = fd;
  cli_user(c) = u;
  cli_status(c) = STAT_USER;
  ircd_strncpy(u->username, "user", sizeof(u->username));
  ircd_strncpy(cli_name(c), "nick", sizeof(cli_name(c)));
  LocalClientArray[fd] = c;
}

static int setup(void **state)
{
  (void)state;
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  make_client(&client, &con, &user, 7);
  nblocks = 0;
  submitted = replies = last_reply = umodes_sent = 0;
  pending_cb = NULL;
  resumed = NULL;
  return 0;
}

static int sethost(char *host, char *pass)
{
  char *parv[] = { "nick", host, pass, NULL };
  return m_sethost(&client, &client, 3, parv);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

/** The block unchanged: the host is applied when the check finishes. */
static void unchanged_block_applies(void **state)
{
  add_block("spoof.example", "$X$pw");
  sethost("spoof.example", "pw");
  assert_int_equal(submitted, 1);
  assert_true(IsSetHostPending(&client));
  assert_int_not_equal(cli_checkcookie(&client), 0);
  assert_null(resumed);
  finish_check(CRYPT_VERIFY_MATCH);
  assert_false(IsSetHostPending(&client));
  assert_int_equal(cli_checkcookie(&client), 0);
  assert_ptr_equal(resumed, &client);       /* answered: input resumes */
  assert_true(IsSetHost(&client));
  assert_string_equal(user.sethost, "user@spoof.example");
}

/** The rehash removed the block: no host (ERR_HOSTUNAVAIL). */
static void removed_block_refused(void **state)
{
  add_block("spoof.example", "$X$pw");
  sethost("spoof.example", "pw");
  nblocks = 0;
  finish_check(CRYPT_VERIFY_MATCH);
  assert_false(IsSetHost(&client));
  assert_int_equal(last_reply, ERR_HOSTUNAVAIL);
  assert_false(IsSetHostPending(&client));
}

/** The rehash changed the block's password: the old one does not give the
 * host (ERR_PASSWDMISMATCH). */
static void changed_password_refused(void **state)
{
  add_block("spoof.example", "$X$pw");
  sethost("spoof.example", "pw");
  blocks[0].passwd = "$X$new";
  finish_check(CRYPT_VERIFY_MATCH);
  assert_false(IsSetHost(&client));
  assert_int_equal(last_reply, ERR_PASSWDMISMATCH);
  assert_ptr_equal(resumed, &client);
}

/** The descriptor now belongs to another connection (the client left, or a
 * bouncer hold moved the session and cleared the check): its result goes
 * to nobody. */
static void another_connection_gets_nothing(void **state)
{
  add_block("spoof.example", "$X$pw");
  sethost("spoof.example", "pw");
  make_client(&other, &other_con, &other_user, 7);   /* same descriptor */
  finish_check(CRYPT_VERIFY_MATCH);
  assert_false(IsSetHost(&other));
  assert_int_equal(replies, 0);
  assert_null(resumed);
}

/** A WEBIRC check still out holds the shared cookie: SETHOST is refused,
 * nothing is submitted and the cookie is the WEBIRC check's still. */
static void refused_while_webirc_check_pending(void **state)
{
  char *parv[] = { "nick", "u", "spoof.example", "pw", NULL };

  add_block("spoof.example", "$X$pw");
  SetWebIRCPending(&client);
  cli_checkcookie(&client) = 99;
  sethost("spoof.example", "pw");
  mo_sethost(&client, &client, 4, parv);
  assert_int_equal(submitted, 0);
  assert_false(IsSetHostPending(&client));
  assert_int_equal(cli_checkcookie(&client), 99);
  assert_true(IsWebIRCPending(&client));
}

/** The oper form's user@host, as long as mo_sethost() takes it (a whole
 * USERLEN user and a host near HOSTLEN, past HOSTLEN together): applied
 * whole when the check finishes, as the synchronous path applies it. */
static void long_user_at_host_applied_whole(void **state)
{
  char host[HOSTLEN + 1], want[USERLEN + HOSTLEN + 2];
  char *parv[] = { "nick", "abcdefghij", host, "pw", NULL };

  memset(host, 'h', HOSTLEN - 10);
  strcpy(host + HOSTLEN - 10, ".example");   /* HOSTLEN - 2 */
  add_block(host, "$X$pw");
  snprintf(want, sizeof(want), "abcdefghij@%s", host);
  assert_true(strlen(want) > HOSTLEN);
  mo_sethost(&client, &client, 4, parv);
  assert_int_equal(submitted, 1);
  finish_check(CRYPT_VERIFY_MATCH);
  assert_string_equal(user.sethost, want);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(unchanged_block_applies, setup),
    cmocka_unit_test_setup(removed_block_refused, setup),
    cmocka_unit_test_setup(changed_password_refused, setup),
    cmocka_unit_test_setup(another_connection_gets_nothing, setup),
    cmocka_unit_test_setup(refused_while_webirc_check_pending, setup),
    cmocka_unit_test_setup(long_user_at_host_applied_whole, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
