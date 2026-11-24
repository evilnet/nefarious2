/*
 * oper_verify_cmocka.c - an OPER whose password check finishes after a
 * REHASH is judged by the configuration in force then
 *
 * can_oper() hands the password check to the thread pool and keeps only
 * the Operator block's name and the password (hash) it checked against;
 * oper_password_verified() runs a loop pass or more later -- after a
 * REHASH that may have freed the block -- and asks oper_live_block() for
 * the block the live configuration gives the client: found by name and
 * host again, with the same password and the client's SSL fingerprint.
 *
 * This includes the real m_oper.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps oper_live_block(), the
 * completion (oper_password_verified()) and what they call;
 * find_conf_exact() and verify_sslclifp() are stubs over a list of blocks
 * the test builds as a configuration pass would, and what do_oper() and
 * the labeled-response answer reach is stubbed (do_oper() itself is real:
 * a granted OPER is seen as the client's opername).
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../m_oper.c"

/* ------------------------------------------------------------------ */
/* The configuration in force                                          */
/* ------------------------------------------------------------------ */

/** The live Operator blocks (a rehash replaces them all). */
static struct ConfItem blocks[4];
static int nblocks;
/** The host each block admits ("*" for any). */
static const char *block_host[4];
/** The SSL fingerprint each block requires ("" for none). */
static const char *block_fp[4];

static const char *client_host;
static const char *client_fp;

struct ConfItem *find_conf_exact(const char *name, struct Client *cptr,
                                 int statmask)
{
  int i;

  (void)cptr;
  assert_int_equal(CONF_OPERATOR, statmask);
  for (i = 0; i < nblocks; i++)
    if (!strcmp(blocks[i].name, name)
        && (!strcmp(block_host[i], "*") || !strcmp(block_host[i], client_host)))
      return &blocks[i];
  return NULL;
}

int verify_sslclifp(struct Client *cptr, struct ConfItem *aconf)
{
  (void)cptr;
  return !*block_fp[aconf - blocks] || !strcmp(block_fp[aconf - blocks], client_fp);
}

/** The blocks' connection class (do_oper() reads its defaults). */
static struct ConnectionClass oper_class;

static void add_block(const char *name, const char *passwd, const char *host,
                      const char *fp)
{
  memset(&blocks[nblocks], 0, sizeof(blocks[nblocks]));
  blocks[nblocks].conn_class = &oper_class;
  blocks[nblocks].status = CONF_OPERATOR;
  blocks[nblocks].name = (char *) name;
  blocks[nblocks].passwd = (char *) passwd;
  block_host[nblocks] = host;
  block_fp[nblocks] = fp;
  nblocks++;
}

/* ------------------------------------------------------------------ */
/* What the completion reaches                                         */
/* ------------------------------------------------------------------ */

struct Client *LocalClientArray[MAXCONNECTIONS];
struct Client me;
int log_inassert;

static int last_reply, attaches;
static char last_sno[512];
static struct ConfItem *attached;

void debug(int level, const char *form, ...) {}

/* s_bsd.c: the client's later lines, held while the check was out, are
 * parsed again once it answers. */
static struct Client *resumed;
void client_input_resume(struct Client *cptr) { resumed = cptr; }
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
int send_reply(struct Client *to, int reply, ...)
{
  last_reply = reply & ~SND_EXPLICIT;
  return 0;
}
void sendto_opmask_butone_global(struct Client *one, unsigned int mask,
                                 const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  vsnprintf(last_sno, sizeof(last_sno), pattern, vl);
  va_end(vl);
}
enum AuthorizationCheckResult attach_conf(struct Client *cptr, struct ConfItem *aconf)
{
  attaches++;
  attached = aconf;
  return ACR_OK;
}
void batch_save(struct Client *cptr, struct BatchSave *save) {}
void batch_restore(struct Client *cptr, const struct BatchSave *save) {}
int labeled_batch_start(struct Client *cptr) { return 0; }
void labeled_batch_end(struct Client *cptr) {}
void send_labeled_ack(struct Client *cptr) {}
/* do_oper() */
void client_set_privs(struct Client *client, struct ConfItem *oper) {}
void client_send_privs(struct Client *from, struct Client *to,
                       struct Client *client) {}
void client_sendtoserv_privs(struct Client *client) {}
int feature_int(enum Feature feat) { return 0; }
int feature_bool(enum Feature feat) { return 0; }
void userstats_count_sync(struct Client *cptr) {}
void set_snomask(struct Client *cptr, unsigned int newmask, int what) {}
void send_umode_out(struct Client *cptr, struct Client *sptr,
                    struct Flags *old, int prop) {}
void send_umode(struct Client *cptr, struct Client *sptr, struct Flags *old,
                int sendset) {}
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc,
                  char *parv[], int allow_modes) { return 0; }
struct BouncerSession *bounce_get_session(struct Client *cptr) { return NULL; }
void bounce_sync_session_umodes(struct Client *cptr, const struct Flags *old,
                                struct Client *origin) {}
int hide_hostmask(struct Client *cptr) { return 0; }
time_t CurrentTime;
void bounce_broadcast(struct BouncerSession *session, char subcmd,
                      const char *extra) {}
void bounce_mark_dirty(struct Client *cptr) {}
int m_join(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{ return 0; }
int m_opermotd(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{ return 0; }
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...) {}
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...) {}

static struct Client client;
static struct Connection con;
static struct User user;

/** A registered local client with an OPER check out for "op" against
 * "$X$old": its context, as can_oper() makes it. */
static struct oper_verify_ctx *pending_oper(int fd)
{
  struct oper_verify_ctx *ctx = calloc(1, sizeof(*ctx));

  memset(&con, 0, sizeof(con));
  memset(&user, 0, sizeof(user));
  cli_connect(&client) = &con;
  cli_from(&client) = &client;
  con_client(&con) = &client;
  s_fd(&con_socket(&con)) = fd;
  cli_user(&client) = &user;
  cli_status(&client) = STAT_USER;
  ircd_strncpy(cli_name(&client), "nick", sizeof(cli_name(&client)));
  LocalClientArray[fd] = &client;
  SetOperPending(&client);
  cli_opercookie(&client) = 77;
  ctx->fd = fd;
  ctx->cookie = 77;
  ctx->name = strdup("op");
  ctx->passwd = strdup("$X$old");
  return ctx;
}

static int setup(void **state)
{
  (void)state;
  memset(&client, 0, sizeof(client));
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  last_reply = attaches = 0;
  resumed = NULL;
  last_sno[0] = '\0';
  attached = NULL;
  nblocks = 0;
  client_host = "10.0.0.1";
  client_fp = "";
  return 0;
}

/* ------------------------------------------------------------------ */
/* Cases: the check was made against "op" with password "$X$old"       */
/* ------------------------------------------------------------------ */

/** Nothing changed (or the block was replaced by an identical one): the
 * live block, not the one the check started with. */
static void unchanged_block_is_the_live_one(void **state)
{
  const char *why = "";

  (void)state;
  add_block("other", "$X$old", "*", "");
  add_block("op", "$X$old", "*", "");
  assert_ptr_equal(&blocks[1], oper_live_block(&client, "op", "$X$old", &why));
}

/** The rehash removed the block: no oper. */
static void removed_block_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("other", "$X$old", "*", "");
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("no operator block", why);
}

/** Retired (flagged illegal, still held by someone): no oper. */
static void illegal_block_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$old", "*", "");
  blocks[0].status |= CONF_ILLEGAL;
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("no operator block", why);
}

/** Its password changed: the old one does not grant oper. */
static void changed_password_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$new", "*", "");
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("password mis-match", why);
}

/** It no longer admits the client's host. */
static void narrowed_host_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$old", "10.9.9.9", "");
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("no operator block", why);
}

/** It now requires an SSL fingerprint the client does not have. */
static void new_fingerprint_fails(void **state)
{
  const char *why = "";

  (void)state;
  add_block("op", "$X$old", "*", "AB:CD");
  client_fp = "EF:01";
  assert_null(oper_live_block(&client, "op", "$X$old", &why));
  assert_string_equal("SSL fingerprint mismatch", why);
}

/* ------------------------------------------------------------------ */
/* The completion: oper_password_verified()                            */
/* ------------------------------------------------------------------ */

/** The block in force: the live one is attached and granted. */
static void completion_grants_the_live_block(void **state)
{
  add_block("op", "$X$old", "*", "");
  oper_password_verified(CRYPT_VERIFY_MATCH, pending_oper(5));
  assert_int_equal(attaches, 1);
  assert_ptr_equal(attached, &blocks[0]);
  assert_string_equal(user.opername, "op");
  assert_false(IsOperPending(&client));
  assert_int_equal(cli_opercookie(&client), 0);
  assert_ptr_equal(resumed, &client);       /* answered: input resumes */
  free(user.opername);
}

/** The block now requires a fingerprint the client lacks: the answer is
 * the synchronous path's, ERR_SSLCLIFP, and the notice says when it was
 * found, naming no rehash. */
static void completion_fingerprint_answers_sslclifp(void **state)
{
  add_block("op", "$X$old", "*", "AB:CD");
  client_fp = "EF:01";
  oper_password_verified(CRYPT_VERIFY_MATCH, pending_oper(5));
  assert_int_equal(attaches, 0);
  assert_int_equal(last_reply, ERR_SSLCLIFP);
  assert_non_null(strstr(last_sno, "(SSL fingerprint mismatch when the password check finished)"));
  assert_null(strstr(last_sno, "rehash"));
}

/** No block for the client now (a rehash removed it, its class filled):
 * ERR_NOOPERHOST. */
static void completion_without_block_answers_nooperhost(void **state)
{
  oper_password_verified(CRYPT_VERIFY_MATCH, pending_oper(5));
  assert_int_equal(attaches, 0);
  assert_int_equal(last_reply, ERR_NOOPERHOST);
  assert_ptr_equal(resumed, &client);       /* answered: input resumes */
  assert_non_null(strstr(last_sno, "(no operator block when the password check finished)"));
}

/** Its password changed: ERR_PASSWDMISMATCH. */
static void completion_changed_password_answers_passwdmismatch(void **state)
{
  add_block("op", "$X$new", "*", "");
  oper_password_verified(CRYPT_VERIFY_MATCH, pending_oper(5));
  assert_int_equal(attaches, 0);
  assert_int_equal(last_reply, ERR_PASSWDMISMATCH);
  assert_ptr_equal(resumed, &client);
}

/** The descriptor is another connection's now (its own cookie, or none):
 * the result goes to nobody. */
static void completion_for_another_connection_does_nothing(void **state)
{
  struct oper_verify_ctx *ctx;

  add_block("op", "$X$old", "*", "");
  ctx = pending_oper(5);
  cli_opercookie(&client) = 78;             /* another check's */
  oper_password_verified(CRYPT_VERIFY_MATCH, ctx);
  assert_int_equal(attaches, 0);
  assert_int_equal(last_reply, 0);
  assert_true(IsOperPending(&client));
  assert_null(resumed);                     /* still waiting on its own */
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(unchanged_block_is_the_live_one, setup),
    cmocka_unit_test_setup(removed_block_fails, setup),
    cmocka_unit_test_setup(illegal_block_fails, setup),
    cmocka_unit_test_setup(changed_password_fails, setup),
    cmocka_unit_test_setup(narrowed_host_fails, setup),
    cmocka_unit_test_setup(new_fingerprint_fails, setup),
    cmocka_unit_test_setup(completion_grants_the_live_block, setup),
    cmocka_unit_test_setup(completion_fingerprint_answers_sslclifp, setup),
    cmocka_unit_test_setup(completion_without_block_answers_nooperhost, setup),
    cmocka_unit_test_setup(completion_changed_password_answers_passwdmismatch, setup),
    cmocka_unit_test_setup(completion_for_another_connection_does_nothing, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
