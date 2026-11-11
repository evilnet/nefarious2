/*
 * services_reply_cmocka.c - what a services reply does to the local
 * client it names.
 *
 * A login-on-connect reply names its client with a request id
 * ".<fd>.<cookie>" (decode_auth_id(), m_account.c).  It arrives from
 * another server, so it is matched against this server's own state only.
 *
 * The REAL m_account.o is linked, with numnicks.o and the ircd's printf;
 * everything it calls besides the lookup is stubbed below, and the stubs
 * that act on a client record what they did.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numnicks.h"
#include "s_auth.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

/* ====================================================================
 * Globals the linked objects expect
 * ==================================================================== */

struct Client me;
time_t CurrentTime = 1000000;
time_t TSoffset;
int log_inassert;

/* The handlers see s_bsd.h's LocalClientArray[MAXCONNECTIONS].  Two more
 * slots here, each holding a client whose cookies match anything, so that
 * a lookup past the declared end finds a client and fails a check
 * instead of depending on what the linker put next (s_bsd.h is not
 * included for that reason). */
struct Client *LocalClientArray[MAXCONNECTIONS + 2];

/* ====================================================================
 * What the code under test did
 * ==================================================================== */

#define LINE 700
#define MAXREC 64

static struct Client *told[MAXREC];     /* clients sent a line */
static int ntold;
static int violations;
static int set_accounts;                /* auth_set_account() calls */
static int auth_result;                 /* what it returns */

static void tell(struct Client *to)
{
  assert_true(ntold < MAXREC);
  told[ntold++] = to;
}

static int was_told(struct Client *c)
{
  int i;
  for (i = 0; i < ntold; i++)
    if (told[i] == c)
      return 1;
  return 0;
}

/* ====================================================================
 * The fake network
 * ==================================================================== */

#define MAXOBJ 64
static struct Client *made[MAXOBJ];
static int nmade;
static struct Connection me_con;
static struct Server me_serv;
static char auth_storage[MAXOBJ][64];   /* stand-ins for AuthRequests */

static struct Client *fake_client(const char *name, int status)
{
  struct Client *c = calloc(1, sizeof(*c));

  assert_non_null(c);
  assert_true(nmade < MAXOBJ);
  made[nmade++] = c;
  ircd_strncpy(cli_name(c), name, sizeof(c->cli_name));
  cli_status(c) = status;
  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  return c;
}

/** A services server linked to this one. */
static struct Client *services_link(void)
{
  struct Client *c = fake_client("x3.test", STAT_SERVER);

  cli_serv(c) = calloc(1, sizeof(struct Server));
  assert_non_null(cli_serv(c));
  SetServerYXX(c, c, "AE]]]");
  SetService(c);
  cli_serv(c)->up = &me;
  return c;
}

/** One of our connections, on @a fd: a client still registering (with a
 * User, an AuthRequest) when @a registering. */
static struct Client *local_client(const char *name, int fd, int registering)
{
  struct Client *c = fake_client(name, registering ? STAT_UNKNOWN_USER
                                                   : STAT_USER);

  cli_user(c) = calloc(1, sizeof(struct User));
  assert_non_null(cli_user(c));
  cli_user(c)->server = &me;
  cli_fd(c) = fd;
  if (registering)
    cli_auth(c) = (struct AuthRequest *)auth_storage[nmade];
  LocalClientArray[fd] = c;
  return c;
}

/** Give @a c a login-on-connect request for @a account with @a cookie
 * (0: PASS seen, the request not sent yet). */
static void loc_request(struct Client *c, const char *account,
                        unsigned int cookie)
{
  cli_loc(c) = MyCalloc(1, sizeof(struct LOCInfo));
  cli_loc(c)->cookie = cookie;
  ircd_strncpy(cli_loc(c)->account, account, sizeof(cli_loc(c)->account));
  ircd_strncpy(cli_loc(c)->password, "secret", sizeof(cli_loc(c)->password));
}

/* --- delivering a line, split as parse_server() splits it --- */

#define MAXARGS (MAXPARA + 2)

static int deliver(int (*handler)(struct Client *, struct Client *, int, char *[]),
                   struct Client *link, struct Client *source,
                   const char *fmt, ...)
{
  static char buf[LINE];
  char *parv[MAXARGS], *line = buf;
  va_list vl;
  int parc = 1;

  va_start(vl, fmt);
  vsnprintf(buf, sizeof(buf), fmt, vl);
  va_end(vl);
  parv[0] = cli_name(source);
  while (*line && parc < MAXARGS - 1) {
    while (*line == ' ')
      line++;
    if (!*line)
      break;
    if (*line == ':') {
      parv[parc++] = line + 1;
      break;
    }
    parv[parc++] = line;
    while (*line && *line != ' ')
      line++;
    if (*line)
      *line++ = '\0';
  }
  parv[parc] = NULL;
  return handler(link, source, parc, parv);
}

static int world_setup(void **state)
{
  (void)state;

  ntold = violations = set_accounts = nmade = 0;
  auth_result = 0;
  memset(LocalClientArray, 0, sizeof(LocalClientArray));

  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  memset(&me_serv, 0, sizeof(me_serv));
  ircd_strncpy(cli_name(&me), "hub.test", sizeof(me.cli_name));
  cli_status(&me) = STAT_ME;
  cli_connect(&me) = &me_con;
  con_client(&me_con) = &me;
  cli_serv(&me) = &me_serv;
  SetServerYXX(&me, &me, "AB]]]");
  CurrentTime = 1000000;
  return 0;
}

static int world_teardown(void **state)
{
  int i;
  (void)state;

  for (i = 0; i < nmade; i++)
    if (cli_serv(made[i]))
      ClearServerYXX(made[i]);
  ClearServerYXX(&me);
  return 0;
}

/* ====================================================================
 * Stubs
 * ==================================================================== */

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{
  (void)cptr; (void)victim; (void)killer; (void)comment;
  fail_msg("exit_client() called");
  return 0;
}

int feature_bool(enum Feature feat)
{
  return feat == FEAT_EXTENDED_ACCOUNTS;
}

int feature_int(enum Feature feat)
{
  (void)feat;
  return 0;
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  (void)cptr; (void)pattern;
  violations++;
  return 0;
}

int need_more_params(struct Client *cptr, const char *cmd)
{
  (void)cptr; (void)cmd;
  return 0;
}

void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  (void)pattern;
  tell(to);
}

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)pattern;
  tell(to);
}

void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)one; (void)pattern;
}

void sendcmdto_common_channels_capab_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Client *one, int withcap,
                                            int skipcap,
                                            const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)one; (void)withcap; (void)skipcap;
  (void)pattern;
}

void sendcmdto_set_client_msgid(const char *msgid)
{
  (void)msgid;
}

void sendcmdto_set_s2s_tags(uint64_t time_ms, const char *msgid)
{
  (void)time_ms; (void)msgid;
}

void sendcmdto_want_s2s_tags(int want)
{
  (void)want;
}

char *generate_msgid(char *buf, size_t buflen)
{
  ircd_strncpy(buf, "ABAAAAAAAAAAAB", buflen);
  return buf;
}

int rename_services_ac(struct Client *cptr, struct Client *sptr, int parc,
                       char *parv[])
{
  (void)cptr; (void)sptr; (void)parc; (void)parv;
  return 0;
}

int hide_hostmask(struct Client *cptr)
{
  (void)cptr;
  return 0;
}

void metadata_load_account(struct Client *cptr, const char *account)
{
  (void)cptr; (void)account;
}

void metadata_mode_sync_restore(struct Client *cptr, int live)
{
  (void)cptr; (void)live;
}

int account_id_valid(const char *id)
{
  (void)id;
  return 0;
}

void channel_account_adjust(struct Client *cptr, int delta)
{
  (void)cptr; (void)delta;
}

void presence_anchor_transfer(struct Client *cptr, const char *old_anchor,
                              int old_is_session, const char *new_anchor,
                              int new_is_session)
{
  (void)cptr; (void)old_anchor; (void)old_is_session; (void)new_anchor;
  (void)new_is_session;
}

void bounce_emit_alias_update(struct Client *primary, const char *field,
                              const char *value)
{
  (void)primary; (void)field; (void)value;
}

void bounce_sync_alias_identity(struct Client *primary)
{
  (void)primary;
}

int bounce_account_deauth_apply(struct Client *acptr)
{
  (void)acptr;
  return 0;
}

/* The registration a login-on-connect answer lets go on: it may exit the
 * client (no I:line, a K-line) or swap it for a held bouncer session; the
 * test says which by auth_result. */
int auth_set_account(struct AuthRequest *auth, const char *account)
{
  (void)auth; (void)account;
  set_accounts++;
  return auth_result;
}

void auth_end_loc(struct AuthRequest *auth)
{
  (void)auth;
}

/* ====================================================================
 * ACCOUNT A / D: the login-on-connect reply
 * ==================================================================== */

/* Services accept a login-on-connect request, and registration then goes
 * on inside ms_account().  When it exits the client (or a bouncer revive
 * frees it), auth_set_account() answers CPTR_KILLED: about the CLIENT.
 * The handler returned it for cptr, the services link, and the parser
 * dropped the rest of what it had read from that link. */
static void test_loc_accept_returns_0_for_the_link(void **state)
{
  struct Client *svs, *c;
  int ret;
  (void)state;

  svs = services_link();
  c = local_client("joiner", 7, 1);
  loc_request(c, "alice", 77);
  auth_result = CPTR_KILLED;

  ret = deliver(ms_account, svs, svs, "AB A .7.77 1700000000");

  assert_int_equal(ret, 0);
  assert_int_equal(set_accounts, 1);
}

/* The client it was for: logged in, its request over. */
static void test_loc_accept_logs_in(void **state)
{
  struct Client *svs, *c;
  int ret;
  (void)state;

  svs = services_link();
  c = local_client("joiner", 7, 1);
  loc_request(c, "alice", 77);

  ret = deliver(ms_account, svs, svs, "AB A .7.77 1700000000");

  assert_int_equal(ret, 0);
  assert_true(IsAccount(c));
  assert_string_equal(cli_user(c)->account, "alice");
  assert_null(cli_loc(c));
  assert_true(was_told(c));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
#define T(f) cmocka_unit_test_setup_teardown(f, world_setup, world_teardown)
    T(test_loc_accept_returns_0_for_the_link),
    T(test_loc_accept_logs_in),
#undef T
  };

  return cmocka_run_group_tests_name("services_reply", tests, NULL, NULL);
}
