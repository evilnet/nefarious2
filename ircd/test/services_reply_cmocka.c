/*
 * services_reply_cmocka.c - what a services reply does to the local
 * client it names.
 *
 * A SASL reply names its client with a token "<server>!<fd>.<cookie>"
 * (ms_sasl(), m_sasl.c), a login-on-connect reply with a request id
 * ".<fd>.<cookie>" (decode_auth_id(), m_account.c).  Both arrive from
 * another server, so the fd may be any number, and only a cookie this
 * server issued to a client with a request in flight may match: never 0,
 * which is what a client with nothing in flight has.
 *
 * The REAL m_account.o and m_sasl.o are linked, with numnicks.o and the
 * ircd's printf;
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
#include "numeric.h"
#include "numnicks.h"
#include "s_auth.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "sasl_auth.h"
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
static struct Client *logged_in[MAXREC];   /* sasl_complete_login() */
static char logged_as[MAXREC][ACCOUNTLEN + 1];
static time_t logged_ts[MAXREC];
static int nlogins;
static int sasl_dones;                  /* auth_sasl_done() calls */
static int auth_result;                 /* what it returns */
/* The last RPL_SASLMECHS (908) sent, and its mechanism list. */
static struct Client *mechs_to;
static char mechs_sent[128];
/* The sasl capability's value (m_cap.c); NULL: none. */
static const char *cap_mechs;
static int refusals;                    /* sasl_reauth_refused() said so */

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

/** A connection on a server port that has sent PASS but nothing else:
 * no User yet (and none until it registers as a server). */
static struct Client *server_port_client(int fd)
{
  struct Client *c = fake_client("", STAT_UNKNOWN_SERVER);

  cli_fd(c) = fd;
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

  ntold = violations = set_accounts = nmade = nlogins = sasl_dones = 0;
  mechs_to = NULL;
  mechs_sent[0] = '\0';
  cap_mechs = NULL;
  refusals = 0;
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
  return feat == FEAT_SASL_TIMEOUT ? 10 : 0;
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

const char *cap_sasl_mechanisms(void)
{
  return cap_mechs;
}

int send_reply(struct Client *to, int reply, ...)
{
  tell(to);
  if (reply == ERR_SASLMECHS) {
    va_list vl;
    va_start(vl, reply);
    ircd_strncpy(mechs_sent, va_arg(vl, const char *), sizeof(mechs_sent));
    va_end(vl);
    mechs_to = to;
  }
  return 0;
}

const char *feature_str(enum Feature feat)
{
  return feat == FEAT_SASL_SERVER ? "*" : "";
}

void timer_del(struct Timer *timer)
{
  (void)timer;
}

/* The login the relay path ends in: whom, as what. */
int sasl_complete_login(struct Client *sptr, const char *account,
                        time_t acc_create, const char *kc_id, int id_live)
{
  (void)kc_id; (void)id_live;
  assert_true(nlogins < MAXREC);
  logged_in[nlogins] = sptr;
  logged_ts[nlogins] = acc_create;
  ircd_strncpy(logged_as[nlogins], account, sizeof(logged_as[nlogins]));
  nlogins++;
  return 0;
}

/* The identity a services L reply names, written as a whole (the real one
 * is in sasl_auth.c, which this suite does not link). */
void sasl_identity_set(struct Client *cptr, const char *account,
                       time_t acc_create, const char *kc_id, int id_live)
{
  ircd_strncpy(cli_saslaccount(cptr), account ? account : "", ACCOUNTLEN + 1);
  cli_saslacccreate(cptr) = acc_create;
  ircd_strncpy(cli_saslkcid(cptr), kc_id ? kc_id : "",
               sizeof(cli_saslkcid(cptr)));
  cli_saslkcidlive(cptr) = id_live;
}

/* The account rule's verdict (sasl_auth.c, not linked; its own cases are
 * in sasl_handler_cmocka): a client the ircd has logged in to an account
 * may not be logged in to another.  The real one also tells the client and
 * the log; the exchange is the caller's to end. */
int sasl_reauth_refused(struct Client *sptr, const char *account,
                        const char *kc_id)
{
  (void)kc_id;
  if (!IsAccount(sptr) || cli_auth(sptr)
      || 0 == ircd_strcmp(cli_user(sptr)->account, account))
    return 0;
  refusals++;
  tell(sptr);
  return 1;
}

int auth_sasl_done(struct AuthRequest *auth)
{
  (void)auth;
  sasl_dones++;
  return 0;
}

void auth_sasl_clear(struct AuthRequest *auth)
{
  (void)auth;
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

/* ====================================================================
 * SASL: which client a reply reaches
 * ==================================================================== */

/** Was @a c reached by any of the three replies a peer could forge: C (an
 * AUTHENTICATE line down its connection), L + D S (a login), D F (a
 * failure, which also lets registration go on)? */
static int forged_sasl_reaches(struct Client *svs, const char *token)
{
  deliver(ms_sasl, svs, svs, "AB %s C :Zm9yZ2Vk", token);
  deliver(ms_sasl, svs, svs, "AB %s L victim", token);
  deliver(ms_sasl, svs, svs, "AB %s D S", token);
  deliver(ms_sasl, svs, svs, "AB %s D F", token);
  return ntold > 0 || nlogins > 0 || sasl_dones > 0;
}

/* A client that never started SASL has cookie 0: so did every reply
 * naming its fd with cookie 0. */
static void test_sasl_cookie_0_idle_client(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);

  assert_false(forged_sasl_reaches(svs, "AB!7.0"));
  assert_false(was_told(c));
  assert_null(cli_saslagent(c));
}

/* ... a registered user (cookie 0 again once its own exchange is over) ... */
static void test_sasl_cookie_0_registered_user(void **state)
{
  struct Client *svs;
  (void)state;
  svs = services_link();
  local_client("alice", 8, 0);

  assert_false(forged_sasl_reaches(svs, "AB!8.0"));
}

/* ... another server's link, which got "AUTHENTICATE <data>" ... */
static void test_sasl_cookie_0_server_link(void **state)
{
  struct Client *svs, *leaf;
  (void)state;
  svs = services_link();
  leaf = fake_client("leafa.test", STAT_SERVER);
  cli_fd(leaf) = 9;
  LocalClientArray[9] = leaf;

  assert_false(forged_sasl_reaches(svs, "AB!9.0"));
  assert_false(was_told(leaf));
}

/* ... a connection on a server port ... */
static void test_sasl_cookie_0_server_port(void **state)
{
  struct Client *svs;
  (void)state;
  svs = services_link();
  server_port_client(10);

  assert_false(forged_sasl_reaches(svs, "AB!10.0"));
}

/* ... and anything atoi() reads as 0. */
static void test_sasl_cookie_reading_as_0(void **state)
{
  struct Client *svs;
  (void)state;
  svs = services_link();
  local_client("joiner", 7, 1);

  assert_false(forged_sasl_reaches(svs, "AB!7.00"));
  assert_false(forged_sasl_reaches(svs, "AB!7.x"));
  assert_false(forged_sasl_reaches(svs, "AB!7."));
}

/* A client in a LOCAL (Keycloak) exchange has a cookie that never goes on
 * the wire, never 0: a relay reply cannot reach the exchange. */
static void test_sasl_local_exchange_unreachable(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslsession(c) = (struct SASLSession *)auth_storage[0];
  cli_saslcookie(c) = 0x1234567;
  cli_saslstart(c) = CurrentTime;

  assert_false(forged_sasl_reaches(svs, "AB!7.0"));
  assert_int_equal(cli_saslcookie(c), 0x1234567);
}

/* The fd is looked up only inside LocalClientArray: the two slots past
 * its end hold clients whose cookie matches, and are never reached. */
static void test_sasl_fd_past_the_end(void **state)
{
  struct Client *svs, *past, *past2;
  char token[64];
  (void)state;
  svs = services_link();
  past = fake_client("past", STAT_USER);
  past2 = fake_client("past2", STAT_USER);
  cli_saslcookie(past) = cli_saslcookie(past2) = 5;
  LocalClientArray[MAXCONNECTIONS] = past;
  LocalClientArray[MAXCONNECTIONS + 1] = past2;

  snprintf(token, sizeof(token), "AB!%d.5", MAXCONNECTIONS);
  assert_false(forged_sasl_reaches(svs, token));
  snprintf(token, sizeof(token), "AB!%d.5", MAXCONNECTIONS + 1);
  assert_false(forged_sasl_reaches(svs, token));
  assert_false(forged_sasl_reaches(svs, "AB!-1.5"));
  assert_false(forged_sasl_reaches(svs, "AB!4294967295.5"));
}

/* The exchange this server started (cookie 777 on fd 7) still works:
 * the challenge reaches the client, L and D S log it in, and the server
 * that answered becomes its agent. */
static void test_sasl_legitimate_exchange(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;

  deliver(ms_sasl, svs, svs, "AB AB!7.777 C :+");
  assert_true(was_told(c));
  assert_ptr_equal(cli_saslagent(c), svs);
  deliver(ms_sasl, svs, svs, "AB AB!7.777 L alice 1700000000");
  deliver(ms_sasl, svs, svs, "AB AB!7.777 D S");
  assert_int_equal(nlogins, 1);
  assert_ptr_equal(logged_in[0], c);
  assert_string_equal(logged_as[0], "alice");

  /* Another cookie on the same fd is not ours. */
  ntold = 0;
  deliver(ms_sasl, svs, svs, "AB AB!7.778 C :+");
  assert_false(was_told(c));
}

/* REGISTER and SASL may overlap (draft/account-registration): a REGISTER
 * login landing between services' L and their D S writes the login
 * identity, and the D S still completes the login services named in L,
 * with L's timestamp -- as a local exchange's success replaces a REGISTER
 * login that landed mid-exchange.  Before, L wrote the identity itself,
 * and D S completed as whatever the identity then was: the REGISTER
 * account, with services' 903 and no id. */
static void test_sasl_relay_success_is_the_account_services_named(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;

  deliver(ms_sasl, svs, svs, "AB AB!7.777 C :+");
  deliver(ms_sasl, svs, svs, "AB AB!7.777 L alice 1700000000");
  /* the REGISTER login, meanwhile */
  sasl_identity_set(c, "newacct", 0, "a6p7gJ2tEdGAtADAT9QwyA", 1);
  SetFlag(c, FLAG_SASLCOMPLETE);
  SetFlag(c, FLAG_REGLOGIN);
  deliver(ms_sasl, svs, svs, "AB AB!7.777 D S");
  assert_int_equal(nlogins, 1);
  assert_ptr_equal(logged_in[0], c);
  assert_string_equal(logged_as[0], "alice");
  assert_int_equal(logged_ts[0], 1700000000);
  assert_string_equal(cli_saslnamed(c), "");

  /* A failure after L names nothing: the REGISTER login stays as it is. */
  c = local_client("joiner2", 8, 1);
  cli_saslcookie(c) = 778;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!8.778 L bob");
  sasl_identity_set(c, "newacct2", 0, NULL, 0);
  SetFlag(c, FLAG_SASLCOMPLETE);
  SetFlag(c, FLAG_REGLOGIN);
  deliver(ms_sasl, svs, svs, "AB AB!8.778 D F");
  assert_int_equal(nlogins, 1);
  assert_string_equal(cli_saslaccount(c), "newacct2");
  assert_string_equal(cli_saslnamed(c), "");
}

/* A REGISTER login that lands while a relayed exchange is in flight sets
 * the SASL-complete flag (draft/account-registration) but completes no
 * exchange: the exchange still times out (and aborts) -- abort_sasl()
 * answers the client and drops the cookie.  Before, it returned at once on
 * the flag, so the exchange could be neither aborted nor timed out.  An
 * exchange an IAuth success completed (the flag, no REGISTER) is still
 * left alone. */
static void test_sasl_relay_exchange_times_out_after_register_login(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.777 C :+");
  assert_ptr_equal(cli_saslagent(c), svs);

  SetFlag(c, FLAG_SASLCOMPLETE);              /* the REGISTER login */
  SetFlag(c, FLAG_REGLOGIN);
  ntold = 0;
  abort_sasl(c, 1);                            /* the exchange's timeout */
  assert_true(was_told(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_null(cli_saslagent(c));

  /* An exchange that completed and kept its cookie: untouched. */
  c = local_client("iauthed", 8, 1);
  cli_saslcookie(c) = 778;
  SetFlag(c, FLAG_SASLCOMPLETE);
  ntold = 0;
  abort_sasl(c, 0);
  assert_false(was_told(c));
  assert_int_equal(cli_saslcookie(c), 778);
}

/* #223 through services: a logged-in client's re-authentication that
 * services answer with ANOTHER account.  The L reply is refused before
 * anything of it is kept -- the login's own record (name, timestamp,
 * Keycloak id and its live mark) stays, and nothing is named for the
 * exchange -- and the exchange ends there: no cookie, no agent, so the D S
 * after it reaches nobody.  An L for the client's own account goes on as
 * before. */
static void test_sasl_reauth_other_account_refused_at_L(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("xav", 7, 0);
  ircd_strncpy(cli_user(c)->account, "xavier", ACCOUNTLEN + 1);
  SetAccount(c);
  sasl_identity_set(c, "xavier", 0, "AAAAAAAAAAAAAAAAAAAAAA", 1);
  SetSASLComplete(c);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;

  deliver(ms_sasl, svs, svs, "AB AB!7.777 C :+");
  assert_ptr_equal(cli_saslagent(c), svs);
  deliver(ms_sasl, svs, svs, "AB AB!7.777 L yvonne 1700000000");
  assert_int_equal(refusals, 1);
  assert_string_equal(cli_saslnamed(c), "");
  assert_string_equal(cli_saslaccount(c), "xavier");
  assert_int_equal(cli_saslacccreate(c), 0);
  assert_string_equal(cli_saslkcid(c), "AAAAAAAAAAAAAAAAAAAAAA");
  assert_int_equal(cli_saslkcidlive(c), 1);
  assert_true(IsSASLComplete(c));
  assert_int_equal(cli_saslcookie(c), 0);
  assert_null(cli_saslagent(c));
  assert_int_equal(cli_saslagentref(svs), 0);
  deliver(ms_sasl, svs, svs, "AB AB!7.777 D S");
  assert_int_equal(nlogins, 0);

  cli_saslcookie(c) = 778;                 /* a refresh of its own */
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.778 L xavier 1700000000");
  assert_int_equal(refusals, 1);
  assert_string_equal(cli_saslnamed(c), "xavier");
  deliver(ms_sasl, svs, svs, "AB AB!7.778 D S");
  assert_int_equal(nlogins, 1);
  assert_string_equal(logged_as[0], "xavier");
  assert_int_equal(logged_ts[0], 1700000000);
}

/* Every end of a relayed re-authentication of a logged-in client -- D F,
 * D A, a refused L, and abort_sasl() (its timeout, an agent's split, the
 * client's AUTHENTICATE *) -- ends the exchange whole: no cookie and no
 * re-authentication mark left behind, the completed login as it was. */
static void test_sasl_relay_ends_clear_the_reauth_mark(void **state)
{
  static const char *const ends[] = { "D F", "D A", "L yvonne", NULL };
  struct Client *svs, *c;
  int i;
  (void)state;
  svs = services_link();
  c = local_client("xav", 7, 0);
  ircd_strncpy(cli_user(c)->account, "xavier", ACCOUNTLEN + 1);
  SetAccount(c);
  SetSASLComplete(c);

  for (i = 0; i <= 3; i++) {
    cli_saslcookie(c) = 700 + i;
    cli_saslstart(c) = CurrentTime;
    SetSASLReauth(c);
    deliver(ms_sasl, svs, svs, "AB AB!7.%d C :+", 700 + i);
    assert_ptr_equal(cli_saslagent(c), svs);
    if (ends[i])
      deliver(ms_sasl, svs, svs, "AB AB!7.%d %s", 700 + i, ends[i]);
    else
      abort_sasl(c, 1);                     /* the timeout */
    assert_int_equal(cli_saslcookie(c), 0);
    assert_false(IsSASLReauth(c));
    assert_null(cli_saslagent(c));
    assert_int_equal(cli_saslagentref(svs), 0);
    assert_true(IsSASLComplete(c));
    assert_string_equal(cli_user(c)->account, "xavier");
  }
  assert_int_equal(nlogins, 0);
}

/* A D S with no L before it, for a logged-in client: the success
 * completes as the login it holds (its own account), never as anything
 * services did not name.  With no login record at all (a services login)
 * it completes as nothing -- the completion's rule then refuses it
 * (sasl_handler_cmocka: reauth_ds_without_l_refused). */
static void test_sasl_relay_ds_without_l(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("xav", 7, 0);
  ircd_strncpy(cli_user(c)->account, "xavier", ACCOUNTLEN + 1);
  SetAccount(c);
  sasl_identity_set(c, "xavier", 0, NULL, 0);
  SetSASLComplete(c);
  cli_saslcookie(c) = 801;
  cli_saslstart(c) = CurrentTime;
  SetSASLReauth(c);
  deliver(ms_sasl, svs, svs, "AB AB!7.801 D S");
  assert_int_equal(nlogins, 1);
  assert_string_equal(logged_as[0], "xavier");

  c = local_client("svc", 8, 0);
  ircd_strncpy(cli_user(c)->account, "xavier", ACCOUNTLEN + 1);
  SetAccount(c);                            /* by services: no record */
  cli_saslcookie(c) = 802;
  cli_saslstart(c) = CurrentTime;
  SetSASLReauth(c);
  deliver(ms_sasl, svs, svs, "AB AB!8.802 D S");
  assert_int_equal(nlogins, 2);
  assert_string_equal(logged_as[1], "");
}

/* RPL_SASLMECHS (#221): services answer an unsupported mechanism with
 * their own list (SASL M); the client gets what the sasl capability
 * advertises -- with the local Keycloak tier more than services offer. */
static void test_sasl_mechs_lists_the_cap_value(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;
  cap_mechs = "PLAIN,OAUTHBEARER,SCRAM-SHA-256";

  deliver(ms_sasl, svs, svs, "AB AB!7.777 M :PLAIN");

  assert_ptr_equal(mechs_to, c);
  assert_string_equal(mechs_sent, "PLAIN,OAUTHBEARER,SCRAM-SHA-256");
}

/* ... and services' own list when the capability has no value. */
static void test_sasl_mechs_services_list_without_cap_value(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;

  deliver(ms_sasl, svs, svs, "AB AB!7.777 M :PLAIN,EXTERNAL");

  assert_ptr_equal(mechs_to, c);
  assert_string_equal(mechs_sent, "PLAIN,EXTERNAL");
}

/* ====================================================================
 * Login-on-connect: which client a reply reaches
 * ==================================================================== */

/* A client that sent PASS :/account/password but whose request has not
 * gone to services yet has cookie 0: an ACCOUNT A with cookie 0 logged it
 * in as the account it named, its password never checked. */
static void test_loc_cookie_0_request_not_sent(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  loc_request(c, "alice", 0);

  deliver(ms_account, svs, svs, "AB A .7.0 1700000000");
  deliver(ms_account, svs, svs, "AB A .7.x 1700000000");

  assert_false(IsAccount(c));
  assert_non_null(cli_loc(c));
  assert_int_equal(set_accounts, 0);
  assert_false(was_told(c));
}

/* A connection on a server port that sent PASS :/a/b keeps cookie 0 for
 * good and has no User: the accept wrote through cli_user() == NULL. */
static void test_loc_cookie_0_server_port(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = server_port_client(11);
  loc_request(c, "a", 0);

  deliver(ms_account, svs, svs, "AB A .11.0");
  deliver(ms_account, svs, svs, "AB D .11.0");

  assert_false(was_told(c));
  assert_non_null(cli_loc(c));
}

/* A deny with cookie 0 does not end a request either. */
static void test_loc_cookie_0_deny(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  loc_request(c, "alice", 0);

  deliver(ms_account, svs, svs, "AB D .7.0");

  assert_false(was_told(c));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
#define T(f) cmocka_unit_test_setup_teardown(f, world_setup, world_teardown)
    T(test_loc_accept_returns_0_for_the_link),
    T(test_loc_accept_logs_in),
    T(test_sasl_cookie_0_idle_client),
    T(test_sasl_cookie_0_registered_user),
    T(test_sasl_cookie_0_server_link),
    T(test_sasl_cookie_0_server_port),
    T(test_sasl_cookie_reading_as_0),
    T(test_sasl_local_exchange_unreachable),
    T(test_sasl_fd_past_the_end),
    T(test_sasl_legitimate_exchange),
    T(test_sasl_mechs_lists_the_cap_value),
    T(test_sasl_mechs_services_list_without_cap_value),
    T(test_sasl_relay_exchange_times_out_after_register_login),
    T(test_sasl_relay_success_is_the_account_services_named),
    T(test_sasl_reauth_other_account_refused_at_L),
    T(test_sasl_relay_ends_clear_the_reauth_mark),
    T(test_sasl_relay_ds_without_l),
    T(test_loc_cookie_0_request_not_sent),
    T(test_loc_cookie_0_server_port),
    T(test_loc_cookie_0_deny),
#undef T
  };

  return cmocka_run_group_tests_name("services_reply", tests, NULL, NULL);
}
