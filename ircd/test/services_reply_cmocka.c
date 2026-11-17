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
static char logged_id[MAXREC][ACCOUNT_ID_LEN + 1];
static int logged_live[MAXREC];
static int nlogins;
static int sasl_dones;                  /* auth_sasl_done() calls */
static int turn_checks;                 /* sasl_client_turn_check() calls */
static int would_abort;                 /* sasl_challenge_would_abort() */
static int auth_result;                 /* what it returns */
/* account-notify sends: who the line was about, and whether that user's
 * own connections were among the recipients.  The channel walk with
 * one == from leaves the user out; the session form includes it (send.c). */
static struct Client *notified[MAXREC];
static int notified_self[MAXREC];
static int nnotified;

/* The last RPL_SASLMECHS (908) sent, and its mechanism list. */
static struct Client *mechs_to;
static char mechs_sent[128];
/* The sasl capability's value (m_cap.c); NULL: none. */
static const char *cap_mechs;
static int refusals;                    /* sasl_reauth_refused() said so */
static int nmoved;                      /* presence_anchor_move() calls */
static int replies[MAXREC];             /* every numeric sent, in order */
static int nreplies;
static char logged_fmt[4][160];         /* log lines at NOTICE or above */
static int nlogged;
static int notices_tried, notices_sent; /* rate-limited oper notices */
static struct Client *session_member;   /* bounce_client_in_session() */
static struct Client *ban_cleared[MAXREC];  /* member_ban_cache_clear() */
static int nban_clears;
static int sasl_failures_counted;       /* sasl_failure_count() calls */

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

static int msgid_on;            /* FEAT_MSGID */

/* The event armed for client lines (send.c's override), what the
 * account-notify lines went out under, and what the relay carried. */
static char armed_msgid[64], notify_msgid[64], relay_msgid[64];
static uint64_t armed_ms, notify_ms, relay_ms;

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
  turn_checks = 0;
  would_abort = 0;
  nnotified = 0;
  msgid_on = 0;
  armed_msgid[0] = notify_msgid[0] = relay_msgid[0] = '\0';
  armed_ms = notify_ms = relay_ms = 0;
  mechs_to = NULL;
  mechs_sent[0] = '\0';
  cap_mechs = NULL;
  refusals = 0;
  nmoved = 0;
  nreplies = 0;
  nlogged = notices_tried = notices_sent = 0;
  nban_clears = 0;
  sasl_failures_counted = 0;
  session_member = NULL;
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

/* Log lines at NOTICE or above, their format kept (the pattern says which
 * line it was). */
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)flags;
  if (severity <= L_NOTICE && nlogged < 4)
    ircd_strncpy(logged_fmt[nlogged++], fmt, sizeof(logged_fmt[0]));
}

/* Oper notices, rate-limited as the real ones are (30 s per rate). */
void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
                                      time_t *rate, const char *pattern, ...)
{
  (void)one; (void)mask; (void)pattern;
  notices_tried++;
  if (CurrentTime - *rate < 30)
    return;
  *rate = CurrentTime;
  notices_sent++;
}

/* A connection of a bouncer session (bouncer_session.c), as a case files
 * it. */
int bounce_client_in_session(struct Client *c)
{
  return c && c == session_member;
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
  return feat == FEAT_EXTENDED_ACCOUNTS || (feat == FEAT_MSGID && msgid_on);
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

static void record_notify(struct Client *from, int withcap, int self)
{
  if (withcap != CAP_ACCNOTIFY)
    return;
  assert_true(nnotified < MAXREC);
  notified[nnotified] = from;
  notified_self[nnotified] = self;
  nnotified++;
}

void sendcmdto_common_channels_capab_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Client *one, int withcap,
                                            int skipcap,
                                            const char *pattern, ...)
{
  (void)cmd; (void)tok; (void)skipcap; (void)pattern;
  record_notify(from, withcap, one != from);
}

void sendcmdto_common_channels_capab_session(struct Client *from,
                                             const char *cmd, const char *tok,
                                             int withcap,
                                             const char *pattern, ...)
{
  (void)cmd; (void)tok; (void)pattern;
  record_notify(from, withcap, 1);
  ircd_strncpy(notify_msgid, armed_msgid, sizeof(notify_msgid));
  notify_ms = armed_ms;
}

void sendcmdto_set_client_msgid(const char *msgid)
{
  if (msgid)
    ircd_strncpy(armed_msgid, msgid, sizeof(armed_msgid));
  else {
    armed_msgid[0] = '\0';
    armed_ms = 0;
  }
}

void sendcmdto_set_client_event(const char *msgid, uint64_t event_ms)
{
  sendcmdto_set_client_msgid(msgid);
  armed_ms = msgid ? event_ms : 0;
}

void sendcmdto_set_s2s_tags(uint64_t time_ms, const char *msgid)
{
  relay_ms = time_ms;
  ircd_strncpy(relay_msgid, msgid ? msgid : "", sizeof(relay_msgid));
}

/** The clock behind a minted event; a tagged peer's time when it sent one
 * (history.c). */
#define NOW_MS 1763000009999ULL
uint64_t history_event_time_ms(struct Client *link)
{
  if (link && cli_s2s_time_ms(link))
    return cli_s2s_time_ms(link);
  return NOW_MS;
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

/* sasl_auth.c (not linked): a failed exchange counted toward
 * SASL_MAX_FAILURES. */
void sasl_failure_count(struct Client *cptr)
{
  (void)cptr;
  sasl_failures_counted++;
}

/* channel.c: whose cached ban verdicts were forgotten. */
void member_ban_cache_clear(struct Client *cptr)
{
  assert_true(nban_clears < MAXREC);
  ban_cleared[nban_clears++] = cptr;
}

void channel_account_adjust(struct Client *cptr, int delta)
{
  (void)cptr; (void)delta;
}

/* The presence moves an account change makes: about whom, from which
 * anchor to which, and whether the open interval's start carried over
 * (a rename) or not (a switch to another account). */
static struct Client *moved[MAXREC];
static char moved_from[MAXREC][ACCOUNTLEN + 1];
static char moved_to[MAXREC][ACCOUNTLEN + 1];
static int moved_carry[MAXREC];

void presence_anchor_move(struct Client *cptr, const char *old_anchor,
                          int old_is_session, const char *new_anchor,
                          int new_is_session, int carry)
{
  (void)old_is_session; (void)new_is_session;
  assert_true(nmoved < MAXREC);
  moved[nmoved] = cptr;
  ircd_strncpy(moved_from[nmoved], old_anchor ? old_anchor : "", ACCOUNTLEN + 1);
  ircd_strncpy(moved_to[nmoved], new_anchor ? new_anchor : "", ACCOUNTLEN + 1);
  moved_carry[nmoved] = carry;
  nmoved++;
}

void presence_anchor_transfer(struct Client *cptr, const char *old_anchor,
                              int old_is_session, const char *new_anchor,
                              int new_is_session)
{
  presence_anchor_move(cptr, old_anchor, old_is_session, new_anchor,
                       new_is_session, 1);
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
  if (nreplies < MAXREC)
    replies[nreplies++] = reply & ~SND_EXPLICIT;
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
  assert_true(nlogins < MAXREC);
  logged_in[nlogins] = sptr;
  logged_ts[nlogins] = acc_create;
  ircd_strncpy(logged_id[nlogins], kc_id ? kc_id : "", sizeof(logged_id[nlogins]));
  logged_live[nlogins] = id_live;
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

/* s_auth.c: a check owed from the loop when a challenge turns the
 * exchange to the client (it aborts one whose client registered). */
void sasl_client_turn_check(struct Client *cptr)
{
  (void)cptr;
  turn_checks++;
}

/* s_auth.c: the client registered meanwhile, only the exchange holds it */
int sasl_challenge_would_abort(struct Client *cptr)
{
  (void)cptr;
  return would_abort;
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

/* A 908 answers a mechanism services do not offer: the exchange cannot go
 * on, and ends at once with its 904 (908, then 904), as a D F would end
 * it -- no cookie, no agent, registration let go on -- rather than at the
 * SASL timeout.  The D F services send after it reaches nobody. */
static void test_sasl_mechs_ends_the_exchange(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 777;
  cli_saslstart(c) = CurrentTime;

  deliver(ms_sasl, svs, svs, "AB AB!7.777 M :PLAIN");

  assert_int_equal(nreplies, 2);
  assert_int_equal(replies[0], ERR_SASLMECHS);
  assert_int_equal(replies[1], ERR_SASLFAIL);
  assert_int_equal(cli_saslcookie(c), 0);
  assert_null(cli_saslagent(c));
  assert_int_equal(cli_saslagentref(svs), 0);
  assert_int_equal(sasl_dones, 1);

  deliver(ms_sasl, svs, svs, "AB AB!7.777 D F");
  assert_int_equal(nreplies, 2);              /* no second 904 */
  assert_int_equal(sasl_dones, 1);
}

/* ... and a logged-in client's re-authentication: ended, its login kept. */
static void test_sasl_mechs_ends_a_reauth(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("xav", 7, 0);
  ircd_strncpy(cli_user(c)->account, "xavier", ACCOUNTLEN + 1);
  SetAccount(c);
  sasl_identity_set(c, "xavier", 0, NULL, 0);
  SetSASLComplete(c);
  cli_saslcookie(c) = 778;
  cli_saslstart(c) = CurrentTime;
  SetSASLReauth(c);

  deliver(ms_sasl, svs, svs, "AB AB!7.778 M :PLAIN");

  assert_int_equal(nreplies, 2);
  assert_int_equal(replies[1], ERR_SASLFAIL);
  assert_int_equal(cli_saslcookie(c), 0);
  assert_false(IsSASLReauth(c));
  assert_true(IsSASLComplete(c));
  assert_string_equal(cli_user(c)->account, "xavier");
}

/* A challenge from services makes it the client's turn (SASL_MAX_FAILURES:
 * a timeout from then on is the client's). */
static void test_sasl_challenge_is_the_clients_turn(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  cli_saslcookie(c) = 813;
  cli_saslstart(c) = CurrentTime;
  assert_false(con_sasl_xflags(cli_connect(c)) & SASLX_CLIENTTURN);
  deliver(ms_sasl, svs, svs, "AB AB!7.813 C +");
  assert_true(con_sasl_xflags(cli_connect(c)) & SASLX_CLIENTTURN);
  /* ... and owes a registration check (SASL 3.1: a client that
   * registered meanwhile has the exchange aborted) */
  assert_int_equal(turn_checks, 1);
}

/* A client that pipelined AUTHENTICATE PLAIN and CAP END has completed
 * registration when services' "+" comes: the check that challenge owes
 * aborts the exchange (906) at once, so the "+" is not relayed -- a
 * client prompted by it sends its credentials after registration, where
 * they would start an exchange of their own, as its mechanism. */
static void test_sasl_challenge_withheld_when_registration_aborts(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("eager", 7, 1);
  cli_saslcookie(c) = 816;
  cli_saslstart(c) = CurrentTime;
  con_sasl_unanswered(cli_connect(c)) = 1;      /* S PLAIN */
  would_abort = 1;
  deliver(ms_sasl, svs, svs, "AB AB!7.816 C +");
  assert_false(was_told(c));                    /* no "AUTHENTICATE +" */
  assert_true(con_sasl_xflags(cli_connect(c)) & SASLX_CLIENTTURN);
  assert_int_equal(turn_checks, 1);             /* the check that aborts */
}

/* ... but a line that does not hand the turn over (pipelined credentials
 * still with services) is relayed: no abort follows it. */
static void test_sasl_challenge_relayed_when_no_turn(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("eager2", 7, 1);
  cli_saslcookie(c) = 817;
  cli_saslstart(c) = CurrentTime;
  con_sasl_unanswered(cli_connect(c)) = 2;      /* S PLAIN, C <creds> */
  would_abort = 1;
  deliver(ms_sasl, svs, svs, "AB AB!7.817 C +");
  assert_true(was_told(c));
  assert_int_equal(turn_checks, 0);
}

/* Pipelined credentials: the client's mechanism and credentials both went
 * to services before their "+"; the "+" answers the mechanism, so it is
 * not the client's turn yet -- no turn, no check (a client that
 * registered meanwhile keeps waiting for services' answer to the
 * credentials, not aborted). */
static void test_sasl_challenge_after_pipelined_credentials(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("piper", 7, 1);
  cli_saslcookie(c) = 814;
  cli_saslstart(c) = CurrentTime;
  con_sasl_unanswered(cli_connect(c)) = 2;      /* S PLAIN, C <creds> */
  con_sasl_xflags(cli_connect(c)) |= SASLX_SENT;
  deliver(ms_sasl, svs, svs, "AB AB!7.814 C +");
  assert_false(con_sasl_xflags(cli_connect(c)) & SASLX_CLIENTTURN);
  assert_int_equal(con_sasl_unanswered(cli_connect(c)), 1);
  assert_int_equal(turn_checks, 0);
}

/* A challenge of 400 bytes or more comes in several lines: the turn is
 * the client's on its last line, not on the first. */
static void test_sasl_chunked_challenge_turns_on_its_last_line(void **state)
{
  struct Client *svs, *c;
  char chunk[401];
  (void)state;
  svs = services_link();
  c = local_client("chunky", 7, 1);
  cli_saslcookie(c) = 815;
  cli_saslstart(c) = CurrentTime;
  con_sasl_unanswered(cli_connect(c)) = 1;      /* S OAUTHBEARER */
  con_sasl_xflags(cli_connect(c)) |= SASLX_SENT;
  memset(chunk, 'A', 400);
  chunk[400] = '\0';
  deliver(ms_sasl, svs, svs, "AB AB!7.815 C %s", chunk);
  assert_false(con_sasl_xflags(cli_connect(c)) & SASLX_CLIENTTURN);
  assert_int_equal(con_sasl_unanswered(cli_connect(c)), 1);
  assert_int_equal(turn_checks, 0);
  deliver(ms_sasl, svs, svs, "AB AB!7.815 C +");
  assert_true(con_sasl_xflags(cli_connect(c)) & SASLX_CLIENTTURN);
  assert_int_equal(con_sasl_unanswered(cli_connect(c)), 0);
  assert_int_equal(turn_checks, 1);
}

/* SASL_MAX_FAILURES: a services failure (D F) counts; their abort (D A)
 * and an unsupported mechanism (M: 908 + 904) do not. */
static void test_sasl_failures_counted_by_services(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);

  cli_saslcookie(c) = 801;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.801 D F");
  assert_int_equal(sasl_failures_counted, 1);

  cli_saslcookie(c) = 802;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.802 D A");
  assert_int_equal(sasl_failures_counted, 1);

  cli_saslcookie(c) = 803;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.803 M :PLAIN");
  assert_int_equal(sasl_failures_counted, 1);
  assert_int_equal(cli_saslcookie(c), 0);
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

/* A services success with no L before it names no account: the login is
 * the identity as it stands -- whole, with its Keycloak id and mark -- so a
 * second exchange before registration that ends so leaves the earlier login
 * exactly as it was (never its name and timestamp without its id), and a
 * first exchange logs in as nothing, as before. */
static void test_sasl_ds_without_l_keeps_the_identity_whole(void **state)
{
  struct Client *svs, *c;
  (void)state;
  svs = services_link();
  c = local_client("joiner", 7, 1);
  sasl_identity_set(c, "xavier", 1600000000, "AAAAAAAAAAAAAAAAAAAAAA", 1);
  SetSASLComplete(c);
  SetSASLReauth(c);                        /* a second exchange */
  cli_saslcookie(c) = 811;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.811 D S");
  assert_int_equal(nlogins, 1);
  assert_string_equal(logged_as[0], "xavier");
  assert_int_equal(logged_ts[0], 1600000000);
  assert_string_equal(logged_id[0], "AAAAAAAAAAAAAAAAAAAAAA");
  assert_int_equal(logged_live[0], 1);

  /* with an L: that account, no id (X3's wire carries none) */
  cli_saslcookie(c) = 812;
  cli_saslstart(c) = CurrentTime;
  deliver(ms_sasl, svs, svs, "AB AB!7.812 L yvonne 1700000000");
  deliver(ms_sasl, svs, svs, "AB AB!7.812 D S");
  assert_int_equal(nlogins, 2);
  assert_string_equal(logged_as[1], "yvonne");
  assert_string_equal(logged_id[1], "");
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

/* ====================================================================
 * ACCOUNT R / M / U: account-notify reaches the user itself (#220)
 * ==================================================================== */

/** A registered local user with a numeric, in no channel. */
static struct Client *registered_user(const char *name, int fd)
{
  struct Client *c = local_client(name, fd, 0);

  cli_from(c) = c;
  assert_true(SetLocalNumNick(c));
  return c;
}

/** One account-notify send about @a c, and it included @a c's own
 * connections ("including themselves"). */
static void assert_self_notified_once(struct Client *c)
{
  assert_int_equal(nnotified, 1);
  assert_ptr_equal(notified[0], c);
  assert_true(notified_self[0]);
}

/* Services log a registered user in (AUTH to AuthServ): the user is told,
 * not only the members of its channels. */
static void test_account_r_tells_the_user(void **state)
{
  struct Client *svs, *c;
  (void)state;

  svs = services_link();
  c = registered_user("uuu", 9);

  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));

  assert_true(IsAccount(c));
  assert_string_equal(cli_user(c)->account, "zed");
  assert_self_notified_once(c);
}

/* An account change: the same. */
static void test_account_m_tells_the_user(void **state)
{
  struct Client *svs, *c;
  (void)state;

  svs = services_link();
  c = registered_user("uuu", 9);
  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));
  nnotified = 0;

  deliver(ms_account, svs, svs, "%s%s M zed2 1700000000", NumNick(c));

  assert_string_equal(cli_user(c)->account, "zed2");
  assert_self_notified_once(c);
}

/* N067: an account change that arrives tagged is the origin's event:
 * the user's and the observers' lines carry its msgid and its time, and
 * so does the relay -- not this server's clock. */
static void test_account_r_keeps_the_origin_time(void **state)
{
  struct Client *svs, *c;
  (void)state;

  svs = services_link();
  c = registered_user("uuu", 9);
  msgid_on = 1;
  ircd_strncpy(cli_s2s_msgid(svs), "AEAAAAAAORIGIN", S2S_MSGID_BUFSIZE);
  cli_s2s_time_ms(svs) = 1762999990123ULL;

  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));

  assert_self_notified_once(c);
  assert_string_equal(notify_msgid, "AEAAAAAAORIGIN");
  assert_true(notify_ms == 1762999990123ULL);
  assert_string_equal(relay_msgid, "AEAAAAAAORIGIN");
  assert_true(relay_ms == 1762999990123ULL);
}

/* An untagged one is minted here, msgid and time together. */
static void test_account_r_untagged_mints_one_event(void **state)
{
  struct Client *svs, *c;
  (void)state;

  svs = services_link();
  c = registered_user("uuu", 9);
  msgid_on = 1;

  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));

  assert_string_equal(notify_msgid, "ABAAAAAAAAAAAB");
  assert_true(notify_ms == NOW_MS);
  assert_string_equal(relay_msgid, "ABAAAAAAAAAAAB");
  assert_true(relay_ms == NOW_MS);
}

/* A logout: ACCOUNT * to the user too. */
static void test_account_u_tells_the_user(void **state)
{
  struct Client *svs, *c;
  (void)state;

  svs = services_link();
  c = registered_user("uuu", 9);
  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));
  nnotified = 0;

  deliver(ms_account, svs, svs, "%s%s U", NumNick(c));

  assert_self_notified_once(c);
}

/* The same account again changes nothing and tells nobody. */
static void test_account_r_same_tells_nobody(void **state)
{
  struct Client *svs, *c;
  (void)state;

  svs = services_link();
  c = registered_user("uuu", 9);
  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));
  nnotified = 0;

  deliver(ms_account, svs, svs, "%s%s M zed 1700000000", NumNick(c));

  assert_int_equal(nnotified, 0);
}

/* ====================================================================
 * ACCOUNT M: a rename by services, or the user's own server's switch
 * ==================================================================== */

/* The same "AC <user> M <account> ..." line means two things.  Services
 * send it when they RENAME the account (X3 nickserv RENAME, irc_rename(),
 * from its own server): the same owner, so the presence window carries
 * over.  The user's own server sends it when the user re-authenticated to
 * a DIFFERENT account (sasl_broadcast_account()): the new account was not
 * there before, so nothing carries.  A relay keeps the line's source (the
 * fork's and master's ms_account() relay with sptr), so every server tells
 * them apart by it: from the user's own server, a switch; from any other,
 * a rename. */

/** Another fork server, linked to this one. */
static struct Client *leaf_link(const char *name, const char *yxx)
{
  struct Client *c = fake_client(name, STAT_SERVER);

  cli_serv(c) = calloc(1, sizeof(struct Server));
  assert_non_null(cli_serv(c));
  SetServerYXX(c, c, yxx);
  cli_serv(c)->up = &me;
  cli_from(c) = c;
  return c;
}

/** A user on @a server, numeric @a yxx, logged in to @a account. */
static struct Client *remote_user(const char *name, struct Client *server,
                                  const char *yxx, const char *account)
{
  struct Client *c = fake_client(name, STAT_USER);

  cli_user(c) = calloc(1, sizeof(struct User));
  assert_non_null(cli_user(c));
  cli_user(c)->server = server;
  cli_from(c) = server;
  SetRemoteNumNick(c, yxx);
  deliver(ms_account, server, server, "%s R %s 1700000000", yxx, account);
  assert_true(IsAccount(c));
  nmoved = 0;
  return c;
}

static void test_account_m_rename_carries_presence(void **state)
{
  struct Client *svs, *leaf, *c;
  (void)state;

  svs = services_link();
  leaf = leaf_link("leaf.test", "AC]]]");
  c = remote_user("ren", leaf, "ACAAB", "zed");

  /* Services rename the account; the line reaches us through the leaf,
   * still services' (the relay keeps the source). */
  deliver(ms_account, leaf, svs, "ACAAB M zed2");
  assert_string_equal(cli_user(c)->account, "zed2");
  assert_int_equal(nmoved, 1);
  assert_string_equal(moved_from[0], "zed");
  assert_string_equal(moved_to[0], "zed2");
  assert_int_equal(moved_carry[0], 1);

  /* ... and straight from services. */
  deliver(ms_account, svs, svs, "ACAAB M zed3");
  assert_int_equal(nmoved, 2);
  assert_int_equal(moved_carry[1], 1);
}

static void test_account_m_switch_carries_no_presence(void **state)
{
  struct Client *svs, *leaf, *hub2, *c;
  (void)state;

  svs = services_link();
  leaf = leaf_link("leaf.test", "AC]]]");
  hub2 = leaf_link("hub2.test", "AD]]]");
  c = remote_user("sw", leaf, "ACAAC", "xavier");

  /* The user's own server announces the switch. */
  deliver(ms_account, leaf, leaf, "ACAAC M yvonne 0");
  assert_string_equal(cli_user(c)->account, "yvonne");
  assert_int_equal(nmoved, 1);
  assert_string_equal(moved_from[0], "xavier");
  assert_string_equal(moved_to[0], "yvonne");
  assert_int_equal(moved_carry[0], 0);

  /* Relayed by another server (a legacy hop keeps the source too). */
  deliver(ms_account, hub2, leaf, "ACAAC M zoe 0");
  assert_int_equal(nmoved, 2);
  assert_int_equal(moved_carry[1], 0);
  (void)svs;
}

/* The user's own server announced an account change (a switch) for a
 * client this server holds as a connection of a bouncer session -- which
 * that server refuses, so only an older build, a race or a bug sends it.
 * It is applied as any M is (ignoring it would leave the account
 * different here than everywhere else), and told: a log line and a
 * rate-limited oper notice naming the client, both accounts and the
 * session.  No repair.  A services rename of a member is not told. */
static void test_account_m_switch_of_a_member_is_told(void **state)
{
  struct Client *svs, *leaf, *c;
  (void)state;

  svs = services_link();
  leaf = leaf_link("leaf.test", "AC]]]");
  c = remote_user("mem", leaf, "ACAAE", "xavier");
  session_member = c;

  deliver(ms_account, svs, svs, "ACAAE M xavier2");          /* a rename */
  assert_string_equal(cli_user(c)->account, "xavier2");
  assert_int_equal(notices_tried, 0);
  assert_int_equal(nlogged, 0);

  deliver(ms_account, leaf, leaf, "ACAAE M yvonne 0");       /* a switch */
  assert_string_equal(cli_user(c)->account, "yvonne");       /* applied */
  assert_int_equal(notices_tried, 1);
  assert_int_equal(notices_sent, 1);
  assert_int_equal(nlogged, 1);
  assert_non_null(strstr(logged_fmt[0], "bouncer session"));

  deliver(ms_account, leaf, leaf, "ACAAE M zoe 0");          /* again: rate */
  assert_string_equal(cli_user(c)->account, "zoe");
  assert_int_equal(notices_tried, 2);
  assert_int_equal(notices_sent, 1);
  assert_int_equal(nlogged, 2);

  session_member = NULL;                                     /* not a member */
  deliver(ms_account, leaf, leaf, "ACAAE M xavier 0");
  assert_int_equal(notices_tried, 2);
  assert_int_equal(nlogged, 2);
}

/* Account bans (~a:) match by account: a LOCAL member's cached ban
 * verdicts are forgotten whenever its account changes -- a login (R), a
 * change (M: a services rename or the user's own server's switch), a
 * logout (U) -- or it could keep speaking past a ban on its new account
 * until the ban list changed.  A remote user's memberships cache nothing
 * here (banflags are kept for local members only). */
static void test_account_change_forgets_cached_bans(void **state)
{
  struct Client *svs, *leaf, *c, *r;
  (void)state;

  svs = services_link();
  c = registered_user("loc", 9);
  deliver(ms_account, svs, svs, "%s%s R zed 1700000000", NumNick(c));
  assert_int_equal(nban_clears, 1);
  assert_ptr_equal(ban_cleared[0], c);
  deliver(ms_account, svs, svs, "%s%s M zed2", NumNick(c));
  assert_int_equal(nban_clears, 2);
  deliver(ms_account, svs, svs, "%s%s U", NumNick(c));
  assert_int_equal(nban_clears, 3);

  leaf = leaf_link("leaf.test", "AC]]]");
  r = remote_user("rem", leaf, "ACAAF", "xavier");     /* R: nothing here */
  deliver(ms_account, leaf, leaf, "ACAAF M yvonne 0");
  deliver(ms_account, leaf, leaf, "ACAAF U");
  assert_int_equal(nban_clears, 3);
  (void)r;
}

/* A first login (R) moves the session's presence to the account, with
 * its start, as before. */
static void test_account_r_carries_presence(void **state)
{
  struct Client *leaf, *c;
  (void)state;

  leaf = leaf_link("leaf.test", "AC]]]");
  c = fake_client("first", STAT_USER);
  cli_user(c) = calloc(1, sizeof(struct User));
  assert_non_null(cli_user(c));
  cli_user(c)->server = leaf;
  cli_from(c) = leaf;
  SetRemoteNumNick(c, "ACAAD");
  deliver(ms_account, leaf, leaf, "ACAAD R xavier 0");
  assert_int_equal(nmoved, 1);
  assert_int_equal(moved_carry[0], 1);
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
    T(test_sasl_mechs_ends_the_exchange),
    T(test_sasl_failures_counted_by_services),
    T(test_sasl_challenge_is_the_clients_turn),
    T(test_sasl_challenge_after_pipelined_credentials),
    T(test_sasl_challenge_withheld_when_registration_aborts),
    T(test_sasl_challenge_relayed_when_no_turn),
    T(test_sasl_chunked_challenge_turns_on_its_last_line),
    T(test_sasl_mechs_ends_a_reauth),
    T(test_sasl_relay_exchange_times_out_after_register_login),
    T(test_sasl_relay_success_is_the_account_services_named),
    T(test_sasl_reauth_other_account_refused_at_L),
    T(test_sasl_relay_ends_clear_the_reauth_mark),
    T(test_sasl_relay_ds_without_l),
    T(test_sasl_ds_without_l_keeps_the_identity_whole),
    T(test_loc_cookie_0_request_not_sent),
    T(test_loc_cookie_0_server_port),
    T(test_loc_cookie_0_deny),
    T(test_account_r_tells_the_user),
    T(test_account_m_tells_the_user),
    T(test_account_r_keeps_the_origin_time),
    T(test_account_r_untagged_mints_one_event),
    T(test_account_u_tells_the_user),
    T(test_account_r_same_tells_nobody),
    T(test_account_m_rename_carries_presence),
    T(test_account_m_switch_carries_no_presence),
    T(test_account_r_carries_presence),
    T(test_account_m_switch_of_a_member_is_told),
    T(test_account_change_forgets_cached_bans),
#undef T
  };

  return cmocka_run_group_tests_name("services_reply", tests, NULL, NULL);
}
