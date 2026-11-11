/*
 * services_reply_t.c - which local client a services reply reaches.
 *
 * A SASL reply names its client with a token <server>!<fd>.<cookie>
 * (ms_sasl(), m_sasl.c), a login-on-connect reply with a request id
 * .<fd>.<cookie> (decode_auth_id(), m_account.c).  Both arrive from
 * another server, so the fd may be any number, and only a cookie this
 * server issued to a client with a request in flight may match.
 *
 * The two handlers are linked as the server builds them.  Everything
 * they call besides the lookup is stubbed below; the stubs that send to
 * a client record which client that was.
 */
#include "config.h"

#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numnicks.h"
#include "s_auth.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The handlers see the declaration in s_bsd.h, LocalClientArray
 * [MAXCONNECTIONS].  This definition has two more slots, each holding a
 * client whose cookies match, so that a lookup reading past the declared
 * end finds a client there rather than whatever the linker put next, and
 * fails a check instead of depending on memory layout.  For the same
 * reason s_bsd.h is not included. */
struct Client *LocalClientArray[MAXCONNECTIONS + 2];

/* ---------- stubs ---------- */

static struct Client *sent_to;  /**< last client a reply was sent to */

static void record(struct Client *to)
{
  sent_to = to;
}

void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  record(to);
}

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  record(to);
}

void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{
}

void sendcmdto_common_channels_capab_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Client *one, int withcap,
                                            int skipcap,
                                            const char *pattern, ...)
{
}

int send_reply(struct Client *to, int reply, ...)
{
  record(to);
  return 0;
}

int need_more_params(struct Client *cptr, const char *cmd)
{
  return 0;
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  return 0;
}

int feature_bool(enum Feature feat)
{
  return feat == FEAT_EXTENDED_ACCOUNTS;
}

int feature_int(enum Feature feat)
{
  return 0;
}

const char *feature_str(enum Feature feat)
{
  return "*";
}

struct Client *FindNServer(const char *numeric)
{
  return strcmp(numeric, "AB") ? NULL : &me;
}

struct Client *findNUser(const char *yxx)
{
  return NULL;
}

struct Client *find_match_server(const char *mask)
{
  return NULL;
}

void timer_del(struct Timer *timer)
{
}

int hide_hostmask(struct Client *cptr)
{
  return 0;
}

int auth_set_account(struct AuthRequest *auth, const char *account)
{
  return 0;
}

int auth_sasl_done(struct AuthRequest *auth)
{
  return 0;
}

void auth_sasl_clear(struct AuthRequest *auth)
{
}

void auth_end_loc(struct AuthRequest *auth)
{
}

/* ---------- checks ---------- */

static int checks;              /**< checks evaluated */
static int failures;            /**< checks that did not hold */

static void check(int ok, int line, const char *what, const char *arg)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED line %d: %s [%s]\n", line, what, arg);
  }
}

#define CHECK(cond, what, arg) check((cond) ? 1 : 0, __LINE__, (what), (arg))

static struct Client peer;      /**< the server the replies come from */

/** Feed "AC SASL AB <token> <reply> :x" to ms_sasl().
 * @return The client something was sent to, or NULL. */
static struct Client *sasl_reaches(const char *token, const char *reply)
{
  char tok[64], rep[8], data[] = "x";
  char *parv[] = { "AC", "AB", tok, rep, data, NULL };

  ircd_strncpy(tok, token, sizeof(tok));
  ircd_strncpy(rep, reply, sizeof(rep));
  sent_to = NULL;
  ms_sasl(&peer, &peer, 5, parv);
  return sent_to;
}

/** Feed "AC AC AB <type> <id>" to ms_account().
 * @return The client something was sent to, or NULL. */
static struct Client *account_reaches(const char *type, const char *id)
{
  char typ[4], rid[64];
  char *parv[] = { "AC", "AB", typ, rid, NULL };

  ircd_strncpy(typ, type, sizeof(typ));
  ircd_strncpy(rid, id, sizeof(rid));
  sent_to = NULL;
  ms_account(&peer, &peer, 4, parv);
  return sent_to;
}

/* Out-of-range fds, as text: past the end, far past it, and negative
 * numbers, which both handlers keep in an unsigned int. */
static const char *far_fds[] = {
  "999999999", "2147483647", "4294967295", "-1", "-2147483648", NULL
};

int main(void)
{
  static struct Connection con_sasl, con_idle, con_loc, con_decoy;
  static struct Client sasl_cli, idle_cli, loc_cli, decoy_cli;
  static struct User loc_user;
  static struct LOCInfo idle_loc, decoy_loc;
  char buf[64];
  int i;

  /* A lookup that strays far enough faults: print each failure as it
   * happens rather than lose it in the buffer. */
  setvbuf(stdout, NULL, _IONBF, 0);

  SetMe(&me);
  ircd_strncpy(cli_yxx(&me), "AB", sizeof(cli_yxx(&me)));
  cli_status(&peer) = STAT_SERVER;

  /* fd 5: a client in the middle of a SASL exchange. */
  cli_connect(&sasl_cli) = &con_sasl;
  cli_saslcookie(&sasl_cli) = 1234;
  LocalClientArray[5] = &sasl_cli;

  /* fd 6: a connection with nothing in flight: no SASL exchange, and a
   * login-on-connect request that has not gone out (cookie 0).  It has no
   * cli_user(), as on a server port. */
  cli_connect(&idle_cli) = &con_idle;
  ircd_strncpy(idle_loc.account, "idleacct", sizeof(idle_loc.account));
  cli_loc(&idle_cli) = &idle_loc;
  LocalClientArray[6] = &idle_cli;

  /* fd 7: a client whose login-on-connect request is out. */
  cli_connect(&loc_cli) = &con_loc;
  cli_user(&loc_cli) = &loc_user;
  cli_loc(&loc_cli) = calloc(1, sizeof(struct LOCInfo));
  cli_loc(&loc_cli)->cookie = 4321;
  ircd_strncpy(cli_loc(&loc_cli)->account, "locacct",
               sizeof(cli_loc(&loc_cli)->account));
  LocalClientArray[7] = &loc_cli;

  /* Past the declared end: a client whose cookies match. */
  cli_connect(&decoy_cli) = &con_decoy;
  cli_saslcookie(&decoy_cli) = 1234;
  decoy_loc.cookie = 4321;
  cli_loc(&decoy_cli) = &decoy_loc;
  LocalClientArray[MAXCONNECTIONS] = &decoy_cli;
  LocalClientArray[MAXCONNECTIONS + 1] = &decoy_cli;

  /* ---- SASL ---- */
  CHECK(sasl_reaches("AB!5.1234", "C") == &sasl_cli,
        "SASL: the right fd and cookie reach the client", "AB!5.1234");
  CHECK(!sasl_reaches("AB!5.1", "C"), "SASL: a wrong cookie reaches nobody",
        "AB!5.1");
  CHECK(!sasl_reaches("AB!7.4321", "C"),
        "SASL: a login-on-connect cookie is not a SASL cookie", "AB!7.4321");
  snprintf(buf, sizeof(buf), "AB!%d.1234", MAXCONNECTIONS - 1);
  CHECK(!sasl_reaches(buf, "C"), "SASL: an empty slot reaches nobody", buf);
  snprintf(buf, sizeof(buf), "AB!%d.1234", MAXCONNECTIONS);
  CHECK(!sasl_reaches(buf, "C"), "SASL: fd MAXCONNECTIONS is not looked up",
        buf);
  snprintf(buf, sizeof(buf), "AB!%d.1234", MAXCONNECTIONS + 1);
  CHECK(!sasl_reaches(buf, "C"),
        "SASL: fd MAXCONNECTIONS + 1 is not looked up", buf);
  CHECK(!sasl_reaches("AB!6.0", "C"),
        "SASL: cookie 0 reaches no client without an exchange", "AB!6.0");
  CHECK(!sasl_reaches("AB!6.zero", "C"),
        "SASL: a cookie atoi() reads as 0 reaches nobody", "AB!6.zero");
  CHECK(!sasl_reaches("AB!6.0", "L"),
        "SASL: cookie 0 logs no client in", "AB!6.0 L");
  CHECK(!cli_saslaccount(&idle_cli)[0], "SASL: ... and sets no account",
        "AB!6.0 L");
  for (i = 0; far_fds[i]; i++) {
    snprintf(buf, sizeof(buf), "AB!%s.1234", far_fds[i]);
    CHECK(!sasl_reaches(buf, "C"), "SASL: an out-of-range fd reaches nobody",
          buf);
  }

  /* ---- ACCOUNT (login-on-connect replies) ---- */
  CHECK(!account_reaches("D", ".7.1"),
        "ACCOUNT: a wrong cookie reaches nobody", ".7.1");
  CHECK(!account_reaches("D", ".5.1234"),
        "ACCOUNT: a SASL cookie is not a login-on-connect cookie", ".5.1234");
  snprintf(buf, sizeof(buf), ".%d.4321", MAXCONNECTIONS - 1);
  CHECK(!account_reaches("D", buf), "ACCOUNT: an empty slot reaches nobody",
        buf);
  snprintf(buf, sizeof(buf), ".%d.4321", MAXCONNECTIONS);
  CHECK(!account_reaches("D", buf),
        "ACCOUNT: fd MAXCONNECTIONS is not looked up", buf);
  snprintf(buf, sizeof(buf), ".%d.4321", MAXCONNECTIONS + 1);
  CHECK(!account_reaches("D", buf),
        "ACCOUNT: fd MAXCONNECTIONS + 1 is not looked up", buf);
  CHECK(!account_reaches("D", ".6.0"),
        "ACCOUNT: cookie 0 reaches no client without a request out", ".6.0");
  /* With cookie 0 matching, A would write through idle_cli's NULL
   * cli_user(). */
  CHECK(!account_reaches("A", ".6.0"),
        "ACCOUNT: cookie 0 logs no client in", ".6.0 A");
  for (i = 0; far_fds[i]; i++) {
    snprintf(buf, sizeof(buf), ".%s.4321", far_fds[i]);
    CHECK(!account_reaches("A", buf),
          "ACCOUNT: an out-of-range fd reaches nobody", buf);
  }
  CHECK(account_reaches("D", ".7.4321") == &loc_cli,
        "ACCOUNT: D with the right fd and cookie reaches the client",
        ".7.4321 D");
  CHECK(account_reaches("A", ".7.4321") == &loc_cli,
        "ACCOUNT: A with the right fd and cookie reaches the client",
        ".7.4321 A");
  CHECK(!strcmp(loc_user.account, "locacct") && !cli_loc(&loc_cli),
        "ACCOUNT: ... logs it in and ends its request", ".7.4321 A");

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
