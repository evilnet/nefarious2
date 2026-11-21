/*
 * sasl_mechs_cmocka.c - what clients are told when the stored SASL
 * mechanism list changes
 *
 * The REAL sasl_mechs.o (the stored list: services' "SASL * * M" list or
 * IAuth's, and its clear when a server matching SASL_SERVER leaves) and
 * the REAL m_cap.o (CAP LS, cap_sasl_mechanisms(), CAP NEW / DEL), against
 * fake clients and servers; the server's own Keycloak tier, IAuth, the
 * features and the send layer are stubbed here.
 *
 * A list services announce tells clients only what changes in what CAP LS
 * says: the effective value (cap_sasl_mechanisms()) and whether sasl is
 * offered at all.  With the server's own Keycloak tier healthy, that is
 * the tier's list whatever services announce, so nothing is sent.  A
 * server that never receives the line (IAuth's list, or none) is told
 * what it was told before.
 *
 * A change in the local tier's health is told the same way: the
 * difference in what CAP LS says before and after (health_* cases).
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "capab.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msgq.h"
#include "querycmds.h"
#include "s_auth.h"
#include "struct.h"

/* ====================================================================
 * Globals the linked objects expect
 * ==================================================================== */

struct Client me;
struct Client *GlobalClientList;
struct UserStatistics UserStats;
int log_inassert;

/* ====================================================================
 * The facts the test sets
 * ==================================================================== */

static const char *local_mechs;        /* the Keycloak tier: NULL = none
                                        * (or configured but unhealthy) */
static const char *sasl_server;        /* FEAT_SASL_SERVER */
static const char *default_mechs;      /* FEAT_SASL_DEFAULT_MECHANISMS */
static int iauth_sasl;                 /* auth_iauth_handles_sasl() */
static const char *iauth_mechs;        /* auth_iauth_sasl_mechs() */

/* ====================================================================
 * What the code under test sent
 * ==================================================================== */

#define LINE 600
#define MAXREC 64

static struct { struct Client *to; char text[LINE]; } sent[MAXREC];
static int nsent;

static const char *sent_text(int nth)
{
  return nth < nsent ? sent[nth].text : "";
}

/* ====================================================================
 * Stubs
 * ==================================================================== */

void sendrawto_one(struct Client *to, const char *pattern, ...)
{
  va_list vl;
  assert_true(nsent < MAXREC);
  va_start(vl, pattern);
  ircd_vsnprintf(NULL, sent[nsent].text, LINE, pattern, vl);
  va_end(vl);
  sent[nsent++].to = to;
}

static char fake_mb;
struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{
  (void)dest; (void)format;
  return (struct MsgBuf *)&fake_mb;
}
unsigned int msgq_bufleft(struct MsgBuf *mb) { (void)mb; return 400; }
void msgq_clean(struct MsgBuf *mb) { (void)mb; }

int feature_bool(enum Feature feat)
{
  if (feat == FEAT_CAP_labeled_response)
    return 0;                          /* unlabeled replies */
  return 1;
}
int feature_int(enum Feature feat) { (void)feat; return 100; }
const char *feature_str(enum Feature feat)
{
  if (feat == FEAT_SASL_SERVER)
    return sasl_server;
  if (feat == FEAT_SASL_DEFAULT_MECHANISMS)
    return default_mechs;
  return "";
}

int sasl_local_available(void) { return local_mechs != NULL; }
const char *sasl_local_mechanisms(void) { return local_mechs; }
int auth_iauth_handles_sasl(void) { return iauth_sasl; }
const char *auth_iauth_sasl_mechs(void)
{
  return iauth_sasl ? iauth_mechs : NULL;
}
int authtoken_service_count(void) { return 0; }
const char *get_vapid_pubkey(void) { return NULL; }

/* The servers linked now.  A server that left is out of this table
 * before sasl_mechanisms_server_gone() runs, as it is out of the hash
 * when free_client() runs. */
#define MAXSRV 4
static struct Client *linked[MAXSRV];

struct Client *find_match_server(char *mask)
{
  int i;
  for (i = 0; i < MAXSRV; i++)
    if (linked[i] && match(mask, cli_name(linked[i])) == 0)
      return linked[i];
  return NULL;
}

int auth_cap_start(struct AuthRequest *auth) { (void)auth; return 0; }
int auth_cap_done(struct AuthRequest *auth) { (void)auth; return 0; }
void cap_dependents_drop(struct Client *cptr, const struct CapSet *before,
                         const struct CapSet *after)
{ (void)cptr; (void)before; (void)after; }
/* Not a bouncer session: the active set is the connection's own. */
void bounce_recompute_session_caps(struct Client *primary)
{ *cli_active(primary) = *cli_active_own(primary); }
void bounce_emit_alias_caps(struct Client *cptr) { (void)cptr; }
void metadata_sub_free(struct Client *cptr) { (void)cptr; }
int labeled_batch_start(struct Client *sptr) { (void)sptr; return 0; }
void labeled_batch_end(struct Client *sptr) { (void)sptr; }
const char *batch_current_id(struct Client *cli) { (void)cli; return ""; }
int send_reply(struct Client *to, int reply, ...)
{ (void)to; (void)reply; return 0; }
void debug(int level, const char *form, ...) { (void)level; (void)form; }
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{ (void)subsys; (void)severity; (void)flags; (void)fmt; }

/* ====================================================================
 * Fake clients and servers
 * ==================================================================== */

#define MAXOBJ 8
static struct Client *made[MAXOBJ];
static int nmade;

static struct Client *fake(const char *name, unsigned int status)
{
  struct Client *c = calloc(1, sizeof(*c));

  assert_non_null(c);
  assert_true(nmade < MAXOBJ);
  made[nmade++] = c;
  ircd_strncpy(cli_name(c), name, sizeof(c->cli_name));
  cli_status(c) = status;
  return c;
}

/** A registered local user that did CAP LS 302 (cap-notify implied);
 * its CAP LS reply stays in the sent record. */
static struct Client *user302_ls(const char *nick)
{
  struct Client *c = fake(nick, STAT_USER);
  char sub[] = "LS", ver[] = "302";
  char *parv[4] = { "CAP", sub, ver, NULL };

  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  cli_next(c) = GlobalClientList;
  GlobalClientList = c;
  m_cap(c, c, 3, parv);
  return c;
}

/** The same, its CAP LS reply not recorded: the sent record is what the
 * code under test sends. */
static struct Client *user302(const char *nick)
{
  int from = nsent;
  struct Client *c = user302_ls(nick);

  nsent = from;
  return c;
}

/** A linked server. */
static struct Client *server(const char *name)
{
  struct Client *c = fake(name, STAT_SERVER);
  int i;

  for (i = 0; i < MAXSRV && linked[i]; i++)
    ;
  assert_true(i < MAXSRV);
  linked[i] = c;
  UserStats.servers++;
  return c;
}

/** @a srv leaves: out of the table, then what free_client() does. */
static void server_leaves(struct Client *srv)
{
  int i;

  for (i = 0; i < MAXSRV; i++)
    if (linked[i] == srv)
      linked[i] = NULL;
  UserStats.servers--;
  sasl_mechanisms_server_gone(srv);
}

/** What CAP LS 302 says of sasl to a new client: "sasl=<value>", "sasl",
 * or "" when it is not listed.  Leaves nothing in the sent record. */
static const char *ls_sasl(void)
{
  static char out[LINE];
  struct Client *c;
  int from = nsent, i;

  out[0] = '\0';
  c = user302_ls("lsprobe");
  for (i = from; i < nsent; i++) {
    const char *p = strstr(sent[i].text, "sasl");
    if (p && (p[-1] == ' ' || p[-1] == ':')) {
      size_t n = strcspn(p, " ");
      if (n >= sizeof(out))
        n = sizeof(out) - 1;
      memcpy(out, p, n);
      out[n] = '\0';
    }
  }
  nsent = from;
  /* Off the client list again: it is not one of the test's clients. */
  GlobalClientList = cli_next(c);
  return out;
}

static int setup(void **state)
{
  (void)state;
  local_mechs = NULL;
  sasl_server = "*";
  default_mechs = "";
  iauth_sasl = 0;
  iauth_mechs = NULL;
  memset(linked, 0, sizeof(linked));
  GlobalClientList = NULL;
  UserStats.servers = 1;               /* me */
  ircd_strncpy(cli_name(&me), "irc.test", sizeof(me.cli_name));
  /* Nothing stored, nothing announced to clients. */
  set_sasl_mechanisms(NULL);
  send_cap_notify("sasl", 0, NULL);
  nsent = 0;
  return 0;
}

static int teardown(void **state)
{
  (void)state;
  while (nmade > 0) {
    struct Client *c = made[--nmade];
    free(cli_connect(c));
    free(c);
  }
  GlobalClientList = NULL;
  return 0;
}

/* ====================================================================
 * B1: the server's own Keycloak tier healthy
 * ==================================================================== */

/** (a) A list services announce changes nothing clients are told: CAP LS
 * gives the tier's list before and after, and no CAP NEW / DEL is sent. */
static void local_tier_list_stored_tells_nothing(void **state)
{
  (void)state;
  local_mechs = "PLAIN,OAUTHBEARER";
  sasl_server = "x3.test";
  server("x3.test");
  user302("n");
  assert_string_equal(ls_sasl(), "sasl=PLAIN,OAUTHBEARER");
  nsent = 0;

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,OAUTHBEARER");

  /* A different list, and the same one again: still nothing. */
  sasl_mechanisms_announced("PLAIN");
  sasl_mechanisms_announced("PLAIN");
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,OAUTHBEARER");
}

/** (b) The services server leaving clears the list services announced,
 * and tells nothing: local SASL still works, CAP LS is unchanged. */
static void local_tier_services_leave_tells_nothing(void **state)
{
  struct Client *x3;
  (void)state;

  local_mechs = "PLAIN,OAUTHBEARER";
  sasl_server = "x3.test";
  x3 = server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(x3);
  assert_null(get_sasl_mechanisms());
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,OAUTHBEARER");
}

/** (b) The same with SASL_SERVER "*": any server leaving clears the list,
 * and still tells nothing. */
static void local_tier_any_split_tells_nothing(void **state)
{
  struct Client *hub;
  (void)state;

  local_mechs = "PLAIN,OAUTHBEARER";
  server("x3.test");
  hub = server("hub.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(hub);
  assert_null(get_sasl_mechanisms());
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,OAUTHBEARER");
}

/* ====================================================================
 * B1: no Keycloak tier (or one configured but unhealthy)
 * ==================================================================== */

/** (c) The first list: one CAP NEW with it. */
static void no_tier_first_list_is_new(void **state)
{
  struct Client *n;
  (void)state;

  sasl_server = "x3.test";
  server("x3.test");
  n = user302("n");
  assert_string_equal(ls_sasl(), "");

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, n);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN,EXTERNAL");
  assert_string_equal(ls_sasl(), "sasl=PLAIN,EXTERNAL");
}

/** (c) With SASL_DEFAULT_MECHANISMS, the list replaces the default value
 * CAP LS gave: a CAP NEW with the new value. */
static void no_tier_list_over_default_is_new_value(void **state)
{
  (void)state;

  default_mechs = "PLAIN";
  server("x3.test");
  user302("n");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN,EXTERNAL");
}

/** ... and nothing when the list is the default value already. */
static void no_tier_list_equal_to_default_tells_nothing(void **state)
{
  (void)state;

  default_mechs = "PLAIN,EXTERNAL";
  server("x3.test");
  user302("n");

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,EXTERNAL");
}

/** (d) The same list again: nothing; a different list: CAP NEW with it. */
static void no_tier_same_list_again_tells_nothing(void **state)
{
  (void)state;

  server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 0);

  sasl_mechanisms_announced("PLAIN");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN");
}

/** (e) A server that does not match SASL_SERVER leaving: the list stays,
 * nothing is sent. */
static void no_tier_other_server_leaves_list_kept(void **state)
{
  struct Client *leaf;
  (void)state;

  sasl_server = "x3.test";
  server("x3.test");
  leaf = server("leaf.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(leaf);
  assert_string_equal(get_sasl_mechanisms(), "PLAIN,EXTERNAL");
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,EXTERNAL");
}

/** (f) The services server, named in SASL_SERVER, leaving: the list is
 * cleared and sasl is no longer offered (no server to relay to), so CAP
 * DEL -- although the server is already out of the server table when the
 * clear runs. */
static void no_tier_named_services_leave_is_del(void **state)
{
  struct Client *x3;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  x3 = server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(x3);
  assert_null(get_sasl_mechanisms());
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
  assert_string_equal(ls_sasl(), "");
}

/** (f) SASL_SERVER "*", a server leaving: the list is cleared and the
 * value falls back to SASL_DEFAULT_MECHANISMS: CAP NEW with it. */
static void no_tier_split_falls_back_to_default(void **state)
{
  struct Client *hub;
  (void)state;

  default_mechs = "PLAIN";
  server("x3.test");
  hub = server("hub.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(hub);
  assert_null(get_sasl_mechanisms());
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
}

/** (f) ... nothing when the default is the value already ... */
static void no_tier_split_default_same_tells_nothing(void **state)
{
  struct Client *hub;
  (void)state;

  default_mechs = "PLAIN,EXTERNAL";
  server("x3.test");
  hub = server("hub.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(hub);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,EXTERNAL");
}

/** (f) ... and CAP DEL when there is no default. */
static void no_tier_split_no_default_is_del(void **state)
{
  struct Client *hub;
  (void)state;

  server("x3.test");
  hub = server("hub.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(hub);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
  assert_string_equal(ls_sasl(), "");
}

/** An empty list services announce withdraws the list they announced. */
static void empty_list_withdraws_announced_list(void **state)
{
  (void)state;

  server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  sasl_mechanisms_announced("");
  assert_null(get_sasl_mechanisms());
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
}

/* ====================================================================
 * IAuth's list (a server that never receives "SASL * * M")
 * ==================================================================== */

/** IAuth's list is stored and told as it always was: a CAP NEW with the
 * list when it is first stored (even past the Keycloak tier's value), a
 * CAP DEL then a CAP NEW with IAuth's list when a server matching
 * SASL_SERVER leaves. */
static void iauth_list_told_as_before(void **state)
{
  struct Client *hub;
  (void)state;

  local_mechs = "PLAIN,OAUTHBEARER";
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  hub = server("hub.test");
  user302("n");

  set_sasl_mechanisms("PLAIN");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN");
  nsent = 0;

  server_leaves(hub);
  assert_string_equal(get_sasl_mechanisms(), "PLAIN");
  assert_int_equal(nsent, 2);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
  assert_string_equal(sent_text(1), "CAP n NEW :sasl=PLAIN");
}

/** A server with only SASL_DEFAULT_MECHANISMS: any server leaving under
 * SASL_SERVER "*" sends CAP DEL, as it always did. */
static void default_only_split_told_as_before(void **state)
{
  struct Client *hub;
  (void)state;

  default_mechs = "PLAIN";
  hub = server("hub.test");
  user302("n");

  server_leaves(hub);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
}

/** IAuth's list taking over when the services server leaves: one change,
 * told as a change (here a CAP NEW with IAuth's list), and IAuth's list
 * is the stored one again, so IAuth's own updates go on applying. */
static void services_leave_falls_back_to_iauth_once(void **state)
{
  struct Client *x3;
  (void)state;

  sasl_server = "x3.test";
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  x3 = server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(x3);
  assert_string_equal(get_sasl_mechanisms(), "PLAIN");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN");
}

/** ... and nothing at all with the Keycloak tier healthy. */
static void services_leave_falls_back_to_iauth_local_tier(void **state)
{
  struct Client *x3;
  (void)state;

  local_mechs = "PLAIN,OAUTHBEARER";
  sasl_server = "x3.test";
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  x3 = server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  server_leaves(x3);
  assert_string_equal(get_sasl_mechanisms(), "PLAIN");
  assert_int_equal(nsent, 0);
}

/** IAuth replacing a list services announced (it does when its previous
 * list was the same text) is told as the change it is. */
static void iauth_replacing_announced_list_is_a_change(void **state)
{
  (void)state;

  local_mechs = "PLAIN,OAUTHBEARER";
  server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  nsent = 0;

  set_sasl_mechanisms("PLAIN");
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN,OAUTHBEARER");
}

/* ====================================================================
 * The local Keycloak tier's health changes
 * ==================================================================== */

#define L_MECHS "PLAIN,OAUTHBEARER"     /* the tier's value */

/** The tier's health changes as sasl_mark_unhealthy() / sasl_mark_healthy()
 * change it: what CAP LS says is taken before the flag flips and the
 * difference told after (sasl_handler_cmocka's
 * health_change_tells_the_difference pins that the real functions do
 * these steps, in this order, once per change).
 * @param[in] mechs The tier's list after: NULL = unhealthy. */
static void tier_health(const char *mechs)
{
  struct sasl_told before;

  sasl_told_snapshot(&before);
  local_mechs = mechs;
  sasl_tell_change(&before);
}

/** 1. Services linked with a different list S: the tier going down moves
 * the value to S (one CAP NEW, no CAP DEL); recovery moves it back. */
static void health_services_list_differs_is_new_value(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 0);

  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN,EXTERNAL");
  assert_string_equal(ls_sasl(), "sasl=PLAIN,EXTERNAL");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=" L_MECHS);
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);
}

/** 2. ... the same list as the tier's: nothing either way. */
static void health_services_list_same_tells_nothing(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  server("x3.test");
  user302("n");
  sasl_mechanisms_announced(L_MECHS);

  tier_health(NULL);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);

  tier_health(L_MECHS);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);
}

/** 3. Services linked, no list stored, a default D: the tier going down
 * moves the value to D; recovery moves it back. */
static void health_services_default_is_new_value(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  server("x3.test");
  user302("n");

  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=" L_MECHS);
}

/** 3. ... a default equal to the tier's list: nothing either way. */
static void health_services_default_same_tells_nothing(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = L_MECHS;
  server("x3.test");
  user302("n");

  tier_health(NULL);
  assert_int_equal(nsent, 0);
  tier_health(L_MECHS);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);
}

/** 4. No fallback (no services server linked, no list, no default, no
 * IAuth): CAP DEL when the tier goes down, CAP NEW with its list when it
 * recovers -- what the server always sent. */
static void health_no_fallback_del_then_new(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  user302("n");

  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
  assert_string_equal(ls_sasl(), "");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=" L_MECHS);
}

/** 4. ... with SASL_SERVER "*" (the default) and only this server: the
 * same. */
static void health_no_fallback_any_server_del_then_new(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  user302("n");

  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n DEL :sasl");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=" L_MECHS);
}

/** 5. A step that changes nothing CAP LS says tells nothing (the real
 * functions do not even tell a call that is no change: sasl_handler). */
static void health_no_change_tells_nothing(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  user302("n");
  tier_health(L_MECHS);
  assert_int_equal(nsent, 0);

  tier_health(NULL);
  nsent = 0;
  tier_health(NULL);
  assert_int_equal(nsent, 0);
}

/** 6. With the tier down and services' list S what clients were told: S
 * again tells nothing, S2 tells CAP NEW with S2. */
static void health_down_then_services_list_changes(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  server("x3.test");
  user302("n");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  tier_health(NULL);
  assert_int_equal(nsent, 1);
  nsent = 0;

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 0);

  sasl_mechanisms_announced("PLAIN,EXTERNAL,SCRAM-SHA-256");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN,EXTERNAL,SCRAM-SHA-256");

  /* Recovery: back to the tier's value, once. */
  nsent = 0;
  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=" L_MECHS);
}

/** IAuth handling SASL with its list I: the tier going down moves the
 * value to I; recovery moves it back. */
static void health_iauth_list_is_new_value(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  user302("n");
  set_sasl_mechanisms("PLAIN");        /* told as it always was */
  nsent = 0;

  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=PLAIN");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), "CAP n NEW :sasl=" L_MECHS);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
#define T(f) cmocka_unit_test_setup_teardown(f, setup, teardown)
    T(local_tier_list_stored_tells_nothing),
    T(local_tier_services_leave_tells_nothing),
    T(local_tier_any_split_tells_nothing),
    T(no_tier_first_list_is_new),
    T(no_tier_list_over_default_is_new_value),
    T(no_tier_list_equal_to_default_tells_nothing),
    T(no_tier_same_list_again_tells_nothing),
    T(no_tier_other_server_leaves_list_kept),
    T(no_tier_named_services_leave_is_del),
    T(no_tier_split_falls_back_to_default),
    T(no_tier_split_default_same_tells_nothing),
    T(no_tier_split_no_default_is_del),
    T(empty_list_withdraws_announced_list),
    T(iauth_list_told_as_before),
    T(default_only_split_told_as_before),
    T(services_leave_falls_back_to_iauth_once),
    T(services_leave_falls_back_to_iauth_local_tier),
    T(iauth_replacing_announced_list_is_a_change),
    T(health_services_list_differs_is_new_value),
    T(health_services_list_same_tells_nothing),
    T(health_services_default_is_new_value),
    T(health_services_default_same_tells_nothing),
    T(health_no_fallback_del_then_new),
    T(health_no_fallback_any_server_del_then_new),
    T(health_no_change_tells_nothing),
    T(health_down_then_services_list_changes),
    T(health_iauth_list_is_new_value),
#undef T
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
