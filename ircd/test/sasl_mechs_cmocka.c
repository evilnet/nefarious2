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
 * The ircd remembers what clients were last told (set at the end of
 * start-up), and after a list change, a health change of the local tier
 * (health_* cases), any server leaving or any server's end of burst, tells
 * the difference from what CAP LS now says.
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
static int iauth_policy_pending;       /* auth_iauth_policy_pending() */
static const char *iauth_mechs;        /* auth_iauth_sasl_mechs() */
static int cap_sasl_off;               /* FEAT_CAP_sasl off */

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
  if (feat == FEAT_CAP_sasl)
    return !cap_sasl_off;
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
int auth_iauth_policy_pending(void) { return iauth_policy_pending; }
const char *auth_iauth_sasl_mechs(void)
{
  return iauth_sasl ? iauth_mechs : NULL;
}
int authtoken_service_count(void) { return 0; }
const char *get_vapid_pubkey(void) { return NULL; }
int kc_transport_ready;          /* draft/webpush is offered with it up */

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
/* Lines logged: "SASL server linked ..., enabling SASL ...", "SASL: told
 * clients ..." (the last one's text, formatted), "Services disconnect:
 * clearing SASL ...". */
static int nlog_linked, nlog_told, nlog_clearing;
static char log_told[LINE];
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags;
  if (strstr(fmt, "SASL server linked"))
    nlog_linked++;
  if (strstr(fmt, "SASL: told clients")) {
    va_list vl;
    va_start(vl, fmt);
    vsnprintf(log_told, sizeof(log_told), fmt, vl);
    va_end(vl);
    nlog_told++;
  }
  if (strstr(fmt, "Services disconnect: clearing SASL"))
    nlog_clearing++;
}

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

/* The end of start-up has run (sasl_told_set_now()). */
static int started;

/** The end of start-up, before any client: what CAP LS says is what
 * clients start from.  A case sets its facts before its first client, so
 * that client's arrival stands for it. */
static void start_up(void)
{
  if (!started) {
    started = 1;
    sasl_told_set_now();
  }
}

/** A registered local user that did CAP LS 302 (cap-notify implied);
 * its CAP LS reply stays in the sent record. */
static struct Client *user302_ls(const char *nick)
{
  struct Client *c;
  char sub[] = "LS", ver[] = "302";
  char *parv[4] = { "CAP", sub, ver, NULL };

  start_up();
  c = fake(nick, STAT_USER);

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

/** A linked server behind @a uplink (&me: linked to this server). */
static struct Client *server_via(const char *name, struct Client *uplink)
{
  struct Client *c = fake(name, STAT_SERVER);
  int i;

  cli_serv(c) = calloc(1, sizeof(struct Server));
  assert_non_null(cli_serv(c));
  cli_serv(c)->up = uplink;

  for (i = 0; i < MAXSRV && linked[i]; i++)
    ;
  assert_true(i < MAXSRV);
  linked[i] = c;
  UserStats.servers++;
  return c;
}

/** A server linked to this one. */
static struct Client *server(const char *name)
{
  return server_via(name, &me);
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

/** A server links: into the table (its SERVER line), then its end of
 * burst (what ms_end_of_burst() does). */
static struct Client *server_links(const char *name)
{
  struct Client *c = server(name);

  sasl_mechanisms_server_linked(c);
  return c;
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
  iauth_policy_pending = 0;
  cap_sasl_off = 0;
  nlog_linked = nlog_told = nlog_clearing = 0;
  log_told[0] = '\0';
  started = 0;
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
    free(cli_serv(c));
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN,EXTERNAL");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN,EXTERNAL");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  nsent = 0;

  server_leaves(hub);
  assert_string_equal(get_sasl_mechanisms(), "PLAIN");
  assert_int_equal(nsent, 2);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  assert_string_equal(sent_text(1), ":irc.test CAP n NEW :sasl=PLAIN");
}

/** A server with only SASL_DEFAULT_MECHANISMS under SASL_SERVER "*": CAP
 * LS offers sasl=<default> whatever is linked (this server itself
 * counts), so a server leaving tells nothing.  (309aed9b sent CAP DEL on
 * every split here.) */
static void default_only_any_split_tells_nothing(void **state)
{
  struct Client *hub;
  (void)state;

  default_mechs = "PLAIN";
  hub = server("hub.test");
  user302("n");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");

  server_leaves(hub);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
}

/** ... and a server linking tells nothing either (309aed9b: nothing). */
static void default_only_any_link_tells_nothing(void **state)
{
  (void)state;

  default_mechs = "PLAIN";
  user302("n");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");

  server_links("hub.test");
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
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
 * change it: the flag flips, then clients are told what CAP LS now says
 * (sasl_handler_cmocka's health_change_tells_the_difference pins that the
 * real functions tell once per change, after the flip).
 * @param[in] mechs The tier's list after: NULL = unhealthy. */
static void tier_health(const char *mechs)
{
  local_mechs = mechs;
  sasl_tell_now("health change");
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN,EXTERNAL");
  assert_string_equal(ls_sasl(), "sasl=PLAIN,EXTERNAL");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
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
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
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
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  assert_string_equal(ls_sasl(), "");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
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
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  nsent = 0;

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
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
  assert_string_equal(sent_text(0),
                      ":irc.test CAP n NEW :sasl=PLAIN,EXTERNAL,SCRAM-SHA-256");

  /* Recovery: back to the tier's value, once. */
  nsent = 0;
  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
}

/** IAuth handling SASL with its list I: IAuth's own store told clients
 * sasl=I (raw, as it always was), so the tier going down -- CAP LS now
 * says I -- tells nothing more; recovery moves the value back.  (Task 6
 * pinned a second CAP NEW :sasl=PLAIN at the tier going down.) */
static void health_iauth_list_already_told_tells_nothing(void **state)
{
  (void)state;
  local_mechs = L_MECHS;
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  user302("n");
  set_sasl_mechanisms("PLAIN");        /* told as it always was */
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  nsent = 0;

  tier_health(NULL);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");

  tier_health(L_MECHS);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
}

/* ====================================================================
 * The services server linking or leaving, no list announced
 * ==================================================================== */

/** 1. Healthy tier, SASL_SERVER naming X3, a default other than the
 * tier's list: X3 leaving tells nothing (CAP LS still gives the tier's
 * list). */
static void services_leave_healthy_tier_default_tells_nothing(void **state)
{
  struct Client *x3;
  (void)state;

  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  x3 = server("x3.test");
  user302("n");
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);

  server_leaves(x3);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);
}

/** 2. ... and X3 linking tells nothing. */
static void services_link_healthy_tier_default_tells_nothing(void **state)
{
  (void)state;

  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  server_links("x3.test");
  assert_int_equal(nsent, 0);
  assert_int_equal(nlog_linked, 0);     /* nothing enabled, nothing logged */
  assert_string_equal(ls_sasl(), "sasl=" L_MECHS);
}

/** 3. No tier, a default: X3 linking is CAP NEW with the default, X3
 * leaving is CAP DEL -- as always. */
static void services_no_tier_default_link_new_leave_del(void **state)
{
  struct Client *x3;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");
  assert_string_equal(ls_sasl(), "");

  x3 = server_links("x3.test");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  assert_int_equal(nlog_linked, 1);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
  nsent = 0;

  server_leaves(x3);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  assert_string_equal(ls_sasl(), "");
}

/** 4. No tier, a default: a server not matching SASL_SERVER linking or
 * leaving tells nothing, with X3 linked (its burst over) or not. */
static void other_server_no_tier_default_tells_nothing(void **state)
{
  struct Client *leaf;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  leaf = server_links("leaf.test");
  server_leaves(leaf);
  assert_int_equal(nsent, 0);

  server_links("x3.test");
  assert_int_equal(nsent, 1);           /* X3's CAP NEW :sasl=PLAIN */
  nsent = 0;
  leaf = server_links("leaf.test");
  server_leaves(leaf);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
}

/** No tier, a default: X3 is in the server table, its burst not over,
 * when another server's end of burst comes: CAP LS offers sasl, clients
 * were not told -- one CAP NEW with the default then (no "SASL server
 * linked" log: that server is not X3); X3's own end of burst afterwards
 * tells nothing. */
static void services_mid_burst_other_eob_tells_once(void **state)
{
  struct Client *x3;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  x3 = server("x3.test");
  server_links("leaf.test");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  assert_int_equal(nlog_linked, 0);
  nsent = 0;

  sasl_mechanisms_server_linked(x3);
  assert_int_equal(nsent, 0);
}

/** 5. A configured tier gone unhealthy, a default: X3 leaving is CAP DEL
 * (nothing else offers sasl), X3 linking CAP NEW with the default. */
static void services_unhealthy_tier_default_leave_del_link_new(void **state)
{
  struct Client *x3;
  (void)state;

  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");
  x3 = server_links("x3.test");
  assert_int_equal(nsent, 0);
  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  nsent = 0;

  server_leaves(x3);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  nsent = 0;

  server_links("x3.test");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
}

/** A SASL_SERVER pattern two linked servers match, no tier, a default:
 * while one of them is linked CAP LS offers sasl, so the other linking
 * or leaving tells nothing; the last one leaving is CAP DEL.  (309aed9b:
 * a CAP NEW at the second link and a CAP DEL at the first leave.) */
static void services_pattern_two_matches(void **state)
{
  struct Client *a, *b;
  (void)state;

  sasl_server = "services.*";
  default_mechs = "PLAIN";
  user302("n");

  a = server_links("services.a");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  nsent = 0;

  b = server_links("services.b");
  assert_int_equal(nsent, 0);
  assert_int_equal(nlog_linked, 1);     /* a's only */

  server_leaves(a);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");

  server_leaves(b);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
}

/** IAuth handling SASL (no list from it yet), a default: X3 linking sends
 * what it always did, CAP NEW with the default, untouched by the
 * difference rule. */
static void iauth_services_link_told_as_before(void **state)
{
  (void)state;

  iauth_sasl = 1;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  server_links("x3.test");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  assert_int_equal(nlog_linked, 1);     /* logged as it always was */
}

/** ... and X3 leaving: CAP DEL, then CAP NEW without a value (IAuth has
 * no list), as always. */
static void iauth_services_leave_told_as_before(void **state)
{
  struct Client *x3;
  (void)state;

  iauth_sasl = 1;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  x3 = server("x3.test");
  user302("n");

  server_leaves(x3);
  assert_int_equal(nsent, 2);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  assert_string_equal(sent_text(1), ":irc.test CAP n NEW :sasl");
}

/** With the sasl capability's feature off, CAP LS never offers sasl, so a
 * health change of the tier tells nothing. */
static void health_cap_sasl_off_tells_nothing(void **state)
{
  (void)state;

  cap_sasl_off = 1;
  local_mechs = L_MECHS;
  user302("n");
  assert_string_equal(ls_sasl(), "");

  tier_health(NULL);
  assert_int_equal(nsent, 0);
  tier_health(L_MECHS);
  assert_int_equal(nsent, 0);
}

/* ====================================================================
 * A net burst: the servers behind the linking one came with it
 * ==================================================================== */

/** (a) A SASL_SERVER pattern matches A and B, B behind A; no tier, a
 * default.  A's net burst put both in the server table, and only A sends
 * an end of burst: clients were not told sasl and CAP LS now offers it,
 * so one CAP NEW with the default (and its log line); an end of burst of
 * B's own afterwards tells nothing. */
static void net_burst_brings_services_told_once(void **state)
{
  struct Client *a, *b;
  (void)state;

  sasl_server = "services.*";
  default_mechs = "PLAIN";
  user302("n");

  a = server("services.a");
  b = server_via("services.b", a);
  sasl_mechanisms_server_linked(a);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  assert_int_equal(nlog_linked, 1);
  nsent = 0;

  sasl_mechanisms_server_linked(b);     /* if b sends one of its own */
  assert_int_equal(nsent, 0);
}

/** (b) A linked alone and was told; B, behind A and matching, sends its
 * own end of burst later: clients already hold sasl=<default> -- nothing,
 * and no log line. */
static void server_behind_linked_services_tells_nothing(void **state)
{
  struct Client *a, *b;
  (void)state;

  sasl_server = "services.*";
  default_mechs = "PLAIN";
  user302("n");
  a = server_links("services.a");
  assert_int_equal(nsent, 1);
  nsent = 0;
  nlog_linked = 0;

  b = server_via("services.b", a);
  sasl_mechanisms_server_linked(b);
  assert_int_equal(nsent, 0);
  assert_int_equal(nlog_linked, 0);
}

/** (c) A matching server C already linked elsewhere, and told; A and B
 * (behind A) arrive: A's end of burst tells nothing. */
static void net_burst_with_services_elsewhere_tells_nothing(void **state)
{
  struct Client *a;
  (void)state;

  sasl_server = "services.*";
  default_mechs = "PLAIN";
  user302("n");
  server_links("services.c");
  assert_int_equal(nsent, 1);
  nsent = 0;
  nlog_linked = 0;

  a = server("services.a");
  server_via("services.b", a);
  sasl_mechanisms_server_linked(a);
  assert_int_equal(nsent, 0);
  assert_int_equal(nlog_linked, 0);
}

/** (d) Under SASL_SERVER "*" a net burst changes nothing either: this
 * server itself counts. */
static void any_server_net_burst_tells_nothing(void **state)
{
  struct Client *hub2;
  (void)state;

  default_mechs = "PLAIN";
  user302("n");

  hub2 = server("hub2.test");
  server_via("x3.test", hub2);
  sasl_mechanisms_server_linked(hub2);
  assert_int_equal(nsent, 0);
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
}

/* ====================================================================
 * The sasl capability's feature off
 * ==================================================================== */

/** CAP LS never offers sasl: the services server linking tells
 * nothing.  (309aed9b: CAP NEW :sasl=<default>.) */
static void cap_sasl_off_services_link_tells_nothing(void **state)
{
  (void)state;

  cap_sasl_off = 1;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  server_links("x3.test");
  assert_int_equal(nsent, 0);
  assert_int_equal(nlog_linked, 0);
}

/** ... nor its leaving.  (309aed9b: CAP DEL :sasl.) */
static void cap_sasl_off_services_leave_tells_nothing(void **state)
{
  struct Client *x3;
  (void)state;

  cap_sasl_off = 1;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  x3 = server("x3.test");
  user302("n");

  server_leaves(x3);
  assert_int_equal(nsent, 0);
}

/* ====================================================================
 * What clients were last told: splits, net joins, bursts
 * ==================================================================== */

/** X3 behind hub H links to this server: H's end of burst comes, X3's
 * too (a fresh link). */
static struct Client *x3_behind(struct Client **hub)
{
  struct Client *x3;

  *hub = server("hub2.test");
  x3 = server_via("x3.test", *hub);
  return x3;
}

/** The known issue: no tier, SASL_SERVER naming X3, a default; X3 is
 * behind hub H.  The split takes both: one CAP DEL.  The net join brings
 * both back already burst, and only H's end of burst comes: one CAP NEW
 * with the default (309aed9b..e7774bb2: none, until clients reconnected). */
static void services_behind_hub_split_and_join(void **state)
{
  struct Client *hub, *x3;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");
  x3 = x3_behind(&hub);
  sasl_mechanisms_server_linked(x3);
  sasl_mechanisms_server_linked(hub);
  assert_int_equal(nsent, 1);           /* the first link: NEW */
  nsent = 0;

  server_leaves(x3);                    /* the split: downlink first */
  server_leaves(hub);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  nsent = 0;

  x3 = x3_behind(&hub);                 /* the net join */
  sasl_mechanisms_server_linked(hub);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
}

/** ... and with X3 still bursting, its own end of burst after H's: still
 * one CAP NEW in all. */
static void services_behind_hub_join_then_own_eob(void **state)
{
  struct Client *hub, *x3;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  x3 = x3_behind(&hub);
  sasl_mechanisms_server_linked(hub);
  sasl_mechanisms_server_linked(x3);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
}

/** No tier, a default D: X3 announces S after its burst -- CAP NEW with
 * S once. */
static void services_list_after_burst_is_new(void **state)
{
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");
  server_links("x3.test");
  assert_int_equal(nsent, 1);
  nsent = 0;

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN,EXTERNAL");
}

/** ... with S equal to D: nothing after the CAP NEW the link sent. */
static void services_list_after_burst_same_as_default(void **state)
{
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");
  server_links("x3.test");
  assert_int_equal(nsent, 1);
  nsent = 0;

  sasl_mechanisms_announced("PLAIN");
  assert_int_equal(nsent, 0);
}

/** No tier: X3 announces S during its burst, before any end of burst --
 * clients are told sasl=S exactly once in all, with a default other than
 * S, the same as S, or none. */
static void services_list_during_burst_told_once(void **state)
{
  static const char *const defaults[] = { "PLAIN", "PLAIN,EXTERNAL", "" };
  struct Client *x3;
  int i;
  (void)state;

  sasl_server = "x3.test";
  user302("n");
  for (i = 0; i < 3; i++) {
    default_mechs = defaults[i];
    nsent = 0;

    x3 = server("x3.test");
    sasl_mechanisms_announced("PLAIN,EXTERNAL");
    sasl_mechanisms_server_linked(x3);
    assert_int_equal(nsent, 1);
    assert_string_equal(sent_text(0),
                        ":irc.test CAP n NEW :sasl=PLAIN,EXTERNAL");

    server_leaves(x3);                  /* clears the list: DEL */
    assert_int_equal(nsent, 2);
    assert_string_equal(sent_text(1), ":irc.test CAP n DEL :sasl");
  }
}

/** A health flip while X3 is bursting: the flip tells the default (X3 is
 * in the table); X3's end of burst repeats nothing. */
static void health_flip_during_burst_no_repeat(void **state)
{
  struct Client *x3;
  (void)state;

  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");

  x3 = server("x3.test");
  tier_health(NULL);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  sasl_mechanisms_server_linked(x3);
  assert_int_equal(nsent, 1);
}

/** Start-up with a healthy tier: what clients start from is the tier's
 * list, so the first later event (any end of burst, X3's included) tells
 * nothing. */
static void boot_healthy_tier_first_eob_tells_nothing(void **state)
{
  (void)state;

  local_mechs = L_MECHS;
  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  start_up();
  user302("n");

  server_links("leaf.test");
  server_links("x3.test");
  assert_int_equal(nsent, 0);
}

/** A raw IAuth send, then an event outside IAuth: the comparison starts
 * from what the raw send told.  With the tier healthy (CAP LS: the tier's
 * list), IAuth's store tells sasl=PLAIN as it always did; IAuth then goes
 * and a server's end of burst tells the tier's list -- which it would not
 * if the raw CAP NEW had not been remembered. */
static void iauth_raw_send_then_other_event(void **state)
{
  (void)state;

  local_mechs = L_MECHS;
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  user302("n");
  set_sasl_mechanisms("PLAIN");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=PLAIN");
  nsent = 0;

  iauth_sasl = 0;
  server_links("leaf.test");
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n NEW :sasl=" L_MECHS);
}

/* ====================================================================
 * The end of a rehash
 * ==================================================================== */

/** The reproduction: IAuth handles SASL with list S, SASL_SERVER names X3,
 * which is not linked; clients were told sasl=S.  A rehash replaces the
 * IAuth program: the new instance has no policy yet (does not handle
 * SASL), so CAP LS says "not offered" for now -- the rehash's telling
 * waits, nothing is sent.  The policy then comes with S: IAuth's list is
 * the stored one already, so IAuth stores and sends nothing, and CAP LS
 * and what clients were told agree (a telling finds nothing to send).
 * (b7d707fe: CAP DEL :sasl at the rehash, never corrected.) */
static void rehash_waits_for_iauth_policy(void **state)
{
  (void)state;

  sasl_server = "x3.test";
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  user302("n");
  set_sasl_mechanisms("PLAIN");         /* told, raw, as always */
  assert_int_equal(nsent, 1);
  nsent = 0;

  iauth_sasl = 0;                       /* the new instance */
  iauth_policy_pending = 1;
  sasl_tell_after_rehash();
  assert_int_equal(nsent, 0);

  iauth_sasl = 1;                       /* its O line, then its l line */
  iauth_policy_pending = 0;
  assert_string_equal(ls_sasl(), "sasl=PLAIN");
  assert_int_equal(sasl_tell_now("check"), 0);
  assert_int_equal(nsent, 0);
}

/** An IAuth block a rehash removed: the program is gone when the rehash's
 * telling runs (after auth_close_unused(); conf_include_cmocka pins the
 * order), so the telling sees CAP LS without it -- here no services
 * server linked: CAP DEL :sasl, logged. */
static void rehash_after_iauth_removed_tells(void **state)
{
  (void)state;

  sasl_server = "x3.test";
  iauth_sasl = 1;
  iauth_mechs = "PLAIN";
  user302("n");
  set_sasl_mechanisms("PLAIN");
  nsent = 0;

  iauth_sasl = 0;                       /* removed: no instance at all */
  iauth_policy_pending = 0;
  sasl_tell_after_rehash();
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_text(0), ":irc.test CAP n DEL :sasl");
  assert_int_equal(nlog_told, 1);
  assert_string_equal(log_told, "SASL: told clients CAP DEL :sasl (rehash)");
}

/* ====================================================================
 * Logging
 * ==================================================================== */

/** A hub's end of burst that announces sasl again (X3 back behind it) is
 * logged; "clearing SASL" only when a list is cleared. */
static void told_and_clearing_logged(void **state)
{
  struct Client *hub, *x3;
  (void)state;

  sasl_server = "x3.test";
  default_mechs = "PLAIN";
  user302("n");
  x3 = server("x3.test");
  sasl_mechanisms_server_linked(x3);
  nsent = nlog_told = 0;

  server_leaves(x3);                    /* default only: nothing cleared */
  assert_int_equal(nlog_clearing, 0);
  assert_int_equal(nlog_told, 1);
  assert_string_equal(log_told, "SASL: told clients CAP DEL :sasl (a server left)");

  hub = server("hub2.test");
  x3 = server_via("x3.test", hub);
  sasl_mechanisms_server_linked(hub);
  assert_int_equal(nsent, 2);
  assert_int_equal(nlog_told, 2);
  assert_string_equal(log_told, "SASL: told clients CAP NEW :sasl=PLAIN (end of burst)");

  sasl_mechanisms_announced("PLAIN,EXTERNAL");
  assert_int_equal(nlog_told, 3);
  server_leaves(x3);                    /* services' list: cleared */
  assert_int_equal(nlog_clearing, 1);
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
    T(default_only_any_split_tells_nothing),
    T(default_only_any_link_tells_nothing),
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
    T(health_iauth_list_already_told_tells_nothing),
    T(services_leave_healthy_tier_default_tells_nothing),
    T(services_link_healthy_tier_default_tells_nothing),
    T(services_no_tier_default_link_new_leave_del),
    T(other_server_no_tier_default_tells_nothing),
    T(services_unhealthy_tier_default_leave_del_link_new),
    T(services_pattern_two_matches),
    T(iauth_services_link_told_as_before),
    T(iauth_services_leave_told_as_before),
    T(health_cap_sasl_off_tells_nothing),
    T(net_burst_brings_services_told_once),
    T(server_behind_linked_services_tells_nothing),
    T(net_burst_with_services_elsewhere_tells_nothing),
    T(any_server_net_burst_tells_nothing),
    T(cap_sasl_off_services_link_tells_nothing),
    T(cap_sasl_off_services_leave_tells_nothing),
    T(services_mid_burst_other_eob_tells_once),
    T(services_behind_hub_split_and_join),
    T(services_behind_hub_join_then_own_eob),
    T(services_list_after_burst_is_new),
    T(services_list_after_burst_same_as_default),
    T(services_list_during_burst_told_once),
    T(health_flip_during_burst_no_repeat),
    T(boot_healthy_tier_first_eob_tells_nothing),
    T(iauth_raw_send_then_other_event),
    T(rehash_waits_for_iauth_policy),
    T(rehash_after_iauth_removed_tells),
    T(told_and_clearing_logged),
#undef T
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
