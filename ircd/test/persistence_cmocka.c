/*
 * persistence_cmocka.c - which connections reach the PERSISTENCE extras
 *
 * ATTACH, DETACH, LIST, PROFILE and REPLAY are not the draft/persistence
 * specification's (it defines STATUS, GET and SET, and says implementations
 * SHOULD ignore unrecognized subcommands, to be compatible with future
 * extensions).  evilnet.github.io/persistence announces them; it does not
 * gate them, and neither does PERSISTENCE_DRAFT_EXTRAS: a bouncer user on a
 * client that knows neither cap must still be able to type
 * /quote PERSISTENCE REPLAY SET OFF.  Each extra checks the account itself.
 *
 * Also: the restore batch's type.
 *
 * The real m_persistence.o; the ircd around it is stubbed here.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "bouncer_session.h"
#include "capab.h"
#include "class.h"
#include "client.h"
#include "handlers.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "metadata.h"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#include "persistence_profile.h"
#pragma GCC diagnostic pop
#include "s_conf.h"
#include "send.h"
#include "struct.h"
#include "webpush.h"

/* ------------------------------------------------------------------ */
/* The ircd around m_persistence.c                                     */
/* ------------------------------------------------------------------ */

struct Client me;
int log_inassert;
void log_write(enum LogSys subsys, enum LogLevel severity,
               unsigned int flags, const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

/* PERSISTENCE_DRAFT_EXTRAS is the test's to set; every other feature is
 * off. */
static int draft_extras;
int feature_bool(enum Feature feat)
{
  return feat == FEAT_PERSISTENCE_DRAFT_EXTRAS ? draft_extras : 0;
}

/* What the client was sent: the last FAIL's code and description, and the
 * last other line. */
static char fail_code[64];
static char fail_desc[128];
static char last_line[512];
static int n_fail, n_lines;

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  (void)to; (void)command; (void)context;
  n_fail++;
  snprintf(fail_code, sizeof(fail_code), "%s", code);
  snprintf(fail_desc, sizeof(fail_desc), "%s", description);
}

void send_fail_ctx(struct Client *to, const char *command, const char *code,
                   const char *description, const char *context_fmt, ...)
{
  (void)context_fmt;
  send_fail(to, command, code, NULL, description);
}

void sendrawto_one_answer(struct Client *to, const char *pattern, ...)
{
  (void)to;
  n_lines++;
  /* The patterns here use only %s. */
  {
    va_list vl;
    va_start(vl, pattern);
    vsnprintf(last_line, sizeof(last_line), pattern, vl);
    va_end(vl);
  }
}

int labeled_batch_defer(struct Client *sptr) { (void)sptr; return 0; }

/* No sessions, no stored settings, no profiles but "default". */
struct BouncerSession *bounce_get_session(struct Client *cptr)
{ (void)cptr; return NULL; }
struct BouncerSession *bounce_should_hold(struct Client *cptr)
{ (void)cptr; return NULL; }
struct AccountSessions *bounce_find_by_account(const char *account)
{ (void)account; return NULL; }
int bounce_end_asker_applies(enum bounce_end_route route)
{ (void)route; return 1; }
enum bounce_end_route bounce_member_end_route(struct BouncerSession *session)
{ (void)session; return (enum bounce_end_route)0; }
enum bounce_end_route bounce_member_end(struct BouncerSession *session,
                                        struct Client *caller,
                                        struct Client *cptr,
                                        enum bounce_member_end how,
                                        const char *reason)
{
  (void)session; (void)caller; (void)cptr; (void)how; (void)reason;
  return (enum bounce_end_route)0;
}
enum bounce_hold_on_plan bounce_hold_on_plan_for(struct Client *cptr)
{ (void)cptr; return (enum bounce_hold_on_plan)0; }
int bounce_hold_on_refused(enum bounce_hold_on_plan plan)
{ (void)plan; return 0; }
void bounce_hold_on_fail(struct Client *to, const char *command,
                         enum bounce_hold_on_plan plan, const char *context)
{ (void)to; (void)command; (void)plan; (void)context; }
enum bounce_hold_on_done bounce_hold_on(struct Client *cptr, int tell_status,
                                        struct BouncerSession **out)
{ (void)cptr; (void)tell_status; (void)out; return BOUNCE_HOLD_ON_NOTHING; }

struct ConnectionClass *get_client_class_conf(struct Client *acptr)
{ (void)acptr; return NULL; }

int metadata_account_get(const char *account, const char *key, char *value)
{ (void)account; (void)key; (void)value; return -1; }
static char written_key[64];
static char written_value[16];
int metadata_account_write(struct Client *src, const char *account,
                           const char *key, const char *value, int vis)
{
  (void)src; (void)account; (void)vis;
  snprintf(written_key, sizeof(written_key), "%s", key);
  snprintf(written_value, sizeof(written_value), "%s", value ? value : "");
  return 0;
}
void webpush_forget_account(const char *account) { (void)account; }

int persistence_profile_name_valid(const char *name)
{ (void)name; return 1; }
int persistence_profile_exists(const char *account, const char *name)
{ (void)account; return 0 == strcmp(name, "default"); }
int persistence_profile_get_effective(const char *account, const char *profile,
                                      const char *key, char *value,
                                      size_t value_len)
{ (void)account; (void)profile; (void)key; (void)value; (void)value_len; return -1; }
int persistence_profile_set(const char *account, const char *profile,
                            const char *key, const char *value)
{ (void)account; (void)profile; (void)key; (void)value; return 0; }
int persistence_profile_create(const char *account, const char *name,
                               const char *parent)
{ (void)account; (void)name; (void)parent; return 0; }
int persistence_profile_delete(const char *account, const char *name)
{ (void)account; (void)name; return 0; }
int persistence_profile_rename(const char *account, const char *old_name,
                               const char *new_name)
{ (void)account; (void)old_name; (void)new_name; return 0; }
int persistence_profile_list(const char *account,
                             persistence_profile_list_cb cb, void *cookie)
{ (void)account; (void)cb; (void)cookie; return 0; }
int persistence_profile_channels_add(const char *account, const char *profile,
                                     const char *channel)
{ (void)account; (void)profile; (void)channel; return 0; }
int persistence_profile_channels_remove(const char *account,
                                        const char *profile,
                                        const char *channel)
{ (void)account; (void)profile; (void)channel; return 0; }
int persistence_profile_channels_clear(const char *account, const char *profile)
{ (void)account; (void)profile; return 0; }
int persistence_profile_channels_effective(const char *account,
                                           const char *profile,
                                           char *out, size_t out_len)
{ (void)account; (void)profile; (void)out; (void)out_len; return -1; }

/* ------------------------------------------------------------------ */
/* Fixtures                                                            */
/* ------------------------------------------------------------------ */

static struct Client cli;
static struct Connection con;
static struct User usr;

/* A local connection that negotiated no capability at all, logged in to
 * no account, with the transition flag off: the one the gate refused. */
static int setup(void **state)
{
  (void)state;
  memset(&cli, 0, sizeof(cli));
  memset(&con, 0, sizeof(con));
  memset(&usr, 0, sizeof(usr));
  memset(&me, 0, sizeof(me));
  strcpy(cli_name(&me), "test.server");
  cli_connect(&cli) = &con;
  cli_from(&cli) = &cli;
  cli_status(&cli) = STAT_USER;
  cli_user(&cli) = &usr;
  draft_extras = 0;
  n_fail = n_lines = 0;
  fail_code[0] = fail_desc[0] = last_line[0] = '\0';
  written_key[0] = written_value[0] = '\0';
  return 0;
}

static void log_in(void)
{
  SetFlag(&cli, FLAG_ACCOUNT);
  strcpy(cli_user(&cli)->account, "alice");
}

static void run(const char *sub, const char *a, const char *b)
{
  char p1[32], p2[32], p3[32];
  char *parv[5] = { NULL, p1, NULL, NULL, NULL };
  int parc = 2;

  snprintf(p1, sizeof(p1), "%s", sub);
  if (a) { snprintf(p2, sizeof(p2), "%s", a); parv[parc++] = p2; }
  if (b) { snprintf(p3, sizeof(p3), "%s", b); parv[parc++] = p3; }
  m_persistence(&cli, &cli, parc, parv);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* Without the vendor cap and with PERSISTENCE_DRAFT_EXTRAS off, every
 * extra is still dispatched: logged out, each answers ACCOUNT_REQUIRED
 * (its own check), not "Unknown PERSISTENCE subcommand". */
static void test_extras_dispatch_without_cap(void **state)
{
  static const char *const extras[] = { "REPLAY", "PROFILE", "DETACH", "LIST" };
  unsigned int i;
  (void)state;

  for (i = 0; i < sizeof(extras) / sizeof(extras[0]); i++) {
    n_fail = 0;
    fail_code[0] = '\0';
    run(extras[i], "GET", NULL);
    assert_int_equal(n_fail, 1);
    assert_string_equal(fail_code, "ACCOUNT_REQUIRED");
  }

  /* ATTACH is registration's: an unregistered connection that has not
   * completed SASL. */
  cli_status(&cli) = STAT_UNKNOWN;
  cli_user(&cli) = NULL;
  n_fail = 0;
  run("ATTACH", "default", NULL);
  assert_int_equal(n_fail, 1);
  assert_string_equal(fail_code, "ACCOUNT_REQUIRED");
}

/* The case the gate broke: a bouncer user whose client knows neither cap
 * turns auto-replay off by hand. */
static void test_replay_set_without_cap(void **state)
{
  (void)state;
  log_in();

  run("REPLAY", "SET", "OFF");
  assert_int_equal(n_fail, 0);
  assert_string_equal(written_key, "draft/persistence/auto-replay");
  assert_string_equal(written_value, "0");
  assert_string_equal(last_line, ":test.server PERSISTENCE REPLAY STATUS DEFAULT OFF");
}

/* LIST for a logged-in connection without the cap: the (empty) list. */
static void test_list_without_cap(void **state)
{
  (void)state;
  log_in();

  run("LIST", NULL, NULL);
  assert_int_equal(n_fail, 0);
  assert_string_equal(last_line, ":test.server PERSISTENCE ENDOFLIST");
}

/* The transition flag changes nothing here either way. */
static void test_flag_does_not_gate(void **state)
{
  (void)state;
  log_in();

  draft_extras = 1;
  run("LIST", NULL, NULL);
  draft_extras = 0;
  run("LIST", NULL, NULL);
  assert_int_equal(n_fail, 0);
  assert_int_equal(n_lines, 2);
}

/* SET DEFAULT is answered with its STATUS; the fork's "PERSISTENCE SET"
 * line before it goes only while PERSISTENCE_DRAFT_EXTRAS is on (or to a
 * connection with the vendor cap), never to a spec client otherwise. */
static void test_set_echo_only_for_old_clients(void **state)
{
  (void)state;
  log_in();

  draft_extras = 0;
  n_lines = 0;
  run("SET", "DEFAULT", NULL);
  assert_int_equal(n_fail, 0);
  assert_int_equal(n_lines, 1);
  assert_non_null(strstr(last_line, "PERSISTENCE STATUS"));

  draft_extras = 1;
  n_lines = 0;
  run("SET", "DEFAULT", NULL);
  assert_int_equal(n_lines, 2);
  assert_non_null(strstr(last_line, "PERSISTENCE STATUS"));
  draft_extras = 0;
}

/* A connection that negotiated the vendor cap gets the SET line with the
 * transition flag off. */
static void test_set_echo_for_vendor_cap(void **state)
{
  (void)state;
  log_in();
  CapSet(cli_active_own(&cli), CAP_EVILNET_PERSISTENCE);

  run("SET", "DEFAULT", NULL);
  assert_int_equal(n_fail, 0);
  assert_int_equal(n_lines, 2);
  assert_non_null(strstr(last_line, "PERSISTENCE STATUS"));
}

/* The restore batch's type: the vendor cap's for a connection that has
 * it, the old one for any other while the flag is on, none otherwise. */
static void test_restore_batch_type(void **state)
{
  struct CapSet *caps = cli_active_own(&cli);
  const char *batch_type;

  (void)state;
  CapSet(caps, CAP_EVILNET_PERSISTENCE);
  batch_type = persistence_restore_batch_type(caps, 0);
  assert_non_null(batch_type);
  assert_string_equal(batch_type, PERSISTENCE_RESTORE_BATCH);
  assert_string_equal(persistence_restore_batch_type(caps, 1),
                      PERSISTENCE_RESTORE_BATCH);
  CapClr(caps, CAP_EVILNET_PERSISTENCE);
  assert_string_equal(persistence_restore_batch_type(caps, 1),
                      PERSISTENCE_RESTORE_BATCH_OLD);
  assert_null(persistence_restore_batch_type(caps, 0));
}

/* A subcommand this server does not have is still answered, so a client
 * (or a person at /quote) is not left waiting. */
static void test_unknown_subcommand_fails(void **state)
{
  (void)state;
  log_in();

  run("FROB", NULL, NULL);
  assert_int_equal(n_fail, 1);
  assert_int_equal(n_lines, 0);
  assert_string_equal(fail_code, "INVALID_PARAMETERS");
  assert_string_equal(fail_desc, "Unknown PERSISTENCE subcommand");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_extras_dispatch_without_cap, setup),
    cmocka_unit_test_setup(test_replay_set_without_cap, setup),
    cmocka_unit_test_setup(test_list_without_cap, setup),
    cmocka_unit_test_setup(test_flag_does_not_gate, setup),
    cmocka_unit_test_setup(test_set_echo_only_for_old_clients, setup),
    cmocka_unit_test_setup(test_set_echo_for_vendor_cap, setup),
    cmocka_unit_test_setup(test_restore_batch_type, setup),
    cmocka_unit_test_setup(test_unknown_subcommand_fails, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
