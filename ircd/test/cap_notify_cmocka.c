/*
 * cap_notify_cmocka.c - CAP NEW / DEL as cap-notify clients get them
 *
 * The REAL m_cap.o against fake clients, with the send layer, the
 * features and the SASL / services facts stubbed here:
 * - a CAP NEW that only changes the value of a capability clients know of
 *   (listed by CAP LS or ACKed since its last CAP DEL) goes to CAP 302
 *   clients with the value, and not to an older client, which sees no
 *   values; immediately and from the rehash batch;
 * - a CAP NEW after a CAP DEL, or of a capability nobody has been told of,
 *   goes to both.
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

static int feat_off[FEAT_LAST_F];
static const char *local_mechs;        /* sasl_local_mechanisms() */
static const char *vapid_key;          /* get_vapid_pubkey() */

/* ====================================================================
 * What the code under test sent
 * ==================================================================== */

#define LINE 600
#define MAXREC 64

static struct { struct Client *to; char text[LINE]; } sent[MAXREC];
static int nsent;

static int sent_count_to(struct Client *to)
{
  int i, n = 0;
  for (i = 0; i < nsent; i++)
    if (sent[i].to == to)
      n++;
  return n;
}

static const char *sent_to(struct Client *to, int nth)
{
  int i;
  for (i = 0; i < nsent; i++)
    if (sent[i].to == to && nth-- == 0)
      return sent[i].text;
  return "";
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
  return !feat_off[feat];
}
int feature_int(enum Feature feat) { (void)feat; return 100; }
const char *feature_str(enum Feature feat)
{
  if (feat == FEAT_SASL_SERVER)
    return "*";
  return "";
}

int sasl_local_available(void) { return local_mechs != NULL; }
const char *sasl_local_mechanisms(void) { return local_mechs; }
const char *get_sasl_mechanisms(void) { return NULL; }
int auth_iauth_handles_sasl(void) { return 0; }
const char *auth_iauth_sasl_mechs(void) { return NULL; }
struct Client *find_match_server(char *mask) { (void)mask; return NULL; }
struct Client *find_match_server_except(char *mask, struct Client *except)
{ (void)mask; (void)except; return NULL; }
int authtoken_service_count(void) { return 0; }
const char *get_vapid_pubkey(void) { return vapid_key; }

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
/* m_cap.o calls Debug() once #288 is in; unused until then. */
void debug(int level, const char *form, ...) { (void)level; (void)form; }
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{ (void)subsys; (void)severity; (void)flags; (void)fmt; }

/* ====================================================================
 * Fake clients
 * ==================================================================== */

#define MAXOBJ 8
static struct Client *made[MAXOBJ];
static int nmade;

/** A registered local user, CAP 302 (so cap-notify is implied). */
static struct Client *user(const char *nick)
{
  struct Client *c = calloc(1, sizeof(*c));

  assert_non_null(c);
  assert_true(nmade < MAXOBJ);
  made[nmade++] = c;
  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  ircd_strncpy(cli_name(c), nick, sizeof(c->cli_name));
  cli_status(c) = STAT_USER;
  cli_next(c) = GlobalClientList;
  GlobalClientList = c;
  return c;
}

static void cap(struct Client *c, const char *sub, const char *list)
{
  char subbuf[16], listbuf[256];
  char *parv[4] = { "CAP", subbuf, listbuf, NULL };

  ircd_strncpy(subbuf, sub, sizeof(subbuf));
  ircd_strncpy(listbuf, list ? list : "", sizeof(listbuf));
  m_cap(c, c, list ? 3 : 2, parv);
}

static int setup(void **state)
{
  (void)state;
  memset(feat_off, 0, sizeof(feat_off));
  local_mechs = NULL;
  vapid_key = NULL;
  nsent = 0;
  GlobalClientList = NULL;
  ircd_strncpy(cli_name(&me), "irc.test", sizeof(me.cli_name));
  /* Nothing is announced: withdraw what an earlier test's clients heard. */
  send_cap_notify("draft/multiline", 0, NULL);
  send_cap_notify("draft/chathistory", 0, NULL);
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
 * Tests
 * ==================================================================== */

/** A 302 client and a pre-302 one with cap-notify. */
static void two(struct Client **n, struct Client **o)
{
  *n = user("n");
  cap(*n, "LS", "302");
  *o = user("o");
  cap(*o, "LS", NULL);
  cap(*o, "REQ", "cap-notify");
  nsent = 0;
}

/** A value change is a CAP NEW for the 302 client only; the capability
 * switched off and on again is news for both. */
static void value_change_only_to_302(void **state)
{
  struct Client *n, *o;
  (void)state;

  two(&n, &o);                         /* both listed draft/multiline */
  send_cap_notify("draft/multiline", 1, "max-lines=50");
  assert_int_equal(sent_count_to(n), 1);
  assert_string_equal(sent_to(n, 0), "CAP n NEW :draft/multiline=max-lines=50");
  assert_int_equal(sent_count_to(o), 0);

  nsent = 0;
  send_cap_notify("draft/multiline", 0, NULL);
  assert_string_equal(sent_to(n, 0), "CAP n DEL :draft/multiline");
  assert_string_equal(sent_to(o, 0), "CAP o DEL :draft/multiline");

  nsent = 0;
  send_cap_notify("draft/multiline", 1, "max-lines=50");
  assert_string_equal(sent_to(n, 0), "CAP n NEW :draft/multiline=max-lines=50");
  assert_string_equal(sent_to(o, 0), "CAP o NEW :draft/multiline");
}

/** The same from the rehash batch: the pre-302 client gets the
 * capability that came back, not the one whose value changed. */
static void batch_value_change_only_to_302(void **state)
{
  struct Client *n, *o;
  (void)state;

  two(&n, &o);
  send_cap_notify("draft/multiline", 0, NULL);
  nsent = 0;
  cap_notify_begin_batch();
  send_cap_notify("draft/multiline", 1, "max-lines=50");
  send_cap_notify("draft/chathistory", 1, "77");
  send_cap_notify("draft/multiline", 1, "max-lines=60");
  cap_notify_flush();
  assert_int_equal(sent_count_to(n), 1);
  assert_string_equal(sent_to(n, 0),
                      "CAP n NEW :draft/multiline=max-lines=60 draft/chathistory=77");
  assert_int_equal(sent_count_to(o), 1);
  assert_string_equal(sent_to(o, 0), "CAP o NEW :draft/multiline");
}

/** A capability a client knows of from its CAP ACK alone counts. */
static void acked_counts_as_known(void **state)
{
  struct Client *o = user("o");
  (void)state;

  cap(o, "REQ", "cap-notify draft/chathistory");
  nsent = 0;
  send_cap_notify("draft/chathistory", 1, "77");
  assert_int_equal(nsent, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(value_change_only_to_302, setup, teardown),
    cmocka_unit_test_setup_teardown(batch_value_change_only_to_302, setup, teardown),
    cmocka_unit_test_setup_teardown(acked_counts_as_known, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
