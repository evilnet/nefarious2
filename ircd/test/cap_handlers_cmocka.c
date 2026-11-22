/*
 * cap_handlers_cmocka.c - CAP LS / REQ and CAP NEW / DEL against fake
 * clients.
 *
 * Links the REAL m_cap.o (with the ircd's printf, so every line asserted
 * below is the line that would go on the wire) and stubs what is
 * underneath it: the send layer records instead of sending, the feature
 * table and the SASL / IAuth / services facts are what the test sets.
 *
 * What it pins down (cap_offer_cmocka covers the pure rules):
 * - CAP REQ NAKs the whole request when any capability in it is not
 *   offered now, and still ACKs re-requesting or removing a held one;
 * - CAP NEW sasl carries the mechanism list CAP LS gives, whatever list
 *   the caller had at hand;
 * - CAP NEW draft/webpush carries its vapid= value as CAP LS gives it,
 *   immediately and from the rehash batch.
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
int kc_transport_ready;
void debug(int level, const char *form, ...) { (void)level; (void)form; }
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
  kc_transport_ready = 0;
  nsent = 0;
  GlobalClientList = NULL;
  ircd_strncpy(cli_name(&me), "irc.test", sizeof(me.cli_name));
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

/** A capability whose feature is off is not listed and its REQ is
 * NAKed; one off-offer entry NAKs the whole request. */
static void req_not_offered_naks_whole(void **state)
{
  struct Client *a = user("a");
  (void)state;

  feat_off[FEAT_CAP_multi_prefix] = 1;
  cap(a, "LS", "302");
  nsent = 0;
  cap(a, "REQ", "server-time multi-prefix");
  assert_int_equal(sent_count_to(a), 1);
  assert_string_equal(sent_to(a, 0),
                      ":irc.test CAP a NAK :server-time multi-prefix");
  assert_false(CapHas(cli_capab(a), CAP_SERVERTIME));

  nsent = 0;
  cap(a, "REQ", "server-time");
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a ACK :server-time");
}

/** A held capability the server stopped offering can be requested
 * again and dropped. */
static void req_held_after_feature_off(void **state)
{
  struct Client *a = user("a");
  (void)state;

  cap(a, "LS", "302");
  cap(a, "REQ", "multi-prefix");
  assert_true(CapHas(cli_capab(a), CAP_NAMESX));
  feat_off[FEAT_CAP_multi_prefix] = 1;
  nsent = 0;
  cap(a, "REQ", "multi-prefix");
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a ACK :multi-prefix");
  nsent = 0;
  cap(a, "REQ", "-multi-prefix");
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a ACK :-multi-prefix");
}

/** cap-notify is always ACKed to a CAP 302 client, whatever
 * CAP_cap_notify says ("Servers MUST accept and CAP ACK the request");
 * an older client's request follows the feature. */
static void cap_notify_always_acked_to_302(void **state)
{
  struct Client *a = user("a"), *b = user("b");
  (void)state;

  feat_off[FEAT_CAP_cap_notify] = 1;
  cap(a, "LS", "302");
  nsent = 0;
  cap(a, "REQ", "server-time cap-notify");
  assert_string_equal(sent_to(a, 0),
                      ":irc.test CAP a ACK :cap-notify server-time");

  cap(b, "LS", NULL);
  nsent = 0;
  cap(b, "REQ", "cap-notify");
  assert_string_equal(sent_to(b, 0), ":irc.test CAP b NAK :cap-notify");
}

/** A CAP DEL takes the capability from the client it goes to: CAP LIST
 * no longer has it and a new REQ is judged by what is offered then.
 * Alone and from a batch. */
static void del_takes_the_capability_away(void **state)
{
  struct Client *a = user("a");
  (void)state;

  cap(a, "LS", "302");
  cap(a, "REQ", "multi-prefix server-time");
  assert_true(CapHas(cli_capab(a), CAP_NAMESX));
  feat_off[FEAT_CAP_multi_prefix] = 1;
  nsent = 0;
  send_cap_notify("multi-prefix", 0, NULL);
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a DEL :multi-prefix");
  assert_false(CapHas(cli_capab(a), CAP_NAMESX));
  assert_false(CapHas(cli_active_own(a), CAP_NAMESX));
  assert_true(CapHas(cli_capab(a), CAP_SERVERTIME));
  nsent = 0;
  cap(a, "REQ", "multi-prefix");
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a NAK :multi-prefix");

  feat_off[FEAT_CAP_server_time] = 1;
  nsent = 0;
  cap_notify_begin_batch();
  send_cap_notify("server-time", 0, NULL);
  cap_notify_flush();
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a DEL :server-time");
  assert_false(CapHas(cli_capab(a), CAP_SERVERTIME));
}

/** A DEL for a capability the client is still offered takes nothing and
 * is not sent to it: cap-notify at CAP 302 with its feature switched
 * off.  Nor is that client told when the feature comes back. */
static void del_keeps_what_is_still_offered(void **state)
{
  struct Client *a = user("a");
  (void)state;

  cap(a, "LS", "302");
  cap(a, "REQ", "cap-notify");
  nsent = 0;
  feat_off[FEAT_CAP_cap_notify] = 1;
  send_cap_notify("cap-notify", 0, NULL);
  assert_true(CapHas(cli_capab(a), CAP_CAPNOTIFY));
  assert_int_equal(sent_count_to(a), 0);
  feat_off[FEAT_CAP_cap_notify] = 0;
  send_cap_notify("cap-notify", 1, NULL);
  assert_int_equal(sent_count_to(a), 0);
}

/** A rehash that withdraws more capabilities than one line holds sends
 * them in several lines, cut between names, every name once. */
static void a_long_del_goes_out_in_whole_lines(void **state)
{
  static const char *const names[] = {
    "multi-prefix", "userhost-in-names", "extended-join", "away-notify",
    "account-notify", "server-time", "echo-message", "account-tag",
    "chghost", "invite-notify", "labeled-response", "setname",
    "standard-replies", "no-implicit-names", "draft/no-implicit-names",
    "draft/extended-isupport", "draft/pre-away", "draft/multiline",
    "draft/chathistory", "soju.im/search", "draft/event-playback",
    "draft/message-redaction", "draft/account-registration",
    "draft/read-marker", "draft/channel-rename", "draft/metadata-2",
    "draft/bouncer", "draft/persistence", "draft/oper-tag",
  };
  struct Client *a = user("a");
  size_t i;
  int l, n;
  (void)state;

  cap(a, "LS", "302");
  nsent = 0;
  for (i = 0; i < FEAT_LAST_F; i++)     /* every feature off: CAP LS drops them */
    feat_off[i] = 1;
  cap_notify_begin_batch();
  for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
    send_cap_notify(names[i], 0, NULL);
  cap_notify_flush();
  n = sent_count_to(a);
  assert_true(n >= 2);
  for (l = 0; l < n; l++) {
    assert_true(strlen(sent_to(a, l)) <= 450);
    assert_non_null(strstr(sent_to(a, l), ":irc.test CAP a DEL :"));
  }
  for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    char want[64];
    int hits = 0;

    snprintf(want, sizeof(want), " %s ", names[i]);
    for (l = 0; l < n; l++) {
      char line[600];

      /* " name name ... name " so every name has a space each side */
      snprintf(line, sizeof(line), " %s ", strstr(sent_to(a, l), " :") + 2);
      if (strstr(line, want))
        hits++;
    }
    assert_int_equal(hits, 1);
  }
}

/** CAP NEW sasl carries the mechanism list, even from a caller that had
 * none at hand. */
static void new_sasl_carries_mechanisms(void **state)
{
  struct Client *a = user("a");
  (void)state;

  cap(a, "LS", "302");
  local_mechs = "PLAIN,EXTERNAL";
  nsent = 0;
  send_cap_notify("sasl", 1, NULL);
  assert_int_equal(sent_count_to(a), 1);
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a NEW :sasl=PLAIN,EXTERNAL");
}

/** CAP NEW draft/webpush carries vapid=<key>, as CAP LS 302 lists it;
 * from the batch, the key as it stands at the flush. */
static void new_webpush_carries_vapid(void **state)
{
  struct Client *a = user("a");
  (void)state;

  kc_transport_ready = 1;
  cap(a, "LS", "302");
  vapid_key = "BKey1";
  nsent = 0;
  send_cap_notify("draft/webpush", 1, NULL);
  assert_int_equal(sent_count_to(a), 1);
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a NEW :draft/webpush=vapid=BKey1");

  nsent = 0;
  cap_notify_begin_batch();
  send_cap_notify("draft/webpush", 1, NULL);
  vapid_key = "BKey2";
  cap_notify_flush();
  assert_int_equal(sent_count_to(a), 1);
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a NEW :draft/webpush=vapid=BKey2");

  vapid_key = NULL;                    /* no key: bare, as LS lists it */
  nsent = 0;
  send_cap_notify("draft/webpush", 1, NULL);
  assert_string_equal(sent_to(a, 0), ":irc.test CAP a NEW :draft/webpush");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(req_not_offered_naks_whole, setup, teardown),
    cmocka_unit_test_setup_teardown(req_held_after_feature_off, setup, teardown),
    cmocka_unit_test_setup_teardown(cap_notify_always_acked_to_302, setup, teardown),
    cmocka_unit_test_setup_teardown(del_takes_the_capability_away, setup, teardown),
    cmocka_unit_test_setup_teardown(del_keeps_what_is_still_offered, setup, teardown),
    cmocka_unit_test_setup_teardown(a_long_del_goes_out_in_whole_lines, setup, teardown),
    cmocka_unit_test_setup_teardown(new_sasl_carries_mechanisms, setup, teardown),
    cmocka_unit_test_setup_teardown(new_webpush_carries_vapid, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
