/*
 * send_label_cmocka.c - which line a labeled command's label goes on
 *
 * labeled-response: the server puts a command's label on the one line
 * that answers it (or on the batch holding its lines), and sends a
 * labeled ACK when nothing did.  parse.c decides the ACK from
 * cli_label_responded(), which the send that took the label sets.  Two
 * kinds of line reach the client whose command is being handled:
 *
 *  - an answer that goes out through a fan-out to many clients -- the
 *    PART, TOPIC, KICK or MODE of a channel it is on.  The fan-out tags
 *    every member's copy alike and never with a label, so a labeled PART
 *    came back unlabeled and was then ACKed (issue #216, case 1).
 *    sendcmdto_channel_butserv_respond() gives the copy to the asking
 *    connection its own tags: the command's label, or its
 *    labeled-response batch -- and a bouncer sibling's copy stays as it
 *    was;
 *  - a message the client sent itself.  Without echo-message that line is
 *    the delivered message, which must not carry the label (the spec
 *    allows it only on the echo-message copy), so the command is ACKed
 *    (case 2).  sendcmdto_one_delivery() never takes the label nor joins
 *    the labeled batch.
 *
 * This includes the real send.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps the functions under
 * test and what they call; the ircd around them is stubbed here.  Every
 * line a client is sent is captured at msgq_add() with its tag region.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

/* send.c's headers carry a comment with a slash-star in it, and it has
 * static helpers no caller here keeps; -Wall's reports are send.c's. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wformat-truncation"
#include "../send.c"
#pragma GCC diagnostic pop

/* ------------------------------------------------------------------ */
/* The ircd around send.c                                              */
/* ------------------------------------------------------------------ */

struct Client me;
static struct Connection me_con;
struct Client his;
int log_inassert;
time_t CurrentTime;
static struct ServerStatistics server_stats;
struct ServerStatistics *ServerStats = &server_stats;

/* A captured line: whose sendQ it went to, and its text. */
struct MsgBuf {
  char text[8192];
  int refs;
};

#define MAX_SENT 16
static struct {
  struct Client *to;
  char text[8192];
} sent[MAX_SENT];
static int n_sent;

static struct Client *sendq_owner(struct MsgQ *mq);

struct MsgBuf *msgq_vmake(struct Client *dest, const char *format, va_list vl)
{
  struct MsgBuf *mb = calloc(1, sizeof(*mb));

  assert_non_null(mb);
  ircd_vsnprintf(dest, mb->text, sizeof(mb->text), format, vl);
  mb->refs = 1;
  return mb;
}

struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{
  struct MsgBuf *mb;
  va_list vl;

  va_start(vl, format);
  mb = msgq_vmake(dest, format, vl);
  va_end(vl);
  return mb;
}

void msgq_clean(struct MsgBuf *mb)
{
  if (mb && --mb->refs == 0)
    free(mb);
}

void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio)
{
  (void)prio;
  assert_true(n_sent < MAX_SENT);
  sent[n_sent].to = sendq_owner(mq);
  snprintf(sent[n_sent].text, sizeof(sent[n_sent].text), "%s", mb->text);
  n_sent++;
}

/* The feature table: the capabilities and msgids on, the rest off. */
int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_CAP_labeled_response:
  case FEAT_CAP_batch:
  case FEAT_CAP_server_time:
  case FEAT_CAP_account_tag:
  case FEAT_MSGID:
    return 1;
  default:
    return 0;
  }
}

int feature_int(enum Feature feat) { (void)feat; return 0; }
const char *feature_str(enum Feature feat) { (void)feat; return ""; }
unsigned int get_sendq(struct Client *cptr) { (void)cptr; return 1u << 30; }
void update_write(struct Client *cptr) { (void)cptr; }
/* The member a persistence profile hides the channel from, if any. */
static struct Client *profile_hidden;

int persistence_channel_visible(struct Client *cptr, const char *chname)
{
  (void)chname;
  return cptr != profile_hidden;
}

/* Kept by the linker for send_buffer()'s other branches; never reached:
 * every line is captured at msgq_add() and the queues stay empty. */
void client_add_sendq(struct Connection *con, struct Connection **con_p)
{
  (void)con; (void)con_p;
}
void client_drop_sendq(struct Connection *con) { (void)con; }
void dbuf_delete(struct DBuf *dyn, unsigned int length) { (void)dyn; (void)length; }
unsigned int deliver_it(struct Client *cptr, struct MsgQ *buf)
{
  (void)cptr; (void)buf;
  fail();
  return 0;
}
void msgq_delete(struct MsgQ *mq, unsigned int length) { (void)mq; (void)length; }
int ws_flush_txrem(struct Client *cptr, unsigned int *wrote_out)
{
  (void)cptr; (void)wrote_out;
  fail();
  return 0;
}
/* is_from_uline()'s, behind FLUSH_ULINE_IMMEDIATE (off here): no U-lines. */
struct ConfItem *find_conf_byhost(struct SLink *lp, const char *host, int statmask)
{
  (void)lp; (void)host; (void)statmask;
  return NULL;
}
/* send.c logs through Debug(()) in a DEBUGMODE build (the testnet images
 * are built that way); nothing here reads it. */
void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

/* ------------------------------------------------------------------ */
/* The clients                                                         */
/* ------------------------------------------------------------------ */

/* asker: the connection whose labeled command is being handled.
 * sibling: another device of the same user (a bouncer alias), its last
 *          command's label long answered.
 * other: an ordinary member. */
static struct Client asker, sibling, other;
static struct Connection asker_con, sibling_con, other_con;
static struct User asker_user, sibling_user, other_user;
static struct Channel *chan;
static struct Membership m_asker, m_sibling, m_other;

static struct Client *sendq_owner(struct MsgQ *mq)
{
  if (mq == &cli_sendQ(&asker)) return &asker;
  if (mq == &cli_sendQ(&sibling)) return &sibling;
  if (mq == &cli_sendQ(&other)) return &other;
  return NULL;
}

static void fixture_client(struct Client *c, struct Connection *con,
                        struct User *u, const char *nick, int fd)
{
  memset(c, 0, sizeof(*c));
  memset(con, 0, sizeof(*con));
  memset(u, 0, sizeof(*u));
  c->cli_connect = con;
  con->con_client = c;
  cli_status(c) = STAT_USER;
  cli_user(c) = u;
  ircd_strncpy(cli_name(c), nick, sizeof(cli_name(c)));
  ircd_strncpy(u->username, "u", sizeof(u->username));
  ircd_strncpy(u->host, "h.example", sizeof(u->host));
  s_fd(&con->con_socket) = fd;
  FlagSet(cli_active_own(c), CAP_LABELEDRESP);
  FlagSet(cli_active_own(c), CAP_BATCH);
  FlagSet(cli_active_own(c), CAP_MSGTAGS);
  FlagSet(cli_active_own(c), CAP_SERVERTIME);
  /* A client outside a bouncer session: its union caps are its own. */
  *cli_active(c) = *cli_active_own(c);
}

/** A labeled command is being handled for @a c. */
static void label_pending(struct Client *c, const char *label)
{
  ircd_strncpy(cli_label(c), label, sizeof(cli_label(c)));
  cli_label_responded(c) = 0;
}

/** The labeled batch labeled_batch_start() opens for @a c. */
static void batch_open(struct Client *c, const char *id)
{
  ircd_strncpy(cli_batch_id(c), id, sizeof(cli_batch_id(c)));
  cli_labeled_batch(c) = 1;
}

static int setup(void **state)
{
  (void)state;
  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  me.cli_connect = &me_con;
  me_con.con_client = &me;
  cli_status(&me) = STAT_ME;
  ircd_strncpy(cli_name(&me), "hub.test", sizeof(cli_name(&me)));

  fixture_client(&asker, &asker_con, &asker_user, "nick", 5);
  fixture_client(&sibling, &sibling_con, &sibling_user, "nick", 6);
  fixture_client(&other, &other_con, &other_user, "other", 7);
  /* The sibling's last command was labeled and answered long ago. */
  ircd_strncpy(cli_label(&sibling), "OLD", sizeof(cli_label(&sibling)));
  cli_label_responded(&sibling) = 1;

  chan = calloc(1, sizeof(*chan) + 8);
  assert_non_null(chan);
  strcpy(chan->chname, "#c");
  memset(&m_asker, 0, sizeof(m_asker));
  memset(&m_sibling, 0, sizeof(m_sibling));
  memset(&m_other, 0, sizeof(m_other));
  m_asker.user = &asker;
  m_sibling.user = &sibling;
  m_other.user = &other;
  m_asker.channel = m_sibling.channel = m_other.channel = chan;
  chan->members = &m_asker;
  m_asker.next_member = &m_sibling;
  m_sibling.next_member = &m_other;

  memset(sent, 0, sizeof(sent));
  n_sent = 0;
  profile_hidden = NULL;
  sendcmdto_set_client_msgid(NULL);
  return 0;
}

static int teardown(void **state)
{
  (void)state;
  free(chan);
  chan = NULL;
  return 0;
}

/** The line @a c was sent, or NULL; there must be at most one. */
static const char *line_to(struct Client *c)
{
  const char *found = NULL;
  int i;

  for (i = 0; i < n_sent; i++)
    if (sent[i].to == c) {
      assert_null(found);
      found = sent[i].text;
    }
  return found;
}

/** The tag region of @a line ("" when it has none), without the '@'. */
static const char *tags_of(const char *line, char *buf, size_t len)
{
  const char *sp;

  buf[0] = '\0';
  if (line[0] != '@')
    return buf;
  sp = strchr(line, ' ');
  assert_non_null(sp);
  snprintf(buf, len, "%.*s", (int)(sp - line - 1), line + 1);
  return buf;
}

/** Whether tag @a name (with "=" or alone) is in @a line's tags. */
static int has_tag(const char *line, const char *name)
{
  char tags[8192];
  char *tok, *save = NULL;
  size_t n = strlen(name);

  tags_of(line, tags, sizeof(tags));
  for (tok = strtok_r(tags, ";", &save); tok; tok = strtok_r(NULL, ";", &save))
    if (!strncmp(tok, name, n) && (tok[n] == '=' || tok[n] == '\0'))
      return 1;
  return 0;
}

/** The value of tag @a name in @a line, or "". */
static const char *tag_value(const char *line, const char *name, char *buf, size_t len)
{
  char tags[8192];
  char *tok, *save = NULL;
  size_t n = strlen(name);

  buf[0] = '\0';
  tags_of(line, tags, sizeof(tags));
  for (tok = strtok_r(tags, ";", &save); tok; tok = strtok_r(NULL, ";", &save))
    if (!strncmp(tok, name, n) && tok[n] == '=') {
      snprintf(buf, len, "%s", tok + n + 1);
      break;
    }
  return buf;
}

/** The line past its tag region. */
static const char *body_of(const char *line)
{
  if (line[0] == '@') {
    const char *sp = strchr(line, ' ');
    return sp ? sp + 1 : line;
  }
  return line;
}

/* ------------------------------------------------------------------ */
/* A channel event the asker's own command caused                      */
/* ------------------------------------------------------------------ */

/* PART #c from the asker: its copy carries the label (consumed, so no
 * ACK), nobody else's does -- not its bouncer sibling's, whose own label
 * is long answered. */
static void test_respond_fanout_labels_only_the_asker(void **state)
{
  const char *a, *s, *o;
  char v[64];

  (void)state;
  label_pending(&asker, "L20");
  sendcmdto_set_client_event("MSGID00000001", 1700000000123ULL);
  sendcmdto_channel_butserv_respond(&asker, CMD_PART, chan, &asker, 0,
                                    "%H :%s", chan, "bye");
  sendcmdto_set_client_msgid(NULL);

  a = line_to(&asker);
  s = line_to(&sibling);
  o = line_to(&other);
  assert_non_null(a);
  assert_non_null(s);
  assert_non_null(o);
  assert_string_equal(tag_value(a, "label", v, sizeof(v)), "L20");
  assert_string_equal(tag_value(a, "msgid", v, sizeof(v)), "MSGID00000001");
  assert_true(has_tag(a, "time"));
  assert_string_equal(body_of(a), ":nick!u@h.example PART #c :bye");
  assert_int_equal(cli_label_responded(&asker), 1);
  assert_false(has_tag(s, "label"));
  assert_false(has_tag(o, "label"));
  assert_string_equal(body_of(s), body_of(a));
  assert_string_equal(tag_value(s, "msgid", v, sizeof(v)), "MSGID00000001");
}

/* Inside the labeled batch its command opened (PART #a,#b, JOIN 0) the
 * asker's copy is tagged with the batch, and the label stays for the
 * batch's BATCH line alone. */
static void test_respond_fanout_joins_labeled_batch(void **state)
{
  const char *a, *o;
  char v[64];

  (void)state;
  label_pending(&asker, "L21");
  cli_label_responded(&asker) = 1;   /* the BATCH +id line took it */
  batch_open(&asker, "BID1");
  sendcmdto_channel_butserv_respond(&asker, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  a = line_to(&asker);
  o = line_to(&other);
  assert_non_null(a);
  assert_string_equal(tag_value(a, "batch", v, sizeof(v)), "BID1");
  assert_false(has_tag(a, "label"));
  assert_false(has_tag(o, "batch"));
}

/* A bouncer device's PART: the event is sourced from its session primary
 * (here the sibling, as m_part rewrites it), and the label is the
 * device's, so only the device's copy carries it. */
static void test_respond_fanout_device_of_a_session(void **state)
{
  const char *a, *s;
  char v[64];

  (void)state;
  label_pending(&asker, "D1");
  sendcmdto_channel_butserv_respond(&sibling, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  a = line_to(&asker);
  s = line_to(&sibling);
  assert_string_equal(tag_value(a, "label", v, sizeof(v)), "D1");
  assert_false(has_tag(s, "label"));
  assert_int_equal(cli_label_responded(&sibling), 1);
}

/* An asker that gets no copy (not a member here) is not answered by the
 * fan-out: its label stays pending, and parse.c sends the ACK. */
static void test_respond_fanout_asker_not_member(void **state)
{
  (void)state;
  label_pending(&asker, "L22");
  m_sibling.next_member = &m_other;
  chan->members = &m_sibling;
  sendcmdto_channel_butserv_respond(&sibling, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  assert_null(line_to(&asker));
  assert_int_equal(cli_label_responded(&asker), 0);
}

/* The plain fan-out labels no one: other callers are unchanged. */
static void test_plain_fanout_labels_no_one(void **state)
{
  (void)state;
  label_pending(&asker, "L23");
  sendcmdto_channel_butserv_butone(&asker, CMD_PART, chan, NULL, 0, ":%H", chan);
  assert_false(has_tag(line_to(&asker), "label"));
  assert_int_equal(cli_label_responded(&asker), 0);
}

/* sendcmdto_one_event() with respond: the label, once. */
static void test_one_event_respond_label_once(void **state)
{
  char v[64];

  (void)state;
  label_pending(&asker, "L24");
  sendcmdto_one_event(&asker, CMD_SETNAME, &asker, 1, ":%s", "new name");
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "L24");
  sendcmdto_one_event(&asker, CMD_SETNAME, &asker, 1, ":%s", "again");
  assert_false(has_tag(sent[1].text, "label"));
  assert_int_equal(cli_label_responded(&asker), 1);
}

/* ------------------------------------------------------------------ */
/* A message the client sent itself                                    */
/* ------------------------------------------------------------------ */

/* PRIVMSG nick :to myself without echo-message: the delivered copy has
 * the message's tags and no label; the label stays pending for the ACK. */
static void test_delivery_takes_no_label(void **state)
{
  const char *a;
  char v[64];

  (void)state;
  label_pending(&asker, "L3");
  sendcmdto_set_client_event("MSGID00000002", 1700000000456ULL);
  sendcmdto_one_delivery(&asker, CMD_PRIVATE, &asker, NULL, "%C :%s",
                         &asker, "to myself");
  sendcmdto_set_client_msgid(NULL);
  a = line_to(&asker);
  assert_non_null(a);
  assert_false(has_tag(a, "label"));
  assert_string_equal(tag_value(a, "msgid", v, sizeof(v)), "MSGID00000002");
  assert_true(has_tag(a, "time"));
  assert_string_equal(body_of(a), ":nick!u@h.example PRIVMSG nick :to myself");
  assert_int_equal(cli_label_responded(&asker), 0);
}

/* Nor does it join the labeled batch its command opened (PRIVMSG to a
 * list of targets): it is not part of the answer. */
static void test_delivery_outside_labeled_batch(void **state)
{
  const char *a;

  (void)state;
  label_pending(&asker, "L4");
  cli_label_responded(&asker) = 1;
  batch_open(&asker, "BID2");
  sendcmdto_one_delivery(&asker, CMD_PRIVATE, &asker, NULL, "%C :%s",
                         &asker, "x");
  a = line_to(&asker);
  assert_false(has_tag(a, "batch"));
  assert_false(has_tag(a, "label"));
}

/* Client-only tags lead the delivered copy for a message-tags client,
 * and are left off for one without. */
static void test_delivery_client_tags(void **state)
{
  const char *a;
  char v[64];

  (void)state;
  label_pending(&asker, "L5");
  sendcmdto_one_delivery(&asker, CMD_TAGMSG, &asker, "+typing=active",
                         "%C", &asker);
  a = line_to(&asker);
  assert_true(!strncmp(a, "@+typing=active;", 16));
  assert_string_equal(tag_value(a, "+typing", v, sizeof(v)), "active");
  assert_false(has_tag(a, "label"));

  FlagClr(cli_active_own(&other), CAP_MSGTAGS);
  sendcmdto_one_delivery(&asker, CMD_PRIVATE, &other, "+typing=active",
                         "%C :%s", &other, "y");
  assert_false(has_tag(line_to(&other), "+typing"));
}

/* A client with no tag capability gets the bare line. */
static void test_delivery_no_tags_at_all(void **state)
{
  (void)state;
  memset(cli_active_own(&other), 0, sizeof(*cli_active_own(&other)));
  label_pending(&other, "L6");
  sendcmdto_one_delivery(&asker, CMD_PRIVATE, &other, "+x=y", "%C :%s",
                         &other, "plain");
  assert_string_equal(line_to(&other), ":nick!u@h.example PRIVMSG other :plain");
}

/* ------------------------------------------------------------------ */
/* The asker's copy when there is nothing to answer, and when it gets  */
/* none                                                                */
/* ------------------------------------------------------------------ */

/* An asker with no label pending -- an unlabeled command, or a client
 * whose command is not the one running -- gets byte for byte the copy
 * the plain fan-out gives a member with the same caps. */
static void test_respond_no_label_is_the_plain_copy(void **state)
{
  char plain[8192];

  (void)state;
  sendcmdto_set_client_event("MSGID00000003", 1700000000789ULL);
  sendcmdto_channel_butserv_butone(&sibling, CMD_PART, chan, NULL, 0,
                                   "%H :%s", chan, "x");
  snprintf(plain, sizeof(plain), "%s", line_to(&asker));
  n_sent = 0;
  sendcmdto_channel_butserv_respond(&sibling, CMD_PART, chan, &asker, 0,
                                    "%H :%s", chan, "x");
  sendcmdto_set_client_msgid(NULL);
  assert_string_equal(line_to(&asker), plain);
  assert_string_equal(line_to(&other), plain);
}

/* A label already answered (or left from an earlier command) is never
 * taken again; nor does it open a labeled batch. */
static void test_respond_answered_label_is_not_taken(void **state)
{
  (void)state;
  label_pending(&asker, "OLD2");
  cli_label_responded(&asker) = 1;
  sendcmdto_channel_butserv_respond(&asker, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  assert_false(has_tag(line_to(&asker), "label"));
  assert_int_equal(labeled_batch_start(&asker), 0);
  assert_int_equal(cli_labeled_batch(&asker), 0);
}

/* The fan-out's own rules decide whether the asker gets a copy at all:
 * a zombie member, a channel its profile hides, a skip mask that rules
 * it out -- no copy, and the label stays pending for the ACK. */
static void test_respond_follows_the_fanout_rules(void **state)
{
  (void)state;
  label_pending(&asker, "L30");

  SetZombie(&m_asker);
  sendcmdto_channel_butserv_respond(&sibling, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  assert_null(line_to(&asker));
  assert_int_equal(cli_label_responded(&asker), 0);
  m_asker.status = 0;

  n_sent = 0;
  profile_hidden = &asker;
  sendcmdto_channel_butserv_respond(&sibling, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  assert_null(line_to(&asker));
  assert_non_null(line_to(&other));
  assert_int_equal(cli_label_responded(&asker), 0);
  profile_hidden = NULL;

  /* SKIP_NONOPS: only chanops are sent the line. */
  n_sent = 0;
  sendcmdto_channel_butserv_respond(&sibling, CMD_MODE, chan, &asker,
                                    SKIP_NONOPS, "%H +m", chan);
  assert_int_equal(n_sent, 0);
  assert_int_equal(cli_label_responded(&asker), 0);
  m_asker.status = CHFL_CHANOP;
  sendcmdto_channel_butserv_respond(&sibling, CMD_MODE, chan, &asker,
                                    SKIP_NONOPS, "%H +m", chan);
  assert_int_equal(n_sent, 1);
  assert_true(has_tag(line_to(&asker), "label"));
  assert_int_equal(cli_label_responded(&asker), 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(test_respond_fanout_labels_only_the_asker, setup, teardown),
    cmocka_unit_test_setup_teardown(test_respond_fanout_joins_labeled_batch, setup, teardown),
    cmocka_unit_test_setup_teardown(test_respond_fanout_device_of_a_session, setup, teardown),
    cmocka_unit_test_setup_teardown(test_respond_fanout_asker_not_member, setup, teardown),
    cmocka_unit_test_setup_teardown(test_plain_fanout_labels_no_one, setup, teardown),
    cmocka_unit_test_setup_teardown(test_one_event_respond_label_once, setup, teardown),
    cmocka_unit_test_setup_teardown(test_respond_no_label_is_the_plain_copy, setup, teardown),
    cmocka_unit_test_setup_teardown(test_respond_answered_label_is_not_taken, setup, teardown),
    cmocka_unit_test_setup_teardown(test_respond_follows_the_fanout_rules, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_takes_no_label, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_outside_labeled_batch, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_client_tags, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_no_tags_at_all, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
