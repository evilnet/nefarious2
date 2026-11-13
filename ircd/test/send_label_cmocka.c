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

/* generate_msgid()'s world (sendcmdto_one_tags() mints a msgid). */
unsigned long MsgIdCounter;
struct HLC hlc_global_event(void)
{
  struct HLC h;
  memset(&h, 0, sizeof(h));
  return h;
}
const char *inttobase64_64(char *buf, uint64_t v, unsigned int count)
{
  unsigned int i;
  for (i = 0; i < count; i++)
    buf[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]"[(v >> (6 * (count - 1 - i))) & 63];
  buf[count] = '\0';
  return buf;
}
/* numnicks.c's decoder (batch_ref_make()): the numeric alphabet, '[' and
 * ']' included. */
unsigned int base64toint(const char *s)
{
  static const char alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";
  unsigned int i = 0;

  while (*s) {
    const char *p = strchr(alpha, *s++);
    assert_non_null(p);
    i = (i << 6) + (unsigned int)(p - alpha);
  }
  return i;
}
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

#define MAX_SENT 320
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

void msgq_buf_data(struct MsgBuf *mb, const char **data, unsigned int *len)
{
  *data = mb->text;
  *len = (unsigned int)strlen(mb->text);
}

/* ircd_alloc.c's, without its out-of-memory handler. */
void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
}
void *DoMallocZero(size_t len, const char *type, const char *file, int line)
{
  void *p = calloc(1, len);

  (void)type; (void)file; (void)line;
  assert_non_null(p);
  return p;
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
  struct Connection *con = cli_connect(c);
  ircd_strncpy(con->con_batch[0].id, id, sizeof(con->con_batch[0].id));
  con->con_batch[0].parent[0] = '\0';
  con->con_batch_depth = 1;
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
  batch_hold_free(&asker_con);
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

/* labeled-response is a no-op until batch is negotiated too: a label left
 * on a connection that holds labeled-response without batch (one an
 * answer that comes later put back, after the client dropped batch) is
 * taken by nothing -- no labeled copy, no labeled batch, no ACK, no
 * labeled FAIL.  The client gets what one without labeled-response gets. */
static void test_label_inert_without_batch(void **state)
{
  int i;

  (void)state;
  FlagClr(cli_active_own(&asker), CAP_BATCH);
  FlagClr(cli_active(&asker), CAP_BATCH);
  label_pending(&asker, "L40");

  sendcmdto_channel_butserv_respond(&asker, CMD_PART, chan, &asker, 0,
                                    ":%H", chan);
  assert_false(has_tag(line_to(&asker), "label"));
  assert_int_equal(cli_label_responded(&asker), 0);

  n_sent = 0;
  assert_int_equal(labeled_batch_start(&asker), 0);
  assert_int_equal(labeled_batch_start_list(&asker, "#a,#b"), 0);
  assert_int_equal(cli_labeled_batch(&asker), 0);
  send_labeled_ack(&asker);
  assert_int_equal(n_sent, 0);

  send_fail(&asker, "BATCH", "UNKNOWN_TYPE", "x", "Unknown batch type");
  assert_int_equal(n_sent, 1);
  assert_false(has_tag(sent[0].text, "label"));

  /* Batch back: live again, in either order of negotiation. */
  FlagSet(cli_active_own(&asker), CAP_BATCH);
  FlagSet(cli_active(&asker), CAP_BATCH);
  n_sent = 0;
  for (i = 0; i < MAX_SENT; i++)
    sent[i].to = NULL;
  send_labeled_ack(&asker);
  assert_int_equal(n_sent, 1);
  assert_true(has_tag(sent[0].text, "label"));
}

/* The forwarded-label batch override (s_numeric.c sets it for one
 * relayed numeric) is consumed by the line it was set for, whether or not
 * that recipient could take it: sent to a client without batch, it must
 * not ride on the NEXT line formatted for another client that has batch
 * -- that client never saw the batch. */
static void test_fwd_batch_override_consumed(void **state)
{
  char v[64];

  (void)state;
  FlagClr(cli_active_own(&other), CAP_BATCH);
  FlagClr(cli_active(&other), CAP_BATCH);

  sendcmdto_set_fwd_batch("fwd9");
  sendcmdto_one_tags(&me, CMD_NOTICE, &other, "%C :to a client without batch", &other);
  assert_non_null(line_to(&other));
  assert_false(has_tag(line_to(&other), "batch"));

  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :the next line, to a client with batch", &asker);
  assert_non_null(line_to(&asker));
  assert_false(has_tag(line_to(&asker), "batch"));

  /* Used where it is set for a client with batch: there, once. */
  n_sent = 0;
  memset(sent, 0, sizeof(sent));
  sendcmdto_set_fwd_batch("fwd10");
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :in the forwarded batch", &asker);
  assert_string_equal(tag_value(line_to(&asker), "batch", v, sizeof(v)), "fwd10");
  n_sent = 0;
  memset(sent, 0, sizeof(sent));
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :after it", &asker);
  assert_false(has_tag(line_to(&asker), "batch"));
}

/* ---- nested batches (send.c's nesting model) ---- */

static void reset_sent(void)
{
  n_sent = 0;
  memset(sent, 0, sizeof(sent));
}

/** The batch id a "BATCH +<id> ..." line opens. */
static const char *opened_id(const char *line, char *buf, size_t len)
{
  const char *p = strstr(line, "BATCH +");
  assert_non_null(p);
  snprintf(buf, len, "%s", p + 7);
  if (strchr(buf, ' '))
    *strchr(buf, ' ') = '\0';
  return buf;
}

/** Whether @a ref is a legal batch reference: "Reference tag MUST contain
 * only ASCII letters, numbers, and/or hyphen" (batch spec). */
static int legal_ref(const char *ref)
{
  const char *p;

  if (!ref[0])
    return 0;
  for (p = ref; *p; p++)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z')
          || (*p >= '0' && *p <= '9') || *p == '-'))
      return 0;
  return 1;
}

/* A numeric with '[' or ']' (the numeric alphabet's last two characters)
 * names a batch by its value: the reference is letters, digits and hyphen
 * only, fits BATCH_REF_SIZE at its longest, and two sequences give two
 * references. */
static void test_batch_ref_legal_for_any_numeric(void **state)
{
  static const char *servers[] = { "A[", "]]", "[A", "AB", "", NULL };
  static const char *clients[] = { "]]]", "A[B", "[[[", "AAA", "]", "" };
  static const unsigned int seqs[] = { 0, 7, 0xffffffffu };
  char ref[BATCH_REF_SIZE], other[BATCH_REF_SIZE], v[64];
  size_t s, c, q;

  (void)state;
  for (s = 0; s < sizeof(servers) / sizeof(servers[0]); s++)
    for (c = 0; c < sizeof(clients) / sizeof(clients[0]); c++)
      for (q = 0; q < sizeof(seqs) / sizeof(seqs[0]); q++) {
        memset(ref, 'x', sizeof(ref));
        batch_ref_make(ref, sizeof(ref), servers[s], clients[c], seqs[q]);
        assert_true(strlen(ref) < sizeof(ref));
        assert_true(legal_ref(ref));
        assert_null(strchr(ref, '['));
        assert_null(strchr(ref, ']'));
      }

  /* The value, not the characters: "A[" is 62, "]]]" is 0x3ffff. */
  assert_string_equal(batch_ref_make(ref, sizeof(ref), "A[", "]]]", 7), "fbffff-7");
  assert_string_equal(batch_ref_make(ref, sizeof(ref), "]]", "]]]", 0xffffffffu),
                      "3fffffff-ffffffff");
  batch_ref_make(other, sizeof(other), "A[", "]]]", 8);
  assert_string_not_equal(ref, other);

  /* A connection's own batch, its client numeric "]A[": the BATCH + line
   * names it legally, and the lines inside carry the same reference. */
  reset_sent();
  ircd_strncpy(cli_yxx(&asker), "]A[", sizeof(cli_yxx(&asker)));
  assert_int_equal(send_batch_start(&asker, "t"), 1);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :inside", &asker);
  send_batch_end(&asker);
  opened_id(sent[0].text, ref, sizeof(ref));
  assert_true(legal_ref(ref));
  assert_string_equal(tag_value(sent[1].text, "batch", v, sizeof(v)), ref);
  assert_non_null(strstr(sent[2].text, ref));
}

/* An inner batch's start AND end lines carry @batch=<outer>; lines sent
 * meanwhile carry the innermost; after the inner end the outer is the
 * innermost again; the outer's own lines carry no batch tag. */
static void test_batch_nesting_tags(void **state)
{
  char outer[32], inner[32], v[64];

  (void)state;
  reset_sent();
  assert_int_equal(send_batch_start(&asker, "outer-type"), 1);
  assert_int_equal(send_batch_start(&asker, "inner-type"), 1);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :inside", &asker);
  send_batch_end(&asker);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :after the inner", &asker);
  send_batch_end(&asker);
  assert_int_equal(n_sent, 6);

  opened_id(sent[0].text, outer, sizeof(outer));
  assert_false(has_tag(sent[0].text, "batch"));
  opened_id(sent[1].text, inner, sizeof(inner));
  assert_string_equal(tag_value(sent[1].text, "batch", v, sizeof(v)), outer);
  assert_string_equal(tag_value(sent[2].text, "batch", v, sizeof(v)), inner);
  assert_non_null(strstr(sent[3].text, "BATCH -"));
  assert_non_null(strstr(sent[3].text, inner));
  assert_string_equal(tag_value(sent[3].text, "batch", v, sizeof(v)), outer);
  assert_string_equal(tag_value(sent[4].text, "batch", v, sizeof(v)), outer);
  assert_non_null(strstr(sent[5].text, "BATCH -"));
  assert_non_null(strstr(sent[5].text, outer));
  assert_false(has_tag(sent[5].text, "batch"));
  assert_string_equal(cli_batch_id(&asker), "");
}

/* A pending label goes on the outermost BATCH + only. */
static void test_batch_label_on_outermost(void **state)
{
  char v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "LB1");
  assert_int_equal(labeled_batch_start(&asker), 1);
  send_batch_start(&asker, "metadata x");
  send_batch_end(&asker);
  labeled_batch_end(&asker);
  assert_int_equal(n_sent, 4);
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "LB1");
  assert_false(has_tag(sent[1].text, "label"));
  assert_int_equal(cli_labeled_batch(&asker), 0);
  assert_string_equal(cli_batch_id(&asker), "");
}

/* labeled_batch_end() and batch_end_line() end what is still open inside,
 * innermost first, each end line tagged with its own parent. */
static void test_batch_end_line_closes_inner_first(void **state)
{
  char outer[32], inner[32], v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "LB2");
  labeled_batch_start(&asker);
  send_batch_start(&asker, "draft/authtoken *");   /* never ended by its opener */
  batch_end_line(&asker);
  assert_int_equal(n_sent, 4);
  opened_id(sent[0].text, outer, sizeof(outer));
  opened_id(sent[1].text, inner, sizeof(inner));
  assert_non_null(strstr(sent[2].text, inner));
  assert_string_equal(tag_value(sent[2].text, "batch", v, sizeof(v)), outer);
  assert_non_null(strstr(sent[3].text, outer));
  assert_false(has_tag(sent[3].text, "batch"));
  assert_int_equal(cli_connect(&asker)->con_batch_depth, 0);
}

/* Past BATCH_NEST_MAX a start opens nothing (its lines stay in the
 * innermost batch) and its end ends nothing: the pairing holds. */
static void test_batch_depth_cap(void **state)
{
  char deepest[32], v[64];
  int i, starts = 0, ends = 0;

  (void)state;
  reset_sent();
  for (i = 0; i < BATCH_NEST_MAX; i++)
    assert_int_equal(send_batch_start(&asker, "t"), 1);
  opened_id(sent[BATCH_NEST_MAX - 1].text, deepest, sizeof(deepest));
  assert_int_equal(send_batch_start(&asker, "t"), 0);       /* over the cap */
  assert_string_equal(cli_batch_id(&asker), deepest);
  for (i = 0; i <= BATCH_NEST_MAX; i++)
    send_batch_end(&asker);
  for (i = 0; i < n_sent; i++) {
    if (strstr(sent[i].text, "BATCH +")) starts++;
    if (strstr(sent[i].text, "BATCH -")) ends++;
  }
  assert_int_equal(starts, BATCH_NEST_MAX);
  assert_int_equal(ends, BATCH_NEST_MAX);
  assert_int_equal(cli_connect(&asker)->con_batch_depth, 0);
  assert_int_equal(cli_connect(&asker)->con_batch_over, 0);
  (void)v;
}

/* A labeled batch asked for at the depth cap opens nothing: the label is
 * answered there and then, once, by a labeled ACK outside every batch, and
 * the answer's lines go out in the innermost batch unlabeled; no ACK
 * follows them, and the pairing holds. */
static void test_labeled_batch_at_cap_answers_once(void **state)
{
  char deepest[32], v[64];
  int i, labels = 0;

  (void)state;
  reset_sent();
  for (i = 0; i < BATCH_NEST_MAX; i++)
    send_batch_start(&asker, "t");
  opened_id(sent[BATCH_NEST_MAX - 1].text, deepest, sizeof(deepest));
  label_pending(&asker, "CAP1");
  assert_int_equal(labeled_batch_start(&asker), 0);
  assert_int_equal(n_sent, BATCH_NEST_MAX + 1);
  assert_string_equal(body_of(sent[BATCH_NEST_MAX].text), ":hub.test ACK");
  assert_string_equal(tag_value(sent[BATCH_NEST_MAX].text, "label", v, sizeof(v)), "CAP1");
  assert_false(has_tag(sent[BATCH_NEST_MAX].text, "batch"));
  assert_int_equal(cli_label_responded(&asker), 1);
  assert_int_equal(cli_labeled_batch(&asker), 0);

  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :a line of the answer", &asker);
  assert_string_equal(tag_value(sent[BATCH_NEST_MAX + 1].text, "batch", v, sizeof(v)),
                      deepest);
  send_labeled_ack(&asker);                  /* parse_client()'s: nothing */
  batch_end_line(&asker);
  for (i = 0; i < n_sent; i++)
    if (has_tag(sent[i].text, "label"))
      labels++;
  assert_int_equal(labels, 1);
  assert_int_equal(n_sent, BATCH_NEST_MAX + 2 + BATCH_NEST_MAX);
  assert_int_equal(cli_connect(&asker)->con_batch_depth, 0);
  assert_int_equal(cli_connect(&asker)->con_batch_over, 0);
}

/* An asynchronous batch (LIST's) is detached from the stack when its line
 * is done: a later labeled line's batch is NOT nested in it and does not
 * disturb it; the LIST's lines, sent while it is resumed, carry its id;
 * both end, each untagged (top level). */
static void test_batch_async_and_unrelated_labeled(void **state)
{
  char list[16], lab[32], v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "LIST1");
  send_batch_start(&asker, "labeled-response");
  batch_detach(&asker, list, sizeof(list));
  assert_true(list[0] != '\0');
  assert_string_equal(cli_batch_id(&asker), "");

  /* a later line: labeled WHOIS */
  label_pending(&asker, "WHOIS1");
  assert_int_equal(labeled_batch_start(&asker), 1);
  opened_id(sent[1].text, lab, sizeof(lab));
  assert_false(has_tag(sent[1].text, "batch"));          /* not inside LIST */
  assert_string_equal(tag_value(sent[1].text, "label", v, sizeof(v)), "WHOIS1");
  batch_end_line(&asker);
  assert_false(has_tag(sent[2].text, "batch"));

  /* the LIST goes on */
  batch_resume(&asker, list);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :a LIST line", &asker);
  assert_string_equal(tag_value(sent[3].text, "batch", v, sizeof(v)), list);
  batch_suspend(&asker);
  assert_string_equal(cli_batch_id(&asker), "");
  batch_resume(&asker, list);
  send_batch_end(&asker);
  assert_non_null(strstr(sent[4].text, "BATCH -"));
  assert_non_null(strstr(sent[4].text, list));
  assert_false(has_tag(sent[4].text, "batch"));
  assert_int_equal(cli_connect(&asker)->con_batch_depth, 0);
}

/* A client without batch: frames with no id, nothing on the wire, the
 * pairing kept. */
static void test_batch_without_batch_cap(void **state)
{
  (void)state;
  reset_sent();
  FlagClr(cli_active_own(&other), CAP_BATCH);
  FlagClr(cli_active(&other), CAP_BATCH);
  assert_int_equal(send_batch_start(&other, "t"), 0);
  sendcmdto_one_tags(&me, CMD_NOTICE, &other, "%C :plain", &other);
  send_batch_end(&other);
  assert_int_equal(n_sent, 1);
  assert_false(has_tag(sent[0].text, "batch"));
  assert_int_equal(cli_connect(&other)->con_batch_depth, 0);
}

/* ---- a deferred labeled batch (labeled_batch_defer()) ---- */

/** Lines in sent[] carrying a label tag. */
static int labels_sent(void)
{
  int i, n = 0;

  for (i = 0; i < n_sent; i++)
    if (has_tag(sent[i].text, "label"))
      n++;
  return n;
}

/* An answer of no message: nothing goes out while the line runs; at its
 * end the lines that are not the answer (a message delivered to oneself)
 * go out as they were, then the label's ACK.  No BATCH line. */
static void test_deferred_none_is_ack(void **state)
{
  char v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "D0");
  assert_int_equal(labeled_batch_defer(&asker), 1);
  assert_int_equal(cli_label_responded(&asker), 1);
  sendcmdto_one_delivery(&asker, CMD_PRIVATE, &asker, NULL, "%C :%s", &asker, "self");
  assert_int_equal(n_sent, 0);                /* held */
  batch_end_line(&asker);
  send_labeled_ack(&asker);                   /* parse_client()'s: nothing */
  assert_int_equal(n_sent, 2);
  assert_string_equal(body_of(sent[0].text), ":nick!u@h.example PRIVMSG nick :self");
  assert_false(has_tag(sent[0].text, "label"));
  assert_false(has_tag(sent[0].text, "batch"));
  assert_string_equal(body_of(sent[1].text), ":hub.test ACK");
  assert_string_equal(tag_value(sent[1].text, "label", v, sizeof(v)), "D0");
  assert_null(con_batch_hold(&asker_con));
  assert_int_equal(cli_connect(&asker)->con_batch_depth, 0);
}

/* An answer of one line: it goes out bare, the label in place of the
 * batch tag; no BATCH line, no ACK. */
static void test_deferred_one_line_takes_label(void **state)
{
  char v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "D1");
  labeled_batch_defer(&asker);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :the one reply", &asker);
  assert_int_equal(n_sent, 0);
  batch_end_line(&asker);
  send_labeled_ack(&asker);
  assert_int_equal(n_sent, 1);
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "D1");
  assert_false(has_tag(sent[0].text, "batch"));
  assert_true(has_tag(sent[0].text, "time"));       /* the other tags kept */
  assert_string_equal(body_of(sent[0].text), ":hub.test NOTICE nick :the one reply");
}

/* A second message opens the batch at once: its BATCH + line with the
 * label, the held lines, then the rest as they come, and BATCH - at the
 * end; lines not in the answer keep their place, untagged. */
static void test_deferred_second_message_opens_batch(void **state)
{
  char id[32], v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "D2");
  labeled_batch_defer(&asker);
  sendcmdto_one_delivery(&asker, CMD_PRIVATE, &asker, NULL, "%C :%s", &asker, "self");
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :first", &asker);
  assert_int_equal(n_sent, 0);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :second", &asker);
  assert_int_equal(n_sent, 4);                       /* opened */
  opened_id(sent[0].text, id, sizeof(id));
  assert_true(legal_ref(id));
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "D2");
  assert_non_null(strstr(sent[0].text, "BATCH +"));
  assert_non_null(strstr(sent[0].text, " labeled-response"));
  assert_false(has_tag(sent[1].text, "batch"));       /* the delivery */
  assert_string_equal(tag_value(sent[2].text, "batch", v, sizeof(v)), id);
  assert_string_equal(tag_value(sent[3].text, "batch", v, sizeof(v)), id);
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :third", &asker);
  assert_int_equal(n_sent, 5);                       /* no longer held */
  batch_end_line(&asker);
  send_labeled_ack(&asker);
  assert_int_equal(n_sent, 6);
  assert_non_null(strstr(sent[5].text, "BATCH -"));
  assert_non_null(strstr(sent[5].text, id));
  assert_int_equal(labels_sent(), 1);
}

/* An answer that is one typed batch (a metadata batch nested in the
 * deferred one): as if no labeled batch had been asked for -- the label on
 * the typed batch's BATCH + line, its BATCH - untagged, its lines tagged
 * with it. */
static void test_deferred_one_nested_batch(void **state)
{
  char inner[32], v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "D3");
  labeled_batch_defer(&asker);
  send_batch_start(&asker, "metadata");
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :inside", &asker);
  send_batch_end(&asker);
  assert_int_equal(n_sent, 0);
  labeled_batch_end(&asker);
  assert_int_equal(n_sent, 3);
  opened_id(sent[0].text, inner, sizeof(inner));
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "D3");
  assert_false(has_tag(sent[0].text, "batch"));
  assert_string_equal(tag_value(sent[1].text, "batch", v, sizeof(v)), inner);
  {
    char want[64];
    snprintf(want, sizeof(want), ":hub.test BATCH -%s", inner);
    assert_string_equal(sent[2].text, want);       /* untagged */
  }
  assert_int_equal(labels_sent(), 1);
  assert_int_equal(cli_labeled_batch(&asker), 0);
}

/* A typed batch AND another line (a FAIL beside the metadata batch): two
 * messages, so the labeled batch opens, the typed one nested in it. */
static void test_deferred_nested_batch_and_line(void **state)
{
  char outer[32], inner[32], v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "D4");
  labeled_batch_defer(&asker);
  send_batch_start(&asker, "metadata");
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :inside", &asker);
  send_batch_end(&asker);
  assert_int_equal(n_sent, 0);
  send_fail(&asker, "METADATA", "KEY_INVALID", "k", "Invalid key");
  assert_int_equal(n_sent, 5);
  opened_id(sent[0].text, outer, sizeof(outer));
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "D4");
  opened_id(sent[1].text, inner, sizeof(inner));
  assert_string_equal(tag_value(sent[1].text, "batch", v, sizeof(v)), outer);
  assert_string_equal(tag_value(sent[2].text, "batch", v, sizeof(v)), inner);
  assert_string_equal(tag_value(sent[3].text, "batch", v, sizeof(v)), outer);
  assert_string_equal(tag_value(sent[4].text, "batch", v, sizeof(v)), outer);
  assert_non_null(strstr(sent[4].text, "FAIL METADATA KEY_INVALID"));
  batch_end_line(&asker);
  assert_int_equal(n_sent, 6);
  assert_non_null(strstr(sent[5].text, outer));
  assert_int_equal(labels_sent(), 1);
}

/* The hold is bounded: past BATCH_HOLD_MAX lines the batch is opened (a
 * labeled batch around one message is legal), nothing is lost, the order
 * is kept. */
static void test_deferred_hold_bounded(void **state)
{
  int i;
  char v[64];

  (void)state;
  reset_sent();
  label_pending(&asker, "D5");
  labeled_batch_defer(&asker);
  for (i = 0; i < BATCH_HOLD_MAX - 1; i++)
    sendcmdto_one_delivery(&asker, CMD_PRIVATE, &asker, NULL, "%C :%d", &asker, i);
  assert_int_equal(n_sent, 0);                       /* all held */
  for (; i < BATCH_HOLD_MAX + 6; i++)
    sendcmdto_one_delivery(&asker, CMD_PRIVATE, &asker, NULL, "%C :%d", &asker, i);
  assert_int_equal(n_sent, 1 + BATCH_HOLD_MAX + 6);
  assert_string_equal(tag_value(sent[0].text, "label", v, sizeof(v)), "D5");
  for (i = 0; i < BATCH_HOLD_MAX + 6; i++) {
    char want[64];
    snprintf(want, sizeof(want), ":nick!u@h.example PRIVMSG nick :%d", i);
    assert_string_equal(body_of(sent[1 + i].text), want);
  }
  batch_end_line(&asker);
  assert_non_null(strstr(sent[1 + BATCH_HOLD_MAX + 6].text, "BATCH -"));
}

/* A client that has not negotiated labels, or no label pending: nothing
 * deferred, nothing held. */
static void test_deferred_needs_a_label(void **state)
{
  (void)state;
  reset_sent();
  assert_int_equal(labeled_batch_defer(&asker), 0);
  label_pending(&asker, "D6");
  FlagClr(cli_active_own(&asker), CAP_LABELEDRESP);
  assert_int_equal(labeled_batch_defer(&asker), 0);
  assert_null(con_batch_hold(&asker_con));
  sendcmdto_one_tags(&me, CMD_NOTICE, &asker, "%C :x", &asker);
  assert_int_equal(n_sent, 1);
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

/* A list of targets opens the labeled batch only when it names two or
 * more different ones; one target's line carries the label itself, and
 * none ("PART ,") is answered by ACK. */
static void test_batch_for_two_or_more_targets(void **state)
{
  static const struct { const char *list; int batch; } cases[] = {
    { "#a", 0 }, { "#a,", 0 }, { ",#a", 0 }, { ",", 0 }, { "", 0 },
    { "#a,#a", 0 }, { "#a,#A", 0 }, { "#a,#b", 1 }, { "#a,,#b", 1 },
    { "#a,#a,#b", 1 },
  };
  size_t i;

  (void)state;
  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    n_sent = 0;
    label_pending(&asker, "L31");
    cli_labeled_batch(&asker) = 0;
    cli_connect(&asker)->con_batch_depth = 0;
    assert_int_equal(labeled_batch_start_list(&asker, cases[i].list) != 0,
                     cases[i].batch);
    assert_int_equal(n_sent, cases[i].batch);
    assert_int_equal(cli_label_responded(&asker), cases[i].batch);
    if (cases[i].batch)
      assert_true(strstr(sent[0].text, "BATCH +") != NULL
                  && has_tag(sent[0].text, "label"));
  }
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
    cmocka_unit_test_setup_teardown(test_label_inert_without_batch, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_ref_legal_for_any_numeric, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_nesting_tags, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_label_on_outermost, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_end_line_closes_inner_first, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_depth_cap, setup, teardown),
    cmocka_unit_test_setup_teardown(test_labeled_batch_at_cap_answers_once, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_async_and_unrelated_labeled, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_without_batch_cap, setup, teardown),
    cmocka_unit_test_setup_teardown(test_fwd_batch_override_consumed, setup, teardown),
    cmocka_unit_test_setup_teardown(test_batch_for_two_or_more_targets, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_none_is_ack, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_one_line_takes_label, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_second_message_opens_batch, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_one_nested_batch, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_nested_batch_and_line, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_hold_bounded, setup, teardown),
    cmocka_unit_test_setup_teardown(test_deferred_needs_a_label, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_takes_no_label, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_outside_labeled_batch, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_client_tags, setup, teardown),
    cmocka_unit_test_setup_teardown(test_delivery_no_tags_at_all, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
