/*
 * send_tags_cmocka.c - the tag region a channel fan-out gives each member
 *
 * The channel and common-channel fan-outs build each member's tag region
 * with format_message_tags_ex() into a 128-byte buffer.  It appended each
 * tag with snprintf() and pos += its return, with no bound:
 *
 *  - a member whose only tag capability is account-tag, sent a line from
 *    a user with no account, got "@ " -- an empty tag section, a
 *    malformed line ("@ :nick!u@h PART #c");
 *  - with the oper's name in draft/oper (OPERTAG_VALUE) and an Operator
 *    block name long enough, pos passed the buffer: the region lost its
 *    trailing space (the tags ran into the line's prefix), and for a +B
 *    source the bot tag was written at buf + pos with buflen - pos
 *    wrapped to a huge size_t -- past the end of the stack buffer.
 *
 * Each tag now goes in whole or not at all, a name too long for the
 * draft/oper value falls back to the bare tag, and a region with no tag
 * in it is no region.
 *
 * This includes the real send.c, compiled with -ffunction-sections and
 * linked with --gc-sections; the ircd around it is stubbed here, and every
 * line a client is sent is captured at msgq_add().
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
/* bump_sentalong()'s (the common-channels fan-out) */
int HighestFd;
struct Client *LocalClientArray[MAXCONNECTIONS];
/* UserStats.local_aliases gates the device walk of the session form. */
struct UserStatistics UserStats;
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

/* send_buffer()'s deferred labeled batch (send.c, labeled_batch_defer())
 * holds lines through these; no case here defers one, so none is reached. */
void msgq_buf_data(struct MsgBuf *mb, const char **data, unsigned int *len)
{
  (void)mb;
  *data = "";
  *len = 0;
  fail();
}
void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  (void)len; (void)type; (void)file; (void)line;
  fail();
  return NULL;
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

/* The feature table: the tag capabilities on, the oper's name in its
 * tag (OPERTAG_VALUE) as a test sets it. */
static int opertag_value;

int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_CAP_server_time:
  case FEAT_CAP_account_tag:
  case FEAT_CAP_oper_tag:
  case FEAT_MSGID:
    return 1;
  case FEAT_OPERTAG_VALUE:
    return opertag_value;
  default:
    return 0;
  }
}

int feature_int(enum Feature feat) { (void)feat; return 0; }
const char *feature_str(enum Feature feat) { (void)feat; return ""; }
unsigned int get_sendq(struct Client *cptr) { (void)cptr; return 1u << 30; }
void update_write(struct Client *cptr) { (void)cptr; }
int persistence_channel_visible(struct Client *cptr, const char *chname)
{
  (void)cptr; (void)chname;
  return 1;
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

static struct Client src, rcpt, dev1, dev2;
static struct Connection src_con, rcpt_con, dev1_con, dev2_con;
static struct User src_user, rcpt_user, dev1_user, dev2_user;
static struct Channel *chan;
static struct Membership m_src, m_rcpt;
static char long_name[128];

static struct Client *sendq_owner(struct MsgQ *mq)
{
  if (mq == &cli_sendQ(&src)) return &src;
  if (mq == &cli_sendQ(&rcpt)) return &rcpt;
  if (mq == &cli_sendQ(&dev1)) return &dev1;
  if (mq == &cli_sendQ(&dev2)) return &dev2;
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

  fixture_client(&src, &src_con, &src_user, "src", 5);
  fixture_client(&rcpt, &rcpt_con, &rcpt_user, "rcpt", 6);
  fixture_client(&dev1, &dev1_con, &dev1_user, "src", 7);
  fixture_client(&dev2, &dev2_con, &dev2_user, "src", 8);
  memset(LocalClientArray, 0, sizeof(LocalClientArray));
  LocalClientArray[5] = &src;
  LocalClientArray[6] = &rcpt;
  LocalClientArray[7] = &dev1;
  LocalClientArray[8] = &dev2;
  HighestFd = 8;
  memset(&UserStats, 0, sizeof(UserStats));

  chan = calloc(1, sizeof(*chan) + 8);
  assert_non_null(chan);
  strcpy(chan->chname, "#c");
  memset(&m_src, 0, sizeof(m_src));
  memset(&m_rcpt, 0, sizeof(m_rcpt));
  m_src.user = &src;
  m_rcpt.user = &rcpt;
  m_src.channel = m_rcpt.channel = chan;
  chan->members = &m_rcpt;
  m_rcpt.next_member = &m_src;

  memset(sent, 0, sizeof(sent));
  n_sent = 0;
  opertag_value = 0;
  sendcmdto_set_client_msgid(NULL);
  return 0;
}

static int teardown(void **state)
{
  (void)state;
  free(chan);
  chan = NULL;
  if (src_user.opername == long_name)
    src_user.opername = NULL;
  return 0;
}

static const char *line_to(struct Client *c)
{
  int i;

  for (i = 0; i < n_sent; i++)
    if (sent[i].to == c)
      return sent[i].text;
  return NULL;
}

/** A line is well formed: no tag region, or "@" then one or more
 * non-empty tags separated by ';', a single space, and the ":" prefix. */
static void assert_well_formed(const char *line)
{
  const char *sp, *p;

  assert_non_null(line);
  if (line[0] != '@') {
    assert_int_equal(line[0], ':');
    return;
  }
  sp = strchr(line, ' ');
  assert_non_null(sp);
  assert_true(sp > line + 1);              /* "@ " is no tag region */
  assert_int_equal(sp[1], ':');           /* the prefix follows the space */
  for (p = line + 1; p < sp; p++)
    if (*p == ';')
      assert_true(p[1] != ';' && p + 1 < sp && p[-1] != '@');
}

/* A member whose only tag capability is account-tag, a source with no
 * account: the line has no tag region at all. */
static void test_account_tag_only_no_account(void **state)
{
  (void)state;
  FlagSet(cli_active_own(&rcpt), CAP_ACCOUNTTAG);
  sendcmdto_channel_butserv_butone(&src, CMD_PART, chan, NULL, 0, ":%H", chan);
  assert_string_equal(line_to(&rcpt), ":src!u@h.example PART :#c");

  /* the common-channels fan-out builds its region the same way */
  n_sent = 0;
  m_src.next_channel = NULL;
  cli_user(&src)->channel = &m_src;
  sendcmdto_common_channels_butone(&src, CMD_NICK, &src, ":%s", "src2");
  assert_string_equal(line_to(&rcpt), ":src!u@h.example NICK :src2");
}

/* Every tag a member can get, from a +B oper with an account whose
 * Operator block name is long: the region stays inside its buffer, ends
 * with its space, keeps every tag whole (the oper tag without its value
 * when the value does not fit), and the bot tag is there. */
static void test_long_oper_name_every_tag(void **state)
{
  const char *l;
  size_t n;

  (void)state;
  opertag_value = 1;
  for (n = 0; n < 120; n++)
    long_name[n] = 'o';
  long_name[n] = '\0';
  SetOper(&src);
  SetPriv(&src, PRIV_DISPLAY);
  SetFlag(&src, FLAG_BOT);
  SetFlag(&src, FLAG_ACCOUNT);
  ircd_strncpy(src_user.account, "acct456789abcde", sizeof(src_user.account));
  src_user.opername = long_name;
  FlagSet(cli_active_own(&rcpt), CAP_ACCOUNTTAG);
  FlagSet(cli_active_own(&rcpt), CAP_SERVERTIME);
  FlagSet(cli_active_own(&rcpt), CAP_MSGTAGS);
  FlagSet(cli_active_own(&rcpt), CAP_DRAFT_OPERTAG);

  for (n = 0; n < 120; n += 7) {
    long_name[n] = '\0';
    n_sent = 0;
    sendcmdto_set_client_event("ABAAAaHRZHliUi", 1700000000123ULL);
    sendcmdto_channel_butserv_butone(&src, CMD_PART, chan, NULL, 0, ":%H", chan);
    sendcmdto_set_client_msgid(NULL);
    l = line_to(&rcpt);
    assert_well_formed(l);
    assert_non_null(strstr(l, ";bot "));
    assert_non_null(strstr(l, "draft/oper"));
    /* "@" time(29) ;msgid(21) ;account(24) ;draft/oper=(12) ;bot(4) " ":
     * 92 bytes and the name in 128 -- the value while the name fits in
     * 35 bytes, the bare tag after that. */
    if (n && n <= 35)
      assert_non_null(strstr(l, "draft/oper=o"));
    else
      assert_null(strstr(l, "draft/oper="));
    assert_non_null(strstr(l, "account=acct456789abcde"));
    assert_non_null(strstr(l, " :src!u@h.example PART :#c"));
    long_name[n] = 'o';
  }
}

/* ---- the session form: the user's own connections (#220) ---- */

static int count_to(struct Client *c)
{
  int i, n = 0;

  for (i = 0; i < n_sent; i++)
    if (sent[i].to == c)
      n++;
  return n;
}

static const char *untagged(const char *l)
{
  const char *sp = (l && l[0] == '@') ? strchr(l, ' ') : NULL;
  return sp ? sp + 1 : l;
}

/** @a d a bouncer device of ours of @a primary. */
static void make_device(struct Client *d, struct Client *primary)
{
  SetFlag(d, FLAG_BOUNCER_ALIAS);
  cli_user(d)->alias_primary = primary;
  UserStats.local_aliases++;
}

/* In one channel with an observer: the user gets the observer's line, once,
 * with the tags it negotiated (it is not left untagged for want of a
 * member with the same tag set). */
static void test_session_form_tells_the_user_once(void **state)
{
  (void)state;
  m_src.next_channel = NULL;
  cli_user(&src)->channel = &m_src;
  FlagSet(cli_active_own(&src), CAP_ACCNOTIFY);
  FlagSet(cli_active(&src), CAP_ACCNOTIFY);
  FlagSet(cli_active_own(&src), CAP_SERVERTIME);
  FlagSet(cli_active_own(&rcpt), CAP_ACCNOTIFY);
  FlagSet(cli_active(&rcpt), CAP_ACCNOTIFY);
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "zed");
  assert_int_equal(count_to(&src), 1);
  assert_int_equal(count_to(&rcpt), 1);
  assert_string_equal(untagged(line_to(&src)), untagged(line_to(&rcpt)));
  assert_string_equal(untagged(line_to(&src)), ":src!u@h.example ACCOUNT zed");
  assert_non_null(strstr(line_to(&src), "time="));
  /* The skip form leaves the user out, as before. */
  n_sent = 0;
  sendcmdto_common_channels_capab_butone(&src, CMD_ACCOUNT, &src, CAP_ACCNOTIFY,
                                         CAP_NONE, "%s", "zed");
  assert_int_equal(count_to(&src), 0);
  assert_int_equal(count_to(&rcpt), 1);
}

/* In no channel: the user still gets it, and a user without the cap not. */
static void test_session_form_no_channel(void **state)
{
  (void)state;
  cli_user(&src)->channel = NULL;
  FlagSet(cli_active_own(&src), CAP_ACCNOTIFY);
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "*");
  assert_int_equal(count_to(&src), 1);
  assert_string_equal(line_to(&src), ":src!u@h.example ACCOUNT *");
  assert_int_equal(count_to(&rcpt), 0);
  n_sent = 0;
  FlagClr(cli_active_own(&src), CAP_ACCNOTIFY);
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "*");
  assert_int_equal(n_sent, 0);
}

/* The devices: one in the channel (reached by the walk) and one not, both
 * with the cap: once each; a device without the cap: nothing; the walk of
 * the local clients is skipped when the server counts no device, and a
 * device already leaving is skipped. */
static void test_session_form_devices(void **state)
{
  struct Membership m_dev1;
  (void)state;
  memset(&m_dev1, 0, sizeof(m_dev1));
  m_dev1.user = &dev1;
  m_dev1.channel = chan;
  m_src.next_member = &m_dev1;               /* rcpt, src, dev1 */
  m_src.next_channel = NULL;
  cli_user(&src)->channel = &m_src;
  make_device(&dev1, &src);
  make_device(&dev2, &src);
  FlagSet(cli_active_own(&src), CAP_ACCNOTIFY);
  FlagSet(cli_active_own(&dev1), CAP_ACCNOTIFY);
  FlagSet(cli_active(&dev1), CAP_ACCNOTIFY);
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "zed");
  assert_int_equal(count_to(&src), 1);
  assert_int_equal(count_to(&dev1), 1);
  assert_int_equal(count_to(&dev2), 0);

  /* dev2 gets the cap; out of the channel, only the walk finds it */
  FlagSet(cli_active_own(&dev2), CAP_ACCNOTIFY);
  n_sent = 0;
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "zed");
  assert_int_equal(count_to(&dev1), 1);
  assert_int_equal(count_to(&dev2), 1);

  SetFlag(&dev2, FLAG_CLOSING);
  n_sent = 0;
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "zed");
  assert_int_equal(count_to(&dev2), 0);
  ClrFlag(&dev2, FLAG_CLOSING);

  UserStats.local_aliases = 0;               /* no device counted: no walk */
  n_sent = 0;
  sendcmdto_common_channels_capab_session(&src, CMD_ACCOUNT, CAP_ACCNOTIFY,
                                          "%s", "zed");
  assert_int_equal(count_to(&dev2), 0);
  assert_int_equal(count_to(&dev1), 1);      /* the channel walk's */
  m_src.next_member = NULL;
}

/* away_notify_common()'s star (m_away.c): a first send for draft/pre-away
 * clients with ":*", a second for the rest with the text.  The sender's
 * own copy -- a session primary of ours told of an away decided
 * elsewhere (one == NULL) -- takes the same filters as the members: one
 * line, the form its own caps ask for (it used to get both). */
static void test_away_star_sender_copy(void **state)
{
  int pre;
  (void)state;
  cli_user(&src)->channel = NULL;
  for (pre = 0; pre < 2; pre++) {
    memset(cli_active_own(&src), 0, sizeof(*cli_active_own(&src)));
    FlagSet(cli_active_own(&src), CAP_AWAYNOTIFY);
    if (pre)
      FlagSet(cli_active_own(&src), CAP_DRAFT_PREAWAY);
    n_sent = 0;
    sendcmdto_set_extra_withcap(CAP_DRAFT_PREAWAY);
    sendcmdto_common_channels_capab_butone(&src, CMD_AWAY, NULL, CAP_AWAYNOTIFY,
                                           CAP_NONE, ":*");
    sendcmdto_common_channels_capab_butone(&src, CMD_AWAY, NULL, CAP_AWAYNOTIFY,
                                           CAP_DRAFT_PREAWAY, ":%s", "Away");
    assert_int_equal(count_to(&src), 1);
    assert_string_equal(line_to(&src), pre ? ":src!u@h.example AWAY :*"
                                           : ":src!u@h.example AWAY :Away");
  }
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(test_account_tag_only_no_account, setup, teardown),
    cmocka_unit_test_setup_teardown(test_long_oper_name_every_tag, setup, teardown),
    cmocka_unit_test_setup_teardown(test_session_form_tells_the_user_once, setup, teardown),
    cmocka_unit_test_setup_teardown(test_session_form_no_channel, setup, teardown),
    cmocka_unit_test_setup_teardown(test_session_form_devices, setup, teardown),
    cmocka_unit_test_setup_teardown(test_away_star_sender_copy, setup, teardown),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
