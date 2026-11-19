/*
 * reveal_handlers_cmocka.c - the JOIN that shows a hidden (+D) member,
 * through the handlers: what a watching client is sent, and what the
 * line to the next server carries.
 *
 * The REAL m_topic.c, m_mode.c, channel.c and send.c
 * (each compiled with -ffunction-sections, the program linked with
 * --gc-sections), the real HLC and the real msgid_derive_join(): the
 * handler reveals, mints and sends as in the ircd, and the end of a line
 * is the ircd's (sendcmdto_reset_s2s_overrides()).  Only msgq_make() is
 * ours: it formats each line (the real ircd_vsnprintf()) and keeps it.
 * The rest of what the kept code reaches is stubbed below.
 *
 * A watcher with message-tags and server-time is in every channel, so
 * each JOIN, MODE and TOPIC is formatted with its msgid and time; a
 * tag-aware server link is below us, so each relayed line is formatted
 * with its compact tag region, @A<time_7><msgid_14>.
 *
 *  - TOPIC #a,#b, the first refused after its reveal: two JOINs, two ids.
 *  - MODE +bbbbbv too long for one line: the JOIN is named after the MODE
 *    that carries the +v, which is also the one the next server gets it
 *    under.
 *  - A TOPIC from another server whose time parse.c replaced: the JOIN is
 *    before the TOPIC, under the derived id, in each channel it names.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>

#include "channel.h"
#include "client.h"
#include "crdt_hlc.h"
#include "handlers.h"
#include "history.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msgq.h"
#include "numeric.h"
#include "numnicks.h"
#include "s_conf.h"
#include "send.h"
#include "struct.h"

/* ------------------------------------------------------------------ */
/* The lines                                                           */
/* ------------------------------------------------------------------ */

#define MAXLINES 64
static char lines[MAXLINES][1024];
static int nlines;

struct MsgBuf *msgq_make(struct Client *dest, const char *format, ...)
{
  static struct MsgBuf *dummy;
  va_list ap;

  if (nlines < MAXLINES) {
    va_start(ap, format);
    ircd_vsnprintf(dest, lines[nlines], sizeof(lines[0]), format, ap);
    va_end(ap);
    nlines++;
  }
  if (!dummy)
    dummy = calloc(1, 256);
  return dummy;
}

/** The @a nth (from 0) line with a msgid that has @a a and @a b in it:
 * a client's ("@time=..;msgid=.. :nick!user@host JOIN #a") or a server
 * link's ("@A<time><msgid> ABAAB T #a ..."). */
static const char *line_with(const char *a, const char *b, int nth)
{
  int i;

  for (i = 0; i < nlines; i++)
    if ((strstr(lines[i], "msgid=") || !strncmp(lines[i], "@A", 2))
        && strstr(lines[i], a) && strstr(lines[i], b) && nth-- == 0)
      return lines[i];
  return NULL;
}

/** The msgid of a line line_with() found. */
static const char *id_of(const char *line)
{
  static char id[4][32];
  static int turn;
  char *out = id[turn++ & 3];
  const char *p;

  assert_non_null(line);
  if (!strncmp(line, "@A", 2))
    p = line + 2 + 7;
  else {
    p = strstr(line, "msgid=");
    assert_non_null(p);
    p += 6;
  }
  ircd_strncpy(out, p, 14 + 1);
  return out;
}

/** The time (epoch ms) of a client's line. */
static uint64_t ms_of(const char *line)
{
  struct tm tm;
  const char *p;
  int ms = 0;

  assert_non_null(line);
  p = strstr(line, "time=");
  assert_non_null(p);
  memset(&tm, 0, sizeof(tm));
  assert_int_equal(sscanf(p, "time=%d-%d-%dT%d:%d:%d.%dZ", &tm.tm_year,
                          &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min,
                          &tm.tm_sec, &ms), 7);
  tm.tm_year -= 1900;
  tm.tm_mon--;
  return (uint64_t)timegm(&tm) * 1000 + ms;
}

/* ------------------------------------------------------------------ */
/* The ircd around the handlers                                        */
/* ------------------------------------------------------------------ */

struct Client me, his;
time_t CurrentTime, TSoffset;
unsigned long MsgIdCounter;
int log_inassert;

static int join_on_removedelay;
int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_MSGID:
  case FEAT_P10_MESSAGE_TAGS:
  case FEAT_CAP_server_time:
  case FEAT_CONFIG_OPERCMDS:
    return 1;
  case FEAT_JOIN_ON_REMOVEDELAY:
    return join_on_removedelay;
  default:
    return 0;
  }
}
int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_MAXBANS:   return 50;
  case FEAT_AVBANLEN:  return 100;
  case FEAT_NICKLEN:   return 30;
  default:             return 0;
  }
}
const char *feature_str(enum Feature feat) { return ""; }

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
void debug(int level, const char *form, ...) {}

#define MAXREPLIES 8
static int replies[MAXREPLIES], nreplies;
int send_reply(struct Client *to, int reply, ...)
{
  if (nreplies < MAXREPLIES)
    replies[nreplies++] = reply;
  return 0;
}
int need_more_params(struct Client *cptr, const char *cmd) { fail(); return 0; }
int protocol_violation(struct Client *cptr, const char *pattern, ...) { fail(); return 0; }

/* What exists: looked up by name, as the hash would. */
static struct Channel *channels[8];
static struct Client *users[8];
struct Channel *hSeekChannel(const char *name)
{
  int i;
  for (i = 0; i < 8; i++)
    if (channels[i] && !ircd_strcmp(channels[i]->chname, name))
      return channels[i];
  return NULL;
}
struct Client *hSeekClient(const char *name, int TMask)
{
  int i;
  for (i = 0; i < 8; i++)
    if (users[i] && !ircd_strcmp(cli_name(users[i]), name))
      return users[i];
  return NULL;
}

/* An event's time, as history.c has it: the line's, else the clock's. */
uint64_t history_event_time_ms(struct Client *link)
{
  if (link && cli_s2s_time_ms(link))
    return cli_s2s_time_ms(link);
  return hlc_global()->physical_ms;
}
/* No history store: no row is written. */
int history_is_available(void) { return 0; }
void history_format_ms(char *buf, size_t buflen, uint64_t ms) { buf[0] = '\0'; }
const char *history_owner_of(char *buf, size_t size, struct Client *sptr) { return NULL; }
int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *original_target,
                          const char *sender, const char *account,
                          enum HistoryMessageType type,
                          const char *content, const char *client_tags,
                          const char *owner)
{ fail(); return -1; }
int rcv_store_open(int require_auth, unsigned int authusers,
                   int public_history, int nostorage) { return 0; }
void history_recv_reset(struct Channel *chptr) {}
void history_recv_update(struct Channel *chptr) {}

/* Sending: every connection's fd is -1, so nothing is queued. */
void msgq_clean(struct MsgBuf *mb) {}
void msgq_buf_data(struct MsgBuf *mb, const char **data, unsigned int *len) { fail(); }
void msgq_add(struct MsgQ *mq, struct MsgBuf *mb, int prio) { fail(); }
void msgq_delete(struct MsgQ *mq, unsigned int length) {}
void dbuf_delete(struct DBuf *dyn, unsigned int length) {}
void client_drop_sendq(struct Connection *con) {}
void client_add_sendq(struct Connection *con, struct Connection **con_p) {}
unsigned int get_sendq(struct Client *cptr) { return 1u << 30; }
unsigned int deliver_it(struct Client *cptr, struct MsgQ *buf) { return 0; }
int ws_flush_txrem(struct Client *cptr, unsigned int *wrote_out) { return 0; }
void update_write(struct Client *cptr) {}
int exit_client(struct Client *cptr, struct Client *bcptr, struct Client *sptr,
                const char *comment) { fail(); return 0; }
struct ConfItem *find_conf_byhost(struct SLink *lp, const char *host, int statmask)
{ return NULL; }

/* The rest of what a MODE or a TOPIC reaches. */
int persistence_channel_visible(struct Client *cptr, const char *channel) { return 1; }
int find_mark_match(struct Client *sptr, const char *mask) { return 0; }
const char *find_quarantine(const char *chname) { return NULL; }
void free_link(struct SLink *lp) {}
struct Client *get_history(const char *nick, time_t timelimit) { return NULL; }
int set_user_mode(struct Client *cptr, struct Client *sptr, int parc,
                  char *parv[], int allow_modes) { fail(); return 0; }
void schedule_destruct_event_1m(struct Channel *chptr) {}
void relocate_channel_restamped(struct Channel *chptr, time_t old_ts) {}
void relocate_tombstone_marks_changed(struct Channel *chptr) {}
int bounce_burst_gate_passes(const char *tok) { return 1; }
int bounce_hold_mark_valid(char mark) { return 0; }
void bounce_mark_dirty(struct Client *cptr) {}
void bounce_sync_alias_chanmodes(struct Channel *chptr, struct Client *primary) {}
int metadata_account_clear(const char *account) { return 0; }
int metadata_account_set_permanent(const char *account, const char *key,
                                   const char *value, int visibility) { return 0; }
void metadata_channel_load(struct Channel *chptr) {}
int metadata_channel_memory_del(struct Channel *chptr, const char *key) { return 0; }
int metadata_lmdb_is_available(void) { return 0; }
void metadata_notify_subscribers(const char *target, const char *key,
                                 const char *value, int visibility) {}

/* ------------------------------------------------------------------ */
/* Servers, users, channels                                            */
/* ------------------------------------------------------------------ */

struct fake_client {
  struct Client cli;
  struct Connection con;
  struct User user;
};

/* We are AB; AC is linked below us and takes tags. */
static struct Connection me_con, peer_con;
static struct Server me_serv, peer_serv;
static struct Client peer;
static struct DLink peer_link;

static struct fake_client watcher, actor, hid1;

static void server_init(struct Client *c, struct Connection *con,
                        struct Server *serv, const char *name, const char *yxx)
{
  memset(c, 0, sizeof(*c));
  memset(con, 0, sizeof(*con));
  memset(serv, 0, sizeof(*serv));
  cli_connect(c) = con;
  con_client(con) = c;
  con_fd(con) = -1;
  cli_serv(c) = serv;
  strcpy(cli_name(c), name);
  strcpy(cli_yxx(c), yxx);
}

/** A user on @a server (ours, or behind the link when it is the peer). */
static void user_init(struct fake_client *f, struct Client *server,
                      const char *nick, const char *yxx)
{
  static int slot;

  memset(f, 0, sizeof(*f));
  cli_user(&f->cli) = &f->user;
  cli_status(&f->cli) = STAT_USER;
  f->user.server = server;
  if (server == &me) {
    cli_connect(&f->cli) = &f->con;
    con_client(&f->con) = &f->cli;
    con_fd(&f->con) = -1;
  } else
    cli_connect(&f->cli) = cli_connect(server);
  strcpy(cli_name(&f->cli), nick);
  strcpy(cli_yxx(&f->cli), yxx);
  strcpy(f->user.username, "user");
  strcpy(f->user.host, "host.test");
  strcpy(f->user.realhost, "host.test");
  users[slot++ & 7] = &f->cli;
}

static struct Channel *chan_new(const char *name, unsigned int mode,
                                unsigned int exmode)
{
  static int slot;
  struct Channel *ch = calloc(1, sizeof(*ch) + strlen(name) + 1);

  strcpy(ch->chname, name);
  ch->mode.mode = mode;
  ch->mode.exmode = exmode;
  ch->creationtime = 1700000000;
  channels[slot++ & 7] = ch;
  return ch;
}

static struct Membership *join(struct Channel *ch, struct fake_client *f,
                               unsigned int status)
{
  struct Membership *m = calloc(1, sizeof(*m));

  m->user = &f->cli;
  m->channel = ch;
  m->status = status;
  m->next_channel = f->user.channel;
  f->user.channel = m;
  m->next_member = ch->members;
  ch->members = m;
  ch->users++;
  return m;
}

/** The world before each case: us, the link, a watcher. */
static int setup(void **state)
{
  memset(channels, 0, sizeof(channels));
  memset(users, 0, sizeof(users));
  server_init(&me, &me_con, &me_serv, "ab.test", "AB");
  cli_status(&me) = STAT_ME;
  server_init(&peer, &peer_con, &peer_serv, "ac.test", "AC");
  cli_status(&peer) = STAT_SERVER;
  SetIRCv3Aware(&peer);
  peer_serv.up = &me;
  memset(&peer_link, 0, sizeof(peer_link));
  peer_link.value.cptr = &peer;
  me_serv.down = &peer_link;
  his = me;

  user_init(&watcher, &me, "watcher", "AAA");
  CapSet(cli_active(&watcher.cli), CAP_MSGTAGS);
  CapSet(cli_active(&watcher.cli), CAP_SERVERTIME);
  CapSet(cli_active_own(&watcher.cli), CAP_MSGTAGS);
  CapSet(cli_active_own(&watcher.cli), CAP_SERVERTIME);

  hlc_init(1);
  CurrentTime = time(NULL);
  join_on_removedelay = 0;
  nlines = nreplies = 0;
  memset(lines, 0, sizeof(lines));
  sendcmdto_set_inbound_link(NULL);
  sendcmdto_reset_s2s_overrides();
  return 0;
}

/** The JOIN's id every server makes for @a f in @a chname from @a event. */
static const char *derived(const char *event, const char *chname,
                           struct fake_client *f)
{
  static char id[4][16];
  static int turn;
  char *out = id[turn++ & 3];

  assert_true(msgid_derive_join(out, 16, event, chname,
                                cli_yxx(f->user.server), cli_yxx(&f->cli)));
  return out;
}

/* ------------------------------------------------------------------ */
/* The cases                                                           */
/* ------------------------------------------------------------------ */

/** TOPIC #a,#b by a user hidden in both; #a is +c and the topic has a
 * colour, so #a shows the user and then refuses the topic, minting
 * nothing.  The two JOINs have two msgids, and #b's is the one every
 * server makes from the TOPIC's. */
static void topic_two_channels_two_join_ids(void **state)
{
  struct Channel *a = chan_new("#a", MODE_DELJOINS, EXMODE_NOCOLOR);
  struct Channel *b = chan_new("#b", MODE_DELJOINS, 0);
  char targets[] = "#a,#b", topic[] = "\0034red";
  char *parv[] = { "", targets, topic, NULL };
  const char *join_a, *join_b, *topic_b;

  user_init(&actor, &me, "setter", "AAB");
  join(a, &watcher, 0);
  join(b, &watcher, 0);
  join(a, &actor, CHFL_DELAYED);
  join(b, &actor, CHFL_DELAYED);

  m_topic(&actor.cli, &actor.cli, 3, parv);
  sendcmdto_reset_s2s_overrides();

  assert_int_equal(nreplies, 1);
  assert_int_equal(replies[0], ERR_CANNOTSENDTOCHAN);
  join_a = line_with("setter!", " JOIN #a", 0);
  join_b = line_with("setter!", " JOIN #b", 0);
  topic_b = line_with("setter!", " TOPIC #b", 0);
  assert_null(line_with("setter!", " TOPIC #a", 0));

  assert_string_not_equal(id_of(join_a), id_of(join_b));
  assert_string_equal(id_of(join_b), derived(id_of(topic_b), "#b", &actor));
  assert_true(ms_of(join_b) + 1 == ms_of(topic_b));
  assert_string_not_equal(id_of(join_a), id_of(topic_b));
  /* the next server makes #b's JOIN from the same TOPIC id */
  assert_string_equal(id_of(line_with("ABAAB T #b", "", 0)), id_of(topic_b));
}

/** MODE #c +bbbbbv with five masks and a hidden nick is too long for
 * one MODE.  Two go out, each under its own msgid, and the JOIN is named
 * after the one that carries the +v: here, and (its tag) on the server
 * that gets the +v from us. */
static void mode_split_join_named_after_its_mode(void **state)
{
  struct Channel *c = chan_new("#c", MODE_DELJOINS, 0);
  char chname[] = "#c", modes[] = "+bbbbbv", nick[] = "hiddennick";
  char mask[5][80];
  char *parv[] = { "", chname, modes, mask[0], mask[1], mask[2], mask[3],
                   mask[4], nick, NULL };
  const char *join_c, *mode_v, *mode_other, *s2s_v;
  int i;

  for (i = 0; i < 5; i++) {
    memset(mask[i], 'a' + i, 79);
    memcpy(mask[i], "*!*@", 4);
    mask[i][66] = '\0';       /* a host as long as a mask may have */
  }
  /* The fifth leaves less room than a nick takes: one of the two has
   * to wait for the second MODE. */
  mask[4][38] = '\0';
  user_init(&actor, &me, "op", "AAB");
  user_init(&hid1, &me, "hiddennick", "AAC");
  join(c, &watcher, 0);
  join(c, &actor, CHFL_CHANOP);
  join(c, &hid1, CHFL_DELAYED);

  m_mode(&actor.cli, &actor.cli, 9, parv);
  sendcmdto_reset_s2s_overrides();

  assert_int_equal(nreplies, 0);
  join_c = line_with("hiddennick!", " JOIN #c", 0);
  mode_v = line_with("op!", "hiddennick", 0);
  assert_non_null(mode_v);
  assert_non_null(strstr(mode_v, " MODE #c "));
  /* two MODEs to the watcher: the one with the +v and one more */
  mode_other = line_with("op!", " MODE #c ", 0);
  if (mode_other == mode_v)
    mode_other = line_with("op!", " MODE #c ", 1);
  assert_non_null(mode_other);
  assert_null(line_with("op!", " MODE #c ", 2));
  assert_string_not_equal(id_of(mode_v), id_of(mode_other));
  for (i = 0; i < 5; i++)
    assert_true(strstr(mode_v, mask[i]) || strstr(mode_other, mask[i]));

  assert_string_equal(id_of(join_c), derived(id_of(mode_v), "#c", &hid1));
  s2s_v = line_with("ABAAB M #c", "ABAAC", 0);
  assert_string_equal(id_of(s2s_v), id_of(mode_v));
}

/** TOPIC #a,#b from another server, set by a user hidden in both, under
 * a msgid whose time is 5 minutes ahead.  parse.c has replaced the
 * line's time with ours (the link's stash is set here as it leaves it).
 * Each channel's JOIN has the id every server derives, they differ, and
 * each is 1 ms before the TOPIC it precedes, not 5 minutes after. */
static void replaced_time_join_before_its_topic(void **state)
{
  struct Channel *a = chan_new("#a", MODE_DELJOINS, 0);
  struct Channel *b = chan_new("#b", MODE_DELJOINS, 0);
  char targets[] = "#a,#b", topic[] = "from afar";
  char *parv[] = { "", targets, topic, NULL };
  uint64_t now = hlc_wall_clock_ms();
  char event[16], t7[8];
  const char *chname[] = { "#a", "#b" };
  const char *join_line[2], *topic_line[2];
  int i;

  user_init(&actor, &peer, "remote", "AAB");
  join(a, &watcher, 0);
  join(b, &watcher, 0);
  join(a, &actor, CHFL_DELAYED);
  join(b, &actor, CHFL_DELAYED);

  inttobase64_64(t7, now + 300000, 7);
  snprintf(event, sizeof(event), "ACAAB%sAB", t7);
  strcpy(cli_s2s_msgid(&peer), event);
  cli_s2s_time_ms(&peer) = now;
  sendcmdto_set_inbound_link(&peer);

  ms_topic(&peer, &actor.cli, 3, parv);
  sendcmdto_reset_s2s_overrides();
  sendcmdto_set_inbound_link(NULL);

  for (i = 0; i < 2; i++) {
    char needle[16];

    snprintf(needle, sizeof(needle), " JOIN %s", chname[i]);
    join_line[i] = line_with("remote!", needle, 0);
    snprintf(needle, sizeof(needle), " TOPIC %s", chname[i]);
    topic_line[i] = line_with("remote!", needle, 0);
    assert_string_equal(id_of(topic_line[i]), event);
    assert_true(ms_of(topic_line[i]) == now);
    assert_string_equal(id_of(join_line[i]), derived(event, chname[i], &actor));
    assert_true(ms_of(join_line[i]) == now - 1);
  }
  assert_string_not_equal(id_of(join_line[0]), id_of(join_line[1]));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(topic_two_channels_two_join_ids, setup),
    cmocka_unit_test_setup(mode_split_join_named_after_its_mode, setup),
    cmocka_unit_test_setup(replaced_time_join_before_its_topic, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
