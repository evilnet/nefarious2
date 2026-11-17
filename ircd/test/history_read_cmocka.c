/*
 * history_read_cmocka.c - history.c's read paths for a renamed channel
 * (include/history_rename.h), on the REAL ../history.o.
 *
 * history_rename_cmocka.c tests the renames record and the merged walk
 * on their own.  This suite runs what a CHATHISTORY command runs: rows
 * stored with history_store_message(), a rename recorded with
 * history_channel_renamed(), and the pages, msgid lookups, redaction
 * lookups and TARGETS stamp read back through history.c -- with the trim
 * engine (../history_trim.o) and the store (RocksDB, ../db_rocksdb.o, in
 * a mkdtemp()'d directory) as the ircd links them.  The channels are the
 * table below (hSeekChannel); everything else history.c needs from the
 * ircd is a stub at the end of the fixture.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <cmocka.h>

#include "channel.h"
#include "chathistory_presence.h"
#include "client.h"
#include "db_types.h"
#include "hash.h"
#include "history.h"
#include "history_rename.h"
#include "chathistory_merge.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "ml_content.h"
#include "send.h"
#include "struct.h"

/* ------------------------------------------------------------------ */
/* What history.c needs from the ircd                                  */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
time_t TSoffset;
struct Channel *GlobalChannelList;
struct Client me;
int log_inassert;

/** CHATHISTORY_RETENTION, in days (0 = keep everything). */
static int retention_days;

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_CHATHISTORY_RETENTION:      return retention_days;
  case FEAT_CHATHISTORY_HIGH_WATERMARK: return 85;
  case FEAT_CHATHISTORY_LOW_WATERMARK:  return 75;
  case FEAT_CHATHISTORY_USER_QUOTA_PCT: return 25;
  case FEAT_CHATHISTORY_TRIM_SLICE_MS:  return 50;
  case FEAT_CHATHISTORY_MAINTENANCE_INTERVAL: return 3600;
  default:                              return 0;
  }
}

int feature_bool(enum Feature feat)
{
  (void)feat;
  return 0;
}

/* Quiet: history.c logs every row it stores.  A warning or an error is
 * kept for the case that asks about it. */
static char last_warning[512];

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  va_list ap;
  (void)subsys; (void)flags;

  if (severity > L_WARNING)
    return;
  va_start(ap, fmt);
  vsnprintf(last_warning, sizeof(last_warning), fmt, ap);
  va_end(ap);
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

/* The channels that exist. */
#define MAX_CHANS 8
static struct {
  struct Channel *ch;
} chans[MAX_CHANS];

static struct Channel *chan_make(const char *name, time_t creation)
{
  struct Channel *ch = calloc(1, sizeof(struct Channel) + strlen(name) + 1);
  int i;

  assert_non_null(ch);
  strcpy(ch->chname, name);
  ch->creationtime = creation;
  for (i = 0; i < MAX_CHANS; i++)
    if (!chans[i].ch) {
      chans[i].ch = ch;
      return ch;
    }
  fail_msg("too many channels");
  return NULL;
}

static void chan_gone(const char *name)
{
  int i;

  for (i = 0; i < MAX_CHANS; i++)
    if (chans[i].ch && 0 == ircd_strcmp(chans[i].ch->chname, name)) {
      free(chans[i].ch);
      chans[i].ch = NULL;
    }
}

struct Channel *hSeekChannel(const char *name)
{
  int i;

  for (i = 0; i < MAX_CHANS; i++)
    if (chans[i].ch && 0 == ircd_strcmp(chans[i].ch->chname, name))
      return chans[i].ch;
  return NULL;
}

int channel_has_local_member(const struct Channel *chptr)
{
  (void)chptr;
  return 0;
}

int channel_store_open(const struct Channel *chptr)
{
  (void)chptr;
  return 1;
}

void chathistory_fed_report(struct Client *to)
{
  (void)to;
}

void presence_shutdown(void)
{
}

int send_reply(struct Client *to, int reply, ...)
{
  (void)to; (void)reply;
  return 0;
}

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  (void)one; (void)mask; (void)pattern;
}

struct Timer *timer_init(struct Timer *timer)
{
  return timer;
}

void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{
  (void)timer; (void)call; (void)data; (void)type; (void)value;
}

void timer_del(struct Timer *timer)
{
  (void)timer;
}

/* No multiline content store: every row is a single line. */
int ml_content_init(struct db_env *env)
{
  (void)env;
  return -1;
}

void ml_content_shutdown(struct db_env *env)
{
  (void)env;
}

#ifndef ml_content_available
int ml_content_available(void)
{
  return 0;
}
#endif

int ml_content_store(struct db_writebatch *wb, const char *msgid,
                     const char *sender, const char *target,
                     const char *content, size_t content_len,
                     const char *paste_secret, size_t *staged_len)
{
  (void)wb; (void)msgid; (void)sender; (void)target; (void)content;
  (void)content_len; (void)paste_secret; (void)staged_len;
  return -1;
}

int ml_content_resolve(struct db_snapshot *snap, struct HistoryMessage *msg)
{
  (void)snap; (void)msg;
  return -1;
}

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

static char g_tmpdir[64];

/** Now, and the creation second of the channel under test: a day ago. */
static time_t now_s;
#define INC   (now_s - 86400)
/** A row time @a s seconds before now, as a key stamp ("sec.mmm"). */
static const char *ago(long s, int ms)
{
  static char buf[8][HISTORY_TIMESTAMP_LEN];
  static int next;
  char *b = buf[next++ % 8];

  snprintf(b, HISTORY_TIMESTAMP_LEN, "%lu.%03d", (unsigned long)(now_s - s), ms);
  return b;
}

static void rm_rf(const char *path)
{
  DIR *d = opendir(path);
  struct dirent *e;
  char buf[512];

  if (!d) {
    unlink(path);
    return;
  }
  while ((e = readdir(d)) != NULL) {
    if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
      continue;
    snprintf(buf, sizeof buf, "%s/%s", path, e->d_name);
    rm_rf(buf);
  }
  closedir(d);
  rmdir(path);
}

static int setup(void **state)
{
  static const char tmpl[] = "/tmp/hreadXXXXXX";
  (void)state;

  memcpy(g_tmpdir, tmpl, sizeof tmpl);
  assert_non_null(mkdtemp(g_tmpdir));
  now_s = time(NULL);
  CurrentTime = now_s;
  retention_days = 0;
  last_warning[0] = '\0';
  assert_int_equal(history_init(g_tmpdir), 0);
  return 0;
}

static int teardown(void **state)
{
  int i;
  (void)state;

  history_shutdown();
  for (i = 0; i < MAX_CHANS; i++) {
    free(chans[i].ch);
    chans[i].ch = NULL;
  }
  rm_rf(g_tmpdir);
  return 0;
}

static void say(const char *chan, const char *ts, const char *msgid)
{
  assert_int_equal(history_store_message(msgid, ts, chan, NULL,
                                         "nick!user@host.example", "acct",
                                         HISTORY_PRIVMSG, msgid, NULL, NULL), 0);
}

static void redact(const char *chan, const char *ts, const char *msgid,
                   const char *parent)
{
  char content[HISTORY_MSGID_LEN + 16];

  snprintf(content, sizeof content, "%s :spam", parent);
  assert_int_equal(history_store_message(msgid, ts, chan, NULL,
                                         "mod!user@host.example", "mod",
                                         HISTORY_REDACT, content, NULL, NULL), 0);
}

/** The classic RENAME, as rename_channel() does it: the channel has the
 * new name, and history is told. */
static void rename_chan(const char *oldname, const char *newname)
{
  struct Channel *ch = hSeekChannel(oldname);
  time_t creation;

  assert_non_null(ch);
  creation = ch->creationtime;
  chan_gone(oldname);
  chan_make(newname, creation);
  history_channel_renamed(oldname, newname, creation);
}

/** The msgids of a result list, in order, each row checked to be
 * presented as @a target's (in the spelling its key folds to).  Frees
 * the list. */
static const char *ids(struct HistoryMessage *list, const char *target)
{
  static char buf[512];
  struct HistoryMessage *m;

  buf[0] = '\0';
  for (m = list; m; m = m->next) {
    assert_int_equal(ircd_strcmp(m->target, target), 0);
    if (buf[0])
      strcat(buf, " ");
    strcat(buf, m->msgid);
  }
  history_free_messages(list);
  return buf;
}

static const char *latest(const char *target, int limit)
{
  struct HistoryMessage *list = NULL;

  assert_true(history_query_latest(target, HISTORY_REF_NONE, NULL, limit,
                                   &list, NULL) >= 0);
  return ids(list, target);
}

/** #old with a1 a2 a3, renamed to #new, then b1 b2. */
static void renamed_channel(void)
{
  chan_make("#old", INC);
  say("#old", ago(300, 0), "a1");
  say("#old", ago(200, 0), "a2");
  say("#old", ago(100, 0), "a3");
  rename_chan("#old", "#New");
  say("#new", ago(-5, 0), "b1");
  say("#new", ago(-6, 0), "b2");
}

/* ------------------------------------------------------------------ */
/* Pages                                                               */
/* ------------------------------------------------------------------ */

/* Every selector pages across the rename, in one time order, every row
 * presented under the current name. */
static void test_pages_follow_the_rename(void **state)
{
  struct HistoryMessage *list = NULL, *m;
  int exhausted = 0;
  (void)state;

  renamed_channel();

  assert_string_equal(latest("#new", 50), "a1 a2 a3 b1 b2");
  assert_string_equal(latest("#NEW", 3), "a3 b1 b2");
  /* the old name is nobody's channel now: what is stored under it is
   * still there under it */
  assert_string_equal(latest("#old", 50), "a1 a2 a3");

  /* BEFORE and AFTER, by msgid and by timestamp, from either side */
  assert_int_equal(history_query_before("#new", HISTORY_REF_MSGID, "b1", 2,
                                        &list, NULL), 2);
  assert_string_equal(ids(list, "#new"), "a2 a3");
  assert_int_equal(history_query_before("#new", HISTORY_REF_MSGID, "a3", 10,
                                        &list, NULL), 2);
  assert_string_equal(ids(list, "#new"), "a1 a2");
  assert_int_equal(history_query_after("#new", HISTORY_REF_MSGID, "a2", 10,
                                       &list, NULL), 3);
  assert_string_equal(ids(list, "#new"), "a3 b1 b2");
  assert_int_equal(history_query_after("#new", HISTORY_REF_TIMESTAMP,
                                       ago(250, 0), 2, &list, NULL), 2);
  assert_string_equal(ids(list, "#new"), "a2 a3");

  /* AROUND a row from before the rename, BETWEEN across it */
  assert_int_equal(history_query_around("#new", HISTORY_REF_MSGID, "a3", 3,
                                        &list, NULL, &exhausted), 3);
  assert_string_equal(ids(list, "#new"), "a2 a3 b1");
  assert_int_equal(history_query_between("#new", HISTORY_REF_MSGID, "a1",
                                         HISTORY_REF_MSGID, "b2", 10, &list,
                                         NULL), 3);
  assert_string_equal(ids(list, "#new"), "a2 a3 b1");

  /* a row says where it is stored (strict presence asks) */
  assert_int_equal(history_query_latest("#new", HISTORY_REF_NONE, NULL, 50,
                                        &list, NULL), 5);
  for (m = list; m; m = m->next)
    assert_string_equal(m->stored_as, m->msgid[0] == 'a' ? "#old" : "#new");
  history_free_messages(list);
}

/* A msgid from before the rename resolves under the new name. */
static void test_msgid_lookups_follow_the_rename(void **state)
{
  struct HistoryMessage *m = NULL;
  char ts[HISTORY_TIMESTAMP_LEN];
  (void)state;

  renamed_channel();

  assert_int_equal(history_lookup_message("#new", "a2", &m), 0);
  assert_non_null(m);
  assert_string_equal(m->target, "#new");
  assert_string_equal(m->msgid, "a2");
  assert_string_equal(m->stored_as, "#old");
  assert_string_equal(m->timestamp, ago(200, 0));
  history_free_messages(m);
  m = NULL;
  assert_int_equal(history_lookup_message("#new", "b1", &m), 0);
  assert_string_equal(m->stored_as, "#new");
  history_free_messages(m);
  m = NULL;
  assert_int_equal(history_lookup_message("#new", "nope", &m), 1);
  assert_int_equal(history_msgid_ref_timestamp("#new", "a1", ts), 0);
  assert_string_equal(ts, ago(300, 0));
}

/* The old name taken by another channel: neither sees the other's rows. */
static void test_recreated_old_name_stays_apart(void **state)
{
  (void)state;

  renamed_channel();
  chan_make("#old", now_s);              /* a stranger's, made just now */
  say("#old", ago(-8, 0), "s1");

  assert_string_equal(latest("#old", 50), "s1");
  assert_string_equal(latest("#new", 50), "a1 a2 a3 b1 b2");
}

/* #a -> #b -> #c -> #b: each row once, in order. */
static void test_chain_and_back(void **state)
{
  (void)state;

  chan_make("#a", INC);
  say("#a", ago(400, 0), "a1");
  rename_chan("#a", "#b");
  say("#b", ago(-2, 0), "b1");
  rename_chan("#b", "#c");
  say("#c", ago(-4, 0), "c1");
  rename_chan("#c", "#b");
  say("#b", ago(-6, 0), "b2");

  assert_string_equal(latest("#b", 50), "a1 b1 c1 b2");
}

/* ------------------------------------------------------------------ */
/* TARGETS                                                             */
/* ------------------------------------------------------------------ */

/* A renamed channel's stamp is its newest row under any of its names:
 * with nothing said since the rename, and after a rename away and back
 * (#a -> #b -> #a), when the name's own stamp is from before it left. */
static void test_target_latest_follows_the_rename(void **state)
{
  char ts[HISTORY_TIMESTAMP_LEN];
  (void)state;

  chan_make("#a", INC);
  say("#a", ago(300, 0), "a1");
  assert_int_equal(history_target_latest("#a", ts, sizeof ts), 0);
  assert_string_equal(ts, ago(300, 0));

  rename_chan("#a", "#b");
  /* nobody has spoken in #b */
  assert_int_equal(history_target_latest("#b", ts, sizeof ts), 0);
  assert_string_equal(ts, ago(300, 0));

  say("#b", ago(-3, 0), "b1");
  rename_chan("#b", "#a");
  /* the newest row is the one said as #b */
  assert_int_equal(history_target_latest("#a", ts, sizeof ts), 0);
  assert_string_equal(ts, ago(-3, 0));

  say("#a", ago(-9, 0), "a2");
  assert_int_equal(history_target_latest("#a", ts, sizeof ts), 0);
  assert_string_equal(ts, ago(-9, 0));

  /* never renamed, never spoken in */
  chan_make("#quiet", INC);
  assert_int_equal(history_target_latest("#quiet", ts, sizeof ts), 1);
}

/* ------------------------------------------------------------------ */
/* Incarnations                                                        */
/* ------------------------------------------------------------------ */

/* A channel renamed into a name does not inherit the earlier names of a
 * dead channel that had the name and was created in the same second. */
static void test_same_second_channel_is_not_inherited(void **state)
{
  (void)state;

  /* the dead channel: #q, renamed to #new, then gone */
  chan_make("#q", INC);
  say("#q", ago(500, 0), "q1");
  rename_chan("#q", "#new");
  chan_gone("#new");
  /* nobody has the name: its history is all there, as before */
  assert_string_equal(latest("#new", 50), "q1");

  /* the live channel, created in the same second, arrives */
  chan_make("#z", INC);
  say("#z", ago(50, 0), "z1");
  rename_chan("#z", "#new");
  say("#new", ago(-5, 0), "n1");

  assert_string_equal(latest("#new", 50), "z1 n1");
}

/* More renames than the record keeps names: the earliest are no longer
 * followed, and the log says so. */
static void test_cap_is_logged(void **state)
{
  char from[16], to[16];
  int i;
  (void)state;

  chan_make("#n0", INC);
  say("#n0", ago(900, 0), "first");
  for (i = 0; i < HREN_MAX_SEGS; i++) {
    snprintf(from, sizeof from, "#n%d", i);
    snprintf(to, sizeof to, "#n%d", i + 1);
    rename_chan(from, to);
    usleep(2000);   /* the record orders names by when they were left */
  }
  assert_string_equal(latest(to, 50), "first");
  assert_null(strstr(last_warning, "no longer followed"));

  snprintf(from, sizeof from, "#n%d", HREN_MAX_SEGS);
  rename_chan(from, "#last");
  assert_non_null(strstr(last_warning, "no longer followed"));
  assert_string_equal(latest("#last", 50), "");
}

/* ------------------------------------------------------------------ */
/* Relocations that cross                                              */
/* ------------------------------------------------------------------ */

/* The store executed the losing relocation (#old to #y) first, then
 * learns the winner is #x: #x has the old channel's history, with the
 * names from before it, and #y has none of it -- as on a store that
 * executed the winner first. */
static void test_crossing_relocations(void **state)
{
  (void)state;

  chan_make("#older", INC);
  say("#older", ago(600, 0), "o1");
  rename_chan("#older", "#old");
  say("#old", ago(-1, 0), "o2");

  /* relocate_execute(): the old channel stays, a tombstone */
  chan_make("#y", INC);
  history_channel_renamed("#old", "#y", INC);
  assert_string_equal(latest("#y", 50), "o1 o2");
  /* said in the tombstone since: its own */
  say("#old", ago(-20, 0), "t1");

  /* relocate_again(): the winner */
  chan_make("#x", INC);
  history_channel_rename_crossed("#old", "#y", "#x", INC);

  assert_string_equal(latest("#x", 50), "o1 o2");
  assert_string_equal(latest("#y", 50), "");
  assert_string_equal(latest("#old", 50), "o2 t1");
}

/* ------------------------------------------------------------------ */
/* Redactions                                                          */
/* ------------------------------------------------------------------ */

/* A REDACT sent in #new of a message from before the rename hides it. */
static void test_redact_across_the_rename(void **state)
{
  struct HistoryMessage *list = NULL, *m;
  int seen = 0;
  (void)state;

  renamed_channel();
  assert_int_equal(history_message_is_redacted("#new", "a2"), 0);
  redact("#new", ago(-7, 0), "r1", "a2");
  assert_int_equal(history_message_is_redacted("#new", "a2"), 1);
  assert_int_equal(history_message_is_redacted("#new", "a1"), 0);

  /* ... and rides along as the message's context, on a page that does
   * not hold the REDACT row itself */
  assert_int_equal(history_query_before("#new", HISTORY_REF_MSGID, "b1", 10,
                                        &list, NULL), 3);
  assert_true(history_attach_context("#new", list) >= 1);
  for (m = list; m; m = m->next)
    if (!strcmp(m->msgid, "a2")) {
      assert_non_null(m->next);
      assert_int_equal(m->next->is_context, 1);
      assert_string_equal(m->next->msgid, "r1");
      seen = 1;
    }
  assert_int_equal(seen, 1);
  history_free_messages(list);
}

/** A stamp at the clock renames are timed by, each later than the last. */
static const char *stamp_now(void)
{
  static char buf[4][HISTORY_TIMESTAMP_LEN];
  static int next;
  char *b = buf[next++ % 4];

  usleep(2000);
  history_format_ms(b, HISTORY_TIMESTAMP_LEN, history_recv_now_ms());
  usleep(2000);
  return b;
}

static int shown_redacted(const struct HistoryMessage *m, void *arg)
{
  return history_message_is_redacted((const char *)arg, m->msgid);
}

/** What a client is shown of @a target's latest page, as m_chathistory.c
 * builds it: the page, its context attached (history_attach_context),
 * through the page's redaction filter (hm_redact_filter) -- which hides a
 * message only when the REDACT row naming it is on the list.  The msgids
 * of the messages left, in order. */
static const char *shown(const char *target)
{
  static char buf[512];
  struct HistoryMessage *list = NULL, *m;
  int n;

  n = history_query_latest(target, HISTORY_REF_NONE, NULL, 50, &list, NULL);
  assert_true(n >= 0);
  n += history_attach_context(target, list);
  hm_redact_filter(&list, n, NULL, shown_redacted, (void *)target);
  buf[0] = '\0';
  for (m = list; m; m = m->next) {
    if (m->type != HISTORY_PRIVMSG)
      continue;
    if (buf[0])
      strcat(buf, " ");
    strcat(buf, m->msgid);
  }
  history_free_messages(list);
  return buf;
}

/** #a with m1 m2, renamed to #b, where m1 is redacted (r1), renamed back
 * to #a, and then away and back through other names until #b is no
 * longer one of the names #a's record keeps. */
static void redacted_then_renamed_out_of_reach(time_t creation,
                                               const char *redact_ts)
{
  char other[16];
  int i;

  chan_make("#a", creation);
  say("#a", ago(3000, 0), "m1");
  say("#a", ago(2000, 0), "m2");
  rename_chan("#a", "#b");
  redact("#b", redact_ts, "r1", "m1");
  assert_int_equal(history_message_is_redacted("#b", "m1"), 1);
  assert_string_equal(shown("#b"), "m2");
  rename_chan("#b", "#a");
  assert_int_equal(history_message_is_redacted("#a", "m1"), 1);
  assert_string_equal(shown("#a"), "m2");

  for (i = 0; i < HREN_MAX_SEGS; i++) {
    snprintf(other, sizeof other, "#t%d", i);
    usleep(2000);
    rename_chan("#a", other);
    usleep(2000);
    rename_chan(other, "#a");
  }
  /* #b is no longer followed ... */
  assert_non_null(strstr(last_warning, "no longer followed"));
}

/* A redaction does not depend on the renames record: the REDACT row is
 * under #b, a name the channel no longer reads, and the message it hides
 * is under #a, which it does.  The message stays redacted. */
static void test_redact_survives_the_names_cap(void **state)
{
  (void)state;

  redacted_then_renamed_out_of_reach(INC, stamp_now());
  assert_string_equal(latest("#a", 50), "m1 m2");
  assert_int_equal(history_message_is_redacted("#a", "m1"), 1);
  assert_int_equal(history_message_is_redacted("#a", "m2"), 0);
  /* ... on the page a client gets, where the REDACT row rides along as
   * the message's context from the name it is stored under */
  assert_string_equal(shown("#a"), "m2");
}

/* A relocation leaves the old channel in place, with the history from
 * before the move readable under both names.  A REDACT in the new channel
 * of a message from before the move hides it in the old one too. */
static void test_redact_reaches_the_relocation_tombstone(void **state)
{
  (void)state;

  chan_make("#old", INC);
  say("#old", ago(300, 0), "a1");
  say("#old", ago(200, 0), "a2");
  chan_make("#new", INC);                          /* relocate_execute() */
  history_channel_renamed("#old", "#new", INC);
  say("#old", ago(-20, 0), "t1");                  /* the tombstone's own */

  redact("#new", ago(-30, 0), "r1", "a2");
  assert_int_equal(history_message_is_redacted("#new", "a2"), 1);
  assert_int_equal(history_message_is_redacted("#old", "a2"), 1);
  assert_int_equal(history_message_is_redacted("#old", "a1"), 0);
  assert_string_equal(shown("#new"), "a1");
  assert_string_equal(shown("#old"), "a1 t1");

  /* what the tombstone stored after the move is not the new channel's to
   * redact */
  redact("#new", ago(-31, 0), "r2", "t1");
  assert_int_equal(history_message_is_redacted("#old", "t1"), 0);

  /* nor does another channel's REDACT row naming the msgid hide anything */
  chan_make("#evil", INC);
  redact("#evil", ago(-32, 0), "x1", "a1");
  assert_int_equal(history_message_is_redacted("#old", "a1"), 0);
  assert_int_equal(history_message_is_redacted("#new", "a1"), 0);
  assert_string_equal(shown("#new"), "a1");
  assert_string_equal(shown("#old"), "a1 t1");
}

/** Run the trim engine until it has nothing left to do. */
static void trim_until_idle(void)
{
  int i;

  history_trim_tick(1);
  for (i = 0; i < 400; i++)
    history_trim_tick(0);
}

/* Trimming must not undo that redaction.  The REDACT row here is past
 * retention and its original is not (the redacter's server stamped it
 * with a clock far behind): age-out takes the REDACT row -- and with it
 * the original, stored under the OLD name.  Left behind, the message
 * would be returned again with nothing to say it was redacted. */
static void test_trim_does_not_undo_a_redact_across_the_rename(void **state)
{
  struct HistoryMessage *m = NULL;
  (void)state;

  retention_days = 7;
  chan_make("#old", now_s - 20 * 86400);
  say("#old", ago(300, 0), "a1");
  say("#old", ago(200, 0), "a2");
  rename_chan("#old", "#new");
  redact("#new", ago(8 * 86400, 0), "r1", "a2");
  assert_int_equal(history_message_is_redacted("#new", "a2"), 1);
  assert_int_equal(history_lookup_message("#new", "a2", &m), 0);
  history_free_messages(m);
  m = NULL;

  trim_until_idle();

  /* the REDACT row has aged out ... */
  assert_int_equal(history_lookup_message("#new", "r1", &m), 1);
  /* ... and the message it hid went with it: not back, unredacted */
  assert_int_equal(history_lookup_message("#new", "a2", &m), 1);
  assert_string_equal(latest("#new", 50), "a1");
  /* the same row is not reachable under the old name either */
  assert_string_equal(latest("#old", 50), "a1");
}

/* The same when the channel has moved on since the REDACT was sent: the
 * REDACT row is under a name that is itself an earlier one by now. */
static void test_trim_redact_after_the_channel_moved_on(void **state)
{
  struct HistoryMessage *m = NULL;
  (void)state;

  retention_days = 7;
  chan_make("#old", now_s - 20 * 86400);
  say("#old", ago(3 * 86400, 0), "a1");
  say("#old", ago(2 * 86400, 0), "a2");
  rename_chan("#old", "#mid");
  redact("#mid", ago(8 * 86400, 0), "r1", "a2");
  rename_chan("#mid", "#new");
  /* a stranger's REDACT row of the same age, naming the same msgid from
   * a channel that never was this one: it takes nothing with it */
  chan_make("#evil", now_s - 20 * 86400);
  redact("#evil", ago(8 * 86400, 5), "x1", "a1");

  trim_until_idle();

  assert_int_equal(history_lookup_message("#evil", "x1", &m), 1);
  assert_int_equal(history_lookup_message("#new", "a2", &m), 1);
  assert_string_equal(latest("#new", 50), "a1");
}

/* Trimming does not undo it either.  The REDACT row is past retention
 * and its original is not (as above), and by now no record joins #b,
 * where the REDACT row is, to #a: the original still goes with it. */
static void test_trim_redact_past_the_names_cap(void **state)
{
  struct HistoryMessage *m = NULL;
  (void)state;

  retention_days = 7;
  redacted_then_renamed_out_of_reach(now_s - 20 * 86400, ago(8 * 86400, 0));

  trim_until_idle();

  assert_int_equal(history_lookup_message("#a", "m1", &m), 1);
  assert_string_equal(latest("#a", 50), "m2");
}

/* ------------------------------------------------------------------ */
/* The burst-loss prune                                                */
/* ------------------------------------------------------------------ */

/* An incarnation that lost a burst loses its rows under every name. */
static void test_purge_incarnation_follows_the_rename(void **state)
{
  (void)state;

  renamed_channel();
  assert_int_equal(history_purge_incarnation("#new", INC), 5);
  assert_string_equal(latest("#new", 50), "");
  chan_gone("#new");
  assert_string_equal(latest("#old", 50), "");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup_teardown(test_pages_follow_the_rename, setup, teardown),
    cmocka_unit_test_setup_teardown(test_msgid_lookups_follow_the_rename, setup, teardown),
    cmocka_unit_test_setup_teardown(test_recreated_old_name_stays_apart, setup, teardown),
    cmocka_unit_test_setup_teardown(test_chain_and_back, setup, teardown),
    cmocka_unit_test_setup_teardown(test_target_latest_follows_the_rename, setup, teardown),
    cmocka_unit_test_setup_teardown(test_same_second_channel_is_not_inherited, setup, teardown),
    cmocka_unit_test_setup_teardown(test_cap_is_logged, setup, teardown),
    cmocka_unit_test_setup_teardown(test_crossing_relocations, setup, teardown),
    cmocka_unit_test_setup_teardown(test_redact_across_the_rename, setup, teardown),
    cmocka_unit_test_setup_teardown(test_redact_survives_the_names_cap, setup, teardown),
    cmocka_unit_test_setup_teardown(test_redact_reaches_the_relocation_tombstone, setup, teardown),
    cmocka_unit_test_setup_teardown(test_trim_does_not_undo_a_redact_across_the_rename, setup, teardown),
    cmocka_unit_test_setup_teardown(test_trim_redact_past_the_names_cap, setup, teardown),
    cmocka_unit_test_setup_teardown(test_trim_redact_after_the_channel_moved_on, setup, teardown),
    cmocka_unit_test_setup_teardown(test_purge_incarnation_follows_the_rename, setup, teardown),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
