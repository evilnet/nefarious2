/*
 * markread_join_cmocka.c - the MARKREAD of a JOIN, and a renamed
 * channel's read markers.
 *
 * Links the REAL m_markread.o (with the ircd's own printf and string
 * helpers) and stubs what is underneath it: the marker store is a small
 * table with metadata_readmarker_set()'s keep-the-newer rule, and the
 * send layer records instead of sending.
 *
 * - The MARKREAD sent after a JOIN goes out as one of the JOIN's replies
 *   (send_reply_line()), which tags it as the TOPIC and NAMES around it
 *   are, @time included -- never as a bare line, never as an event.
 * - A rename carries the old name's markers to the new one
 *   (markread_channel_renamed(), called by rename_channel() on every
 *   server): the account markers of the channel's members and every
 *   session marker, without lowering a newer marker the new name has.
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
#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "send.h"
#include "session_markread.h"
#include "struct.h"

/* ====================================================================
 * Globals the linked objects expect
 * ==================================================================== */

struct Client me;
struct Client *GlobalClientList;
time_t CurrentTime = 2000000000;
int log_inassert;

/* ====================================================================
 * What the code under test sent
 * ==================================================================== */

#define LINE 512
#define MAXREC 32

static char replies[MAXREC][LINE];      /* send_reply_line() */
static struct Client *reply_to[MAXREC];
static int nreplies;
static int nevents;                     /* sendcmdto_one_event() */

static void forget(void)
{
  nreplies = nevents = 0;
}

void send_reply_line(struct Client *to, const char *pattern, ...)
{
  struct VarData vd;

  assert_true(nreplies < MAXREC);
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  ircd_snprintf(0, replies[nreplies], LINE, "%v", &vd);
  va_end(vd.vd_args);
  reply_to[nreplies++] = to;
}

void sendcmdto_one_event(struct Client *from, const char *cmd,
                         const char *tok, struct Client *to, int respond,
                         const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)to; (void)respond; (void)pattern;
  nevents++;
}

void sendcmdto_serv_butone_v3(struct Client *from, const char *cmd,
                              const char *tok, struct Client *one,
                              const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)one; (void)pattern;
}

int send_reply(struct Client *to, int reply, ...)
{
  (void)to; (void)reply;
  return 0;
}

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  (void)to; (void)command; (void)code; (void)context; (void)description;
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  (void)cptr; (void)pattern;
  return 0;
}

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

void webpush_notify_read(const char *account, const char *target,
                         const char *timestamp)
{
  (void)account; (void)target; (void)timestamp;
}

void presence_apply_close(const char *anchor, int anchor_is_session,
                          const char *channel, int64_t start, int64_t end)
{
  (void)anchor; (void)anchor_is_session; (void)channel; (void)start; (void)end;
}

int64_t presence_norm_time(int64_t v)
{
  return v;
}

/* "2025-01-01T00:00:00.000Z" <-> "1735689600.000" and nothing else is
 * needed: the timestamps below are the unix form, the ISO form is shown
 * as "iso(<unix>)" so a line says which marker it carries. */
int history_unix_to_iso(const char *unix_ts, char *iso_buf, size_t iso_buflen)
{
  snprintf(iso_buf, iso_buflen, "iso(%s)", unix_ts);
  return 0;
}

int history_iso_to_unix(const char *iso_ts, char *unix_buf, size_t unix_buflen)
{
  if (strcmp(iso_ts, "2025-01-01T00:00:00.000Z") != 0)
    return -1;
  snprintf(unix_buf, unix_buflen, "1735689600.000");
  return 0;
}

/* ====================================================================
 * The marker store: (account, target) -> timestamp, keep the newer
 * ==================================================================== */

#define MAXMARK 16

static struct {
  char account[32];
  char target[64];
  char ts[32];
} marks[MAXMARK];
static int nmarks;
static int store_up = 1;
static int store_sets;

int metadata_lmdb_is_available(void)
{
  return store_up;
}

static int mark_find(const char *account, const char *target)
{
  int i;
  for (i = 0; i < nmarks; i++)
    if (!ircd_strcmp(marks[i].account, account)
        && !ircd_strcmp(marks[i].target, target))
      return i;
  return -1;
}

int metadata_readmarker_get(const char *account, const char *target,
                            char *timestamp)
{
  int i = mark_find(account, target);
  if (i < 0)
    return 1;
  strcpy(timestamp, marks[i].ts);
  return 0;
}

int metadata_readmarker_set(const char *account, const char *target,
                            const char *timestamp)
{
  int i = mark_find(account, target);

  store_sets++;
  if (i >= 0) {
    if (strcmp(timestamp, marks[i].ts) <= 0)
      return 1;
  } else {
    assert_true(nmarks < MAXMARK);
    i = nmarks++;
    snprintf(marks[i].account, sizeof(marks[i].account), "%s", account);
    snprintf(marks[i].target, sizeof(marks[i].target), "%s", target);
  }
  snprintf(marks[i].ts, sizeof(marks[i].ts), "%s", timestamp);
  return 0;
}

/* ====================================================================
 * Clients and channels
 * ==================================================================== */

/** A local user with draft/read-marker; @a account may be NULL (then it
 * has session id @a sessid). */
static struct Client *local_user(const char *nick, const char *account,
                                 const char *sessid)
{
  struct Client *c = calloc(1, sizeof(*c));

  assert_non_null(c);
  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  cli_user(c) = calloc(1, sizeof(struct User));
  assert_non_null(cli_user(c));
  cli_status(c) = STAT_USER;
  ircd_strncpy(cli_name(c), nick, sizeof(c->cli_name));
  if (account)
    ircd_strncpy(cli_user(c)->account, account,
                 sizeof(cli_user(c)->account));
  if (sessid)
    ircd_strncpy(cli_session_id(c), sessid, sizeof(c->cli_session_id));
  CapSet(cli_active(c), CAP_DRAFT_READMARKER);
  cli_next(c) = GlobalClientList;
  GlobalClientList = c;
  return c;
}

static struct Channel *channel_named(const char *name)
{
  struct Channel *ch = calloc(1, sizeof(*ch) + strlen(name));

  assert_non_null(ch);
  strcpy(ch->chname, name);
  return ch;
}

static void add_member(struct Channel *ch, struct Client *who)
{
  struct Membership *m = calloc(1, sizeof(*m));

  assert_non_null(m);
  m->user = who;
  m->channel = ch;
  m->next_member = ch->members;
  ch->members = m;
}

static int setup(void **state)
{
  (void)state;
  forget();
  nmarks = 0;
  store_up = 1;
  store_sets = 0;
  GlobalClientList = NULL;
  ircd_strncpy(cli_name(&me), "irc.example", sizeof(me.cli_name));
  return 0;
}

/* ====================================================================
 * The JOIN's MARKREAD
 * ==================================================================== */

/** A known marker goes out as a reply line (tagged like TOPIC/NAMES, so
 * with @time), not as a bare line or an event. */
static void join_markread_is_a_reply_line(void **state)
{
  struct Client *alice = local_user("alice", "alice", NULL);

  (void)state;
  metadata_readmarker_set("alice", "#c", "1735689600.000");
  forget();

  send_markread_on_join(alice, "#c");

  assert_int_equal(nreplies, 1);
  assert_ptr_equal(reply_to[0], alice);
  assert_string_equal(replies[0],
                      ":irc.example MARKREAD #c timestamp=iso(1735689600.000)");
  assert_int_equal(nevents, 0);
}

/** No marker, no store, no account: still one reply line, with `*`. */
static void join_markread_unknown_is_star(void **state)
{
  struct Client *alice = local_user("alice", "alice", NULL);
  struct Client *anon = local_user("anon", NULL, "sess-anon");

  (void)state;
  send_markread_on_join(alice, "#none");
  store_up = 0;
  send_markread_on_join(alice, "#none");
  send_markread_on_join(anon, "#none");

  assert_int_equal(nreplies, 3);
  assert_string_equal(replies[0], ":irc.example MARKREAD #none *");
  assert_string_equal(replies[1], ":irc.example MARKREAD #none *");
  assert_string_equal(replies[2], ":irc.example MARKREAD #none *");
  assert_int_equal(nevents, 0);
}

/* ====================================================================
 * Rename
 * ==================================================================== */

/** The members' account markers follow the channel to its new name; a
 * member without one gets none; a non-member's stays behind. */
static void rename_copies_member_account_markers(void **state)
{
  struct Client *alice = local_user("alice", "alice", NULL);
  struct Client *bob = local_user("bob", "bob", NULL);
  struct Channel *ch = channel_named("#new");
  char ts[32];

  (void)state;
  add_member(ch, alice);
  add_member(ch, bob);
  metadata_readmarker_set("alice", "#old", "1735689600.000");
  metadata_readmarker_set("carol", "#old", "1735689700.000");   /* not a member */

  markread_channel_renamed(ch, "#old", ch->chname);

  assert_int_equal(metadata_readmarker_get("alice", "#new", ts), 0);
  assert_string_equal(ts, "1735689600.000");
  assert_int_equal(metadata_readmarker_get("bob", "#new", ts), 1);
  assert_int_equal(metadata_readmarker_get("carol", "#new", ts), 1);
  /* the old name keeps its marker */
  assert_int_equal(metadata_readmarker_get("alice", "#old", ts), 0);

  /* and the rename fallback's JOIN reports it */
  forget();
  send_markread_on_join(alice, "#new");
  assert_int_equal(nreplies, 1);
  assert_string_equal(replies[0],
                      ":irc.example MARKREAD #new timestamp=iso(1735689600.000)");
}

/** A newer marker the new name already has is kept. */
static void rename_keeps_a_newer_marker(void **state)
{
  struct Client *alice = local_user("alice", "alice", NULL);
  struct Channel *ch = channel_named("#new");
  char ts[32];

  (void)state;
  add_member(ch, alice);
  metadata_readmarker_set("alice", "#old", "1735689600.000");
  metadata_readmarker_set("alice", "#new", "1735689900.000");

  markread_channel_renamed(ch, "#old", ch->chname);

  assert_int_equal(metadata_readmarker_get("alice", "#new", ts), 0);
  assert_string_equal(ts, "1735689900.000");
}

/** With the store down, nothing is read or written. */
static void rename_without_store_touches_nothing(void **state)
{
  struct Client *alice = local_user("alice", "alice", NULL);
  struct Channel *ch = channel_named("#new");

  (void)state;
  add_member(ch, alice);
  store_up = 0;
  store_sets = 0;

  markread_channel_renamed(ch, "#old", ch->chname);

  assert_int_equal(store_sets, 0);
}

/** Session markers (clients without an account) follow too. */
static void rename_copies_session_markers(void **state)
{
  struct Client *anon = local_user("anon", NULL, "sess-rename");
  struct Channel *ch = channel_named("#snew");
  char *parv[] = { "anon", "#sold", "timestamp=2025-01-01T00:00:00.000Z", NULL };

  (void)state;
  add_member(ch, anon);
  m_markread(anon, anon, 3, parv);      /* session marker on #sold */
  forget();

  markread_channel_renamed(ch, "#sold", ch->chname);
  send_markread_on_join(anon, "#snew");

  assert_int_equal(nreplies, 1);
  assert_string_equal(replies[0],
                      ":irc.example MARKREAD #snew timestamp=iso(1735689600.000)");
}

/* ====================================================================
 * Relocation
 * ==================================================================== */

/** A relocation copies from the old channel, still under its old name
 * and holding every member: the mover's and the stayer's account
 * markers, and the session markers, go to the new name; the old name
 * keeps them (the tombstone lives on). */
static void relocation_copies_the_old_channels_markers(void **state)
{
  struct Client *alice = local_user("alice", "alice", NULL);
  struct Client *bob = local_user("bob", "bob", NULL);
  struct Client *anon = local_user("anon", NULL, "sess-reloc");
  struct Channel *ch = channel_named("#rold");
  char *parv[] = { "anon", "#rold", "timestamp=2025-01-01T00:00:00.000Z", NULL };
  char ts[32];

  (void)state;
  add_member(ch, alice);
  add_member(ch, bob);
  add_member(ch, anon);
  metadata_readmarker_set("alice", "#rold", "1735689600.000");
  metadata_readmarker_set("bob", "#rold", "1735689700.000");
  m_markread(anon, anon, 3, parv);      /* session marker on #rold */

  markread_channel_renamed(ch, ch->chname, "#rnew");

  assert_int_equal(metadata_readmarker_get("alice", "#rnew", ts), 0);
  assert_string_equal(ts, "1735689600.000");
  assert_int_equal(metadata_readmarker_get("bob", "#rnew", ts), 0);
  assert_string_equal(ts, "1735689700.000");
  assert_int_equal(metadata_readmarker_get("alice", "#rold", ts), 0);

  /* the mover's JOIN of the new name reports its marker, not `*` */
  forget();
  send_markread_on_join(alice, "#rnew");
  assert_int_equal(nreplies, 1);
  assert_string_equal(replies[0],
                      ":irc.example MARKREAD #rnew timestamp=iso(1735689600.000)");
  forget();
  send_markread_on_join(anon, "#rnew");
  assert_int_equal(nreplies, 1);
  assert_string_equal(replies[0],
                      ":irc.example MARKREAD #rnew timestamp=iso(1735689600.000)");
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(join_markread_is_a_reply_line, setup),
    cmocka_unit_test_setup(join_markread_unknown_is_star, setup),
    cmocka_unit_test_setup(rename_copies_member_account_markers, setup),
    cmocka_unit_test_setup(rename_keeps_a_newer_marker, setup),
    cmocka_unit_test_setup(rename_without_store_touches_nothing, setup),
    cmocka_unit_test_setup(rename_copies_session_markers, setup),
    cmocka_unit_test_setup(relocation_copies_the_old_channels_markers, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
