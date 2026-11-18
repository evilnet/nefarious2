/*
 * markread_join_cmocka.c - the MARKREAD of a JOIN.
 *
 * Links the REAL m_markread.o (with the ircd's own printf and string
 * helpers) and stubs what is underneath it: the marker store is a small
 * table with metadata_readmarker_set()'s keep-the-newer rule, and the
 * send layer records instead of sending.
 *
 * - The MARKREAD sent after a JOIN goes out as one of the JOIN's replies
 *   (send_reply_line()), which tags it as the TOPIC and NAMES around it
 *   are, @time included -- never as a bare line, never as an event.
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

static int setup(void **state)
{
  (void)state;
  forget();
  nmarks = 0;
  store_up = 1;
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

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(join_markread_is_a_reply_line, setup),
    cmocka_unit_test_setup(join_markread_unknown_is_star, setup),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
