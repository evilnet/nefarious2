/*
 * redact_judge_cmocka.c - a redaction from elsewhere judges the row a client
 * could act on
 *
 * A channel destroyed and created again is a new incarnation; the rows of
 * the old one stay in the store until the trim takes them, hidden from
 * every history walk (row_incarnation_ok, history.c).  REDACT from a local
 * client finds such a row "not found" (history_lookup_live_message), and
 * so must a redaction that reaches this server from elsewhere -- a peer's
 * live REDACT, a catch-up row, a write-forwarded REDACT row -- or the old
 * incarnation's message would be redacted, and a catch-up row shown to the
 * new channel's members, for a message none of them can see.
 *
 * This links the real m_redact.o and redact_index.o.  The store is two
 * answers: what history_lookup_message() finds (every row) and what
 * history_lookup_live_message() finds (the live incarnation's).
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
#include <cmocka.h>

#include "channel.h"
#include "client.h"
#include "history.h"
#include "ircd_features.h"
#include "redact_index.h"
#include "struct.h"

extern int redact_row_judge(const char *target, const char *msgid);
extern int redact_apply_row(struct Client *src, struct Channel *chptr,
                            const char *msgid, const char *redact_msgid,
                            uint64_t time_ms, const char *reason,
                            const char *sender_str, const char *account_str,
                            int show_always);
extern int m_redact(struct Client *cptr, struct Client *sptr, int parc,
                    char *parv[]);

/* ------------------------------------------------------------------ */
/* The store                                                           */
/* ------------------------------------------------------------------ */

static int row_stored;          /* the message is in the store */
static int row_live;            /* ... and belongs to the live incarnation */
static int redacted_rows;       /* history_redact_message() calls */
static int stored_rows;         /* history_store_message() calls */
static int live_lookups, raw_lookups;
static int lookup_fails;        /* the store cannot be read */

int history_is_available(void)
{
  return 1;
}

static int lookup(int found, struct HistoryMessage **msg)
{
  *msg = NULL;
  if (!found)
    return 1;
  *msg = calloc(1, sizeof(**msg));
  assert_non_null(*msg);
  return 0;
}

int history_lookup_message(const char *target, const char *msgid,
                           struct HistoryMessage **msg)
{
  (void)target; (void)msgid;
  raw_lookups++;
  return lookup(row_stored, msg);
}

int history_lookup_live_message(const char *target, const char *msgid,
                                struct HistoryMessage **msg)
{
  (void)target; (void)msgid;
  live_lookups++;
  if (lookup_fails) {
    *msg = NULL;
    return -1;
  }
  return lookup(row_stored && row_live, msg);
}

void history_free_messages(struct HistoryMessage *list)
{
  free(list);
}

int history_message_is_redacted(const char *target, const char *msgid)
{
  (void)target; (void)msgid;
  return 0;
}

int history_redact_message(const char *target, const char *msgid)
{
  (void)target; (void)msgid;
  redacted_rows++;
  return 0;
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *original_target,
                          const char *sender, const char *account,
                          enum HistoryMessageType type,
                          const char *content, const char *client_tags,
                          const char *owner)
{
  (void)msgid; (void)timestamp; (void)target; (void)original_target;
  (void)sender; (void)account; (void)content; (void)client_tags;
  (void)owner;
  assert_int_equal(type, HISTORY_REDACT);
  stored_rows++;
  return 0;
}

int htc_owner_key(char *buf, size_t size, const char *account,
                  const void *ip, const char *server)
{
  (void)ip; (void)server;
  snprintf(buf, size, "a:%s", account);
  return 0;
}

/* ------------------------------------------------------------------ */
/* A local REDACT (m_redact): one member of one channel                */
/* ------------------------------------------------------------------ */

static struct Channel *the_chan;
static struct Membership the_member;
static char last_fail[64];      /* the code of the last FAIL sent */
static int fails_sent;

int feature_bool(enum Feature feat)
{
  return feat == FEAT_CAP_draft_message_redaction;
}

struct Channel *hSeekChannel(const char *name)
{
  return (the_chan && 0 == strcmp(name, the_chan->chname)) ? the_chan : NULL;
}

struct Membership *find_member_link(struct Channel *chptr, const struct Client *cptr)
{
  (void)cptr;
  return chptr == the_chan ? &the_member : NULL;
}

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  (void)to; (void)context; (void)description;
  assert_string_equal(command, "REDACT");
  snprintf(last_fail, sizeof(last_fail), "%s", code);
  fails_sent++;
}

/* Run "REDACT #c <msgid>" from a client; @a oper and @a chanop set who it
 * is.  Anything past the authorization -- a stored row, the fan-out, the
 * relay -- fails the case (redact_judge_stubs.c) or is counted. */
static void local_redact(int oper, int chanop, const char *msgid)
{
  struct Client *c = calloc(1, sizeof(*c));
  struct User *u = calloc(1, sizeof(*u));
  char *parv[] = { "n", "#c", (char *)msgid, NULL };

  assert_non_null(c);
  assert_non_null(u);
  the_chan = calloc(1, sizeof(*the_chan) + 8);  /* chname[] runs on */
  assert_non_null(the_chan);
  strcpy(the_chan->chname, "#c");
  memset(&the_member, 0, sizeof(the_member));
  if (chanop)
    the_member.status = CHFL_CHANOP;
  cli_user(c) = u;
  if (oper)
    FlagSet(&cli_flags(c), FLAG_OPER);
  assert_int_equal(m_redact(c, c, 3, parv), 0);
  free(the_chan);
  the_chan = NULL;
  free(u);
  free(c);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static int reset(void **state)
{
  (void)state;
  row_stored = row_live = 0;
  redacted_rows = stored_rows = live_lookups = raw_lookups = 0;
  lookup_fails = fails_sent = 0;
  last_fail[0] = '\0';
  return 0;
}

/* The live incarnation's message: applied. */
static void live_row_is_applied(void **state)
{
  (void)state;
  row_stored = row_live = 1;
  assert_int_equal(redact_row_judge("#c", "m1"), RDX_ROW_APPLY);
}

/* The previous incarnation's message is no message of this channel: an
 * orphan, as when the store never held it. */
static void previous_incarnation_row_is_an_orphan(void **state)
{
  (void)state;
  row_stored = 1;
  assert_int_equal(redact_row_judge("#c", "m1"), RDX_ROW_SKIP_ORPHAN);
  assert_int_equal(raw_lookups, 0);
  assert_int_equal(live_lookups, 1);

  row_stored = 0;               /* the same answer as a row never stored */
  assert_int_equal(redact_row_judge("#c", "m2"), RDX_ROW_SKIP_ORPHAN);
}

/* A catch-up row for the previous incarnation's message: the old row is
 * left alone, a tombstone is kept (as for any orphan), and nobody is
 * shown it -- an announce would need a sender, which this call has none
 * of, and would fail the case. */
static void catchup_row_leaves_previous_incarnation_alone(void **state)
{
  struct Channel *ch = calloc(1, sizeof(*ch) + 8);  /* chname[] runs on */
  int d;

  (void)state;
  assert_non_null(ch);
  strcpy(ch->chname, "#c");
  row_stored = 1;
  d = redact_apply_row(NULL, ch, "m1", "r1", 1700000000123ULL, "why",
                       "n!u@h", "acct", 0);
  assert_int_equal(d, RDX_ROW_SKIP_ORPHAN);
  assert_int_equal(redacted_rows, 0);
  assert_int_equal(stored_rows, 1);   /* the tombstone */
  free(ch);
}

/* A local REDACT whose row the store cannot read cannot be authorized:
 * it is refused, and nothing is stored, shown or relayed -- whoever asks,
 * an IRC operator and a chanop included (the rule needs the row: its type,
 * its sender, its time). */
static void local_redact_refused_when_the_row_cannot_be_read(void **state)
{
  (void)state;
  lookup_fails = 1;

  local_redact(0, 0, "m1");
  assert_int_equal(live_lookups, 1);
  assert_int_equal(fails_sent, 1);
  assert_string_equal(last_fail, "INTERNAL_ERROR");

  local_redact(1, 1, "m1");
  assert_int_equal(fails_sent, 2);
  assert_string_equal(last_fail, "INTERNAL_ERROR");

  assert_int_equal(redacted_rows, 0);
  assert_int_equal(stored_rows, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(live_row_is_applied, reset),
    cmocka_unit_test_setup(previous_incarnation_row_is_an_orphan, reset),
    cmocka_unit_test_setup(catchup_row_leaves_previous_incarnation_alone, reset),
    cmocka_unit_test_setup(local_redact_refused_when_the_row_cannot_be_read, reset),
  };

  return cmocka_run_group_tests_name("redact_judge", tests, NULL, NULL);
}
