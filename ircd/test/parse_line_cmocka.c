/*
 * parse_line_cmocka.c - a line that ends after its tags or its source
 * prefix is parsed from its own bytes only, never from what is left in
 * the buffer after its terminator
 *
 * A connection's input buffer is reused line after line: a line is copied
 * in from offset 0 and NUL-terminated, and whatever a longer earlier line
 * left after that NUL is still there.  parse_server() stepped over the NUL
 * in three places:
 *
 *  - a line of tags, a space and nothing else ("@x ", which also covers
 *    the S2S compact form "@A<time><msgid> ") reached the numeric-prefix
 *    code with the cursor on the NUL; that reported "Missing Prefix" and
 *    then advanced past the NUL, so the earlier line's tail was parsed as
 *    this line's command -- and run, with the link as its source;
 *  - an unknown source prefix with nothing after it read ch[1] (the "SQ"
 *    test) when ch[0] was the NUL, and ch[2] (the "KILL" test) when ch[1]
 *    was;
 *  - a one-character numeric prefix at the end of the line read ch[2].
 *
 * parse_client() is checked for the same edge cases: its tag and prefix
 * skips stop at the NUL.
 *
 * This includes the real parse.c, compiled with -ffunction-sections and
 * linked with --gc-sections, so the program keeps parse_server(),
 * parse_client() and what they call, and nothing else of parse.c (not the
 * message table and its handlers): only those need the ircd around them
 * here.  Each case runs the line twice over: alone in a zeroed buffer
 * (the reference), and after a previous line laid out so that a parser
 * reading past the terminator would run it, plus single-byte fillers that
 * steer the ch[1]/ch[2] tests.  The outcome must be the reference one
 * every time -- and the reference outcome is checked against the expected
 * one.  Each line is also parsed from an exact-size heap block, so a read
 * past the terminator is an out-of-bounds read under valgrind or ASan.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

/* parse.c's own comments name a vendor tag namespace with a trailing
 * slash-star, which -Wall's -Wcomment reports; it is parse.c's, not ours. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcomment"
#include "../parse.c"
#pragma GCC diagnostic pop

/* ------------------------------------------------------------------ */
/* The ircd around parse_server() and parse_client()                   */
/* ------------------------------------------------------------------ */

time_t CurrentTime;
int log_inassert;
struct Client me;
static struct ServerStatistics server_stats;
struct ServerStatistics *ServerStats = &server_stats;

static struct Connection me_con, leaf_con, user_con;
static struct Client leaf;       /* leafa.test, numeric AC, our link */
static struct Client user;       /* a registered local client */
static struct User user_user;

/** What one parse did, beyond its return value. */
static struct {
  int handler_calls;       /* a command handler ran */
  char handler_cmd[16];    /* which (token) */
  char handler_par1[64];   /* its first parameter */
  int violations;          /* protocol_violation() */
  int numerics;            /* send_reply() */
  int last_numeric;
  int do_numeric;          /* do_numeric() */
  int kills;               /* sendcmdto_one() (the unknown-numeric KILL) */
  char label[64];          /* the label the PING handler saw */
  char batch_tag[128];     /* the batch= tag the PING handler saw */
  int concat;              /* and draft/multiline-concat */
} seen;

static void record_handler(const char *cmd, int parc, char *parv[])
{
  seen.handler_calls++;
  snprintf(seen.handler_cmd, sizeof(seen.handler_cmd), "%s", cmd);
  snprintf(seen.handler_par1, sizeof(seen.handler_par1), "%s",
           parc > 1 && parv[1] ? parv[1] : "");
}

static int h_ping(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)sptr;
  snprintf(seen.label, sizeof(seen.label), "%s",
           IsServer(cptr) ? "" : cli_label(cptr));
  snprintf(seen.batch_tag, sizeof(seen.batch_tag), "%s",
           IsServer(cptr) ? "" : cli_msg_batch_tag(cptr));
  seen.concat = IsServer(cptr) ? 0 : cli_msg_concat(cptr);
  record_handler("PING", parc, parv);
  return 0;
}

static int h_kick(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr;
  record_handler("KICK", parc, parv);
  return 0;
}

static int h_squit(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr;
  record_handler("SQUIT", parc, parv);
  return 0;
}

static int h_kill(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr;
  record_handler("KILL", parc, parv);
  return 0;
}

static int h_nick(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr;
  record_handler("NICK", parc, parv);
  return 0;
}

static int h_privmsg(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr;
  record_handler("PRIVMSG", parc, parv);
  return 0;
}

#define ALL_HANDLERS(h) { h, h, h, h, h }   /* LAST_HANDLER_TYPE */
static struct Message test_msgs[] = {
  { "PING", "G", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_ping), NULL },
  { "KICK", "K", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_kick), NULL },
  { "SQUIT", "SQ", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_squit), NULL },
  { "KILL", "D", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_kill), NULL },
  { "NICK", "N", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_nick), NULL },
  { "PRIVMSG", "P", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_privmsg), NULL },
  { "BATCH", "BT", 0, MAXPARA, 0, 0, NULL, ALL_HANDLERS(h_privmsg), NULL },
};

/* parse_client() compares the handler with these two. */
int m_ping(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr; (void)parc; (void)parv;
  return 0;
}

int m_ignore(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  (void)cptr; (void)sptr; (void)parc; (void)parv;
  return 0;
}

/* Quiet: parse_*() log every line they parse. */
void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

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

const char *get_client_name(const struct Client *sptr, int showip)
{
  (void)showip;
  return cli_name(sptr);
}

/* FindClient() is a macro over this. */
struct Client *hSeekClient(const char *name, int TMask)
{
  (void)TMask;
  if (!strcmp(name, "leafa.test"))
    return &leaf;
  if (!strcmp(name, "hub.test"))
    return &me;
  return NULL;
}

/* A server numeric, or a user numnick's server part (its first two). */
struct Client *FindNServer(const char *numeric)
{
  return strncmp(numeric, "AC", 2) ? NULL : &leaf;
}

struct Client *findNUser(const char *yxx)
{
  (void)yxx;
  return NULL;
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  (void)cptr; (void)pattern;
  seen.violations++;
  return 0;
}

int send_reply(struct Client *to, int reply, ...)
{
  (void)to;
  seen.numerics++;
  seen.last_numeric = reply;
  return 0;
}

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)to; (void)pattern;
  seen.kills++;
}

int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
               int parc, char *parv[])
{
  (void)numeric; (void)nnn; (void)cptr; (void)sptr; (void)parc; (void)parv;
  seen.do_numeric++;
  return 0;
}

int feature_bool(enum Feature feat)
{
  return feat == FEAT_CAP_labeled_response;
}

int feature_int(enum Feature feat)
{
  (void)feat;
  return 0;
}

/* S2S compact tags: the HLC receive. */
uint64_t base64toint_64(const char *str)
{
  (void)str;
  return 0;
}

unsigned int base64toint(const char *str)
{
  (void)str;
  return 0;
}

uint64_t hlc_max_forward_ms(void)
{
  return 0;
}

int hlc_global_receive(const struct HLC *remote, uint64_t max_forward_ms,
                       uint64_t *ahead)
{
  (void)remote; (void)max_forward_ms; (void)ahead;
  return 0;
}

void sendto_opmask_butone_ratelimited(struct Client *one, unsigned int mask,
                                      time_t *rate, const char *pattern, ...)
{
  (void)one; (void)mask; (void)rate; (void)pattern;
}

int bounce_hold_mark_valid(char mark)
{
  return mark == 'h' || mark == 'p' || mark == 'n';
}

/* parse_client() */
void fwd_label_close_draining(struct Client *cptr)
{
  (void)cptr;
}

int is_client_tag_denied(const char *tag, size_t len)
{
  (void)tag; (void)len;
  return 0;
}

int is_reserved_vendor_tag(const char *tag, size_t len)
{
  (void)tag; (void)len;
  return 0;
}

struct Shun *shun_lookup(struct Client *cptr, unsigned int flags)
{
  (void)cptr; (void)flags;
  return NULL;
}

int get_lag_min(struct Client *cptr)
{
  (void)cptr;
  return -1;
}

static int test_lagfactor;         /* 0: no fake lag (the default) */

int get_lag_factor(struct Client *cptr)
{
  (void)cptr;
  return test_lagfactor;
}

void batch_end_line(struct Client *cptr)
{
  (void)cptr;
}

void labeled_batch_end(struct Client *cptr)
{
  (void)cptr;
}

void send_labeled_ack(struct Client *cptr)
{
  (void)cptr;
}

void bounce_record_activity(struct Client *cptr)
{
  (void)cptr;
}

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

static int group_setup(void **state)
{
  size_t i;

  (void)state;
  memset(&msg_tree, 0, sizeof(msg_tree));
  memset(&tok_tree, 0, sizeof(tok_tree));
  for (i = 0; i < sizeof(test_msgs) / sizeof(test_msgs[0]); i++) {
    add_msg_element(&msg_tree, &test_msgs[i], test_msgs[i].cmd);
    add_msg_element(&tok_tree, &test_msgs[i], test_msgs[i].tok);
  }

  cli_connect(&me) = &me_con;    /* cli_from() is the Connection's */
  ircd_strncpy(cli_name(&me), "hub.test", sizeof(cli_name(&me)));
  cli_from(&me) = &me;
  cli_status(&me) = STAT_ME;

  cli_connect(&leaf) = &leaf_con;
  ircd_strncpy(cli_name(&leaf), "leafa.test", sizeof(cli_name(&leaf)));
  cli_from(&leaf) = &leaf;
  cli_status(&leaf) = STAT_SERVER;
  con_handler(&leaf_con) = SERVER_HANDLER;

  cli_connect(&user) = &user_con;
  ircd_strncpy(cli_name(&user), "tagger", sizeof(cli_name(&user)));
  cli_from(&user) = &user;
  cli_status(&user) = STAT_USER;
  cli_user(&user) = &user_user;
  con_handler(&user_con) = CLIENT_HANDLER;
  CapSet(cli_active(&user), CAP_MSGTAGS);
  return 0;
}

/** Everything a parse is judged by. */
struct outcome {
  int ret;
  int handler_calls;
  char handler_cmd[16];
  char handler_par1[64];
  int violations;
  int numerics, last_numeric;
  int do_numeric;
  int kills;
  unsigned int empt, unpf, unco, wrdi, ref;
};

typedef int (*parse_fn)(struct Client *, char *, char *);

static void run(parse_fn fn, struct Client *cptr, char *buf, size_t len,
                struct outcome *o)
{
  struct ServerStatistics before = server_stats;

  memset(&seen, 0, sizeof(seen));
  o->ret = fn(cptr, buf, buf + len);
  o->handler_calls = seen.handler_calls;
  memcpy(o->handler_cmd, seen.handler_cmd, sizeof(o->handler_cmd));
  memcpy(o->handler_par1, seen.handler_par1, sizeof(o->handler_par1));
  o->violations = seen.violations;
  o->numerics = seen.numerics;
  o->last_numeric = seen.last_numeric;
  o->do_numeric = seen.do_numeric;
  o->kills = seen.kills;
  o->empt = server_stats.is_empt - before.is_empt;
  o->unpf = server_stats.is_unpf - before.is_unpf;
  o->unco = server_stats.is_unco - before.is_unco;
  o->wrdi = server_stats.is_wrdi - before.is_wrdi;
  o->ref = server_stats.is_ref - before.is_ref;
}

static void assert_same(const char *line, const char *how,
                        const struct outcome *want, const struct outcome *got)
{
  if (want->ret != got->ret || want->handler_calls != got->handler_calls
      || strcmp(want->handler_cmd, got->handler_cmd)
      || strcmp(want->handler_par1, got->handler_par1)
      || want->violations != got->violations || want->numerics != got->numerics
      || want->last_numeric != got->last_numeric
      || want->do_numeric != got->do_numeric || want->kills != got->kills
      || want->empt != got->empt || want->unpf != got->unpf
      || want->unco != got->unco || want->wrdi != got->wrdi
      || want->ref != got->ref)
    fail_msg("\"%s\" %s: ret %d/%d, handler %d %s(%s)/%d %s(%s), violations %d/%d, "
             "numerics %d/%d, kills %d/%d, empty %u/%u, unknown prefix %u/%u, "
             "unknown command %u/%u, wrong direction %u/%u (reference/this run)",
             line, how, want->ret, got->ret,
             want->handler_calls, want->handler_cmd, want->handler_par1,
             got->handler_calls, got->handler_cmd, got->handler_par1,
             want->violations, got->violations, want->numerics, got->numerics,
             want->kills, got->kills, want->empt, got->empt, want->unpf, got->unpf,
             want->unco, got->unco, want->wrdi, got->wrdi);
}

#define BUFLEN 256

/** Parse \a line every way: alone (the reference), after previous lines
 * and fillers that a parser reading past the terminator would act on, and
 * from an exact-size heap block.  Every run must match the reference.
 * @return The reference outcome, for the case to check. */
static struct outcome parse_every_way(parse_fn fn, struct Client *cptr,
                                      const char *line)
{
  static const char fillers[] = { ' ', 'Q', 'L', 'N', 'I', ':', '@', 'G' };
  struct outcome ref, o;
  char buf[BUFLEN], prev[BUFLEN];
  size_t len = strlen(line), i;
  char *exact;

  assert_true(len + 40 < BUFLEN);

  /* the reference: nothing after the terminator */
  memset(buf, 0, sizeof(buf));
  memcpy(buf, line, len);
  run(fn, cptr, buf, len, &ref);

  /* an exact-size block: a read past the NUL is out of bounds */
  exact = malloc(len + 1);
  assert_non_null(exact);
  memcpy(exact, line, len + 1);
  run(fn, cptr, exact, len, &o);
  free(exact);
  assert_same(line, "from an exact-size block", &ref, &o);

  /* a previous line whose tail is a command: an unknown word long enough
   * to cover this line and its NUL, then the command (a PING from the
   * link, or from the client) */
  snprintf(prev, sizeof(prev), "%.*s G :stale PING :stale", (int)(len + 3),
           "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
           "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
           "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
  memset(buf, 0, sizeof(buf));
  memcpy(buf, prev, strlen(prev));
  memcpy(buf, line, len);
  buf[len] = '\0';
  run(fn, cptr, buf, len, &o);
  assert_same(line, "after a previous line", &ref, &o);

  /* the same, with the command right after the terminator */
  memset(buf, 0, sizeof(buf));
  snprintf(buf + len + 1, sizeof(buf) - len - 1, "G :stale");
  memcpy(buf, line, len);
  run(fn, cptr, buf, len, &o);
  assert_same(line, "with G after the terminator", &ref, &o);

  /* single bytes the SQUIT / KILL / nick-change tests look at */
  for (i = 0; i < sizeof(fillers); i++) {
    char how[40];

    memset(buf, fillers[i], sizeof(buf));
    memcpy(buf, line, len);
    buf[len] = '\0';
    run(fn, cptr, buf, len, &o);
    snprintf(how, sizeof(how), "with '%c' after the terminator", fillers[i]);
    assert_same(line, how, &ref, &o);
  }

  return ref;
}

static void expect_empty(const char *line, const struct outcome *o)
{
  if (o->ret != -1 || o->handler_calls || o->empt != 1 || o->violations
      || o->numerics || o->kills || o->unpf || o->unco)
    fail_msg("\"%s\": want an empty line (-1, empty 1, nothing run or sent); "
             "got ret %d, handler %d %s, empty %u, unknown prefix %u, "
             "unknown command %u, violations %d, numerics %d, kills %d",
             line, o->ret, o->handler_calls, o->handler_cmd, o->empt, o->unpf,
             o->unco, o->violations, o->numerics, o->kills);
}

static void expect_unknown_prefix(const char *line, const struct outcome *o)
{
  if (o->ret != 0 || o->handler_calls || o->empt || o->unpf != 1
      || o->violations || o->numerics || o->kills)
    fail_msg("\"%s\": want a dropped unknown prefix (0, unknown prefix 1, "
             "nothing run or sent); got ret %d, handler %d %s, empty %u, "
             "unknown prefix %u, violations %d, numerics %d, kills %d",
             line, o->ret, o->handler_calls, o->handler_cmd, o->empt, o->unpf,
             o->violations, o->numerics, o->kills);
}

static void expect_handler(const char *line, const struct outcome *o,
                           const char *cmd, const char *par1)
{
  if (o->handler_calls != 1 || strcmp(o->handler_cmd, cmd)
      || strcmp(o->handler_par1, par1) || o->violations || o->empt)
    fail_msg("\"%s\": want %s(%s); got handler %d %s(%s), ret %d, empty %u, "
             "violations %d", line, cmd, par1, o->handler_calls,
             o->handler_cmd, o->handler_par1, o->ret, o->empt, o->violations);
}

/* ------------------------------------------------------------------ */
/* parse_server()                                                      */
/* ------------------------------------------------------------------ */

#define COMPACT "@A" "BBBBBBB" "AAAAAAAAAAAAAA"   /* version A, 1+7+14 */

/* Tags, then nothing: an empty line.  It used to report "Missing Prefix"
 * and run the previous line's tail. */
static void server_tags_then_nothing_is_an_empty_line(void **state)
{
  static const char *const lines[] = {
    "@x ", "@x   ", "@ ", "@+tag=value ", "@label=a;+b=c ",
    COMPACT " ", COMPACT "   ", COMPACT ",Sabc,Hh ", COMPACT ",Cfoo=bar ",
    "@A ",
  };
  size_t i;

  (void)state;
  for (i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    struct outcome o = parse_every_way(parse_server, &leaf, lines[i]);
    expect_empty(lines[i], &o);
  }
}

/* A source prefix and nothing after it. */
static void server_prefix_then_nothing(void **state)
{
  static const char *const empty[] = {
    "AC ", "AC   ", ":leafa.test ", "@x :leafa.test ", "@x AC ",
    COMPACT " AC ", COMPACT " :leafa.test ",
  };
  static const char *const unknown[] = {
    /* the prefix names nobody: dropped, whatever the bytes after it */
    ":nosuch.test ", "@x :nosuch.test ", "ZZZZZ ", "ZZZZZ", "AC", "A",
    "ZZZ", "@x", "@", COMPACT, "@x ZZZZZ ",
  };
  size_t i;

  (void)state;
  for (i = 0; i < sizeof(empty) / sizeof(empty[0]); i++) {
    struct outcome o = parse_every_way(parse_server, &leaf, empty[i]);
    expect_empty(empty[i], &o);
  }
  for (i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++) {
    struct outcome o = parse_every_way(parse_server, &leaf, unknown[i]);
    expect_unknown_prefix(unknown[i], &o);
  }
}

/* A P9 prefix with no space after it, and a P9 prefix of another
 * direction. */
static void server_p9_prefix_edges(void **state)
{
  static const char *const lines[] = {
    ":leafa.test", "@x :leafa.test", ":nosuch.test", "@x :nosuch.test", ":",
  };
  struct outcome o;
  size_t i;

  (void)state;
  for (i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    o = parse_every_way(parse_server, &leaf, lines[i]);
    if (o.ret != -1 || o.handler_calls || o.empt || o.unpf || o.violations)
      fail_msg("\"%s\": want -1 and nothing else; got ret %d, handler %d, "
               "empty %u, unknown prefix %u", lines[i], o.ret,
               o.handler_calls, o.empt, o.unpf);
  }
  o = parse_every_way(parse_server, &leaf, ":hub.test ");
  assert_int_equal(o.ret, 0);
  assert_int_equal(o.wrdi, 1);
  assert_int_equal(o.handler_calls, 0);
}

/* An unknown prefix lets SQUIT and KILL through (they travel against a
 * split), and asks for a KILL of an unknown nick-change source -- but only
 * for a command that is on the line. */
static void server_unknown_prefix_exceptions_read_only_the_line(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_server, &leaf, "ZZZZZ K");
  expect_unknown_prefix("ZZZZZ K", &o);
  o = parse_every_way(parse_server, &leaf, "ZZZZZ KI");
  expect_unknown_prefix("ZZZZZ KI", &o);
  o = parse_every_way(parse_server, &leaf, "ZZZZZ S");
  expect_unknown_prefix("ZZZZZ S", &o);
  o = parse_every_way(parse_server, &leaf, ":nosuch.test S");
  expect_unknown_prefix(":nosuch.test S", &o);

  o = parse_every_way(parse_server, &leaf, "ZZZZZ SQ x 0 :gone");
  expect_handler("ZZZZZ SQ x 0 :gone", &o, "SQUIT", "x");
  o = parse_every_way(parse_server, &leaf, ":nosuch.test SQ x 0 :gone");
  expect_handler(":nosuch.test SQ x 0 :gone", &o, "SQUIT", "x");
  o = parse_every_way(parse_server, &leaf, "ZZZZZ D ABAAA :bye");
  expect_handler("ZZZZZ D ABAAA :bye", &o, "KILL", "ABAAA");
  o = parse_every_way(parse_server, &leaf, "ACZZZ N newnick 1");
  assert_int_equal(o.kills, 1);
  assert_int_equal(o.handler_calls, 0);
}

/* Lines with a command still parse as they did. */
static void server_ordinary_lines(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_server, &leaf, "AC G :hello");
  expect_handler("AC G :hello", &o, "PING", "hello");
  o = parse_every_way(parse_server, &leaf, "@x AC G :hello");
  expect_handler("@x AC G :hello", &o, "PING", "hello");
  o = parse_every_way(parse_server, &leaf, COMPACT ",Sabc AC G :hello");
  expect_handler(COMPACT ",Sabc AC G :hello", &o, "PING", "hello");
  o = parse_every_way(parse_server, &leaf, "@x   :leafa.test   PING   x");
  expect_handler("@x   :leafa.test   PING   x", &o, "PING", "x");
  o = parse_every_way(parse_server, &leaf, "AC G");
  expect_handler("AC G", &o, "PING", "");
  /* no prefix: reported, and the line is the link's own */
  o = parse_every_way(parse_server, &leaf, " G :x");
  assert_int_equal(o.violations, 1);
  /* a numeric reply */
  o = parse_every_way(parse_server, &leaf, "AC 401 ABAAA x :No such nick");
  assert_int_equal(o.do_numeric, 1);
}

/* A compact tag segment the parser does not know is skipped, and the
 * line and the segments after it are read as usual.  A new segment is
 * rolled out on exactly this: an older server ignores it.  (The same
 * lines -- ,F included -- were run against e81d12aa's parse.c, which
 * does not know ,F, with the same result for the line and its ,C.) */
static void server_unknown_segment_is_skipped(void **state)
{
  static const char *const lines[] = {
    COMPACT ",Qzz,Cfoo=bar AC G :hello",
    COMPACT ",Sabc,Qzz,Cfoo=bar AC G :hello",
    COMPACT ",FAAAAAAAAAAAAAB,Cfoo=bar AC G :hello",
    COMPACT ",Q,FAAAAAAAAAAAAAB,Cfoo=bar AC G :hello",
  };
  size_t i;

  (void)state;
  for (i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    struct outcome o = parse_every_way(parse_server, &leaf, lines[i]);
    expect_handler(lines[i], &o, "PING", "hello");
    assert_string_equal(cli_s2s_client_tags(&leaf), "foo=bar");
  }
}

/* The multiline fallback mark ,F<msgid>: kept for the line it came on,
 * gone with the next line; present but empty still marks the line. */
static void server_fallback_segment(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_server, &leaf, COMPACT ",FAAAAAAAAAAAAAB,Cfoo=bar AC G :hello");
  expect_handler("fallback mark", &o, "PING", "hello");
  assert_string_equal(cli_s2s_fallback(&leaf), "AAAAAAAAAAAAAB");
  o = parse_every_way(parse_server, &leaf, COMPACT ",Sabc,Hh,F,Cfoo=bar AC G :hello");
  assert_string_equal(cli_s2s_fallback(&leaf), "?");
  o = parse_every_way(parse_server, &leaf, COMPACT " AC G :hello");
  assert_string_equal(cli_s2s_fallback(&leaf), "");
  /* Too long for the buffer (>= 64 bytes): still a mark, "?". */
  o = parse_every_way(parse_server, &leaf, COMPACT
      ",F0123456789012345678901234567890123456789012345678901234567890123,Cfoo=bar AC G :hello");
  expect_handler("long fallback mark", &o, "PING", "hello");
  assert_string_equal(cli_s2s_fallback(&leaf), "?");
  assert_string_equal(cli_s2s_client_tags(&leaf), "foo=bar");
  /* Repeated: the last one counts. */
  o = parse_every_way(parse_server, &leaf, COMPACT ",FAAAAAAAAAAAAAB,FBBBBBBBBBBBBBC AC G :hello");
  assert_string_equal(cli_s2s_fallback(&leaf), "BBBBBBBBBBBBBC");
  /* Only a tag region's own segment sets it: inside ,C it is text. */
  o = parse_every_way(parse_server, &leaf, COMPACT ",C+x=a,FAAAAAAAAAAAAAB AC G :hello");
  assert_string_equal(cli_s2s_fallback(&leaf), "");
  assert_string_equal(cli_s2s_client_tags(&leaf), "+x=a,FAAAAAAAAAAAAAB");
}

/* The status-message PRIVMSG mark ,P (#226): no data; kept for the line
 * it came on, gone with the next; read in any position before ,C, with
 * every other segment intact; inside ,C it is text; with data it is not
 * this version's mark (a later extension) and is ignored. */
static void server_statusmsg_segment(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_server, &leaf, COMPACT ",P AC G :hello");
  expect_handler("mark", &o, "PING", "hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 1);
  o = parse_every_way(parse_server, &leaf, COMPACT " AC G :hello");
  expect_handler("no mark", &o, "PING", "hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 0);

  /* every segment, documented order */
  o = parse_every_way(parse_server, &leaf,
      COMPACT ",Sabc,Hp,M+ref1,FAAAAAAAAAAAAAB,P,Cfoo=bar AC G :hello");
  expect_handler("all segments", &o, "PING", "hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 1);
  assert_string_equal(cli_s2s_sessid(&leaf), "abc");
  assert_int_equal(cli_s2s_held(&leaf), 'p');
  assert_string_equal(cli_s2s_ml(&leaf), "+ref1");
  assert_string_equal(cli_s2s_fallback(&leaf), "AAAAAAAAAAAAAB");
  assert_string_equal(cli_s2s_client_tags(&leaf), "foo=bar");

  /* first segment, and among unknown ones */
  o = parse_every_way(parse_server, &leaf, COMPACT ",P,Sabc,Cfoo=bar AC G :hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 1);
  assert_string_equal(cli_s2s_sessid(&leaf), "abc");
  assert_string_equal(cli_s2s_client_tags(&leaf), "foo=bar");
  o = parse_every_way(parse_server, &leaf, COMPACT ",Qzz,P,Q AC G :hello");
  expect_handler("among unknown", &o, "PING", "hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 1);

  /* with data: not this version's mark */
  o = parse_every_way(parse_server, &leaf, COMPACT ",Pzz,Cfoo=bar AC G :hello");
  expect_handler("mark with data", &o, "PING", "hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 0);
  assert_string_equal(cli_s2s_client_tags(&leaf), "foo=bar");

  /* inside ,C it is text */
  o = parse_every_way(parse_server, &leaf, COMPACT ",C+x=a,P AC G :hello");
  assert_int_equal(cli_s2s_statusmsg(&leaf), 0);
  assert_string_equal(cli_s2s_client_tags(&leaf), "+x=a,P");
}

/* A client cannot set the status mark either. */
static void client_cannot_set_statusmsg_mark(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_client, &user, "@,P;+x=a,P PING :hello");
  expect_handler("client status mark", &o, "PING", "hello");
  assert_int_equal(cli_s2s_statusmsg(&user), 0);
}

/* A client cannot set the mark: client lines never fill the S2S stash. */
static void client_cannot_set_fallback_mark(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_client, &user, "@,FAAAAAAAAAAAAAB;+x=a,FAAAAAAAAAAAAAB PING :hello");
  expect_handler("client mark", &o, "PING", "hello");
  assert_string_equal(cli_s2s_fallback(&user), "");
}

/* Spaces only: no prefix (reported, as before), then an empty line. */
static void server_spaces_only(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_server, &leaf, "   ");
  assert_int_equal(o.ret, -1);
  assert_int_equal(o.violations, 1);
  assert_int_equal(o.empt, 1);
  assert_int_equal(o.handler_calls, 0);
  o = parse_every_way(parse_server, &leaf, " ");
  assert_int_equal(o.ret, -1);
  assert_int_equal(o.empt, 1);
  assert_int_equal(o.handler_calls, 0);
}

/* ------------------------------------------------------------------ */
/* parse_client()                                                      */
/* ------------------------------------------------------------------ */

static void client_tags_or_prefix_then_nothing_is_an_empty_line(void **state)
{
  static const char *const lines[] = {
    "@x ", "@x   ", "@ ", "@+typing=active ", "@label=abc ",
    "@x :pfx", "@x :pfx ", ":pfx", ":pfx ", ":", "   ", " ",
    "  @x ",
  };
  size_t i;

  (void)state;
  for (i = 0; i < sizeof(lines) / sizeof(lines[0]); i++) {
    struct outcome o = parse_every_way(parse_client, &user, lines[i]);
    expect_empty(lines[i], &o);
  }
}

/* "@x" with no space is a command word, not a tag section: unknown
 * command, 421 (as for any unknown command). */
static void client_tags_without_space_is_an_unknown_command(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_client, &user, "@x");
  assert_int_equal(o.ret, -1);
  assert_int_equal(o.handler_calls, 0);
  assert_int_equal(o.numerics, 1);
  assert_int_equal(o.last_numeric, ERR_UNKNOWNCOMMAND);
}

static void client_ordinary_lines(void **state)
{
  struct outcome o;

  (void)state;
  o = parse_every_way(parse_client, &user, "PING :hello");
  expect_handler("PING :hello", &o, "PING", "hello");
  o = parse_every_way(parse_client, &user, "@x PING :hello");
  expect_handler("@x PING :hello", &o, "PING", "hello");
  o = parse_every_way(parse_client, &user, "@x :pfx PING :hello");
  expect_handler("@x :pfx PING :hello", &o, "PING", "hello");
}

/* labeled-response: the label belongs to its line.  The handler sees it;
 * once parse_client() returns -- the line handled, or refused before a
 * handler -- it is gone, so nothing sent to the client afterwards (a
 * numeric relayed from a server, another client's event) can carry it. */
/** Give or take a capability the way CAP REQ does: the connection's own
 * set, then the active set the bouncer recomputes from it. */
static void user_cap(int cap, int on)
{
  if (on) {
    CapSet(cli_active_own(&user), cap);
    CapSet(cli_active(&user), cap);
  } else {
    CapClr(cli_active_own(&user), cap);
    CapClr(cli_active(&user), cap);
  }
}

static void client_label_ends_with_its_line(void **state)
{
  char buf[64];

  (void)state;
  user_cap(CAP_LABELEDRESP, 1);
  user_cap(CAP_BATCH, 1);

  memset(&seen, 0, sizeof(seen));
  strcpy(buf, "@label=L1 PING :hello");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.label, "L1");
  assert_string_equal(cli_label(&user), "");
  assert_int_equal(cli_label_responded(&user), 0);

  /* Refused before any handler (unknown command): gone too. */
  strcpy(buf, "@label=L2 NOSUCHCMD x");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), -1);
  assert_string_equal(cli_label(&user), "");

  user_cap(CAP_LABELEDRESP, 0);
  user_cap(CAP_BATCH, 0);
}

/* labeled-response depends on batch, which "MUST be negotiated to use"
 * it; the order of negotiation is not enforced.  Until batch is active
 * too the capability is a no-op: the label is not accepted, so nothing
 * is labelled.  It goes live when batch is added, in either order, and
 * inert again when batch is dropped. */
static void client_label_needs_batch(void **state)
{
  char buf[64];
  struct outcome o;

  (void)state;
  /* labeled-response + message-tags, no batch: the line runs, unlabelled */
  user_cap(CAP_LABELEDRESP, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, "@label=N1 PING :hello");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_int_equal(seen.handler_calls, 1);
  assert_string_equal(seen.label, "");

  /* batch added after labeled-response: live */
  user_cap(CAP_BATCH, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, "@label=N2 PING :hello");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.label, "N2");

  /* batch dropped: inert again */
  user_cap(CAP_BATCH, 0);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, "@label=N3 PING :hello");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.label, "");

  /* labeled-response alone (no message-tags, no batch, no server-time):
   * the client has shown tag-awareness, so its tagged line is parsed and
   * the command runs -- with the label ignored, as for a client with
   * message-tags and without labeled-response. */
  user_cap(CAP_MSGTAGS, 0);
  o = parse_every_way(parse_client, &user, "@label=N4 PING :hello");
  assert_int_equal(o.ret, 0);
  assert_int_equal(o.handler_calls, 1);
  assert_int_equal(o.ref, 0);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, "@label=N4 PING :hello");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.label, "");
  /* No tag capability at all: refused before any handler (the gate). */
  user_cap(CAP_LABELEDRESP, 0);
  o = parse_every_way(parse_client, &user, "@label=N4 PING :hello");
  assert_int_equal(o.ret, -1);
  assert_int_equal(o.handler_calls, 0);
  assert_int_equal(o.ref, 1);

  /* batch first, labeled-response second: live */
  user_cap(CAP_MSGTAGS, 1);
  user_cap(CAP_BATCH, 1);
  user_cap(CAP_LABELEDRESP, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, "@label=N5 PING :hello");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.label, "N5");

  user_cap(CAP_LABELEDRESP, 0);
  user_cap(CAP_BATCH, 0);
}

/* draft/multiline depends on batch the same way: until batch is active
 * too, a client's batch= and draft/multiline-concat tags are not read --
 * the line is the plain message a client without draft/multiline sends.
 * Live once both are active, in either order; inert again without batch. */
static void client_multiline_tags_need_batch(void **state)
{
  char buf[96];
  const char *line = "@batch=r1;draft/multiline-concat PING :hello";

  (void)state;
  user_cap(CAP_DRAFT_MULTILINE, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, line);
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_int_equal(seen.handler_calls, 1);
  assert_string_equal(seen.batch_tag, "");
  assert_int_equal(seen.concat, 0);

  user_cap(CAP_BATCH, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, line);
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.batch_tag, "r1");
  assert_int_equal(seen.concat, 1);

  user_cap(CAP_BATCH, 0);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, line);
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.batch_tag, "");
  assert_int_equal(seen.concat, 0);

  /* batch first, draft/multiline second: live */
  user_cap(CAP_DRAFT_MULTILINE, 0);
  user_cap(CAP_BATCH, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, line);
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.batch_tag, "");
  user_cap(CAP_DRAFT_MULTILINE, 1);
  memset(&seen, 0, sizeof(seen));
  strcpy(buf, line);
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_string_equal(seen.batch_tag, "r1");
  assert_int_equal(seen.concat, 1);

  user_cap(CAP_DRAFT_MULTILINE, 0);
  user_cap(CAP_BATCH, 0);
}

/* Inside an open multiline batch only the batch's own lines -- a PRIVMSG
 * or NOTICE tagged with its reference, while draft/multiline is in use --
 * skip the per-line fake lag (the batch is charged by the multiline
 * cooldown at its close).  Any other line sent meanwhile is charged as
 * usual: an open batch is not a licence to flood. */
static void client_batch_fakelag_only_its_own_lines(void **state)
{
  static const struct { const char *line; int charged; } cases[] = {
    { "@batch=B1 PRIVMSG #c :in the batch", 0 },
    { "@batch=B1;draft/multiline-concat PRIVMSG #c :more", 0 },
    { "PRIVMSG #c :untagged, during the batch", 1 },
    { "PRIVMSG elsewhere :untagged, another target", 1 },
    { "@batch=B2 PRIVMSG #c :another reference", 1 },
    { "@batch=B1 PING :tagged, but not a batch line", 1 },
    { "PING :plain", 1 },
    { "BATCH -B1", 0 },            /* the batch's own end: as on the tip */
    { "BATCH -B2", 1 },            /* another reference */
    { "BATCH +B3 draft/multiline #c", 1 },
  };
  char buf[128];
  size_t i;

  (void)state;
  user_cap(CAP_DRAFT_MULTILINE, 1);
  user_cap(CAP_BATCH, 1);
  test_lagfactor = 120;
  strcpy(cli_ml_batch_id(&user), "B1");

  for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    cli_since(&user) = 1000;
    cli_lagcredit(&user) = 0;
    strcpy(buf, cases[i].line);
    assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
    if (cases[i].charged)
      assert_true(cli_since(&user) > 1000);
    else
      assert_int_equal(cli_since(&user), 1000);
  }

  /* batch dropped with the batch still open: nothing is exempt */
  user_cap(CAP_BATCH, 0);
  cli_since(&user) = 1000;
  strcpy(buf, "@batch=B1 PRIVMSG #c :inert now");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_true(cli_since(&user) > 1000);

  /* no batch open: nothing is exempt */
  user_cap(CAP_BATCH, 1);
  cli_ml_batch_id(&user)[0] = '\0';
  cli_since(&user) = 1000;
  strcpy(buf, "@batch=B1 PRIVMSG #c :no batch open");
  assert_int_equal(parse_client(&user, buf, buf + strlen(buf)), 0);
  assert_true(cli_since(&user) > 1000);

  test_lagfactor = 0;
  cli_since(&user) = 0;
  user_cap(CAP_DRAFT_MULTILINE, 0);
  user_cap(CAP_BATCH, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(server_tags_then_nothing_is_an_empty_line),
    cmocka_unit_test(server_prefix_then_nothing),
    cmocka_unit_test(server_p9_prefix_edges),
    cmocka_unit_test(server_unknown_prefix_exceptions_read_only_the_line),
    cmocka_unit_test(server_ordinary_lines),
    cmocka_unit_test(server_spaces_only),
    cmocka_unit_test(server_unknown_segment_is_skipped),
    cmocka_unit_test(server_fallback_segment),
    cmocka_unit_test(server_statusmsg_segment),
    cmocka_unit_test(client_cannot_set_statusmsg_mark),
    cmocka_unit_test(client_tags_or_prefix_then_nothing_is_an_empty_line),
    cmocka_unit_test(client_label_ends_with_its_line),
    cmocka_unit_test(client_label_needs_batch),
    cmocka_unit_test(client_multiline_tags_need_batch),
    cmocka_unit_test(client_batch_fakelag_only_its_own_lines),
    cmocka_unit_test(client_tags_without_space_is_an_unknown_command),
    cmocka_unit_test(client_ordinary_lines),
    cmocka_unit_test(client_cannot_set_fallback_mark),
  };

  return cmocka_run_group_tests(tests, group_setup, NULL);
}
