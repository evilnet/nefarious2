/*
 * parse_line_t.c - a line is parsed from its own bytes only, never from
 * what an earlier line left in the buffer after its terminator.
 *
 * A connection's input buffer is reused line after line (packet.c): a
 * line is copied in from the start and NUL-terminated, and whatever a
 * longer earlier line left after the NUL is still there.  parse_server()
 * stepped over the NUL in three places:
 *
 *  - a line of tags, a space and nothing else ("@x ") reached the numeric
 *    prefix code with the cursor on the NUL, which reported "Missing
 *    Prefix" and then advanced past the NUL: the earlier line's tail was
 *    parsed as this line's command, and run with the link as its source;
 *  - an unknown source prefix with nothing after it read ch[1] (the SQUIT
 *    test) when ch[0] was the NUL, and ch[2] (the KILL test) when ch[1]
 *    was;
 *  - a one-character numeric prefix at the end of the line read ch[2].
 *
 * Each line is parsed alone in a zeroed buffer -- the reference, which is
 * checked against the expected outcome -- then after an earlier line whose
 * tail would run if it were read, and over single-byte fillers that steer
 * the ch[1]/ch[2] tests.  Every outcome must be the reference one.  Each
 * line is also parsed from a heap block of exactly its size, so that a
 * read past its terminator is an invalid read under valgrind.  A few
 * client lines (parse_client()) are checked the same way.
 *
 * The real parse.o is linked, with its message table: handler_stubs.c,
 * generated from handlers.h (see Makefile.in), defines every command
 * handler as a stub that records its name.  What else parse.c calls is
 * stubbed below.
 */
#include "config.h"

#include "class.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_handler.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "numnicks.h"
#include "parse.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_numeric.h"
#include "send.h"
#include "shun.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- what one parse did ---------- */

#define LOOKUP_SERVER 1         /**< FindNServer() was asked */
#define LOOKUP_USER   2         /**< findNUser() was asked */

struct outcome {
  int ret;                      /**< parse_*()'s return value */
  char handler[24];             /**< command handler that ran, if any */
  char par1[24];                /**< its first parameter */
  int numeric;                  /**< do_numeric()'s numeric, if called */
  int violations;               /**< protocol_violation() calls */
  int sent;                     /**< replies or messages sent */
  int lookups;                  /**< LOOKUP_* */
  unsigned int empt, unpf, unco, wrdi; /**< ServerStats counters */
};

static struct outcome now;      /**< what the parse in progress does */

/* ---------- the ircd around parse.c ---------- */

time_t CurrentTime;
int log_inassert;
struct Client me;
static struct ServerStatistics stats;
struct ServerStatistics *ServerStats = &stats;

static struct Connection leaf_con, unreg_con;
static struct Client leaf;      /**< leafa.test (AC): the link the lines come from */
static struct Client unreg;     /**< an unregistered local client */

/** Called by every handler stub (handler_stubs.c). */
int handler_ran(const char *name, int parc, char *parv[])
{
  snprintf(now.handler, sizeof(now.handler), "%s", name);
  snprintf(now.par1, sizeof(now.par1), "%s",
           parc > 1 && parv[1] ? parv[1] : "");
  return 0;
}

/* in parse.c's message table, declared in hash.h, not handlers.h */
int m_hash(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  return handler_ran("m_hash", parc, parv);
}

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
}

void debug(int level, const char *form, ...)
{
}

void *DoMalloc(size_t len, const char *type, const char *file, int line)
{
  void *p = malloc(len);

  if (!p)
    abort();
  return p;
}

void *DoMallocZero(size_t len, const char *type, const char *file, int line)
{
  void *p = calloc(1, len);

  if (!p)
    abort();
  return p;
}

int do_numeric(int numeric, int nnn, struct Client *cptr, struct Client *sptr,
               int parc, char *parv[])
{
  now.numeric = numeric;
  return 0;
}

int feature_bool(enum Feature feat)
{
  return 0;
}

struct Client *FindNServer(const char *numeric)
{
  now.lookups |= LOOKUP_SERVER;
  return strcmp(numeric, "AC") ? NULL : &leaf;
}

struct Client *findNUser(const char *yxx)
{
  now.lookups |= LOOKUP_USER;
  return NULL;
}

/* FindClient() is a macro over this. */
struct Client *hSeekClient(const char *name, int TMask)
{
  return strcmp(name, "leafa.test") ? NULL : &leaf;
}

const char *get_client_name(const struct Client *sptr, int showip)
{
  return cli_name(sptr);
}

int get_lag_min(struct Client *cptr)
{
  return -1;
}

int get_lag_factor(struct Client *cptr)
{
  return -1;
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  now.violations++;
  return 0;
}

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  now.sent++;
}

int send_reply(struct Client *to, int reply, ...)
{
  now.sent++;
  return 0;
}

struct Shun *shun_lookup(struct Client *cptr, unsigned int flags)
{
  return NULL;
}

/* ---------- checks ---------- */

static int checks;              /**< checks evaluated */
static int failures;            /**< checks that did not hold */

static void show(const char *tag, const struct outcome *o)
{
  printf("    %-9s ret %d handler \"%s\" (\"%s\") numeric %d violations %d "
         "sent %d lookups %d empt %u unpf %u unco %u wrdi %u\n", tag, o->ret,
         o->handler, o->par1, o->numeric, o->violations, o->sent, o->lookups,
         o->empt, o->unpf, o->unco, o->wrdi);
}

static int same(const struct outcome *a, const struct outcome *b)
{
  return a->ret == b->ret && !strcmp(a->handler, b->handler)
      && !strcmp(a->par1, b->par1) && a->numeric == b->numeric
      && a->violations == b->violations && a->sent == b->sent
      && a->lookups == b->lookups && a->empt == b->empt && a->unpf == b->unpf
      && a->unco == b->unco && a->wrdi == b->wrdi;
}

static void check(int ok, const char *line, const char *what,
                  const struct outcome *got, const struct outcome *want)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED \"%s\": %s\n", line, what);
    show("got", got);
    show("expected", want);
  }
}

/** Parse \a line from \a cptr's point of view, laid out in a buffer whose
 * bytes after the terminator are \a after (if not NULL) and else \a fill
 * up to the end of the buffer.  With \a exact, parse it from a heap block
 * of exactly its size instead. */
static void parse(struct Client *cptr, const char *line, const char *after,
                  int fill, int exact, struct outcome *out)
{
  static char buf[2 * BUFSIZE];
  size_t len = strlen(line);
  char *p = buf;

  if (exact) {
    p = malloc(len + 1);
    if (!p)
      abort();
  } else {
    memset(buf, fill, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    if (after)
      memcpy(buf + len + 1, after, strlen(after) + 1);
  }
  memcpy(p, line, len + 1);

  memset(&now, 0, sizeof(now));
  memset(&stats, 0, sizeof(stats));
  if (IsServer(cptr))
    now.ret = parse_server(cptr, p, p + len);
  else
    now.ret = parse_client(cptr, p, p + len);
  now.empt = stats.is_empt;
  now.unpf = stats.is_unpf;
  now.unco = stats.is_unco;
  now.wrdi = stats.is_wrdi;
  *out = now;

  if (exact)
    free(p);
}

/** One line and the outcome it must have. */
struct line_case {
  const char *line;
  int ret;
  const char *handler;          /**< "" for none */
  const char *par1;
  int violations;
  int lookups;
  unsigned int empt, unpf, unco;
};

/** An earlier line's tail, as it is left after the terminator of a
 * shorter line: a parser that steps over the terminator, and then over
 * the rest of a word, meets a PING from the link. */
#define STALE_TAIL "ZZ G :stale"

/** Bytes that steer the tests of ch[1] and ch[2]: 'Q' (SQUIT), 'L'
 * (KILL), ' ' (a server numeric, a KILL token). */
static const int fillers[] = { 'Q', 'L', ' ' };

static void run_case(struct Client *cptr, const struct line_case *c)
{
  struct outcome want, ref, got;
  unsigned int i;

  memset(&want, 0, sizeof(want));
  want.ret = c->ret;
  snprintf(want.handler, sizeof(want.handler), "%s", c->handler);
  snprintf(want.par1, sizeof(want.par1), "%s", c->par1);
  want.violations = c->violations;
  want.lookups = c->lookups;
  want.empt = c->empt;
  want.unpf = c->unpf;
  want.unco = c->unco;

  parse(cptr, c->line, NULL, 0, 0, &ref);
  check(same(&ref, &want), c->line, "alone in a zeroed buffer: the expected "
        "outcome", &ref, &want);

  parse(cptr, c->line, STALE_TAIL, 0, 0, &got);
  check(same(&got, &ref), c->line, "after a longer line: the same outcome "
        "(not the earlier line's tail run)", &got, &ref);

  for (i = 0; i < sizeof(fillers) / sizeof(fillers[0]); i++) {
    char what[64];

    parse(cptr, c->line, NULL, fillers[i], 0, &got);
    snprintf(what, sizeof(what), "over '%c' fillers: the same outcome",
             fillers[i]);
    check(same(&got, &ref), c->line, what, &got, &ref);
  }

  parse(cptr, c->line, NULL, 0, 1, &got);
  check(same(&got, &ref), c->line, "from an exact-size block: the same "
        "outcome", &got, &ref);
}

#define S LOOKUP_SERVER
#define U LOOKUP_USER

static const struct line_case server_cases[] = {
  /* tags, then nothing: an empty line */
  { "@x ", -1, "", "", 0, 0, 1, 0, 0 },
  { "@x   ", -1, "", "", 0, 0, 1, 0, 0 },
  { "@ ", -1, "", "", 0, 0, 1, 0, 0 },
  { "@+tag=v ", -1, "", "", 0, 0, 1, 0, 0 },
  { "@ABBBBBBBBBBBBBBBBBBBBB ", -1, "", "", 0, 0, 1, 0, 0 },
  /* no space after the tags: dropped as before */
  { "@x", -1, "", "", 0, 0, 0, 0, 0 },
  /* a known prefix, then nothing */
  { "@x :leafa.test ", -1, "", "", 0, 0, 1, 0, 0 },
  { "AC ", -1, "", "", 0, S, 1, 0, 0 },
  { "@x AC ", -1, "", "", 0, S, 1, 0, 0 },
  /* an unknown prefix, then nothing */
  { ":nosuch.test", -1, "", "", 0, 0, 0, 0, 0 },
  { ":nosuch.test ", 0, "", "", 0, 0, 0, 1, 0 },
  { "@x :nosuch.test ", 0, "", "", 0, 0, 0, 1, 0 },
  { "AC", 0, "", "", 0, U, 0, 1, 0 },
  { "ZZZZZ", 0, "", "", 0, U, 0, 1, 0 },
  { "ZZZZZ ", 0, "", "", 0, U, 0, 1, 0 },
  { "ZZZZZ K", 0, "", "", 0, U, 0, 1, 0 },
  { "ZZZZZ D", 0, "", "", 0, U, 0, 1, 0 },
  { "A", 0, "", "", 0, U, 0, 1, 0 },
  /* spaces only: no prefix, reported as before */
  { "   ", -1, "", "", 1, 0, 1, 0, 0 },
  /* lines with a command parse as before */
  { "AC G :x", 0, "ms_ping", "x", 0, S, 0, 0, 0 },
  { "@x AC G :x", 0, "ms_ping", "x", 0, S, 0, 0, 0 },
  { ":leafa.test G :x", 0, "ms_ping", "x", 0, 0, 0, 0, 0 },
  { "ZZZZZ SQ hub.test 0 :x", 0, "ms_squit", "hub.test", 0, U, 0, 1, 0 },
  { "ZZZZZ D ABAAA :x", 0, "ms_kill", "ABAAA", 0, U, 0, 1, 0 },
  { "ZZZZZ KILL ABAAA :x", 0, "ms_kill", "ABAAA", 0, U, 0, 1, 0 },
  { "ZZZZZ K #c ABAAA", 0, "", "", 0, U, 0, 1, 0 },
  { ":nosuch.test SQ hub.test 0 :x", 0, "ms_squit", "hub.test", 0, 0, 0, 1, 0 },
};

static const struct line_case client_cases[] = {
  { "@x ", -1, "", "", 0, 0, 0, 0, 1 },
  { ":p", -1, "", "", 0, 0, 1, 0, 0 },
  { ":p ", -1, "", "", 0, 0, 1, 0, 0 },
  { "   ", -1, "", "", 0, 0, 1, 0, 0 },
  { "PING :x", 0, "m_unregistered", "x", 0, 0, 0, 0, 0 },
};

int main(void)
{
  unsigned int i;

  setvbuf(stdout, NULL, _IONBF, 0);

  initmsgtree();

  cli_connect(&leaf) = &leaf_con;
  cli_from(&leaf) = &leaf;
  cli_status(&leaf) = STAT_SERVER;
  cli_handler(&leaf) = SERVER_HANDLER;
  ircd_strncpy(cli_name(&leaf), "leafa.test", sizeof(cli_name(&leaf)));

  cli_connect(&unreg) = &unreg_con;
  cli_from(&unreg) = &unreg;
  cli_status(&unreg) = STAT_UNKNOWN_USER;
  cli_handler(&unreg) = UNREGISTERED_HANDLER;
  ircd_strncpy(cli_name(&unreg), "unreg", sizeof(cli_name(&unreg)));

  for (i = 0; i < sizeof(server_cases) / sizeof(server_cases[0]); i++)
    run_case(&leaf, &server_cases[i]);
  for (i = 0; i < sizeof(client_cases) / sizeof(client_cases[0]); i++)
    run_case(&unreg, &client_cases[i]);

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
