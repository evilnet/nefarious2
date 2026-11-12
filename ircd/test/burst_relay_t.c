/*
 * burst_relay_t.c - the BURST lines ms_burst() relays for one it received.
 *
 * What ms_burst() (m_burst.c) relays can be longer than what came in: a
 * short ban mask is expanded ("aa" becomes "aa!*@*") and a member's mode
 * field can grow.  The relay must go on as many lines as it needs, each
 * a complete BURST of at most 510 bytes, with every ban, exception and
 * member on one of them and the modes on the first.
 *
 * m_burst.o is linked as the server builds it, with the string and match
 * code it uses.  The BURST names a channel with the same timestamp as
 * ours, so its modes, bans and members are all applied and relayed.
 * Everything else ms_burst() calls is stubbed below; the relay stub
 * formats each line as the server would and keeps it.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "match.h"
#include "msg.h"
#include "numnicks.h"
#include "send.h"
#include "struct.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

time_t CurrentTime;
time_t TSoffset;
struct Client his;

/* ---------- the network ---------- */

static struct Client peer;      /**< the server the BURST comes from */
static struct Connection peer_con;
static struct Client users[64]; /**< its users, ACAB<c> for each <c> */
static struct User user_info[64];
static const char b64[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";
static struct Channel *channel; /**< the channel the BURST names */
static int excepts_on;          /**< FEAT_EXCEPTS */

/* ---------- what is relayed ---------- */

#define MAXLINES 16
static char oplevel_lines[MAXLINES][1024]; /**< to servers with op-levels */
static char plain_lines[MAXLINES][1024];   /**< to servers without */
static int n_oplevel, n_plain;

/* ---------- stubs ---------- */

void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...)
{
  char (*lines)[1024] = require == FLAG_OPLEVELS ? oplevel_lines : plain_lines;
  int *n = require == FLAG_OPLEVELS ? &n_oplevel : &n_plain;
  struct VarData vd;

  if (*n >= MAXLINES)
    return;
  /* The line as it goes out: "<source numnick> B <arguments>". */
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  ircd_snprintf(0, lines[*n], sizeof(lines[*n]), "%s %s %v",
                cli_yxx(from), tok, &vd);
  va_end(vd.vd_args);
  (*n)++;
}

struct Channel *get_channel(struct Client *cptr, char *chname,
                            ChannelGetType flag)
{
  return channel;
}

struct Client *findNUser(const char *yxx)
{
  const char *c;

  if (strlen(yxx) != 5 || strncmp(yxx, "ACAB", 4)
      || !(c = strchr(b64, yxx[4])))
    return NULL;
  return &users[c - b64];
}

struct Membership *find_member_link(struct Channel *chptr,
                                    const struct Client *cptr)
{
  return NULL;
}

void add_user_to_channel(struct Channel *chptr, struct Client *who,
                         unsigned int flags, int oplevel)
{
}

char *pretty_extmask(char *mask)
{
  /* Enough of pretty_mask() for the masks below: a bare nick is
   * expanded to nick!*@*. */
  static char buf[NICKLEN + USERLEN + HOSTLEN + 3];

  if (strchr(mask, '!') || strchr(mask, '@'))
    return mask;
  ircd_snprintf(0, buf, sizeof(buf), "%s!*@*", mask);
  return buf;
}

struct Ban *make_ban(const char *banstr)
{
  struct Ban *ban = calloc(1, sizeof(*ban));

  ircd_strncpy(ban->banstr, banstr, sizeof(ban->banstr));
  return ban;
}

void free_ban(struct Ban *ban)
{
  free(ban);
}

int feature_bool(enum Feature feat)
{
  return feat == FEAT_EXCEPTS ? excepts_on : 0;
}

/* Mode strings: mode_parse() takes the letters of a "+..." parameter and a
 * parameter for each of k l L (all a BURST below uses), and
 * modebuf_extract() gives them back. */
static char parsed_modes[BUFSIZE];

int mode_parse(struct ModeBuf *mbuf, struct Client *cptr,
               struct Client *sptr, struct Channel *chptr, int parc,
               char *parv[], unsigned int flags, struct Membership *member)
{
  const char *m;
  int used = 1;

  ircd_strncpy(parsed_modes, parv[0], sizeof(parsed_modes));
  for (m = parv[0]; *m; m++)
    if (strchr("klL", *m) && used < parc) {
      strcat(parsed_modes, " ");
      strcat(parsed_modes, parv[used++]);
    }
  return used;
}

void modebuf_extract(struct ModeBuf *mbuf, char *buf, int oplevels)
{
  strcpy(buf, parsed_modes);
}

void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
                  struct Client *connect, struct Channel *chan,
                  unsigned int dest)
{
}

void modebuf_mode(struct ModeBuf *mbuf, unsigned int mode)
{
}

void modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
                         struct Client *client, int oplevel)
{
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free)
{
}

int modebuf_flush(struct ModeBuf *mbuf)
{
  return 0;
}

void mode_ban_invalidate(struct Channel *chan)
{
}

void mode_except_invalidate(struct Channel *chan)
{
}

void mode_invite_clear(struct Channel *chan)
{
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  return 0;
}

int sub1_from_channel(struct Channel *chptr)
{
  return 0;
}

void make_zombie(struct Membership *member, struct Client *who,
                 struct Client *cptr, struct Client *sptr,
                 struct Channel *chptr)
{
}

void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{
}

void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
}

void sendcmdto_channel_capab_butserv_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Channel *to,
                                            struct Client *one,
                                            unsigned int skip, int withcap,
                                            int skipcap,
                                            const char *pattern, ...)
{
}

/* ---------- checks ---------- */

static int checks;              /**< checks evaluated */
static int failures;            /**< checks that did not hold */

static void check(int ok, int line, const char *what, const char *arg)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED line %d: %s [%s]\n", line, what, arg);
  }
}

#define CHECK(cond, what, arg) check((cond) ? 1 : 0, __LINE__, (what), (arg))

/** Feed "AC B #relay 1000 <rest>" to ms_burst() for our #relay, which
 * has the same timestamp and nothing on it. */
static void burst(const char *rest)
{
  static char line[2048];
  char *parv[MAXPARA + 2], *p;
  int parc = 0;
  struct Ban *ban, *next;

  for (ban = channel->banlist; ban; ban = next) {
    next = ban->next;
    free(ban);
  }
  for (ban = channel->exceptlist; ban; ban = next) {
    next = ban->next;
    free(ban);
  }
  channel->banlist = channel->exceptlist = NULL;
  channel->creationtime = 1000;
  n_oplevel = n_plain = 0;
  parsed_modes[0] = '\0';

  /* Split as parse_server() does: words, and a final ":" parameter. */
  ircd_snprintf(0, line, sizeof(line), "#relay 1000 %s", rest);
  parv[parc++] = "AC";
  for (p = line; *p && parc < MAXPARA; ) {
    if (*p == ':') {
      parv[parc++] = p + 1;
      break;
    }
    parv[parc++] = p;
    if (!(p = strchr(p, ' ')))
      break;
    *p++ = '\0';
  }
  parv[parc] = NULL;
  ms_burst(&peer, &peer, parc, parv);
}

/** Every relayed line is a BURST of #relay 1000 and at most 510 bytes. */
static int lines_ok(char (*lines)[1024], int n)
{
  int i;

  for (i = 0; i < n; i++)
    if (strlen(lines[i]) > 510 || strncmp(lines[i], "AC B #relay 1000", 16))
      return 0;
  return n > 0;
}

/** How many of the lines carry @a word as a whole word (a mode string,
 * a ban, a member numnick). */
static int count_word(char (*lines)[1024], int n, const char *word,
                      const char *seps)
{
  int i, count = 0;
  size_t len = strlen(word);

  for (i = 0; i < n; i++) {
    const char *s = lines[i];

    while ((s = strstr(s, word))) {
      if (strchr(seps, s[-1]) && (!s[len] || strchr(seps, s[len])))
        count++;
      s += len;
    }
  }
  return count;
}

/** The part of a ban parameter after its "~", on any line. */
static int count_exception(char (*lines)[1024], int n, const char *mask)
{
  int i, count = 0;

  for (i = 0; i < n; i++) {
    const char *tilde = strstr(lines[i], " :%");

    if (tilde && (tilde = strstr(tilde, "~ ")) && strstr(tilde, mask))
      count++;
  }
  return count;
}

int main(void)
{
  char rest[1024], word[32];
  int i, pos;

  setvbuf(stdout, NULL, _IONBF, 0);

  cli_connect(&peer) = &peer_con;
  con_client(&peer_con) = &peer;
  cli_status(&peer) = STAT_SERVER;
  ircd_strncpy(cli_name(&peer), "leafa.test", sizeof(cli_name(&peer)));
  ircd_strncpy(cli_yxx(&peer), "AC", sizeof(cli_yxx(&peer)));
  for (i = 0; i < 64; i++) {
    cli_connect(&users[i]) = &peer_con;     /* cli_from() is the peer */
    cli_status(&users[i]) = STAT_USER;
    cli_user(&users[i]) = &user_info[i];
  }
  channel = calloc(1, sizeof(*channel) + sizeof("#relay"));
  strcpy(channel->chname, "#relay");

  /* A BURST that fits is relayed as it came, on one line. */
  burst("+nt ACABA:o,ACABB :%*!*@a.example *!*@b.example");
  CHECK(n_oplevel == 1 && n_plain == 1, "short BURST: one line each", "");
  CHECK(!strcmp(oplevel_lines[0], "AC B #relay 1000 +nt ACABA:o,ACABB :%*!*@a.example *!*@b.example"),
        "short BURST: relayed unchanged", oplevel_lines[0]);
  CHECK(!strcmp(plain_lines[0], oplevel_lines[0]),
        "short BURST: the same without op-levels", plain_lines[0]);

  /* 160 two-letter masks (a 479-byte parameter), each relayed as
   * "xx!*@*": three times as long. */
  pos = ircd_snprintf(0, rest, sizeof(rest), "+lk 10 key :%%");
  for (i = 0; i < 160; i++)
    pos += ircd_snprintf(0, rest + pos, sizeof(rest) - pos, "%s%c%c",
                         i ? " " : "", 'a' + i / 13, 'a' + i % 13);
  burst(rest);
  CHECK(lines_ok(oplevel_lines, n_oplevel) && n_oplevel > 1,
        "growing bans: several lines of at most 510 bytes", oplevel_lines[0]);
  CHECK(lines_ok(plain_lines, n_plain) && n_plain == n_oplevel,
        "growing bans: the same without op-levels", plain_lines[0]);
  for (i = 0; i < 160; i++) {
    ircd_snprintf(0, word, sizeof(word), "%c%c!*@*", 'a' + i / 13, 'a' + i % 13);
    CHECK(count_word(oplevel_lines, n_oplevel, word, " %") == 1,
          "growing bans: each relayed once", word);
  }
  CHECK(count_word(oplevel_lines, n_oplevel, "+lk", " ") == 1
        && strstr(oplevel_lines[0], " +lk 10 key "),
        "growing bans: the modes on the first line only", oplevel_lines[0]);

  /* 10 bans and 150 exceptions, which grow the same way. */
  excepts_on = 1;
  pos = ircd_snprintf(0, rest, sizeof(rest), ":%%");
  for (i = 0; i < 10; i++)
    pos += ircd_snprintf(0, rest + pos, sizeof(rest) - pos, "b%c ", 'a' + i);
  pos += ircd_snprintf(0, rest + pos, sizeof(rest) - pos, "~");
  for (i = 0; i < 150; i++)
    pos += ircd_snprintf(0, rest + pos, sizeof(rest) - pos, " %c%c",
                         'n' + i / 13, 'a' + i % 13);
  burst(rest);
  CHECK(lines_ok(oplevel_lines, n_oplevel) && n_oplevel > 1,
        "growing exceptions: several lines of at most 510 bytes",
        oplevel_lines[0]);
  for (i = 0; i < 10; i++) {
    ircd_snprintf(0, word, sizeof(word), "b%c!*@*", 'a' + i);
    CHECK(count_word(oplevel_lines, n_oplevel, word, " %") == 1
          && !count_exception(oplevel_lines, n_oplevel, word),
          "growing exceptions: each ban relayed once, as a ban", word);
  }
  for (i = 0; i < 150; i++) {
    ircd_snprintf(0, word, sizeof(word), " %c%c!*@*", 'n' + i / 13, 'a' + i % 13);
    CHECK(count_exception(oplevel_lines, n_oplevel, word) == 1,
          "growing exceptions: each relayed once, after a ~", word);
  }
  excepts_on = 0;

  /* Without EXCEPTS the exceptions are not relayed, and leave nothing
   * behind in the ban parameter. */
  burst(":%ba ~ na nb");
  CHECK(n_oplevel == 1 && !strcmp(oplevel_lines[0], "AC B #relay 1000 :%ba!*@*"),
        "exceptions without EXCEPTS: only the ban", oplevel_lines[0]);

  /* 64 members.  The first 30 alternate ":5h", whose mode field grows
   * (it leaves the op-level at -1, relayed as ":h4294967295"), and ":v";
   * the other 34 have no mode field of their own, so they keep +v, and
   * the relay has to go to a new line in the middle of them. */
  pos = 0;
  for (i = 0; i < 64; i++)
    pos += ircd_snprintf(0, rest + pos, sizeof(rest) - pos, "%sACAB%c%s",
                         i ? "," : "", b64[i],
                         i >= 30 ? "" : (i & 1) ? ":v" : ":5h");
  burst(rest);
  CHECK(lines_ok(oplevel_lines, n_oplevel) && n_oplevel > 1,
        "growing members: several lines of at most 510 bytes",
        oplevel_lines[0]);
  CHECK(lines_ok(plain_lines, n_plain) && n_plain == n_oplevel,
        "growing members: the same number without op-levels", plain_lines[0]);
  for (i = 0; i < 64; i++) {
    ircd_snprintf(0, word, sizeof(word), "ACAB%c", b64[i]);
    CHECK(count_word(oplevel_lines, n_oplevel, word, " ,:") == 1
          && count_word(plain_lines, n_plain, word, " ,:") == 1,
          "growing members: each relayed once", word);
  }
  /* A line's first member states its mode, though in the BURST it had
   * none of its own: a receiver starts each line with no mode. */
  for (i = 1; i < n_oplevel; i++) {
    const char *first = strstr(oplevel_lines[i], " ACAB");
    const char *firsto = strstr(plain_lines[i], " ACAB");

    CHECK(first && strchr(b64, first[5]) - b64 >= 30
          && !strncmp(first + 6, ":v,", 3)
          && firsto && !strncmp(firsto + 6, ":v,", 3),
          "growing members: the first member of a later line states its +v",
          oplevel_lines[i]);
  }

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
