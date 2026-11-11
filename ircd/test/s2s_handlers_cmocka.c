/*
 * s2s_handlers_cmocka.c - server-to-server handlers against a fake network.
 *
 * Links the REAL handler objects (m_burst.o, m_destruct.o, m_endburst.o,
 * m_svsnick.o, m_svsquit.o, m_topic.o), with numnicks.o,
 * match.o and the ircd's own printf, so every line asserted below is the
 * line the handler would put on the wire.  What sits underneath the
 * handlers is stubbed: the send layer records instead of sending, the
 * channel table is a list, and mode_parse() / the modebuf only count what
 * a BURST's mode string uses up.
 *
 * Lines reach a handler split the way parse_server() splits them: parv[0]
 * is the source, a parameter starting with ':' takes the rest of the line.
 * The fake network is built per test: this server is "hub.test" (AB);
 * linked() makes a server linked to it, remote_user() a user on one, and
 * local_user() one of ours.
 */
#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "bouncer_session.h"
#include "channel.h"
#include "client.h"
#include "destruct_event.h"
#include "handlers.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "match.h"
#include "msg.h"
#include "numnicks.h"
#include "s_debug.h"
#include "s_misc.h"
#include "send.h"
#include "struct.h"

/* ====================================================================
 * Globals the linked objects expect
 * ==================================================================== */

struct Client me;
struct Client his;
struct Channel *GlobalChannelList;
time_t CurrentTime = 1000000;
time_t TSoffset;
int log_inassert;

/* ====================================================================
 * What the code under test did
 * ==================================================================== */

#define LINE 2048               /* longer than any wire line: an over-long
                                 * line is seen whole, not cut */
#define MAXREC 256

struct Sent {
  struct Client *to;            /* the connection the line went to */
  char text[LINE];
};

static struct Sent sent[MAXREC];
static int nsent;
static char violations[MAXREC][LINE];
static int nviolations;
static char opnotices[MAXREC][LINE];
static int nopnotices;
static int destructed;                  /* destruct_channel() calls */

static void record_sent(struct Client *to, const char *text)
{
  assert_true(nsent < MAXREC);
  sent[nsent].to = to;
  snprintf(sent[nsent].text, LINE, "%s", text);
  nsent++;
}

/** How many lines went to @a to. */
static int sent_count_to(struct Client *to)
{
  int i, count = 0;
  for (i = 0; i < nsent; i++)
    if (sent[i].to == to)
      count++;
  return count;
}

/** The @a nth (from 0) line that went to @a to, or "" when there are
 * fewer. */
static const char *sent_to(struct Client *to, int nth)
{
  int i;
  for (i = 0; i < nsent; i++)
    if (sent[i].to == to && nth-- == 0)
      return sent[i].text;
  return "";
}

static void forget(void)
{
  nsent = nviolations = nopnotices = destructed = 0;
}

/* ====================================================================
 * The fake network
 * ==================================================================== */

#define MAXOBJ 256
static struct Client *made[MAXOBJ];
static int nmade;
static struct Connection me_con;
static struct Server me_serv;

static struct Client *fake_client(const char *name, int status)
{
  struct Client *c = calloc(1, sizeof(*c));

  assert_non_null(c);
  assert_true(nmade < MAXOBJ);
  made[nmade++] = c;
  ircd_strncpy(cli_name(c), name, sizeof(c->cli_name));
  cli_status(c) = status;
  return c;
}

/** A server linked directly to this one, numeric @a numeric with room for
 * 4096 users.  @a oplevels: it understands op-levels (FLAG_OPLEVELS). */
static struct Client *linked(const char *name, const char *numeric,
                             int oplevels)
{
  struct Client *c = fake_client(name, STAT_SERVER);
  struct DLink *dl = calloc(1, sizeof(*dl));
  char yxx[6];

  assert_non_null(dl);
  cli_serv(c) = calloc(1, sizeof(struct Server));
  assert_non_null(cli_serv(c));
  snprintf(yxx, sizeof(yxx), "%s]]]", numeric);
  SetServerYXX(c, c, yxx);
  if (oplevels)
    SetFlag(c, FLAG_OPLEVELS);
  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  cli_serv(c)->up = &me;

  dl->value.cptr = c;
  dl->next = cli_serv(&me)->down;
  cli_serv(&me)->down = dl;
  return c;
}

static struct Client *a_user(const char *nick)
{
  struct Client *c = fake_client(nick, STAT_USER);

  cli_user(c) = calloc(1, sizeof(struct User));
  assert_non_null(cli_user(c));
  ircd_strncpy(cli_user(c)->username, "user", sizeof(cli_user(c)->username));
  ircd_strncpy(cli_user(c)->host, "host.example", sizeof(cli_user(c)->host));
  ircd_strncpy(cli_info(c), "Real Name", sizeof(c->cli_info));
  return c;
}

/** A user on @a server (made by linked()), full numeric @a numnick. */
static struct Client *remote_user(struct Client *server, const char *nick,
                                  const char *numnick)
{
  struct Client *c = a_user(nick);

  cli_user(c)->server = server;
  cli_connect(c) = cli_connect(server);
  SetRemoteNumNick(c, numnick);
  return c;
}

/** One of this server's users, numeric AB + @a yxx. */
static struct Client *local_user(const char *nick, const char *yxx)
{
  struct Client *c = a_user(nick);

  cli_user(c)->server = &me;
  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  ircd_strncpy(cli_yxx(c), yxx, sizeof(c->cli_yxx));
  cli_serv(&me)->client_list[base64toint(yxx) & cli_serv(&me)->nn_mask] = c;
  return c;
}

/** A services server: it announced itself with SERVER ... +s. */
static struct Client *services(struct Client *server)
{
  SetService(server);
  return server;
}

/* --- clients by name: a walk instead of the hash --- */

static struct Client *exited[MAXOBJ];   /* what exit_client*() was asked to exit */
static int nexited;
static int forced_exits;                /* bounce_forced_exit() calls */

static int was_exited(struct Client *c)
{
  int i;
  for (i = 0; i < nexited; i++)
    if (exited[i] == c)
      return 1;
  return 0;
}

struct Client *hSeekClient(const char *name, int TMask)
{
  int i;
  for (i = 0; i < nmade; i++)
    if ((cli_status(made[i]) & TMask) && !was_exited(made[i])
        && 0 == ircd_strcmp(cli_name(made[i]), name))
      return made[i];
  return NULL;
}

/* --- channels: a list instead of the hash --- */

static struct Channel *channels[MAXOBJ];
static int nchannels;

static struct Channel *fake_channel(const char *name)
{
  struct Channel *ch = calloc(1, sizeof(*ch) + strlen(name));

  assert_non_null(ch);
  assert_true(nchannels < MAXOBJ);
  strcpy(ch->chname, name);
  channels[nchannels++] = ch;
  return ch;
}

static struct Membership *add_member(struct Channel *ch, struct Client *who,
                                     unsigned int status, int oplevel)
{
  struct Membership *m = calloc(1, sizeof(*m));

  assert_non_null(m);
  m->user = who;
  m->channel = ch;
  m->status = status;
  m->oplevel = oplevel;
  m->next_member = ch->members;
  if (ch->members)
    ch->members->prev_member = m;
  ch->members = m;
  ch->users++;
  return m;
}

static int count_bans(struct Ban *list)
{
  int n = 0;
  for (; list; list = list->next)
    n++;
  return n;
}

/* --- nick changes set_nick_name() was asked for --- */

static char renames[MAXREC][LINE];
static int nrenames;

/* --- features --- */

static int feat_excepts;

/* --- the modebuf, as far as ms_burst() reads it back --- */

static const char *fake_modes;  /* what modebuf_extract() reports */
static int ban_invalidations, except_invalidations;

/* --- the source of a line, as parse_server() splits it --- */

#define MAXARGS (MAXPARA + 2)

static int split_line(char *line, char **parv)
{
  int parc = 1;

  while (*line && parc < MAXARGS - 1) {
    while (*line == ' ')
      line++;
    if (!*line)
      break;
    if (*line == ':') {
      parv[parc++] = line + 1;
      break;
    }
    parv[parc++] = line;
    while (*line && *line != ' ')
      line++;
    if (*line)
      *line++ = '\0';
  }
  parv[parc] = NULL;
  return parc;
}

/** Hand @a fmt (the line after "<source> <token>") to @a handler as
 * arriving on @a link from @a source. */
static int deliver(int (*handler)(struct Client *, struct Client *, int, char *[]),
                   struct Client *link, struct Client *source,
                   const char *fmt, ...)
{
  static char buf[LINE];
  char *parv[MAXARGS];
  va_list vl;
  int parc;

  va_start(vl, fmt);
  vsnprintf(buf, sizeof(buf), fmt, vl);
  va_end(vl);
  parv[0] = cli_name(source);
  parc = split_line(buf, parv);
  return handler(link, source, parc, parv);
}

/* --- setup / teardown --- */

static int world_setup(void **state)
{
  (void)state;

  forget();
  nmade = nchannels = nexited = 0;
  nrenames = 0;
  forced_exits = 0;
  ban_invalidations = except_invalidations = 0;
  fake_modes = "";
  feat_excepts = 0;

  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  memset(&me_serv, 0, sizeof(me_serv));
  ircd_strncpy(cli_name(&me), "hub.test", sizeof(me.cli_name));
  cli_status(&me) = STAT_ME;
  cli_connect(&me) = &me_con;
  con_client(&me_con) = &me;
  cli_serv(&me) = &me_serv;
  SetServerYXX(&me, &me, "AB]]]");

  memset(&his, 0, sizeof(his));
  ircd_strncpy(cli_name(&his), "his.example", sizeof(his.cli_name));
  cli_status(&his) = STAT_SERVER;
  cli_connect(&his) = &me_con;

  CurrentTime = 1000000;
  TSoffset = 0;
  return 0;
}

static int world_teardown(void **state)
{
  int i;
  (void)state;

  for (i = 0; i < nmade; i++)
    if (IsServer(made[i]))
      ClearServerYXX(made[i]);
  ClearServerYXX(&me);
  /* The objects themselves are left to the process: a test binary. */
  return 0;
}

/* ====================================================================
 * Stubs
 * ==================================================================== */

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...)
{
  (void)subsys; (void)severity; (void)flags; (void)fmt;
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{
  (void)killer; (void)comment;
  assert_true(nexited < MAXOBJ);
  exited[nexited++] = victim;
  return (cptr == victim) ? CPTR_KILLED : 0;
}

int exit_client_msg(struct Client *cptr, struct Client *bcptr,
                    struct Client *sptr, const char *pattern, ...)
{
  return exit_client(cptr, bcptr, sptr, pattern);
}

static struct ServerStatistics server_stats;
struct ServerStatistics *ServerStats = &server_stats;

int need_more_params(struct Client *cptr, const char *cmd)
{
  (void)cptr; (void)cmd;
  return 0;
}

int send_reply(struct Client *to, int reply, ...)
{
  char buf[LINE];

  snprintf(buf, sizeof(buf), "numeric %d", reply);
  record_sent(to, buf);
  return 0;
}

/* m_nick.c's, as it is: a nick ends at its first invalid character. */
int do_nick_name(char *nick)
{
  char *ch = nick, *end = ch + NICKLEN;

  if (*ch == '-' || IsDigit(*ch))
    return 0;
  for (; (ch < end) && *ch; ++ch)
    if (!IsNickChar(*ch))
      break;
  *ch = '\0';
  return (ch - nick);
}

int bounce_forced_exit(struct Client *cptr, struct Client *victim,
                       enum bounce_forced_exit why, const char *reason)
{
  (void)cptr; (void)victim; (void)why; (void)reason;
  forced_exits++;
  return 0;
}

int isNickJuped(const char *nick)
{
  (void)nick;
  return 0;
}

int set_nick_name(struct Client *cptr, struct Client *sptr, const char *nick,
                  int parc, char *parv[], int svsnick)
{
  (void)cptr; (void)parc; (void)parv; (void)svsnick;
  assert_true(nrenames < MAXREC);
  snprintf(renames[nrenames++], LINE, "%s -> %s", cli_name(sptr), nick);
  ircd_strncpy(cli_name(sptr), nick, sizeof(sptr->cli_name));
  return 0;
}

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_NICKLEN: return NICKLEN;
  default: return 0;
  }
}

const char *feature_str(enum Feature feat)
{
  switch (feat) {
  case FEAT_HIS_SERVERNAME: return "*.example";
  default: return "";
  }
}

int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_EXCEPTS: return feat_excepts;
  default: return 0;
  }
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  va_list vl;
  (void)cptr;

  assert_true(nviolations < MAXREC);
  va_start(vl, pattern);
  ircd_vsnprintf(NULL, violations[nviolations++], LINE, pattern, vl);
  va_end(vl);
  return 0;
}

/* The real one goes through msgq_make(&me, "%C %s %v") to every server
 * link with the flags asked for, but not to @a one's. */
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...)
{
  struct DLink *lp;
  (void)cmd;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *to = lp->value.cptr;
    struct VarData vd;
    char buf[LINE];

    if (one && to == cli_from(one))
      continue;
    if ((require < FLAG_LAST_FLAG && !HasFlag(to, require))
        || (forbid < FLAG_LAST_FLAG && HasFlag(to, forbid)))
      continue;
    vd.vd_format = pattern;
    va_start(vd.vd_args, pattern);
    ircd_snprintf(&me, buf, sizeof(buf), "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
    record_sent(to, buf);
  }
}

void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{
  struct DLink *lp;
  (void)cmd;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct Client *to = lp->value.cptr;
    struct VarData vd;
    char buf[LINE];

    if (one && to == cli_from(one))
      continue;
    vd.vd_format = pattern;
    va_start(vd.vd_args, pattern);
    ircd_snprintf(&me, buf, sizeof(buf), "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
    record_sent(to, buf);
  }
}

static void to_local_members(struct Client *from, const char *cmd,
                             struct Channel *to, struct Client *one,
                             const char *pattern, va_list args)
{
  struct Membership *m;

  for (m = to->members; m; m = m->next_member) {
    struct VarData vd;
    char buf[LINE];

    if (!MyConnect(m->user) || !IsUser(m->user) || IsZombie(m)
        || m->user == one)
      continue;
    vd.vd_format = pattern;
    va_copy(vd.vd_args, args);
    ircd_snprintf(m->user, buf, sizeof(buf), "%:#C %s %v", from, cmd, &vd);
    va_end(vd.vd_args);
    record_sent(m->user, buf);
  }
}

void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  va_list vl;
  (void)tok; (void)skip;

  va_start(vl, pattern);
  to_local_members(from, cmd, to, one, pattern, vl);
  va_end(vl);
}

void sendcmdto_channel_capab_butserv_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Channel *to,
                                            struct Client *one,
                                            unsigned int skip, int withcap,
                                            int skipcap,
                                            const char *pattern, ...)
{
  va_list vl;
  (void)tok; (void)skip; (void)skipcap;

  /* Each JOIN goes out twice, with and without extended-join; record the
   * plain form only. */
  if (withcap != CAP_NONE)
    return;
  va_start(vl, pattern);
  to_local_members(from, cmd, to, one, pattern, vl);
  va_end(vl);
}

void sendcmdto_set_client_event(const char *msgid, uint64_t event_ms)
{
  (void)msgid; (void)event_ms;
}

void sendcmdto_set_client_msgid(const char *msgid)
{
  (void)msgid;
}

void sendcmdto_set_s2s_tags(uint64_t time_ms, const char *msgid)
{
  (void)time_ms; (void)msgid;
}

void sendcmdto_want_s2s_tags(int want)
{
  (void)want;
}

char *generate_msgid(char *buf, size_t buflen)
{
  ircd_strncpy(buf, "ABAAAAAAAAAAAB", buflen);
  return buf;
}

uint64_t history_event_time_ms(struct Client *link)
{
  (void)link;
  return (uint64_t)CurrentTime * 1000;
}

int history_purge_incarnation(const char *channel, time_t incarnation)
{
  (void)channel; (void)incarnation;
  return 0;
}

void history_recv_reset(struct Channel *chptr)
{
  (void)chptr;
}

int64_t presence_event_time(const char *msgid, uint64_t event_ms)
{
  (void)msgid;
  return (int64_t)event_ms;
}

void presence_set_event_time(int64_t t)
{
  (void)t;
}

int channel_store_wanted(const struct Channel *chptr, int ours)
{
  (void)chptr; (void)ours;
  return 0;
}

void channel_store_kick(struct Client *src, struct Channel *chptr,
                        const char *victim, const char *comment,
                        const char *msgid, uint64_t event_ms, int wanted)
{
  (void)src; (void)chptr; (void)victim; (void)comment; (void)msgid;
  (void)event_ms; (void)wanted;
}

void relocate_channel_restamped(struct Channel *chptr, time_t old_ts)
{
  (void)chptr; (void)old_ts;
}

void relocate_tombstone_burst_done(struct Channel *chptr)
{
  (void)chptr;
}

void relocate_tombstone_ts_lost(struct Channel *chptr)
{
  (void)chptr;
}

int bounce_session_has_plaintext(struct Client *cptr)
{
  (void)cptr;
  return 0;
}

struct Channel *hSeekChannel(const char *name)
{
  int i;
  for (i = 0; i < nchannels; i++)
    if (channels[i] && 0 == ircd_strcmp(channels[i]->chname, name))
      return channels[i];
  return NULL;
}

struct Channel *get_channel(struct Client *cptr, char *chname,
                            ChannelGetType flag)
{
  struct Channel *ch = hSeekChannel(chname);
  (void)cptr;

  if (!ch && flag == CGT_CREATE)
    ch = fake_channel(chname);
  return ch;
}

int sub1_from_channel(struct Channel *chptr)
{
  (void)chptr;
  return 0;
}

struct Membership *find_member_link(struct Channel *chptr,
                                    const struct Client *cptr)
{
  struct Membership *m;
  for (m = chptr->members; m; m = m->next_member)
    if (m->user == cptr)
      return m;
  return NULL;
}

void add_user_to_channel(struct Channel *chptr, struct Client *who,
                         unsigned int flags, int oplevel)
{
  add_member(chptr, who, flags, oplevel);
}

/* What the Net Rider loop needs of the real one: the member is a zombie
 * afterwards, so the walk passes over it. */
void make_zombie(struct Membership *member, struct Client *who,
                 struct Client *cptr, struct Client *sptr,
                 struct Channel *chptr)
{
  (void)who; (void)cptr; (void)sptr; (void)chptr;
  member->status |= CHFL_ZOMBIE;
}

void mode_invite_clear(struct Channel *chan)
{
  (void)chan;
}

void mode_ban_invalidate(struct Channel *chan)
{
  (void)chan;
  ban_invalidations++;
}

void mode_except_invalidate(struct Channel *chan)
{
  (void)chan;
  except_invalidations++;
}

/* The real pretty_extmask() canonifies through pretty_mask(); for the
 * masks these tests use -- a bare nick, or a mask already in n!u@h form --
 * that is "nick!*@*" and the mask itself. */
char *pretty_extmask(char *mask)
{
  static char retmask[NICKLEN + USERLEN + HOSTLEN + 3];

  if (strchr(mask, '!') || strchr(mask, '@') || strchr(mask, '.'))
    ircd_strncpy(retmask, mask, sizeof(retmask));
  else
    ircd_snprintf(0, retmask, sizeof(retmask), "%s!*@*", mask);
  return retmask;
}

struct Ban *make_ban(const char *banstr)
{
  struct Ban *ban = calloc(1, sizeof(*ban));

  assert_non_null(ban);
  ircd_strncpy(ban->banstr, banstr, sizeof(ban->banstr));
  return ban;
}

void free_ban(struct Ban *ban)
{
  free(ban);
}

void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
                  struct Client *connect, struct Channel *chan,
                  unsigned int dest)
{
  memset(mbuf, 0, sizeof(*mbuf));
  mbuf->mb_source = source;
  mbuf->mb_connect = connect;
  mbuf->mb_channel = chan;
  mbuf->mb_dest = dest;
}

void modebuf_mode(struct ModeBuf *mbuf, unsigned int mode)
{
  (void)mbuf; (void)mode;
}

void modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
                         struct Client *client, int oplevel)
{
  (void)mbuf; (void)mode; (void)client; (void)oplevel;
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free_it)
{
  (void)mbuf; (void)mode;
  if (free_it)
    MyFree(string);
}

int modebuf_flush(struct ModeBuf *mbuf)
{
  (void)mbuf;
  return 0;
}

void modebuf_extract(struct ModeBuf *mbuf, char *buf, int oplevels)
{
  (void)mbuf; (void)oplevels;
  strcpy(buf, fake_modes);
}

/* How many parameters the real mode_parse() takes in a BURST
 * (MODE_PARSE_BURST: one mode string): the string, and one for every
 * letter channel.c's mode_parse() hands a parameter to while adding --
 * the prefixes o h v, the lists b e, the keys k A U, and l L, which
 * take theirs only when added.  The modes themselves are not applied. */
int mode_parse(struct ModeBuf *mbuf, struct Client *cptr,
               struct Client *sptr, struct Channel *chptr, int parc,
               char *parv[], unsigned int flags, struct Membership *member)
{
  const char *p;
  int used = 1, adding = 1;
  (void)mbuf; (void)cptr; (void)sptr; (void)chptr; (void)flags; (void)member;

  for (p = parv[0]; *p; p++) {
    switch (*p) {
    case '+': adding = 1; break;
    case '-': adding = 0; break;
    case 'l': case 'L':
      if (!adding)
        break;
      /* fall through */
    case 'o': case 'h': case 'v': case 'b': case 'e':
    case 'k': case 'A': case 'U':
      if (used < parc)
        used++;
      break;
    }
  }
  return used;
}

/* --- for m_topic.o: no storage, everybody may talk --- */

int history_is_available(void)
{
  return 0;
}

void history_format_ms(char *buf, size_t buflen, uint64_t ms)
{
  ircd_snprintf(0, buf, buflen, "%llu", (unsigned long long)ms);
}

const char *history_owner_of(char *buf, size_t size, struct Client *sptr)
{
  ircd_strncpy(buf, cli_name(sptr), size);
  return buf;
}

int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *original_target,
                          const char *sender, const char *account,
                          enum HistoryMessageType type, const char *content,
                          const char *client_tags, const char *owner)
{
  (void)msgid; (void)timestamp; (void)target; (void)original_target;
  (void)sender; (void)account; (void)type; (void)content; (void)client_tags;
  (void)owner;
  return 0;
}

struct Membership *find_channel_member(struct Client *cptr,
                                       struct Channel *chptr)
{
  return find_member_link(chptr, cptr);
}

int client_can_send_to_channel(struct Client *cptr, struct Channel *chptr,
                               int reveal)
{
  (void)cptr; (void)chptr; (void)reveal;
  return 1;
}

int is_chan_op(struct Client *cptr, struct Channel *chptr)
{
  struct Membership *m = find_member_link(chptr, cptr);
  return m && (m->status & CHFL_CHANOP);
}

int is_half_op(struct Client *cptr, struct Channel *chptr)
{
  (void)cptr; (void)chptr;
  return 0;
}

void RevealDelayedJoin(struct Membership *member)
{
  (void)member;
}

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  (void)command; (void)code; (void)context; (void)description;
  record_sent(to, "FAIL");
}

void send_warn(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  (void)command; (void)code; (void)context; (void)description;
  record_sent(to, "WARN");
}

/* The real sendcmdto_one() formats "%:#C %s %v" for the link the
 * destination is reached through; so does this. */
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  struct VarData vd;
  char buf[LINE];

  to = cli_from(to);
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  ircd_snprintf(to, buf, sizeof(buf), "%:#C %s %v", from,
                IsServer(to) || IsMe(to) ? tok : cmd, &vd);
  va_end(vd.vd_args);
  record_sent(to, buf);
}

/* --- for m_endburst.o and m_destruct.o --- */

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
  va_list vl;
  (void)one; (void)mask;

  assert_true(nopnotices < MAXREC);
  va_start(vl, pattern);
  ircd_vsnprintf(NULL, opnotices[nopnotices++], LINE, pattern, vl);
  va_end(vl);
}

void send_netjoin_batch_end(struct Client *server)
{
  (void)server;
}

void chathistory_server_eob(struct Client *server)
{
  (void)server;
}

void chathistory_reflood_ads(struct Client *newpeer)
{
  (void)newpeer;
}

int send_channel_advertisements(struct Client *cptr)
{
  (void)cptr;
  return 0;
}

int history_coverage_days(void)
{
  return 0;
}

void bounce_release_idle_gates(void)
{
}

void bounce_prune_stale_aliases(void)
{
}

void bounce_post_burst_reconcile(void)
{
}

void bounce_away_restate_to(struct Client *link)
{
  (void)link;
}

void presence_burst_sync(struct Client *cptr)
{
  (void)cptr;
}

void mdsync_link_eob(struct Client *link)
{
  (void)link;
}

void sasl_webhook_link_catchup(struct Client *cptr)
{
  (void)cptr;
}

const char *get_sasl_mechanisms(void)
{
  return "PLAIN";
}

void send_cap_notify(const char *capname, int available, const char *value)
{
  (void)capname; (void)available; (void)value;
}

int destruct_channel(struct Channel *chptr)
{
  (void)chptr;
  destructed++;
  return 0;
}

void remove_destruct_event(struct Channel *chptr)
{
  (void)chptr;
}

void modebuf_mode_uint(struct ModeBuf *mbuf, unsigned int mode,
                       unsigned int uint)
{
  (void)mbuf; (void)mode; (void)uint;
}

/* ====================================================================
 * Reading a relayed BURST back
 * ==================================================================== */

/** The parameters of @a line after "<source> B <channel> <ts>". */
static int burst_params(const char *line, char *copy, size_t size,
                        char **params)
{
  char *parv[MAXARGS];
  int parc, i;

  snprintf(copy, size, "%s", line);
  parc = split_line(copy, parv);
  /* parv[1] = source, [2] = B, [3] = channel, [4] = ts */
  for (i = 5; i < parc; i++)
    params[i - 5] = parv[i];
  params[i - 5] = NULL;
  return parc > 5 ? parc - 5 : 0;
}

/** Whether @a mask is one of the bans (or, with @a excepts, exceptions)
 * the relayed lines to @a to carry. */
static int relayed_ban(struct Client *to, const char *mask, int excepts)
{
  int i;

  for (i = 0; i < sent_count_to(to); i++) {
    char copy[LINE], *params[MAXARGS], *list, *tok, *save = NULL;
    int n = burst_params(sent_to(to, i), copy, sizeof(copy), params);
    int in_excepts = 0;

    if (n == 0 || params[n - 1][0] != '%')
      continue;
    list = params[n - 1] + 1;
    for (tok = strtok_r(list, " ", &save); tok; tok = strtok_r(NULL, " ", &save)) {
      if (!strcmp(tok, "~")) {
        in_excepts = 1;
        continue;
      }
      if (in_excepts == excepts && !strcmp(tok, mask))
        return 1;
    }
  }
  return 0;
}

/* Members as a receiver reads them out of the relayed lines: the mode of
 * every nick, line by line, with each line starting afresh (ms_burst()'s
 * own rules for a ":<mode>" field: v, h, o, and digits -- absolute after
 * a v or h or at the start, an increment otherwise). */
struct ReadMember {
  char numnick[8];
  int voice, halfop, op, oplevel;
};

static int read_members(struct Client *to, struct ReadMember *out, int max)
{
  int i, n = 0;

  for (i = 0; i < sent_count_to(to); i++) {
    char copy[LINE], *params[MAXARGS], *save = NULL, *nick;
    int np = burst_params(sent_to(to, i), copy, sizeof(copy), params), k;
    int voice = 0, halfop = 0, op = 0, oplevel = -1;

    for (k = 0; k < np; k++) {
      if (params[k][0] == '+' || params[k][0] == '%')
        continue;
      for (nick = strtok_r(params[k], ",", &save); nick;
           nick = strtok_r(NULL, ",", &save)) {
        char *spec = strchr(nick, ':');

        if (spec) {
          *spec++ = '\0';
          voice = halfop = op = 0;
          for (; *spec; spec++) {
            if (*spec == 'v') {
              voice = 1;
              oplevel = -1;
            } else if (*spec == 'h') {
              halfop = 1;
              oplevel = -1;
            } else if (*spec == 'o') {
              op = 1;
              oplevel = MAXOPLEVEL;
            } else if (*spec >= '0' && *spec <= '9') {
              unsigned long v = strtoul(spec, &spec, 10);
              spec--;
              op = 1;
              oplevel = (oplevel == -1) ? (int)v : oplevel + (int)v;
            }
          }
        }
        assert_true(n < max);
        snprintf(out[n].numnick, sizeof(out[n].numnick), "%s", nick);
        out[n].voice = voice;
        out[n].halfop = halfop;
        out[n].op = op;
        out[n].oplevel = oplevel;
        n++;
      }
    }
  }
  return n;
}

/** Every line that went to @a to is a BURST of @a chname at @a ts that
 * fits on the wire: at most 510 bytes before CR LF. */
static void assert_burst_lines(struct Client *to, const char *chname,
                               unsigned long ts)
{
  char head[64];
  int i;

  snprintf(head, sizeof(head), "AC B %s %lu", chname, ts);
  assert_true(sent_count_to(to) > 0);
  for (i = 0; i < sent_count_to(to); i++) {
    const char *l = sent_to(to, i);
    if (strlen(l) > BUFSIZE - 2)
      fail_msg("line %d to %s is %zu bytes: %.80s...", i, cli_name(to),
               strlen(l), l);
    assert_memory_equal(l, head, strlen(head));
  }
}

/* ====================================================================
 * BURST: the relay holds whatever the line it got grows to
 * ==================================================================== */

/* 160 two-letter masks: "aa ab ... " as one '%' parameter, 479 bytes. */
static void short_masks(char *buf, size_t size, int count, char first)
{
  int i;
  size_t pos = 0;

  for (i = 0; i < count; i++)
    pos += snprintf(buf + pos, size - pos, "%s%c%c", i ? " " : "",
                    first + i / 13, 'a' + i % 13);
}

/* Each "aa" is relayed as "aa!*@*": one 495-byte line from a peer becomes
 * over a thousand bytes of bans.  They used to be copied into banstr[512]
 * with no bound (a stack overflow); now they go on as many BURST lines as
 * they need, and none is dropped, from the relay or the channel. */
static void test_burst_bans_growing_past_a_line_all_relayed(void **state)
{
  struct Client *ac, *ad, *ae;
  struct Channel *ch;
  char masks[600], expect[16];
  int i;
  (void)state;

  ac = linked("leafa.test", "AC", 1);
  ad = linked("leafb.test", "AD", 0);  /* no op-levels: the other relay */
  ae = linked("leafc.test", "AE", 1);
  short_masks(masks, sizeof(masks), 160, 'a');
  assert_true(strlen(masks) < 480);

  deliver(ms_burst, ac, ac, "#bb 999000 :%%%s", masks);

  ch = hSeekChannel("#bb");
  assert_non_null(ch);
  assert_int_equal(count_bans(ch->banlist), 160);
  assert_int_equal(sent_count_to(ac), 0);
  assert_burst_lines(ad, "#bb", 999000);
  assert_burst_lines(ae, "#bb", 999000);
  assert_true(sent_count_to(ae) > 1);
  for (i = 0; i < 160; i++) {
    snprintf(expect, sizeof(expect), "%c%c!*@*", 'a' + i / 13, 'a' + i % 13);
    assert_true(relayed_ban(ad, expect, 0));
    assert_true(relayed_ban(ae, expect, 0));
  }
  assert_true(ban_invalidations > 0);
}

/* The same for ban exceptions ("~" in the list, relayed with EXCEPTS on). */
static void test_burst_excepts_growing_past_a_line_all_relayed(void **state)
{
  struct Client *ac, *ae;
  struct Channel *ch;
  char bans[300], excepts[300], expect[16];
  int i;
  (void)state;

  feat_excepts = 1;
  ac = linked("leafa.test", "AC", 1);
  ae = linked("leafc.test", "AE", 1);
  short_masks(bans, sizeof(bans), 70, 'a');
  short_masks(excepts, sizeof(excepts), 70, 'n');

  deliver(ms_burst, ac, ac, "#bb 999000 :%%%s ~ %s", bans, excepts);

  ch = hSeekChannel("#bb");
  assert_int_equal(count_bans(ch->banlist), 70);
  assert_int_equal(count_bans(ch->exceptlist), 70);
  assert_burst_lines(ae, "#bb", 999000);
  for (i = 0; i < 70; i++) {
    snprintf(expect, sizeof(expect), "%c%c!*@*", 'a' + i / 13, 'a' + i % 13);
    assert_true(relayed_ban(ae, expect, 0));
    assert_false(relayed_ban(ae, expect, 1));
    snprintf(expect, sizeof(expect), "%c%c!*@*", 'n' + i / 13, 'a' + i % 13);
    assert_true(relayed_ban(ae, expect, 1));
    assert_false(relayed_ban(ae, expect, 0));
  }
  assert_true(except_invalidations > 0);
}

/* The mode string goes on the first relayed line only, as
 * send_channel_modes() puts it on the first line of a channel's BURST. */
static void test_burst_split_relay_modes_on_first_line_only(void **state)
{
  struct Client *ac, *ae;
  char masks[600], copy[LINE], *params[MAXARGS];
  int i;
  (void)state;

  ac = linked("leafa.test", "AC", 1);
  ae = linked("leafc.test", "AE", 1);
  fake_modes = "+nt";
  short_masks(masks, sizeof(masks), 150, 'a');

  deliver(ms_burst, ac, ac, "#bb 999000 +nt :%%%s", masks);

  assert_burst_lines(ae, "#bb", 999000);
  assert_true(sent_count_to(ae) > 1);
  for (i = 0; i < sent_count_to(ae); i++) {
    int n = burst_params(sent_to(ae, i), copy, sizeof(copy), params);
    assert_true(n > 0);
    if (i == 0)
      assert_string_equal(params[0], "+nt");
    else
      assert_int_equal(params[0][0], '%');
  }
}

/** "ACAA" and the @a i-th numnick digit: the i-th user on AC. */
static void nth_numnick(char *buf, int i)
{
  char digit[2];

  inttobase64(digit, i, 1);
  sprintf(buf, "ACAA%s", digit);
}

/* Members whose mode field comes out longer than it went in (":5h" is
 * relayed as ":h" and the op-level -1 that 'h' leaves, ten digits) used to
 * overflow nickstr[512] the same way.  Every member is relayed, and a
 * continued line states the mode of its first member again. */
static void test_burst_members_growing_past_a_line_all_relayed(void **state)
{
  struct Client *ac, *ae, *ad;
  struct ReadMember got[128];
  char list[700], numnick[8];
  size_t pos = 0;
  int i, n;
  (void)state;

  ac = linked("leafa.test", "AC", 1);
  ad = linked("leafb.test", "AD", 0);
  ae = linked("leafc.test", "AE", 1);
  for (i = 0; i < 52; i++) {
    nth_numnick(numnick, i);
    remote_user(ac, numnick, numnick);
    pos += snprintf(list + pos, sizeof(list) - pos, "%s%s:%s", i ? "," : "",
                    numnick, (i & 1) ? "v" : "5h");
  }
  assert_true(pos < 470);

  deliver(ms_burst, ac, ac, "#nn 999000 %s", list);

  assert_int_equal(hSeekChannel("#nn")->users, 52);
  assert_burst_lines(ae, "#nn", 999000);
  assert_burst_lines(ad, "#nn", 999000);
  assert_true(sent_count_to(ae) > 1);

  n = read_members(ae, got, 128);
  assert_int_equal(n, 52);
  for (i = 0; i < 52; i++) {
    nth_numnick(numnick, i);
    assert_string_equal(got[i].numnick, numnick);
    if (i & 1) {
      assert_true(got[i].voice);
      assert_false(got[i].op);
    } else {
      assert_true(got[i].halfop);
      assert_true(got[i].op);
    }
  }
  n = read_members(ad, got, 128);
  assert_int_equal(n, 52);
  for (i = 0; i < 52; i++) {
    assert_int_equal(got[i].voice, i & 1);
    assert_int_equal(got[i].op, !(i & 1));
  }
}

/* A BURST that fits keeps its one relayed line, unchanged. */
static void test_burst_that_fits_relayed_as_one_line(void **state)
{
  struct Client *ac, *ae;
  (void)state;

  ac = linked("leafa.test", "AC", 1);
  ae = linked("leafc.test", "AE", 1);
  remote_user(ac, "alice", "ACAAA");
  remote_user(ac, "amy", "ACAAB");

  deliver(ms_burst, ac, ac, "#c 999000 ACAAA:o,ACAAB :%%a b!c@d");

  assert_int_equal(sent_count_to(ae), 1);
  assert_string_equal(sent_to(ae, 0), "AC B #c 999000 ACAAA:o,ACAAB :%a!*@* b!c@d");
}

/* ====================================================================
 * BURST: the Net Rider check reads the key where mode_parse() does
 * ==================================================================== */

/** Whether a Net Rider KICK of @a victim went anywhere. */
static int kicked(struct Client *victim)
{
  char needle[64];
  int i;

  snprintf(needle, sizeof(needle), " :Net Rider");
  for (i = 0; i < nsent; i++)
    if (strstr(sent[i].text, needle)
        && (strstr(sent[i].text, cli_name(victim))
            || strstr(sent[i].text, cli_yxx(victim))))
      return 1;
  return 0;
}

/** A BURST with an older timestamp than our #nr, which is +k key and has
 * our dave in it: is dave kicked as a Net Rider? */
static int burst_kicks(const char *modes_and_params)
{
  struct Client *ac, *dave;
  struct Channel *ch;

  ac = linked("leafa.test", "AC", 1);
  linked("leafc.test", "AE", 1);
  remote_user(ac, "alice", "ACAAA");
  dave = local_user("dave", "AAB");
  ch = fake_channel("#nr");
  ch->creationtime = 2000000;
  ircd_strncpy(ch->mode.key, "key", sizeof(ch->mode.key));
  add_member(ch, dave, CHFL_CHANOP, MAXOPLEVEL);

  deliver(ms_burst, ac, ac, "#nr 999000 %s ACAAA:o", modes_and_params);
  return kicked(dave);
}

/* The control: a key that matches ours keeps our members; one that does
 * not kicks them. */
static void test_burst_netride_key_alone(void **state)
{
  (void)state;
  assert_false(burst_kicks("+k key"));
}

static void test_burst_netride_other_key_kicks(void **state)
{
  (void)state;
  assert_true(burst_kicks("+k other"));
}

/* +L takes a parameter in a BURST (the redirect), so the key is the one
 * after it.  send_channel_modes() itself orders a channel's parameters
 * l L k A U, so any +L+k channel losing its TS met this. */
static void test_burst_netride_redirect_before_key(void **state)
{
  (void)state;
  assert_false(burst_kicks("+Lk #redir key"));
}

static void test_burst_netride_limit_redirect_key(void **state)
{
  (void)state;
  assert_false(burst_kicks("+lLk 10 #redir key"));
}

static void test_burst_netride_redirect_other_key_kicks(void **state)
{
  (void)state;
  assert_true(burst_kicks("+Lk #redir other"));
}

/* Every other letter mode_parse() gives a parameter to while adding: the
 * op-level passwords A U, the lists b e, the prefixes o h v. */
static void test_burst_netride_every_parameter_letter(void **state)
{
  static const char *forms[] = {
    "+Ak apass key", "+Uk upass key", "+bk *!*@x key", "+ek *!*@x key",
    "+ok ACAAA key", "+hk ACAAA key", "+vk ACAAA key",
    "+lLAUbeohvk 5 #r a u *!*@b *!*@e ACAAA ACAAA ACAAA key",
  };
  size_t i;
  (void)state;

  for (i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
    world_teardown(NULL);
    world_setup(NULL);
    if (burst_kicks(forms[i]))
      fail_msg("\"%s\": our member kicked although the key matches", forms[i]);
  }
}

/* ====================================================================
 * SVSNICK
 * ==================================================================== */

/* The network for the SVSNICK cases: services (AE, +s) with its bot X3,
 * a plain server AC with alice, and our dave, the target. */
static struct Client *svs, *svsbot, *leaf, *alice, *dave;

static void svsnick_world(void)
{
  svs = services(linked("x3.test", "AE", 0));
  svsbot = remote_user(svs, "X3", "AEAAA");
  leaf = linked("leafa.test", "AC", 1);
  alice = remote_user(leaf, "alice", "ACAAA");
  dave = local_user("dave", "AAB");
}

/* What services do with it: rename the target, and tell the network. */
static void test_svsnick_from_services(void **state)
{
  (void)state;
  svsnick_world();

  deliver(ms_svsnick, svs, svs, "%s fresh 1000000", "ABAAB");

  assert_int_equal(nrenames, 1);
  assert_string_equal(renames[0], "dave -> fresh");
  assert_int_equal(sent_count_to(svs), 0);
  assert_int_equal(sent_count_to(leaf), 1);
  assert_string_equal(sent_to(leaf, 0), "AE SN ABAAB fresh");
  assert_int_equal(nviolations, 0);
}

/* (c) A nick another user holds: that user is killed (Nickname
 * Enforcement) and the target renamed. */
static void test_svsnick_nick_of_another_user(void **state)
{
  (void)state;
  svsnick_world();

  deliver(ms_svsnick, svs, svs, "ABAAB alice");

  assert_true(was_exited(alice));
  assert_false(was_exited(dave));
  assert_int_equal(nrenames, 1);
  assert_string_equal(renames[0], "dave -> alice");
  assert_string_equal(sent_to(leaf, 0), "AB D ACAAA :hub.test (Nickname Enforcement)");
  assert_string_equal(sent_to(leaf, 1), "AE SN ABAAB alice");
}

/* (a) The target's own nick: nothing to do. */
static void test_svsnick_own_nick(void **state)
{
  (void)state;
  svsnick_world();

  deliver(ms_svsnick, svs, svs, "ABAAB dave");

  assert_int_equal(nrenames, 0);
  assert_int_equal(nexited, 0);
  assert_int_equal(nsent, 0);
}

/* (b) The nick the source holds.  The handler used to kill the source to
 * free the nick and then relay the SVSNICK from it: a NULL dereference
 * (the source was freed).  It is refused: nobody is killed or renamed,
 * nothing is relayed. */
static void test_svsnick_nick_of_its_source(void **state)
{
  (void)state;
  svsnick_world();

  deliver(ms_svsnick, svs, svsbot, "ABAAB X3");

  assert_false(was_exited(svsbot));
  assert_int_equal(nexited, 0);
  assert_int_equal(nrenames, 0);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 1);
}

/* SVSNICK is a services command: from a server that did not announce
 * itself as services, or a user on one, it is refused. */
static void test_svsnick_from_non_services(void **state)
{
  (void)state;
  svsnick_world();

  deliver(ms_svsnick, leaf, leaf, "ABAAB fresh");
  deliver(ms_svsnick, leaf, alice, "ABAAB alice");

  assert_int_equal(nrenames, 0);
  assert_int_equal(nexited, 0);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 2);
}

/* ====================================================================
 * SVSQUIT
 * ==================================================================== */

/* Services quit one of our users.  The handler returned exit_client()'s
 * result for the USER as if it were the link's: CPTR_KILLED told the
 * parser that the services link was gone, and the rest of what it had
 * read from that link was thrown away.  Only the user goes. */
static void test_svsquit_our_user_keeps_the_link(void **state)
{
  int ret;
  (void)state;
  svsnick_world();

  ret = deliver(ms_svsquit, svs, svs, "ABAAB :bye");

  assert_int_equal(ret, 0);
  assert_true(was_exited(dave));
  assert_false(was_exited(svs));
  assert_int_equal(forced_exits, 1);
}

/* A user on another server: relayed toward it, nobody exited here. */
static void test_svsquit_remote_user_relayed(void **state)
{
  int ret;
  (void)state;
  svsnick_world();

  ret = deliver(ms_svsquit, svs, svs, "ACAAA :bye");

  assert_int_equal(ret, 0);
  assert_int_equal(nexited, 0);
  assert_int_equal(sent_count_to(leaf), 1);
  assert_string_equal(sent_to(leaf, 0), "AE SX ACAAA :bye");
}

/* ====================================================================
 * TOPIC from a server
 * ==================================================================== */

/* Our #c with carol in it; leafa (AC) and leafc (AE) linked. */
static struct Client *carol;
static struct Channel *topic_world(struct Client **leafa, struct Client **leafc)
{
  struct Channel *ch;

  *leafa = linked("leafa.test", "AC", 1);
  *leafc = linked("leafc.test", "AE", 1);
  carol = local_user("carol", "AAA");
  ch = fake_channel("#c");
  ch->creationtime = 999000;
  add_member(ch, carol, CHFL_CHANOP, MAXOPLEVEL);
  return ch;
}

/* A setter field: the members see its nick, the topic keeps the field. */
static void test_topic_with_a_setter(void **state)
{
  struct Client *ac, *ae;
  struct Channel *ch;
  (void)state;
  ch = topic_world(&ac, &ae);

  deliver(ms_topic, ac, ac, "#c bob!b@host 999000 1000500 :the topic");

  assert_string_equal(sent_to(carol, 0), ":leafa.test TOPIC #c :the topic (bob)");
  assert_string_equal(ch->topic_nick, "bob!b@host");
  assert_string_equal(sent_to(ae, 0), "AC T #c bob!b@host 999000 1000500 :the topic");
}

/* A setter field with no nick in it ("!") left nick[] unset, and the
 * members were sent whatever the stack held: "(<garbage>)".  It is now
 * no setter field: the topic names its source, as one sent without the
 * field does (the server, not a NULL user -- b5f466aa). */
static void test_topic_setter_with_no_nick(void **state)
{
  struct Client *ac, *ae;
  struct Channel *ch;
  (void)state;
  ch = topic_world(&ac, &ae);

  deliver(ms_topic, ac, ac, "#c ! 999000 1000500 :the topic");

  assert_string_equal(sent_to(carol, 0), ":leafa.test TOPIC #c :the topic");
  assert_string_equal(ch->topic, "the topic");
  assert_string_equal(ch->topic_nick, "leafa.test");
  assert_string_equal(sent_to(ae, 0), "AC T #c 999000 1000500 :the topic");
}

static void test_topic_without_a_setter(void **state)
{
  struct Client *ac, *ae;
  struct Channel *ch;
  (void)state;
  ch = topic_world(&ac, &ae);

  deliver(ms_topic, ac, ac, "#c 999000 1000500 :the topic");

  assert_string_equal(sent_to(carol, 0), ":leafa.test TOPIC #c :the topic");
  assert_string_equal(ch->topic_nick, "leafa.test");
  assert_string_equal(sent_to(ae, 0), "AC T #c 999000 1000500 :the topic");
}

/* ====================================================================
 * Burst state from a user source
 * ==================================================================== */

/* A server ends its burst: relayed, announced, acknowledged. */
static void test_end_of_burst_from_a_server(void **state)
{
  struct Client *ac, *ae;
  (void)state;
  ac = linked("leafa.test", "AC", 1);
  ae = linked("leafc.test", "AE", 1);
  SetBurst(ac);

  deliver(ms_end_of_burst, ac, ac, "");

  assert_false(IsBurst(ac));
  assert_string_equal(sent_to(ae, 0), "AC EB ");
  assert_string_equal(sent_to(ac, 0), "AB EA ");
  assert_int_equal(nopnotices, 1);
  assert_int_equal(nviolations, 0);
}

/* "ACAAA EB" was relayed and announced as "Completed net.burst from
 * alice."  END_OF_BURST, its ack, BURST and DESTRUCT are server messages;
 * from a user they are protocol violations, go no further and change
 * nothing.  The link that carried them stays. */
static void test_end_of_burst_from_a_user(void **state)
{
  struct Client *ac, *ae, *alice;
  (void)state;
  ac = linked("leafa.test", "AC", 1);
  ae = linked("leafc.test", "AE", 1);
  alice = remote_user(ac, "alice", "ACAAA");

  assert_int_equal(deliver(ms_end_of_burst, ac, alice, ""), 0);

  assert_int_equal(nsent, 0);
  assert_int_equal(nopnotices, 0);
  assert_int_equal(nviolations, 1);
  assert_int_equal(sent_count_to(ae), 0);
}

static void test_end_of_burst_ack_from_a_user(void **state)
{
  struct Client *ac, *alice;
  (void)state;
  ac = linked("leafa.test", "AC", 1);
  linked("leafc.test", "AE", 1);
  alice = remote_user(ac, "alice", "ACAAA");

  assert_int_equal(deliver(ms_end_of_burst_ack, ac, alice, ""), 0);

  assert_int_equal(nsent, 0);
  assert_int_equal(nopnotices, 0);
  assert_int_equal(nviolations, 1);
}

static void test_burst_from_a_user(void **state)
{
  struct Client *ac, *alice;
  (void)state;
  ac = linked("leafa.test", "AC", 1);
  linked("leafc.test", "AE", 1);
  alice = remote_user(ac, "alice", "ACAAA");

  assert_int_equal(deliver(ms_burst, ac, alice, "#ub 999000 +i ACAAA:o"), 0);

  assert_null(hSeekChannel("#ub"));
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 1);
}

static void test_destruct_from_a_user(void **state)
{
  struct Client *ac, *alice;
  struct Channel *ch;
  (void)state;
  ac = linked("leafa.test", "AC", 1);
  linked("leafc.test", "AE", 1);
  alice = remote_user(ac, "alice", "ACAAA");
  ch = fake_channel("#empty");
  ch->creationtime = 999000;

  assert_int_equal(deliver(ms_destruct, ac, alice, "#empty 999000"), 0);

  assert_int_equal(destructed, 0);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 1);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
#define T(f) cmocka_unit_test_setup_teardown(f, world_setup, world_teardown)
    T(test_burst_bans_growing_past_a_line_all_relayed),
    T(test_burst_excepts_growing_past_a_line_all_relayed),
    T(test_burst_split_relay_modes_on_first_line_only),
    T(test_burst_members_growing_past_a_line_all_relayed),
    T(test_burst_that_fits_relayed_as_one_line),
    T(test_burst_netride_key_alone),
    T(test_burst_netride_other_key_kicks),
    T(test_burst_netride_redirect_before_key),
    T(test_burst_netride_limit_redirect_key),
    T(test_burst_netride_redirect_other_key_kicks),
    T(test_burst_netride_every_parameter_letter),
    T(test_svsnick_from_services),
    T(test_svsnick_nick_of_another_user),
    T(test_svsnick_own_nick),
    T(test_svsnick_nick_of_its_source),
    T(test_svsnick_from_non_services),
    T(test_svsquit_our_user_keeps_the_link),
    T(test_svsquit_remote_user_relayed),
    T(test_topic_with_a_setter),
    T(test_topic_setter_with_no_nick),
    T(test_topic_without_a_setter),
    T(test_end_of_burst_from_a_server),
    T(test_end_of_burst_from_a_user),
    T(test_end_of_burst_ack_from_a_user),
    T(test_burst_from_a_user),
    T(test_destruct_from_a_user),
#undef T
  };

  return cmocka_run_group_tests_name("s2s_handlers", tests, NULL, NULL);
}
