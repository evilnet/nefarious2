/*
 * rename_handlers_cmocka.c - channel RENAME's handlers against a fake
 * network.
 *
 * Links the REAL m_rename.o (with rename_proto.o, numnicks.o and the
 * ircd's own printf, so every line asserted below is the line that would
 * go on the wire) and stubs what is underneath it: the send layer records
 * instead of sending, the channel table is a list, timers fire when the
 * test says so.
 *
 * The fake network is built per test from three helpers -- linked() for a
 * server linked to this one, behind() for a server reached through one of
 * those, user_on() for a user -- and this server is always numeric "AC".
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
#include "gline.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_features.h"
#include "ircd_log.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "list.h"
#include "msg.h"
#include "numnicks.h"
#include "rename_proto.h"
#include "s_debug.h"
#include "s_misc.h"
#include "s_user.h"
#include "send.h"
#include "struct.h"

/* ====================================================================
 * Globals the linked objects expect
 * ==================================================================== */

struct Client me;
struct Client his;
struct Client *GlobalClientList;
time_t CurrentTime = 1000000;
time_t TSoffset;
int log_inassert;

/* ====================================================================
 * What the code under test did
 * ==================================================================== */

#define LINE 700
#define MAXREC 96

struct Sent {
  struct Client *to;            /* the local connection the line went to */
  char text[LINE];
};

static struct Sent sent[MAXREC];
static int nsent;
static char violations[MAXREC][LINE];
static int nviolations;
static char opnotices[MAXREC][LINE];
static int nopnotices;
static char debuglines[MAXREC][LINE];
static int ndebug;

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
  nsent = nviolations = nopnotices = ndebug = 0;
}

/* ====================================================================
 * The fake network
 * ==================================================================== */

#define MAXOBJ 64
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
  cli_next(c) = GlobalClientList;
  GlobalClientList = c;
  return c;
}

static void apply_flags(struct Client *c, const char *flags)
{
  for (; *flags; flags++) switch (*flags) {
  case 's': SetService(c); break;
  case 'v': SetIRCv3Aware(c); break;
  case 'r': SetRenameCapable(c); break;
  }
}

static struct Client *fake_server(const char *name, const char *numeric,
                                  const char *flags)
{
  struct Client *c = fake_client(name, STAT_SERVER);
  char yxx[6];

  cli_serv(c) = calloc(1, sizeof(struct Server));
  assert_non_null(cli_serv(c));
  /* two numeric characters and a three-character capacity ("AAB": 2) */
  snprintf(yxx, sizeof(yxx), "%sAAB", numeric);
  SetServerYXX(c, c, yxx);
  apply_flags(c, flags);
  return c;
}

/** A server linked directly to this one.  @a flags: 's' services,
 * 'v' IRCv3-aware (a fork server), 'r' rename-capable. */
static struct Client *linked(const char *name, const char *numeric,
                           const char *flags)
{
  struct Client *c = fake_server(name, numeric, flags);
  struct DLink *dl = calloc(1, sizeof(*dl));

  assert_non_null(dl);
  cli_connect(c) = calloc(1, sizeof(struct Connection));
  assert_non_null(cli_connect(c));
  con_client(cli_connect(c)) = c;
  cli_serv(c)->up = &me;

  dl->value.cptr = c;
  dl->next = cli_serv(&me)->down;
  cli_serv(&me)->down = dl;
  return c;
}

/** A server reached through @a via (a server made by linked() or behind()). */
static struct Client *behind(struct Client *via, const char *name,
                             const char *numeric, const char *flags)
{
  struct Client *c = fake_server(name, numeric, flags);

  cli_connect(c) = cli_connect(via);    /* cli_from(c) is via's link */
  cli_serv(c)->up = via;
  return c;
}

/** A user on @a server (&me for one of ours), numeric @a yxx. */
static struct Client *user_on(struct Client *server, const char *nick,
                              const char *yxx)
{
  struct Client *c = fake_client(nick, STAT_USER);

  cli_user(c) = calloc(1, sizeof(struct User));
  assert_non_null(cli_user(c));
  cli_user(c)->server = server;
  ircd_strncpy(cli_user(c)->username, "user", sizeof(cli_user(c)->username));
  ircd_strncpy(cli_user(c)->host, "host.example", sizeof(cli_user(c)->host));
  ircd_strncpy(cli_yxx(c), yxx, sizeof(c->cli_yxx));
  ircd_strncpy(cli_info(c), "Real Name", sizeof(c->cli_info));
  if (server == &me) {
    cli_connect(c) = calloc(1, sizeof(struct Connection));
    assert_non_null(cli_connect(c));
    con_client(cli_connect(c)) = c;
  } else
    cli_connect(c) = cli_connect(server);
  return c;
}

/* --- channels: a list instead of the hash --- */

static struct Channel *channels[MAXOBJ];
static int nchannels;
static struct Channel *destroyed[MAXOBJ];   /* see fake_destruct() */
static int ndestroyed;
static int alias_syncs, dirty_marks;        /* calls into the bouncer */

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
                                     unsigned int status)
{
  struct Membership *m = calloc(1, sizeof(*m));

  assert_non_null(m);
  m->user = who;
  m->channel = ch;
  m->status = status;
  /* as a member of a channel without oplevels (no +A) has it */
  m->oplevel = MAXOPLEVEL;
  m->next_member = ch->members;
  if (ch->members)
    ch->members->prev_member = m;
  ch->members = m;
  if (status & CHFL_ALIAS)
    ch->aliases++;
  else
    ch->users++;
  return m;
}

static struct Channel *channel_named(const char *name)
{
  int i;
  for (i = 0; i < nchannels; i++)
    if (channels[i] && 0 == strcmp(channels[i]->chname, name))
      return channels[i];
  return NULL;
}

/* --- features --- */

static int feat_rename_services;
static int feat_rename_consent;
static int feat_channellen;
static int feat_utf8_only;
static int feat_relocate_grace;

/* --- timers: recorded, fired by hand --- */

static struct Timer *timers[MAXOBJ];
static int ntimers;
static struct Timer *in_dispatch;       /* the timer whose ET_EXPIRE runs */

static void fire(struct Timer *t, enum EventType type)
{
  struct Event ev;

  memset(&ev, 0, sizeof(ev));
  ev.ev_type = type;
  ev.ev_gen.gen_timer = t;
  if (type == ET_EXPIRE)
    in_dispatch = t;
  (*t->t_header.gh_call)(&ev);
  if (type == ET_EXPIRE)
    in_dispatch = NULL;
}

/** How many timers are armed for @a when (the event loop's clock). */
static int timers_at(time_t when)
{
  int i, count = 0;
  for (i = 0; i < ntimers; i++)
    if (timers[i]->t_type == TT_ABSOLUTE && timers[i]->t_value == when)
      count++;
  return count;
}

/** Fire every tombstone timer that is due (they are the absolute ones;
 * the services timeouts are relative and stay). */
static void fire_due(void)
{
  int i;

  for (i = 0; i < ntimers; ) {
    struct Timer *t = timers[i];

    if (t->t_type != TT_ABSOLUTE || t->t_value > CurrentTime) {
      i++;
      continue;
    }
    timers[i] = timers[--ntimers];
    fire(t, ET_EXPIRE);
    fire(t, ET_DESTROY);
    i = 0;                      /* the callback may have changed the list */
  }
}

/** Let @a seconds pass. */
static void advance(int seconds)
{
  CurrentTime += seconds;
  fire_due();
}

/** Let every pending rename's services timeout expire. */
static void expire_all_timers(void)
{
  while (ntimers > 0) {
    struct Timer *t = timers[--ntimers];
    fire(t, ET_EXPIRE);
    fire(t, ET_DESTROY);
  }
}

/* --- setup / teardown --- */

static int world_setup(void **state)
{
  (void)state;

  forget();
  nmade = nchannels = ntimers = 0;
  ndestroyed = 0;
  alias_syncs = dirty_marks = 0;
  GlobalClientList = NULL;

  memset(&me, 0, sizeof(me));
  memset(&me_con, 0, sizeof(me_con));
  memset(&me_serv, 0, sizeof(me_serv));
  ircd_strncpy(cli_name(&me), "me.example", sizeof(me.cli_name));
  cli_status(&me) = STAT_ME;
  cli_connect(&me) = &me_con;
  con_client(&me_con) = &me;
  cli_serv(&me) = &me_serv;
  SetServerYXX(&me, &me, "ACAAB");
  SetIRCv3Aware(&me);
  cli_next(&me) = NULL;
  GlobalClientList = &me;

  /* the name server-sourced lines to clients go out under */
  memset(&his, 0, sizeof(his));
  ircd_strncpy(cli_name(&his), "his.example", sizeof(his.cli_name));
  cli_status(&his) = STAT_SERVER;
  cli_connect(&his) = &me_con;

  feat_rename_services = 1;
  feat_rename_consent = 0;
  feat_channellen = CHANNELLEN;
  feat_utf8_only = 0;
  feat_relocate_grace = 900;
  CurrentTime = 1000000;
  TSoffset = 0;
  return 0;
}

/* +L and +l live in their parameters (mode.redir, mode.limit) and
 * nowhere else: nothing in channel.c ever sets, clears or reads
 * MODE_REDIRECT or MODE_LIMIT in a channel's mode.mode -- mode_parse_redir()
 * writes the string, channel_modes() and do_join() read it.  So a channel
 * that got its redirect from a BURST or a MODE never has the bit, and the
 * relocation engine may neither rely on it nor leave it behind (it once
 * did both: a tombstone learned from a BURST was never recognised).  Every
 * channel of every test is checked on the way out. */
static void assert_parameter_modes_are_not_bits(void)
{
  int i;

  for (i = 0; i < nchannels; i++)
    if (channels[i])
      assert_int_equal(channels[i]->mode.mode & (MODE_REDIRECT | MODE_LIMIT), 0);
  for (i = 0; i < ndestroyed; i++)
    assert_int_equal(destroyed[i]->mode.mode & (MODE_REDIRECT | MODE_LIMIT), 0);
}

static int world_teardown(void **state)
{
  int i;
  (void)state;

  assert_parameter_modes_are_not_bits();

  /* Requests still waiting on services go the way they would in the
   * ircd, so no pending request leaks into the next test. */
  expire_all_timers();

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
  va_list vl;
  (void)subsys; (void)severity; (void)flags;

  if (ndebug >= MAXREC)
    return;
  va_start(vl, fmt);
  ircd_vsnprintf(NULL, debuglines[ndebug++], LINE, fmt, vl);
  va_end(vl);
}

void debug(int level, const char *form, ...)
{
  (void)level; (void)form;
}

int exit_client(struct Client *cptr, struct Client *victim,
                struct Client *killer, const char *comment)
{
  (void)cptr; (void)victim; (void)killer; (void)comment;
  fail_msg("exit_client() called");
  return 0;
}

int feature_bool(enum Feature feat)
{
  switch (feat) {
  case FEAT_RENAME_SERVICES: return feat_rename_services;
  case FEAT_RENAME_CONSENT: return feat_rename_consent;
  case FEAT_VALID_UTF8_CHANNELS_ONLY: return feat_utf8_only;
  default: return 0;
  }
}

int feature_int(enum Feature feat)
{
  switch (feat) {
  case FEAT_CHANNELLEN: return feat_channellen;
  case FEAT_RELOCATE_GRACE: return feat_relocate_grace;
  default: return 0;
  }
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

/* The real one adds the recipient's tags (@time, @account, ...) in front;
 * the line itself is formatted the same way. */
void sendcmdto_one_event(struct Client *from, const char *cmd, const char *tok,
                         struct Client *to, int respond, const char *pattern,
                         ...)
{
  struct VarData vd;
  char buf[LINE];
  (void)respond;

  to = cli_from(to);
  vd.vd_format = pattern;
  va_start(vd.vd_args, pattern);
  ircd_snprintf(to, buf, sizeof(buf), "%:#C %s %v", from,
                IsServer(to) || IsMe(to) ? tok : cmd, &vd);
  va_end(vd.vd_args);
  record_sent(to, buf);
}

/* As the real one: every IRCv3-aware link except the one @a one is
 * reached through. */
void sendcmdto_serv_butone_v3(struct Client *from, const char *cmd,
                              const char *tok, struct Client *one,
                              const char *pattern, ...)
{
  struct DLink *lp;
  (void)cmd;

  for (lp = cli_serv(&me)->down; lp; lp = lp->next) {
    struct VarData vd;
    char buf[LINE];

    if (one && lp->value.cptr == cli_from(one))
      continue;
    if (!IsIRCv3Aware(lp->value.cptr))
      continue;
    vd.vd_format = pattern;
    va_start(vd.vd_args, pattern);
    ircd_snprintf(lp->value.cptr, buf, sizeof(buf), "%C %s %v", from, tok, &vd);
    va_end(vd.vd_args);
    record_sent(lp->value.cptr, buf);
  }
}

/* As the real one: every local member's connection, the source's own
 * and bouncer aliases included; zombies and @a one are skipped. */
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  struct Membership *m;
  (void)tok; (void)skip;

  for (m = to->members; m; m = m->next_member) {
    struct VarData vd;
    char buf[LINE];

    if (!MyConnect(m->user) || !IsUser(m->user) || IsZombie(m)
        || m->user == one)
      continue;
    vd.vd_format = pattern;
    va_start(vd.vd_args, pattern);
    ircd_snprintf(m->user, buf, sizeof(buf), "%:#C %s %v", from, cmd, &vd);
    va_end(vd.vd_args);
    record_sent(m->user, buf);
  }
}

void send_fail(struct Client *to, const char *command, const char *code,
               const char *context, const char *description)
{
  char buf[LINE];

  snprintf(buf, sizeof(buf), "FAIL %s %s %s :%s", command, code, context,
           description);
  record_sent(to, buf);
}

int send_reply(struct Client *to, int reply, ...)
{
  char buf[LINE];

  snprintf(buf, sizeof(buf), "numeric %d", reply);
  record_sent(to, buf);
  return 0;
}

void do_names(struct Client *sptr, struct Channel *chptr, int filter)
{
  char buf[LINE];
  (void)filter;

  snprintf(buf, sizeof(buf), "(names of %s)", chptr->chname);
  record_sent(sptr, buf);
}

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

struct Channel *hSeekChannel(const char *name)
{
  int i;
  for (i = 0; i < nchannels; i++)
    if (channels[i] && 0 == ircd_strcmp(channels[i]->chname, name))
      return channels[i];
  return NULL;
}

struct Membership *find_channel_member(struct Client *cptr,
                                       struct Channel *chptr)
{
  struct Membership *m;
  for (m = chptr->members; m; m = m->next_member)
    if (m->user == cptr && !IsZombie(m))
      return m;
  return NULL;
}

/* What the real rename_channel() (channel.c) promises its callers: -1 for
 * a name too long, -2 for a name in use, otherwise the channel -- possibly
 * a NEW struct -- under the new name. */
int rename_channel(struct Channel **chptr_p, const char *newname)
{
  struct Channel *old = *chptr_p, *ch;
  struct Membership *m;
  int i;

  if (strlen(newname) > CHANNELLEN)
    return -1;
  if (hSeekChannel(newname))
    return -2;

  ch = calloc(1, sizeof(*ch) + strlen(newname));
  assert_non_null(ch);
  memcpy(ch, old, sizeof(*ch));
  strcpy(ch->chname, newname);
  for (m = ch->members; m; m = m->next_member)
    m->channel = ch;
  for (i = 0; i < nchannels; i++)
    if (channels[i] == old)
      channels[i] = ch;
  free(old);
  *chptr_p = ch;
  return 0;
}

struct Gline *gline_find(char *userhost, unsigned int flags)
{
  (void)userhost; (void)flags;
  return NULL;
}

struct Timer *timer_init(struct Timer *timer)
{
  memset(timer, 0, sizeof(*timer));
  return timer;
}

void timer_add(struct Timer *timer, EventCallBack call, void *data,
               enum TimerType type, time_t value)
{
  timer->t_type = type;
  timer->t_value = value;
  timer->t_header.gh_call = call;
  timer->t_header.gh_data = data;
  assert_true(ntimers < MAXOBJ);
  timers[ntimers++] = timer;
}

/* As the real one outside a dispatch: ET_DESTROY at once.  The two ways
 * to misuse it fail the test: on a timer in dispatch the real one does
 * nothing (the caller then believes it cancelled), and a timer that is
 * not queued has no business being deleted. */
void timer_del(struct Timer *timer)
{
  int i;

  if (timer == in_dispatch)
    fail_msg("timer_del() on the timer whose ET_EXPIRE is running");
  for (i = 0; i < ntimers; i++) {
    if (timers[i] == timer) {
      timers[i] = timers[--ntimers];
      break;
    }
  }
  if (i > ntimers)
    fail_msg("timer_del() on a timer that is not queued");
  fire(timer, ET_DESTROY);
}

void timer_chg(struct Timer *timer, enum TimerType type, time_t value)
{
  int i;

  assert_true(value != 0);              /* as the real one asserts */
  for (i = 0; i < ntimers; i++)
    if (timers[i] == timer)
      break;
  if (i == ntimers)
    fail_msg("timer_chg() on a timer that is not queued");
  timer->t_type = type;
  timer->t_value = value;
}

/* --- what relocation mode needs of channel.c ---
 *
 * The channel table is the list above; a destroyed channel leaves it (and
 * is kept, not freed, so a stale pointer in the code under test reads
 * something a test can still assert on). */

static void fake_destruct(struct Channel *ch)
{
  int i;

  assert_null(ch->members);
  /* as destruct_channel() */
  relocate_tombstone_channel_gone(ch);
  for (i = 0; i < nchannels; i++)
    if (channels[i] == ch)
      channels[i] = NULL;
  assert_true(ndestroyed < MAXOBJ);
  destroyed[ndestroyed++] = ch;
}

static int was_destroyed(struct Channel *ch)
{
  int i;
  for (i = 0; i < ndestroyed; i++)
    if (destroyed[i] == ch)
      return 1;
  return 0;
}

/* As the real one: a channel a local user makes is stamped now, one made
 * for a remote line is stamped by its caller. */
struct Channel *get_channel(struct Client *cptr, char *chname,
                            ChannelGetType flag)
{
  struct Channel *ch = hSeekChannel(chname);

  if (ch || flag != CGT_CREATE)
    return ch;
  ch = fake_channel(chname);
  ch->creationtime = MyUser(cptr) ? TStime() : (time_t)0;
  return ch;
}

void add_user_to_channel(struct Channel *chptr, struct Client *who,
                         unsigned int flags, int oplevel)
{
  SetOpLevel(add_member(chptr, who, flags), oplevel);
}

/* As the real one for a channel without oplevels or zannels: an empty
 * channel that is not persistent and has no alias left is reset and
 * destroyed. */
int sub1_from_channel(struct Channel *chptr)
{
  if (chptr->users > 1) {
    --chptr->users;
    return 1;
  }
  chptr->users = 0;
  if (chptr->aliases > 0)
    return 0;
  if (chptr->mode.exmode & EXMODE_PERSIST)
    return 0;
  chptr->mode.mode = 0;
  chptr->mode.exmode = 0;
  chptr->mode.limit = 0;
  chptr->mode.redir[0] = '\0';
  chptr->mode.key[0] = '\0';
  fake_destruct(chptr);
  return 0;
}

static void unlink_member(struct Membership *m)
{
  struct Channel *ch = m->channel;

  if (m->prev_member)
    m->prev_member->next_member = m->next_member;
  else
    ch->members = m->next_member;
  if (m->next_member)
    m->next_member->prev_member = m->prev_member;
  free(m);
}

/* As the real one: the member's alias shadows go first and silently
 * (bounce_sync_alias_part()), zombies are found too. */
void remove_user_from_channel(struct Client *sptr, struct Channel *chptr)
{
  struct Membership *m, *next;
  int was_alias;

  for (m = chptr->members; m; m = m->next_member)
    if (m->user == sptr)
      break;
  if (!m)
    return;
  was_alias = IsMemberAlias(m) ? 1 : 0;

  if (!was_alias) {
    struct Membership *a;

    for (a = chptr->members; a; a = next) {
      next = a->next_member;
      if (IsMemberAlias(a) && cli_user(a->user)->alias_primary == sptr) {
        unlink_member(a);
        chptr->aliases--;
      }
    }
  }
  unlink_member(m);
  if (was_alias)
    chptr->aliases--;
  else
    sub1_from_channel(chptr);
}

struct Ban *make_ban(const char *banstr)
{
  struct Ban *ban = calloc(1, sizeof(*ban));

  assert_non_null(ban);
  snprintf(ban->banstr, sizeof(ban->banstr), "%s", banstr);
  return ban;
}

/* A mode buffer that holds one +L/-L, or up to three member modes.  The
 * engine's own marks (+L on a tombstone) are for the channel's local
 * members only; the one thing that may also go to servers is the status a
 * follower takes along (relocate_follow()). */
static struct {
  struct Channel *chan;
  struct Client *source;
  unsigned int dest;
  unsigned int mode;
  char arg[CHANNELLEN + 1];
  int nclients;
  unsigned int cmode[3];
  struct Client *client[3];
  int oplevel[3];
} fake_mb;

void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
                  struct Client *connect, struct Channel *chan,
                  unsigned int dest)
{
  (void)mbuf; (void)connect;
  assert_true(dest == MODEBUF_DEST_CHANNEL
              || dest == (MODEBUF_DEST_CHANNEL | MODEBUF_DEST_SERVER));
  fake_mb.chan = chan;
  fake_mb.source = source;
  fake_mb.dest = dest;
  fake_mb.mode = 0;
  fake_mb.nclients = 0;
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free_it)
{
  (void)mbuf; (void)free_it;
  assert_true(mode & MODE_REDIRECT);
  /* a tombstone's redirect never goes to a server as a MODE */
  assert_int_equal(fake_mb.dest, MODEBUF_DEST_CHANNEL);
  fake_mb.mode = mode;
  snprintf(fake_mb.arg, sizeof(fake_mb.arg), "%s", string);
}

void modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
                         struct Client *client, int oplevel)
{
  (void)mbuf;
  assert_true(fake_mb.nclients < 3);
  assert_true(mode & MODE_ADD);
  fake_mb.cmode[fake_mb.nclients] = mode;
  fake_mb.client[fake_mb.nclients] = client;
  fake_mb.oplevel[fake_mb.nclients] = oplevel;
  fake_mb.nclients++;
}

/* As the real one, in outline: ":<source> MODE <chan> +ov nick nick" to
 * the local members, "<server> M <chan> +ov <numnick> <numnick> <ts>" to
 * every server link when the buffer was opened for servers too. */
int modebuf_flush(struct ModeBuf *mbuf)
{
  struct Membership *m;
  char buf[LINE];
  (void)mbuf;

  if (fake_mb.mode) {
    if (fake_mb.mode & MODE_ADD)
      snprintf(buf, sizeof(buf), ":%s MODE %s +L %s", cli_name(fake_mb.source),
               fake_mb.chan->chname, fake_mb.arg);
    else
      snprintf(buf, sizeof(buf), ":%s MODE %s -L", cli_name(fake_mb.source),
               fake_mb.chan->chname);
    for (m = fake_mb.chan->members; m; m = m->next_member)
      if (MyConnect(m->user) && IsUser(m->user) && !IsZombie(m))
        record_sent(m->user, buf);
    fake_mb.mode = 0;
  }

  if (fake_mb.nclients) {
    char letters[8], nicks[300] = "", nums[100] = "";
    struct DLink *lp;
    int i;

    for (i = 0; i < fake_mb.nclients; i++) {
      struct Client *c = fake_mb.client[i];
      char one[100];

      letters[i] = (fake_mb.cmode[i] & MODE_CHANOP) ? 'o'
                 : (fake_mb.cmode[i] & MODE_HALFOP) ? 'h' : 'v';
      snprintf(one, sizeof(one), " %s", cli_name(c));
      strcat(nicks, one);
      if ((fake_mb.cmode[i] & MODE_CHANOP) && fake_mb.oplevel[i] < MAXOPLEVEL)
        snprintf(one, sizeof(one), " %s%s:%d", cli_yxx(cli_user(c)->server),
                 cli_yxx(c), fake_mb.oplevel[i]);
      else
        snprintf(one, sizeof(one), " %s%s", cli_yxx(cli_user(c)->server),
                 cli_yxx(c));
      strcat(nums, one);
    }
    letters[i] = '\0';

    snprintf(buf, sizeof(buf), ":%s MODE %s +%s%s", cli_name(fake_mb.source),
             fake_mb.chan->chname, letters, nicks);
    for (m = fake_mb.chan->members; m; m = m->next_member)
      if (MyConnect(m->user) && IsUser(m->user) && !IsZombie(m))
        record_sent(m->user, buf);

    if (fake_mb.dest & MODEBUF_DEST_SERVER) {
      snprintf(buf, sizeof(buf), "%s M %s +%s%s %ld", cli_yxx(fake_mb.source),
               fake_mb.chan->chname, letters, nums,
               (long)fake_mb.chan->creationtime);
      for (lp = cli_serv(&me)->down; lp; lp = lp->next)
        record_sent(lp->value.cptr, buf);
    }
    fake_mb.nclients = 0;
  }

  return 0;
}

/* --- PART through a join buffer, as m_part and relocate_follow() do ---
 *
 * joinbuf_join() tells the channel (the parting user's own connections
 * are members and hear it there; a member the channel never saw JOIN is
 * told alone); joinbuf_flush() removes the member and sends ONE line,
 * "<user> L <chan>[,<chan>] :<comment>", to every server. */

void joinbuf_init(struct JoinBuf *jbuf, struct Client *source,
                  struct Client *connect, unsigned int type, char *comment,
                  time_t create)
{
  (void)create;
  assert_int_equal(type, JOINBUF_TYPE_PART);
  assert_non_null(connect);
  memset(jbuf, 0, sizeof(*jbuf));
  jbuf->jb_source = source;
  jbuf->jb_connect = connect;
  jbuf->jb_type = type;
  jbuf->jb_comment = comment;
}

void joinbuf_join(struct JoinBuf *jbuf, struct Channel *chan,
                  unsigned int flags)
{
  char buf[LINE];

  ircd_snprintf(jbuf->jb_source, buf, sizeof(buf), "%:#C PART %s :%s",
                jbuf->jb_source, chan->chname, jbuf->jb_comment);
  if (!(flags & (CHFL_ZOMBIE | CHFL_DELAYED))) {
    struct Membership *m;

    for (m = chan->members; m; m = m->next_member)
      if (MyConnect(m->user) && IsUser(m->user) && !IsZombie(m))
        record_sent(m->user, buf);
  } else if (MyUser(jbuf->jb_source))
    record_sent(jbuf->jb_source, buf);

  assert_true(jbuf->jb_count < MAXJOINARGS);
  jbuf->jb_channels[jbuf->jb_count++] = chan;
}

int joinbuf_flush(struct JoinBuf *jbuf)
{
  char list[300] = "", buf[LINE];
  struct DLink *lp;
  unsigned int i;

  if (!jbuf->jb_count)
    return 0;
  for (i = 0; i < jbuf->jb_count; i++) {
    if (i)
      strcat(list, ",");
    strcat(list, jbuf->jb_channels[i]->chname);
    remove_user_from_channel(jbuf->jb_source, jbuf->jb_channels[i]);
  }
  jbuf->jb_count = 0;

  snprintf(buf, sizeof(buf), "%s%s L %s :%s",
           cli_yxx(cli_user(jbuf->jb_source)->server), cli_yxx(jbuf->jb_source),
           list, jbuf->jb_comment);
  for (lp = cli_serv(&me)->down; lp; lp = lp->next)
    record_sent(lp->value.cptr, buf);
  return 0;
}

/* As the real one: the hidden member is shown to the others. */
void RevealDelayedJoin(struct Membership *member)
{
  struct Membership *m;
  char buf[LINE];

  member->status &= ~CHFL_DELAYED;
  ircd_snprintf(member->user, buf, sizeof(buf), "%:#C JOIN %s", member->user,
                member->channel->chname);
  for (m = member->channel->members; m; m = m->next_member)
    if (m->user != member->user && MyConnect(m->user) && IsUser(m->user))
      record_sent(m->user, buf);
}

void bounce_sync_alias_chanmodes(struct Channel *chptr, struct Client *primary)
{
  (void)chptr; (void)primary;
  alias_syncs++;
}

void bounce_mark_dirty(struct Client *cptr)
{
  (void)cptr;
  dirty_marks++;
}

/* ====================================================================
 * Driving the handlers
 * ==================================================================== */

/** Hand ACCOUNT parameters (after the source) to the rename hook the way
 * ms_account() does.  @return what rename_services_ac() returned. */
static int account_line(struct Client *cptr, struct Client *sptr, int nparams,
                        ...)
{
  char *parv[MAXPARA + 2];
  char store[MAXPARA][256];
  va_list vl;
  int i;

  parv[0] = cli_name(sptr);
  va_start(vl, nparams);
  for (i = 0; i < nparams; i++) {
    snprintf(store[i], sizeof(store[i]), "%s", va_arg(vl, const char *));
    parv[i + 1] = store[i];
  }
  va_end(vl);
  parv[nparams + 1] = NULL;

  return rename_services_ac(cptr, sptr, nparams + 1, parv);
}

/** A local user's "RENAME <old> <new> :<reason>". */
static void client_rename(struct Client *who, const char *oldname,
                          const char *newname, const char *reason)
{
  char a[256], b[256], c[256];
  char *parv[5];

  snprintf(a, sizeof(a), "%s", oldname);
  snprintf(b, sizeof(b), "%s", newname);
  snprintf(c, sizeof(c), "%s", reason);
  parv[0] = cli_name(who);
  parv[1] = a;
  parv[2] = b;
  parv[3] = c;
  parv[4] = NULL;
  m_rename(who, who, 4, parv);
}

/** "<sptr> RN <old> <new> :<reason>" arriving on link @a cptr. */
static void server_rename(struct Client *cptr, struct Client *sptr,
                          const char *oldname, const char *newname,
                          const char *reason)
{
  char a[256], b[256], c[256];
  char *parv[5];

  snprintf(a, sizeof(a), "%s", oldname);
  snprintf(b, sizeof(b), "%s", newname);
  snprintf(c, sizeof(c), "%s", reason);
  parv[0] = cli_name(sptr);
  parv[1] = a;
  parv[2] = b;
  parv[3] = c;
  parv[4] = NULL;
  ms_rename(cptr, sptr, 4, parv);
}

/** An unregistered channel with @a op as its only member, opped. */
static struct Channel *plain_channel(const char *name, struct Client *op)
{
  struct Channel *ch = fake_channel(name);

  add_member(ch, op, CHFL_CHANOP);
  return ch;
}

/** A registered channel with @a op as its only member, opped. */
static struct Channel *registered_channel(const char *name, struct Client *op)
{
  struct Channel *ch = fake_channel(name);

  ch->mode.mode |= MODE_REGISTERED;
  add_member(ch, op, CHFL_CHANOP);
  return ch;
}

/** Pull the cookie out of a recorded "… AC <user> R <cookie> …" query. */
static const char *cookie_of(const char *query)
{
  static char cookie[64];
  const char *p = strstr(query, " R ");
  size_t len;

  assert_non_null(p);
  p += 3;
  len = strcspn(p, " ");
  assert_true(len < sizeof(cookie));
  memcpy(cookie, p, len);
  cookie[len] = '\0';
  return cookie;
}

/* ====================================================================
 * Fix 1: services arbitration across servers
 * ==================================================================== */

/* The origin: the cookie on the wire names this server. */
static void origin_sends_its_numeric_in_the_cookie(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char numeric[3];
  unsigned int n;
  char expect[LINE];
  (void)state; (void)x3;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "why");

  /* one line, toward services: down the hub's link */
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, hub);
  assert_int_equal(rename_cookie_parse(cookie_of(sent[0].text), numeric, &n),
                   RENAME_COOKIE_ROUTED);
  assert_string_equal(numeric, "AC");
  snprintf(expect, sizeof(expect), "AC AC ACAAB R AC.%u #reg RENAME #new", n);
  assert_string_equal(sent[0].text, expect);
  /* nothing has been renamed yet */
  assert_non_null(channel_named("#reg"));
  assert_null(channel_named("#new"));
}

/* A hop between the origin and services: the query goes on, unchanged,
 * with the origin as its source -- and is not an account stamp. */
static void query_is_relayed_to_a_services_server_linked_here(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(leaf, "bob", "AAC");
  (void)state;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new"), 1);

  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, x3);
  assert_string_equal(sent[0].text, "Bj AC BjAAC R Bj.17 #reg RENAME #new");
  /* the requester was not touched */
  assert_false(IsAccount(bob));
  assert_string_equal(cli_user(bob)->account, "");
  assert_int_equal(nviolations, 0);
}

/* Services further on: toward them, through the next server. */
static void query_is_relayed_toward_services_further_on(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  (void)state; (void)x3;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, hub);
  assert_string_equal(sent[0].text, "Bj AC BjAAC R Bj.17 #reg RENAME #new");
}

/* The origin may itself be remote on the link the query came in on. */
static void query_from_an_origin_two_hops_away(void **state)
{
  struct Client *mid = linked("mid.example", "Bk", "v");
  struct Client *far = behind(mid, "far.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  (void)state;

  assert_int_equal(account_line(mid, far, 6, "BjAAC", "R", "Bj.4", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, x3);
  assert_string_equal(sent[0].text, "Bj AC BjAAC R Bj.4 #reg RENAME #new");
}

/* The bare-number cookie of a server not upgraded yet is NOT passed on:
 * services' answer to it would name no server. */
static void query_with_a_bare_cookie_is_dropped(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(leaf, "bob", "AAC");
  (void)state; (void)x3;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 0);
  assert_true(ndebug > 0);
  assert_non_null(strstr(debuglines[ndebug - 1], "does not name its source"));
  /* and it is still not an account stamp */
  assert_false(IsAccount(bob));
}

/* A cookie that names a server other than the one asking would send the
 * answer to a server that never asked. */
static void query_whose_cookie_names_another_server_is_dropped(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *other = linked("other.example", "Bm", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  (void)state; (void)other; (void)x3;

  /* another server's numeric, ours, an unknown one, a malformed one */
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bm.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "AC.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Zz.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(ndebug, 4);
}

/* Never back down the link it came from: with the only services server on
 * that side there is nowhere to send it. */
static void query_is_never_sent_back_where_it_came_from(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *origin = behind(hub, "leaf.example", "Bj", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *other = linked("other.example", "Bm", "v");
  (void)state; (void)x3; (void)other;

  assert_int_equal(account_line(hub, origin, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 0);
  assert_true(ndebug > 0);              /* a debug line says why */
  assert_non_null(strstr(debuglines[ndebug - 1], "no services server"));
}

static void query_with_no_services_at_all_is_dropped(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *hub = linked("hub.example", "AB", "v");
  (void)state; (void)hub;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 0);
  assert_true(ndebug > 0);
}

/* Several services servers: every server picks the one with the lowest
 * numeric, so the relay sends where the origin meant -- wherever the
 * others are, and whichever was linked first. */
static void query_goes_to_the_services_server_every_server_picks(void **state)
{
  /* x3 first, so it is LAST in the global client list */
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *behind_leaf = behind(leaf, "stats.services", "AY", "s");
  struct Client *near = linked("near.services", "AZ", "sr");
  (void)state; (void)behind_leaf; (void)near; (void)x3;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, hub);    /* AX, not the one linked here */
}

/* ... and when that one lies back where the query came from, the two
 * servers disagree about the network: dropped, not sent elsewhere. */
static void query_is_not_diverted_to_another_services_server(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *behind_leaf = behind(leaf, "x3.services", "AX", "sr");
  struct Client *near = linked("near.services", "AZ", "sr");
  (void)state; (void)behind_leaf;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(sent_count_to(near), 0);
}

/* The origin picks by the same rule and remembers whom it asked. */
static void origin_asks_the_services_server_every_server_picks(void **state)
{
  /* x3 first, so it is LAST in the global client list */
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *near = linked("near.services", "AZ", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, hub);
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  /* the other services server may not answer for it */
  assert_int_equal(account_line(near, near, 3, reply, "A", "RENAME"), 1);
  assert_non_null(channel_named("#reg"));
  assert_int_equal(nviolations, 1);
  assert_non_null(strstr(violations[0], "near.services"));
  assert_non_null(strstr(violations[0], "different services server"));

  assert_int_equal(account_line(hub, x3, 3, reply, "A", "RENAME"), 1);
  assert_non_null(channel_named("#new"));
}

/* A new name that could not be written back as one parameter would turn
 * the query into an account stamp at the next hop. */
static void query_with_a_malformed_new_name_is_dropped(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  (void)state; (void)x3;

  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", ""), 1);
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", "#new name"), 1);
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME", ":#new"), 1);
  assert_int_equal(nsent, 0);
}

/* What is NOT a rename line is left for ms_account(). */
static void account_messages_are_left_alone(void **state)
{
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  (void)state;

  /* stamps: name, name + timestamp, name + timestamp + Keycloak id */
  assert_int_equal(account_line(leaf, leaf, 3, "BjAAC", "R", "bob"), 0);
  assert_int_equal(account_line(leaf, leaf, 4, "BjAAC", "R", "bob", "1700000000"), 0);
  assert_int_equal(account_line(leaf, leaf, 5, "BjAAC", "R", "bob", "0",
                                "ZP-D7eraToi4r24EgSYing"), 0);
  /* six parameters, RENAME where services do not look for it */
  assert_int_equal(account_line(leaf, leaf, 5, "BjAAC", "R", "Bj.17", "#reg",
                                "RENAME"), 0);
  /* services match the keyword exactly; so does the relay */
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "R", "Bj.17", "#reg",
                                "rename", "#new"), 0);
  /* other subtypes with seven parameters */
  assert_int_equal(account_line(leaf, leaf, 6, "BjAAC", "M", "Bj.17", "#reg",
                                "RENAME", "#new"), 0);
  assert_int_equal(account_line(leaf, leaf, 6, "AC", "H", ".5.6", "u@h:1.2.3.4",
                                "RENAME", "pw"), 0);
  /* logout, and the LOC replies */
  assert_int_equal(account_line(leaf, leaf, 2, "BjAAC", "U"), 0);
  assert_int_equal(account_line(x3, x3, 3, "AC", "A", ".5.6"), 0);
  assert_int_equal(account_line(x3, x3, 4, "AC", "A", ".5.6", "1700000000"), 0);
  assert_int_equal(account_line(x3, x3, 3, "AC", "D", ".5.6"), 0);
  /* a non-extended stamp for an account called R */
  assert_int_equal(account_line(leaf, leaf, 2, "BjAAC", "R"), 0);

  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 0);
}

/* --- replies --- */

/* A hop between services and the origin: toward the server the cookie
 * names, same source. */
static void reply_is_relayed_toward_the_server_in_the_cookie(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  (void)state;

  assert_int_equal(account_line(x3, x3, 3, "Bj.17", "A", "RENAME"), 1);
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, leaf);
  assert_string_equal(sent[0].text, "AX AC Bj.17 A RENAME");
}

static void denial_is_relayed_with_its_reason(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *mid = linked("mid.example", "Bk", "v");
  struct Client *far = behind(mid, "far.example", "Bj", "v");
  (void)state; (void)far;

  assert_int_equal(account_line(x3, x3, 4, "Bj.17", "D", "RENAME",
                                "You must be the channel owner to rename it."), 1);
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, mid);
  assert_string_equal(sent[0].text,
                      "AX AC Bj.17 D RENAME :You must be the channel owner to rename it.");
}

/* Services behind another server: the source is still services. */
static void reply_from_services_two_hops_away(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  (void)state;

  assert_int_equal(account_line(hub, x3, 3, "Bj.17", "A", "RENAME"), 1);
  assert_int_equal(nsent, 1);
  assert_ptr_equal(sent[0].to, leaf);
  assert_string_equal(sent[0].text, "AX AC Bj.17 A RENAME");
}

static void reply_for_an_unknown_server_is_dropped(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  (void)state;

  assert_int_equal(account_line(x3, x3, 3, "Zz.17", "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_true(ndebug > 0);
  assert_non_null(strstr(debuglines[ndebug - 1], "Zz"));
}

static void reply_is_never_sent_back_where_it_came_from(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *leaf = behind(hub, "leaf.example", "Bj", "v");
  (void)state; (void)leaf;

  assert_int_equal(account_line(hub, x3, 3, "Bj.17", "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_true(ndebug > 0);
}

static void reply_with_a_malformed_cookie_is_dropped(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  (void)state; (void)leaf;

  assert_int_equal(account_line(x3, x3, 3, "Bj.", "A", "RENAME"), 1);
  assert_int_equal(account_line(x3, x3, 3, "Bj.x", "A", "RENAME"), 1);
  assert_int_equal(account_line(x3, x3, 3, "BjAAC", "A", "RENAME"), 1);
  assert_int_equal(account_line(x3, x3, 3, "Bj.17.1", "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
}

/* Authority: only a services server's answer counts -- for forwarding as
 * much as for acting on it. */
static void reply_from_a_server_that_is_not_services_is_refused(void **state)
{
  struct Client *rogue = linked("rogue.example", "Bk", "v");
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state; (void)leaf;

  /* in transit */
  assert_int_equal(account_line(rogue, rogue, 3, "Bj.17", "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 1);
  assert_non_null(strstr(violations[0], "rogue.example"));

  /* for a request of our own */
  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  assert_ptr_equal(sent[0].to, x3);
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  assert_int_equal(account_line(rogue, rogue, 3, reply, "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(nviolations, 1);
  assert_non_null(channel_named("#reg"));       /* not renamed */
  assert_null(channel_named("#new"));

  /* ... and the real answer still works afterwards */
  assert_int_equal(account_line(x3, x3, 3, reply, "A", "RENAME"), 1);
  assert_null(channel_named("#reg"));
  assert_non_null(channel_named("#new"));
}

/* The whole round trip at the origin, services two hops away. */
static void origin_completes_on_an_approval_for_its_own_cookie(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *other = linked("other.example", "Bm", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  CapSet(cli_active_own(alice), CAP_DRAFT_CHANRENAME);
  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "rebrand");
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  assert_int_equal(account_line(hub, x3, 3, reply, "A", "RENAME"), 1);

  assert_null(channel_named("#reg"));
  assert_non_null(channel_named("#new"));
  /* the member is told, both fork links get the RN, nothing goes back to
   * services as an AC */
  assert_string_equal(sent_to(alice, 0), ":alice!user@host.example RENAME #reg #new :rebrand");
  assert_string_equal(sent_to(hub, 0), "ACAAB RN #reg #new :rebrand");
  assert_string_equal(sent_to(other, 0), "ACAAB RN #reg #new :rebrand");
  assert_int_equal(nviolations, 0);
}

static void origin_denies_with_services_reason(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  assert_int_equal(account_line(x3, x3, 4, reply, "D", "RENAME",
                                "You must be the channel owner to rename it."), 1);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_to(alice, 0),
                      "FAIL RENAME CANNOT_RENAME #reg :You must be the channel owner to rename it.");
  assert_non_null(channel_named("#reg"));
}

/* An approval answers ONE request: a second copy finds nothing. */
static void a_second_reply_for_the_same_cookie_does_nothing(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  assert_int_equal(account_line(x3, x3, 3, reply, "A", "RENAME"), 1);
  forget();

  assert_int_equal(account_line(x3, x3, 3, reply, "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_non_null(channel_named("#new"));
}

/* A bare-number reply names no server.  It is never relayed, and it
 * completes a request only when it comes from the services server that
 * request was sent to, linked to this server itself. */
static void bare_number_reply_from_the_asked_services_server_linked_here(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *leaf = linked("leaf.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char numeric[3], bare[32];
  unsigned int n;
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  assert_int_equal(rename_cookie_parse(cookie_of(sent[0].text), numeric, &n),
                   RENAME_COOKIE_ROUTED);
  forget();

  /* a number nobody here is waiting on: nothing, and nothing forwarded */
  snprintf(bare, sizeof(bare), "%u", n + 1000);
  assert_int_equal(account_line(x3, x3, 3, bare, "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_int_equal(sent_count_to(leaf), 0);
  assert_non_null(channel_named("#reg"));

  snprintf(bare, sizeof(bare), "%u", n);
  assert_int_equal(account_line(x3, x3, 3, bare, "A", "RENAME"), 1);
  assert_non_null(channel_named("#new"));
}

static void bare_number_reply_from_services_further_away_is_dropped(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char numeric[3], bare[32];
  unsigned int n;
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  assert_int_equal(rename_cookie_parse(cookie_of(sent[0].text), numeric, &n),
                   RENAME_COOKIE_ROUTED);
  forget();

  snprintf(bare, sizeof(bare), "%u", n);
  assert_int_equal(account_line(hub, x3, 3, bare, "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_non_null(channel_named("#reg"));
  assert_null(channel_named("#new"));
}

/* The cross-approval this design must not allow.  This server is
 * services' uplink and has request <n> of its own pending (alice, on
 * #victim).  A server that still sends bare cookies asks about an
 * unrelated channel under the same number -- the numbers are small
 * counters, so that is easy to arrange.  Were its query passed on,
 * services' answer "AC <n> A RENAME" would come back to this server,
 * name nobody, and be tried against this server's table: alice's rename
 * of #victim approved by an answer about somebody else's channel. */
static void a_bare_query_cannot_get_another_servers_request_approved(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *old = linked("old.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *mallory = user_on(old, "mallory", "AAC");
  char numeric[3], bare[32];
  unsigned int n;
  (void)state; (void)mallory;

  registered_channel("#victim", alice);
  client_rename(alice, "#victim", "#taken", "");
  assert_ptr_equal(sent[0].to, x3);
  assert_int_equal(rename_cookie_parse(cookie_of(sent[0].text), numeric, &n),
                   RENAME_COOKIE_ROUTED);
  forget();

  /* the old server's query, same number: it goes no further */
  snprintf(bare, sizeof(bare), "%u", n);
  assert_int_equal(account_line(old, old, 6, "BjAAC", "R", bare, "#mallorys",
                                "RENAME", "#other"), 1);
  assert_int_equal(sent_count_to(x3), 0);
  assert_int_equal(nsent, 0);

  /* so services never answer it, and #victim stays where it is until
   * services answer ALICE's question */
  assert_non_null(channel_named("#victim"));
  assert_null(channel_named("#taken"));

  /* nor can the old server supply the answer itself */
  assert_int_equal(account_line(old, old, 3, bare, "A", "RENAME"), 1);
  assert_int_equal(account_line(old, old, 3, "AC.1", "A", "RENAME"), 1);
  assert_non_null(channel_named("#victim"));
  assert_int_equal(nviolations, 2);
}

/* A second services server answering a request it was never sent. */
static void reply_from_a_services_server_that_was_not_asked_is_refused(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *other = linked("other.services", "AY", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char numeric[3], reply[64], bare[32];
  unsigned int n;
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  assert_ptr_equal(sent[0].to, x3);
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  assert_int_equal(rename_cookie_parse(reply, numeric, &n), RENAME_COOKIE_ROUTED);
  snprintf(bare, sizeof(bare), "%u", n);
  forget();

  assert_int_equal(account_line(other, other, 3, reply, "A", "RENAME"), 1);
  assert_int_equal(account_line(other, other, 3, bare, "A", "RENAME"), 1);
  assert_int_equal(account_line(other, other, 4, reply, "D", "RENAME", "no"), 1);
  assert_int_equal(nsent, 0);                   /* neither renamed nor denied */
  assert_int_equal(nviolations, 3);
  assert_non_null(channel_named("#reg"));

  /* the request is still there for the server that was asked */
  assert_int_equal(account_line(x3, x3, 3, reply, "A", "RENAME"), 1);
  assert_non_null(channel_named("#new"));
}

/* The services server leaves: its requests fail at once instead of
 * waiting out the timer. */
static void services_leaving_fails_the_requests_sent_to_them(void **state)
{
  struct Client *hub = linked("hub.example", "AB", "v");
  struct Client *x3 = behind(hub, "x3.services", "AX", "sr");
  struct Client *other = linked("other.example", "Bm", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  /* some other server going does not concern the request */
  pending_rename_server_exit(other);
  assert_int_equal(nsent, 0);
  assert_int_equal(ntimers, 1);

  pending_rename_server_exit(x3);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_to(alice, 0),
                      "FAIL RENAME TEMPORARILY_UNAVAILABLE #reg :Registration service is not available");
  assert_int_equal(ntimers, 0);
  forget();

  /* an answer that was already on its way finds nothing */
  assert_int_equal(account_line(hub, x3, 3, reply, "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_non_null(channel_named("#reg"));
}

/* No answer: the origin's own timeout tells the user. */
static void origin_times_out_without_an_answer(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#new", "");
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  expire_all_timers();
  assert_string_equal(sent_to(alice, 0),
                      "FAIL RENAME CANNOT_RENAME #reg :Services response timeout");
  forget();

  /* a late approval finds nothing */
  assert_int_equal(account_line(x3, x3, 3, reply, "A", "RENAME"), 1);
  assert_int_equal(nsent, 0);
  assert_non_null(channel_named("#reg"));
}

/* ====================================================================
 * Fix 2: local channels and the new name's validity
 * ==================================================================== */

/** Expect a local user's RENAME to be refused with exactly @a text, and
 * nothing to have left this server. */
static void expect_refused(struct Client *who, struct Client *peer,
                           const char *oldname, const char *newname,
                           const char *text)
{
  char expect[LINE];

  forget();
  client_rename(who, oldname, newname, "x");
  snprintf(expect, sizeof(expect), "FAIL RENAME CANNOT_RENAME %s :%s",
           oldname, text);
  assert_int_equal(nsent, 1);
  assert_string_equal(sent_to(who, 0), expect);
  assert_int_equal(sent_count_to(peer), 0);
  assert_non_null(channel_named(oldname));
}

static void client_cannot_rename_a_local_channel(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("&ops", alice);
  expect_refused(alice, peer, "&ops", "#leak", "Local channels cannot be renamed");
  expect_refused(alice, peer, "&ops", "&staff", "Local channels cannot be renamed");
  assert_null(channel_named("#leak"));
  assert_null(channel_named("&staff"));
}

static void client_cannot_rename_to_a_local_name(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("#chan", alice);
  expect_refused(alice, peer, "#chan", "&chan",
                 "A channel cannot be renamed to a local channel name");
  assert_null(channel_named("&chan"));
}

static void client_new_name_must_be_one_join_would_take(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  const char *badchars = "New channel name contains a character that is "
                         "not allowed in channel names";
  char longname[CHANNELLEN + 3];
  (void)state;

  plain_channel("#a", alice);

  expect_refused(alice, peer, "#a", "#a,b", badchars);
  expect_refused(alice, peer, "#a", "#a\007", badchars);
  expect_refused(alice, peer, "#a", "#a\001b", badchars);
  expect_refused(alice, peer, "#a", "#a\xa0" "b", badchars);
  expect_refused(alice, peer, "#a", "nochan", "Invalid channel name");

  /* the compile-time cap */
  memset(longname, 'x', sizeof(longname));
  longname[0] = '#';
  longname[CHANNELLEN + 1] = '\0';
  expect_refused(alice, peer, "#a", longname, "New channel name is too long");

  /* the configured cap, as do_join() applies it to a new name */
  feat_channellen = 8;
  expect_refused(alice, peer, "#a", "#12345678", "New channel name is too long");
  forget();
  client_rename(alice, "#a", "#1234567", "x");
  assert_non_null(channel_named("#1234567"));
  assert_string_equal(sent_to(peer, 0), "ACAAB RN #a #1234567 :x");
}

static void client_utf8_only_feature_is_honoured(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("#a", alice);

  feat_utf8_only = 1;
  expect_refused(alice, peer, "#a", "#\xe9t\xe9", "New channel name is not valid UTF-8");

  feat_utf8_only = 0;
  forget();
  client_rename(alice, "#a", "#\xe9t\xe9", "x");
  assert_non_null(channel_named("#\xe9t\xe9"));
}

/* For a registered channel the names are judged before services are
 * asked. */
static void client_bad_name_never_reaches_services(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  registered_channel("#reg", alice);
  expect_refused(alice, x3, "#reg", "#reg,b",
                 "New channel name contains a character that is not allowed "
                 "in channel names");
  expect_refused(alice, x3, "#reg", "&reg",
                 "A channel cannot be renamed to a local channel name");
  assert_int_equal(ntimers, 0);         /* no request was left pending */
}

/* The limit can change while services think about it. */
static void approval_does_not_carry_a_name_past_a_lowered_cap(void **state)
{
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char reply[64];
  (void)state;

  registered_channel("#reg", alice);
  client_rename(alice, "#reg", "#a-rather-long-name", "");
  snprintf(reply, sizeof(reply), "%s", cookie_of(sent[0].text));
  forget();

  feat_channellen = 10;                 /* REHASH */
  assert_int_equal(account_line(x3, x3, 3, reply, "A", "RENAME"), 1);

  assert_int_equal(nsent, 1);
  assert_string_equal(sent_to(alice, 0),
                      "FAIL RENAME CANNOT_RENAME #reg :New channel name is too long");
  assert_non_null(channel_named("#reg"));
  assert_null(channel_named("#a-rather-long-name"));
  assert_int_equal(sent_count_to(x3), 0);
}

/* From a peer: a local channel on either side is a protocol violation,
 * not applied and not relayed. */
static void server_rename_naming_a_local_channel_is_a_violation(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  /* our own, unrelated &ops */
  plain_channel("&ops", alice);
  plain_channel("#chan", alice);

  server_rename(peer, bob, "&ops", "#leak", "x");
  assert_int_equal(nviolations, 1);
  assert_non_null(strstr(violations[0], "&ops"));
  assert_non_null(channel_named("&ops"));
  assert_null(channel_named("#leak"));

  server_rename(peer, bob, "#chan", "&chan", "x");
  assert_int_equal(nviolations, 2);
  assert_non_null(channel_named("#chan"));
  assert_null(channel_named("&chan"));

  /* nobody was told anything: no member, no other server, no services */
  assert_int_equal(nsent, 0);
  assert_int_equal(sent_count_to(down) + sent_count_to(x3), 0);
  assert_int_equal(nopnotices, 0);
}

/* From a peer: a new name that would corrupt later messages. */
static void server_rename_to_an_unusable_name_is_a_violation(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char longname[CHANNELLEN + 3];
  (void)state;

  plain_channel("#chan", alice);

  server_rename(peer, bob, "#chan", "#chan,b", "x");
  server_rename(peer, bob, "#chan", "#chan\007", "x");
  server_rename(peer, bob, "#chan", "#chan\xa0", "x");
  server_rename(peer, bob, "#chan", "chan", "x");
  server_rename(peer, bob, "chan", "#chan2", "x");
  memset(longname, 'x', sizeof(longname));
  longname[0] = '#';
  longname[CHANNELLEN + 1] = '\0';
  server_rename(peer, bob, "#chan", longname, "x");

  assert_int_equal(nviolations, 6);
  assert_int_equal(nsent, 0);
  assert_int_equal(sent_count_to(down), 0);
  assert_non_null(channel_named("#chan"));
}

/* From a peer: this server's own naming policy is not the peer's. */
static void server_rename_is_not_held_to_local_policy(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("#chan", alice);
  feat_channellen = 8;
  feat_utf8_only = 1;

  server_rename(peer, bob, "#chan", "#longer-than-eight-\xe9", "x");
  assert_int_equal(nviolations, 0);
  assert_null(channel_named("#chan"));
  assert_non_null(channel_named("#longer-than-eight-\xe9"));
  assert_string_equal(sent_to(down, 0), "BjAAC RN #chan #longer-than-eight-\xe9 :x");
  assert_int_equal(sent_count_to(peer), 0);
}

/* From a peer: a badly named OLD channel can be renamed away. */
static void server_rename_away_from_a_bad_name_is_applied(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("#a,b", alice);
  server_rename(peer, bob, "#a,b", "#ab", "repair");
  assert_int_equal(nviolations, 0);
  assert_non_null(channel_named("#ab"));
}

/* ====================================================================
 * Fix 3: an RN this server cannot apply is still relayed
 * ==================================================================== */

/* What a rename that DOES apply sends, for the cases below to match. */
static void server_rename_applied_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  CapSet(cli_active_own(alice), CAP_DRAFT_CHANRENAME);
  plain_channel("#old", alice);

  server_rename(peer, bob, "#old", "#new", "moving");

  assert_null(channel_named("#old"));
  assert_non_null(channel_named("#new"));
  assert_string_equal(sent_to(alice, 0), ":bob!user@host.example RENAME #old #new :moving");
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new :moving");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new :moving");
  assert_int_equal(sent_count_to(peer), 0);     /* not back where it came from */
  assert_int_equal(nopnotices, 0);
}

/* The channel is not here under the old name (it emptied here, or was
 * renamed here by a crossing RN): local state untouched, operators told,
 * and the line goes on exactly as above. */
static void server_rename_of_a_channel_not_here_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *legacy_like = linked("plain.example", "Bn", "");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("#unrelated", alice);

  server_rename(peer, bob, "#old", "#new", "moving");

  assert_null(channel_named("#old"));
  assert_null(channel_named("#new"));
  assert_non_null(channel_named("#unrelated"));
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new :moving");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new :moving");
  assert_int_equal(sent_count_to(down), 1);
  assert_int_equal(sent_count_to(x3), 1);
  assert_int_equal(sent_count_to(peer), 0);
  assert_int_equal(sent_count_to(legacy_like), 0);      /* neither v3 nor 'r' */
  assert_int_equal(sent_count_to(alice), 0);
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "#old"));
  assert_non_null(strstr(opnotices[0], "#new"));
  assert_non_null(strstr(opnotices[0], "does not exist"));
  assert_non_null(strstr(opnotices[0], "relayed"));
  assert_int_equal(nviolations, 0);
}

/* The new name is taken here (somebody created it while the rename was
 * on its way): both channels stay as they are, and the line goes on. */
static void server_rename_onto_a_name_taken_here_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  CapSet(cli_active_own(alice), CAP_DRAFT_CHANRENAME);
  oldch = plain_channel("#old", alice);
  newch = plain_channel("#new", carol);

  server_rename(peer, bob, "#old", "#new", "moving");

  /* the very same two channels, the same members */
  assert_ptr_equal(channel_named("#old"), oldch);
  assert_ptr_equal(channel_named("#new"), newch);
  assert_ptr_equal(oldch->members->user, alice);
  assert_ptr_equal(newch->members->user, carol);
  assert_int_equal(sent_count_to(alice), 0);
  assert_int_equal(sent_count_to(carol), 0);

  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new :moving");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new :moving");
  assert_int_equal(sent_count_to(peer), 0);
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "#old"));
  assert_non_null(strstr(opnotices[0], "#new"));
  assert_non_null(strstr(opnotices[0], "already exists"));
  assert_non_null(strstr(opnotices[0], "divergent"));
}

/* Two renames of one channel that cross: this server renamed #x to #a,
 * the peer renamed it to #b.  The peer's RN finds no #x here. */
static void crossing_renames_are_both_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  add_member(plain_channel("#x", alice), bob, CHFL_CHANOP);

  client_rename(alice, "#x", "#a", "mine");
  assert_string_equal(sent_to(peer, 0), "ACAAB RN #x #a :mine");
  assert_string_equal(sent_to(down, 0), "ACAAB RN #x #a :mine");
  forget();

  server_rename(peer, bob, "#x", "#b", "theirs");
  assert_non_null(channel_named("#a"));
  assert_null(channel_named("#b"));
  /* the server behind this one hears of both */
  assert_string_equal(sent_to(down, 0), "BjAAC RN #x #b :theirs");
  assert_int_equal(sent_count_to(peer), 0);
  assert_int_equal(nopnotices, 1);
}

/* A case-only rename names one channel twice here. */
static void server_rename_to_the_same_channel_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  plain_channel("#Chan", alice);
  server_rename(peer, bob, "#chan", "#CHAN", "case");
  assert_non_null(channel_named("#Chan"));
  assert_string_equal(sent_to(down, 0), "BjAAC RN #chan #CHAN :case");
  assert_int_equal(nopnotices, 1);
}

/* The source rewrite for a bouncer alias still happens on the relay of a
 * rename that was not applied: a rename-capable non-v3 peer (X3) was
 * never told about the alias, so it gets the primary as the source. */
static void unapplied_rename_from_an_alias_reaches_x3_as_its_primary(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *primary = user_on(peer, "bob", "AAC");
  struct Client *alias = user_on(peer, "bob", "AAE");
  (void)state;

  SetBouncerAlias(alias);
  cli_user(alias)->alias_primary = primary;

  server_rename(peer, alias, "#old", "#new", "moving");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new :moving");
  assert_int_equal(nopnotices, 1);
}

/* ====================================================================
 * Fix 4: the PART/JOIN fallback's JOIN for an extended-join member
 * ==================================================================== */

static void login(struct Client *who, const char *account)
{
  ircd_strncpy(cli_user(who)->account, account, sizeof(cli_user(who)->account));
  SetAccount(who);
}

/* Four local members, each told in the form its own connection asked
 * for. */
static void fallback_join_has_the_form_the_member_negotiated(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *plain = user_on(&me, "plain", "AAB");
  struct Client *ext = user_on(&me, "ext", "AAD");
  struct Client *extanon = user_on(&me, "extanon", "AAE");
  struct Client *capable = user_on(&me, "capable", "AAF");
  struct Channel *ch;
  (void)state;

  login(plain, "plainacct");
  login(ext, "extacct");
  CapSet(cli_active_own(ext), CAP_EXTJOIN);
  CapSet(cli_active_own(extanon), CAP_EXTJOIN);
  login(capable, "capacct");
  CapSet(cli_active_own(capable), CAP_EXTJOIN);
  CapSet(cli_active_own(capable), CAP_DRAFT_CHANRENAME);

  ch = plain_channel("#old", plain);
  add_member(ch, ext, 0);
  add_member(ch, extanon, 0);
  add_member(ch, capable, 0);
  add_member(ch, bob, CHFL_CHANOP);

  server_rename(peer, bob, "#old", "#new", "why");

  /* no extended-join: the bare JOIN, as before */
  assert_string_equal(sent_to(plain, 0),
                      ":plain!user@host.example PART #old :Channel renamed to #new: why");
  assert_string_equal(sent_to(plain, 1), ":plain!user@host.example JOIN #new");
  assert_string_equal(sent_to(plain, 2), "(names of #new)");

  /* extended-join, logged in: account and realname */
  assert_string_equal(sent_to(ext, 0),
                      ":ext!user@host.example PART #old :Channel renamed to #new: why");
  assert_string_equal(sent_to(ext, 1),
                      ":ext!user@host.example JOIN #new extacct :Real Name");
  assert_string_equal(sent_to(ext, 2), "(names of #new)");

  /* extended-join, not logged in: "*" for the account */
  assert_string_equal(sent_to(extanon, 1),
                      ":extanon!user@host.example JOIN #new * :Real Name");

  /* draft/channel-rename: the RENAME and nothing else */
  assert_int_equal(sent_count_to(capable), 1);
  assert_string_equal(sent_to(capable, 0),
                      ":bob!user@host.example RENAME #old #new :why");
}

/* A bouncer alias has its own connection and its own caps; its shadow
 * membership is walked like any member, and the form follows the alias
 * connection, not the primary's. */
static void fallback_join_follows_each_bouncer_connection(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *primary = user_on(&me, "dana", "AAB");
  struct Client *alias = user_on(&me, "dana", "AAD");
  struct Channel *ch;
  (void)state;

  login(primary, "dana");
  login(alias, "dana");
  SetBouncerAlias(alias);
  cli_user(alias)->alias_primary = primary;
  CapSet(cli_active_own(alias), CAP_EXTJOIN);   /* the alias only */

  ch = plain_channel("#old", primary);
  add_member(ch, alias, CHFL_ALIAS);
  add_member(ch, bob, CHFL_CHANOP);

  server_rename(peer, bob, "#old", "#new", "");

  assert_string_equal(sent_to(primary, 1), ":dana!user@host.example JOIN #new");
  assert_string_equal(sent_to(alias, 1),
                      ":dana!user@host.example JOIN #new dana :Real Name");
}

/* ====================================================================
 * Relocation mode (evilnet/channel-relocate)
 * ==================================================================== */

/** "<sptr> RN <old> <new> C [<expires>] :<reason>" arriving on link
 * @a cptr; @a expires NULL for the five-parameter form of a server from
 * before the expiry travelled. */
static void server_relocate(struct Client *cptr, struct Client *sptr,
                            const char *oldname, const char *newname,
                            const char *expires, const char *reason)
{
  char store[5][256];
  char *parv[7];
  int n = 0;

  parv[n++] = cli_name(sptr);
  snprintf(store[0], sizeof(store[0]), "%s", oldname);
  parv[n++] = store[0];
  snprintf(store[1], sizeof(store[1]), "%s", newname);
  parv[n++] = store[1];
  snprintf(store[2], sizeof(store[2]), "C");
  parv[n++] = store[2];
  if (expires) {
    snprintf(store[3], sizeof(store[3]), "%s", expires);
    parv[n++] = store[3];
  }
  snprintf(store[4], sizeof(store[4]), "%s", reason);
  parv[n++] = store[4];
  parv[n] = NULL;
  ms_rename(cptr, sptr, n, parv);
}

/** A channel created at @a ts with @a op as its only member, opped. */
static struct Channel *channel_at(const char *name, time_t ts,
                                  struct Client *op)
{
  struct Channel *ch = plain_channel(name, op);

  ch->creationtime = ts;
  return ch;
}

static struct Membership *member_of(struct Channel *ch, struct Client *who)
{
  struct Membership *m;
  for (m = ch->members; m; m = m->next_member)
    if (m->user == who)
      return m;
  return NULL;
}

/* --- Status preservation: live status, then part (no snapshots) --- */

#define STATUS (CHFL_CHANOP | CHFL_HALFOP | CHFL_VOICE)

/** A successful JOIN of an existing channel as do_join() carries it out:
 * joinbuf_join() adds the member (deopped; hidden on a +D channel) and
 * sends the J to every server at once, and then -- for a local user only
 * -- comes relocate_follow().  @a conn is the connection the JOIN came
 * from (the user's own, or one of its bouncer devices).
 * @return The status the user has in the channel afterwards. */
static unsigned int joins_from(struct Client *conn, struct Client *who,
                               struct Channel *ch)
{
  struct Membership *m;
  struct DLink *lp;
  char buf[LINE];

  m = add_member(ch, who, CHFL_DEOPPED
                 | ((ch->mode.mode & MODE_DELJOINS) ? CHFL_DELAYED : 0));
  snprintf(buf, sizeof(buf), "%s%s J %s %ld", cli_yxx(cli_user(who)->server),
           cli_yxx(who), ch->chname, (long)ch->creationtime);
  for (lp = cli_serv(&me)->down; lp; lp = lp->next)
    record_sent(lp->value.cptr, buf);

  if (MyUser(who))
    relocate_follow(conn, who, ch);

  return m->status & STATUS;
}

static unsigned int joins(struct Client *who, struct Channel *ch)
{
  return joins_from(who, who, ch);
}

/* A member who stayed follows: it gets, in the new channel, the status it
 * holds in the tombstone NOW, and is parted from the tombstone -- for its
 * own client, for the members who stay, and for every server.  JOIN, then
 * MODE, then PART. */
static void follower_takes_its_current_status_and_leaves_the_tombstone(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  add_member(oldch, carol, CHFL_VOICE);
  client_rename(alice, "#old", "#new", "moving");
  newch = channel_named("#new");
  forget();

  assert_int_equal(joins(bob, newch), CHFL_CHANOP);

  /* the membership moved */
  assert_false(member_of(newch, bob)->status & CHFL_DEOPPED);
  assert_null(member_of(oldch, bob));
  assert_int_equal(oldch->users, 1);
  /* every server: the JOIN, the status, the PART -- in that order, and
   * nothing else */
  assert_int_equal(sent_count_to(peer), 3);
  assert_string_equal(sent_to(peer, 0), "ACAAC J #new 500000");
  assert_string_equal(sent_to(peer, 1), "AC M #new +o ACAAC 500000");
  assert_string_equal(sent_to(peer, 2), "ACAAC L #old :Channel has moved to #new");
  assert_string_equal(sent_to(x3, 2), "ACAAC L #old :Channel has moved to #new");
  /* its own client: the MODE in the new channel, the PART of the old */
  assert_string_equal(sent_to(bob, 0), ":me.example MODE #new +o bob");
  assert_string_equal(sent_to(bob, 1),
                      ":bob!user@host.example PART #old :Channel has moved to #new");
  assert_int_equal(sent_count_to(bob), 2);
  /* the member who stays sees it go; the one in the new channel sees the op */
  assert_string_equal(sent_to(carol, 0),
                      ":bob!user@host.example PART #old :Channel has moved to #new");
  assert_string_equal(sent_to(alice, 0), ":me.example MODE #new +o bob");
  /* the bouncer hooks every member-mode grant calls */
  assert_int_equal(alias_syncs, 1);
  assert_true(dirty_marks >= 1);
  /* the tombstone itself is untouched */
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(ntimers, 1);

  /* voice likewise, and an unprivileged member takes nothing but leaves */
  forget();
  assert_int_equal(joins(carol, newch), CHFL_VOICE);
  assert_string_equal(sent_to(peer, 1), "AC M #new +v ACAAD 500000");
  assert_null(member_of(oldch, carol));
}

/* The status is the one held when following, not the one held when the
 * channel was relocated: deopped in the tombstone since, the member
 * follows without ops -- and still leaves the tombstone. */
static void deopped_in_the_tombstone_follows_without_ops(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");

  member_of(oldch, bob)->status &= ~CHFL_CHANOP;        /* M #old -o bob */
  forget();
  assert_int_equal(joins(bob, newch), 0);

  assert_null(member_of(oldch, bob));
  assert_int_equal(sent_count_to(peer), 2);             /* J and L: no MODE */
  assert_string_equal(sent_to(peer, 1), "ACAAC L #old :Channel has moved to #new");
  assert_int_equal(sent_count_to(alice), 0);
}

/* ... and opped in the tombstone since, with ops. */
static void opped_in_the_tombstone_since_follows_with_ops(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, 0);
  client_rename(alice, "#old", "#new", "");
  member_of(oldch, bob)->status |= CHFL_CHANOP | CHFL_VOICE;
  assert_int_equal(joins(bob, channel_named("#new")), CHFL_CHANOP | CHFL_VOICE);
}

/* Kicked from the tombstone (or parted from it): not a member, nothing to
 * take -- an ordinary JOIN.  The same for a zombie, a member that was
 * kicked but has not been removed yet. */
static void not_in_the_tombstone_any_more_gets_nothing(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  add_member(oldch, carol, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");

  remove_user_from_channel(bob, oldch);                 /* KICK #old bob */
  member_of(oldch, carol)->status |= CHFL_ZOMBIE;
  forget();

  assert_int_equal(joins(bob, newch), 0);
  assert_int_equal(joins(carol, newch), 0);
  assert_int_equal(sent_count_to(peer), 2);             /* the two J */
  assert_int_equal(sent_count_to(bob), 0);
  assert_non_null(member_of(oldch, carol));             /* the zombie stays */
}

/* Used once.  The follower is deopped in the new channel, parts and joins
 * again: nothing -- it is not in the tombstone, and no server holds a
 * copy of anything.  The same when it comes back through another server. */
static void status_is_carried_over_once(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *bob_elsewhere;
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  login(bob, "bobacct");
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");

  assert_int_equal(joins(bob, newch), CHFL_CHANOP);
  member_of(newch, bob)->status &= ~CHFL_CHANOP;        /* M #new -o bob */
  remove_user_from_channel(bob, newch);                 /* PART #new */
  forget();
  assert_int_equal(joins(bob, newch), 0);
  assert_int_equal(sent_count_to(peer), 1);             /* the J alone */

  /* reconnected through the peer, same account, same nick and host: its
   * JOIN arrives as a remote JOIN and this server gives it nothing */
  remove_user_from_channel(bob, newch);
  bob_elsewhere = user_on(peer, "bob", "AAF");
  login(bob_elsewhere, "bobacct");
  forget();
  assert_int_equal(joins(bob_elsewhere, newch), 0);
  assert_int_equal(sent_count_to(alice), 0);
  assert_null(member_of(oldch, bob_elsewhere));
}

/* Never in the old channel: an ordinary JOIN. */
static void never_a_member_gets_nothing(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *eve = user_on(&me, "eve", "AAE");
  (void)state;

  feat_rename_consent = 1;
  add_member(channel_at("#old", 500000, alice), bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  forget();

  assert_int_equal(joins(eve, channel_named("#new")), 0);
  assert_int_equal(sent_count_to(peer), 1);
  assert_int_equal(sent_count_to(eve), 0);
}

/* The issuer was moved by the relocation and is not in the tombstone:
 * deopped in the new channel, a PART and a JOIN give it nothing. */
static void issuer_has_nothing_to_take(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *newch;
  (void)state;

  feat_rename_consent = 1;
  add_member(channel_at("#old", 500000, alice), bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  assert_true(member_of(newch, alice)->status & CHFL_CHANOP);

  add_member(newch, bob, 0);                    /* somebody keeps it alive */
  remove_user_from_channel(alice, newch);
  assert_int_equal(joins(alice, newch), 0);
}

/* Somebody who is ALREADY in the new channel and also still in the
 * tombstone (it got into the new channel some other way).  do_join()
 * ignores its JOIN of the new channel before anything here runs, so
 * nothing moves; it is swept from the tombstone at the deadline.  When it
 * parts the new channel and really joins it, it follows like anybody. */
static void already_in_the_new_channel(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  add_member(newch, bob, 0);                    /* e.g. SVSJOIN */
  forget();

  /* "JOIN #new": find_member_link() says already on channel; do_join()
   * returns.  Nothing was called, nothing changed. */
  assert_non_null(member_of(oldch, bob));
  assert_false(member_of(newch, bob)->status & CHFL_CHANOP);

  remove_user_from_channel(bob, newch);         /* PART #new */
  assert_int_equal(joins(bob, newch), CHFL_CHANOP);
  assert_null(member_of(oldch, bob));
}

/* What the JOIN itself gave is kept, and only what is missing is added. */
static void follower_is_never_given_less_than_the_join_gave(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP | CHFL_VOICE);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  forget();

  /* the JOIN opped it (a channel key that does) */
  add_member(newch, bob, CHFL_CHANOP);
  relocate_follow(bob, bob, newch);

  assert_int_equal(member_of(newch, bob)->status & STATUS,
                   CHFL_CHANOP | CHFL_VOICE);
  assert_string_equal(sent_to(peer, 0), "AC M #new +v ACAAC 500000");
  assert_null(member_of(oldch, bob));
}

/* A channel with oplevels (+A): the oplevel the member holds in the
 * tombstone goes with the op, on the wire as "<numnick>:<level>". */
static void follower_takes_its_oplevel(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  SetOpLevel(add_member(oldch, bob, CHFL_CHANOP), 3);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  forget();

  assert_int_equal(joins(bob, newch), CHFL_CHANOP);
  assert_int_equal(OpLevel(member_of(newch, bob)), 3);
  assert_string_equal(sent_to(peer, 1), "AC M #new +o ACAAC:3 500000");
}

/* The new channel emptied and a stranger made it again: it is not the
 * channel the relocation made (another creation timestamp).  A member of
 * the tombstone who joins it takes nothing into the stranger's channel
 * and stays in the tombstone. */
static void nothing_follows_into_a_recreated_channel(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch, *again;
  char name[] = "#new";
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "moving");

  newch = channel_named("#new");
  remove_user_from_channel(alice, newch);
  assert_true(was_destroyed(newch));

  again = get_channel(carol, name, CGT_CREATE);
  assert_int_equal(again->creationtime, CurrentTime);
  add_member(again, carol, CHFL_CHANOP);
  forget();

  assert_int_equal(joins(bob, again), 0);
  assert_non_null(member_of(oldch, bob));
  assert_true(member_of(oldch, bob)->status & CHFL_CHANOP);
  assert_int_equal(sent_count_to(carol), 0);
}

/* A chain: #a -> #b -> #c.  Both tombstones point at #c.  A member of #a
 * who joins #c moves from #a; one who is in BOTH old channels leaves both
 * with one PART and takes the union of what it holds in them. */
static void follower_through_a_chain(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *a, *b, *c;
  (void)state;

  feat_rename_consent = 1;
  a = channel_at("#a", 500000, alice);
  add_member(a, bob, CHFL_CHANOP);
  add_member(a, carol, CHFL_VOICE);
  client_rename(alice, "#a", "#b", "one");
  b = channel_named("#b");
  assert_int_equal(joins(carol, b), CHFL_VOICE);        /* carol follows once */
  add_member(a, carol, CHFL_VOICE);                     /* (and rejoins #a) */
  member_of(b, carol)->status |= CHFL_HALFOP;
  client_rename(alice, "#b", "#c", "two");
  c = channel_named("#c");
  assert_string_equal(a->mode.redir, "#c");
  assert_string_equal(b->mode.redir, "#c");
  forget();

  /* bob: in #a only */
  assert_int_equal(joins(bob, c), CHFL_CHANOP);
  assert_null(member_of(a, bob));
  assert_string_equal(sent_to(peer, 2), "ACAAC L #a :Channel has moved to #c");

  /* carol: voice in #a, voice and halfop in #b */
  forget();
  assert_int_equal(joins(carol, c), CHFL_VOICE | CHFL_HALFOP);
  assert_null(member_of(a, carol));
  assert_null(member_of(b, carol));
  assert_int_equal(sent_count_to(peer), 3);
  assert_string_equal(sent_to(peer, 1), "AC M #c +hv ACAAD ACAAD 500000");
  assert_string_equal(sent_to(peer, 2), "ACAAD L #b,#a :Channel has moved to #c");
}

/* A tombstone that is not one any more -- a chanop took +L off -- moves
 * nobody: its member joins the new channel like anybody else. */
static void cancelled_tombstone_moves_nobody(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  oldch->mode.redir[0] = '\0';                          /* MODE #old -L */

  assert_int_equal(joins(bob, channel_named("#new")), 0);
  assert_non_null(member_of(oldch, bob));
}

/* Delayed join.  The new channel is +D: a follower with status is shown
 * to the channel before it is opped; one without stays hidden.  And a
 * member the TOMBSTONE never saw join is not announced leaving it -- only
 * its own connection is told. */
static void follower_and_delayed_join(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  oldch->mode.mode |= MODE_DELJOINS;
  add_member(oldch, bob, CHFL_CHANOP);
  add_member(oldch, carol, CHFL_DELAYED);       /* hidden in #old */
  add_member(oldch, dan, 0);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  assert_true(newch->mode.mode & MODE_DELJOINS);
  forget();

  /* with status: revealed, then opped */
  assert_int_equal(joins(bob, newch), CHFL_CHANOP);
  assert_false(member_of(newch, bob)->status & CHFL_DELAYED);
  assert_string_equal(sent_to(alice, 0), ":bob!user@host.example JOIN #new");
  assert_string_equal(sent_to(alice, 1), ":me.example MODE #new +o bob");

  /* without: hidden in the new channel too; and its PART of the old
   * channel, where it was hidden, goes to itself alone */
  forget();
  assert_int_equal(joins(carol, newch), 0);
  assert_true(member_of(newch, carol)->status & CHFL_DELAYED);
  assert_null(member_of(oldch, carol));
  assert_int_equal(sent_count_to(alice), 0);
  assert_int_equal(sent_count_to(dan), 0);
  assert_string_equal(sent_to(carol, 0),
                      ":carol!user@host.example PART #old :Channel has moved to #new");
  /* the network is told all the same */
  assert_string_equal(sent_to(peer, 1), "ACAAD L #old :Channel has moved to #new");
}

/* A bouncer session.  The membership is the primary's; its devices hold
 * shadows of it.  A JOIN from a device is the primary's JOIN (m_join()
 * rewrites the source): the primary takes the status and is parted, both
 * connections hear the PART, and the shadow goes with the membership. */
static void follower_with_a_bouncer_device(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *primary = user_on(&me, "dana", "AAC");
  struct Client *device = user_on(&me, "dana", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  SetBouncerAlias(device);
  cli_user(device)->alias_primary = primary;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, primary, CHFL_CHANOP);
  add_member(oldch, device, CHFL_ALIAS | CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  forget();

  /* "JOIN #new" typed on the device */
  assert_int_equal(joins_from(device, primary, newch), CHFL_CHANOP);

  assert_null(member_of(oldch, primary));
  assert_null(member_of(oldch, device));
  assert_int_equal(oldch->aliases, 0);
  assert_string_equal(sent_to(peer, 2), "ACAAC L #old :Channel has moved to #new");
  assert_string_equal(sent_to(primary, sent_count_to(primary) - 1),
                      ":dana!user@host.example PART #old :Channel has moved to #new");
  assert_string_equal(sent_to(device, sent_count_to(device) - 1),
                      ":dana!user@host.example PART #old :Channel has moved to #new");
  assert_int_equal(alias_syncs, 1);
}

/* A device whose primary is on ANOTHER server: the JOIN is the remote
 * primary's, this server is not its server, and nothing is done here --
 * the session stays in the tombstone until the deadline. */
static void device_of_a_remote_primary_does_not_follow_here(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *primary = user_on(peer, "dana", "AAC");
  struct Client *device = user_on(&me, "dana", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  SetBouncerAlias(device);
  cli_user(device)->alias_primary = primary;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, primary, CHFL_CHANOP);
  add_member(oldch, device, CHFL_ALIAS | CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");
  forget();

  assert_int_equal(joins_from(device, primary, newch), 0);
  /* do_join() does not even call it for a user that is not local; called
   * all the same, it does nothing */
  relocate_follow(device, primary, newch);
  assert_int_equal(member_of(newch, primary)->status & STATUS, 0);
  assert_non_null(member_of(oldch, primary));
  assert_non_null(member_of(oldch, device));
  assert_int_equal(sent_count_to(peer), 1);             /* the J */
}

/* A remote user's follow reaches this server as three ordinary lines from
 * its own server -- J, M, L -- and this server adds nothing of its own to
 * any of them. */
static void remote_follower_is_just_applied(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAE");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  newch = channel_named("#new");
  forget();

  /* BjAAE J #new 500000 */
  assert_int_equal(joins(eve, newch), 0);
  relocate_follow(eve, eve, newch);             /* not even if it were called */
  assert_int_equal(member_of(newch, eve)->status & STATUS, 0);
  /* nothing but the relayed J went anywhere (the fake sends it to every
   * link); eve is in both channels until her server's M and L arrive */
  assert_int_equal(sent_count_to(down), 1);
  assert_int_equal(sent_count_to(carol), 0);
  assert_non_null(member_of(oldch, eve));
  assert_int_equal(alias_syncs, 0);
}

/* --- C.1: a dissolved tombstone is never left +z --- */

/* The engine's own +z goes with the tombstone (as before). */
static void dissolve_clears_the_persist_flag_it_set(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, 0);
  client_rename(alice, "#old", "#new", "moving");
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  forget();

  advance(900);
  assert_string_equal(sent_to(bob, 0),
                      ":bob!user@host.example PART #old :Channel has moved to #new");
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
}

/* A channel that was +z before it was relocated (a registered channel
 * under services' persist) is not left behind as an empty, unregistered
 * +z channel: the registration went with the relocation. */
static void dissolve_clears_a_persist_flag_that_was_there_before(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  oldch->mode.exmode |= EXMODE_PERSIST;
  add_member(oldch, bob, 0);
  client_rename(alice, "#old", "#new", "moving");
  /* the new channel keeps what the old one had */
  assert_true(channel_named("#new")->mode.exmode & EXMODE_PERSIST);

  advance(900);
  assert_false(oldch->mode.exmode & EXMODE_PERSIST);
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
}

/* A chanop took +L off the tombstone: at the deadline nobody is parted
 * (the channel no longer authenticates), but the +z goes -- whoever set
 * it -- so the channel is collected like any other once it empties. */
static void cancelled_tombstone_gives_the_persist_flag_back(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  oldch->mode.exmode |= EXMODE_PERSIST;
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "moving");

  /* MODE #old -L */
  oldch->mode.redir[0] = '\0';
  forget();

  advance(900);
  assert_int_equal(sent_count_to(bob), 0);
  assert_non_null(member_of(oldch, bob));
  assert_false(oldch->mode.exmode & EXMODE_PERSIST);
  assert_false(was_destroyed(oldch));
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "lost its redirect"));
  /* the log names what happened: the redirect is gone, not changed */
  {
    int i, said = 0;
    for (i = 0; i < ndebug; i++)
      if (strstr(debuglines[i], "(+L was cleared)"))
        said = 1;
    assert_true(said);
  }

  /* ... and the last member leaving now collects it */
  remove_user_from_channel(bob, oldch);
  assert_true(was_destroyed(oldch));
}

/* The same with nobody left in it: collected at the deadline. */
static void cancelled_empty_tombstone_is_collected(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  oldch->mode.exmode |= EXMODE_PERSIST;
  client_rename(alice, "#old", "#new", "moving");
  oldch->mode.redir[0] = '\0';

  advance(900);
  assert_true(was_destroyed(oldch));
}

/* ... unless the channel is registered by then: its +z is services'. */
static void cancelled_registered_channel_keeps_its_persist_flag(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "moving");
  oldch->mode.redir[0] = '\0';
  oldch->mode.mode |= MODE_REGISTERED;

  advance(900);
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_non_null(member_of(oldch, bob));
  assert_int_equal(nopnotices, 0);
}

/* --- A.1: the deadline travels --- */

/* The issuing server computes the deadline once, in network time, and
 * every peer a relocation goes to is sent it. */
static void relocation_carries_its_deadline(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *legacy = linked("old.example", "Bo", "r");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  (void)state; (void)legacy;

  feat_rename_consent = 1;
  feat_relocate_grace = 900;
  TSoffset = 250;               /* network time is 1000250 */
  add_member(channel_at("#old", 500000, alice), bob, 0);

  client_rename(alice, "#old", "#new", "moving");

  assert_string_equal(sent_to(peer, 0), "ACAAB RN #old #new C 1001150 :moving");
  assert_string_equal(sent_to(x3, 0), "ACAAB RN #old #new C 1001150 :moving");
  /* armed for the same instant on this server's own clock */
  assert_int_equal(timers_at(1000900), 1);
  assert_non_null(strstr(sent_to(bob, 0), "this channel closes in 15 minutes."));
}

/* An empty reason is still sent: the trailing parameter is what makes the
 * marker a marker. */
static void relocation_without_a_reason_keeps_the_trailing_parameter(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  (void)state;

  feat_rename_consent = 1;
  channel_at("#old", 500000, alice);
  client_rename(alice, "#old", "#new", "");
  assert_string_equal(sent_to(peer, 0), "ACAAB RN #old #new C 1000900 :");
}

/* A registered channel's relocation, approved by services, carries it
 * too. */
static void approved_relocation_carries_its_deadline(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  char cookie[64];
  (void)state;

  feat_rename_consent = 1;
  registered_channel("#reg", alice)->creationtime = 500000;
  client_rename(alice, "#reg", "#new", "why");
  snprintf(cookie, sizeof(cookie), "%s", cookie_of(sent_to(x3, 0)));
  forget();

  assert_int_equal(account_line(x3, x3, 3, cookie, "A", "RENAME"), 1);
  assert_string_equal(sent_to(peer, 0), "ACAAB RN #reg #new C 1000900 :why");
  assert_string_equal(sent_to(x3, 0), "ACAAB RN #reg #new C 1000900 :why");
  assert_true(channel_named("#new")->mode.mode & MODE_REGISTERED);
  assert_false(channel_named("#reg")->mode.mode & MODE_REGISTERED);
}

/* A receiver arms for the deadline it is sent -- not for its own grace
 * counted from now -- and passes the same deadline on. */
static void receiver_arms_for_the_deadline_on_the_wire(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  feat_relocate_grace = 900;    /* ours; the issuer's was 300 */
  TSoffset = -40;               /* network time is 999960 */
  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);

  server_relocate(peer, bob, "#old", "#new", "1000260", "moving");

  assert_non_null(member_of(channel_named("#new"), bob));
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(timers_at(1000300), 1);      /* 1000260 less TSoffset */
  assert_int_equal(ntimers, 1);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000260 :moving");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new C 1000260 :moving");
  assert_int_equal(sent_count_to(peer), 0);
  /* five minutes are left of it */
  assert_non_null(strstr(sent_to(carol, 0), "this channel closes in 5 minutes."));

  /* not yet ... */
  advance(299);
  assert_non_null(member_of(oldch, carol));
  /* ... now */
  advance(1);
  assert_true(was_destroyed(oldch));
}

/* The five-parameter form of a peer from before the deadline travelled:
 * this server's own grace from now, as every server used to; and what it
 * relays carries the deadline it went by. */
static void five_parameter_relocation_uses_the_local_grace(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  (void)state;

  feat_relocate_grace = 120;
  add_member(channel_at("#old", 500000, bob), carol, 0);

  server_relocate(peer, bob, "#old", "#new", NULL, "moving");

  assert_non_null(member_of(channel_named("#new"), bob));
  assert_int_equal(timers_at(1000120), 1);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000120 :moving");
  assert_int_equal(nviolations, 0);
}

/* A reason that happens to be a number is a reason in the five-parameter
 * form. */
static void five_parameter_reason_is_never_read_as_a_deadline(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  (void)state;

  feat_relocate_grace = 120;
  channel_at("#old", 500000, bob);
  server_relocate(peer, bob, "#old", "#new", NULL, "1000050");
  assert_int_equal(timers_at(1000120), 1);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000120 :1000050");
}

/* A fifth parameter that is not a deadline: the relocation is executed
 * all the same (or membership would diverge), on the local grace. */
static void garbage_deadline_falls_back_to_the_local_grace(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  (void)state;

  feat_relocate_grace = 120;
  channel_at("#old", 500000, bob);
  server_relocate(peer, bob, "#old", "#new", "-5", "moving");

  assert_non_null(member_of(channel_named("#new"), bob));
  assert_int_equal(timers_at(1000120), 1);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000120 :moving");
  assert_int_equal(nviolations, 1);
  assert_non_null(strstr(violations[0], "not a relocation deadline"));
}

/* A deadline already past: the relocation is executed and the tombstone
 * dissolved on the spot; the relay passes the same past time on. */
static void past_deadline_dissolves_at_once(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);

  server_relocate(peer, bob, "#old", "#new", "999990", "moving");

  assert_non_null(member_of(channel_named("#new"), bob));
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
  assert_int_equal(ntimers, 0);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 999990 :moving");
}

/* A deadline absurdly far ahead is cut to the protocol's longest grace,
 * and the cut value is what goes on. */
static void far_deadline_is_clamped_and_relayed_clamped(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  char expect[LINE];
  (void)state;

  channel_at("#old", 500000, bob);
  server_relocate(peer, bob, "#old", "#new", "2147483647", "moving");

  assert_int_equal(timers_at(1000000 + RELOCATE_GRACE_MAX), 1);
  snprintf(expect, sizeof(expect), "BjAAC RN #old #new C %d :moving",
           1000000 + RELOCATE_GRACE_MAX);
  assert_string_equal(sent_to(down, 0), expect);
}

/* A relocation issued from a bouncer alias reaches X3 as its primary,
 * with the deadline. */
static void relocation_from_an_alias_reaches_x3_as_its_primary(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *primary = user_on(peer, "bob", "AAC");
  struct Client *alias = user_on(peer, "bob", "AAE");
  (void)state;

  SetBouncerAlias(alias);
  cli_user(alias)->alias_primary = primary;
  channel_at("#old", 500000, primary);

  server_relocate(peer, alias, "#old", "#new", "1000300", "moving");

  /* the primary is the member, and the one that moved */
  assert_non_null(member_of(channel_named("#new"), primary));
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new C 1000300 :moving");
  /* fork servers know the alias (the real send rewrites toward the ones
   * that do not) */
  assert_string_equal(sent_to(down, 0), "BjAAE RN #old #new C 1000300 :moving");
}

/* --- C.3: RELOCATE_GRACE 0 --- */

/* The issuer moves, everyone else is parted in the same breath, the old
 * channel is gone when the command returns, and nothing is left to fire
 * or to restore from. */
static void grace_zero_dissolves_at_once(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *dave = user_on(peer, "dave", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 0;
  CapSet(cli_active_own(alice), CAP_DRAFT_CHANRENAME);
  oldch = channel_at("#old", 500000, alice);
  oldch->mode.exmode |= EXMODE_PERSIST;      /* even a +z from before */
  add_member(oldch, bob, CHFL_CHANOP);
  add_member(oldch, dave, CHFL_VOICE);

  client_rename(alice, "#old", "#new", "now");

  /* the issuer moved, with its status, and was told */
  newch = channel_named("#new");
  assert_non_null(newch);
  assert_true(member_of(newch, alice)->status & CHFL_CHANOP);
  assert_int_equal(newch->users, 1);
  assert_string_equal(sent_to(alice, 0),
                      ":alice!user@host.example RENAME #old #new :now");
  assert_int_equal(sent_count_to(alice), 1);

  /* the stayer: the notice, the issuer leaving, the redirect, its own
   * PART -- in that order, and nothing after */
  assert_non_null(strstr(sent_to(bob, 0), "#old has moved to #new (now)."));
  assert_non_null(strstr(sent_to(bob, 0), "closes in 0 minutes."));
  assert_string_equal(sent_to(bob, 1),
                      ":alice!user@host.example PART #old :Moved to #new");
  assert_string_equal(sent_to(bob, 2), ":me.example MODE #old +L #new");
  assert_string_equal(sent_to(bob, 3),
                      ":dave!user@host.example PART #old :Channel has moved to #new");
  assert_string_equal(sent_to(bob, 4),
                      ":bob!user@host.example PART #old :Channel has moved to #new");
  assert_int_equal(sent_count_to(bob), 5);

  /* nothing left behind: no channel, no timer */
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
  assert_int_equal(ntimers, 0);

  /* the deadline on the wire is now */
  assert_string_equal(sent_to(peer, 0), "ACAAB RN #old #new C 1000000 :now");
  assert_string_equal(sent_to(x3, 0), "ACAAB RN #old #new C 1000000 :now");

  /* ... and nothing to take along: swept, bob joins like anybody */
  assert_int_equal(joins(bob, newch), 0);
}

/* The name is free again at once: it can be created and relocated anew,
 * and that relocation is not confused by anything the first left. */
static void grace_zero_leaves_the_old_name_free(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *again;
  char name[] = "#old";
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 0;
  channel_at("#old", 500000, alice);
  client_rename(alice, "#old", "#new", "");
  assert_null(channel_named("#old"));

  feat_relocate_grace = 900;
  again = get_channel(bob, name, CGT_CREATE);
  add_member(again, bob, CHFL_CHANOP);
  forget();
  client_rename(bob, "#old", "#other", "");
  assert_string_equal(again->mode.redir, "#other");
  assert_true(again->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(ntimers, 1);
}

/* A receiver whose clock stands exactly at the deadline dissolves at
 * once too: "now" is not "later". */
static void deadline_of_this_very_second_dissolves_at_once(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000000", "");

  assert_non_null(member_of(channel_named("#new"), bob));
  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
}

/* A chain still flattens when its last hop has no grace: #a -> #b, then
 * #b -> #c at once; #a redirects to #c and #b is gone. */
static void grace_zero_still_flattens_a_chain(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *a;
  (void)state;

  feat_rename_consent = 1;
  a = channel_at("#a", 500000, alice);
  add_member(a, bob, 0);
  client_rename(alice, "#a", "#b", "");
  feat_relocate_grace = 0;
  client_rename(alice, "#b", "#c", "");

  assert_string_equal(a->mode.redir, "#c");
  assert_null(channel_named("#b"));
  assert_non_null(member_of(channel_named("#c"), alice));
  assert_int_equal(ntimers, 1);         /* #a's */
}

/* --- C.2: a tombstone that is +R at its deadline is cancelled --- */

/* Services register the old name inside the grace.  Nothing happens when
 * the +R arrives; at the deadline the tombstone is cancelled instead of
 * swept: nobody is parted, the redirect goes, +z is left to services. */
static void registered_tombstone_is_cancelled_at_the_deadline(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *dave = user_on(peer, "dave", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  add_member(oldch, dave, 0);
  client_rename(alice, "#old", "#new", "moving");
  newch = channel_named("#new");

  /* MODE #old +R, mid-grace: the record, the redirect and the timer are
   * as they were */
  advance(400);
  oldch->mode.mode |= MODE_REGISTERED;
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(ntimers, 1);
  forget();

  advance(500);

  /* cancelled: members stay, and are told the redirect is gone */
  assert_non_null(member_of(oldch, bob));
  assert_non_null(member_of(oldch, dave));
  assert_int_equal(oldch->users, 2);
  assert_int_equal(sent_count_to(bob), 1);
  assert_string_equal(sent_to(bob, 0), ":me.example MODE #old -L");
  assert_string_equal(oldch->mode.redir, "");
  /* an ordinary registered channel again; +z is services' to clear */
  assert_true(oldch->mode.mode & MODE_REGISTERED);
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_false(was_destroyed(oldch));
  /* the record is gone */
  assert_int_equal(ntimers, 0);
  /* nothing goes to a server: every server does this by itself */
  assert_int_equal(sent_count_to(peer), 0);
  /* and #old is an ordinary channel: its op joins #new as anybody would,
   * taking nothing and leaving nothing */
  assert_int_equal(joins(bob, newch), 0);
  assert_non_null(member_of(oldch, bob));
}

/* The race that makes "at the deadline" the rule.  A channel is
 * registered and relocated within a second; services' MODE +R is still
 * on its way.
 *
 * Order one (the hub in the field report): +R is applied BEFORE the RN.
 * The new channel inherits it, the tombstone has it stripped, and at the
 * deadline the tombstone -- not +R -- is swept. */
static void stray_registration_before_the_relocation(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);

  oldch->mode.mode |= MODE_REGISTERED;                  /* M #old +R */
  server_relocate(peer, bob, "#old", "#new", "1000900", "");

  assert_true(channel_named("#new")->mode.mode & MODE_REGISTERED);
  assert_false(oldch->mode.mode & MODE_REGISTERED);
  assert_int_equal(timers_at(1000900), 1);

  advance(900);
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
}

/* Order two (the issuing leaf): the RN is executed first and the +R then
 * lands on the tombstone.  The record is not touched by it -- the same
 * deadline, the same redirect, the snapshots -- and at the deadline this
 * server does what ITS +R bit says: the tombstone is cancelled. */
static void stray_registration_after_the_relocation(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *newch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_VOICE);
  add_member(oldch, dan, CHFL_VOICE);

  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  newch = channel_named("#new");
  oldch->mode.mode |= MODE_REGISTERED;                  /* M #old +R */

  /* neither the mode nor time passing has corrupted the record */
  assert_false(newch->mode.mode & MODE_REGISTERED);
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(ntimers, 1);
  advance(899);
  assert_non_null(member_of(oldch, carol));
  assert_string_equal(oldch->mode.redir, "#new");
  /* it is still a tombstone to follow out of */
  assert_int_equal(joins(dan, newch), CHFL_VOICE);
  assert_null(member_of(oldch, dan));

  advance(1);
  assert_non_null(member_of(oldch, carol));
  assert_string_equal(oldch->mode.redir, "");
  assert_true(oldch->mode.mode & MODE_REGISTERED);
  assert_false(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
}

/* The repair services have the whole grace for: -R on the old name.
 * Then order two ends as order one does. */
static void stray_registration_corrected_before_the_deadline(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->mode.mode |= MODE_REGISTERED;                  /* M #old +R */
  advance(5);
  oldch->mode.mode &= ~MODE_REGISTERED;                 /* M #old -R */

  advance(895);
  assert_true(was_destroyed(oldch));
}

/* With no grace the same question is asked on the spot: the relocation
 * has just taken +R off the tombstone, so it is swept. */
static void registered_channel_relocated_without_grace_is_swept(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  oldch->mode.mode |= MODE_REGISTERED;
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000000", "");

  assert_true(channel_named("#new")->mode.mode & MODE_REGISTERED);
  assert_true(was_destroyed(oldch));
}

/* --- the life of a tombstone record ---
 *
 * A record's timer is embedded in it, so a record the event engine holds
 * is freed only from the timer's ET_DESTROY.  These run clean under
 * AddressSanitizer or they are wrong; the timer fakes above fail a
 * timer_del() the real engine would ignore. */

/* The deadline has come but the timer has not fired yet (the same
 * second), and a second relocation of the tombstone arrives: the record,
 * whose timer IS armed, is dissolved on the spot and freed once. */
static void record_with_an_armed_timer_is_ended_through_its_timer(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAE");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000100", "");
  assert_int_equal(timers_at(1000100), 1);

  CurrentTime = 1000100;        /* due, not yet run */
  server_relocate(peer, eve, "#old", "#other", "1000050", "");

  assert_int_equal(ntimers, 0);
  assert_true(was_destroyed(oldch));
  /* nothing is left to fire, or to find */
  advance(1000);
  assert_null(channel_named("#old"));
}

/* The same through a step of the network clock: the timer is still far
 * off on this server's clock, the deadline is behind on the network's. */
static void record_past_its_deadline_by_a_clock_step_is_ended_through_its_timer(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAE");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  assert_int_equal(timers_at(1000900), 1);

  TSoffset = 5000;              /* SETTIME: network time is 1005000 */
  server_relocate(peer, eve, "#old", "#other", "1000950", "");

  assert_int_equal(ntimers, 0);
  assert_true(was_destroyed(oldch));
}

/* The tombstone's channel is destroyed under a record whose timer is
 * armed (services DESTRUCT): the record goes with it, through its timer,
 * and nothing fires later. */
static void record_goes_with_its_channel(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  client_rename(alice, "#old", "#new", "");
  assert_int_equal(ntimers, 1);

  oldch->mode.exmode &= ~EXMODE_PERSIST;
  sub1_from_channel(oldch);             /* as destruct_channel() */
  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
  advance(900);
}

/* The sweep at the deadline empties the channel, which destroys it, which
 * runs the destruct hook for the record that is being swept: it is not
 * found, and freed once -- from the timer here ... */
static void sweep_that_destroys_the_channel_frees_the_record_once(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, 0);
  client_rename(alice, "#old", "#new", "");

  advance(900);
  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
}

/* ... and by hand for a record that never had a timer. */
static void sweep_on_the_spot_frees_the_record_once(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 0;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, 0);
  client_rename(alice, "#old", "#new", "");

  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
}

/* --- D.1: a relocation this server cannot apply is still relayed --- */

/* The old channel is not here.  The servers behind this one must hear of
 * the relocation all the same, with the deadline, and the operators of
 * this one must hear that it may now differ. */
static void relocation_of_a_channel_not_here_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  (void)state;

  server_relocate(peer, bob, "#old", "#new", "1000300", "moving");

  assert_null(channel_named("#old"));
  assert_null(channel_named("#new"));
  assert_int_equal(ntimers, 0);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000300 :moving");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new C 1000300 :moving");
  assert_int_equal(sent_count_to(peer), 0);
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "#old"));
  assert_non_null(strstr(opnotices[0], "#new"));
  assert_non_null(strstr(opnotices[0], "does not exist"));
  assert_non_null(strstr(opnotices[0], "relayed"));
}

/* ... in the old form too: relayed with the deadline this server would
 * have gone by. */
static void five_parameter_relocation_of_a_channel_not_here_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  (void)state;

  feat_relocate_grace = 60;
  server_relocate(peer, bob, "#old", "#new", NULL, "moving");
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000060 :moving");
  assert_int_equal(nopnotices, 1);
}

/* The new name is taken here: nothing is touched, and it is relayed (as
 * before this change). */
static void relocation_onto_a_name_taken_here_is_relayed(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, alice, 0);
  newch = channel_at("#new", 600000, carol);

  server_relocate(peer, bob, "#old", "#new", "1000300", "moving");

  assert_non_null(member_of(oldch, bob));
  assert_string_equal(oldch->mode.redir, "");
  assert_false(oldch->mode.exmode & EXMODE_PERSIST);
  assert_null(member_of(newch, bob));
  assert_int_equal(ntimers, 0);
  assert_int_equal(sent_count_to(alice), 0);
  assert_string_equal(sent_to(down, 0), "BjAAC RN #old #new C 1000300 :moving");
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "already exists"));
}

/* The alias source rewrite toward X3 happens on such a relay as well. */
static void unapplied_relocation_from_an_alias_reaches_x3_as_its_primary(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *primary = user_on(peer, "bob", "AAC");
  struct Client *alias = user_on(peer, "bob", "AAE");
  (void)state;

  SetBouncerAlias(alias);
  cli_user(alias)->alias_primary = primary;

  server_relocate(peer, alias, "#old", "#new", "1000300", "");
  assert_string_equal(sent_to(x3, 0), "BjAAC RN #old #new C 1000300 :");
}

/* --- D.2: a classic rename of a live tombstone --- */

/* Refused for a local user whatever RENAME_CONSENT says here: the
 * tombstone came off the wire, and this server's own setting has no say
 * in whether it is one. */
static void tombstone_cannot_be_renamed_with_consent_off(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 0;
  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  forget();

  client_rename(carol, "#old", "#mine", "");

  assert_string_equal(sent_to(carol, 0),
                      "FAIL RENAME CANNOT_RENAME #old :Channel is a relocation tombstone");
  assert_int_equal(sent_count_to(peer), 0);
  assert_ptr_equal(channel_named("#old"), oldch);
  assert_null(channel_named("#mine"));
}

/* ... and when it became one while services were being asked. */
static void approval_does_not_rename_a_tombstone_with_consent_off(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  char cookie[64];
  (void)state;

  feat_rename_consent = 0;
  oldch = registered_channel("#old", carol);
  oldch->creationtime = 500000;
  add_member(oldch, bob, CHFL_CHANOP);

  client_rename(carol, "#old", "#mine", "");            /* asks services */
  snprintf(cookie, sizeof(cookie), "%s", cookie_of(sent_to(x3, 0)));
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->mode.mode |= MODE_REGISTERED;  /* a stray +R, still an op */
  forget();

  assert_int_equal(account_line(x3, x3, 3, cookie, "A", "RENAME"), 1);
  assert_string_equal(sent_to(carol, 0),
                      "FAIL RENAME CANNOT_RENAME #old :Channel is a relocation tombstone");
  assert_ptr_equal(channel_named("#old"), oldch);
  assert_null(channel_named("#mine"));
}

/* A classic RN for a tombstone from the network (a server with the
 * refusal missing, or a services rename): the channel is renamed like
 * any other, and its record goes with it -- the tombstone, under its new
 * name, still redirects, still restores a follower, and is dissolved at
 * its deadline instead of being left +z +L for good. */
static void renamed_tombstone_keeps_its_record(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAE");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAG");
  struct Channel *oldch, *renamed;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  add_member(oldch, carol, CHFL_VOICE);
  add_member(oldch, dan, CHFL_VOICE);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  forget();

  server_rename(peer, eve, "#old", "#older", "tidy");

  renamed = channel_named("#older");
  assert_non_null(renamed);
  assert_null(channel_named("#old"));
  assert_string_equal(renamed->mode.redir, "#new");
  assert_true(renamed->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(sent_to(down, 0), "BjAAE RN #old #older :tidy");
  assert_int_equal(nopnotices, 0);
  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(ntimers, 1);
  /* a member still follows out of it, with its status */
  assert_int_equal(joins(dan, channel_named("#new")), CHFL_VOICE);
  assert_null(member_of(renamed, dan));
  forget();

  advance(900);
  assert_string_equal(sent_to(carol, 0),
                      ":carol!user@host.example PART #older :Channel has moved to #new");
  assert_true(was_destroyed(renamed));
  assert_null(channel_named("#older"));
  assert_int_equal(nopnotices, 0);
  assert_int_equal(ntimers, 0);
}

/* The old name is free at once: a channel created under it afterwards is
 * nobody's tombstone. */
static void renamed_tombstone_frees_its_old_name(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAE");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *again;
  char name[] = "#old";
  (void)state;

  add_member(channel_at("#old", 500000, bob), eve, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  server_rename(peer, eve, "#old", "#older", "");

  feat_rename_consent = 1;
  feat_relocate_grace = 2000;
  again = get_channel(carol, name, CGT_CREATE);
  add_member(again, carol, CHFL_CHANOP);
  forget();
  client_rename(carol, "#old", "#fresh", "");
  assert_string_equal(sent_to(carol, 0), ":carol!user@host.example PART #old :Channel renamed to #fresh");
  assert_non_null(member_of(channel_named("#fresh"), carol));

  /* the first tombstone's deadline does not touch the new #old */
  advance(900);
  assert_null(channel_named("#older"));
  assert_ptr_equal(channel_named("#old"), again);
  assert_string_equal(again->mode.redir, "#fresh");
}

/* --- B: two relocations of one channel that cross --- */

/* The world of a crossing, seen from a third server: vic on one peer
 * relocates #old to #x, uma on another relocates it to #y, each before
 * hearing of the other.  #x sorts first and wins. */
struct Crossing {
  struct Client *pa, *pb, *x3;
  struct Client *vic, *uma, *carol;
  struct Channel *old;
};

static void crossing_world(struct Crossing *w)
{
  w->pa = linked("a.example", "Bj", "v");
  w->pb = linked("b.example", "Bk", "v");
  w->x3 = linked("x3.services", "AX", "sr");
  w->vic = user_on(w->pa, "vic", "AAC");
  w->uma = user_on(w->pb, "uma", "AAD");
  w->carol = user_on(&me, "carol", "AAE");

  w->old = channel_at("#old", 500000, w->vic);
  add_member(w->old, w->uma, CHFL_CHANOP);
  add_member(w->old, w->carol, CHFL_VOICE);
  w->old->mode.mode |= MODE_NOPRIVMSGS;
  w->old->mode.limit = 5;
  ircd_strncpy(w->old->mode.key, "sesame", sizeof(w->old->mode.key));
}

static void vic_relocates(struct Crossing *w)
{
  server_relocate(w->pa, w->vic, "#old", "#x", "1000900", "to x");
}

static void uma_relocates(struct Crossing *w)
{
  server_relocate(w->pb, w->uma, "#old", "#y", "1000600", "to y");
}

/* What every server must hold after both, whichever came first. */
static void assert_crossing_end_state(struct Crossing *w)
{
  struct Channel *x = channel_named("#x"), *y = channel_named("#y");

  assert_non_null(x);
  assert_non_null(y);
  assert_ptr_equal(channel_named("#old"), w->old);

  /* #old: a tombstone redirecting to the winner, with the stayer */
  assert_string_equal(w->old->mode.redir, "#x");
  assert_true(w->old->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(w->old->users, 1);
  assert_non_null(member_of(w->old, w->carol));

  /* the winner: an ordinary channel with the state the old one had --
   * nothing of the tombstone's +z, +L or redirect -- and its issuer */
  assert_false(x->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(x->mode.redir, "");
  assert_true(x->mode.mode & MODE_NOPRIVMSGS);
  assert_int_equal(x->mode.limit, 5);
  assert_string_equal(x->mode.key, "sesame");
  assert_int_equal(x->creationtime, 500000);
  assert_int_equal(x->users, 1);
  assert_true(member_of(x, w->vic)->status & CHFL_CHANOP);

  /* the loser: a tombstone too, redirecting to the winner, with ITS
   * issuer, who can follow from there */
  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_true(y->mode.mode & MODE_NOPRIVMSGS);
  assert_int_equal(y->mode.limit, 0);
  assert_string_equal(y->mode.key, "sesame");
  assert_int_equal(y->creationtime, 500000);
  assert_int_equal(y->users, 1);
  assert_true(member_of(y, w->uma)->status & CHFL_CHANOP);

  /* two records, one deadline: the later of the two */
  assert_int_equal(ntimers, 2);
  assert_int_equal(timers_at(1000900), 2);

  /* a member of #old follows into the WINNER with its status and leaves
   * #old; joining the loser moves nobody (it is no tombstone's target) */
  assert_int_equal(joins(w->carol, y), 0);
  assert_non_null(member_of(w->old, w->carol));
  remove_user_from_channel(w->carol, y);
  assert_int_equal(joins(w->carol, x), CHFL_VOICE);
  assert_null(member_of(w->old, w->carol));
  /* (uma, in the loser, is another server's user: her own server moves
   * her when she joins #x -- crossing_loser_with_the_cap_gets_a_relocate
   * has the local case) */

  /* at the deadline both tombstones go, and the winner stays */
  advance(900);
  assert_true(was_destroyed(w->old));
  assert_true(was_destroyed(y));
  assert_null(channel_named("#old"));
  assert_null(channel_named("#y"));
  assert_ptr_equal(channel_named("#x"), x);
  assert_int_equal(ntimers, 0);
}

/* This server hears the winner first. */
static void crossing_relocations_winner_first(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  vic_relocates(&w);
  forget();
  uma_relocates(&w);

  /* each RN goes on as it came, with its own deadline: the servers
   * behind work the same thing out from the same two lines */
  assert_string_equal(sent_to(w.pa, 0), "BkAAD RN #old #y C 1000600 :to y");
  assert_string_equal(sent_to(w.x3, 0), "BkAAD RN #old #y C 1000600 :to y");
  assert_int_equal(sent_count_to(w.pb), 0);
  /* the stayer saw the second issuer leave; the redirect did not change */
  assert_string_equal(sent_to(w.carol, 0),
                      ":uma!user@host.example PART #old :Moved to #y");
  assert_int_equal(sent_count_to(w.carol), 1);
  assert_int_equal(nopnotices, 0);

  assert_crossing_end_state(&w);
}

/* This server hears the loser first: its first new channel becomes the
 * second tombstone, and #old is pointed at the winner. */
static void crossing_relocations_loser_first(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  uma_relocates(&w);
  assert_string_equal(w.old->mode.redir, "#y");
  assert_int_equal(channel_named("#y")->mode.limit, 5);
  forget();
  vic_relocates(&w);

  assert_string_equal(sent_to(w.pb, 0), "BjAAC RN #old #x C 1000900 :to x");
  assert_string_equal(sent_to(w.x3, 0), "BjAAC RN #old #x C 1000900 :to x");
  assert_int_equal(sent_count_to(w.pa), 0);
  /* the stayer saw the winner's issuer leave and the redirect change */
  assert_string_equal(sent_to(w.carol, 0),
                      ":vic!user@host.example PART #old :Moved to #x");
  assert_string_equal(sent_to(w.carol, 1), ":me.example MODE #old +L #x");
  assert_int_equal(sent_count_to(w.carol), 2);
  assert_int_equal(nopnotices, 0);

  assert_crossing_end_state(&w);
}

/* The issuer of the losing relocation on its own server: it sits in what
 * is now a tombstone, and is told so like any stayer. */
static void crossing_loser_is_told_on_its_own_server(void **state)
{
  struct Client *peer = linked("a.example", "Bj", "v");
  struct Client *vic = user_on(peer, "vic", "AAC");
  struct Client *uma = user_on(&me, "uma", "AAD");
  struct Channel *oldch, *y;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 600;
  CapSet(cli_active_own(uma), CAP_DRAFT_CHANRENAME);
  oldch = channel_at("#old", 500000, vic);
  add_member(oldch, uma, CHFL_CHANOP);

  client_rename(uma, "#old", "#y", "to y");
  y = channel_named("#y");
  forget();
  server_relocate(peer, vic, "#old", "#x", "1000900", "to x");

  assert_string_equal(oldch->mode.redir, "#x");
  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_non_null(member_of(channel_named("#x"), vic));
  assert_non_null(member_of(y, uma));
  assert_non_null(strstr(sent_to(uma, 0),
                         "NOTICE #y :#y has moved to #x (to x). Join #x to "
                         "follow; this channel closes in 15 minutes."));
  assert_string_equal(sent_to(uma, 1), ":me.example MODE #y +L #x");
  assert_int_equal(sent_count_to(uma), 2);
  assert_int_equal(timers_at(1000900), 2);

  /* swept from the loser at the deadline */
  forget();
  advance(900);
  assert_string_equal(sent_to(uma, 0),
                      ":uma!user@host.example PART #y :Channel has moved to #x");
  assert_true(was_destroyed(y));
}

/* ... and with evilnet/channel-relocate, as a RELOCATE from the winner's
 * issuer. */
static void crossing_loser_with_the_cap_gets_a_relocate(void **state)
{
  struct Client *peer = linked("a.example", "Bj", "v");
  struct Client *vic = user_on(peer, "vic", "AAC");
  struct Client *uma = user_on(&me, "uma", "AAD");
  (void)state;

  feat_rename_consent = 1;
  CapSet(cli_active(uma), CAP_EVILNET_RELOCATE);
  add_member(channel_at("#old", 500000, vic), uma, CHFL_CHANOP);
  client_rename(uma, "#old", "#y", "");
  forget();
  server_relocate(peer, vic, "#old", "#x", "1000900", "to x");

  assert_string_equal(sent_to(uma, 0),
                      ":vic!user@host.example RELOCATE #y #x :to x");

  /* she follows from the LOSER's channel, itself a tombstone now, with the
   * status she holds there, and leaves it */
  assert_int_equal(joins(uma, channel_named("#x")), CHFL_CHANOP);
  assert_null(member_of(channel_named("#y"), uma));
  assert_string_equal(sent_to(peer, sent_count_to(peer) - 1),
                      "ACAAD L #y :Channel has moved to #x");
}

/* The winner's issuer on its own server: nothing changes for it; the
 * losing channel appears as a tombstone with its issuer in it. */
static void crossing_winner_on_its_own_server(void **state)
{
  struct Client *peer = linked("b.example", "Bk", "v");
  struct Client *uma = user_on(peer, "uma", "AAD");
  struct Client *vic = user_on(&me, "vic", "AAC");
  struct Channel *oldch, *y;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 300;
  oldch = channel_at("#old", 500000, vic);
  add_member(oldch, uma, CHFL_CHANOP);

  client_rename(vic, "#old", "#x", "to x");
  forget();
  server_relocate(peer, uma, "#old", "#y", "1000600", "to y");

  y = channel_named("#y");
  assert_non_null(y);
  assert_string_equal(oldch->mode.redir, "#x");
  assert_string_equal(y->mode.redir, "#x");
  assert_non_null(member_of(y, uma));
  assert_int_equal(oldch->users, 0);
  assert_int_equal(sent_count_to(vic), 0);
  /* one deadline for the pair: the later (uma's) */
  assert_int_equal(timers_at(1000600), 2);
  assert_int_equal(ntimers, 2);
}

/* Both servers relocated #old to the SAME name: nothing to decide.  The
 * second issuer joins the first in the new channel, and the later
 * deadline is kept. */
static void same_relocation_twice_moves_the_second_issuer(void **state)
{
  struct Crossing w;
  struct Channel *newch;
  (void)state;

  crossing_world(&w);
  server_relocate(w.pa, w.vic, "#old", "#new", "1000300", "");
  newch = channel_named("#new");
  forget();
  server_relocate(w.pb, w.uma, "#old", "#NEW", "1000900", "");

  assert_ptr_equal(channel_named("#new"), newch);
  assert_true(member_of(newch, w.vic)->status & CHFL_CHANOP);
  assert_true(member_of(newch, w.uma)->status & CHFL_CHANOP);
  assert_int_equal(newch->users, 2);
  assert_int_equal(w.old->users, 1);
  assert_string_equal(w.old->mode.redir, "#new");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000900), 1);
  assert_string_equal(sent_to(w.pa, 0), "BkAAD RN #old #NEW C 1000900 :");
  assert_string_equal(sent_to(w.carol, 0),
                      ":uma!user@host.example PART #old :Moved to #new");
}

/* ... and an earlier deadline in the second does not shorten the first. */
static void same_relocation_twice_keeps_the_later_deadline(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  server_relocate(w.pa, w.vic, "#old", "#new", "1000900", "");
  server_relocate(w.pb, w.uma, "#old", "#new", "1000300", "");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000900), 1);

  /* not even one that is already past: the armed record stays armed */
  server_relocate(w.pb, w.uma, "#old", "#new", "999000", "");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000900), 1);
  assert_ptr_equal(channel_named("#old"), w.old);
}

/* The merged deadline can itself be past: the record's timer is due this
 * very second and has not run.  The tombstone is dissolved on the spot
 * and its record, whose timer is armed, freed once. */
static void merged_deadline_that_is_past_dissolves_through_the_timer(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  server_relocate(w.pa, w.vic, "#old", "#new", "1000100", "");
  assert_int_equal(timers_at(1000100), 1);

  CurrentTime = 1000100;
  server_relocate(w.pb, w.uma, "#old", "#new", "1000050", "");

  assert_int_equal(ntimers, 0);
  assert_true(was_destroyed(w.old));
  assert_non_null(member_of(channel_named("#new"), w.uma));
  advance(1000);
}

/* A chain is not a crossing: #a -> #b, then #b -> #c.  #b is no
 * tombstone when it is relocated, so nobody "wins"; both old names
 * redirect to #c, and #c carries nothing of a tombstone. */
static void chain_is_not_a_crossing(void **state)
{
  struct Crossing w;
  struct Channel *b, *c;
  (void)state;

  crossing_world(&w);
  server_relocate(w.pa, w.vic, "#old", "#b", "1000900", "");
  b = channel_named("#b");
  server_relocate(w.pa, w.vic, "#b", "#a", "1000950", "");     /* "#a" < "#b" */
  c = channel_named("#a");

  assert_non_null(c);
  assert_string_equal(w.old->mode.redir, "#a");
  assert_string_equal(b->mode.redir, "#a");
  assert_true(b->mode.exmode & EXMODE_PERSIST);
  assert_false(c->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(c->mode.redir, "");
  assert_non_null(member_of(c, w.vic));
  assert_int_equal(c->mode.limit, 5);
  /* each keeps its own deadline */
  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(timers_at(1000950), 1);
  assert_int_equal(ntimers, 2);
}

/* A crossing under a chain: #first was relocated to #old before #old was
 * relocated twice.  #first follows #old to the winner in either order,
 * and keeps its own deadline. */
static void crossing_carries_an_earlier_hop_to_the_winner(void **state)
{
  int order;
  (void)state;

  for (order = 0; order < 2; order++) {
    struct Client *pa, *pb, *zed, *vic, *uma, *carol;
    struct Channel *first, *oldch;

    if (order) {
      world_teardown(NULL);
      world_setup(NULL);
    }
    pa = linked("a.example", "Bj", "v");
    pb = linked("b.example", "Bk", "v");
    zed = user_on(pa, "zed", "AAF");
    vic = user_on(pa, "vic", "AAC");
    uma = user_on(pb, "uma", "AAD");
    carol = user_on(&me, "carol", "AAE");

    first = channel_at("#first", 500000, zed);
    add_member(first, carol, 0);
    server_relocate(pa, zed, "#first", "#old", "1000500", "");
    oldch = channel_named("#old");
    add_member(oldch, vic, CHFL_CHANOP);        /* they followed */
    add_member(oldch, uma, CHFL_CHANOP);
    forget();

    if (order == 0) {
      server_relocate(pa, vic, "#old", "#x", "1000900", "");
      server_relocate(pb, uma, "#old", "#y", "1000600", "");
    } else {
      server_relocate(pb, uma, "#old", "#y", "1000600", "");
      assert_string_equal(first->mode.redir, "#y");
      server_relocate(pa, vic, "#old", "#x", "1000900", "");
    }

    assert_string_equal(first->mode.redir, "#x");
    assert_string_equal(oldch->mode.redir, "#x");
    assert_string_equal(channel_named("#y")->mode.redir, "#x");
    /* the local stayer of #first was told where it points now */
    assert_string_equal(sent_to(carol, sent_count_to(carol) - 1),
                        ":me.example MODE #first +L #x");
    /* #first's deadline is its own; the crossing pair shares the later */
    assert_int_equal(timers_at(1000500), 1);
    assert_int_equal(timers_at(1000900), 2);
    assert_int_equal(ntimers, 3);
  }
}

/* The loser's channel emptied and was collected here before the winner
 * arrived.  The servers that heard the winner first made that channel
 * and hold it as a tombstone until the deadline; so must this one, or it
 * is swept on some servers and not on others. */
static void crossing_loser_that_emptied_here_is_a_tombstone_all_the_same(void **state)
{
  struct Crossing w;
  struct Channel *y;
  (void)state;

  crossing_world(&w);
  uma_relocates(&w);
  y = channel_named("#y");
  remove_user_from_channel(w.uma, y);           /* uma parts #y */
  assert_true(was_destroyed(y));
  vic_relocates(&w);

  y = channel_named("#y");
  assert_non_null(y);
  assert_int_equal(y->users, 0);
  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(y->creationtime, 500000);
  assert_string_equal(w.old->mode.redir, "#x");
  assert_non_null(member_of(channel_named("#x"), w.vic));
  assert_int_equal(timers_at(1000900), 2);

  advance(900);
  assert_true(was_destroyed(y));
  assert_null(channel_named("#y"));
}

/* ... which is what the server that heard the winner first holds after
 * the same PART. */
static void crossing_loser_that_emptied_after_both(void **state)
{
  struct Crossing w;
  struct Channel *y;
  (void)state;

  crossing_world(&w);
  vic_relocates(&w);
  uma_relocates(&w);
  y = channel_named("#y");
  remove_user_from_channel(w.uma, y);

  assert_false(was_destroyed(y));
  assert_int_equal(y->users, 0);
  assert_string_equal(y->mode.redir, "#x");
  assert_int_equal(timers_at(1000900), 2);
}

/* The losing name is taken here by an unrelated channel: it is left
 * alone, the operators are told, and #old still follows the winner. */
static void crossing_loser_name_taken_here(void **state)
{
  struct Crossing w;
  struct Client *dan = user_on(&me, "dan", "AAG");
  struct Channel *y;
  (void)state;

  crossing_world(&w);
  y = channel_at("#y", 700000, dan);
  vic_relocates(&w);
  forget();
  uma_relocates(&w);

  assert_string_equal(w.old->mode.redir, "#x");
  assert_string_equal(y->mode.redir, "");
  assert_false(y->mode.exmode & EXMODE_PERSIST);
  assert_null(member_of(y, w.uma));
  assert_int_equal(sent_count_to(dan), 0);
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "#y already exists"));
  assert_string_equal(sent_to(w.pa, 0), "BkAAD RN #old #y C 1000600 :to y");
}

/* The winning name is taken here by an unrelated channel: nothing is
 * touched, and the operators are told. */
static void crossing_winner_name_taken_here(void **state)
{
  struct Crossing w;
  struct Client *dan = user_on(&me, "dan", "AAG");
  struct Channel *x;
  (void)state;

  crossing_world(&w);
  x = channel_at("#x", 700000, dan);
  uma_relocates(&w);
  forget();
  vic_relocates(&w);

  assert_string_equal(w.old->mode.redir, "#y");
  assert_null(member_of(x, w.vic));
  assert_false(channel_named("#y")->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(sent_count_to(dan), 0);
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "#x already exists"));
  assert_string_equal(sent_to(w.pb, 0), "BjAAC RN #old #x C 1000900 :to x");
}

/* Three relocations of one channel, in all six orders: the name that
 * sorts first wins, the other two are tombstones redirecting to it, each
 * issuer is in its own channel, and all three records share the latest
 * deadline. */
static void three_way_crossing_converges_in_every_order(void **state)
{
  static const int orders[6][3] = {
    {0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {1, 2, 0}, {2, 0, 1}, {2, 1, 0},
  };
  static const char *const target[3] = { "#p", "#q", "#r" };
  static const char *const deadline[3] = { "1000600", "1000900", "1000700" };
  int o, i;
  (void)state;

  for (o = 0; o < 6; o++) {
    struct Client *peer[3], *who[3];
    struct Channel *oldch;

    if (o) {
      world_teardown(NULL);
      world_setup(NULL);
    }
    peer[0] = linked("a.example", "Bj", "v");
    peer[1] = linked("b.example", "Bk", "v");
    peer[2] = linked("c.example", "Bl", "v");
    who[0] = user_on(peer[0], "one", "AAC");
    who[1] = user_on(peer[1], "two", "AAD");
    who[2] = user_on(peer[2], "three", "AAE");
    oldch = channel_at("#old", 500000, who[0]);
    add_member(oldch, who[1], CHFL_CHANOP);
    add_member(oldch, who[2], CHFL_CHANOP);

    for (i = 0; i < 3; i++) {
      int n = orders[o][i];
      server_relocate(peer[n], who[n], "#old", target[n], deadline[n], "");
    }

    assert_string_equal(oldch->mode.redir, "#p");
    assert_int_equal(oldch->users, 0);
    assert_false(channel_named("#p")->mode.exmode & EXMODE_PERSIST);
    assert_string_equal(channel_named("#p")->mode.redir, "");
    assert_string_equal(channel_named("#q")->mode.redir, "#p");
    assert_string_equal(channel_named("#r")->mode.redir, "#p");
    assert_true(channel_named("#q")->mode.exmode & EXMODE_PERSIST);
    assert_true(channel_named("#r")->mode.exmode & EXMODE_PERSIST);
    for (i = 0; i < 3; i++) {
      assert_non_null(member_of(channel_named(target[i]), who[i]));
      assert_int_equal(channel_named(target[i])->users, 1);
    }
    assert_int_equal(ntimers, 3);
    assert_int_equal(timers_at(1000900), 3);
    assert_int_equal(nopnotices, 0);
  }
}

/* --- A.2: a tombstone is announced in the burst --- */

/** "<sptr> RT <old> <ts> <new> <expires>" arriving on link @a cptr. */
static void server_tombstone(struct Client *cptr, struct Client *sptr,
                             const char *oldname, const char *ts,
                             const char *newname, const char *expires)
{
  char store[4][256];
  char *parv[6];

  parv[0] = cli_name(sptr);
  snprintf(store[0], sizeof(store[0]), "%s", oldname);
  parv[1] = store[0];
  snprintf(store[1], sizeof(store[1]), "%s", ts);
  parv[2] = store[1];
  snprintf(store[2], sizeof(store[2]), "%s", newname);
  parv[3] = store[2];
  snprintf(store[3], sizeof(store[3]), "%s", expires);
  parv[4] = store[3];
  parv[5] = NULL;
  ms_tombstone(cptr, sptr, 5, parv);
}

/** What server_finish_burst() does for each channel after its BURST. */
static void burst_to(struct Client *link)
{
  int i;
  for (i = 0; i < nchannels; i++)
    if (channels[i])
      relocate_burst(link, channels[i]);
}

/* A server that links mid-grace is sent the record after the channel's
 * BURST: the old name, the old channel's creation timestamp, the target
 * and the deadline.  A fork server gets it and so does a rename-capable
 * one that is not IRCv3-aware (X3); a plain legacy server never does. */
static void tombstone_is_announced_in_the_burst(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *fork, *x3, *legacy;
  (void)state;

  add_member(channel_at("#old", 500000, bob), carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");

  fork = linked("new.example", "Bn", "v");
  x3 = linked("x3.services", "AX", "sr");
  legacy = linked("old.example", "Bo", "");
  forget();

  burst_to(fork);
  burst_to(x3);
  burst_to(legacy);

  /* one line each: the tombstone, not the channel it redirects to */
  assert_int_equal(sent_count_to(fork), 1);
  assert_string_equal(sent_to(fork, 0), "AC RT #old 500000 #new 1000900");
  assert_int_equal(sent_count_to(x3), 1);
  assert_string_equal(sent_to(x3, 0), "AC RT #old 500000 #new 1000900");
  assert_int_equal(sent_count_to(legacy), 0);
}

/* An ordinary channel that is +z and +L (services' persist, an op's
 * overflow redirect) is nobody's tombstone and is not announced. */
static void ordinary_persistent_redirecting_channel_is_not_announced(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *fork;
  struct Channel *ch;
  (void)state;

  ch = channel_at("#lobby", 500000, alice);
  ch->mode.exmode |= EXMODE_PERSIST;
  ch->mode.limit = 50;
  ircd_strncpy(ch->mode.redir, "#overflow", sizeof(ch->mode.redir));

  fork = linked("new.example", "Bn", "v");
  burst_to(fork);
  assert_int_equal(sent_count_to(fork), 0);
}

/* A tombstone a chanop took +L off is not one any more (its record only
 * waits to hand +z back): not announced. */
static void cancelled_tombstone_is_not_announced(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *fork;
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  /* MODE #old -L */
  oldch->mode.redir[0] = '\0';

  fork = linked("new.example", "Bn", "v");
  forget();
  burst_to(fork);
  assert_int_equal(sent_count_to(fork), 0);
}

/* After a crossing both tombstones are announced, each with the shared
 * deadline and the winner as its target; a chain's old names with the
 * flattened target. */
static void crossing_and_chain_are_announced_as_they_stand(void **state)
{
  struct Crossing w;
  struct Client *zed, *fork;
  struct Channel *first;
  int i, old = 0, y = 0, f = 0;
  (void)state;

  crossing_world(&w);
  zed = user_on(w.pa, "zed", "AAF");
  first = channel_at("#first", 400000, zed);
  server_relocate(w.pa, zed, "#first", "#x", "1000500", "");
  remove_user_from_channel(zed, channel_named("#x"));   /* zed leaves; #x is free */
  (void)first;
  uma_relocates(&w);
  vic_relocates(&w);

  fork = linked("new.example", "Bn", "v");
  forget();
  burst_to(fork);

  assert_int_equal(sent_count_to(fork), 3);
  for (i = 0; i < 3; i++) {
    const char *line = sent_to(fork, i);

    if (0 == strcmp(line, "AC RT #old 500000 #x 1000900")) old++;
    if (0 == strcmp(line, "AC RT #y 500000 #x 1000900")) y++;
    if (0 == strcmp(line, "AC RT #first 400000 #x 1000500")) f++;
  }
  assert_int_equal(old, 1);
  assert_int_equal(y, 1);
  assert_int_equal(f, 1);
}

/* An announcement is relayed the way burst state is, so a server two
 * hops from the newcomer learns of the tombstone too: to the other fork
 * links and the rename-capable ones, as it came, never back, never to a
 * plain legacy server. */
static void announcement_is_relayed_like_burst_state(void **state)
{
  struct Client *peer = linked("new.example", "Bn", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *legacy = linked("old.example", "Bo", "");
  struct Client *far = behind(peer, "far.example", "Bf", "v");
  (void)state;

  server_tombstone(peer, far, "#old", "500000", "#new", "1000900");

  assert_string_equal(sent_to(down, 0), "Bf RT #old 500000 #new 1000900");
  assert_string_equal(sent_to(x3, 0), "Bf RT #old 500000 #new 1000900");
  assert_int_equal(sent_count_to(peer), 0);
  assert_int_equal(sent_count_to(legacy), 0);
  assert_int_equal(nviolations, 0);
}

/* What is not an announcement is refused from the message alone -- the
 * same on every server, so it is not relayed either. */
static void malformed_announcement_is_refused_and_not_relayed(void **state)
{
  struct Client *peer = linked("new.example", "Bn", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  char *parv[6];
  char a[] = "#old", b[] = "500000", c[] = "#new";
  (void)state;

  server_tombstone(peer, peer, "#old", "soon", "#new", "1000900");
  server_tombstone(peer, peer, "#old", "500000", "#new", "-1");
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900 ");
  server_tombstone(peer, peer, "&old", "500000", "#new", "1000900");
  server_tombstone(peer, peer, "#old", "500000", "&new", "1000900");
  server_tombstone(peer, peer, "#old", "500000", "#ne,w", "1000900");
  server_tombstone(peer, peer, "old", "500000", "#new", "1000900");
  /* a channel that redirects to itself */
  server_tombstone(peer, peer, "#old", "500000", "#OLD", "1000900");
  assert_int_equal(nviolations, 8);
  /* from a user: no server sends that */
  server_tombstone(peer, bob, "#old", "500000", "#new", "1000900");
  assert_int_equal(nviolations, 9);
  /* too short */
  parv[0] = cli_name(peer); parv[1] = a; parv[2] = b; parv[3] = c; parv[4] = NULL;
  ms_tombstone(peer, peer, 4, parv);
  assert_int_equal(nviolations, 10);

  assert_int_equal(sent_count_to(down), 0);
  assert_int_equal(ntimers, 0);
}

/* --- A.3 / A.4: acting on an announcement --- */

/** A channel as the BURST of a tombstone leaves it on a server that had
 * no such channel or held it as an ordinary one: +z, +L @a target --
 * exactly what mode_parse() writes for "+zL <target>": the persist bit in
 * mode.exmode and the target in mode.redir.  No MODE_REDIRECT bit; there
 * is no such thing in a real channel. */
static struct Channel *burst_tombstone(const char *name, time_t ts,
                                       const char *target, struct Client *who)
{
  struct Channel *ch = fake_channel(name);

  ch->creationtime = ts;
  ch->mode.exmode |= EXMODE_PERSIST;
  ircd_strncpy(ch->mode.redir, target, sizeof(ch->mode.redir));
  if (who)
    add_member(ch, who, 0);
  return ch;
}

/* The server that healed a netsplit (or linked) mid-grace: the BURST gave
 * it "+z +L #new", the announcement gives it the record.  Its local
 * members -- who were never told the channel moved -- are told now, can
 * regain their status if they follow, and the tombstone is dissolved at
 * the deadline everybody else has. */
static void announcement_builds_the_record(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAG");
  struct Channel *oldch, *newch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#new", bob);
  add_member(oldch, carol, CHFL_CHANOP);
  add_member(oldch, dan, CHFL_CHANOP);
  /* our side still had +l */
  oldch->mode.limit = 10;
  newch = channel_at("#new", 500000, bob);

  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");

  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(ntimers, 1);
  /* the limit would keep the redirect from firing */
  assert_int_equal(oldch->mode.limit, 0);
  assert_non_null(strstr(sent_to(carol, 0),
                         "NOTICE #old :#old has moved to #new. Join #new to "
                         "follow; this channel closes in 15 minutes."));
  assert_int_equal(sent_count_to(carol), 1);
  assert_string_equal(sent_to(down, 0), "Bj RT #old 500000 #new 1000900");
  /* a member follows from it as from any tombstone */
  assert_int_equal(joins(dan, newch), CHFL_CHANOP);
  assert_null(member_of(oldch, dan));

  /* and this server now announces it in its own bursts */
  forget();
  burst_to(down);
  assert_string_equal(sent_to(down, 0), "AC RT #old 500000 #new 1000900");

  forget();
  advance(900);
  assert_string_equal(sent_to(carol, 0),
                      ":carol!user@host.example PART #old :Channel has moved to #new");
  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
}

/* With evilnet/channel-relocate the local member gets a RELOCATE, from
 * the server (nobody here knows who relocated the channel). */
static void announcement_tells_a_member_with_the_cap(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAD");
  (void)state;

  CapSet(cli_active(carol), CAP_EVILNET_RELOCATE);
  burst_tombstone("#old", 500000, "#new", carol);
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");
  assert_string_equal(sent_to(carol, 0), ":his.example RELOCATE #old #new :");
}

/* The receiver had already dissolved its copy; the sender's BURST brought
 * the channel back and its announcement says the deadline is past: gone
 * again at once, and the stale deadline is passed on as it came. */
static void announcement_with_a_past_deadline_dissolves_at_once(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#new", bob);
  server_tombstone(peer, peer, "#old", "500000", "#new", "999990");

  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
  assert_string_equal(sent_to(down, 0), "Bj RT #old 500000 #new 999990");
}

/* ... or still ahead: the tombstone is back until then (the later
 * deadline wins also against a server that had none left). */
static void announcement_restores_a_tombstone_the_receiver_had_dissolved(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#new", bob);
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000040");
  assert_int_equal(timers_at(1000040), 1);
  advance(40);
  assert_true(was_destroyed(oldch));
}

static void announcement_with_an_absurd_deadline_is_clamped(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  (void)state;

  burst_tombstone("#old", 500000, "#new", bob);
  server_tombstone(peer, peer, "#old", "500000", "#new", "2147483647");
  assert_int_equal(timers_at(1000000 + RELOCATE_GRACE_MAX), 1);
}

/* A registered channel is not left out: the record is built, and the +R
 * decides at the deadline -- here it is still set, so the tombstone is
 * cancelled and nobody is parted. */
static void announcement_for_a_registered_channel_builds_the_record_too(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#new", carol);
  oldch->mode.mode |= MODE_REGISTERED;
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");

  assert_int_equal(timers_at(1000900), 1);
  assert_true(oldch->mode.mode & MODE_REGISTERED);
  assert_string_equal(oldch->mode.redir, "#new");

  advance(900);
  assert_non_null(member_of(oldch, carol));
  assert_string_equal(oldch->mode.redir, "");
  assert_true(oldch->mode.mode & MODE_REGISTERED);
  assert_false(was_destroyed(oldch));
}

/* ... and with the stray +R taken back in time, swept. */
static void announced_registered_tombstone_is_swept_once_unregistered(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#new", carol);
  oldch->mode.mode |= MODE_REGISTERED;
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");
  oldch->mode.mode &= ~MODE_REGISTERED;                 /* M #old -R */
  advance(900);
  assert_true(was_destroyed(oldch));
}

/* The BURST lost on timestamp here: our channel of that name is older,
 * and is not the sender's tombstone.  Nothing is built; the line still
 * goes on. */
static void announcement_for_another_incarnation_is_ignored(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *ours;
  (void)state;

  ours = channel_at("#old", 400000, carol);
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");

  assert_int_equal(ntimers, 0);
  assert_int_equal(sent_count_to(carol), 0);
  assert_string_equal(ours->mode.redir, "");
  assert_string_equal(sent_to(down, 0), "Bj RT #old 500000 #new 1000900");
  advance(900);
  assert_non_null(member_of(ours, carol));
}

static void announcement_for_a_channel_not_here_is_ignored(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  (void)state;

  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");
  assert_int_equal(ntimers, 0);
  assert_null(channel_named("#old"));
  assert_string_equal(sent_to(down, 0), "Bj RT #old 500000 #new 1000900");
}

/* The channel is the one, but the burst merge left it with another
 * redirect (an op's own +L here sorted first): on the sender the
 * tombstone has lost its redirect the same way.  The record is kept, as
 * the sender's is, and at the deadline nobody is parted and +z goes. */
static void announcement_for_a_channel_with_another_redirect(void **state)
{
  struct Client *peer = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#aaa", carol);
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");

  assert_int_equal(timers_at(1000900), 1);
  assert_string_equal(oldch->mode.redir, "#aaa");       /* not imposed */
  assert_int_equal(sent_count_to(carol), 0);            /* not a tombstone here */

  advance(900);
  assert_non_null(member_of(oldch, carol));
  assert_string_equal(oldch->mode.redir, "#aaa");
  assert_false(oldch->mode.exmode & EXMODE_PERSIST);
  {
    int i, said = 0;
    for (i = 0; i < ndebug; i++)
      if (strstr(debuglines[i], "(redirect was retargeted)"))
        said = 1;
    assert_true(said);
  }
}

/* Both sides hold the tombstone, with deadlines of their own (one side
 * was behind an older server): one deadline, the later, whichever side
 * this server is on. */
static void announcement_for_a_tombstone_held_here_keeps_the_later_deadline(void **state)
{
  struct Crossing w;
  struct Client *hub;
  (void)state;

  crossing_world(&w);
  hub = linked("hub.example", "Bh", "v");
  server_relocate(w.pa, w.vic, "#old", "#new", "1000300", "");
  forget();

  server_tombstone(hub, hub, "#old", "500000", "#new", "1000900");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000900), 1);
  assert_int_equal(sent_count_to(w.carol), 0);          /* told long ago */

  /* an earlier one changes nothing ... */
  server_tombstone(hub, hub, "#old", "500000", "#NEW", "1000100");
  assert_int_equal(timers_at(1000900), 1);
  /* ... nor does one that is already past: the record's timer is armed,
   * and stays so */
  server_tombstone(hub, hub, "#old", "500000", "#new", "999000");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000900), 1);
  assert_ptr_equal(channel_named("#old"), w.old);

  /* what this server announces is the merged deadline */
  forget();
  burst_to(hub);
  assert_string_equal(sent_to(hub, 0), "AC RT #old 500000 #new 1000900");
}

/* The record's own deadline is due this second and its timer has not
 * run; an announcement that cannot move it past now arrives.  Dissolved
 * on the spot, the armed record freed through its timer. */
static void announcement_meeting_a_record_that_is_due_dissolves_through_the_timer(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  server_relocate(w.pa, w.vic, "#old", "#new", "1000100", "");
  CurrentTime = 1000100;

  server_tombstone(w.pb, w.pb, "#old", "500000", "#new", "1000050");

  assert_int_equal(ntimers, 0);
  assert_true(was_destroyed(w.old));
  advance(1000);
}

/* Two sides of a netsplit relocated #old to different names.  At the
 * netjoin each side announces its own tombstone; both apply the crossing
 * rule to the pair and end alike.
 *
 * This is the side whose name wins (#x): #old keeps pointing at #x, and
 * the other side's #y is a tombstone redirecting to #x -- here its BURST
 * arrived before the announcement. */
static void disagreeing_announcements_on_the_winning_side(void **state)
{
  struct Crossing w;
  struct Channel *y;
  (void)state;

  crossing_world(&w);
  remove_user_from_channel(w.uma, w.old);       /* uma was across the split */
  vic_relocates(&w);                            /* 1000900 */

  /* the other side's burst: #y with uma, then #old (+L #y loses the +L
   * merge to #x, which sorts first), then the record */
  y = channel_at("#y", 500000, w.uma);
  forget();
  server_tombstone(w.pb, w.pb, "#old", "500000", "#y", "1000600");

  assert_string_equal(w.old->mode.redir, "#x");
  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_non_null(member_of(y, w.uma));
  assert_int_equal(ntimers, 2);
  assert_int_equal(timers_at(1000900), 2);
  assert_int_equal(sent_count_to(w.carol), 0);
  assert_string_equal(sent_to(w.pa, 0), "Bk RT #old 500000 #y 1000600");

  /* the other side announces #y too once it has made it a tombstone
   * (it does that when OUR announcement reaches it): the same record */
  server_tombstone(w.pb, w.pb, "#y", "500000", "#x", "1000900");
  assert_int_equal(ntimers, 2);
  assert_int_equal(timers_at(1000900), 2);

  advance(900);
  assert_true(was_destroyed(w.old));
  assert_true(was_destroyed(y));
  assert_non_null(channel_named("#x"));
}

/* The same side, but the announcement arrives BEFORE the BURST of #y
 * (channels are burst in no particular order).  The loser cannot be made
 * a tombstone yet; it is when its BURST has been taken in. */
static void disagreeing_announcements_before_the_losers_burst(void **state)
{
  struct Crossing w;
  struct Channel *y;
  (void)state;

  crossing_world(&w);
  remove_user_from_channel(w.uma, w.old);
  vic_relocates(&w);

  server_tombstone(w.pb, w.pb, "#old", "500000", "#y", "1000600");
  assert_null(channel_named("#y"));
  assert_string_equal(w.old->mode.redir, "#x");
  assert_int_equal(timers_at(1000900), 2);      /* #old's, and one waiting for #y */

  /* B #y 500000 +n ... uma */
  y = channel_at("#y", 500000, w.uma);
  y->mode.limit = 5;
  relocate_tombstone_burst_done(y);

  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(y->mode.limit, 0);
  assert_int_equal(ntimers, 2);

  advance(900);
  assert_true(was_destroyed(y));
  assert_true(was_destroyed(w.old));
}

/* ... and a channel of another creation timestamp that turns up under
 * the loser's name is not that channel: it is left alone, and the
 * waiting record expires without touching it. */
static void waiting_record_does_not_take_another_channel(void **state)
{
  struct Crossing w;
  struct Client *dan = user_on(&me, "dan", "AAG");
  struct Channel *y;
  (void)state;

  crossing_world(&w);
  remove_user_from_channel(w.uma, w.old);
  vic_relocates(&w);
  server_tombstone(w.pb, w.pb, "#old", "500000", "#y", "1000600");

  y = channel_at("#y", 1000010, dan);           /* a stranger's #y */
  relocate_tombstone_burst_done(y);
  assert_string_equal(y->mode.redir, "");
  assert_false(y->mode.exmode & EXMODE_PERSIST);

  /* nor does the stranger's channel going away take the waiting record
   * with it: the real #y may still be burst */
  remove_user_from_channel(dan, y);
  assert_true(was_destroyed(y));
  assert_int_equal(ntimers, 2);

  /* a second stranger's #y, +z by services, is there at the deadline */
  y = channel_at("#y", 1000020, dan);
  y->mode.exmode |= EXMODE_PERSIST;
  forget();
  advance(900);
  assert_non_null(member_of(y, dan));
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(sent_count_to(dan), 0);
  assert_int_equal(nopnotices, 0);
  assert_int_equal(ntimers, 0);
}

/* The side whose name loses (#y, with uma local): the BURST's +L merge
 * has already pointed #old at #x; the announcement makes that the
 * record's target, turns the local #y into a tombstone redirecting to #x
 * and tells uma. */
static void disagreeing_announcements_on_the_losing_side(void **state)
{
  struct Client *hub = linked("hub.example", "Bh", "v");
  struct Client *vic = user_on(hub, "vic", "AAC");
  struct Client *uma = user_on(&me, "uma", "AAD");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch, *y, *x;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 600;
  oldch = channel_at("#old", 500000, uma);
  add_member(oldch, carol, CHFL_VOICE);
  client_rename(uma, "#old", "#y", "to y");     /* deadline 1000600 */
  y = channel_named("#y");

  /* the hub's burst: #x with vic; #old "+z +L #x" (merged: #x sorts
   * first); then the record */
  x = channel_at("#x", 500000, vic);
  ircd_strncpy(oldch->mode.redir, "#x", sizeof(oldch->mode.redir));
  forget();
  server_tombstone(hub, hub, "#old", "500000", "#x", "1000900");

  assert_string_equal(oldch->mode.redir, "#x");
  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_non_null(member_of(y, uma));
  assert_int_equal(ntimers, 2);
  assert_int_equal(timers_at(1000900), 2);
  /* uma, in the loser, is told like any stayer */
  assert_non_null(strstr(sent_to(uma, 0), "NOTICE #y :#y has moved to #x. Join #x"));
  assert_string_equal(sent_to(uma, 1), ":me.example MODE #y +L #x");
  /* carol, in #old, and uma, in the loser, both follow into the winner */
  assert_int_equal(joins(carol, x), CHFL_VOICE);
  assert_null(member_of(oldch, carol));
  assert_int_equal(joins(uma, x), CHFL_CHANOP);
  assert_null(member_of(y, uma));

  /* what this side announces from now on is the agreed state */
  forget();
  burst_to(hub);
  assert_int_equal(sent_count_to(hub), 2);
}

/* The losing side again, with two things the first case leaves out: the
 * BURST's merge did not change #old's redirect (whatever the reason, the
 * announcement must), and an earlier tombstone -- #first, relocated to
 * #old before -- pointed at the loser and has to follow to the winner. */
static void disagreeing_announcements_retarget_everything_on_the_losing_side(void **state)
{
  struct Client *hub = linked("hub.example", "Bh", "v");
  struct Client *zed = user_on(&me, "zed", "AAF");
  struct Client *uma = user_on(&me, "uma", "AAD");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *first, *oldch, *y;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 600;
  first = channel_at("#first", 500000, zed);
  add_member(first, carol, 0);
  client_rename(zed, "#first", "#old", "");
  oldch = channel_named("#old");
  add_member(oldch, uma, CHFL_CHANOP);
  client_rename(uma, "#old", "#y", "");
  y = channel_named("#y");
  assert_string_equal(first->mode.redir, "#y");
  assert_string_equal(oldch->mode.redir, "#y");
  forget();

  server_tombstone(hub, hub, "#old", "500000", "#x", "1000900");

  assert_string_equal(oldch->mode.redir, "#x");
  assert_string_equal(first->mode.redir, "#x");
  assert_string_equal(y->mode.redir, "#x");
  /* zed, left in #old, and carol, left in #first, see where they point */
  assert_string_equal(sent_to(zed, 0), ":me.example MODE #old +L #x");
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #first +L #x");
  /* #first keeps its own deadline; #old and #y share the later */
  assert_int_equal(timers_at(1000600), 1);
  assert_int_equal(timers_at(1000900), 2);

  /* and all three are announced that way */
  forget();
  burst_to(hub);
  assert_int_equal(sent_count_to(hub), 3);
}

/* --- A.4: what a BURST does to a tombstone held here --- */

/* The channel loses the BURST on timestamp: it is another server's older
 * channel now, wiped as any loser is.  The tombstone is over at that
 * moment -- record dropped, and the +z, which the wipe-out leaves alone,
 * taken off (if the winner is itself +z its BURST sets it again). */
static void tombstone_that_loses_a_burst_on_timestamp_is_cancelled(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  vic_relocates(&w);
  assert_int_equal(ntimers, 1);

  relocate_tombstone_ts_lost(w.old);

  assert_int_equal(ntimers, 0);
  assert_false(w.old->mode.exmode & EXMODE_PERSIST);
  assert_non_null(member_of(w.old, w.carol));
  advance(900);
  assert_non_null(member_of(w.old, w.carol));
}

/* A BURST for an ordinary channel changes nothing through either hook. */
static void burst_hooks_leave_ordinary_channels_alone(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Channel *ch;
  (void)state;

  ch = channel_at("#plain", 500000, alice);
  ch->mode.exmode |= EXMODE_PERSIST;
  ch->mode.limit = 7;
  relocate_tombstone_ts_lost(ch);
  relocate_tombstone_burst_done(ch);
  assert_true(ch->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(ch->mode.limit, 7);
}

/* The other side still held the channel as an ordinary one with +l; the
 * merge put the limit on our tombstone, where it would stop the redirect
 * from firing.  Stripped again when the BURST has been taken in. */
static void burst_cannot_leave_a_limit_on_a_tombstone(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  vic_relocates(&w);

  /* B #old 500000 +l 10 ... */
  w.old->mode.limit = 10;
  relocate_tombstone_burst_done(w.old);

  assert_int_equal(w.old->mode.limit, 0);
  assert_string_equal(w.old->mode.redir, "#x");
  assert_int_equal(timers_at(1000900), 1);
}

/* --- the bed's netjoin (2026-11-11, sync 4) ---
 *
 * #rssp, created on the hub and joined from the leaf, same creation
 * timestamp on both.  The leaf splits away; the hub's only member
 * relocates the channel (1 moved, 0 stayed: an EMPTY tombstone); the leaf
 * links again inside the grace.  On the bed the leaf told its member
 * nothing and at the deadline logged "no longer authenticates (+L was
 * cleared)": it had looked for a MODE_REDIRECT bit that a BURST's +L
 * never sets. */

/* The leaf.  What it holds when the announcement arrives is exactly what
 * the hub's "B #rssp <ts> +tnzL #rsspn" made of its own channel. */
static void netjoin_leaf_with_a_local_member_gets_the_tombstone(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *issuer = user_on(hub, "issuer", "AA7");
  struct Client *stayer = user_on(&me, "stayer", "AAE");
  struct Client *other = user_on(&me, "other", "AAF");
  struct Channel *oldch, *newch;
  (void)state;

  /* ours since before the split: +tn, our member (voiced, say) */
  oldch = fake_channel("#rssp");
  oldch->creationtime = 500000;
  oldch->mode.mode |= MODE_TOPICLIMIT | MODE_NOPRIVMSGS;
  add_member(oldch, stayer, CHFL_VOICE);
  add_member(oldch, other, CHFL_VOICE);

  /* Bj B #rsspn 500000 +tn BjAA7:o */
  newch = channel_at("#rsspn", 500000, issuer);
  /* Bj B #rssp 500000 +tnzL #rsspn -- merged at the equal timestamp */
  oldch->mode.exmode |= EXMODE_PERSIST;
  ircd_strncpy(oldch->mode.redir, "#rsspn", sizeof(oldch->mode.redir));
  relocate_tombstone_burst_done(oldch);
  /* Bj RT #rssp 500000 #rsspn 1000045 */
  server_tombstone(hub, hub, "#rssp", "500000", "#rsspn", "1000045");

  /* Defect 1: the members are told NOW */
  assert_int_equal(sent_count_to(other), 1);
  assert_int_equal(sent_count_to(stayer), 1);
  assert_non_null(strstr(sent_to(stayer, 0),
                         "NOTICE #rssp :#rssp has moved to #rsspn. Join "
                         "#rsspn to follow; this channel closes in 0 minutes."));
  assert_int_equal(timers_at(1000045), 1);
  /* ... one of them follows, with its status ... */
  assert_int_equal(joins(other, newch), CHFL_VOICE);
  assert_null(member_of(oldch, other));
  /* ... and the leaf announces the tombstone onward as its own */
  forget();
  burst_to(hub);
  assert_string_equal(sent_to(hub, 0), "AC RT #rssp 500000 #rsspn 1000045");

  /* Defect 2: at the deadline the tombstone IS one -- swept, dissolved */
  forget();
  advance(45);
  assert_string_equal(sent_to(stayer, 0),
                      ":stayer!user@host.example PART #rssp :Channel has moved to #rsspn");
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#rssp"));
  assert_int_equal(nopnotices, 0);
  assert_int_equal(ntimers, 0);
}

/* The same leaf when its member has left before the deadline (the bed
 * run: the test client quit).  The empty tombstone stays what it is --
 * +z, redirecting, recorded -- until the deadline, and is dissolved then:
 * not "cancelled", and not by accident. */
static void netjoin_leaf_whose_member_left_keeps_the_tombstone(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *stayer = user_on(&me, "stayer", "AAE");
  struct Channel *oldch;
  int i;
  (void)state;

  oldch = burst_tombstone("#rssp", 500000, "#rsspn", stayer);
  server_tombstone(hub, hub, "#rssp", "500000", "#rsspn", "1000045");
  remove_user_from_channel(stayer, oldch);              /* QUIT */

  assert_false(was_destroyed(oldch));
  assert_string_equal(oldch->mode.redir, "#rsspn");
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  advance(44);
  assert_false(was_destroyed(oldch));
  assert_string_equal(oldch->mode.redir, "#rsspn");
  assert_int_equal(timers_at(1000045), 1);

  advance(1);
  assert_true(was_destroyed(oldch));
  assert_int_equal(nopnotices, 0);
  /* swept and dissolved, said the log -- not "no longer authenticates" */
  for (i = 0; i < ndebug; i++)
    assert_null(strstr(debuglines[i], "no longer authenticates"));
}

/* The hub.  Its tombstone was empty; the leaf's BURST puts the leaf's
 * member into it.  Nothing about the tombstone changes, and at the
 * deadline the hub removes that REMOTE member from its copy and destroys
 * the channel without a word to anybody: the member's own server parts it
 * at the same instant (previous two cases), which is what makes the two
 * agree that the channel is gone and nobody is in it. */
static void netjoin_hub_with_an_empty_tombstone_takes_the_leafs_member(void **state)
{
  struct Client *leaf;
  struct Client *issuer = user_on(&me, "issuer", "AA7");
  struct Client *stayer;
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  feat_relocate_grace = 45;
  oldch = channel_at("#rssp", 500000, issuer);
  oldch->mode.mode |= MODE_TOPICLIMIT | MODE_NOPRIVMSGS;
  client_rename(issuer, "#rssp", "#rsspn", "during the split");
  assert_int_equal(oldch->users, 0);

  leaf = linked("leaf.example", "AD", "v");
  stayer = user_on(leaf, "stayer", "AAE");
  forget();
  /* our burst to the leaf carries the record */
  burst_to(leaf);
  assert_string_equal(sent_to(leaf, 0), "AC RT #rssp 500000 #rsspn 1000045");
  /* AD B #rssp 500000 +tn ADAAE */
  add_member(oldch, stayer, 0);
  relocate_tombstone_burst_done(oldch);

  assert_string_equal(oldch->mode.redir, "#rsspn");
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(timers_at(1000045), 1);
  assert_int_equal(oldch->users, 1);

  forget();
  advance(45);
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#rssp"));
  assert_int_equal(nsent, 0);           /* no server, no client */
  assert_int_equal(nopnotices, 0);
  assert_int_equal(ntimers, 0);
}

/* An empty tombstone -- the issuer was the only member -- keeps its marks
 * and its record for the whole grace: the name stays redirected. */
static void empty_tombstone_lasts_until_its_deadline(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *down;
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  client_rename(alice, "#old", "#new", "");
  assert_int_equal(oldch->users, 0);

  advance(899);
  assert_false(was_destroyed(oldch));
  assert_ptr_equal(channel_named("#old"), oldch);
  assert_string_equal(oldch->mode.redir, "#new");
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(timers_at(1000900), 1);
  down = linked("down.example", "Bk", "v");
  burst_to(down);
  assert_string_equal(sent_to(down, sent_count_to(down) - 1),
                      "AC RT #old 500000 #new 1000900");

  advance(1);
  assert_true(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
}

/* The last LOCAL member of a tombstone leaves mid-grace; members on other
 * servers are still in it.  Nothing about the tombstone changes. */
static void last_local_member_leaving_changes_nothing(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *dave = user_on(peer, "dave", "AAD");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, dave, 0);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");

  advance(100);
  remove_user_from_channel(carol, oldch);               /* PART #old */
  assert_string_equal(oldch->mode.redir, "#new");
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_non_null(member_of(oldch, dave));
  assert_int_equal(timers_at(1000900), 1);

  /* and the remote one too */
  remove_user_from_channel(dave, oldch);
  assert_false(was_destroyed(oldch));
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(timers_at(1000900), 1);

  forget();
  advance(800);
  assert_true(was_destroyed(oldch));
  assert_int_equal(nsent, 0);
  assert_int_equal(nopnotices, 0);
}

/* The other mark: services took +z off the tombstone (MODE -z).  It is
 * not a tombstone any more -- the existing cancellation, unchanged: at the
 * deadline nobody is parted, and it is not announced meanwhile. */
static void tombstone_that_lost_its_persist_flag_is_not_swept(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch;
  int i, said = 0;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->mode.exmode &= ~EXMODE_PERSIST;                /* M #old -z */
  forget();

  burst_to(peer);
  assert_int_equal(sent_count_to(peer), 0);

  advance(900);
  assert_non_null(member_of(oldch, carol));
  assert_int_equal(sent_count_to(carol), 0);
  assert_false(was_destroyed(oldch));
  assert_int_equal(ntimers, 0);
  for (i = 0; i < ndebug; i++)
    if (strstr(debuglines[i], "no longer authenticates")
        && strstr(debuglines[i], "+z was cleared"))
      said = 1;
  assert_true(said);
}

/* Dissolving a tombstone whose members are all on other servers: each is
 * removed from this server's copy, nothing is sent to any server or
 * client, and the channel is destroyed. */
static void dissolve_with_only_remote_members(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *dave = user_on(peer, "dave", "AAD");
  struct Client *eve = user_on(peer, "eve", "AAF");
  struct Channel *oldch;
  (void)state; (void)x3;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, dave, CHFL_CHANOP);
  add_member(oldch, eve, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  assert_int_equal(oldch->users, 2);
  forget();

  advance(900);
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
  assert_int_equal(nsent, 0);
  assert_int_equal(nopnotices, 0);
  assert_int_equal(ntimers, 0);
}

/* --- a record is bound to its channel: name AND creation timestamp --- */

static int logged(const char *what)
{
  int i;
  for (i = 0; i < ndebug; i++)
    if (strstr(debuglines[i], what))
      return 1;
  return 0;
}

/* The channel under the old name is ANOTHER one -- another creation
 * timestamp -- and it happens to be +z with the same redirect (services'
 * persist, an op's +L to the same place, a burst).  Name and marks all
 * match; the record was not made for it.  Its members are not swept, its
 * +z is not taken, and the log says why. */
static void another_channel_with_the_same_marks_is_not_swept(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Client *fork;
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");

  /* the channel under the name is replaced by one created later, by a
   * path that told the engine nothing; +z and +L #new are on it */
  oldch->creationtime = 600000;
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(oldch->mode.redir, "#new");

  /* not announced as the tombstone meanwhile */
  fork = linked("new.example", "Bn", "v");
  forget();
  burst_to(fork);
  assert_int_equal(sent_count_to(fork), 0);

  advance(900);
  assert_non_null(member_of(oldch, carol));
  assert_int_equal(sent_count_to(carol), 0);
  assert_false(was_destroyed(oldch));
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);     /* not ours to take */
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(nopnotices, 0);
  assert_int_equal(ntimers, 0);
  /* the reason given is the true one */
  assert_true(logged("another channel"));
  assert_true(logged("600000"));
  assert_false(logged("+L was cleared"));
  assert_false(logged("+z was cleared"));
  assert_false(logged("retargeted"));
}

/* The same through the ordinary route: the tombstone is destroyed
 * (services DESTRUCT) and somebody creates the name again; services
 * persist it and it is given the same redirect.  The record went with the
 * first channel; nothing happens to the second at the old deadline, and
 * an announcement of the FIRST (its timestamp) is not about it. */
static void recreated_channel_is_nobodys_tombstone(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch, *again;
  char name[] = "#old";
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->mode.exmode &= ~EXMODE_PERSIST;
  sub1_from_channel(oldch);                     /* DESTRUCT */
  assert_true(was_destroyed(oldch));

  again = get_channel(carol, name, CGT_CREATE); /* created at 1000000 */
  add_member(again, carol, CHFL_CHANOP);
  again->mode.exmode |= EXMODE_PERSIST;
  ircd_strncpy(again->mode.redir, "#new", sizeof(again->mode.redir));

  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");
  assert_int_equal(ntimers, 0);

  advance(900);
  assert_non_null(member_of(again, carol));
  assert_true(again->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(again->mode.redir, "#new");
  assert_int_equal(sent_count_to(carol), 0);
}

/* A relocation of such a channel is a relocation of THAT channel: the
 * stale record under its name is dropped, and the +z, which is the
 * channel's own, goes to the new channel with the rest of its state. */
static void relocating_another_channel_under_a_stale_record(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAF");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->creationtime = 600000;                 /* another channel now */

  server_relocate(peer, eve, "#old", "#second", "1002000", "");

  assert_true(channel_named("#second")->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(channel_named("#second")->creationtime, 600000);
  assert_non_null(member_of(channel_named("#second"), eve));
  assert_string_equal(oldch->mode.redir, "#second");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1002000), 1);
}

/* A stale record under the name is in nobody's way.  The channel that
 * has the name now (another timestamp) is announced as a tombstone in its
 * own right: a record is built for IT, and it is swept at ITS deadline. */
static void announcement_for_another_channel_under_a_stale_record(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->creationtime = 600000;                 /* another channel now */

  server_tombstone(peer, peer, "#old", "600000", "#new", "1000300");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000300), 1);

  advance(300);
  assert_true(was_destroyed(oldch));
  assert_false(logged("another channel"));
}

/* ... losing to an older timestamp, it keeps what is its own: only the
 * stale record goes. */
static void another_channel_under_a_stale_record_is_wiped_as_itself(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->creationtime = 600000;
  forget();

  relocate_tombstone_ts_lost(oldch);
  assert_int_equal(ntimers, 0);
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(sent_count_to(carol), 0);
}

/* ... and renamed, it does not take the stale record along. */
static void another_channel_under_a_stale_record_is_renamed_as_itself(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAF");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch, *renamed;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  oldch->creationtime = 600000;

  server_rename(peer, eve, "#old", "#older", "");
  renamed = channel_named("#older");
  assert_non_null(renamed);
  assert_int_equal(ntimers, 0);

  advance(900);
  assert_non_null(member_of(renamed, carol));
  assert_false(was_destroyed(renamed));
}

/* The channel's timestamp is corrected without the channel being wiped:
 * a MODE or CREATE carrying an older timestamp, a BURST for an empty
 * channel a few seconds off.  It is the same channel with its marks; the
 * record follows the timestamp, and so does a record that points AT the
 * channel (which knows the channel to follow into by that timestamp). */
static void record_follows_a_corrected_timestamp(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Client *down;
  struct Channel *oldch, *newch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_VOICE);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  newch = channel_named("#new");

  oldch->creationtime = 499998;                 /* M #old +m 499998 */
  relocate_tombstone_ts_follow(oldch, 500000);
  newch->creationtime = 499998;                 /* the same for #new */
  relocate_tombstone_ts_follow(newch, 500000);

  /* still the tombstone: announced with its timestamp of now ... */
  down = linked("down.example", "Bk", "v");
  burst_to(down);
  assert_string_equal(sent_to(down, sent_count_to(down) - 1),
                      "AC RT #old 499998 #new 1000900");
  /* ... a member still follows into the new channel ... */
  assert_int_equal(joins(carol, newch), CHFL_VOICE);
  assert_null(member_of(oldch, carol));
  /* ... and dissolved at the deadline */
  advance(900);
  assert_true(was_destroyed(oldch));
  assert_false(logged("no longer authenticates"));
}

/* ... and nothing follows a timestamp that is not the record's. */
static void follow_leaves_other_records_alone(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Channel *oldch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");

  oldch->creationtime = 700000;
  relocate_tombstone_ts_follow(oldch, 650000);  /* not the record's 500000 */

  advance(900);
  assert_non_null(member_of(oldch, carol));     /* not swept */
  assert_true(logged("another channel"));
}

/* The channel is WIPED for an older timestamp outside a burst: a remote
 * JOIN carrying one (m_join.c takes the modes, the limit and the keys,
 * deops everybody -- and leaves +z and the redirect standing).  The
 * tombstone is over at that moment, as when it loses a BURST: record
 * dropped, +z off, and its redirect withdrawn, so that what is left is an
 * ordinary channel and not a tombstone nobody will ever dissolve. */
static void tombstone_wiped_for_an_older_timestamp_is_ended(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  vic_relocates(&w);
  forget();

  relocate_tombstone_ts_lost(w.old);
  w.old->creationtime = 400000;

  assert_int_equal(ntimers, 0);
  assert_false(w.old->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(w.old->mode.redir, "");
  assert_string_equal(sent_to(w.carol, 0), ":me.example MODE #old -L");
  assert_non_null(member_of(w.old, w.carol));
  advance(900);
  assert_non_null(member_of(w.old, w.carol));
  assert_int_equal(nopnotices, 0);
}

/* ... but a redirect that is not the tombstone's (an op changed it) is
 * left for the wipe to deal with. */
static void wiped_tombstone_keeps_a_redirect_that_is_not_its_own(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  vic_relocates(&w);
  ircd_strncpy(w.old->mode.redir, "#elsewhere", sizeof(w.old->mode.redir));
  forget();

  relocate_tombstone_ts_lost(w.old);
  assert_int_equal(ntimers, 0);
  assert_string_equal(w.old->mode.redir, "#elsewhere");
  assert_int_equal(sent_count_to(w.carol), 0);
}

/* The BURST before an announcement merged into our channel although ours
 * is a few seconds younger (we have users: m_burst.c does not deop our
 * side).  The announcement carries the sender's timestamp; it is about
 * this channel all the same, and the record is bound to OUR timestamp. */
static void announcement_within_the_burst_fuzz_builds_the_record(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAE");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500003, "#new", carol);
  server_tombstone(hub, hub, "#old", "500000", "#new", "1000900");

  assert_int_equal(timers_at(1000900), 1);
  assert_non_null(strstr(sent_to(carol, 0), "has moved to #new"));
  forget();
  burst_to(down);
  assert_string_equal(sent_to(down, 0), "AC RT #old 500003 #new 1000900");
  advance(900);
  assert_true(was_destroyed(oldch));
}

/* Outside that rule the channel here is another one. */
static void announcement_outside_the_burst_fuzz_is_ignored(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAE");
  (void)state;

  burst_tombstone("#old", 500005, "#new", carol);
  server_tombstone(hub, hub, "#old", "500000", "#new", "1000900");
  assert_int_equal(ntimers, 0);

  burst_tombstone("#older", 499999, "#new", carol);
  server_tombstone(hub, hub, "#older", "500000", "#new", "1000900");
  assert_int_equal(ntimers, 0);
  assert_int_equal(sent_count_to(carol), 0);
}

/* --- a tombstone's TARGET is renamed (classic) --- */

/* #old redirects to #new; #new is then renamed to #newer by a classic RN.
 * Left alone, the tombstone would go on pointing at a name that no longer
 * exists -- which anybody can create, to be sent every user the tombstone
 * forwards.  It follows its target instead, as it does when the target is
 * relocated on: the redirect, what the local members are shown, the
 * record, what it announces, and where a member follows to. */
static void renamed_target_takes_its_tombstones_along(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *mallory = user_on(&me, "mallory", "AAG");
  struct Channel *oldch, *newer, *fake;
  char name[] = "#new";
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  forget();

  server_rename(peer, bob, "#new", "#newer", "tidy");

  newer = channel_named("#newer");
  assert_non_null(newer);
  assert_string_equal(oldch->mode.redir, "#newer");
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old +L #newer");
  assert_string_equal(sent_to(down, 0), "BjAAC RN #new #newer :tidy");
  assert_int_equal(nopnotices, 0);
  assert_int_equal(timers_at(1000900), 1);
  forget();
  burst_to(down);
  assert_string_equal(sent_to(down, 0), "AC RT #old 500000 #newer 1000900");

  /* the old target's name is free; whoever takes it gets nobody */
  fake = get_channel(mallory, name, CGT_CREATE);
  add_member(fake, mallory, CHFL_CHANOP);
  forget();
  assert_int_equal(joins(carol, fake), 0);
  assert_non_null(member_of(oldch, carol));
  remove_user_from_channel(carol, fake);

  /* and a member follows to where the community is */
  assert_int_equal(joins(carol, newer), CHFL_CHANOP);
  assert_null(member_of(oldch, carol));

  advance(900);
  assert_true(was_destroyed(oldch));
  assert_false(logged("no longer authenticates"));
}

/* The same when the rename is made HERE, by an op of the new channel on a
 * server that runs classic renames (RENAME_CONSENT off) ... */
static void locally_renamed_target_takes_its_tombstones_along(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch;
  (void)state;

  feat_rename_consent = 0;
  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  add_member(channel_named("#new"), dan, CHFL_CHANOP);
  forget();

  client_rename(dan, "#new", "#newer", "");

  assert_non_null(channel_named("#newer"));
  assert_string_equal(oldch->mode.redir, "#newer");
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old +L #newer");
  assert_string_equal(sent_to(peer, 0), "ACAAE RN #new #newer :");
}

/* ... and when services approved it (a registered target). */
static void approved_rename_of_a_target_takes_its_tombstones_along(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *x3 = linked("x3.services", "AX", "sr");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch;
  char cookie[64];
  (void)state;

  feat_rename_consent = 0;
  oldch = channel_at("#old", 500000, bob);
  oldch->mode.mode |= MODE_REGISTERED;
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  add_member(channel_named("#new"), dan, CHFL_CHANOP);
  forget();

  client_rename(dan, "#new", "#newer", "");
  snprintf(cookie, sizeof(cookie), "%s", cookie_of(sent_to(x3, 0)));
  assert_string_equal(oldch->mode.redir, "#new");       /* not yet */
  assert_int_equal(account_line(x3, x3, 3, cookie, "A", "RENAME"), 1);

  assert_non_null(channel_named("#newer"));
  assert_string_equal(oldch->mode.redir, "#newer");
}

/* The renamed channel is NOT the tombstone's target: the target emptied
 * and a stranger made the name again (another creation timestamp), then
 * renamed it.  The tombstone does not follow a stranger's channel. */
static void renamed_stranger_under_the_targets_name_takes_nothing(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *mallory = user_on(peer, "mallory", "AAG");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *fake;
  char name[] = "#new";
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  remove_user_from_channel(bob, channel_named("#new"));  /* #new empties */

  fake = get_channel(mallory, name, CGT_CREATE);
  fake->creationtime = 1000005;
  add_member(fake, mallory, CHFL_CHANOP);
  forget();
  server_rename(peer, mallory, "#new", "#trap", "");

  assert_non_null(channel_named("#trap"));
  assert_string_equal(oldch->mode.redir, "#new");
  assert_int_equal(sent_count_to(carol), 0);
}

/* This server does not hold the target (it is out of step), so it cannot
 * apply the rename and relays it -- but the rest of the network did
 * rename the channel and moved its tombstones' redirects, and a redirect
 * left on the old name here would be the one that can be hijacked.  The
 * tombstone is retargeted all the same. */
static void rename_of_a_target_not_held_here_still_retargets(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *eve = user_on(peer, "eve", "AAE");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#new", carol);
  server_tombstone(peer, peer, "#old", "500000", "#new", "1000900");
  assert_null(channel_named("#new"));
  forget();

  server_rename(peer, eve, "#new", "#newer", "");

  assert_int_equal(nopnotices, 1);                      /* not applied */
  assert_string_equal(sent_to(down, 0), "BjAAE RN #new #newer :");
  assert_string_equal(oldch->mode.redir, "#newer");
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old +L #newer");
  assert_int_equal(timers_at(1000900), 1);
}

/* --- a target this server cannot follow: the tombstone is DETACHED --- */

/** A detached tombstone: still one (do_join() admits nobody: it refuses a
 * JOIN of a tombstone that has no redirect), still on its clock, but
 * pointing nowhere. */
static void assert_detached(struct Channel *tomb)
{
  assert_true(relocate_is_tombstone(tomb));
  assert_string_equal(tomb->mode.redir, "");
  assert_true(tomb->mode.exmode & EXMODE_PERSIST);
}

/* The network renames the target to a name that ANOTHER channel has on
 * this server (another creation timestamp).  This server cannot follow,
 * and it must not point the tombstone at the stranger's channel: joiners
 * would be forwarded into it, and a follower's status carried into it.
 * The tombstone is detached -- redirect withdrawn, the operators told --
 * and still ends on time: members parted, +z gone, channel collected. */
static void target_renamed_onto_a_strangers_name_detaches_the_tombstone(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *down = linked("down.example", "Bk", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *stranger;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  stranger = channel_at("#newer", 700000, dan);
  forget();

  server_rename(peer, bob, "#new", "#newer", "");

  /* the rename could not be applied: two notices, the RN's and ours */
  assert_non_null(channel_named("#new"));
  assert_int_equal(nopnotices, 2);
  assert_non_null(strstr(opnotices[1], "#old"));
  assert_non_null(strstr(opnotices[1], "detached"));
  assert_string_equal(sent_to(down, 0), "BjAAC RN #new #newer :");
  /* no forward ... */
  assert_detached(oldch);
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old -L");
  /* ... no status: not into the stranger's channel, and not into the
   * channel left under the old name either */
  assert_int_equal(joins(carol, stranger), 0);
  assert_non_null(member_of(oldch, carol));
  remove_user_from_channel(carol, stranger);
  assert_int_equal(joins(carol, channel_named("#new")), 0);
  assert_non_null(member_of(oldch, carol));
  /* what it tells a new link is what the NETWORK calls the target; its
   * own BURST of the channel carries no redirect to spread */
  forget();
  burst_to(down);
  assert_string_equal(sent_to(down, 0), "AC RT #old 500000 #newer 1000900");

  /* ... and it ends on time */
  forget();
  advance(900);
  assert_string_equal(sent_to(carol, 0),
                      ":carol!user@host.example PART #old :Channel has moved to #newer");
  assert_true(was_destroyed(oldch));
  assert_false(oldch->mode.exmode & EXMODE_PERSIST);
  assert_int_equal(ntimers, 0);
  assert_false(logged("no longer authenticates"));
}

/* The new name is held here by the RIGHT channel -- the record's target
 * by creation timestamp (this server already has the channel under its
 * new name): the tombstone is retargeted. */
static void target_renamed_onto_the_right_channel_retargets(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAF");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newer;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_VOICE);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  newer = channel_at("#newer", 500000, eve);    /* the same channel, by TS */
  forget();

  server_rename(peer, bob, "#new", "#newer", "");

  assert_int_equal(nopnotices, 1);                      /* the RN's alone */
  assert_string_equal(oldch->mode.redir, "#newer");
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old +L #newer");
  assert_int_equal(joins(carol, newer), CHFL_VOICE);
  assert_null(member_of(oldch, carol));
}

/* The same three, with the tombstone learned from a burst announcement
 * AFTER the rename went through: the announcement names the target as
 * the network has it, and the receiver applies the same test. */
static void announcement_naming_a_strangers_channel_builds_a_detached_tombstone(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *eve = user_on(hub, "eve", "AAF");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *stranger;
  (void)state;

  stranger = channel_at("#newer", 700000, dan);
  /* BjAAF RN #new #newer: nothing here by either name; relayed */
  server_rename(hub, eve, "#new", "#newer", "");
  /* Bj B #old 500000 +zL #newer carol..., then the record */
  oldch = burst_tombstone("#old", 500000, "#newer", carol);
  member_of(oldch, carol)->status |= CHFL_CHANOP;
  forget();
  server_tombstone(hub, hub, "#old", "500000", "#newer", "1000900");

  assert_detached(oldch);
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old -L");
  assert_int_equal(sent_count_to(carol), 1);            /* no "join #newer" */
  assert_int_equal(joins(carol, stranger), 0);
  assert_non_null(member_of(oldch, carol));
  assert_int_equal(timers_at(1000900), 1);

  advance(900);
  assert_true(was_destroyed(oldch));
}

static void announcement_naming_the_right_channel_builds_an_attached_tombstone(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *eve = user_on(hub, "eve", "AAF");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newer;
  (void)state;

  newer = channel_at("#newer", 500000, eve);
  oldch = burst_tombstone("#old", 500000, "#newer", carol);
  member_of(oldch, carol)->status |= CHFL_VOICE;
  server_tombstone(hub, hub, "#old", "500000", "#newer", "1000900");

  assert_string_equal(oldch->mode.redir, "#newer");
  assert_int_equal(joins(carol, newer), CHFL_VOICE);
}

/* The target is not held here and its name is free: attached, pointing at
 * a name with no local channel (as a tombstone whose target emptied
 * always could). */
static void announcement_naming_a_free_name_builds_an_attached_tombstone(void **state)
{
  struct Client *hub = linked("hub.example", "Bj", "v");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch;
  (void)state;

  oldch = burst_tombstone("#old", 500000, "#newer", carol);
  server_tombstone(hub, hub, "#old", "500000", "#newer", "1000900");
  assert_string_equal(oldch->mode.redir, "#newer");
  assert_true(relocate_is_tombstone(oldch));
  assert_non_null(strstr(sent_to(carol, 0), "has moved to #newer"));
}

/* A detached tombstone is attached again when it can be: the stranger's
 * channel goes away and a peer's BURST and announcement name the target
 * once more -- or the network renames the target again, to a free name. */
static void detached_tombstone_is_attached_again_when_it_can_be(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *stranger, *real;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  stranger = channel_at("#newer", 700000, dan);
  server_rename(peer, bob, "#new", "#newer", "");
  assert_detached(oldch);

  /* a BURST puts "+L #newer" back while the stranger's channel is there:
   * withdrawn again when the BURST has been taken in */
  ircd_strncpy(oldch->mode.redir, "#newer", sizeof(oldch->mode.redir));
  relocate_tombstone_burst_done(oldch);
  assert_detached(oldch);

  /* only one operator notice for it, not one per BURST */
  {
    int i, n = 0;
    for (i = 0; i < nopnotices; i++)
      if (strstr(opnotices[i], "detached"))
        n++;
    assert_int_equal(n, 1);
  }

  /* the stranger's channel empties and the real target turns up under
   * the name; until something points the tombstone again it stays
   * detached, and carries nothing even there */
  remove_user_from_channel(dan, stranger);
  assert_true(was_destroyed(stranger));
  real = channel_at("#newer", 500000, bob);
  member_of(oldch, carol)->status |= CHFL_VOICE;
  assert_int_equal(joins(carol, real), 0);
  assert_non_null(member_of(oldch, carol));
  remove_user_from_channel(carol, real);

  /* the announcement attaches it */
  forget();
  server_tombstone(peer, peer, "#old", "500000", "#newer", "1000900");
  assert_string_equal(oldch->mode.redir, "#newer");
  assert_string_equal(sent_to(carol, 0), ":me.example MODE #old +L #newer");
  assert_true(relocate_is_tombstone(oldch));
  assert_int_equal(joins(carol, real), CHFL_VOICE);
  assert_null(member_of(oldch, carol));
}

/* A detached tombstone that is itself renamed (classic) keeps its record,
 * detached, and still ends on time under its new name. */
static void detached_tombstone_renamed_still_ends_on_time(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *eve = user_on(peer, "eve", "AAF");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *older;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  add_member(oldch, carol, 0);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  channel_at("#newer", 700000, dan);
  server_rename(peer, bob, "#new", "#newer", "");
  assert_detached(oldch);

  server_rename(peer, eve, "#old", "#older", "");
  older = channel_named("#older");
  assert_detached(older);
  assert_int_equal(timers_at(1000900), 1);
  advance(900);
  assert_true(was_destroyed(older));
}

/* A crossing whose winner's name is a stranger's channel here: both
 * tombstones are detached rather than pointed at it. */
static void crossing_onto_a_strangers_channel_detaches(void **state)
{
  struct Client *hub = linked("hub.example", "Bh", "v");
  struct Client *uma = user_on(&me, "uma", "AAD");
  struct Client *dan = user_on(&me, "dan", "AAE");
  struct Channel *oldch, *y;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, uma);
  client_rename(uma, "#old", "#y", "");
  y = channel_named("#y");
  channel_at("#x", 700000, dan);                /* a stranger's #x */

  /* the other side relocated #old to #x */
  ircd_strncpy(oldch->mode.redir, "#x", sizeof(oldch->mode.redir));
  server_tombstone(hub, hub, "#old", "500000", "#x", "1000900");

  assert_detached(oldch);
  assert_detached(y);
  assert_int_equal(timers_at(1000900), 2);
  advance(900);
  assert_true(was_destroyed(oldch));
  assert_true(was_destroyed(y));
}

/* A tombstone that was itself renamed (classic) and whose target is
 * renamed too, in either order: the record is found under its new name
 * and points at the target's new name. */
static void renamed_tombstone_and_renamed_target_in_either_order(void **state)
{
  int order;
  (void)state;

  for (order = 0; order < 2; order++) {
    struct Client *peer, *bob, *eve, *carol;
    struct Channel *older;

    if (order) {
      world_teardown(NULL);
      world_setup(NULL);
    }
    peer = linked("peer.example", "Bj", "v");
    bob = user_on(peer, "bob", "AAC");
    eve = user_on(peer, "eve", "AAE");
    carol = user_on(&me, "carol", "AAD");

    add_member(channel_at("#old", 500000, bob), eve, CHFL_CHANOP);
    add_member(channel_named("#old"), carol, 0);
    server_relocate(peer, bob, "#old", "#new", "1000900", "");

    if (order == 0) {
      server_rename(peer, eve, "#old", "#older", "");
      server_rename(peer, bob, "#new", "#newer", "");
    } else {
      server_rename(peer, bob, "#new", "#newer", "");
      server_rename(peer, eve, "#old", "#older", "");
    }

    older = channel_named("#older");
    assert_non_null(older);
    assert_string_equal(older->mode.redir, "#newer");
    assert_int_equal(timers_at(1000900), 1);
    assert_int_equal(ntimers, 1);
    forget();
    advance(900);
    assert_true(was_destroyed(older));
  }
}

/* A crossing whose WINNER is then renamed: both tombstones follow.  And
 * the rename can overtake the losing relocation on its way to a third
 * server -- the winner's server renamed before it heard of the loser.
 * That server compares the loser's name with the name the first
 * relocation was ISSUED with, not with what the channel is called by
 * now, so it decides as everybody else does. */
static void crossing_whose_winner_is_renamed_in_either_order(void **state)
{
  int order;
  (void)state;

  for (order = 0; order < 2; order++) {
    struct Crossing w;

    if (order) {
      world_teardown(NULL);
      world_setup(NULL);
    }
    crossing_world(&w);
    vic_relocates(&w);                          /* #old -> #x */
    if (order == 0) {
      uma_relocates(&w);                        /* #old -> #y: loses */
      server_rename(w.pa, w.vic, "#x", "#zz", "");
    } else {
      /* "#y" sorts before "#zz": by today's names the loser would win */
      server_rename(w.pa, w.vic, "#x", "#zz", "");
      uma_relocates(&w);
    }

    assert_null(channel_named("#x"));
    assert_string_equal(w.old->mode.redir, "#zz");
    assert_string_equal(channel_named("#y")->mode.redir, "#zz");
    assert_true(channel_named("#y")->mode.exmode & EXMODE_PERSIST);
    assert_string_equal(channel_named("#zz")->mode.redir, "");
    assert_false(channel_named("#zz")->mode.exmode & EXMODE_PERSIST);
    assert_non_null(member_of(channel_named("#zz"), w.vic));
    assert_non_null(member_of(channel_named("#y"), w.uma));
    assert_int_equal(channel_named("#zz")->mode.limit, 5);
    assert_int_equal(ntimers, 2);
    assert_int_equal(timers_at(1000900), 2);
    assert_int_equal(nopnotices, 0);
  }
}

/** #old is relocated to @a b by one, and to @a y by two; one then
 * relocates @a b on to @a c.  The second and third reach a server in
 * either order.  @return the name of the one channel left that is not a
 * tombstone (asserting the rest are tombstones pointing at it). */
static const char *chain_across_a_crossing(int order, const char *b,
                                           const char *y, const char *c)
{
  struct Client *pa = linked("a.example", "Bj", "v");
  struct Client *pb = linked("b.example", "Bk", "v");
  struct Client *one = user_on(pa, "one", "AAC");
  struct Client *two = user_on(pb, "two", "AAD");
  const char *names[4];
  const char *live = NULL;
  int i;

  names[0] = "#old"; names[1] = b; names[2] = y; names[3] = c;
  add_member(channel_at("#old", 500000, one), two, CHFL_CHANOP);

  server_relocate(pa, one, "#old", b, "1000900", "");
  if (order == 0) {
    server_relocate(pb, two, "#old", y, "1000600", "");
    server_relocate(pa, one, b, c, "1000700", "");
  } else {
    server_relocate(pa, one, b, c, "1000700", "");
    server_relocate(pb, two, "#old", y, "1000600", "");
  }

  for (i = 0; i < 4; i++) {
    struct Channel *ch = channel_named(names[i]);

    assert_non_null(ch);
    if (!ch->mode.redir[0]) {
      assert_null(live);
      live = names[i];
      assert_false(ch->mode.exmode & EXMODE_PERSIST);
    }
  }
  assert_non_null(live);
  for (i = 0; i < 4; i++)
    if (names[i] != live) {
      assert_string_equal(channel_named(names[i])->mode.redir, live);
      assert_true(channel_named(names[i])->mode.exmode & EXMODE_PERSIST);
    }
  assert_int_equal(nopnotices, 0);
  return live;
}

/* The winner of a crossing is relocated ON while the losing relocation is
 * still on its way.  Whatever the three names, both orders leave the same
 * channel alive -- here the winner's line (b, then c), although "#m"
 * sorts before "#z". */
static void chain_across_a_crossing_winner_moves_on(void **state)
{
  const char *first, *second;
  (void)state;

  first = chain_across_a_crossing(0, "#b", "#m", "#z");
  world_teardown(NULL);
  world_setup(NULL);
  second = chain_across_a_crossing(1, "#b", "#m", "#z");
  assert_string_equal(first, "#z");
  assert_string_equal(second, "#z");
}

/* ... and here the other relocation of #old wins ("#b" before "#m"): the
 * channel that lost, and the channel it was relocated on to, both end as
 * tombstones of the winner -- a relocation of a channel that has lost a
 * crossing loses with it. */
static void chain_across_a_crossing_loser_moves_on(void **state)
{
  const char *first, *second;
  (void)state;

  first = chain_across_a_crossing(0, "#m", "#b", "#a");
  world_teardown(NULL);
  world_setup(NULL);
  second = chain_across_a_crossing(1, "#m", "#b", "#a");
  assert_string_equal(first, "#b");
  assert_string_equal(second, "#b");
}

/* The same relocation heard a second time (two issuers) after its target
 * was renamed: the second issuer goes where the first now is. */
static void same_relocation_twice_after_the_target_was_renamed(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  server_relocate(w.pa, w.vic, "#old", "#new", "1000300", "");
  server_rename(w.pa, w.vic, "#new", "#newer", "");
  server_relocate(w.pb, w.uma, "#old", "#new", "1000900", "");

  assert_null(channel_named("#new"));
  assert_non_null(member_of(channel_named("#newer"), w.uma));
  assert_non_null(member_of(channel_named("#newer"), w.vic));
  assert_string_equal(w.old->mode.redir, "#newer");
  assert_int_equal(ntimers, 1);
  assert_int_equal(timers_at(1000900), 1);
}

/* The same relocation heard a second time after its target was relocated
 * ON (a chain): the second issuer goes into the channel of the name it
 * relocated to -- a tombstone by now -- exactly where it is on a server
 * that heard the two the other way round. */
static void same_relocation_twice_across_a_chain_in_either_order(void **state)
{
  int order;
  (void)state;

  for (order = 0; order < 2; order++) {
    struct Crossing w;
    struct Channel *b;

    if (order) {
      world_teardown(NULL);
      world_setup(NULL);
    }
    crossing_world(&w);
    server_relocate(w.pa, w.vic, "#old", "#b", "1000300", "");
    if (order == 0) {
      server_relocate(w.pb, w.uma, "#old", "#b", "1000900", "");
      server_relocate(w.pa, w.vic, "#b", "#c", "1000400", "");
    } else {
      server_relocate(w.pa, w.vic, "#b", "#c", "1000400", "");
      server_relocate(w.pb, w.uma, "#old", "#b", "1000900", "");
    }

    b = channel_named("#b");
    assert_non_null(member_of(b, w.uma));
    assert_null(member_of(channel_named("#c"), w.uma));
    assert_non_null(member_of(channel_named("#c"), w.vic));
    assert_string_equal(b->mode.redir, "#c");
    assert_string_equal(w.old->mode.redir, "#c");
  }
}

/* The winner's channel is made here with the old channel's timestamp as
 * it is NOW; when that was corrected since the first relocation, the
 * tombstones that turn to the winner know it by its own timestamp, and a
 * member still follows into it. */
static void crossing_winner_made_after_a_timestamp_correction(void **state)
{
  struct Crossing w;
  (void)state;

  crossing_world(&w);
  uma_relocates(&w);                            /* #old -> #y, at 500000 */
  w.old->creationtime = 499998;                 /* M #old ... 499998 */
  relocate_tombstone_ts_follow(w.old, 500000);
  vic_relocates(&w);                            /* #x wins, made at 499998 */

  assert_int_equal(channel_named("#x")->creationtime, 499998);
  assert_string_equal(w.old->mode.redir, "#x");
  assert_int_equal(joins(w.carol, channel_named("#x")), CHFL_VOICE);
  assert_null(member_of(w.old, w.carol));
}

/* --- who can be in a tombstone: a closed set --- */

/* A follower takes its CURRENT status, so everything rests on nobody
 * getting INTO a tombstone after the relocation.  do_join() forwards a
 * JOIN of a channel with a redirect when "users >= limit OR
 * relocate_is_tombstone()", before it looks at +i, +k, bans or invites;
 * so for a live tombstone the forward does not depend on anything a
 * remaining chanop can set.  Before, it depended on the limit alone: an
 * op in the tombstone could MODE +l 500, a stranger then joined the
 * tombstone itself, was opped there and followed with ops. */
static void tombstone_admits_nobody_whatever_its_modes(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");

  assert_true(relocate_is_tombstone(oldch));
  /* what the remaining op can do to it: MODE #old +l 500 +i +k sesame */
  oldch->mode.limit = 500;
  assert_true(oldch->users < oldch->mode.limit);        /* the old test fails */
  oldch->mode.mode |= MODE_INVITEONLY;
  ircd_strncpy(oldch->mode.key, "sesame", sizeof(oldch->mode.key));
  assert_true(relocate_is_tombstone(oldch));
  /* -l again */
  oldch->mode.limit = 0;
  assert_true(relocate_is_tombstone(oldch));

  /* the channel it points at is not one, nor is any ordinary channel */
  assert_false(relocate_is_tombstone(newch));
}

/* Not a tombstone, so the ordinary +L rule (forward only when full)
 * applies: an ordinary persistent channel with a redirect, a tombstone a
 * chanop took +L off or services took +z off, and another channel under
 * a record's name. */
static void ordinary_redirecting_channels_keep_the_ordinary_rule(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Channel *lobby, *oldch, *second, *third;
  (void)state;

  lobby = channel_at("#lobby", 500000, alice);
  lobby->mode.exmode |= EXMODE_PERSIST;
  lobby->mode.limit = 50;
  ircd_strncpy(lobby->mode.redir, "#overflow", sizeof(lobby->mode.redir));
  assert_false(relocate_is_tombstone(lobby));

  oldch = channel_at("#old", 500000, bob);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  assert_true(relocate_is_tombstone(oldch));
  oldch->mode.redir[0] = '\0';                          /* MODE #old -L */
  assert_false(relocate_is_tombstone(oldch));

  second = channel_at("#two", 500000, bob);
  server_relocate(peer, bob, "#two", "#twonew", "1000900", "");
  second->mode.exmode &= ~EXMODE_PERSIST;               /* M #two -z */
  assert_false(relocate_is_tombstone(second));

  third = channel_at("#three", 500000, bob);
  server_relocate(peer, bob, "#three", "#threenew", "1000900", "");
  third->creationtime = 600000;                         /* another channel */
  assert_false(relocate_is_tombstone(third));
}

/* A stranger who IS a member all the same: it joined the old name through
 * a server that does not hold the tombstone (one from before these
 * changes, or one still mid-netjoin), and its JOIN arrived here as an
 * ordinary remote JOIN.  It is another server's user, so this server
 * never moves it, whatever status it is given in the tombstone; it is
 * removed with everybody else at the deadline. */
static void stranger_in_the_tombstone_by_a_remote_join(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *bob = user_on(peer, "bob", "AAC");
  struct Client *mallory = user_on(peer, "mallory", "AAG");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *oldch, *newch;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_CHANOP);
  server_relocate(peer, bob, "#old", "#new", "1000900", "");
  newch = channel_named("#new");

  add_member(oldch, mallory, 0);                        /* BjAAG J #old */
  member_of(oldch, mallory)->status |= CHFL_CHANOP;     /* M #old +o mallory */
  forget();

  /* BjAAG J #new: applied, nothing added */
  assert_int_equal(joins(mallory, newch), 0);
  relocate_follow(mallory, mallory, newch);
  assert_int_equal(member_of(newch, mallory)->status & STATUS, 0);
  assert_non_null(member_of(oldch, mallory));
  assert_int_equal(sent_count_to(carol), 0);

  advance(900);
  assert_true(was_destroyed(oldch));
  assert_int_equal(member_of(newch, mallory)->status & STATUS, 0);
}

/* A tombstone a chanop cancelled with -L is an ordinary channel again
 * (until its record hands +z back): it can be joined like one, and its
 * members -- opped there or not -- take nothing anywhere and are not
 * parted from it. */
static void cancelled_tombstone_carries_nothing(void **state)
{
  struct Client *peer = linked("peer.example", "Bj", "v");
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *mallory = user_on(&me, "mallory", "AAG");
  struct Channel *oldch, *newch;
  (void)state;

  feat_rename_consent = 1;
  oldch = channel_at("#old", 500000, alice);
  add_member(oldch, bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "");
  newch = channel_named("#new");

  oldch->mode.redir[0] = '\0';                          /* bob: MODE #old -L */
  assert_false(relocate_is_tombstone(oldch));
  add_member(oldch, mallory, CHFL_CHANOP);              /* joins, is opped */
  forget();

  assert_int_equal(joins(mallory, newch), 0);
  assert_int_equal(joins(bob, newch), 0);
  assert_non_null(member_of(oldch, mallory));
  assert_non_null(member_of(oldch, bob));
  assert_int_equal(sent_count_to(peer), 2);             /* the two J */
  assert_int_equal(sent_count_to(alice), 0);
}

#define T(f) cmocka_unit_test_setup_teardown(f, world_setup, world_teardown)

int main(void)
{
  const struct CMUnitTest tests[] = {
    T(origin_sends_its_numeric_in_the_cookie),
    T(query_is_relayed_to_a_services_server_linked_here),
    T(query_is_relayed_toward_services_further_on),
    T(query_from_an_origin_two_hops_away),
    T(query_with_a_bare_cookie_is_dropped),
    T(query_whose_cookie_names_another_server_is_dropped),
    T(query_is_never_sent_back_where_it_came_from),
    T(query_with_no_services_at_all_is_dropped),
    T(query_goes_to_the_services_server_every_server_picks),
    T(query_is_not_diverted_to_another_services_server),
    T(origin_asks_the_services_server_every_server_picks),
    T(query_with_a_malformed_new_name_is_dropped),
    T(account_messages_are_left_alone),
    T(reply_is_relayed_toward_the_server_in_the_cookie),
    T(denial_is_relayed_with_its_reason),
    T(reply_from_services_two_hops_away),
    T(reply_for_an_unknown_server_is_dropped),
    T(reply_is_never_sent_back_where_it_came_from),
    T(reply_with_a_malformed_cookie_is_dropped),
    T(reply_from_a_server_that_is_not_services_is_refused),
    T(origin_completes_on_an_approval_for_its_own_cookie),
    T(origin_denies_with_services_reason),
    T(a_second_reply_for_the_same_cookie_does_nothing),
    T(bare_number_reply_from_the_asked_services_server_linked_here),
    T(bare_number_reply_from_services_further_away_is_dropped),
    T(a_bare_query_cannot_get_another_servers_request_approved),
    T(reply_from_a_services_server_that_was_not_asked_is_refused),
    T(services_leaving_fails_the_requests_sent_to_them),
    T(origin_times_out_without_an_answer),

    T(client_cannot_rename_a_local_channel),
    T(client_cannot_rename_to_a_local_name),
    T(client_new_name_must_be_one_join_would_take),
    T(client_utf8_only_feature_is_honoured),
    T(client_bad_name_never_reaches_services),
    T(approval_does_not_carry_a_name_past_a_lowered_cap),
    T(server_rename_naming_a_local_channel_is_a_violation),
    T(server_rename_to_an_unusable_name_is_a_violation),
    T(server_rename_is_not_held_to_local_policy),
    T(server_rename_away_from_a_bad_name_is_applied),

    T(server_rename_applied_is_relayed),
    T(server_rename_of_a_channel_not_here_is_relayed),
    T(server_rename_onto_a_name_taken_here_is_relayed),
    T(crossing_renames_are_both_relayed),
    T(server_rename_to_the_same_channel_is_relayed),
    T(unapplied_rename_from_an_alias_reaches_x3_as_its_primary),

    T(fallback_join_has_the_form_the_member_negotiated),
    T(fallback_join_follows_each_bouncer_connection),

    T(follower_takes_its_current_status_and_leaves_the_tombstone),
    T(deopped_in_the_tombstone_follows_without_ops),
    T(opped_in_the_tombstone_since_follows_with_ops),
    T(not_in_the_tombstone_any_more_gets_nothing),
    T(status_is_carried_over_once),
    T(never_a_member_gets_nothing),
    T(issuer_has_nothing_to_take),
    T(already_in_the_new_channel),
    T(follower_is_never_given_less_than_the_join_gave),
    T(follower_takes_its_oplevel),
    T(nothing_follows_into_a_recreated_channel),
    T(follower_through_a_chain),
    T(cancelled_tombstone_moves_nobody),
    T(follower_and_delayed_join),
    T(follower_with_a_bouncer_device),
    T(device_of_a_remote_primary_does_not_follow_here),
    T(remote_follower_is_just_applied),
    T(tombstone_admits_nobody_whatever_its_modes),
    T(ordinary_redirecting_channels_keep_the_ordinary_rule),
    T(stranger_in_the_tombstone_by_a_remote_join),
    T(cancelled_tombstone_carries_nothing),

    T(dissolve_clears_the_persist_flag_it_set),
    T(dissolve_clears_a_persist_flag_that_was_there_before),
    T(cancelled_tombstone_gives_the_persist_flag_back),
    T(cancelled_empty_tombstone_is_collected),
    T(cancelled_registered_channel_keeps_its_persist_flag),

    T(relocation_carries_its_deadline),
    T(relocation_without_a_reason_keeps_the_trailing_parameter),
    T(approved_relocation_carries_its_deadline),
    T(receiver_arms_for_the_deadline_on_the_wire),
    T(five_parameter_relocation_uses_the_local_grace),
    T(five_parameter_reason_is_never_read_as_a_deadline),
    T(garbage_deadline_falls_back_to_the_local_grace),
    T(past_deadline_dissolves_at_once),
    T(far_deadline_is_clamped_and_relayed_clamped),
    T(relocation_from_an_alias_reaches_x3_as_its_primary),

    T(grace_zero_dissolves_at_once),
    T(grace_zero_leaves_the_old_name_free),
    T(deadline_of_this_very_second_dissolves_at_once),
    T(grace_zero_still_flattens_a_chain),

    T(registered_tombstone_is_cancelled_at_the_deadline),
    T(stray_registration_before_the_relocation),
    T(stray_registration_after_the_relocation),
    T(stray_registration_corrected_before_the_deadline),
    T(registered_channel_relocated_without_grace_is_swept),

    T(record_with_an_armed_timer_is_ended_through_its_timer),
    T(record_past_its_deadline_by_a_clock_step_is_ended_through_its_timer),
    T(record_goes_with_its_channel),
    T(sweep_that_destroys_the_channel_frees_the_record_once),
    T(sweep_on_the_spot_frees_the_record_once),

    T(relocation_of_a_channel_not_here_is_relayed),
    T(five_parameter_relocation_of_a_channel_not_here_is_relayed),
    T(relocation_onto_a_name_taken_here_is_relayed),
    T(unapplied_relocation_from_an_alias_reaches_x3_as_its_primary),

    T(tombstone_cannot_be_renamed_with_consent_off),
    T(approval_does_not_rename_a_tombstone_with_consent_off),
    T(renamed_tombstone_keeps_its_record),
    T(renamed_tombstone_frees_its_old_name),

    T(crossing_relocations_winner_first),
    T(crossing_relocations_loser_first),
    T(crossing_loser_is_told_on_its_own_server),
    T(crossing_loser_with_the_cap_gets_a_relocate),
    T(crossing_winner_on_its_own_server),
    T(same_relocation_twice_moves_the_second_issuer),
    T(same_relocation_twice_keeps_the_later_deadline),
    T(merged_deadline_that_is_past_dissolves_through_the_timer),
    T(chain_is_not_a_crossing),
    T(crossing_carries_an_earlier_hop_to_the_winner),
    T(crossing_loser_that_emptied_here_is_a_tombstone_all_the_same),
    T(crossing_loser_that_emptied_after_both),
    T(crossing_loser_name_taken_here),
    T(crossing_winner_name_taken_here),
    T(three_way_crossing_converges_in_every_order),

    T(tombstone_is_announced_in_the_burst),
    T(ordinary_persistent_redirecting_channel_is_not_announced),
    T(cancelled_tombstone_is_not_announced),
    T(crossing_and_chain_are_announced_as_they_stand),
    T(announcement_is_relayed_like_burst_state),
    T(malformed_announcement_is_refused_and_not_relayed),

    T(announcement_builds_the_record),
    T(announcement_tells_a_member_with_the_cap),
    T(announcement_with_a_past_deadline_dissolves_at_once),
    T(announcement_restores_a_tombstone_the_receiver_had_dissolved),
    T(announcement_with_an_absurd_deadline_is_clamped),
    T(announcement_for_a_registered_channel_builds_the_record_too),
    T(announced_registered_tombstone_is_swept_once_unregistered),
    T(announcement_for_another_incarnation_is_ignored),
    T(announcement_for_a_channel_not_here_is_ignored),
    T(announcement_for_a_channel_with_another_redirect),
    T(announcement_for_a_tombstone_held_here_keeps_the_later_deadline),
    T(announcement_meeting_a_record_that_is_due_dissolves_through_the_timer),
    T(disagreeing_announcements_on_the_winning_side),
    T(disagreeing_announcements_before_the_losers_burst),
    T(waiting_record_does_not_take_another_channel),
    T(disagreeing_announcements_on_the_losing_side),
    T(disagreeing_announcements_retarget_everything_on_the_losing_side),
    T(tombstone_that_loses_a_burst_on_timestamp_is_cancelled),
    T(burst_hooks_leave_ordinary_channels_alone),
    T(burst_cannot_leave_a_limit_on_a_tombstone),

    T(netjoin_leaf_with_a_local_member_gets_the_tombstone),
    T(netjoin_leaf_whose_member_left_keeps_the_tombstone),
    T(netjoin_hub_with_an_empty_tombstone_takes_the_leafs_member),
    T(empty_tombstone_lasts_until_its_deadline),
    T(last_local_member_leaving_changes_nothing),
    T(tombstone_that_lost_its_persist_flag_is_not_swept),
    T(dissolve_with_only_remote_members),

    T(another_channel_with_the_same_marks_is_not_swept),
    T(recreated_channel_is_nobodys_tombstone),
    T(relocating_another_channel_under_a_stale_record),
    T(announcement_for_another_channel_under_a_stale_record),
    T(another_channel_under_a_stale_record_is_wiped_as_itself),
    T(another_channel_under_a_stale_record_is_renamed_as_itself),
    T(record_follows_a_corrected_timestamp),
    T(follow_leaves_other_records_alone),
    T(tombstone_wiped_for_an_older_timestamp_is_ended),
    T(wiped_tombstone_keeps_a_redirect_that_is_not_its_own),
    T(announcement_within_the_burst_fuzz_builds_the_record),
    T(announcement_outside_the_burst_fuzz_is_ignored),

    T(renamed_target_takes_its_tombstones_along),
    T(locally_renamed_target_takes_its_tombstones_along),
    T(approved_rename_of_a_target_takes_its_tombstones_along),
    T(renamed_stranger_under_the_targets_name_takes_nothing),
    T(rename_of_a_target_not_held_here_still_retargets),
    T(target_renamed_onto_a_strangers_name_detaches_the_tombstone),
    T(target_renamed_onto_the_right_channel_retargets),
    T(announcement_naming_a_strangers_channel_builds_a_detached_tombstone),
    T(announcement_naming_the_right_channel_builds_an_attached_tombstone),
    T(announcement_naming_a_free_name_builds_an_attached_tombstone),
    T(detached_tombstone_is_attached_again_when_it_can_be),
    T(detached_tombstone_renamed_still_ends_on_time),
    T(crossing_onto_a_strangers_channel_detaches),
    T(renamed_tombstone_and_renamed_target_in_either_order),
    T(crossing_whose_winner_is_renamed_in_either_order),
    T(chain_across_a_crossing_winner_moves_on),
    T(chain_across_a_crossing_loser_moves_on),
    T(same_relocation_twice_after_the_target_was_renamed),
    T(same_relocation_twice_across_a_chain_in_either_order),
    T(crossing_winner_made_after_a_timestamp_correction),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
