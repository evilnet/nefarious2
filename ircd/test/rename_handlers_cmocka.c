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

static int world_teardown(void **state)
{
  int i;
  (void)state;

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

/* A mode buffer that holds one +L/-L for the channel's local members. */
static struct {
  struct Channel *chan;
  struct Client *source;
  unsigned int mode;
  char arg[CHANNELLEN + 1];
} fake_mb;

void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
                  struct Client *connect, struct Channel *chan,
                  unsigned int dest)
{
  (void)mbuf; (void)connect;
  /* nothing relocation does to a mode may reach a server */
  assert_int_equal(dest, MODEBUF_DEST_CHANNEL);
  fake_mb.chan = chan;
  fake_mb.source = source;
  fake_mb.mode = 0;
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free_it)
{
  (void)mbuf; (void)free_it;
  assert_true(mode & MODE_REDIRECT);
  fake_mb.mode = mode;
  snprintf(fake_mb.arg, sizeof(fake_mb.arg), "%s", string);
}

int modebuf_flush(struct ModeBuf *mbuf)
{
  struct Membership *m;
  char buf[LINE];
  (void)mbuf;

  if (!fake_mb.mode)
    return 0;
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
  return 0;
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

/* --- D.3: whose snapshot, and for which channel --- */

/* A former op of #old who follows gets the status back, once. */
static void follower_regains_status_once(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *newch;
  unsigned int flags = 0;
  int oplevel = -1;
  (void)state;

  feat_rename_consent = 1;
  add_member(channel_at("#old", 500000, alice), bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "moving");

  newch = channel_named("#new");
  assert_non_null(newch);
  assert_int_equal(newch->creationtime, 500000);
  assert_int_equal(relocate_snap_lookup(newch, bob, &flags, &oplevel), 1);
  assert_int_equal(flags, CHFL_CHANOP);
  /* consumed */
  assert_int_equal(relocate_snap_lookup(newch, bob, &flags, &oplevel), 0);
}

/* The issuer was moved with its status; it has nothing to regain, so a
 * PART and JOIN after being deopped in #new does not re-op it. */
static void issuer_has_no_snapshot(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Channel *newch;
  unsigned int flags = 0;
  int oplevel = -1;
  (void)state;

  feat_rename_consent = 1;
  add_member(channel_at("#old", 500000, alice), bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "moving");

  newch = channel_named("#new");
  assert_non_null(member_of(newch, alice));
  assert_true(member_of(newch, alice)->status & CHFL_CHANOP);
  assert_int_equal(relocate_snap_lookup(newch, alice, &flags, &oplevel), 0);
}

/* #new empties and a stranger creates it again inside the grace: a
 * former op of #old is not opped in the stranger's channel. */
static void snapshot_is_not_honoured_in_a_recreated_channel(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  struct Client *carol = user_on(&me, "carol", "AAD");
  struct Channel *newch, *again;
  char name[] = "#new";
  unsigned int flags = 0;
  int oplevel = -1;
  (void)state;

  feat_rename_consent = 1;
  add_member(channel_at("#old", 500000, alice), bob, CHFL_CHANOP);
  client_rename(alice, "#old", "#new", "moving");

  newch = channel_named("#new");
  remove_user_from_channel(alice, newch);
  assert_true(was_destroyed(newch));

  again = get_channel(carol, name, CGT_CREATE);
  assert_ptr_not_equal(again, newch);
  assert_int_equal(again->creationtime, CurrentTime);
  add_member(again, carol, CHFL_CHANOP);

  assert_int_equal(relocate_snap_lookup(again, bob, &flags, &oplevel), 0);
  assert_int_equal(flags, 0);
}

/* A chain keeps the binding: #a -> #b -> #c, and an op of #a who follows
 * straight to #c is restored there. */
static void snapshot_follows_a_chain_to_the_same_channel(void **state)
{
  struct Client *alice = user_on(&me, "alice", "AAB");
  struct Client *bob = user_on(&me, "bob", "AAC");
  unsigned int flags = 0;
  int oplevel = -1;
  (void)state;

  feat_rename_consent = 1;
  add_member(channel_at("#a", 500000, alice), bob, CHFL_CHANOP);
  client_rename(alice, "#a", "#b", "one");
  client_rename(alice, "#b", "#c", "two");

  assert_string_equal(channel_named("#a")->mode.redir, "#c");
  assert_int_equal(relocate_snap_lookup(channel_named("#c"), bob, &flags,
                                        &oplevel), 1);
  assert_int_equal(flags, CHFL_CHANOP);
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
  oldch->mode.mode &= ~MODE_REDIRECT;
  oldch->mode.redir[0] = '\0';
  forget();

  advance(900);
  assert_int_equal(sent_count_to(bob), 0);
  assert_non_null(member_of(oldch, bob));
  assert_false(oldch->mode.exmode & EXMODE_PERSIST);
  assert_false(was_destroyed(oldch));
  assert_int_equal(nopnotices, 1);
  assert_non_null(strstr(opnotices[0], "lost its redirect"));

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
  oldch->mode.mode &= ~MODE_REDIRECT;
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
  oldch->mode.mode &= ~MODE_REDIRECT;
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
  unsigned int flags = 0;
  int oplevel = 0;
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

  /* nothing left behind: no channel, no timer, no snapshot */
  assert_true(was_destroyed(oldch));
  assert_null(channel_named("#old"));
  assert_int_equal(ntimers, 0);
  assert_int_equal(relocate_snap_lookup(newch, bob, &flags, &oplevel), 0);

  /* the deadline on the wire is now */
  assert_string_equal(sent_to(peer, 0), "ACAAB RN #old #new C 1000000 :now");
  assert_string_equal(sent_to(x3, 0), "ACAAB RN #old #new C 1000000 :now");
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
  unsigned int flags = 0;
  int oplevel = 0;
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
  assert_true(oldch->mode.mode & MODE_REDIRECT);
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
  assert_false(oldch->mode.mode & MODE_REDIRECT);
  assert_string_equal(oldch->mode.redir, "");
  /* an ordinary registered channel again; +z is services' to clear */
  assert_true(oldch->mode.mode & MODE_REGISTERED);
  assert_true(oldch->mode.exmode & EXMODE_PERSIST);
  assert_false(was_destroyed(oldch));
  /* the record is gone, and its snapshots with it */
  assert_int_equal(ntimers, 0);
  assert_int_equal(relocate_snap_lookup(newch, bob, &flags, &oplevel), 0);
  /* nothing goes to a server: every server does this by itself */
  assert_int_equal(sent_count_to(peer), 0);
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
  struct Channel *oldch, *newch;
  unsigned int flags = 0;
  int oplevel = 0;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, carol, CHFL_VOICE);

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
  assert_int_equal(relocate_snap_lookup(newch, carol, &flags, &oplevel), 1);
  assert_int_equal(flags, CHFL_VOICE);

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
  struct Channel *oldch, *renamed;
  unsigned int flags = 0;
  int oplevel = 0;
  (void)state;

  oldch = channel_at("#old", 500000, bob);
  add_member(oldch, eve, CHFL_CHANOP);
  add_member(oldch, carol, CHFL_VOICE);
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
  /* a follower is still restored */
  assert_int_equal(relocate_snap_lookup(channel_named("#new"), carol, &flags,
                                        &oplevel), 1);
  assert_int_equal(flags, CHFL_VOICE);
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
  w->old->mode.mode |= MODE_NOPRIVMSGS | MODE_LIMIT;
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
  unsigned int flags;
  int oplevel;

  assert_non_null(x);
  assert_non_null(y);
  assert_ptr_equal(channel_named("#old"), w->old);

  /* #old: a tombstone redirecting to the winner, with the stayer */
  assert_string_equal(w->old->mode.redir, "#x");
  assert_true(w->old->mode.mode & MODE_REDIRECT);
  assert_true(w->old->mode.exmode & EXMODE_PERSIST);
  assert_false(w->old->mode.mode & MODE_LIMIT);
  assert_int_equal(w->old->users, 1);
  assert_non_null(member_of(w->old, w->carol));

  /* the winner: an ordinary channel with the state the old one had --
   * nothing of the tombstone's +z, +L or redirect -- and its issuer */
  assert_false(x->mode.exmode & EXMODE_PERSIST);
  assert_false(x->mode.mode & MODE_REDIRECT);
  assert_string_equal(x->mode.redir, "");
  assert_true(x->mode.mode & MODE_NOPRIVMSGS);
  assert_true(x->mode.mode & MODE_LIMIT);
  assert_int_equal(x->mode.limit, 5);
  assert_string_equal(x->mode.key, "sesame");
  assert_int_equal(x->creationtime, 500000);
  assert_int_equal(x->users, 1);
  assert_true(member_of(x, w->vic)->status & CHFL_CHANOP);

  /* the loser: a tombstone too, redirecting to the winner, with ITS
   * issuer, who can follow from there */
  assert_string_equal(y->mode.redir, "#x");
  assert_true(y->mode.mode & MODE_REDIRECT);
  assert_true(y->mode.exmode & EXMODE_PERSIST);
  assert_true(y->mode.mode & MODE_NOPRIVMSGS);
  assert_false(y->mode.mode & MODE_LIMIT);
  assert_int_equal(y->mode.limit, 0);
  assert_string_equal(y->mode.key, "sesame");
  assert_int_equal(y->creationtime, 500000);
  assert_int_equal(y->users, 1);
  assert_true(member_of(y, w->uma)->status & CHFL_CHANOP);

  /* two records, one deadline: the later of the two */
  assert_int_equal(ntimers, 2);
  assert_int_equal(timers_at(1000900), 2);

  /* a member of #old regains its status in the winner; so does the
   * loser's issuer, who was one -- each once */
  flags = 0;
  assert_int_equal(relocate_snap_lookup(x, w->carol, &flags, &oplevel), 1);
  assert_int_equal(flags, CHFL_VOICE);
  assert_int_equal(relocate_snap_lookup(x, w->carol, &flags, &oplevel), 0);
  flags = 0;
  assert_int_equal(relocate_snap_lookup(x, w->uma, &flags, &oplevel), 1);
  assert_int_equal(flags, CHFL_CHANOP);
  assert_int_equal(relocate_snap_lookup(x, w->uma, &flags, &oplevel), 0);
  /* the winner's issuer was moved with its status and has none */
  assert_int_equal(relocate_snap_lookup(x, w->vic, &flags, &oplevel), 0);
  /* and nothing restores anybody in the loser */
  assert_int_equal(relocate_snap_lookup(y, w->carol, &flags, &oplevel), 0);

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

    T(follower_regains_status_once),
    T(issuer_has_no_snapshot),
    T(snapshot_is_not_honoured_in_a_recreated_channel),
    T(snapshot_follows_a_chain_to_the_same_channel),

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
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
