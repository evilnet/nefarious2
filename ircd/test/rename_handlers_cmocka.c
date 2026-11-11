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
int log_inassert;

/* ====================================================================
 * What the code under test did
 * ==================================================================== */

#define LINE 700
#define MAXREC 48

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

#define MAXOBJ 32
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

/* --- timers: recorded, fired by hand --- */

static struct Timer *timers[MAXOBJ];
static int ntimers;

static void fire(struct Timer *t, enum EventType type)
{
  struct Event ev;

  memset(&ev, 0, sizeof(ev));
  ev.ev_type = type;
  ev.ev_gen.gen_timer = t;
  (*t->t_header.gh_call)(&ev);
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

  feat_rename_services = 1;
  feat_rename_consent = 0;
  feat_channellen = CHANNELLEN;
  feat_utf8_only = 0;
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

void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)to; (void)one; (void)skip;
  (void)pattern;
  fail_msg("a channel-wide send: only relocation mode does that");
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
  (void)type; (void)value;

  timer->t_header.gh_call = call;
  timer->t_header.gh_data = data;
  assert_true(ntimers < MAXOBJ);
  timers[ntimers++] = timer;
}

/* As the real one outside a dispatch: ET_DESTROY at once. */
void timer_del(struct Timer *timer)
{
  int i;

  for (i = 0; i < ntimers; i++) {
    if (timers[i] == timer) {
      timers[i] = timers[--ntimers];
      break;
    }
  }
  fire(timer, ET_DESTROY);
}

/* Relocation mode (FEAT_RENAME_CONSENT) is not exercised here; anything
 * only it reaches fails the test that reached it. */
#define RELOCATION_ONLY(name) fail_msg(name "() called: relocation mode only")

struct Channel *get_channel(struct Client *cptr, char *chname,
                            ChannelGetType flag)
{
  (void)cptr; (void)chname; (void)flag;
  RELOCATION_ONLY("get_channel");
  return NULL;
}

void add_user_to_channel(struct Channel *chptr, struct Client *who,
                         unsigned int flags, int oplevel)
{
  (void)chptr; (void)who; (void)flags; (void)oplevel;
  RELOCATION_ONLY("add_user_to_channel");
}

void remove_user_from_channel(struct Client *sptr, struct Channel *chptr)
{
  (void)sptr; (void)chptr;
  RELOCATION_ONLY("remove_user_from_channel");
}

int sub1_from_channel(struct Channel *chptr)
{
  (void)chptr;
  RELOCATION_ONLY("sub1_from_channel");
  return 0;
}

struct Ban *make_ban(const char *banstr)
{
  (void)banstr;
  RELOCATION_ONLY("make_ban");
  return NULL;
}

void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
                  struct Client *connect, struct Channel *chan,
                  unsigned int dest)
{
  (void)mbuf; (void)source; (void)connect; (void)chan; (void)dest;
  RELOCATION_ONLY("modebuf_init");
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free_it)
{
  (void)mbuf; (void)mode; (void)string; (void)free_it;
  RELOCATION_ONLY("modebuf_mode_string");
}

int modebuf_flush(struct ModeBuf *mbuf)
{
  (void)mbuf;
  RELOCATION_ONLY("modebuf_flush");
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
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
