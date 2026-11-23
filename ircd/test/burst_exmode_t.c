/*
 * burst_exmode_t.c - what a timestamp (TS) loss does to a channel's
 * extended modes.
 *
 * When two servers link and both have a channel of the same name, the copy
 * with the younger creation timestamp loses: ms_burst() (m_burst.c) wipes
 * its modes and the older channel's modes, from the BURST, win.  ms_join()
 * (m_join.c) does the same for a JOIN that carries an older timestamp.
 * The extended modes (+C +N +Z +M ...) are wiped with the classic ones and
 * the local members are told in the same MODE.  Every server the BURST or
 * JOIN reaches finds its own copy younger and wipes by itself, so nothing
 * is sent to any server for it.  A channel that +z held open and that is
 * left empty without it gets a destruct event.
 *
 * m_burst.o and m_join.o are linked as the server builds them.  What they
 * call is stubbed below: mode_parse() applies a BURST's extended modes,
 * the modebuf keeps the extended modes it is given, and the server sends
 * are recorded as "<to>: <arguments>" ("relay" for the relayed BURST).
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
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

/* ---------- what was sent ---------- */

#define MAXSENT 32
static char sent[MAXSENT][512];  /**< "<to>: <arguments>" */
static int nsent;

static void record(const char *to, const char *pattern, va_list args)
{
  struct VarData vd;

  if (nsent >= MAXSENT)
    return;
  vd.vd_format = pattern;
  va_copy(vd.vd_args, args);
  ircd_snprintf(0, sent[nsent], sizeof(sent[nsent]), "%s: %v", to, &vd);
  va_end(vd.vd_args);
  nsent++;
}

/** How many of the lines sent start with @a prefix. */
static int sent_with(const char *prefix)
{
  int i, n = 0;

  for (i = 0; i < nsent; i++)
    if (!strncmp(sent[i], prefix, strlen(prefix)))
      n++;
  return n;
}

/* schedule_destruct_event_1m() calls. */
static int destructs;

/* The modebuf as far as the checks read it: its extended modes and where
 * the last one flushed was going. */
static unsigned int flushed_exrem, flushed_exadd, flushed_dest;
static int nflushes;

/* ---------- the channel table ---------- */

static struct Channel *channel; /**< the one channel there is */

static struct Channel *new_channel(const char *name)
{
  struct Channel *chptr = calloc(1, sizeof(*chptr) + strlen(name));

  strcpy(chptr->chname, name);
  return chptr;
}

struct Channel *get_channel(struct Client *cptr, char *chname,
                            ChannelGetType flag)
{
  if (!channel && flag == CGT_CREATE)
    channel = new_channel(chname);
  return channel;
}

struct Channel *hSeekChannel(const char *name)
{
  return channel;
}

/* ---------- stubs for m_burst.o ---------- */

void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...)
{
  char to[64];
  va_list vl;

  /* The Net Rider KICK goes everywhere (one is NULL); not looked at. */
  ircd_snprintf(0, to, sizeof(to), "all but %s", one ? cli_name(one) : "none");
  va_start(vl, pattern);
  record(to, pattern, vl);
  va_end(vl);
}

void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  va_list vl;

  va_start(vl, pattern);
  record(cli_name(to), pattern, vl);
  va_end(vl);
}

/* The relayed BURST, once for each line (it goes out in two forms, with
 * op-levels and without; burst_relay_t reads them). */
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...)
{
  va_list vl;

  if (require != FLAG_OPLEVELS)
    return;
  va_start(vl, pattern);
  record("relay", pattern, vl);
  va_end(vl);
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
                                            unsigned int skip, int require,
                                            int forbid,
                                            const char *pattern, ...)
{
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  return 0;
}

void schedule_destruct_event_1m(struct Channel *chptr)
{
  destructs++;
}

int sub1_from_channel(struct Channel *chptr)
{
  return 0;
}

void mode_invite_clear(struct Channel *chan)
{
}

void make_zombie(struct Membership *member, struct Client *who,
                 struct Client *cptr, struct Client *sptr,
                 struct Channel *chptr)
{
}

int feature_bool(enum Feature feat)
{
  return 0;
}

int feature_int(enum Feature feat)
{
  return 0;
}

const char *feature_str(enum Feature feat)
{
  return "";
}

struct Membership *find_member_link(struct Channel *chptr,
                                    const struct Client *cptr)
{
  return NULL;
}

/* No member of the BURSTs below is known: none is added. */
struct Client *findNUser(const char *yxx)
{
  return NULL;
}

void add_user_to_channel(struct Channel *chptr, struct Client *who,
                         unsigned int flags, int oplevel)
{
}

struct Ban *make_ban(const char *banstr)
{
  abort();
}

void free_ban(struct Ban *ban)
{
  abort();
}

char *pretty_extmask(char *mask)
{
  abort();
}

void mode_ban_invalidate(struct Channel *chan)
{
}

void mode_except_invalidate(struct Channel *chan)
{
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
}

/* As the real one keeps them: an add cancels a pending removal and the
 * other way round. */
void modebuf_exmode(struct ModeBuf *mbuf, unsigned int mode)
{
  unsigned int bits = mode & ~(MODE_ADD | MODE_DEL);

  if (mode & MODE_ADD) {
    mbuf->mb_exrem &= ~bits;
    mbuf->mb_exadd |= bits;
  } else {
    mbuf->mb_exadd &= ~bits;
    mbuf->mb_exrem |= bits;
  }
}

void modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
                         struct Client *client, int oplevel)
{
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free)
{
}

void modebuf_mode_uint(struct ModeBuf *mbuf, unsigned int mode,
                       unsigned int uint)
{
}

void modebuf_extract(struct ModeBuf *mbuf, char *buf, int oplevels)
{
  buf[0] = '\0';
}

int modebuf_flush(struct ModeBuf *mbuf)
{
  flushed_exrem = mbuf->mb_exrem;
  flushed_exadd = mbuf->mb_exadd;
  flushed_dest = mbuf->mb_dest;
  nflushes++;
  return 0;
}

/* channel.h's extended modes and their letters. */
static const struct { unsigned int flag; char letter; } exletters[] = {
  { EXMODE_ADMINONLY, 'a' }, { EXMODE_OPERONLY, 'O' },
  { EXMODE_REGMODERATED, 'M' }, { EXMODE_NONOTICES, 'N' },
  { EXMODE_PERSIST, 'z' }, { EXMODE_SSLONLY, 'Z' },
  { EXMODE_NOQUITPARTS, 'Q' }, { EXMODE_NOCTCPS, 'C' },
  { EXMODE_NOMULTITARG, 'T' }, { EXMODE_NOCOLOR, 'c' },
  { EXMODE_STRIPCOLOR, 'S' }, { EXMODE_PUBLICHISTORY, 'H' },
  { EXMODE_NOSTORAGE, 'P' },
};
#define NEXLETTERS (sizeof(exletters) / sizeof(exletters[0]))

/* A BURST's mode string: the string and a parameter for each of k l L A U
 * (all a BURST below uses); with MODE_PARSE_SET its extended modes are set
 * on the channel, the ones it did not have added to the modebuf -- +z only
 * from a server in its netburst or from services, as channel.c takes it. */
int mode_parse(struct ModeBuf *mbuf, struct Client *cptr,
               struct Client *sptr, struct Channel *chptr, int parc,
               char *parv[], unsigned int flags, struct Membership *member)
{
  const char *p;
  int used = 1;
  unsigned int exadd = 0;
  size_t i;

  for (p = parv[0]; *p; p++) {
    if (strchr("klLAU", *p) && used < parc)
      used++;
    for (i = 0; i < NEXLETTERS; i++)
      if (exletters[i].letter == *p
          && (exletters[i].flag != EXMODE_PERSIST
              || IsBurst(sptr) || IsService(sptr)))
        exadd |= exletters[i].flag;
  }
  if (mbuf && (flags & MODE_PARSE_SET)) {
    if (exadd & ~chptr->mode.exmode)
      modebuf_exmode(mbuf, MODE_ADD | (exadd & ~chptr->mode.exmode));
    chptr->mode.exmode |= exadd;
  }
  return used;
}

/* ---------- stubs for m_join.o ---------- */

static int njoined;

void joinbuf_init(struct JoinBuf *jbuf, struct Client *source,
                  struct Client *connect, unsigned int type, char *comment,
                  time_t create)
{
  memset(jbuf, 0, sizeof(*jbuf));
}

void joinbuf_join(struct JoinBuf *jbuf, struct Channel *chan,
                  unsigned int flags)
{
  njoined++;
}

int joinbuf_flush(struct JoinBuf *jbuf)
{
  return 0;
}

int need_more_params(struct Client *cptr, const char *cmd)
{
  return 0;
}

int send_reply(struct Client *to, int reply, ...)
{
  return 0;
}

void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...)
{
}

void remove_user_from_channel(struct Client *sptr, struct Channel *chptr)
{
}

int check_target_limit(struct Client *sptr, void *target, const char *name,
                       int created)
{
  abort();
}

void del_invite(struct Client *cptr, struct Channel *chptr)
{
  abort();
}

int destruct_channel(struct Channel *chptr)
{
  abort();
}

void do_names(struct Client *sptr, struct Channel *chptr, int filter)
{
  abort();
}

struct Ban *find_ban(struct Client *cptr, struct Ban *banlist, int extbantype,
                     int level)
{
  abort();
}

unsigned int get_client_maxchans(struct Client *acptr)
{
  abort();
}

struct Gline *gline_find(char *userhost, unsigned int flags)
{
  abort();
}

int IsInvited(struct Client *cptr, const void *chptr)
{
  abort();
}

/* ---------- checks ---------- */

static int checks;              /**< checks evaluated */
static int failures;            /**< checks that did not hold */

static void check(int ok, int line, const char *what)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED line %d: %s\n", line, what);
  }
}

#define CHECK(cond) check((cond), __LINE__, #cond)

static struct Client peer;      /**< the server the BURST or JOIN comes from */
static struct Connection peer_con;
static struct Client alice;     /**< a user on it */
static struct Connection alice_con;
static struct User alice_user;
static struct Membership member; /**< alice in #x, when a check wants one */
static struct Client far;       /**< a server behind peer */
static struct Connection far_con;

/** Our #x, created at @a ts with extended modes @a exmode; @a bursting:
 * the peer's link is in its netburst (we are an end of a new link). */
static struct Channel *world(time_t ts, unsigned int exmode, int bursting)
{
  channel = new_channel("#x");
  channel->creationtime = ts;
  channel->mode.exmode = exmode;
  nsent = 0;
  nflushes = 0;
  flushed_exrem = flushed_exadd = flushed_dest = 0;
  njoined = 0;
  destructs = 0;
  if (bursting)
    SetBurst(&peer);
  else
    ClrFlag(&peer, FLAG_BURST);
  return channel;
}

/** Hand ms_burst() or ms_join() the words of @a line from @a source. */
static void deliver(int (*handler)(struct Client *, struct Client *, int, char *[]),
                    struct Client *source, const char *line)
{
  static char buf[512];
  char *parv[16], *p = 0, *word;
  int parc = 0;

  parv[parc++] = cli_name(source);
  ircd_strncpy(buf, line, sizeof(buf));
  for (word = ircd_strtok(&p, buf, " "); word; word = ircd_strtok(&p, 0, " "))
    parv[parc++] = word;
  parv[parc] = NULL;
  handler(&peer, source, parc, parv);
}

int main(void)
{
  struct Channel *ch;
  unsigned int all = 0;
  size_t i;

  setvbuf(stdout, NULL, _IONBF, 0);

  cli_status(&me) = STAT_ME;
  ircd_strncpy(cli_name(&me), "hub.test", sizeof(cli_name(&me)));
  cli_connect(&peer) = &peer_con;
  con_client(&peer_con) = &peer;
  cli_status(&peer) = STAT_SERVER;
  ircd_strncpy(cli_name(&peer), "leafa.test", sizeof(cli_name(&peer)));
  cli_connect(&alice) = &alice_con;
  con_client(&alice_con) = &alice;
  cli_status(&alice) = STAT_USER;
  cli_user(&alice) = &alice_user;
  ircd_strncpy(cli_name(&alice), "alice", sizeof(cli_name(&alice)));
  cli_connect(&far) = &far_con;
  con_client(&far_con) = &far;
  cli_status(&far) = STAT_SERVER;
  ircd_strncpy(cli_name(&far), "far.test", sizeof(cli_name(&far)));
  for (i = 0; i < NEXLETTERS; i++)
    all |= exletters[i].flag;

  /* We lose: every extended mode goes, the winner's come back, and our
   * members are told in the wipe-out's MODE, which goes to no server. */
  ch = world(2000, EXMODE_NOCTCPS | EXMODE_NONOTICES | EXMODE_NOSTORAGE, 1);
  deliver(ms_burst, &peer, "#x 1000 +nt ACAAA:o");
  CHECK(ch->creationtime == 1000);
  CHECK(ch->mode.exmode == 0);
  CHECK(flushed_exrem == (EXMODE_NOCTCPS | EXMODE_NONOTICES | EXMODE_NOSTORAGE));
  CHECK(flushed_dest & MODEBUF_DEST_CHANNEL);
  CHECK(!(flushed_dest & MODEBUF_DEST_SERVER));

  /* The winner's own stay. */
  ch = world(2000, EXMODE_NOCTCPS | EXMODE_NONOTICES, 1);
  deliver(ms_burst, &peer, "#x 1000 +ntC ACAAA:o");
  CHECK(ch->mode.exmode == EXMODE_NOCTCPS);
  CHECK(flushed_exrem == EXMODE_NONOTICES);

  /* Nothing goes to any server but the relayed BURST, at the end of the
   * new link and on a server the BURST was relayed to alike: every server
   * that gets it wipes by itself. */
  CHECK(nsent == 1 && sent_with("relay: #x 1000") == 1);
  ch = world(2000, EXMODE_NOCTCPS | EXMODE_NONOTICES, 0);
  deliver(ms_burst, &peer, "#x 1000 +ntC ACAAA:o");
  CHECK(ch->mode.exmode == EXMODE_NOCTCPS);
  CHECK(nsent == 1 && sent_with("relay: #x 1000") == 1);

  /* We win: the loser's mode letters are not applied (mode_parse() gets no
   * modebuf), and nothing goes to any server but the relay. */
  ch = world(1000, EXMODE_NOCTCPS, 1);
  deliver(ms_burst, &peer, "#x 2000 +ntCNH ACAAA:o");
  CHECK(ch->creationtime == 1000);
  CHECK(ch->mode.exmode == EXMODE_NOCTCPS);
  CHECK(nsent == 1 && sent_with("relay: #x 1000") == 1);

  /* Every extended mode goes, and a winner that has them all sets them
   * all again. */
  ch = world(2000, all, 1);
  deliver(ms_burst, &peer, "#x 1000 +nt ACAAA:o");
  CHECK(ch->mode.exmode == 0);
  CHECK(flushed_exrem == all);
  ch = world(2000, all, 1);
  deliver(ms_burst, &peer, "#x 1000 +aOMNzZQCTcSHP ACAAA:o");
  CHECK(ch->mode.exmode == all);
  CHECK(flushed_exrem == 0);

  /* +z: a server takes it only from a server in its netburst, or from
   * services.  A +z channel losing to a +z winner keeps it and nothing is
   * scheduled: over the new link, and relayed from two hops away (its
   * source was introduced in its netburst, "J"). */
  ch = world(2000, EXMODE_PERSIST | EXMODE_NOCTCPS, 1);
  deliver(ms_burst, &peer, "#x 1000 +ntz");
  CHECK(ch->mode.exmode == EXMODE_PERSIST);
  CHECK(destructs == 0);
  ch = world(2000, EXMODE_PERSIST | EXMODE_NOCTCPS, 0);
  SetBurst(&far);
  deliver(ms_burst, &far, "#x 1000 +ntz");
  CHECK(ch->mode.exmode == EXMODE_PERSIST);
  CHECK(destructs == 0);

  /* A +z channel losing to a winner without +z ends without it and, with
   * nobody in it, gets the destruct event a -z gets; with a member, not. */
  ch = world(2000, EXMODE_PERSIST, 1);
  deliver(ms_burst, &peer, "#x 1000 +nt");
  CHECK(ch->mode.exmode == 0);
  CHECK(destructs == 1);
  CHECK(nsent == 1 && sent_with("relay: #x 1000") == 1);
  ch = world(2000, EXMODE_PERSIST, 1);
  ch->members = &member;
  ch->users = 1;
  member.user = &alice;
  member.channel = ch;
  deliver(ms_burst, &peer, "#x 1000 +nt");
  CHECK(ch->mode.exmode == 0);
  CHECK(destructs == 0);

  /* A BURST whose source cannot set +z (outside a netburst): our +z is
   * left as it is and nothing is scheduled, whether it shows +z or not. */
  ch = world(2000, EXMODE_PERSIST | EXMODE_NOCTCPS, 0);
  deliver(ms_burst, &peer, "#x 1000 +ntz");
  CHECK(ch->mode.exmode == EXMODE_PERSIST);
  CHECK(flushed_exrem == EXMODE_NOCTCPS);
  CHECK(destructs == 0);
  ch = world(2000, EXMODE_PERSIST, 0);
  deliver(ms_burst, &peer, "#x 1000 +nt");
  CHECK(ch->mode.exmode == EXMODE_PERSIST);
  CHECK(destructs == 0);

  /* A JOIN with an older timestamp: the extended modes go, the members
   * and the opers (HACK(3)) are told, no server is. */
  ch = world(2000, EXMODE_NOCTCPS | EXMODE_NOSTORAGE, 0);
  deliver(ms_join, &alice, "#x 1000");
  CHECK(njoined == 1);
  CHECK(ch->creationtime == 1000);
  CHECK(ch->mode.exmode == 0);
  CHECK(flushed_exrem == (EXMODE_NOCTCPS | EXMODE_NOSTORAGE));
  CHECK(flushed_dest & MODEBUF_DEST_HACK3);
  CHECK(!(flushed_dest & MODEBUF_DEST_SERVER));
  CHECK(sent_with("all but") == 0 && sent_with("leafa.test") == 0);

  /* +z stays at a JOIN's wipe-out: nothing in a JOIN can set it again (a
   * BURST's mode string can, which is why ms_burst() takes it), and it is
   * services' to set and to take. */
  ch = world(2000, EXMODE_NOCTCPS | EXMODE_PERSIST, 0);
  deliver(ms_join, &alice, "#x 1000");
  CHECK(ch->creationtime == 1000);
  CHECK(ch->mode.exmode == EXMODE_PERSIST);
  CHECK(flushed_exrem == EXMODE_NOCTCPS);

  /* The control: a JOIN at the channel's timestamp into a channel with
   * members leaves the modes alone. */
  ch = world(1000, EXMODE_NOCTCPS, 0);
  ch->users = 1;
  deliver(ms_join, &alice, "#x 1000");
  CHECK(ch->mode.exmode == EXMODE_NOCTCPS);
  CHECK(nflushes == 0);

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
