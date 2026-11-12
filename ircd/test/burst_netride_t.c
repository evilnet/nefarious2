/*
 * burst_netride_t.c - which local members a BURST's net.ride check kicks.
 *
 * When a BURST names one of our channels with an older timestamp,
 * ms_burst() (m_burst.c) kicks the local members its modes would have
 * kept out: a key they did not match, +i, +r and so on.  To find the key
 * it walks the mode string, passing over the parameter of each letter
 * that takes one.
 *
 * m_burst.o is linked as the server builds it.  The channel has the key
 * "key" and one local member, and the BURST comes from a directly linked
 * server.  The stubs below end ms_burst() right after the check (the
 * second get_channel() finds nothing) and record the kick.
 */
#include "config.h"

#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "match.h"
#include "numnicks.h"
#include "send.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

time_t CurrentTime;
time_t TSoffset;
struct Client his;

/* ---------- stubs ---------- */

static struct Channel *channel; /**< what get_channel() returns, once */
static int kicked;              /**< make_zombie() calls */

struct Channel *get_channel(struct Client *cptr, char *chname,
                            ChannelGetType flag)
{
  struct Channel *chptr = channel;

  channel = NULL;
  return chptr;
}

void make_zombie(struct Membership *member, struct Client *who,
                 struct Client *cptr, struct Client *sptr,
                 struct Channel *chptr)
{
  kicked++;
}

int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  return 0;
}

int sub1_from_channel(struct Channel *chptr)
{
  return 0;
}

void mode_invite_clear(struct Channel *chan)
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

/* Not reached: ms_burst() returns before anything below runs. */

void sendcmdto_channel_capab_butserv_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Channel *to,
                                            struct Client *one,
                                            unsigned int skip, int require,
                                            int forbid,
                                            const char *pattern, ...)
{
  abort();
}

void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...)
{
  abort();
}

int feature_bool(enum Feature feat)
{
  abort();
}

struct Membership *find_member_link(struct Channel *chptr,
                                    const struct Client *cptr)
{
  abort();
}

struct Client *findNUser(const char *yxx)
{
  abort();
}

void add_user_to_channel(struct Channel *chptr, struct Client *who,
                         unsigned int flags, int oplevel)
{
  abort();
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
  abort();
}

void mode_except_invalidate(struct Channel *chan)
{
  abort();
}

void modebuf_init(struct ModeBuf *mbuf, struct Client *source,
                  struct Client *connect, struct Channel *chan,
                  unsigned int dest)
{
  abort();
}

void modebuf_mode(struct ModeBuf *mbuf, unsigned int mode)
{
  abort();
}

void modebuf_mode_client(struct ModeBuf *mbuf, unsigned int mode,
                         struct Client *client, int oplevel)
{
  abort();
}

void modebuf_mode_string(struct ModeBuf *mbuf, unsigned int mode,
                         char *string, int free)
{
  abort();
}

void modebuf_extract(struct ModeBuf *mbuf, char *buf, int oplevels)
{
  abort();
}

int modebuf_flush(struct ModeBuf *mbuf)
{
  abort();
}

int mode_parse(struct ModeBuf *mbuf, struct Client *cptr,
               struct Client *sptr, struct Channel *chptr, int parc,
               char *parv[], unsigned int flags, struct Membership *member)
{
  abort();
}

/* ---------- checks ---------- */

static int checks;              /**< checks evaluated */
static int failures;            /**< checks that did not hold */

static struct Client peer;      /**< the server the BURST comes from */
static struct Connection peer_con;
static struct Client local;     /**< our member of the channel */
static struct Connection local_con;
static struct Membership member;

/** Feed "AC B #nr 1000 <modes...> ACAAA:o" to ms_burst() for our #nr
 * (timestamp 2000, key "key").
 * @return Non-zero when our member was kicked as a Net Rider. */
static int kicks(const char *modes)
{
  static struct Channel *chptr;
  char buf[256], *parv[16], *p = 0, *word;
  int parc = 0;

  if (!chptr)
    chptr = calloc(1, sizeof(*chptr) + sizeof("#nr"));
  strcpy(chptr->chname, "#nr");
  ircd_strncpy(chptr->mode.key, "key", sizeof(chptr->mode.key));
  chptr->creationtime = 2000;
  chptr->users = 1;
  chptr->members = &member;
  member.user = &local;
  member.channel = chptr;
  member.status = CHFL_CHANOP;

  parv[parc++] = "AC";
  parv[parc++] = "#nr";
  parv[parc++] = "1000";
  ircd_strncpy(buf, modes, sizeof(buf));
  for (word = ircd_strtok(&p, buf, " "); word; word = ircd_strtok(&p, 0, " "))
    parv[parc++] = word;
  parv[parc++] = "ACAAA:o";
  parv[parc] = NULL;

  channel = chptr;
  kicked = 0;
  ms_burst(&peer, &peer, parc, parv);
  return kicked;
}

static void check(int ok, int line, const char *what, const char *arg)
{
  checks++;
  if (!ok) {
    failures++;
    printf("FAILED line %d: %s [%s]\n", line, what, arg);
  }
}

#define KEEPS(modes) \
  check(!kicks(modes), __LINE__, "our key: member kept", modes)
#define KICKS(modes) \
  check(kicks(modes), __LINE__, "member kicked as a Net Rider", modes)

int main(void)
{
  setvbuf(stdout, NULL, _IONBF, 0);

  cli_connect(&peer) = &peer_con;
  con_client(&peer_con) = &peer;
  cli_status(&peer) = STAT_SERVER;
  ircd_strncpy(cli_name(&peer), "leafa.test", sizeof(cli_name(&peer)));

  cli_connect(&local) = &local_con;
  con_client(&local_con) = &local;
  cli_status(&local) = STAT_USER;
  ircd_strncpy(cli_name(&local), "dave", sizeof(cli_name(&local)));

  /* The key compared with ours is the one after the 'k'. */
  KEEPS("+k key");
  KEEPS("+lk 10 key");
  KEEPS("+Lk #redir key");
  KEEPS("+lLk 10 #redir key");
  KEEPS("+Ak apass key");
  KEEPS("+Uk upass key");
  KEEPS("+AUk apass upass key");
  KEEPS("+lLkAU 10 #redir key apass upass");
  KEEPS("+bk *!*@ban key");
  KEEPS("+ek *!*@except key");
  KEEPS("+ok ACAAB key");
  KEEPS("+hk ACAAB key");
  KEEPS("+vk ACAAB key");
  KEEPS("+ntmsk key");
  KEEPS("+nt");

  /* Another key, or a mode our member does not satisfy, kicks. */
  KICKS("+k other");
  KICKS("+lk 10 other");
  KICKS("+Lk #redir other");
  KICKS("+lLkAU 10 #redir other apass upass");
  KICKS("+bk *!*@ban other");
  KICKS("+i");
  KICKS("+Lki #redir key");
  KICKS("+r");

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
