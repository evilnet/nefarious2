/*
 * burst_modes_t.c - the modes a relayed BURST carries.
 *
 * A server that receives a channel's BURST relays it to its other links
 * (ms_burst(), m_burst.c), with the modes the BURST set read back from the
 * modebuf by modebuf_extract(): with op-levels for the peers that have
 * them, and without them (no +A/+U and their parameters) for the others.
 * Every other mode goes to both, extended modes (+a +O +M +N +z +Z +Q +C
 * +T +c +S +H +P) included, so a server two or more hops from the
 * channel's side of a netjoin rebuilds the channel with the modes it has.
 *
 * This drives the real modebuf_extract() and mode_parse(): channel.c is
 * included, compiled with -ffunction-sections and linked with
 * --gc-sections, so the program keeps those and what they call; the rest
 * of the server they reach is stubbed below.
 */
#include "../channel.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

time_t CurrentTime;
time_t TSoffset;
struct Client his;

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

/* ---------- stubs ---------- */

/* A parse of good modes from a server sends no reply and reports no
 * error: each of these counts as a failed check. */
static int unexpected;

int feature_bool(enum Feature feat) { return 1; }
int feature_int(enum Feature feat) { return 0; }
const char *feature_str(enum Feature feat) { return ""; }
int send_reply(struct Client *to, int reply, ...) { unexpected++; return 0; }
int need_more_params(struct Client *cptr, const char *cmd) { unexpected++; return 0; }
int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  unexpected++;
  return 0;
}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...) {}
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...) {}
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...) {}
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...) {}
void sendcmdto_channel_capab_butserv_butone(struct Client *from, const char *cmd,
                                            const char *tok, struct Channel *to,
                                            struct Client *one, unsigned int skip,
                                            int withcap, int skipcap,
                                            const char *pattern, ...) {}
void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...) {}
void schedule_destruct_event_1m(struct Channel *chptr) {}
struct Channel *hSeekChannel(const char *name) { return NULL; }
struct Client *hSeekClient(const char *name, int TMask) { return NULL; }
struct Client *findNUser(const char *yxx) { return NULL; }
struct Client *get_history(const char *nick, time_t timelimit) { return NULL; }
void free_link(struct SLink *lp) {}

/* ---------- servers and channels ---------- */

/* The server whose BURST is parsed: a link of ours in its burst. */
static struct Client peer;
static struct Connection peer_con;
static struct Server peer_serv;

static void peer_init(void)
{
  cli_status(&peer) = STAT_SERVER;
  cli_connect(&peer) = &peer_con;
  con_client(&peer_con) = &peer;
  cli_serv(&peer) = &peer_serv;
  ircd_strncpy(cli_name(&peer), "leaf.example", sizeof(cli_name(&peer)));
  SetFlag(&peer, FLAG_BURST);
}

static struct Channel *chan_new(const char *name)
{
  struct Channel *ch = calloc(1, sizeof(*ch) + strlen(name) + 1);
  strcpy(ch->chname, name);
  ch->creationtime = 1700000000;
  return ch;
}

/** Parse the mode part of a BURST (@a modes: "+modes params", modified in
 * place) into @a ch as ms_burst() does for a channel that takes the
 * BURST's modes, from the peer, into @a mbuf. */
static void burst_parse(struct ModeBuf *mbuf, struct Channel *ch, char *modes)
{
  char *parv[MAXPARA];
  int parc = 0, used;
  char *p = strtok(modes, " ");

  while (p && parc < MAXPARA) {
    parv[parc++] = p;
    p = strtok(NULL, " ");
  }
  modebuf_init(mbuf, &me, &peer, ch,
               MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);
  used = mode_parse(mbuf, &peer, &peer, ch, parc, parv,
                    MODE_PARSE_SET | MODE_PARSE_BURST, NULL);
  CHECK(used == parc, "the BURST's parameters are all taken", parv[0]);
}

/* Every extended mode and its letter (the 005 CHANMODES list, by hand). */
static const struct { unsigned int exmode; const char *letter; } exrows[] = {
  { EXMODE_ADMINONLY, "a" },
  { EXMODE_OPERONLY, "O" },
  { EXMODE_REGMODERATED, "M" },
  { EXMODE_NONOTICES, "N" },
  { EXMODE_PERSIST, "z" },
  { EXMODE_SSLONLY, "Z" },
  { EXMODE_NOQUITPARTS, "Q" },
  { EXMODE_NOCTCPS, "C" },
  { EXMODE_NOMULTITARG, "T" },
  { EXMODE_NOCOLOR, "c" },
  { EXMODE_STRIPCOLOR, "S" },
  { EXMODE_PUBLICHISTORY, "H" },
  { EXMODE_NOSTORAGE, "P" },
};

int main(void)
{
  static const char *bursts[] = {
    "+ntZ",
    "+ntklL key 7 #elsewhere",
    "+smaOMNzZQCTcHP",
    "+imlSk 12 k2",
    "+nzP",
  };
  struct Channel *ch;
  struct ModeBuf mbuf;
  char buf[BUFSIZE], want[8];
  size_t i;
  int oplevels;

  peer_init();

  /* Each extended mode is in the relayed modes, for a peer with
   * op-levels and for one without them. */
  for (i = 0; i < sizeof(exrows) / sizeof(exrows[0]); i++)
    for (oplevels = 0; oplevels < 2; oplevels++) {
      memset(&mbuf, 0, sizeof(mbuf));
      mbuf.mb_exadd = exrows[i].exmode;
      modebuf_extract(&mbuf, buf, oplevels);
      snprintf(want, sizeof(want), "+%s", exrows[i].letter);
      CHECK(!strcmp(buf, want),
            oplevels ? "an extended mode, with op-levels"
            : "an extended mode, without op-levels", buf);
    }

  /* With parameter modes: the letters first, the parameters after them in
   * the letters' order, the extended modes taking none.  Only +A/+U and
   * their parameters are left out without op-levels. */
  ch = chan_new("#params");
  modebuf_init(&mbuf, &me, &peer, ch, MODEBUF_DEST_CHANNEL);
  modebuf_mode(&mbuf, MODE_ADD | MODE_TOPICLIMIT | MODE_NOPRIVMSGS);
  modebuf_exmode(&mbuf, MODE_ADD | EXMODE_SSLONLY | EXMODE_OPERONLY);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_KEY, "sekrit", 0);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_APASS, "apw", 0);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_UPASS, "upw", 0);
  modebuf_mode_uint(&mbuf, MODE_ADD | MODE_LIMIT, 5);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_REDIRECT, "#over", 0);
  modebuf_extract(&mbuf, buf, 1);
  CHECK(!strcmp(buf, "+tnkAUlLOZ sekrit apw upw 5 #over"),
        "parameters line up, with op-levels", buf);
  modebuf_extract(&mbuf, buf, 0);
  CHECK(!strcmp(buf, "+tnklLOZ sekrit 5 #over"),
        "parameters line up, without op-levels", buf);

  /* The relayed BURST, parsed at the next server, sets what the BURST
   * that came in set: the same simple modes, limit, key and redirect, and
   * the same extended modes. */
  for (i = 0; i < sizeof(bursts) / sizeof(bursts[0]); i++) {
    struct Channel *hub = chan_new("#relay");    /* the BURST's first hop */
    struct Channel *far = chan_new("#relay");    /* the relay's next hop */
    struct ModeBuf in, out;
    char line[BUFSIZE], relayed[BUFSIZE];

    ircd_strncpy(line, bursts[i], sizeof(line));
    burst_parse(&in, hub, line);
    modebuf_extract(&in, relayed, 0);           /* burst_relay_modes() */
    CHECK(hub->mode.exmode || !strpbrk(bursts[i], "aOMNzZQCTcSHP"),
          "the BURST set its extended modes", bursts[i]);
    burst_parse(&out, far, relayed);
    CHECK(far->mode.mode == hub->mode.mode
          && far->mode.exmode == hub->mode.exmode
          && far->mode.limit == hub->mode.limit
          && !strcmp(far->mode.key, hub->mode.key)
          && !strcmp(far->mode.redir, hub->mode.redir),
          "the relayed BURST sets what the BURST set", bursts[i]);
  }
  CHECK(!unexpected, "no reply or error from a parse", "");

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
