/*
 * burst_modes_cmocka.c - the modes a relayed BURST carries.
 *
 * A server that receives a channel's BURST relays it to its other links
 * (ms_burst(), m_burst.c), with the modes the BURST set read back from the
 * modebuf by modebuf_extract(): with oplevels for the peers that have
 * them, and without them (no +A/+U and their parameters) for the others.
 * Every other mode goes to both, extended modes (+a +O +M +N +z +Z +Q +C
 * +T +c +S +H +P) included, so a server two or more hops from the
 * channel's side of a netjoin rebuilds the channel with the modes it has.
 *
 * This drives the REAL modebuf_extract() and mode_parse(): channel.c is
 * included, compiled with -ffunction-sections and linked with
 * --gc-sections, so the program keeps those and what they call; the rest
 * of the ircd they reach is stubbed here.
 */
#include "config.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "../channel.c"

/* ------------------------------------------------------------------ */
/* The ircd around modebuf_extract() and mode_parse()                  */
/* ------------------------------------------------------------------ */

struct Client me;
struct Client his;
time_t CurrentTime;
int log_inassert;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
void debug(int level, const char *form, ...) {}

int feature_bool(enum Feature feat) { return 1; }
int feature_int(enum Feature feat) { return 0; }
const char *feature_str(enum Feature feat) { return ""; }

/* What a parse from a server reaches and nothing here asks of it: a parse
 * of good modes sends no reply, invalidates nothing, stores nothing. */
int send_reply(struct Client *to, int reply, ...)
{
  fail_msg("a reply was sent (%d)", reply);
  return 0;
}
int need_more_params(struct Client *cptr, const char *cmd)
{
  fail_msg("too few parameters for %s", cmd);
  return 0;
}
int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  fail_msg("protocol violation: %s", pattern);
  return 0;
}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...) {}
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
                                const char *pattern, ...) {}
void sendcmdto_channel_butserv_respond(struct Client *from, const char *cmd,
                                       const char *tok, struct Channel *to,
                                       struct Client *one, unsigned int skip,
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
void sendcmdto_set_client_event(const char *msgid, uint64_t event_ms) {}
void sendcmdto_set_client_msgid(const char *msgid) {}
void sendcmdto_set_s2s_tags(uint64_t time_ms, const char *msgid) {}
void sendcmdto_want_s2s_tags(int want) {}
void schedule_destruct_event_1m(struct Channel *chptr) {}
void relocate_channel_restamped(struct Channel *chptr, time_t old_ts) {}
void relocate_tombstone_marks_changed(struct Channel *chptr) {}
struct Channel *hSeekChannel(const char *name) { return NULL; }
struct Client *hSeekClient(const char *name, int TMask) { return NULL; }
struct Client *findNUser(const char *yxx) { return NULL; }
struct Client *get_history(const char *nick, time_t timelimit) { return NULL; }
struct Client *sendcmdto_inbound_link(void) { return NULL; }
time_t TSoffset;
void free_link(struct SLink *lp) {}
char *generate_msgid(char *buf, size_t buflen)
{
  ircd_strncpy(buf, "ABAAAZp6]R57AA", buflen);
  return buf;
}
const char *generate_msgid_ahead(void) { return "ABAAAZp6]R57AA"; }

/* No history store, no metadata store, no bouncer session. */
uint64_t history_event_time_ms(struct Client *link) { return 0; }
int history_is_available(void) { return 0; }
void history_format_ms(char *buf, size_t buflen, uint64_t ms) { buf[0] = '\0'; }
const char *history_owner_of(char *buf, size_t size, struct Client *sptr) { return NULL; }
int history_store_message(const char *msgid, const char *timestamp,
                          const char *target, const char *original_target,
                          const char *sender, const char *account,
                          enum HistoryMessageType type,
                          const char *content, const char *client_tags,
                          const char *owner)
{
  fail_msg("a history row was stored");
  return -1;
}
int rcv_store_open(int require_auth, unsigned int authusers,
                   int public_history, int nostorage) { return 0; }
void history_recv_reset(struct Channel *chptr) {}
void history_recv_update(struct Channel *chptr) {}
void bounce_mark_dirty(struct Client *cptr) {}
void bounce_sync_alias_chanmodes(struct Channel *chptr, struct Client *primary) {}
int metadata_account_clear(const char *account) { return 0; }
int metadata_account_set_permanent(const char *account, const char *key,
                                   const char *value, int visibility) { return 0; }
void metadata_channel_load(struct Channel *chptr) {}
int metadata_channel_memory_del(struct Channel *chptr, const char *key) { return 0; }
int metadata_lmdb_is_available(void) { return 0; }
void metadata_notify_subscribers(const char *target, const char *key,
                                 const char *value, int visibility) {}

/* ------------------------------------------------------------------ */
/* Servers and channels                                                */
/* ------------------------------------------------------------------ */

/* The server whose BURST is parsed: a link of ours in its burst. */
static struct Client peer;
static struct Connection peer_con;
static struct Server peer_serv;

static void peer_init(void)
{
  memset(&peer, 0, sizeof(peer));
  memset(&peer_con, 0, sizeof(peer_con));
  memset(&peer_serv, 0, sizeof(peer_serv));
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

/** Split @a line at spaces into @a parv (modified in place). */
static int split(char *line, char *parv[], int max)
{
  int parc = 0;
  char *p = strtok(line, " ");

  while (p && parc < max) {
    parv[parc++] = p;
    p = strtok(NULL, " ");
  }
  return parc;
}

/** Parse the mode part of a BURST (@a modes: "+modes params") into @a ch
 * as ms_burst() does for a channel that takes the BURST's modes, from the
 * peer, into @a mbuf.  @a modes is modified. */
static void burst_parse(struct ModeBuf *mbuf, struct Channel *ch, char *modes)
{
  char *parv[MAXPARA];
  int parc = split(modes, parv, MAXPARA);

  modebuf_init(mbuf, &me, &peer, ch,
               MODEBUF_DEST_CHANNEL | MODEBUF_DEST_NOKEY);
  assert_int_equal(mode_parse(mbuf, &peer, &peer, ch, parc, parv,
                              MODE_PARSE_SET | MODE_PARSE_BURST, NULL),
                   parc);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

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

/** Each extended mode is in the relayed modes, for a peer with oplevels
 * and for one without them. */
static void exmodes_in_both_forms(void **state)
{
  size_t i;
  int oplevels;

  for (i = 0; i < sizeof(exrows) / sizeof(exrows[0]); i++)
  for (oplevels = 0; oplevels < 2; oplevels++) {
    struct ModeBuf mbuf;
    char buf[BUFSIZE], want[8];

    memset(&mbuf, 0, sizeof(mbuf));
    mbuf.mb_exadd = exrows[i].exmode;
    modebuf_extract(&mbuf, buf, oplevels);
    snprintf(want, sizeof(want), "+%s", exrows[i].letter);
    if (strcmp(buf, want))
      fail_msg("+%s, oplevels %d: extracted \"%s\"", exrows[i].letter,
               oplevels, buf);
  }
}

/** With parameter modes: the letters come first and the parameters follow
 * in the letters' order, the extended modes taking none.  Only +A/+U and
 * their parameters are left out without oplevels. */
static void params_line_up(void **state)
{
  struct Channel *ch = chan_new("#params");
  struct ModeBuf mbuf;
  char buf[BUFSIZE];

  modebuf_init(&mbuf, &me, &peer, ch, MODEBUF_DEST_CHANNEL);
  modebuf_mode(&mbuf, MODE_ADD | MODE_TOPICLIMIT | MODE_NOPRIVMSGS);
  modebuf_exmode(&mbuf, MODE_ADD | EXMODE_SSLONLY | EXMODE_OPERONLY);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_KEY, "sekrit", 0);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_APASS, "apw", 0);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_UPASS, "upw", 0);
  modebuf_mode_uint(&mbuf, MODE_ADD | MODE_LIMIT, 5);
  modebuf_mode_string(&mbuf, MODE_ADD | MODE_REDIRECT, "#over", 0);

  modebuf_extract(&mbuf, buf, 1);
  assert_string_equal(buf, "+tnkAUlLOZ sekrit apw upw 5 #over");
  modebuf_extract(&mbuf, buf, 0);
  assert_string_equal(buf, "+tnklLOZ sekrit 5 #over");
}

/** The relayed BURST, parsed at the next server, sets what the BURST
 * that came in set: the same simple modes, limit, key and redirect, and
 * the same extended modes. */
static void relay_parses_like_the_burst(void **state)
{
  static const char *bursts[] = {
    "+ntZ",
    "+ntklL key 7 #elsewhere",
    "+smaOMNzZQCTcHP",
    "+imlSk 12 k2",
    "+nzP",
  };
  size_t i;

  peer_init();
  for (i = 0; i < sizeof(bursts) / sizeof(bursts[0]); i++) {
    struct Channel *hub = chan_new("#relay");    /* the BURST's first hop */
    struct Channel *far = chan_new("#relay");    /* the relay's next hop */
    struct ModeBuf in, out;
    char line[BUFSIZE], relayed[BUFSIZE];

    ircd_strncpy(line, bursts[i], sizeof(line));
    burst_parse(&in, hub, line);
    modebuf_extract(&in, relayed, 0);           /* burst_relay_modes() */
    burst_parse(&out, far, relayed);
    if (far->mode.mode != hub->mode.mode
        || far->mode.exmode != hub->mode.exmode
        || far->mode.limit != hub->mode.limit
        || strcmp(far->mode.key, hub->mode.key)
        || strcmp(far->mode.redir, hub->mode.redir))
      fail_msg("\"%s\": relayed as \"%s\"; modes %#x/%#x, exmodes %#x/%#x, "
               "limit %u/%u, key \"%s\"/\"%s\", redirect \"%s\"/\"%s\"",
               bursts[i], relayed, hub->mode.mode, far->mode.mode,
               hub->mode.exmode, far->mode.exmode, hub->mode.limit,
               far->mode.limit, hub->mode.key, far->mode.key,
               hub->mode.redir, far->mode.redir);
    assert_true(hub->mode.exmode || !strpbrk(bursts[i], "aOMNzZQCTcSHP"));
  }
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(exmodes_in_both_forms),
    cmocka_unit_test(params_line_up),
    cmocka_unit_test(relay_parses_like_the_burst),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
