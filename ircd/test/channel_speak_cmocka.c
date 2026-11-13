/*
 * channel_speak_cmocka.c - may a bouncer device of ours speak in a channel?
 *
 * A device speaks where, and only where, its primary may: every identity
 * check is judged by the primary's face and membership at the device's own
 * server, and only +Z is the device's own (its connection's TLS).  A device
 * that is not a member -- or whose primary is not -- is held to the
 * non-member rules with the primary's identity; a device with no primary
 * (an orphan) does not speak.  A remote primary's ban cache is never read
 * or written.  A member that is not a device keeps the stock rules.
 *
 * This drives the REAL predicates: channel.c is included, compiled with
 * -ffunction-sections and linked with --gc-sections, so the program keeps
 * client_can_send_to_channel(), member_can_send_to_channel(), find_ban(),
 * make_ban() and what they call, and nothing else of channel.c; only that
 * needs the ircd around it here (match.o and the string/printf objects are
 * the real ones).  Clients, memberships and channels are built by hand.
 *
 * The grid: +Z x device TLS x device a member x primary (ours / another
 * server's / none / a zombie member / not a member) x voiced x +m x banned
 * x excepted, each verdict checked against an oracle written from the rule,
 * for client_can_send_to_channel() and, where the device is a member, for
 * member_can_send_to_channel() on the device's own membership.
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
/* The ircd around the predicates                                      */
/* ------------------------------------------------------------------ */

struct Client me;
struct Client his;
time_t CurrentTime;
int log_inassert;

void log_write(enum LogSys subsys, enum LogLevel severity, unsigned int flags,
               const char *fmt, ...) {}
void debug(int level, const char *form, ...) {}

static int feat_apass_cansend;
int feature_bool(enum Feature feat)
{
  if (feat == FEAT_APASS_CANSEND)
    return feat_apass_cansend;
  return 1;   /* EXTBANS, EXTBAN_*, EXCEPTS: on */
}
int feature_int(enum Feature feat) { return 0; }   /* HOST_HIDING_STYLE 0 */
const char *feature_str(enum Feature feat) { return ""; }

/* A delayed-join reveal is never asked for here: the device paths reveal
 * nothing, and the cases with reveal on are not delayed. */
static int reveals;
void sendcmdto_channel_capab_butserv_butone(struct Client *from, const char *cmd,
                                            const char *tok, struct Channel *to,
                                            struct Client *one, unsigned int skip,
                                            int withcap, int skipcap,
                                            const char *pattern, ...)
{
  reveals++;
}
void sendcmdto_channel_butserv_butone(struct Client *from, const char *cmd,
                                      const char *tok, struct Channel *to,
                                      struct Client *one, unsigned int skip,
                                      const char *pattern, ...)
{
  reveals++;
}
void sendcmdto_set_client_event(const char *msgid, uint64_t event_ms) {}
void sendcmdto_set_client_msgid(const char *msgid) {}
char *generate_msgid(char *buf, size_t buflen)
{
  if (buflen)
    buf[0] = '\0';
  return buf;
}
uint64_t history_event_time_ms(struct Client *link) { return 0; }
int find_mark_match(struct Client *sptr, const char *mask) { return 0; }
/* The reveal's history row (store_channel_event(), kept with
 * RevealDelayedJoin()): never reached, the reveal is never asked for. */
int history_is_available(void) { return 0; }
void history_format_ms(char *buf, size_t buflen, uint64_t ms)
{
  if (buflen)
    buf[0] = '\0';
}
const char *history_owner_of(char *buf, size_t size, struct Client *sptr)
{
  return NULL;
}
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
                   int public_history, int nostorage)
{
  return 0;
}
struct Channel *hSeekChannel(const char *name) { return NULL; }

/* ------------------------------------------------------------------ */
/* Clients, memberships, channels                                      */
/* ------------------------------------------------------------------ */

struct fake_client {
  struct Client cli;
  struct Connection con;
  struct User user;
};

/* Another server's clients are behind the uplink: they share its
 * Connection, whose client is the uplink (MyConnect() is false). */
static struct Client uplink;
static struct Connection uplink_con;

static void fake_init(struct fake_client *f, const char *nick, const char *host,
                      const char *account, int ours, int tls)
{
  memset(f, 0, sizeof(*f));
  cli_user(&f->cli) = &f->user;
  cli_status(&f->cli) = STAT_USER;
  con_client(&uplink_con) = &uplink;
  if (ours) {
    cli_connect(&f->cli) = &f->con;
    con_client(&f->con) = &f->cli;
  } else
    cli_connect(&f->cli) = &uplink_con;
  ircd_strncpy(cli_name(&f->cli), nick, sizeof(cli_name(&f->cli)));
  ircd_strncpy(f->user.username, nick, sizeof(f->user.username));
  ircd_strncpy(f->user.host, host, sizeof(f->user.host));
  ircd_strncpy(f->user.realhost, host, sizeof(f->user.realhost));
  if (account) {
    ircd_strncpy(f->user.account, account, sizeof(f->user.account));
    SetFlag(&f->cli, FLAG_ACCOUNT);
  }
  if (tls)
    SetFlag(&f->cli, FLAG_SSL);
}

static struct Channel *chan_new(const char *name)
{
  struct Channel *ch = calloc(1, sizeof(*ch) + strlen(name) + 1);
  strcpy(ch->chname, name);
  return ch;
}

static struct Membership *join(struct Channel *ch, struct fake_client *f,
                               unsigned int status)
{
  struct Membership *m = calloc(1, sizeof(*m));
  m->user = &f->cli;
  m->channel = ch;
  m->status = status;
  m->next_channel = f->user.channel;
  f->user.channel = m;
  m->next_member = ch->members;
  ch->members = m;
  return m;
}

static void add_ban(struct Ban **list, const char *mask, int exception)
{
  struct Ban *b = make_ban(mask);
  assert_non_null(b);
  if (exception)
    b->flags |= BAN_EXCEPTION;
  b->next = *list;
  *list = b;
}

/* The primary of a case. */
enum prim { P_OURS, P_REMOTE, P_NONE, P_ZOMBIE, P_ABSENT };
static const char *prim_name[] = { "ours", "remote", "none", "zombie", "absent" };

/** The rule, written out: what a device may do. */
static int oracle(int z, int dev_tls, int dev_member, enum prim p, int voiced,
                  int moderated, int banned, int excepted)
{
  if (z && !dev_tls)
    return 0;                        /* +Z: the device's own connection */
  if (p == P_NONE)
    return 0;                        /* an orphan does not speak */
  if (dev_member && (p == P_OURS || p == P_REMOTE)) {
    if (voiced)
      return 1;                      /* the primary's voice */
    if (moderated)
      return 0;
    return !(banned && !excepted);
  }
  /* the non-member rules, the primary's identity (-n here) */
  if (moderated)
    return 0;
  return !(banned && !excepted);
}

static void device_grid(void **state)
{
  int z, dev_tls, dev_member, p, voiced, moderated, banned, excepted;
  int cases = 0;

  for (z = 0; z < 2; z++)
  for (dev_tls = 0; dev_tls < 2; dev_tls++)
  for (dev_member = 0; dev_member < 2; dev_member++)
  for (p = P_OURS; p <= P_ABSENT; p++)
  for (voiced = 0; voiced < 2; voiced++)
  for (moderated = 0; moderated < 2; moderated++)
  for (banned = 0; banned < 2; banned++)
  for (excepted = 0; excepted < 2; excepted++) {
    struct fake_client prim, dev;
    struct Channel *ch = chan_new("#grid");
    struct Membership *pm = NULL, *dm = NULL;
    int want, got, got_member;

    /* The primary: its own face (nick, host, account).  The device keeps
     * another nick and host here, so a verdict that matched the device's
     * own identity would show: no ban below matches the device. */
    fake_init(&prim, "prim", "prim.host", "pacct", p != P_REMOTE, 0);
    fake_init(&dev, "devnick", "dev.host", "dacct", 1, dev_tls);
    SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
    if (p != P_NONE)
      dev.user.alias_primary = &prim.cli;
    if (p == P_OURS || p == P_REMOTE || p == P_ZOMBIE)
      pm = join(ch, &prim, (voiced ? CHFL_VOICE : 0)
                | (p == P_ZOMBIE ? CHFL_ZOMBIE : 0));
    if (dev_member)
      dm = join(ch, &dev, CHFL_ALIAS | (voiced ? CHFL_VOICE : 0));
    ch->mode.mode = moderated ? MODE_MODERATED : 0;
    ch->mode.exmode = z ? EXMODE_SSLONLY : 0;
    if (banned)
      add_ban(&ch->banlist, "prim!*@*", 0);
    if (excepted)
      add_ban(&ch->exceptlist, "*!*@prim.host", 0);

    want = oracle(z, dev_tls, dev_member, p, voiced, moderated, banned, excepted);
    reveals = 0;
    got = client_can_send_to_channel(&dev.cli, ch, 1);
    if (got != want)
      fail_msg("client_can_send_to_channel: +Z=%d tls=%d member=%d primary=%s "
               "voiced=%d +m=%d banned=%d excepted=%d: got %d, want %d",
               z, dev_tls, dev_member, prim_name[p], voiced, moderated,
               banned, excepted, got, want);
    if (dm) {
      got_member = member_can_send_to_channel(dm, 1);
      if (got_member != want)
        fail_msg("member_can_send_to_channel: +Z=%d tls=%d primary=%s voiced=%d "
                 "+m=%d banned=%d excepted=%d: got %d, want %d",
                 z, dev_tls, prim_name[p], voiced, moderated, banned, excepted,
                 got_member, want);
    }
    assert_int_equal(reveals, 0);
    /* Another server's primary: its ban cache is neither read nor written. */
    if (pm && p == P_REMOTE)
      assert_int_equal(pm->banflags, 0);
    /* The device's own membership keeps no ban verdict either. */
    if (dm)
      assert_int_equal(dm->banflags, 0);
    cases++;
  }
  assert_int_equal(cases, 2 * 2 * 2 * 5 * 2 * 2 * 2 * 2);
}

/** Our primary's ban cache is the one read: what it says is the verdict, as
 * when the primary speaks itself. */
static void ours_reads_primary_cache(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#cache");
  struct Membership *pm;

  fake_init(&prim, "prim", "prim.host", "pacct", 1, 0);
  fake_init(&dev, "devnick", "dev.host", "dacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  pm = join(ch, &prim, 0);
  join(ch, &dev, CHFL_ALIAS);
  add_ban(&ch->banlist, "prim!*@*", 0);

  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  assert_true(pm->banflags & MBFL_BANVALID_QUIET);
  assert_true(pm->banflags & MBFL_BANNED_QUIET);
  /* The cache, not the list, answers next (a ban's removal invalidates it
   * in the ircd; nothing did here). */
  ch->banlist = NULL;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  pm->banflags = 0;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
}

/** The Apass rule is the primary's membership's. */
static void apass_rule_is_primary(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#apass");

  fake_init(&prim, "prim", "prim.host", "pacct", 1, 0);
  fake_init(&dev, "devnick", "dev.host", "dacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  join(ch, &prim, CHFL_CHANOP | CHFL_CHANNEL_MANAGER);
  join(ch, &dev, CHFL_ALIAS);            /* the device's mirror: no status */
  strcpy(ch->mode.apass, "secret");
  feat_apass_cansend = 0;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  feat_apass_cansend = 1;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
  feat_apass_cansend = 0;
}

/** +a, +O, +M, +r are the primary's: an account-less, non-oper primary is
 * refused even when the device (here) carries an account and +o. */
static void identity_modes_are_primary(void **state)
{
  static const struct { unsigned int mode, exmode; const char *what; } rows[] = {
    { 0, EXMODE_ADMINONLY, "+a" },
    { 0, EXMODE_OPERONLY, "+O" },
    { 0, EXMODE_REGMODERATED, "+M" },
    { MODE_REGONLY, 0, "+r" },
  };
  size_t i;
  int member;

  for (i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
  for (member = 0; member < 2; member++) {
    struct fake_client prim, dev;
    struct Channel *ch = chan_new("#ident");

    fake_init(&prim, "prim", "prim.host", NULL, 1, 0);
    fake_init(&dev, "devnick", "dev.host", "dacct", 1, 0);
    SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
    SetFlag(&dev.cli, FLAG_OPER);
    SetFlag(&dev.cli, FLAG_ADMIN);
    dev.user.alias_primary = &prim.cli;
    join(ch, &prim, 0);
    if (member)
      join(ch, &dev, CHFL_ALIAS);
    ch->mode.mode = rows[i].mode;
    ch->mode.exmode = rows[i].exmode;
    if (client_can_send_to_channel(&dev.cli, ch, 0) != 0)
      fail_msg("%s, device %s: spoke by its own identity", rows[i].what,
               member ? "a member" : "not a member");
    /* the primary qualifies: the device speaks */
    SetFlag(&prim.cli, FLAG_ACCOUNT);
    ircd_strncpy(prim.user.account, "pacct", sizeof(prim.user.account));
    SetFlag(&prim.cli, FLAG_OPER);
    SetFlag(&prim.cli, FLAG_ADMIN);
    if (client_can_send_to_channel(&dev.cli, ch, 0) != 1)
      fail_msg("%s, device %s: refused though its primary qualifies",
               rows[i].what, member ? "a member" : "not a member");
  }
}

/** A device that is not a member is held to +n, as any non-member. */
static void nonmember_device_and_plus_n(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#n");

  fake_init(&prim, "prim", "prim.host", "pacct", 1, 0);
  fake_init(&dev, "devnick", "dev.host", "dacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  join(ch, &prim, CHFL_VOICE);          /* the primary is in, voiced */
  ch->mode.mode = MODE_NOPRIVMSGS;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  ch->mode.mode = 0;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
}

/** A member that is not a device keeps the stock rules: voice speaks under
 * +m and before +Z; a plaintext unvoiced member is refused in +Z; a ban
 * silences; another server's member is not judged here. */
static void stock_member_unchanged(void **state)
{
  struct fake_client u, r;
  struct Channel *ch = chan_new("#stock");
  struct Membership *um, *rm;

  fake_init(&u, "user", "user.host", NULL, 1, 0);
  fake_init(&r, "rem", "rem.host", NULL, 0, 0);
  um = join(ch, &u, 0);
  rm = join(ch, &r, 0);
  ch->mode.exmode = EXMODE_SSLONLY;
  assert_int_equal(member_can_send_to_channel(um, 0), 0);
  um->status |= CHFL_VOICE;
  assert_int_equal(member_can_send_to_channel(um, 0), 1);
  ch->mode.exmode = 0;
  ch->mode.mode = MODE_MODERATED;
  assert_int_equal(member_can_send_to_channel(um, 0), 1);
  um->status &= ~CHFL_VOICE;
  assert_int_equal(member_can_send_to_channel(um, 0), 0);
  ch->mode.mode = 0;
  add_ban(&ch->banlist, "user!*@*", 0);
  assert_int_equal(client_can_send_to_channel(&u.cli, ch, 0), 0);
  assert_int_equal(member_can_send_to_channel(rm, 0), 1);
  /* a non-member, stock: +n refuses, a ban silences, +Z by its own TLS */
  {
    struct fake_client o;
    fake_init(&o, "out", "out.host", NULL, 1, 0);
    ch->mode.mode = MODE_NOPRIVMSGS;
    assert_int_equal(client_can_send_to_channel(&o.cli, ch, 0), 0);
    ch->mode.mode = 0;
    assert_int_equal(client_can_send_to_channel(&o.cli, ch, 0), 1);
    ch->mode.exmode = EXMODE_SSLONLY;
    assert_int_equal(client_can_send_to_channel(&o.cli, ch, 0), 0);
    SetFlag(&o.cli, FLAG_SSL);
    assert_int_equal(client_can_send_to_channel(&o.cli, ch, 0), 1);
    ch->mode.exmode = 0;
    add_ban(&ch->banlist, "out!*@*", 0);
    assert_int_equal(client_can_send_to_channel(&o.cli, ch, 0), 0);
  }
}

/** Another server's device (a replica here) is not judged by this server
 * (the receive side is unchanged): a member speaks as any remote member. */
static void remote_device_unchanged(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#rdev");
  struct Membership *dm;

  fake_init(&prim, "prim", "prim.host", "pacct", 0, 0);
  fake_init(&dev, "devnick", "dev.host", "pacct", 0, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  join(ch, &prim, 0);
  dm = join(ch, &dev, CHFL_ALIAS);
  ch->mode.mode = MODE_MODERATED;
  assert_int_equal(member_can_send_to_channel(dm, 0), 1);
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
}

/** A ban that matches only the device's own identity (its nick and host
 * here; nobody can see them to write one) does not silence it: the
 * primary's identity is the one judged, member or not. */
static void device_only_ban_lets_it_speak(void **state)
{
  int member;

  for (member = 0; member < 2; member++) {
    struct fake_client prim, dev;
    struct Channel *ch = chan_new("#devban");

    fake_init(&prim, "prim", "prim.host", "pacct", 1, 0);
    fake_init(&dev, "devnick", "dev.host", "dacct", 1, 0);
    SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
    dev.user.alias_primary = &prim.cli;
    join(ch, &prim, 0);
    if (member)
      join(ch, &dev, CHFL_ALIAS);
    add_ban(&ch->banlist, "devnick!*@*", 0);
    add_ban(&ch->banlist, "*!*@dev.host", 0);
    add_ban(&ch->banlist, "~a:dacct", 0);
    if (client_can_send_to_channel(&dev.cli, ch, 0) != 1)
      fail_msg("device %s: silenced by a ban on its own identity",
               member ? "a member" : "not a member");
  }
}

/** A held ghost of ours as the primary: ours (MyUser), so its ban cache
 * is read and kept, as when it speaks itself; its voice lets the device
 * speak. */
static void held_ghost_primary(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#ghost");
  struct Membership *pm;

  fake_init(&prim, "prim", "prim.host", "pacct", 1, 0);
  SetFlag(&prim.cli, FLAG_BOUNCER_HOLD);
  fake_init(&dev, "devnick", "dev.host", "dacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  pm = join(ch, &prim, 0);
  join(ch, &dev, CHFL_ALIAS);
  add_ban(&ch->banlist, "prim!*@*", 0);
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  assert_true(pm->banflags & MBFL_BANVALID_QUIET);
  pm->status |= CHFL_VOICE;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
}

/** The state a refused D.2 demote finish leaves: a device whose "primary"
 * is itself an alias (the demoted connection, with no primary of its
 * own).  Pinned: no recursion -- that alias's membership and identity are
 * judged as a primary's would be. */
static void alias_of_alias_primary(void **state)
{
  struct fake_client mid, dev;
  struct Channel *ch = chan_new("#aoa");
  struct Membership *mm;

  fake_init(&mid, "mid", "mid.host", "pacct", 1, 0);
  SetFlag(&mid.cli, FLAG_BOUNCER_ALIAS);          /* no primary of its own */
  fake_init(&dev, "devnick", "dev.host", "pacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &mid.cli;
  mm = join(ch, &mid, CHFL_ALIAS);
  join(ch, &dev, CHFL_ALIAS);
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
  ch->mode.mode = MODE_MODERATED;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  ch->mode.mode = 0;
  add_ban(&ch->banlist, "mid!*@*", 0);
  mm->banflags = 0;          /* a new ban invalidates the cache (mode.c) */
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
}

/** A device's zombie membership is no membership: the non-member rules
 * (+n refuses though the primary is a voiced member). */
static void zombie_device_membership(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#zomb");
  struct Membership *dm;

  fake_init(&prim, "prim", "prim.host", "pacct", 1, 0);
  fake_init(&dev, "devnick", "dev.host", "pacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  join(ch, &prim, CHFL_VOICE);
  dm = join(ch, &dev, CHFL_ALIAS | CHFL_ZOMBIE);
  ch->mode.mode = MODE_NOPRIVMSGS;
  assert_int_equal(member_can_send_to_channel(dm, 0), 0);
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  ch->mode.mode = 0;
  assert_int_equal(member_can_send_to_channel(dm, 0), 1);
}

/** Another server's primary that is the channel's manager (it joined with
 * the Apass there).  CHFL_CHANNEL_MANAGER is set only by the server the
 * join happened on (m_join), so here its membership shows just the op:
 * the device speaks, where the primary itself is refused at its own
 * server (APASS_CANSEND off).  Pinned divergence; were the flag ever
 * carried, the rule would apply. */
static void remote_apass_manager_divergence(void **state)
{
  struct fake_client prim, dev;
  struct Channel *ch = chan_new("#rapass");
  struct Membership *pm;

  fake_init(&prim, "prim", "prim.host", "pacct", 0, 0);
  fake_init(&dev, "devnick", "dev.host", "pacct", 1, 0);
  SetFlag(&dev.cli, FLAG_BOUNCER_ALIAS);
  dev.user.alias_primary = &prim.cli;
  pm = join(ch, &prim, CHFL_CHANOP);       /* as this server knows it */
  join(ch, &dev, CHFL_ALIAS);
  strcpy(ch->mode.apass, "secret");
  feat_apass_cansend = 0;
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 1);
  pm->status |= CHFL_CHANNEL_MANAGER;      /* not carried today */
  assert_int_equal(client_can_send_to_channel(&dev.cli, ch, 0), 0);
  assert_int_equal(pm->banflags, 0);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(device_grid),
    cmocka_unit_test(ours_reads_primary_cache),
    cmocka_unit_test(apass_rule_is_primary),
    cmocka_unit_test(identity_modes_are_primary),
    cmocka_unit_test(nonmember_device_and_plus_n),
    cmocka_unit_test(stock_member_unchanged),
    cmocka_unit_test(remote_device_unchanged),
    cmocka_unit_test(device_only_ban_lets_it_speak),
    cmocka_unit_test(held_ghost_primary),
    cmocka_unit_test(alias_of_alias_primary),
    cmocka_unit_test(zombie_device_membership),
    cmocka_unit_test(remote_apass_manager_divergence),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
