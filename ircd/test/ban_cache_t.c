/*
 * ban_cache_t.c - a member's cached ban verdict follows what its bans
 * match.
 *
 * A local member's verdicts on the channel's bans and exceptions (may it
 * speak, may it change nick) are cached on its membership.  They must not
 * outlive a change of what an extended ban matches: its account (~a), its
 * realname (~r), its marks (~m, ~M), its other channels (~c), another
 * channel's lists (~j), and its oper status (the oper form of the hidden
 * host under HOST_HIDING_STYLE 1 and 3).
 *
 * This drives the real predicates: channel.c is included, compiled with
 * -ffunction-sections and linked with --gc-sections, so the program keeps
 * member_can_send_to_channel(), find_no_nickchange_channel(), find_ban(),
 * make_ban() and what they call.  The account, realname and mark changes
 * go through the real ms_account() (m_account.c), ms_svsinfo()
 * (m_svsinfo.c) and add_mark() (s_conf.c), each compiled here the same
 * way.  The rest of the server they reach is stubbed below.
 */
#include "../channel.c"
#include "handlers.h"
#include "s_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

time_t CurrentTime;
time_t TSoffset;
struct Client his;
struct Client *LocalClientArray[MAXCONNECTIONS];

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

static int feat_extended_accounts = 1;  /**< FEAT_EXTENDED_ACCOUNTS */
static int feat_host_hiding_style;      /**< FEAT_HOST_HIDING_STYLE */
static int unexpected;                  /**< replies and errors: none wanted */

int feature_bool(enum Feature feat)
{
  if (feat == FEAT_EXTENDED_ACCOUNTS)
    return feat_extended_accounts;
  return 1;     /* EXTBANS, EXTBAN_*, EXCEPTS, OPERHOST_HIDING: on */
}
int feature_int(enum Feature feat)
{
  if (feat == FEAT_HOST_HIDING_STYLE)
    return feat_host_hiding_style;
  if (feat == FEAT_EXTBAN_j_MAXDEPTH)
    return 1;
  return 0;
}
const char *feature_str(enum Feature feat)
{
  if (feat == FEAT_HIDDEN_HOST)
    return "users.example";
  if (feat == FEAT_HIDDEN_OPERHOST)
    return "staff.example";
  return "";
}
int send_reply(struct Client *to, int reply, ...) { unexpected++; return 0; }
int need_more_params(struct Client *cptr, const char *cmd) { unexpected++; return 0; }
int protocol_violation(struct Client *cptr, const char *pattern, ...)
{
  unexpected++;
  return 0;
}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...) {}
void sendcmdto_serv_butone(struct Client *from, const char *cmd,
                           const char *tok, struct Client *one,
                           const char *pattern, ...) {}
void sendcmdto_flag_serv_butone(struct Client *from, const char *cmd,
                                const char *tok, struct Client *one,
                                int require, int forbid,
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
void sendcmdto_common_channels_capab_butone(struct Client *from,
                                            const char *cmd, const char *tok,
                                            struct Client *one, int withcap,
                                            int skipcap,
                                            const char *pattern, ...) {}
void sendto_opmask_butone(struct Client *one, unsigned int mask,
                          const char *pattern, ...) {}
int hide_hostmask(struct Client *cptr) { return 0; }
/* The login-on-connect replies (ACCOUNT A and D): not sent here. */
int auth_set_account(struct AuthRequest *auth, const char *account)
{
  unexpected++;
  return 0;
}
void auth_end_loc(struct AuthRequest *auth) { unexpected++; }
int account_id_valid(const char *id) { return 0; }
struct SLink *make_link(void) { return calloc(1, sizeof(struct SLink)); }
void free_link(struct SLink *lp) { free(lp); }

/* The user an ACCOUNT or SVSINFO names; the channels a ~j ban names. */
static struct Client *target;
struct Client *findNUser(const char *yxx) { return target; }
struct Client *FindNServer(const char *numeric) { return NULL; }
static struct Channel *known_channels[4];
struct Channel *hSeekChannel(const char *name)
{
  int i;

  for (i = 0; i < 4; i++)
    if (known_channels[i] && !ircd_strcmp(known_channels[i]->chname, name))
      return known_channels[i];
  return NULL;
}

/* ---------- clients, memberships, channels ---------- */

struct fake_client {
  struct Client cli;
  struct Connection con;
  struct User user;
};

/* The server the ACCOUNT and SVSINFO lines come from. */
static struct Client peer;

/** A local user @a nick at @a host, logged in as @a account (or not). */
static void user_init(struct fake_client *f, const char *nick,
                      const char *host, const char *account)
{
  memset(f, 0, sizeof(*f));
  cli_user(&f->cli) = &f->user;
  cli_status(&f->cli) = STAT_USER;
  cli_connect(&f->cli) = &f->con;
  con_client(&f->con) = &f->cli;
  ircd_strncpy(cli_name(&f->cli), nick, sizeof(cli_name(&f->cli)));
  ircd_strncpy(f->user.username, nick, sizeof(f->user.username));
  ircd_strncpy(f->user.host, host, sizeof(f->user.host));
  ircd_strncpy(f->user.realhost, host, sizeof(f->user.realhost));
  ircd_strncpy(cli_info(&f->cli), "a nice person", sizeof(cli_info(&f->cli)));
  if (account) {
    ircd_strncpy(f->user.account, account, sizeof(f->user.account));
    SetFlag(&f->cli, FLAG_ACCOUNT);
  }
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

/** Take @a m off its user's channel list. */
static void part(struct fake_client *f, struct Membership *m)
{
  struct Membership **pp;

  for (pp = &f->user.channel; *pp; pp = &(*pp)->next_channel)
    if (*pp == m) {
      *pp = m->next_channel;
      return;
    }
}

static void add_ban(struct Ban **list, const char *mask)
{
  char buf[NICKLEN + USERLEN + HOSTLEN + 32];
  struct Ban *b;

  ircd_strncpy(buf, mask, sizeof(buf));
  b = make_ban(buf);
  CHECK(b != NULL, "the ban is made", mask);
  if (!b)
    return;
  b->next = *list;
  *list = b;
}

/** Feed "AB AC <user> <args...>" to ms_account() for @a f. */
static void account(struct fake_client *f, const char *a1, const char *a2)
{
  char n[] = "ABAAB", x1[ACCOUNTLEN + 1], x2[ACCOUNTLEN + 1];
  char *parv[] = { "AB", n, x1, x2, NULL };

  ircd_strncpy(x1, a1, sizeof(x1));
  ircd_strncpy(x2, a2 ? a2 : "", sizeof(x2));
  target = &f->cli;
  ms_account(&peer, &peer, a2 ? 4 : 3, parv);
  target = NULL;
}

#define SPEAKS(m) member_can_send_to_channel((m), 0)

int main(void)
{
  cli_status(&peer) = STAT_SERVER;

  /* ~a: an account set (R), changed (M) or removed (U) by services, and
   * an account set by the old (not extended) ACCOUNT. */
  {
    struct fake_client u;
    struct Channel *ch = chan_new("#acct"), *any = chan_new("#anyacct");
    struct Membership *m, *ma;

    user_init(&u, "u", "u.host", NULL);
    m = join(ch, &u, 0);
    ma = join(any, &u, 0);
    add_ban(&ch->banlist, "~a:bad");
    add_ban(&any->banlist, "~!a:*");                /* not logged in */
    CHECK(SPEAKS(m), "~a: not logged in, speaks", "#acct");
    CHECK(!SPEAKS(ma), "~!a:*: not logged in, silenced", "#anyacct");
    account(&u, "R", "good");
    CHECK(SPEAKS(m), "~a: logged in as another, speaks", "R good");
    CHECK(SPEAKS(ma), "~!a:*: logged in, speaks", "R good");
    account(&u, "M", "bad");
    CHECK(!SPEAKS(m), "~a: changed to the banned account, silenced", "M bad");
    account(&u, "U", NULL);
    CHECK(SPEAKS(m), "~a: logged out, speaks", "U");
    CHECK(!SPEAKS(ma), "~!a:*: logged out, silenced", "U");
    account(&u, "R", "bad");
    CHECK(!SPEAKS(m), "~a: logged in as the banned account, silenced", "R bad");
    CHECK(!unexpected, "no reply or error from ACCOUNT", "");

    user_init(&u, "u", "u.host", NULL);
    m = join(ch, &u, 0);
    CHECK(SPEAKS(m), "~a: not logged in, speaks", "#acct");
    feat_extended_accounts = 0;
    account(&u, "bad", NULL);
    feat_extended_accounts = 1;
    CHECK(!SPEAKS(m), "~a: logged in (old ACCOUNT) as the banned account, "
          "silenced", "bad");
  }

  /* ~r: SVSINFO changes the realname. */
  {
    struct fake_client u;
    struct Channel *ch = chan_new("#rn");
    struct Membership *m;
    char n[] = "ABAAB", name[] = "spam spam spam";
    char *parv[] = { "AB", n, name, NULL };

    user_init(&u, "u", "u.host", NULL);
    m = join(ch, &u, 0);
    add_ban(&ch->banlist, "~r:*spam*");
    CHECK(SPEAKS(m), "~r: speaks under its realname", cli_info(&u.cli));
    target = &u.cli;
    ms_svsinfo(&peer, &peer, 3, parv);
    target = NULL;
    CHECK(!strcmp(cli_info(&u.cli), "spam spam spam"), "SVSINFO sets it",
          cli_info(&u.cli));
    CHECK(!SPEAKS(m), "~r: silenced under the realname SVSINFO gave",
          cli_info(&u.cli));
  }

  /* ~m and ~M: a mark given to a registered user (a MARK). */
  {
    struct fake_client u;
    struct Channel *ch = chan_new("#mark"), *ch2 = chan_new("#markua");
    struct Membership *m, *m2;

    user_init(&u, "u", "u.host", NULL);
    m = join(ch, &u, 0);
    m2 = join(ch2, &u, 0);
    add_ban(&ch->banlist, "~m:dnsbl*");
    add_ban(&ch2->banlist, "~M:proxy");
    CHECK(SPEAKS(m) && SPEAKS(m2), "~m, ~M: speaks without marks", "");
    add_mark(&u.cli, "dnsbl-tor");
    CHECK(!SPEAKS(m), "~m: silenced once marked", "dnsbl-tor");
    CHECK(SPEAKS(m2), "~M: another mark, speaks", "dnsbl-tor");
    add_mark(&u.cli, "proxy");
    CHECK(!SPEAKS(m2), "~M: silenced once marked", "proxy");
  }

  /* ~c: the member's other channels and its status there, for speaking
   * and for changing nick. */
  {
    struct fake_client u;
    struct Channel *ch = chan_new("#home"), *bad = chan_new("#bad");
    struct Membership *m, *bm;

    user_init(&u, "u", "u.host", NULL);
    m = join(ch, &u, 0);
    add_ban(&ch->banlist, "~c:#bad");
    CHECK(SPEAKS(m), "~c: speaks outside #bad", "");
    CHECK(!find_no_nickchange_channel(&u.cli), "~c: changes nick outside #bad", "");
    bm = join(bad, &u, 0);
    CHECK(!SPEAKS(m), "~c: silenced in #bad", "");
    CHECK(find_no_nickchange_channel(&u.cli) != NULL,
          "~c: cannot change nick in #bad", "");
    part(&u, bm);
    CHECK(SPEAKS(m), "~c: speaks again after leaving #bad", "");

    ch->banlist = NULL;
    add_ban(&ch->banlist, "~c:@#bad");
    bm = join(bad, &u, 0);
    CHECK(SPEAKS(m), "~c:@: speaks unopped in #bad", "");
    bm->status |= CHFL_CHANOP;
    CHECK(!SPEAKS(m), "~c:@: silenced opped in #bad", "");
    bm->status &= ~CHFL_CHANOP;
    CHECK(SPEAKS(m), "~c:@: speaks again deopped", "");
  }

  /* ~j: another channel's ban list, and its exception list. */
  {
    struct fake_client u;
    struct Channel *ch = chan_new("#home"), *list = chan_new("#list");
    struct Channel *ch2 = chan_new("#home2"), *friends = chan_new("#friends");
    struct Membership *m, *m2;

    known_channels[0] = list;
    known_channels[1] = friends;
    user_init(&u, "u", "u.host", NULL);
    m = join(ch, &u, 0);
    add_ban(&ch->banlist, "~j:#list");
    CHECK(SPEAKS(m), "~j: speaks, #list bans nobody", "");
    add_ban(&list->banlist, "u!*@*");
    CHECK(!SPEAKS(m), "~j: silenced once #list bans it", "");
    list->banlist = NULL;
    CHECK(SPEAKS(m), "~j: speaks again once #list drops the ban", "");

    m2 = join(ch2, &u, 0);
    add_ban(&ch2->banlist, "u!*@*");
    add_ban(&ch2->exceptlist, "~j:#friends");
    CHECK(!SPEAKS(m2), "~j exception: silenced, #friends excepts nobody", "");
    add_ban(&friends->exceptlist, "u!*@*");
    CHECK(SPEAKS(m2), "~j exception: speaks once #friends excepts it", "");
    friends->exceptlist = NULL;
    CHECK(!SPEAKS(m2), "~j exception: silenced once #friends drops it", "");
    known_channels[0] = known_channels[1] = NULL;
  }

  /* The oper form of the hidden host (HOST_HIDING_STYLE 1): becoming an
   * oper, or no longer one, without the shown host changing. */
  {
    struct fake_client u;
    struct Channel *ch = chan_new("#oper"), *ch2 = chan_new("#user");
    struct Membership *m, *m2;

    feat_host_hiding_style = 1;
    user_init(&u, "u", "u.host", "acct");
    m = join(ch, &u, 0);
    m2 = join(ch2, &u, 0);
    add_ban(&ch->banlist, "*!*@acct.staff.example");
    add_ban(&ch2->banlist, "*!*@acct.users.example");
    CHECK(SPEAKS(m) && !SPEAKS(m2), "not an oper: the user form is banned", "");
    SetFlag(&u.cli, FLAG_OPER);
    CHECK(!SPEAKS(m) && SPEAKS(m2), "an oper: the oper form is banned", "");
    ClrFlag(&u.cli, FLAG_OPER);
    CHECK(SPEAKS(m) && !SPEAKS(m2), "deopered: the user form is banned", "");
    feat_host_hiding_style = 0;
  }

  printf("%d checks, %d failed\n", checks, failures);
  return failures ? 1 : 0;
}
