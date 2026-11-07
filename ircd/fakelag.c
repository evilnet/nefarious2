/*
 * IRC - Internet Relay Chat, ircd/fakelag.c
 *
 * The fake-lag pool: a server-wide budget of lag-seconds behind the
 * post-registration credit, with guaranteed per-class shares.  See include/fakelag.h and
 * doc/design/fakelag-htb.md.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include "config.h"

#include "fakelag.h"
#include "class.h"
#include "client.h"
#include "ircd.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_string.h"
#include "msg.h"
#include "random.h"

#include <string.h>

/** Slots in the table of account budgets (a power of two), and how many a
 * lookup tries before it gives up and lends nothing.  Fixed at build time:
 * the table is a static array, and a lookup's cost is FAKELAG_PROBE. */
#define FAKELAG_SLOTS      1024
#define FAKELAG_PROBE      16
/** Clamps on the features, so the refill math stays in int. */
#define FAKELAG_POOL_MAX   100000
#define FAKELAG_BORROW_MAX 600
#define FAKELAG_TIME_MAX   3600

/** The commands that may draw on the pool: the connect-time catch-up.
 * PRIVMSG and NOTICE are left out, so the pool never lets a client send
 * more messages at once than it could without it. */
static const char *const borrowers[] = {
  MSG_JOIN, MSG_CHATHISTORY, MSG_MODE, MSG_MARKREAD
};

/** The part of FAKELAG_POOL no class has reserved. */
static struct FakelagBucket unreserved;

/** What an account has borrowed in its current window.  An entry is
 * made at the account's first actual draw, compared by name, and never
 * reused while its window is open, so no account can push another out.
 * When every slot a name may use is open, that name borrows nothing. */
struct budget {
  char   account[ACCOUNTLEN + 1]; /**< Account name; "" = free. */
  time_t start;                   /**< When the window opened. */
  int    used;                    /**< Seconds borrowed in it. */
};
static struct budget budgets[FAKELAG_SLOTS];
static unsigned int  budget_seed;   /**< Keeps the slots unguessable. */

/** What a draw is charged to. */
struct draw {
  const char             *account;  /**< Whose budget. */
  struct ConnectionClass *cl;       /**< Whose share; may be NULL. */
};

/** Clamp @a v to [0, @a hi]. */
static int clamp(int v, int hi)
{
  if (v < 0)
    return 0;
  if (v > hi)
    return hi;
  return v;
}

/** A time feature, clamped to [1, FAKELAG_TIME_MAX]. */
static int seconds(enum Feature feat)
{
  int v = clamp(feature_int(feat), FAKELAG_TIME_MAX);

  return v ? v : 1;
}

/** May @a cmd draw on the pool?
 * @param[in] cmd The command's canonical name (struct Message::cmd).
 * @return Non-zero if it is one of #borrowers.
 */
int fakelag_borrows(const char *cmd)
{
  size_t i;

  if (!cmd)
    return 0;
  for (i = 0; i < sizeof(borrowers) / sizeof(borrowers[0]); i++)
    if (!strcmp(cmd, borrowers[i]))
      return 1;
  return 0;
}

/** Settle @a b to now, refilling it to @a cap over 60 seconds, then take
 * up to @a want seconds from it.  Settled only when drawn on: a long gap,
 * a forward clock step or a raised cap credits at most one cap, and a
 * backward step adds nothing.  A bucket starts empty and begins to fill
 * at the first grant that could draw on it. */
static int bucket_take(struct FakelagBucket *b, int cap, int want)
{
  time_t dt = (b->last && CurrentTime > b->last) ? CurrentTime - b->last : 0;
  int got;

  b->last = CurrentTime;
  if (dt > 60)
    dt = 60;
  b->rem += (int)dt * cap;            /* at most 60 * FAKELAG_POOL_MAX */
  b->level += b->rem / 60;
  b->rem %= 60;
  if (b->level >= cap) {
    b->level = cap;
    b->rem = 0;
  }
  if (want <= 0)
    return 0;
  got = want < b->level ? want : b->level;
  b->level -= got;
  return got;
}

/** A class's guaranteed share, in lag-seconds per minute. */
static int share_of(const struct ConnectionClass *cl)
{
  return cl ? clamp(LagShare(cl), FAKELAG_POOL_MAX) : 0;
}

/** Take up to @a want seconds for a client of class @a cl: from the
 * class's own share first, then from the part of FAKELAG_POOL that no
 * class reserved.  A class never reaches another class's share, so a
 * quiet class keeps its guarantee however hard the others draw.
 * @param[in] cl The client's class, or NULL.
 * @param[in] want Seconds wanted; 0 just starts the clocks.
 * @return Seconds taken.
 */
int fakelag_pool_take(struct ConnectionClass *cl, int want)
{
  int pool = clamp(feature_int(FEAT_FAKELAG_POOL), FAKELAG_POOL_MAX);
  const struct ConnectionClass *c;
  int reserved = 0, got = 0;

  if (pool <= 0)
    return 0;                         /* off: shares lend nothing either */
  for (c = get_class_list(); c; c = c->next)
    if (c->valid && reserved < FAKELAG_POOL_MAX)
      reserved += share_of(c);
  if (cl)
    got = bucket_take(&cl->lag_bucket, share_of(cl), want);
  got += bucket_take(&unreserved, pool > reserved ? pool - reserved : 0,
                     want - got);
  return got;
}

/** Is @a b's window still open?  A window that opened in the future (the
 * clock stepped back) restarts now, keeping what was borrowed in it. */
static int budget_open(struct budget *b)
{
  if (!b->account[0])
    return 0;
  if (CurrentTime < b->start)
    b->start = CurrentTime;
  return CurrentTime - b->start < seconds(FEAT_FAKELAG_ACCOUNT_TIME);
}

/** Find @a account's budget, or the slot its first draw would take.
 * Names compare as the server compares them (ircd_strcmp()).
 * @param[in] account The account name.
 * @return Its open budget; a closed or free slot for it (account[0] is
 *   then 0 or another name); NULL when every slot it may use is open. */
static struct budget *budget_find(const char *account)
{
  struct budget *spare = NULL;
  unsigned int h, i;
  const char *p;

  if (!budget_seed)
    budget_seed = ircrandom() | 1;
  h = 2166136261u ^ budget_seed;               /* FNV-1a over the fold */
  for (p = account; *p; p++)
    h = (h ^ (unsigned char)ToLower(*p)) * 16777619u;
  h ^= h >> 16;                                /* mix the high bits down */
  h *= 0x85ebca6bu;
  h ^= h >> 13;
  for (i = 0; i < FAKELAG_PROBE; i++) {
    struct budget *b = &budgets[(h + i) & (FAKELAG_SLOTS - 1)];
    int open = budget_open(b);

    if (open && !ircd_strcmp(b->account, account))
      return b;
    if (!open && !spare)
      spare = b;
  }
  return spare;
}

/** The pool, through the budget of the account being charged. */
static int take_for_account(void *ctx, int want)
{
  const struct draw *d = ctx;
  int cap = clamp(feature_int(FEAT_FAKELAG_BORROW), FAKELAG_BORROW_MAX);
  struct budget *b = budget_find(d->account);
  int mine, room, got;

  if (!b)
    return 0;
  mine = b->account[0] && !ircd_strcmp(b->account, d->account)
         && budget_open(b);
  room = cap - (mine ? b->used : 0);
  if (room <= 0)
    return 0;
  got = fakelag_pool_take(d->cl, want < room ? want : room);
  if (got > 0) {
    if (!mine) {
      ircd_strncpy(b->account, d->account, sizeof(b->account));
      b->start = CurrentTime;
      b->used = 0;
    }
    b->used += got;
  }
  return got;
}

/** Charge @a lag to @a cptr: its grace, then (for a command that may
 * borrow, while its allowance is live) the pool through its account's
 * budget and its class's share, then its clock.
 * @param[in] cptr The local client the line came from.
 * @param[in] cmd The command's canonical name.
 * @param[in] lag Seconds the line costs.
 * @return Seconds to add to the client's clock.
 */
int fakelag_charge_client(struct Client *cptr, const char *cmd, int lag)
{
  struct draw d;
  int (*take)(void *, int) = NULL;

  /* Logged out since the grant (services can do that): no account to
   * charge a draw to, so the allowance goes. */
  if (cli_lagborrow_until(cptr)
      && (!IsAccount(cptr) || !cli_account(cptr)[0]))
    cli_lagborrow_until(cptr) = 0;
  if (cli_lagborrow_until(cptr) && fakelag_borrows(cmd)) {
    d.account = cli_account(cptr);
    d.cl = get_client_class_conf(cptr);
    take = take_for_account;
  }
  return fakelag_spend(&cli_lagcredit(cptr), cli_lagborrow_until(cptr),
                       CurrentTime, take, &d, lag);
}

/** Grant the post-registration credit, and the pool allowance when the
 * pool is on.  Called at the end of every registration path (fresh
 * registration, held-session revive, alias attach).
 *
 * Modern clients burst init commands (MONITOR, METADATA SUB, WHO,
 * CHATHISTORY...) right after 001, and the ~10 s cli_since headroom covers
 * only ~5 of them.  The credit raises that initial budget; every command
 * is still charged (credit, not exemption), and recvQ byte caps still
 * bound the wire.  It is not a clock set below now: read_packet() floors
 * the clock to the last read time and would erase that.
 * @param[in] cptr The client that keeps the socket: on a revive that is
 *   the ghost, not the freed incoming client.
 */
void fakelag_grant(struct Client *cptr)
{
  int grace = feature_int(FEAT_POSTREG_GRACE);

  /* A revived ghost may still carry credit from its last life. */
  cli_lagcredit(cptr) = 0;
  cli_lagborrow_until(cptr) = 0;

  /* Authenticated clients only: an anonymous connection (the
   * drive-by/WS-flood surface) keeps the classic ~5-command burst. */
  if (grace <= 0 || !IsAccount(cptr))
    return;
  cli_lagcredit(cptr) = grace;

  /* A class with fake lag off never spends it: lend nothing.  How much
   * the account may still borrow is checked at each draw. */
  if (feature_int(FEAT_FAKELAG_POOL) <= 0
      || feature_int(FEAT_FAKELAG_BORROW) <= 0 || get_lag_factor(cptr) == 0)
    return;
  /* start the clocks of the pool and of the class's share */
  fakelag_pool_take(get_client_class_conf(cptr), 0);
  cli_lagborrow_until(cptr) = CurrentTime + seconds(FEAT_FAKELAG_BORROW_TIME);
}

#ifdef CMOCKA_TEST
/** Empty the pool, forget when it was last settled and every budget. */
void fakelag_test_reset(void)
{
  memset(&unreserved, 0, sizeof(unreserved));
  memset(budgets, 0, sizeof(budgets));
}
#endif
