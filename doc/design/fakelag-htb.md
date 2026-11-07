# A shared budget for the connect burst

Status: v5, implemented on this branch, 2026-11-06. Base: evilnet
`ircv3.2-upgrade` @ 5725812e. All features are off by default.

v5 takes the review on #158: guaranteed per-class shares of one parent pool,
only the connect-time catch-up commands borrow (not PRIVMSG or NOTICE), both
windows are features, the draw is passed its context instead of a file-level
pointer, and the per-connection allowance counter is gone (the account budget
already bounds it).

## Problem

Every non-oper command from a registered client is charged
`lag = lagmin + len / lagfactor` seconds (defaults 2 and 120; `len` counts from
the first parameter when there is one, so tags and the command token are
usually free) onto `cli_since`
(`ircd/parse.c` L1658-1671). `read_packet()` parses the next line only while
`cli_since - CurrentTime < 10` (`ircd/s_bsd.c` L1693), and that check comes
before the charge. Each socket read with data pulls `cli_since` up to now
(L1313-1314), so idle time never banks; leftover lines are retried on a 2 s
timer (L1746). In practice: about 5 short commands at once, then one every 2 s.

Lines before 001 are free: a fresh `Connection` is zeroed, so the cached
`con_lag_factor` is 0 and `get_lag_factor()` returns it (`class.c` L388), and
`parse.c` L1658 requires `lagfactor > 0`. `register_user` resets the cache to -2
(`s_user.c` L626-627), so charging starts at 001 with the clock at about now.

`POSTREG_GRACE` (default 20) gives a logged-in connection a one-shot credit at
registration (`con_lagcredit`), which `fakelag_charge()` (`include/fakelag.h`)
spends before the clock. That raises the post-001 burst to about 15 short
commands.

A phone needs more, because it reconnects a lot (network changes, the OS
killing a backgrounded socket), and each reconnect re-sends its post-001 work:
one JOIN, `CHATHISTORY TARGETS`, a history fetch and read marker per channel,
MONITOR, METADATA SUB, a push renewal. With 15 channels that is 30-plus
commands, so the catch-up still dribbles in at one command per 2 s for most of a
minute.

The grace cannot just be made bigger. It is the same size for every connection,
so after a restart or a netsplit heal a big grace is a big burst from everyone at
once.

## Idea

A shared budget that backs the connect grace when the server can spare it,
shaped as a hierarchical token bucket.

- **The parent** is `FAKELAG_POOL` lag-seconds that refill over a minute.
- **Classes.** A `Class` block may reserve part of it with `fakelagshare`.
  Each share is its own bucket, refilled over a minute. What no class
  reserved (`FAKELAG_POOL` minus the shares) is one more bucket that every
  class shares. A client draws on its class's share first, then on the
  unreserved part, never on another class's share. So however hard one class
  draws, a quiet class keeps its guarantee. With no shares set (the default),
  the whole pool is unreserved, as in v4.
- **Connections.** A logged-in registration may draw for
  `FAKELAG_BORROW_TIME` seconds (default 30), once its own `POSTREG_GRACE` is
  spent. The point is the connect burst; a connection cannot sit on it.
- **Commands.** Only `JOIN`, `CHATHISTORY`, `MODE` and `MARKREAD` draw on the
  pool, from one table in `fakelag.c` (`borrowers[]`), so it is easy to widen
  later. Everything else, PRIVMSG and NOTICE included, spends the grace and
  then the clock as today. The pool never lets a client send more messages at
  once than it could without it.
- **Accounts.** An account draws at most `FAKELAG_BORROW` per
  `FAKELAG_ACCOUNT_TIME` seconds (default 60), across all its connections and
  classes. A phone that flaps gets what its last connection left; two devices
  share it; a reconnect loop gets one allowance a minute. The budget opens at
  the account's first actual draw, so a connection that dropped before its
  burst costs nothing.
- The pool is charged only for seconds actually spent, and once it is empty
  connections get today's grace, never less.
- Every bucket starts empty and fills over a minute, so a restart (when
  IPcheck's clone throttle is still off, `IPCHECK_CLONE_DELAY`, default 600 s)
  lends nothing to the first wave.

A lone reconnecting phone with the suggested settings gets `POSTREG_GRACE`
plus 60 s more for its catch-up: about 40 short commands at once, against
about 15 today.

It is an opportunistic boost for a quiet server, not storm control. The
guaranteed part, `POSTREG_GRACE` for each connection, is today's behaviour and
unchanged.

## Code

Per connection (`include/client.h`): `con_lagborrow_until`, the last second
the connection may draw; 0 means it may not. Per class (`include/class.h`):
`lag_share` and its bucket. The rest is in `ircd/fakelag.c`.

`include/fakelag.h` keeps the charge order pure, so it can be unit-tested:

```c
static inline int fakelag_spend(int *credit, time_t until, time_t now,
                                int (*take)(void *ctx, int want), void *ctx,
                                int lag)
{
  lag = fakelag_charge(credit, lag);
  if (lag > 0 && take && now <= until)
    lag -= take(ctx, lag);
  return lag;
}
```

The charge site keeps its single-statement shape under the existing multiline
guard (`parse.c`):

```c
    if (!cli_ml_batch_id(cptr)[0])
      cli_since(cptr) += fakelag_charge_client(cptr, mptr->cmd, lag);
```

`fakelag_charge_client()` passes a `take` only when the command is in
`borrowers[]` and the allowance is live, with the account and the class in a
`struct draw` on the stack. The draw goes through the account's budget, then
the class's share, then the unreserved bucket. With no allowance it is
`fakelag_charge()` exactly, as today.

The grant, called at the end of all three registration paths (fresh
registration, held-session revive on the ghost, alias attach):

```c
void fakelag_grant(struct Client *cptr)
{
  int grace = feature_int(FEAT_POSTREG_GRACE);

  /* A revived ghost may still carry credit from its last life. */
  cli_lagcredit(cptr) = 0;
  cli_lagborrow_until(cptr) = 0;

  if (grace <= 0 || !IsAccount(cptr))
    return;
  cli_lagcredit(cptr) = grace;

  if (feature_int(FEAT_FAKELAG_POOL) <= 0
      || feature_int(FEAT_FAKELAG_BORROW) <= 0 || get_lag_factor(cptr) == 0)
    return;
  /* start the clocks of the pool and of the class's share */
  fakelag_pool_take(get_client_class_conf(cptr), 0);
  cli_lagborrow_until(cptr) = CurrentTime + seconds(FEAT_FAKELAG_BORROW_TIME);
}
```

How much the account may still borrow is checked at each draw, not at the
grant. A bucket settles only when drawn on: a long gap, a clock step forward
or a raised cap credits at most one cap, and a step back adds nothing. The
remainder carries over, so a cap that is not a multiple of 60 refills at its
true rate.

The account budgets are a static table of 1024 slots, each name tried in a
window of 16 picked by a seeded hash, compared with `ircd_strcmp()`. Both
sizes stay compile-time constants: the table is a static array, and the
probe window is the cost of every draw. An open budget is never pushed out.

**Off means off.** With `FAKELAG_POOL` 0 no allowance is set and the shares
lend nothing, so every charge is `fakelag_charge()`, and the grant sets
exactly what the three inline blocks set before.

Suggested start for AfterNET: `FAKELAG_POOL` 600, `FAKELAG_BORROW` 60, no
shares.

## Tests

`ircd/test/fakelag_cmocka.c`, 54 cases. `fakelag_spend()` needs only a fake
`take`; the `fakelag.c` cases stub `CurrentTime`, the features,
`get_lag_factor()` and two classes.

- Spend order: grace, then the pool while the allowance is live, then the
  clock; no `take` or no allowance is `fakelag_charge()` exactly.
- Grant: pool off, borrow off, anonymous, lag factor 0, a revive clearing the
  old state, `FAKELAG_BORROW_TIME` and its clamps.
- Buckets: start empty, fill in a minute, a long gap or raised cap credits
  one cap, a step back adds nothing, the remainder carries, a lowered cap
  clamps, off lends nothing.
- Shares: a class's share survives another class draining the unreserved
  part; unreserved is the pool minus the shares; share first, then
  unreserved; a removed class frees its share; shares over the pool; the
  pool off silences the shares; the account budget spans classes.
- Commands: the `borrowers[]` table; PRIVMSG and NOTICE spend the grace but
  never the pool.
- Account budget: a reconnect loop, an unused allowance, a flap, two devices,
  per account, reopening, the server's case folding, clock steps, an empty
  pool, a full table, a lowered `FAKELAG_BORROW`, a full-length name, a
  logged-out client, `FAKELAG_ACCOUNT_TIME`.

Mutants of the new checks (the command table, the unreserved part, the class
validity test, pool-off, both windows, borrow-off) are all caught.

## Live tests

An ASan + UBSan build of this branch, `BOUNCER_ENABLE` and auto-resume on,
behind an iauth stub that logs each client into the account named by its
ident. `FAKELAG_POOL` 600, `FAKELAG_BORROW` 60, `POSTREG_GRACE` 20. Each client
sends 40 `MODE <self>` (a borrowing command) and counts the replies within a
second.

| Case | Result |
| --- | --- |
| Fresh login | 40 at once (14 with the pool off) |
| Revive of a held session after a dropped socket (resumes its channels) | 40 |
| Alias attach, a second device on a live session (the first stays up) | 40 |
| The same three with `fakelagshare = 100` on the users' class | 40 each |
| A non-borrowing burst (`PING`) with the pool full | 15, as today |
| One account reconnecting in a loop, 18 logins | 40 the first time, then 15; five other users logging in during it get 40 each |

No sanitizer report in any run. Earlier v4 runs (rehash, two linked servers,
a netsplit) behaved as designed; the bucket arithmetic they exercised is
unchanged.

## Checked by tools

The budget table and the class shares are covered by unit tests, ASan,
UBSan, valgrind, gcc `-fanalyzer` and cppcheck, and by mutants of their
checks. The CBMC and z3 results below were run on the v4 pool and
`fakelag_spend()`; v5 keeps the bucket arithmetic as it was and runs it once
per class share, so the bound holds per bucket and the server lends at most
the larger of `FAKELAG_POOL` and the shares' sum per minute.

- ASan + UBSan and valgrind over the unit tests, and ASan + UBSan over a live
  ircd running the probe and a 20-client storm: no reports.
- gcc `-fanalyzer` and cppcheck: clean. scan-build: the same 115 warnings as
  the base commit, none new.
- CBMC, with bounds, pointer, signed-overflow and conversion checks, on any
  input and any state the code can leave: no overflow; the pool stays in
  `[0, cap]` and the remainder in `[0, 60)`; a backward clock step adds nothing;
  `fakelag_spend()` charges between 0 and the line's lag, never grows a credit,
  conserves every second, equals `fakelag_charge()` with no allowance, and
  draws nothing after the window.
- The refill rate, for every run length, in z3 over exact integers (sound
  because CBMC proved there is no overflow). With `P = 60*pool + remainder`,
  one settle never lends plus banks more than `min(gap, 60) * cap`. `P` starts
  at 0 and never goes negative, so over any run the pool lends at most
  `cap * elapsed / 60`, and at most one cap per settle. CBMC alone could not
  close this: the divide by 60 times out even with the gap fixed.
  Mutants of the refill divisor, the backward-step test, the take and the full
  test are all caught. Dropping the 60 s clamp on the gap survives, because the
  cap clamp already bounds the refill; the clamp is there to stop the overflow,
  which the unit tests and CBMC catch.

## The client has to know

Seance never sends past its own model of the server's clock (`FakeLagClock`,
`client/js/irc/fakelag.ts`). It ignores `POSTREG_GRACE` because the server does
not advertise it, so a bigger credit changes nothing for Seance on its own.
Clients that just blast (most desktop clients) benefit at once, and the probe
above shows the server side without any Seance change.

For the Seance half of the demo, the simplest honest option is a per-network
setting in Seance's `config.json` (say `fakeLagCredit: 20`) that the network
sets to match its server. Seance's nefarious2 profile then starts the clock
with that credit after a SASL registration.

Getting the borrowed part as well needs the server to say what it granted, for
example one `NOTE` after 001 under a vendor cap. That is new protocol surface,
so it stays out of this change until the pool proves itself.

## Known limits

- **Many accounts.** The budget is per account, so k accounts draw k
  allowances a minute: with the suggested settings, ten accounts can still
  empty the unreserved part every minute. A class share keeps that class's
  guarantee, and whoever drains the rest only brings everyone else back to
  today's behaviour.
- **IPCHECK_SASL_REFUND.** With refunds on, a logged-in reconnect does not
  count against IPcheck's clone throttle (`IPcheck.c`), so the throttle does
  not slow a reconnect loop. The account budget is what bounds such a loop
  here; the many-accounts limit above is the same with or without refunds.
- **The budget table.** A name whose 16 slots are all open borrows nothing
  that window. Filling a chosen name's window takes 16 accounts that each
  borrow, placed without knowing the seed.
- **Renames.** Budgets are keyed by account name, so an account renamed by
  services (`ACCOUNT M`) starts a fresh budget, and a name reused within the
  window inherits the old one's.
- **Shares over the pool.** If the shares add up to more than
  `FAKELAG_POOL`, nothing is unreserved and each class has only its share.
- **Registration only.** A client that logs in after 001 gets neither the
  grace (as today) nor an allowance.
- **Not every line is charged.** Unknown and shunned commands skip the charge,
  and so do lines inside a multiline batch, while a multiline close charges the
  clock directly (`m_batch.c`).
- **A clock step back still freezes clients.** That happens today too: their
  `cli_since` is left in the future. The buckets' own handling only keeps them
  from locking up.
- **Per server.** Each server has its own pool. Fake lag is local and never
  crosses P10.

## Not in scope

- Borrowing for a client that wakes from the background without
  reconnecting.
- Borrowing for PRIVMSG and NOTICE; widening `borrowers[]` is a one-line
  change once there is a reason.
- Folding the multiline, METADATA, BATCH and WebSocket control-frame meters
  into one hierarchy.
- Advertising the credit to clients.
