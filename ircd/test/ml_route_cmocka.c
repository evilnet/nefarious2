/*
 * ml_route_cmocka.c - CMocka tests for ml_route_carries_multiline().
 *
 * The predicate the originating server of a multiline batch decides by:
 * does every server on the way to the recipient's server take ML?  The
 * tests build small server trees by hand (cli_serv()->up chains ending
 * at &me) and check the answer for each shape the network can have:
 * fork links only, a legacy hop on the way, a fork server with its
 * multiline cap off, a far server whose ML announcement was lost, and
 * the shapes no network has (a non-server in the chain, a loop).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <cmocka.h>

#include "client.h"
#include "ircd_defs.h"
#include "struct.h"
#include "ml_route.h"

struct Client me;

#define F_V   1   /* IRCv3-aware: 'v' in its SERVER line */
#define F_ML  2   /* announced ML */
#define FORK  (F_V | F_ML)

struct node {
  struct Client cli;
  struct Server serv;
};

/** Make \a n a server one hop further from us than \a up. */
static struct Client *
mk(struct node *n, struct Client *up, int flags)
{
  memset(n, 0, sizeof(*n));
  cli_status(&n->cli) = STAT_SERVER;
  cli_serv(&n->cli) = &n->serv;
  n->serv.up = up;
  if (flags & F_V)
    SetIRCv3Aware(&n->cli);
  if (flags & F_ML)
    SetMultiline(&n->cli);
  return &n->cli;
}

static int
setup(void **state)
{
  (void)state;
  memset(&me, 0, sizeof(me));
  cli_status(&me) = STAT_ME;
  return 0;
}

/* ---- trivial ends ---- */

static void
test_null_is_no(void **state)
{
  (void)state;
  assert_false(ml_route_carries_multiline(NULL));
}

static void
test_me_is_yes(void **state)
{
  (void)state;
  assert_true(ml_route_carries_multiline(&me));
}

/* ---- one hop: our own link ---- */

static void
test_direct_fork_link(void **state)
{
  struct node a;
  (void)state;
  assert_true(ml_route_carries_multiline(mk(&a, &me, FORK)));
}

static void
test_direct_legacy_link(void **state)
{
  struct node a;
  (void)state;
  assert_false(ml_route_carries_multiline(mk(&a, &me, 0)));
}

/* A fork server with its multiline cap off: IRCv3-aware, no ML. */
static void
test_direct_fork_cap_off(void **state)
{
  struct node a;
  (void)state;
  assert_false(ml_route_carries_multiline(mk(&a, &me, F_V)));
}

/* A server that announced ML but is not IRCv3-aware: no network makes
 * one (ML crosses only 'v' links), and the 'v' term refuses it. */
static void
test_direct_ml_without_v(void **state)
{
  struct node a;
  (void)state;
  assert_false(ml_route_carries_multiline(mk(&a, &me, F_ML)));
}

/* ---- longer ways ---- */

/* us - fork - fork - fork */
static void
test_three_fork_hops(void **state)
{
  struct node a, b, c;
  struct Client *pa, *pb;
  (void)state;
  pa = mk(&a, &me, FORK);
  pb = mk(&b, pa, FORK);
  assert_true(ml_route_carries_multiline(mk(&c, pb, FORK)));
  assert_true(ml_route_carries_multiline(pb));
  assert_true(ml_route_carries_multiline(pa));
}

/* The prod case (giskard - Fractal - Thunderbird - luna):
 * us - fork - legacy - legacy.  Our next hop takes ML; the way does
 * not, for the legacy target and for the legacy relay alike. */
static void
test_fork_then_legacy(void **state)
{
  struct node a, b, c;
  struct Client *pa, *pb, *pc;
  (void)state;
  pa = mk(&a, &me, FORK);
  pb = mk(&b, pa, 0);
  pc = mk(&c, pb, 0);
  assert_true(ml_route_carries_multiline(pa));
  assert_false(ml_route_carries_multiline(pb));
  assert_false(ml_route_carries_multiline(pc));
}

/* us - fork - legacy - fork: the far fork server is seen without 'v'
 * (the legacy hop does not repeat it) and without ML (the announcement
 * does not cross the legacy hop).  Even with both flags somehow set on
 * it, the legacy hop on the way makes the answer no. */
static void
test_fork_behind_legacy(void **state)
{
  struct node a, b, c;
  struct Client *pa, *pb;
  (void)state;
  pa = mk(&a, &me, FORK);
  pb = mk(&b, pa, 0);
  assert_false(ml_route_carries_multiline(mk(&c, pb, 0)));
  assert_false(ml_route_carries_multiline(mk(&c, pb, FORK)));
}

/* us - fork - fork(cap off) - fork: the cap-off relay would not be
 * handed the batch by our next hop (it forwards only to links that
 * announced ML), so the far fork server is not reached. */
static void
test_cap_off_relay(void **state)
{
  struct node a, b, c;
  struct Client *pa, *pb;
  (void)state;
  pa = mk(&a, &me, FORK);
  pb = mk(&b, pa, F_V);
  assert_false(ml_route_carries_multiline(mk(&c, pb, FORK)));
  assert_false(ml_route_carries_multiline(pb));
}

/* An unpatched peer bursts the other servers' ML lines before it
 * introduces them, so a server that linked before us is seen with 'v'
 * and without ML: the answer is the fallback, never a batch a hop drops. */
static void
test_lost_announcement_degrades_to_fallback(void **state)
{
  struct node a, b;
  struct Client *pa;
  (void)state;
  pa = mk(&a, &me, FORK);
  assert_false(ml_route_carries_multiline(mk(&b, pa, F_V)));
}

/* ---- shapes no network has ---- */

static void
test_non_server_in_chain(void **state)
{
  struct node a, b;
  struct Client *pa;
  (void)state;
  pa = mk(&a, &me, FORK);
  cli_status(pa) = STAT_UNKNOWN;
  assert_false(ml_route_carries_multiline(mk(&b, pa, FORK)));
}

static void
test_server_without_serv_struct(void **state)
{
  struct node a;
  struct Client *pa;
  (void)state;
  pa = mk(&a, &me, FORK);
  cli_serv(pa) = NULL;
  assert_false(ml_route_carries_multiline(pa));
}

/* A chain that never reaches &me: it ends at NULL, or loops. */
static void
test_chain_without_me(void **state)
{
  struct node a, b;
  struct Client *pa, *pb;
  (void)state;
  pa = mk(&a, NULL, FORK);
  assert_false(ml_route_carries_multiline(pa));
  pb = mk(&b, pa, FORK);
  a.serv.up = pb;   /* a <-> b */
  assert_false(ml_route_carries_multiline(pb));
}

static void
test_hop_bound(void **state)
{
  static struct node chain[ML_ROUTE_MAX_HOPS + 1];
  struct Client *up = &me;
  int i;
  (void)state;
  for (i = 0; i < ML_ROUTE_MAX_HOPS; i++)
    up = mk(&chain[i], up, FORK);
  assert_true(ml_route_carries_multiline(up));      /* exactly the bound */
  up = mk(&chain[ML_ROUTE_MAX_HOPS], up, FORK);
  assert_false(ml_route_carries_multiline(up));     /* one past it */
}

int
main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test_setup(test_null_is_no, setup),
    cmocka_unit_test_setup(test_me_is_yes, setup),
    cmocka_unit_test_setup(test_direct_fork_link, setup),
    cmocka_unit_test_setup(test_direct_legacy_link, setup),
    cmocka_unit_test_setup(test_direct_fork_cap_off, setup),
    cmocka_unit_test_setup(test_direct_ml_without_v, setup),
    cmocka_unit_test_setup(test_three_fork_hops, setup),
    cmocka_unit_test_setup(test_fork_then_legacy, setup),
    cmocka_unit_test_setup(test_fork_behind_legacy, setup),
    cmocka_unit_test_setup(test_cap_off_relay, setup),
    cmocka_unit_test_setup(test_lost_announcement_degrades_to_fallback, setup),
    cmocka_unit_test_setup(test_non_server_in_chain, setup),
    cmocka_unit_test_setup(test_server_without_serv_struct, setup),
    cmocka_unit_test_setup(test_chain_without_me, setup),
    cmocka_unit_test_setup(test_hop_bound, setup),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
