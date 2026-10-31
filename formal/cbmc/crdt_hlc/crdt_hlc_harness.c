/*
 * CBMC harnesses for ircd/crdt_hlc.c (Hybrid Logical Clock).
 *
 * Properties (Kulkarni et al. 2014, the ones the msgid/S2S ordering
 * relies on):
 *   P1  local event:  the new stamp is strictly greater than the old one.
 *   P2  receive:      the new stamp is strictly greater than the old one
 *                     AND (when adopted) than the remote's (pt, l).
 *   P3  bounded rcv:  a refused remote never moves the clock past
 *                     max(old.pt, now).
 *   P4  drift bound:  physical_ms never exceeds max(old.pt, now, remote.pt)
 *                     + 1 (the +1 is the logical-overflow carry).
 *
 * Precondition throughout: physical times are below UINT64_MAX (a
 * millisecond epoch clock does not reach 2^64).
 *
 * Before the fix the logical counter wrapped to 0 at the same
 * physical_ms, failing P1/P2a/P2b with logical = 65535; since the msgid
 * packs logical with a 12-bit counter and 65536 % 4096 == 0, the wrap
 * re-minted an earlier msgid exactly.
 *   P5  hlc_compare is a strict total order (antisymmetric, reflexive 0).
 */
#include "../../../ircd/crdt_hlc.c"

#include <assert.h>

uint64_t nondet_u64(void);
uint16_t nondet_u16(void);
int nondet_int(void);

/* Environment model: a real epoch clock (seconds below 2^40, usec in
 * range), so the ms conversion in hlc_wall_clock_ms cannot overflow. */
int gettimeofday(struct timeval *tv, void *tz)
{
  (void)tz;
  tv->tv_sec = (time_t)nondet_u64();
  tv->tv_usec = (suseconds_t)nondet_u64();
  __CPROVER_assume(tv->tv_sec >= 0 && tv->tv_sec < ((time_t)1 << 40));
  __CPROVER_assume(tv->tv_usec >= 0 && tv->tv_usec < 1000000);
  return 0;
}

static struct HLC any_hlc(uint16_t node)
{
  struct HLC h;
  h.physical_ms = nondet_u64();
  __CPROVER_assume(h.physical_ms < UINT64_MAX);
  h.logical = nondet_u16();
  h.node_id = node;
  return h;
}

/* (pt, l) strictly greater, ignoring node_id */
static int pl_gt(const struct HLC *a, const struct HLC *b)
{
  return a->physical_ms > b->physical_ms ||
         (a->physical_ms == b->physical_ms && a->logical > b->logical);
}

void harness_local_event(void)
{
  struct HLC h = any_hlc(1);
  struct HLC old = h;
  struct HLC n = hlc_local_event(&h);
  assert(hlc_compare(&n, &old) > 0 && "P1 local event is monotonic");
}

void harness_receive(void)
{
  struct HLC l = any_hlc(1), r = any_hlc(2);
  uint64_t now = nondet_u64(), maxf = nondet_u64();
  __CPROVER_assume(now < UINT64_MAX);
  int rej = -1;
  struct HLC old = l;
  struct HLC n = hlc_receive_bounded(&l, &r, now, maxf, &rej);
  uint64_t hi = old.physical_ms > now ? old.physical_ms : now;

  assert(rej == 0 || rej == 1);
  assert(pl_gt(&n, &old) && "P2a receive is monotonic");
  if (!rej)
    assert(pl_gt(&n, &r) && "P2b receive happens-after the remote");
  else
    assert(n.physical_ms <= hi + 1 && "P3 refused remote does not move the clock");
  if (r.physical_ms > hi) hi = r.physical_ms;
  assert(n.physical_ms <= hi + 1 && "P4 no invented time");
}

void harness_compare(void)
{
  struct HLC a = any_hlc(nondet_u16()), b = any_hlc(nondet_u16());
  int ab = hlc_compare(&a, &b), ba = hlc_compare(&b, &a);
  assert((ab > 0) == (ba < 0) && (ab == 0) == (ba == 0));
  assert(ab == 0 ? (a.physical_ms == b.physical_ms && a.logical == b.logical
                    && a.node_id == b.node_id) : 1);
}
