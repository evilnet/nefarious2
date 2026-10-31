/*
 * crdt_hlc.c - Hybrid Logical Clock implementation
 *
 * Based on the HLC algorithm from Kulkarni et al. (2014):
 *   "Logical Physical Clocks and Consistent Snapshots in Globally
 *    Distributed Databases"
 *
 * The logical counter uses uint16_t (max 65535).  It is not bounded by
 * events per wall-clock millisecond: while the clock is pinned ahead of
 * the wall clock (a peer that read ahead, an NTP step back) every event
 * increments it.  On overflow the step carries into physical_ms instead
 * of wrapping: a wrap at the same physical_ms would mint a stamp older
 * than the previous one and, since 65536 is a multiple of the msgid's
 * 12-bit counter, an exact duplicate msgid (formal/cbmc/crdt_hlc).
 */

#include "config.h"
#include "crdt_hlc.h"
#include "ircd_log.h"

#include <sys/time.h>

/** Global HLC state for this server. */
static struct HLC global_hlc;

/** Step @a h to the next stamp at or after (pt, logical): logical + 1,
 * or on overflow the next millisecond with logical 0. */
static void hlc_step(struct HLC *h, uint64_t pt, uint16_t logical)
{
  if (logical == UINT16_MAX) {
    log_write(LS_SYSTEM, L_WARNING, 0,
              "HLC logical counter overflow (node %u, pt %llu) — carrying "
              "into physical time", (unsigned)h->node_id,
              (unsigned long long)pt);
    h->physical_ms = pt + 1;
    h->logical = 0;
  } else {
    h->physical_ms = pt;
    h->logical = logical + 1;
  }
}

uint64_t hlc_wall_clock_ms(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

struct HLC hlc_local_event(struct HLC *local)
{
  uint64_t now = hlc_wall_clock_ms();

  if (now > local->physical_ms) {
    local->physical_ms = now;
    local->logical = 0;
  } else {
    hlc_step(local, local->physical_ms, local->logical);
  }

  return *local;
}

struct HLC hlc_receive_bounded(struct HLC *local, const struct HLC *remote,
                                uint64_t now_ms, uint64_t max_forward_ms,
                                int *rejected)
{
  uint64_t now = now_ms;

  /* Compare by subtraction, never by summing now_ms + max_forward_ms:
   * that sum can overflow uint64_t when max_forward_ms is very large
   * (e.g. a misconfigured FEAT_HLC_MAX_FORWARD_MS sign-extended to
   * near UINT64_MAX), which would wrap the threshold down and refuse
   * nearly every peer reading, including ones behind us. */
  if (max_forward_ms > 0 && remote->physical_ms > now &&
      remote->physical_ms - now > max_forward_ms) {
    if (rejected)
      *rejected = 1;

    /* Advance local exactly as a local event at now_ms — the remote
     * reading is refused, so our clock does not move toward it. */
    if (now > local->physical_ms) {
      local->physical_ms = now;
      local->logical = 0;
    } else {
      hlc_step(local, local->physical_ms, local->logical);
    }

    return *local;
  }

  if (rejected)
    *rejected = 0;

  if (now > local->physical_ms && now > remote->physical_ms) {
    /* Wall clock is ahead of both — reset logical */
    local->physical_ms = now;
    local->logical = 0;
  } else if (local->physical_ms == remote->physical_ms) {
    /* Same physical time — take max logical + 1 */
    uint16_t max_l = (local->logical > remote->logical)
                     ? local->logical : remote->logical;
    hlc_step(local, local->physical_ms, max_l);
  } else if (local->physical_ms > remote->physical_ms) {
    /* Local is ahead — just increment local logical */
    hlc_step(local, local->physical_ms, local->logical);
  } else {
    /* Remote is ahead — adopt remote's time, increment its logical */
    hlc_step(local, remote->physical_ms, remote->logical);
  }

  return *local;
}

struct HLC hlc_receive(struct HLC *local, const struct HLC *remote)
{
  return hlc_receive_bounded(local, remote, hlc_wall_clock_ms(), 0, NULL);
}

int hlc_compare(const struct HLC *a, const struct HLC *b)
{
  if (a->physical_ms != b->physical_ms)
    return (a->physical_ms < b->physical_ms) ? -1 : 1;
  if (a->logical != b->logical)
    return (a->logical < b->logical) ? -1 : 1;
  if (a->node_id != b->node_id)
    return (a->node_id < b->node_id) ? -1 : 1;
  return 0;
}

void hlc_init(uint16_t node_id)
{
  global_hlc.physical_ms = hlc_wall_clock_ms();
  global_hlc.logical = 0;
  global_hlc.node_id = node_id;
}

const struct HLC *hlc_global(void)
{
  return &global_hlc;
}

struct HLC hlc_global_event(void)
{
  return hlc_local_event(&global_hlc);
}

int hlc_global_receive(const struct HLC *remote, uint64_t max_forward_ms,
                        uint64_t *ahead_ms)
{
  uint64_t now = hlc_wall_clock_ms();
  int rejected = 0;

  hlc_receive_bounded(&global_hlc, remote, now, max_forward_ms, &rejected);

  if (rejected && ahead_ms)
    *ahead_ms = remote->physical_ms - now;

  return rejected;
}
