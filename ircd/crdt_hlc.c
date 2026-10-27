/*
 * crdt_hlc.c - Hybrid Logical Clock implementation
 *
 * Based on the HLC algorithm from Kulkarni et al. (2014):
 *   "Logical Physical Clocks and Consistent Snapshots in Globally
 *    Distributed Databases"
 *
 * The logical counter uses uint16_t (max 65535). Overflow wraps to 0
 * with a log warning. In practice, 65k+ events within a single
 * millisecond is unrealistic for IRC.
 */

#include "config.h"
#include "crdt_hlc.h"
#include "ircd_log.h"

#include <sys/time.h>

/** Global HLC state for this server. */
static struct HLC global_hlc;

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
    if (local->logical == UINT16_MAX) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "HLC logical counter overflow (node %u, pt %llu) — wrapping to 0",
                (unsigned)local->node_id,
                (unsigned long long)local->physical_ms);
      local->logical = 0;
    } else {
      local->logical++;
    }
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
      if (local->logical == UINT16_MAX) {
        log_write(LS_SYSTEM, L_WARNING, 0,
                  "HLC logical counter overflow (node %u, pt %llu) — wrapping to 0",
                  (unsigned)local->node_id,
                  (unsigned long long)local->physical_ms);
        local->logical = 0;
      } else {
        local->logical++;
      }
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
    if (max_l == UINT16_MAX) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "HLC logical counter overflow on receive (node %u) — wrapping to 0",
                (unsigned)local->node_id);
      local->logical = 0;
    } else {
      local->logical = max_l + 1;
    }
    /* physical_ms stays the same */
  } else if (local->physical_ms > remote->physical_ms) {
    /* Local is ahead — just increment local logical */
    if (local->logical == UINT16_MAX) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "HLC logical counter overflow on receive (node %u) — wrapping to 0",
                (unsigned)local->node_id);
      local->logical = 0;
    } else {
      local->logical++;
    }
  } else {
    /* Remote is ahead — adopt remote's time, increment its logical */
    local->physical_ms = remote->physical_ms;
    if (remote->logical == UINT16_MAX) {
      log_write(LS_SYSTEM, L_WARNING, 0,
                "HLC logical counter overflow on receive (node %u) — wrapping to 0",
                (unsigned)local->node_id);
      local->logical = 0;
    } else {
      local->logical = remote->logical + 1;
    }
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
