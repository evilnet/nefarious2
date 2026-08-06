/* ircd/register_throttle.c
 * Cross-connection throttle for REGISTER (m_register.c).
 *
 * Two independent limiters:
 *  - per-IP rolling window, IPcheck-shaped: the counter resets when
 *    `period` has elapsed since the last COUNTED attempt, otherwise it
 *    increments and refuses at `limit`.  Refusals record nothing, so a
 *    hammering client still recovers `period` after its last counted
 *    attempt.
 *  - a server-wide fixed window (`global_limit` per `period`), so a
 *    botnet spread over many IPs cannot mint unbounded accounts here.
 *
 * Addresses are canonicalized the way IPcheck does it: IPv4 -> 6to4,
 * IPv6 keyed on the first /64 (the rest is user-controlled).
 *
 * Storage is a fixed-size open hash with per-bucket LRU eviction: memory
 * never grows with attacker IP count, and evicting a live entry merely
 * grants that IP fresh budget -- never a crash.  Expiry is lazy (on
 * contact); nothing schedules reg_throttle_expire().
 *
 * The module is deliberately pure -- the caller supplies now and the
 * limits -- so ircd/test/register_throttle_cmocka.c gates it in the
 * build.  Keep it free of feature reads, Client accessors, and logging.
 */
#include "config.h"
#include "register_throttle.h"
#include "res.h"

#include <netinet/in.h>
#include <string.h>

/* Overridable so the CMocka build can shrink the table to force
 * collisions and eviction (see test/Makefile.in). */
#ifndef REG_THROTTLE_TABLE_BITS
#define REG_THROTTLE_TABLE_BITS 6
#endif
#ifndef REG_THROTTLE_BUCKET_DEPTH
#define REG_THROTTLE_BUCKET_DEPTH 4
#endif
#define REG_THROTTLE_TABLE_SIZE (1 << REG_THROTTLE_TABLE_BITS)

struct reg_throttle_entry {
  struct irc_in_addr addr;   /* canonical (see reg_canon) */
  time_t last;               /* last counted attempt */
  int attempts;              /* counted attempts in the current window */
  int in_use;
};

static struct reg_throttle_entry
  reg_table[REG_THROTTLE_TABLE_SIZE][REG_THROTTLE_BUCKET_DEPTH];
static time_t reg_global_start;   /* global window anchor (first attempt) */
static int reg_global_count;

/* IPv4 -> 6to4, IPv6 -> first /64 with the host half zeroed, so a plain
 * memcmp compares canonical keys.  Same intent as IPcheck's
 * ip_registry_canonicalize()/48-or-64-bit match. */
static void reg_canon(struct irc_in_addr *out, const struct irc_in_addr *in)
{
  memset(out, 0, sizeof(*out));
  if (irc_in_addr_is_ipv4(in)) {
    out->in6_16[0] = htons(0x2002);
    out->in6_16[1] = in->in6_16[6];
    out->in6_16[2] = in->in6_16[7];
  } else {
    out->in6_16[0] = in->in6_16[0];
    out->in6_16[1] = in->in6_16[1];
    out->in6_16[2] = in->in6_16[2];
    out->in6_16[3] = in->in6_16[3];
  }
}

static unsigned int reg_hash(const struct irc_in_addr *canon)
{
  unsigned int res = canon->in6_16[0] ^ canon->in6_16[1]
                   ^ canon->in6_16[2] ^ canon->in6_16[3];
  return res & (REG_THROTTLE_TABLE_SIZE - 1);
}

enum reg_throttle_result reg_throttle_check(const struct irc_in_addr *ip,
                                            time_t now, int limit,
                                            int period, int global_limit)
{
  struct irc_in_addr canon;
  struct reg_throttle_entry *bucket = 0, *match = 0, *reusable = 0, *oldest = 0;
  int have_ip = 0;

  if (period <= 0)
    return REG_THROTTLE_OK;

  /* Phase 1: find (but do not mutate) the per-IP slot this attempt would
   * land in, and refuse now if the per-IP window is already exhausted.
   * This refusal is unconditional -- it must not touch the global
   * counter either, so it stays a hard early return. */
  if (limit > 0 && ip) {
    int i;

    have_ip = 1;
    reg_canon(&canon, ip);
    bucket = reg_table[reg_hash(&canon)];
    for (i = 0; i < REG_THROTTLE_BUCKET_DEPTH; ++i) {
      struct reg_throttle_entry *e = &bucket[i];
      if (e->in_use && now - e->last < period) {
        if (0 == memcmp(&e->addr, &canon, sizeof(canon))) {
          match = e;
          break;
        }
        if (!oldest || e->last < oldest->last)
          oldest = e;
      } else if (!reusable) {
        reusable = e;              /* free or expired: reuse first */
      }
    }

    if (match && match->attempts >= limit)
      return REG_THROTTLE_IP;   /* refusal: no count, no window slide */
  }

  /* Phase 2: evaluate (but do not yet commit) the global cap.  Checking
   * this before touching per-IP state is what keeps a global refusal
   * from consuming per-IP budget -- the bug this function used to have:
   * it recorded the per-IP attempt first, then refused globally, so a
   * botnet-exhausted global window silently ate a legit IP's budget too. */
  if (global_limit > 0) {
    if (now - reg_global_start >= period) {
      reg_global_start = now;
      reg_global_count = 0;
    }
    if (reg_global_count >= global_limit)
      return REG_THROTTLE_GLOBAL;  /* refusal: per-IP state untouched */
  }

  /* Both limiters (whichever are enabled) have cleared the attempt --
   * commit it to both now. */
  if (have_ip) {
    if (match) {
      ++match->attempts;
      match->last = now;
    } else {
      struct reg_throttle_entry *e = reusable ? reusable : oldest;
      /* oldest can only be null if the bucket is empty, in which case
       * reusable is set; e is never null */
      memcpy(&e->addr, &canon, sizeof(canon));
      e->last = now;
      e->attempts = 1;
      e->in_use = 1;
    }
  }

  if (global_limit > 0)
    ++reg_global_count;

  return REG_THROTTLE_OK;
}

void reg_throttle_expire(time_t now, int period)
{
  int b, i;
  for (b = 0; b < REG_THROTTLE_TABLE_SIZE; ++b)
    for (i = 0; i < REG_THROTTLE_BUCKET_DEPTH; ++i) {
      struct reg_throttle_entry *e = &reg_table[b][i];
      if (e->in_use && (period <= 0 || now - e->last >= period))
        e->in_use = 0;
    }
}

void reg_throttle_clear(void)
{
  memset(reg_table, 0, sizeof(reg_table));
  reg_global_start = 0;
  reg_global_count = 0;
}
