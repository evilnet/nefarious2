/* ircd/ipcheck_refund.c
 * Per-account cap on IPcheck connection refunds.
 *
 * One fixed window per account: the first counted refund opens it, and
 * `limit` refunds fit in it; `period` seconds after it opened the next
 * refund opens a new one.  A refused refund records nothing.
 *
 * Storage is a fixed-size open hash with per-bucket eviction of the
 * entry whose window opened earliest: memory never grows with the
 * number of accounts, and evicting a live entry merely grants that
 * account a fresh window -- never a crash.  Expiry is lazy (on contact).
 *
 * The module is deliberately pure -- the caller supplies now and the
 * limits -- so ircd/test/ipcheck_refund_cmocka.c gates it in the build.
 * Keep it free of feature reads, Client accessors, and logging.
 */
#include "config.h"
#include "ipcheck_refund.h"
#include "ircd_defs.h"      /* ACCOUNTLEN */

#include <string.h>

/* Overridable so the CMocka build can shrink the table to force
 * collisions and eviction (see test/Makefile.in). */
#ifndef IPCHECK_REFUND_TABLE_BITS
#define IPCHECK_REFUND_TABLE_BITS 6
#endif
#ifndef IPCHECK_REFUND_BUCKET_DEPTH
#define IPCHECK_REFUND_BUCKET_DEPTH 4
#endif
#define IPCHECK_REFUND_TABLE_SIZE (1 << IPCHECK_REFUND_TABLE_BITS)

struct ipcheck_refund_entry {
  char account[ACCOUNTLEN + 1];
  time_t start;              /* when the current window opened */
  int count;                 /* refunds counted in it */
  int in_use;
};

static struct ipcheck_refund_entry
  refund_table[IPCHECK_REFUND_TABLE_SIZE][IPCHECK_REFUND_BUCKET_DEPTH];

/* ASCII case fold: account names come from services in one canonical
 * spelling, so this only keeps two spellings of one name from drawing
 * two budgets. */
static int refund_lc(int c)
{
  return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/* Over the kept length only: an entry stores the first ACCOUNTLEN bytes. */
static int refund_same(const char *stored, const char *account)
{
  int i;
  for (i = 0; i < ACCOUNTLEN; ++i, ++stored, ++account) {
    if (refund_lc((unsigned char)*stored) != refund_lc((unsigned char)*account))
      return 0;
    if (!*stored)
      return 1;
  }
  return 1;
}

/* FNV-1a over the folded bytes. */
static unsigned int refund_hash(const char *account)
{
  unsigned int h = 2166136261u;
  for (; *account; ++account) {
    h ^= (unsigned int)refund_lc((unsigned char)*account);
    h *= 16777619u;
  }
  return h & (IPCHECK_REFUND_TABLE_SIZE - 1);
}

int ipcheck_refund_take(const char *account, time_t now, int limit,
                        int period)
{
  struct ipcheck_refund_entry *bucket, *match = 0, *reusable = 0, *oldest = 0;
  int i;

  if (limit <= 0 || period <= 0 || !account || !*account)
    return 0;

  bucket = refund_table[refund_hash(account)];
  for (i = 0; i < IPCHECK_REFUND_BUCKET_DEPTH; ++i) {
    struct ipcheck_refund_entry *e = &bucket[i];
    if (e->in_use && now - e->start < period) {
      if (refund_same(e->account, account)) {
        match = e;
        break;
      }
      if (!oldest || e->start < oldest->start)
        oldest = e;
    } else if (!reusable) {
      reusable = e;              /* free or expired: reuse first */
    }
  }

  if (match) {
    if (match->count >= limit)
      return 0;                  /* refusal: nothing recorded */
    ++match->count;
    return 1;
  }

  /* No live window for this account: open one.  oldest is null only when
   * the bucket is empty, in which case reusable is set; e is never null. */
  {
    struct ipcheck_refund_entry *e = reusable ? reusable : oldest;
    strncpy(e->account, account, ACCOUNTLEN);
    e->account[ACCOUNTLEN] = '\0';
    e->start = now;
    e->count = 1;
    e->in_use = 1;
  }
  return 1;
}

void ipcheck_refund_clear(void)
{
  memset(refund_table, 0, sizeof(refund_table));
}
