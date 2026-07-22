/* chathistory_presence_cmocka.c - CMocka regression test for F-CH3
 *
 * Links the REAL ircd/chathistory_presence.c (compiled as a normal
 * object file, ../chathistory_presence.o) rather than hand-duplicating
 * its logic.  The functions under test (record_apply_join,
 * record_apply_part, record_was_present, effective_max_intervals) are
 * file-static, so this test drives them indirectly through the public
 * API (presence_record_join / presence_record_part / presence_was_present)
 * using an in-memory session anchor (anchor_is_session=1), which never
 * touches the persistence layer (acct_load/acct_store bail out early
 * whenever presence_persistence_ready is 0, which it is here since we
 * never call presence_init()).  That keeps the RocksDB-backed
 * account-anchored storage functions unreachable at runtime, so the
 * db_* stubs below only need to satisfy the linker, not behave
 * correctly.
 *
 * Regression under test (F-CH3): struct presence_record.count is
 * uint8_t.  record_apply_part() does `intervals[r->count] = ...;
 * r->count++`.  Before the fix, effective_max_intervals() could return
 * 256 (PRESENCE_MAX_INTERVALS) when FEAT_CHATHISTORY_PRESENCE_MAX_INTERVALS
 * is misconfigured to 0 or >=256, and record_apply_part's trim-before-
 * increment guard (`if (r->count >= cap) { ...; r->count = cap - 1; }`)
 * never fires because a uint8_t can never reach the value 256 in the
 * comparison `r->count >= cap` -- so on the 256th closed interval,
 * `r->count++` overflows 255 -> 0, silently orphaning every interval
 * recorded so far (record_was_present() only walks indices
 * [0, r->count), so count==0 hides everything, including the interval
 * *just* written).  After the fix, effective_max_intervals() is
 * clamped to PRESENCE_MAX_INTERVALS_SAFE == 255, which keeps
 * record_apply_part's `count >= cap` guard reachable and count is
 * FIFO-trimmed to a clean [0,255] window forever -- no overflow, no
 * orphaning.
 *
 * test_presence_no_wraparound_at_misconfigured_cap below stubs
 * feature_int() to 0 (the "misconfigured/max" case per the F-CH3
 * brief) and drives 300 strictly-increasing, non-overlapping
 * join/part pairs through the real code.  With the fix in place, the
 * most recent 255 of those 300 intervals must all still be visible to
 * presence_was_present() (an unbroken recent run, not lost to
 * wraparound) and the interval immediately before that window must
 * have been cleanly FIFO-evicted (not corrupted).  Reverting the
 * F-CH3 fix (effective_max_intervals returning PRESENCE_MAX_INTERVALS
 * instead of _SAFE) makes this test fail: after exactly 300 inserts
 * the wraparound described above leaves only the last 44 visible,
 * so the assertions over indices 45..298 of the retained window fail.
 */

#include "config.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <cmocka.h>

#include "ircd_defs.h"
#include "ircd_features.h"
#include "db_types.h"
#include "db_env.h"
#include "db_cursor.h"
#include "db_txn.h"
#include "history.h"
#include "chathistory_presence.h"

/* ------------------------------------------------------------------ */
/* Link-time stubs for chathistory_presence.c's other dependencies.   */
/*                                                                     */
/* presence_record_join/part/was_present(..., anchor_is_session=1,    */
/* ...) only ever exercises the in-memory session-anchored branch in  */
/* the real .c file, which never calls any of these -- they exist     */
/* solely so the linker can resolve chathistory_presence.o.  The      */
/* account-anchored (persistent) branch, and presence_filter_messages */
/* / presence_on_channel_add / presence_on_channel_remove /           */
/* presence_retention_sweep (none of which this test calls), are the  */
/* only callers, and they're all dead code at runtime here because    */
/* presence_persistence_ready stays 0 (presence_init() is never       */
/* called) and FEAT_CHATHISTORY_STRICT_PRESENCE-gated entry points     */
/* are simply not invoked.                                             */
/* ------------------------------------------------------------------ */

/** Controllable per the F-CH3 brief: effective_max_intervals() reads
 * this via feature_int(FEAT_CHATHISTORY_PRESENCE_MAX_INTERVALS).
 * Fixed at 0 for this suite -- the "misconfigured/max" case that used
 * to let count overflow. */
int feature_int(enum Feature feat)
{
  (void)feat;
  return 0;
}

int feature_bool(enum Feature feat)
{
  (void)feat;
  return 0;
}

struct db_env *history_get_env(void)
{
  return NULL;
}

void db_val_free(struct db_val *v)
{
  if (v) {
    v->base = NULL;
    v->len = 0;
  }
}

int db_cf_open(struct db_env *env, const char *name,
               const struct db_cf_opts *opts, struct db_cf **out)
{
  (void)env; (void)name; (void)opts;
  if (out)
    *out = NULL;
  return DB_ERR_OTHER;
}

int db_get(struct db_env *env, struct db_cf *cf,
           const void *key, size_t klen,
           struct db_snapshot *snap, struct db_val *out)
{
  (void)env; (void)cf; (void)key; (void)klen; (void)snap; (void)out;
  return DB_NOTFOUND;
}

struct db_writebatch *db_writebatch_new(struct db_env *env)
{
  (void)env;
  return NULL;
}

void db_writebatch_destroy(struct db_writebatch *wb)
{
  (void)wb;
}

int db_writebatch_put(struct db_writebatch *wb, struct db_cf *cf,
                       const void *key, size_t klen,
                       const void *val, size_t vlen)
{
  (void)wb; (void)cf; (void)key; (void)klen; (void)val; (void)vlen;
  return DB_ERR_OTHER;
}

int db_writebatch_del(struct db_writebatch *wb, struct db_cf *cf,
                       const void *key, size_t klen)
{
  (void)wb; (void)cf; (void)key; (void)klen;
  return DB_ERR_OTHER;
}

int db_writebatch_commit(struct db_writebatch *wb, int sync_durably)
{
  (void)wb; (void)sync_durably;
  return DB_ERR_OTHER;
}

unsigned int db_writebatch_count(const struct db_writebatch *wb)
{
  (void)wb;
  return 0;
}

const char *db_strerror(int rc)
{
  (void)rc;
  return "stub";
}

struct db_iter *db_iter_open(struct db_env *env, struct db_cf *cf,
                              struct db_snapshot *snap)
{
  (void)env; (void)cf; (void)snap;
  return NULL;
}

void db_iter_close(struct db_iter *it)
{
  (void)it;
}

int db_iter_seek_first(struct db_iter *it)
{
  (void)it;
  return DB_NOTFOUND;
}

int db_iter_next(struct db_iter *it)
{
  (void)it;
  return DB_NOTFOUND;
}

int db_iter_valid(const struct db_iter *it)
{
  (void)it;
  return 0;
}

const void *db_iter_key(const struct db_iter *it, size_t *klen)
{
  (void)it;
  if (klen)
    *klen = 0;
  return NULL;
}

const void *db_iter_value(const struct db_iter *it, size_t *vlen)
{
  (void)it;
  if (vlen)
    *vlen = 0;
  return NULL;
}

void history_free_messages(struct HistoryMessage *list)
{
  (void)list;
}

int history_msgid_to_timestamp(const char *msgid, char *timestamp)
{
  (void)msgid; (void)timestamp;
  return -1;
}

struct Channel *hSeekChannel(const char *name)
{
  (void)name;
  return NULL;
}

/** presence_on_channel_add/remove and presence_retention_sweep
 * reference the real ircd.c global; not exercised at runtime by this
 * suite (both are FEAT_CHATHISTORY_STRICT_PRESENCE-gated / never
 * called here), but the symbol must exist to link. */
time_t CurrentTime;

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

#define TEST_ANCHOR  "test-session-anchor-0001"
#define TEST_CHANNEL "#f-ch3-test"

/* Base epoch far enough from 0 to make failures easy to eyeball. */
#define BASE_TS ((time_t)1700000000)

/* Interval i occupies [BASE_TS + i*10, BASE_TS + i*10 + 1]; consecutive
 * intervals are strictly increasing and never overlap (gap of 10 vs a
 * 1-second span). */
static time_t join_ts(int i) { return BASE_TS + (time_t)i * 10; }
static time_t part_ts(int i) { return join_ts(i) + 1; }

static void test_presence_basic_join_part_present(void **state)
{
  (void)state;

  presence_record_join(TEST_ANCHOR, 1, TEST_CHANNEL, join_ts(0));
  /* Still open: present at and after the join time. */
  assert_true(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, join_ts(0)));
  assert_true(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, join_ts(0) + 100));
  /* Not present before the join. */
  assert_false(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, join_ts(0) - 1));

  presence_record_part(TEST_ANCHOR, 1, TEST_CHANNEL, part_ts(0));
  /* Closed interval: present within [start,end], not after. */
  assert_true(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, join_ts(0)));
  assert_true(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, part_ts(0)));
  assert_false(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, part_ts(0) + 1));

  /* Clean up so later tests in this suite (same in-memory session
   * table) start from a known state. */
  presence_purge_session(TEST_ANCHOR);
  assert_false(presence_was_present(TEST_ANCHOR, 1, TEST_CHANNEL, join_ts(0)));
}

/* The F-CH3 regression test: with feature_int() stubbed to 0 (the
 * misconfigured/max case), 300 closed intervals must not overflow
 * presence_record.count (uint8_t) and silently orphan history.  See
 * the file header comment for the full wraparound derivation. */
static void test_presence_no_wraparound_at_misconfigured_cap(void **state)
{
  const char *anchor = "test-session-anchor-wrap";
  int i;
  int total = 300;
  int retained = 255; /* PRESENCE_MAX_INTERVALS_SAFE */

  (void)state;

  presence_purge_session(anchor);

  for (i = 0; i < total; i++) {
    presence_record_join(anchor, 1, TEST_CHANNEL, join_ts(i));
    presence_record_part(anchor, 1, TEST_CHANNEL, part_ts(i));
  }

  /* The oldest (total - retained) intervals were cleanly FIFO-evicted
   * -- confirms the retained window boundary is where we expect,
   * i.e. this isn't passing by accident. */
  for (i = 0; i < total - retained; i++) {
    if (presence_was_present(anchor, 1, TEST_CHANNEL, join_ts(i))) {
      fail_msg("evicted interval %d (ts=%ld) unexpectedly present -- "
               "FIFO eviction boundary is wrong", i, (long)join_ts(i));
    }
  }

  /* The critical assertion: an unbroken run of the most recent 255
   * intervals must ALL be visible.  Before the F-CH3 fix, the uint8_t
   * count wraparound at the 256th insert orphans everything recorded
   * up to that point (including entries that are still well within
   * the intended retention window), so this loop would fail partway
   * through on an unfixed tree. */
  for (i = total - retained; i < total; i++) {
    if (!presence_was_present(anchor, 1, TEST_CHANNEL, join_ts(i))) {
      fail_msg("recent interval %d (ts=%ld) missing -- lost to uint8_t "
               "count wraparound (F-CH3 regression)", i, (long)join_ts(i));
    }
    if (!presence_was_present(anchor, 1, TEST_CHANNEL, part_ts(i))) {
      fail_msg("recent interval %d end (ts=%ld) missing -- lost to "
               "uint8_t count wraparound (F-CH3 regression)", i, (long)part_ts(i));
    }
  }

  /* The single most recent interval in particular must have survived
   * -- this is the specific case the brief calls out: the interval
   * closed *right at* the wrap boundary must not vanish. */
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, join_ts(total - 1)));

  presence_purge_session(anchor);
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_presence_basic_join_part_present),
    cmocka_unit_test(test_presence_no_wraparound_at_misconfigured_cap),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
