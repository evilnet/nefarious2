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
#include "crdt_hlc.h"

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

/* history.c is not linked here; the presence filter paths that parse a
 * row stamp are never exercised by this suite, but the symbol must
 * resolve.  Kept faithful anyway ("sec[.mmm]" -> epoch ms). */
uint64_t history_parse_ms(const char *ts)
{
  char *end = NULL;
  unsigned long long sec;
  unsigned long ms = 0;
  int digits = 0;
  if (!ts || !*ts)
    return 0;
  sec = strtoull(ts, &end, 10);
  if (end == ts)
    return 0;
  if (end && *end == '.') {
    const char *p = end + 1;
    while (*p >= '0' && *p <= '9' && digits < 3) { ms = ms * 10 + (unsigned long)(*p - '0'); p++; digits++; }
    while (digits < 3) { ms *= 10; digits++; }
  }
  return sec * 1000ULL + ms;
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

/** presence_backfill_now walks the real channel list; this suite never
 * calls it (feature-gated, no channels exist here) but the standalone
 * link of ../chathistory_presence.o needs the symbol. */
struct Channel *GlobalChannelList;

/* PN replication emit path (presence_broadcast_close): never fires in
 * this suite (feature stubbed off / no server init) but the standalone
 * link needs the symbols. */
/* 'me' comes from test_stub.o. */
void sendcmdto_serv_butone_v3(struct Client *from, const char *cmd,
                              const char *tok, struct Client *one,
                              const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)one; (void)pattern;
}
struct db_env *metadata_get_env(void) { return NULL; }
/* presence's fallback clock when no caller supplied an event time
 * (SQUIT teardown, backfill); this suite always passes explicit times. */
static struct HLC test_hlc;
const struct HLC *hlc_global(void)
{
  test_hlc.physical_ms = (uint64_t)time(NULL) * 1000;
  return &test_hlc;
}
void sendcmdto_one(struct Client *from, const char *cmd, const char *tok,
                   struct Client *to, const char *pattern, ...)
{
  (void)from; (void)cmd; (void)tok; (void)to; (void)pattern;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

#define TEST_ANCHOR  "test-session-anchor-0001"
#define TEST_CHANNEL "#f-ch3-test"

/* Base epoch far enough from 0 to make failures easy to eyeball.
 * Presence stamps are epoch MILLISECONDS (2026-09-02); SEC() scales the
 * seconds-era offsets these tests were written with. */
#define BASE_MS PRESENCE_TIME_FROM_MS((int64_t)1700000000 * 1000)
/* Presence time is the HLC packed as ms<<16|logical; SEC() scales the
 * seconds-era offsets these tests were written with, MS() millisecond
 * ones, and a bare +1/-1 is one logical tick inside a millisecond. */
#define SEC(n) PRESENCE_TIME_FROM_MS((int64_t)(n) * 1000)
#define MS(n)  PRESENCE_TIME_FROM_MS((int64_t)(n))

/* Interval i occupies [BASE_MS + i*100 s, +1 s]; consecutive intervals
 * are strictly increasing and never overlap.  The 99-second gap
 * deliberately exceeds the 30 s reconnect-coalescing window in
 * record_apply_part, so each join/part pair stays a distinct interval
 * and the FIFO-eviction assertions below keep their meaning. */
static int64_t join_ts(int i) { return BASE_MS + SEC((int64_t)i * 100); }
static int64_t part_ts(int i) { return join_ts(i) + SEC(1); }

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

/* Reconnect-churn coalescing: a part/rejoin gap of <=30s must merge
 * into the previous interval (one FIFO slot, and the blip itself is
 * covered), while a larger gap must stay a distinct interval with the
 * gap NOT covered. */
static void test_presence_reconnect_coalescing(void **state)
{
  const char *anchor = "test-session-anchor-coal";
  int64_t t = BASE_MS;

  (void)state;
  presence_purge_session(anchor);

  presence_record_join(anchor, 1, TEST_CHANNEL, t);
  presence_record_part(anchor, 1, TEST_CHANNEL, t + SEC(5));
  /* Reconnect 10s later: inside the 30s window -> coalesce. */
  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(15));
  presence_record_part(anchor, 1, TEST_CHANNEL, t + SEC(20));
  /* The blip gap is covered by the merged interval. */
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(10)));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(20)));

  /* Reconnect 100s later: outside the window -> distinct interval,
   * gap NOT covered. */
  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(120));
  presence_record_part(anchor, 1, TEST_CHANNEL, t + SEC(125));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(70)));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(122)));

  presence_purge_session(anchor);
}

/* Backward clock step: a part BEFORE the open's start must clamp to a
 * zero-length visit at the join instant, not discard the window
 * entirely (the old behavior erased the member's whole real window). */
static void test_presence_clock_skew_clamp(void **state)
{
  const char *anchor = "test-session-anchor-skew";
  int64_t t = BASE_MS + SEC(1000000);

  (void)state;
  presence_purge_session(anchor);

  presence_record_join(anchor, 1, TEST_CHANNEL, t);
  presence_record_part(anchor, 1, TEST_CHANNEL, t - SEC(50));  /* skewed */
  /* The join instant survives as a zero-length interval. */
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t - SEC(50)));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(1)));

  /* Record remains usable afterwards. */
  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(100));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(150)));

  presence_purge_session(anchor);
}

/* Remote-close union merge (#6 metadata replication): closed intervals
 * arriving from peers -- out of order, overlapping, or duplicated --
 * must union into the record without disturbing correctness of the
 * membership test.  Exercised via the session flavor (the account
 * flavor shares the merge code; its load/store is stubbed here). */
static void test_presence_remote_close_union(void **state)
{
  const char *anchor = "test-session-anchor-union";
  int64_t t = BASE_MS + SEC(2000000);

  (void)state;
  presence_purge_session(anchor);

  /* Base closed interval. */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(100), t + SEC(200));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(150)));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(250)));

  /* Overlapping close extends the same window (union, not append). */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(150), t + SEC(300));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(250)));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(350)));

  /* Disjoint later window. */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(500), t + SEC(600));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(550)));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(400)));

  /* Out-of-order EARLIER window still lands. */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(10), t + SEC(40));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(20)));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(60)));

  /* Duplicate apply is idempotent (no visibility change). */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(10), t + SEC(40));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(20)));

  /* Degenerate input (end < start) is clamped, not corrupting. */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(900), t + SEC(800));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(900)));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(850)));

  /* An open interval must survive a union merge underneath it. */
  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(1000));
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(700), t + SEC(750));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(1100)));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(720)));

  presence_purge_session(anchor);
}

/* Presence-aware paging (2026-09-02): the store walk asks, for a row
 * OUTSIDE the anchor's presence, where the next presence boundary lies
 * in the walk direction so it can seek there instead of stepping (or
 * stop when nothing further is visible).  Pure interval logic over the
 * same record the membership test uses.
 *
 *   forward  (reverse=0): smallest interval start > t, or open_since
 *                         if that is > t; -1 when none
 *   backward (reverse=1): largest interval end < t; -1 when none
 *   t inside an interval (or >= open_since): the query never asks, but
 *   the answer is t itself (identity) so a caller can't be misled. */
static void test_presence_next_visible_boundaries(void **state)
{
  const char *anchor = "test-session-anchor-page";
  int64_t t = BASE_MS + SEC(3000000);

  (void)state;
  presence_purge_session(anchor);

  /* No record at all: nothing visible in either direction. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t, 0), -1);
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t, 1), -1);

  /* Two closed windows [100,200] and [500,600], gaps around them. */
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(100), t + SEC(200));
  presence_apply_close(anchor, 1, TEST_CHANNEL, t + SEC(500), t + SEC(600));

  /* Before everything, walking forward: first window's start. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t, 0), t + SEC(100));
  /* Before everything, walking backward: nothing. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t, 1), -1);

  /* In the gap between the windows. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(300), 0), t + SEC(500));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(300), 1), t + SEC(200));

  /* After everything (no open interval): forward nothing, backward last end. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(900), 0), -1);
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(900), 1), t + SEC(600));

  /* Inside a window: identity in both directions. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(150), 0), t + SEC(150));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(150), 1), t + SEC(150));

  /* Boundary seconds are inclusive: end+1 is outside, end is inside. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(201), 1), t + SEC(200));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(200), 1), t + SEC(200));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(499), 0), t + SEC(500));

  /* Open interval from t+1000: forward from the trailing gap lands on
   * open_since; backward from inside the open run is identity; forward
   * from inside is identity. */
  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(1000));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(900), 0), t + SEC(1000));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(900), 1), t + SEC(600));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(5000), 0), t + SEC(5000));
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, t + SEC(5000), 1), t + SEC(5000));

  presence_purge_session(anchor);
}

/* Sub-second precision (2026-09-02): presence stamps are milliseconds,
 * inclusive at both edges, so a row 1 ms before the join is hidden and
 * a row 1 ms after the part is hidden -- and a row in the SAME
 * wall-clock second as the join but before it is hidden too, which the
 * old whole-second records could not express. */
static void test_presence_millisecond_edges(void **state)
{
  const char *anchor = "test-session-anchor-ms";
  /* join at .500 with logical counter 7; part 10 s later at .750, logical 3 */
  int64_t j = BASE_MS + SEC(4000000) + PRESENCE_TIME_PACK(500, 7);
  int64_t p = PRESENCE_TIME_PACK(PRESENCE_TIME_MS(j) + 10250, 3);

  (void)state;
  presence_purge_session(anchor);

  presence_record_join(anchor, 1, TEST_CHANNEL, j);
  /* One logical tick before the join, SAME millisecond: hidden. */
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, j - 1));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, j));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, j + 1));
  /* Same second as the join, 400 ms earlier: hidden. */
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, j - MS(400)));
  /* One millisecond earlier, any logical: hidden. */
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL,
                                    PRESENCE_TIME_PACK(PRESENCE_TIME_MS(j) - 1, 60000)));

  presence_record_part(anchor, 1, TEST_CHANNEL, p);
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, p));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, p + 1));   /* same ms, later tick */

  /* Boundary seeks are exact too. */
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, j - 1, 0), j);
  assert_int_equal(presence_next_visible(anchor, 1, TEST_CHANNEL, p + 1, 1), p);

  presence_purge_session(anchor);
}

/* The msgid's embedded HLC is the row's presence time when it agrees
 * with the row's millisecond stamp; a foreign/legacy msgid, or one that
 * disagrees, falls back to (row ms, logical 0). */
static void test_presence_event_time_from_msgid(void **state)
{
  (void)state;
  /* No msgid: (ms, 0). */
  assert_int_equal(presence_event_time(NULL, 1700000000123ULL),
                   PRESENCE_TIME_FROM_MS(1700000000123LL));
  assert_int_equal(presence_event_time("", 1700000000123ULL),
                   PRESENCE_TIME_FROM_MS(1700000000123LL));
  /* Legacy-shaped msgid that cannot decode: (ms, 0). */
  assert_int_equal(presence_event_time("AB-1703334400-123", 1700000000123ULL),
                   PRESENCE_TIME_FROM_MS(1700000000123LL));
}

/* The reconnect-coalescing window is 30 000 ms exactly: a gap of that
 * size merges, one millisecond more stays a distinct interval. */
static void test_presence_coalesce_window_ms(void **state)
{
  const char *anchor = "test-session-anchor-coalms";
  int64_t t = BASE_MS + SEC(5000000);

  (void)state;
  presence_purge_session(anchor);

  presence_record_join(anchor, 1, TEST_CHANNEL, t);
  presence_record_part(anchor, 1, TEST_CHANNEL, t + SEC(5));
  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(5) + MS(30000));  /* gap == window: merge */
  presence_record_part(anchor, 1, TEST_CHANNEL, t + SEC(40));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(20)));

  presence_record_join(anchor, 1, TEST_CHANNEL, t + SEC(40) + MS(30001)); /* one ms past: distinct */
  presence_record_part(anchor, 1, TEST_CHANNEL, t + SEC(80));
  assert_false(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(55)));
  assert_true(presence_was_present(anchor, 1, TEST_CHANNEL, t + SEC(75)));

  presence_purge_session(anchor);
}

/* Older stamps (stored rows, PN values from older peers) migrate on
 * read by magnitude: seconds (~1.7e9) below 1e11, milliseconds
 * (~1.7e12) below 1e15, packed HLC (~1.1e17) above. */
static void test_presence_norm_ms(void **state)
{
  (void)state;
  assert_int_equal(presence_norm_time(0), 0);
  assert_int_equal(presence_norm_time(1700000000LL),
                   PRESENCE_TIME_FROM_MS(1700000000000LL));
  assert_int_equal(presence_norm_time(1700000000000LL),
                   PRESENCE_TIME_FROM_MS(1700000000000LL));
  assert_int_equal(presence_norm_time(PRESENCE_TIME_PACK(1700000000000LL, 9)),
                   PRESENCE_TIME_PACK(1700000000000LL, 9));
  assert_int_equal(presence_norm_time(99999999999LL),
                   PRESENCE_TIME_FROM_MS(99999999999000LL));
}

int main(void)
{
  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_presence_basic_join_part_present),
    cmocka_unit_test(test_presence_no_wraparound_at_misconfigured_cap),
    cmocka_unit_test(test_presence_reconnect_coalescing),
    cmocka_unit_test(test_presence_clock_skew_clamp),
    cmocka_unit_test(test_presence_remote_close_union),
    cmocka_unit_test(test_presence_next_visible_boundaries),
    cmocka_unit_test(test_presence_millisecond_edges),
    cmocka_unit_test(test_presence_event_time_from_msgid),
    cmocka_unit_test(test_presence_coalesce_window_ms),
    cmocka_unit_test(test_presence_norm_ms),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);
}
