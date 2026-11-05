/* include/history_trim.h
 * Chathistory trimming -- the trim engine: index staging for the store
 * path, the boot accounting scan, budgeted main-loop slices, the ONE
 * delete function every trim path goes through, and the cleanup of
 * targets a slice emptied.
 *
 * The engine sits on the db_* storage API and the pure codec
 * (history_trim_codec.h) only: no feature_*, no struct Client.  history.c
 * hands it the column-family handles (struct htrim_store), a parse
 * callback for message values, a monotonic clock and the "targets
 * emptied" callback, and drives it from its slice timer.
 *
 * Slices.  A slice is one WriteBatch plus the in-memory consequences of
 * what it staged: pending accounting deltas, the touched targets and the
 * per-path delete counters.  None of those is applied until
 * db_writebatch_commit succeeds -- a failed commit leaves the store, the
 * totals and the counters exactly as they were.
 *
 * Accounting.  Owner totals live in an htc_acct table rebuilt at boot by a
 * sliced scan of by_owner.  Every store/delete delta goes through one rule
 * so the scan cannot count a row twice or subtract one it never added:
 *
 *   apply(bo_key, delta) iff acct_loaded,
 *                        or scan_started && bo_key <= scan_cursor (bytewise)
 *
 * The scan walks by_owner from the successor of its cursor (cursor ‖ 0x00)
 * with a bounded iterator, adds each entry's be32 size, and sets the
 * cursor to the last key it read; an exhausted iterator sets acct_loaded.
 *
 * Backfill.  Rows stored before by_time existed -- or by an older binary
 * while this one was down -- have no index rows, so age-out never sees
 * them and the totals never count them.  The backfill phase walks the
 * messages CF in sliced steps from the successor of a cursor persisted in
 * the meta CF (the last messages key processed, put in the same batch as
 * the index rows it covers, so a restart neither skips nor re-walks a
 * row).  Per row: a by_time row that already exists means the store path
 * indexed and counted it -- skipped; a row past retention is deleted in
 * full, uncounted (it was never counted); any other row is indexed and
 * counted through the accounting rule.  An exhausted walk puts the done
 * marker and deletes the cursor; a boot whose newest stored row is past
 * the last alive stamp plus a slack (a downgrade window) deletes both --
 * done or mid-walk -- and the walk runs again from the first key.  A meta
 * row that cannot be read counts as an unfinished walk.
 *
 * Age-out.  Retention is enforced by walking by_time -- globally ordered
 * by time -- over [resume point, be64(cutoff_ms)), oldest first, THE
 * delete for each row (counted), in budgeted slices.  The resume point is
 * the successor of the last by_time key a slice stopped by its budget
 * deleted, or the bound itself once a walk reached it (every key below is
 * gone; a retention rise never moves it back); it moves only when a slice
 * commits, so after a failed commit the same rows come round again.  It
 * is persisted (HTRIM_META_AGEOUT_RESUME) in each age-out slice's batch,
 * so a restart resumes there too.  A pass opens at htrim_pass_start (each
 * maintenance tick, and a retention change) and resumes there -- never at
 * the first key again, whose seek would walk every tombstone the earlier
 * passes left.  A row indexed behind the resume point since (a late CH W
 * or relay, a backfill after a retention rise) is kept by key (up to 64):
 * the next pass deletes those first, oldest first, and resumes at its
 * frontier without crossing the run between; past 64 it sends the walk
 * back to the oldest such row instead.  Such a row also moves the
 * persisted point back, in its own batch, and an age-out batch never
 * stores a point past a late row still to go, so a restart before the
 * pass that takes it still walks it.  A walk that reaches the cutoff
 * closes the pass.  Rows at the cutoff ms are kept.
 *
 * The cap.  Once the backfill is done and the totals are loaded, a store
 * whose total is strictly above cap * high% starts a drain, which runs
 * until the total is at or below cap * low% (hysteresis; cap 0 = no cap).
 * Each eviction slice plans afresh (htc_plan_eviction) and then:
 *   - finishes the owner step in progress: an owner over its share, once
 *     picked, loses its own oldest rows (a by_owner walk, resumed past
 *     the last key the step deleted) down to its share -- while the share
 *     step stays on (htc_share_active); a new step starts at owner 0x00 ‖
 *     the live floor, past its aged-out head, and when that runs out walks
 *     below it once (orphan entries a boot scan counted go with their
 *     bytes) -- only a whole range short of the trim recounts the totals;
 *   - while the total is still above the low watermark, starts the
 *     plan's next owner step (largest over-share first);
 *   - only when nobody is over share and the plan listed every owner
 *     (never when it was truncated: compliant owners' rows would go while
 *     over-share owners keep theirs), deletes the oldest rows overall,
 *     walking by_time from the live floor (the larger of where this drain
 *     stopped and where age-out resumes, or an older late row), and moves
 *     the coverage floor (HTRIM_META_FLOOR, the newest ms that walk
 *     deleted) in the same batch; a walk that runs out of rows recounts
 *     the totals.
 * Two known costs of the owner step (deferred): an owner whose total
 * holds orphan bytes O (by_owner entries below the floor whose rows are
 * gone, which a boot scan counted) loses live rows above the floor until
 * the trim is met, before its walk reaches the orphans -- so it ends up
 * to O below its share; and a row the owner stores while its walk below
 * the start is still going lies above that walk, which then runs short
 * by the row's bytes and has the totals counted again although they were
 * right.
 * A pass start whose cutoff is past the floor clears it: retention then
 * covers what eviction took.  A drain's end hints compaction over every
 * column family it deleted from and arms the targets sweep.
 *
 * Targets sweep.  The touched-target cleanup checks a target only when a
 * slice deleted its newest stamped row -- exact for oldest-first age-out,
 * but not for eviction (an owner trim can take a target's newest row and
 * a later slice the older rest), and a failed cleanup or a restart (which
 * drops the carried checks) can leave an emptied target's key.  The
 * sweep walks the targets CF in budgeted slices, one bounded tail seek of
 * [fold(t) 0x00, fold(t) 0x01) per key, deletes the keys of empty
 * targets and reports them; it runs once per start (after the accounting
 * scan), after every drain, and after a cleanup that could not finish.
 * It never rewrites a stamp.  Every emptiness check (cleanup or sweep)
 * steps over at most 10000 tombstones (db_iter_open_bounded_limited);
 * past that it is undecided: the key stays, the target's range is flushed
 * and hinted for compaction, and the sweep at the next pass start checks
 * it again.
 *
 * Compaction hints.  Each tracked column family (messages, msgid,
 * reply, ml_content, by_time, by_owner) keeps the smallest and largest
 * key deleted since its last hint.  The time-ordered ones (by_time,
 * msgid, ml_content) are hinted once compact_min_rows keys have gone
 * (any path); every one at a drain's end (the prefix-keyed ones over
 * what that drain deleted).  A hint flushes the CF's memtable, then calls
 * db_suggest_compact over [smallest, largest ‖ 0x00).  The flush does not
 * wait for the flush job, but switches the memtable on the calling
 * thread and blocks while it would stall writes, so the engine's slices
 * issue at most one hint each (a cleanup-only slice takes the rest), a
 * caller's slice none, and a CF with a flush in flight or L0 near its
 * slowdown trigger gets the suggestion alone, its flush left due for a
 * later slice.  An undecided target's range is hinted the same way, each
 * target apart (up to 8), one messages flush serving both.  A hint that
 * fails or is dropped keeps its count -- a drain's start keeps it too --
 * and the cumulative trigger backs off (compact_min_rows more keys, or 60
 * slices), one WARNING a failure streak.
 */
#ifndef INCLUDED_history_trim_h
#define INCLUDED_history_trim_h

#ifndef INCLUDED_stdint_h
#include <stdint.h>
#define INCLUDED_stdint_h
#endif
#ifndef INCLUDED_stddef_h
#include <stddef.h>
#define INCLUDED_stddef_h
#endif
#ifndef INCLUDED_history_trim_codec_h
#include "history_trim_codec.h"
#endif

struct db_env;
struct db_cf;
struct db_writebatch;

/** The engine's meta rows (st->meta, the env's default CF). */
#define HTRIM_META_BACKFILL_DONE   "schema/trim-backfill"          /* value "done" */
#define HTRIM_META_BACKFILL_CURSOR "schema/trim-backfill-cursor"   /* value: the last messages key processed */
#define HTRIM_META_ALIVE           "trim/alive-ms"                 /* decimal epoch ms */
#define HTRIM_META_FLOOR           "trim/coverage-floor"           /* decimal epoch ms */
#define HTRIM_META_AGEOUT_RESUME   "trim/ageout-resume"            /* value: the by_time key age-out resumes at */

/** The history env's column families the engine reads and writes.
 * @a meta is the env's default CF (the engine's own marker rows). */
struct htrim_store {
  struct db_env *env;
  struct db_cf  *messages, *msgid, *targets, *reply, *redact,
                *ml_content, *ml_paste, *by_time, *by_owner, *meta;
};

/** What the parse callback extracts from a stored message value. */
struct htrim_row_info {
  char          account[HTC_OWNER_MAX];
  unsigned char flags;                        /**< HTC_F_* */
  char          reply_parent[HTC_MSGID_MAX];
  char          redact_parent[HTC_MSGID_MAX];
};

/** Decode a messages-CF value. @return 0 when parsed. */
typedef int (*htrim_parse_fn)(const void *val, size_t vlen,
                              struct htrim_row_info *out);

/** Called once per slice, after the commit that removed their targets-CF
 * keys, with the (folded) names of the targets that slice emptied. */
typedef void (*htrim_emptied_fn)(const char **targets, int count);

/** Monotonic clock, in microseconds. */
typedef uint64_t (*htrim_clock_fn)(void);

/** Which trim path deleted a row (the per-path counters in htrim_stats). */
enum htrim_path {
  HTRIM_PATH_AGEOUT,
  HTRIM_PATH_OWNER,
  HTRIM_PATH_OLDEST,
  HTRIM_PATH_EMERGENCY,
  HTRIM_PATH_BACKFILL,
  HTRIM_PATH_INCARNATION,
  HTRIM_PATH_COUNT
};

/** The phase one htrim_run_slice call ran.  AGEOUT, BACKFILL, ACCTSCAN,
 * EVICT and TSWEEP take turns; CLEANUP runs only when none of them has
 * work but carried emptiness checks remain; INCARNATION names the
 * burst-loss prune's unbudgeted slice (history.c, htrim_slice_set_phase),
 * never picked by the engine. */
enum htrim_phase {
  HTRIM_PH_NONE,
  HTRIM_PH_AGEOUT,
  HTRIM_PH_BACKFILL,
  HTRIM_PH_ACCTSCAN,
  HTRIM_PH_EVICT,
  HTRIM_PH_CLEANUP,
  HTRIM_PH_INCARNATION,
  HTRIM_PH_TSWEEP
};

/** The live configuration for one slice. */
struct htrim_params {
  uint64_t     now_ms;
  int          retention_days;
  uint64_t     cap_bytes;
  int          high_pct;
  int          low_pct;
  int          quota_on;
  int          share_pct;
  unsigned int slice_ms;         /**< budget; 0 = no budget */
  unsigned int compact_min_rows; /**< hint a CF's compaction once this many
                                      of its keys were deleted since its
                                      last hint; 0 = only at a drain's end */
};

struct htrim_stats {
  uint64_t         deleted[HTRIM_PATH_COUNT];   /**< committed deletes per path */
  uint64_t         last_slice_us;               /**< begin to end of cleanup */
  uint64_t         max_slice_us;
  enum htrim_phase max_phase;                   /**< the phase of the max_slice_us slice */
  enum htrim_phase last_phase;
  uint64_t         oldest_seen_ms;              /**< ms of the first by_time key the
                                                     last age-out slice read; 0 = none yet */
  /* The max_slice_us slice, broken down (a budgeted slice with a commit or
   * a cleanup to pay for; any other slice is all walk): staging (the
   * walk), the batch commit and the in-memory applies, the touched-target
   * cleanup, and the emptiness seeks it did (cleanup + sweep). */
  uint64_t         max_walk_us, max_commit_us, max_cleanup_us;
  uint64_t         max_hint_us;                 /**< a compaction hint it issued
                                                     (flush + suggest), one at most */
  unsigned int     max_seeks;
};

struct htrim_slice;

/** Called after a commit that moved or cleared the coverage floor. */
typedef void (*htrim_coverage_fn)(void);

/** Register the coverage callback (NULL = none).  It survives
 * htrim_init / htrim_shutdown. */
void htrim_set_coverage_cb(htrim_coverage_fn cb);

/** The coverage floor: the newest ms oldest-overall eviction deleted, so
 * rows older than it may be missing inside retention; 0 = none. */
uint64_t htrim_coverage_floor_ms(void);

/** @return non-zero while an eviction drain is under way. */
int htrim_draining(void);

/** @return non-zero while a targets sweep pass is due or under way. */
int htrim_tsweep_pending(void);

/** Start the engine over @a st (copied).  Reads the engine's meta rows
 * (the backfill's done marker and cursor, the alive stamp, the coverage
 * floor, the age-out resume point -- an unreadable one means the first
 * key) and arms this start's targets sweep; logs nothing
 * (history_init runs on a worker thread).  @a st's env, messages, msgid,
 * targets, reply, by_time and by_owner and @a clock are required; redact,
 * ml_content, ml_paste and meta may be NULL (rows in a missing CF are then
 * never written, so never deleted; without meta the backfill keeps its
 * state in memory and runs on every start), as may @a parse (the backfill
 * then reads every row as unparseable) and @a emptied.  Calling it again
 * restarts the engine (shutdown first).
 * @return 0, or -1 on a missing handle/callback or an allocation failure. */
int htrim_init(const struct htrim_store *st, htrim_parse_fn parse,
               htrim_clock_fn clock, htrim_emptied_fn emptied);

/** Drop every in-memory structure; the store is untouched. */
void htrim_shutdown(void);

/** Stage a stored row's by_time and by_owner rows on @a wb (the store's
 * own batch).  @a ms and @a target/@a msgid form the by_time key -- @a ms
 * must be htc_parse_ms(rec->ts), the time the row's redact_index key
 * carries, since the delete rebuilds that key from the by_time key's
 * first 8 bytes; @a rec is its record (rec->owner, rec->bytes the
 * by_owner key and value).  The by_owner key is copied to @a bo_key
 * (@a bo_size bytes), its length to *@a bo_klen, for htrim_note_stored
 * after the commit.  A row behind the stored age-out resume point (a late
 * row) also puts that point back to its by_time key, on @a wb.
 * @return 0, or -1: a key did not fit (nothing staged) or a put failed
 * (do not commit @a wb). */
int htrim_stage_index(struct db_writebatch *wb, uint64_t ms,
                      const char *target, const char *msgid,
                      const struct htc_rec *rec,
                      char *bo_key, size_t bo_size, size_t *bo_klen);

/** Account a row htrim_stage_index indexed, once its batch committed.
 * Age-out depends on it: a row indexed behind the age-out walk's resume
 * point is found only through here (and the backfill's own note), so
 * every committed by_time put -- every store path, every retry -- must
 * reach it, or the row outlives retention.  The drain's walks (the owner
 * step in progress, oldest overall) go back for such a row too. */
void htrim_note_stored(const char *owner, const void *bo_key, size_t bo_klen,
                       uint32_t bytes);

/** @return non-zero once the boot accounting scan has finished. */
int htrim_acct_loaded(void);

/** The owner totals (complete only once htrim_acct_loaded()). */
const struct htc_acct *htrim_acct(void);

/** @return non-zero once every messages row is indexed (the done marker:
 * HTRIM_PH_BACKFILL has work until then). */
int htrim_backfill_done(void);

/** @return the messages rows the backfill walked since htrim_init. */
size_t htrim_backfill_rows(void);

/** The downgrade check, once at start before any slice (main thread; may
 * log): when @a newest_row_ms is past the last alive stamp plus
 * @a slack_ms, rows were stored while this binary was not running (an
 * older binary wrote them unindexed).  Whatever the walk's state -- done,
 * or stopped mid-way (rows sorting before its cursor would never be
 * walked) -- the done marker and the cursor go, in memory and in the
 * store, and the backfill runs again from the first key (its skip rule
 * keeps the rows already indexed as they are).
 * @return 0: no gap, or no walk state to reset (nothing logged);
 *         1: reset (logged);
 *        -1: reset in memory, but the store kept its marker or cursor --
 *            the caller must not stamp alive this start, so that a crash
 *            before the re-run's first slice commits leaves the gap for
 *            the next start to find. */
int htrim_check_index_gap(uint64_t newest_row_ms, uint64_t slack_ms);

/** Persist @a now_ms as the alive stamp (one small batch): call at each
 * pass start and at shutdown. */
void htrim_stamp_alive(uint64_t now_ms);

/** Open a slice with a budget of @a budget_ms (0 = no budget).
 * Reads the clock once.  @return NULL on allocation failure. */
struct htrim_slice *htrim_slice_begin(unsigned int budget_ms);

/** Whether the slice's budget is spent: one clock read per call (none for
 * an unbudgeted slice).  Expired when
 *   now - start + cost(phase) * staged >= budget_ms * 1000
 * where staged is the rows the slice has staged (deletes, backfill index
 * rows) and cost(phase) what the commit and the cleanup of that phase's
 * last budgeted slices cost per staged row (an EWMA, alpha 1/4, seeded by
 * the first sample; 0 for a slice without a phase).  Checked after each
 * row, so a slice always stages at least one. */
int htrim_slice_expired(struct htrim_slice *s);

/** Name the phase @a s runs for: htrim_run_slice does it for its own
 * slices; a caller's unbudgeted slice (the burst-loss prune) passes
 * HTRIM_PH_INCARNATION so its commit is recorded in htrim_stats (last /
 * max slice).  A slice without a phase is neither recorded nor
 * measured. */
void htrim_slice_set_phase(struct htrim_slice *s, enum htrim_phase ph);

/** THE delete: stage the removal of one stored row and every index row
 * that names it -- its messages row (key from rec->ts verbatim), both
 * msgid-index forms, its multiline content and paste rows, its own
 * reply_index entries as a CHILD (never its children's), its redact_index
 * row, its by_time and by_owner rows -- on @a s's batch, and record its
 * accounting delta (-rec->bytes, only when @a counted), its touched
 * target and the @a path counter, all applied at commit.
 *
 * A row the engine cannot read is still removed from the index, so a walk
 * over by_time always advances: @a rec NULL (its by_time value did not
 * parse), a by_time key without a readable target/msgid, an empty
 * rec->ts, or a key that does not fit stage ONLY the engine-owned rows --
 * the by_time key and, when @a rec names the owner, its by_owner key (with
 * its delta when @a counted) -- and count under @a path.  No other row is
 * touched: the engine does not guess at a message row it cannot name.
 *
 * @return 0: staged (in full, or index-only as above);
 *         -1: an invalid call (NULL slice or key, a bad @a path, the
 *             engine not started) -- nothing staged, @a s unchanged;
 *         -2: @a s is poisoned (a batch op failed, now or earlier): its
 *             commit applies nothing; abort it. */
int htrim_delete_row(struct htrim_slice *s, enum htrim_path path,
                     const void *bt_key, size_t bt_klen,
                     const struct htc_rec *rec, int counted);

/** Commit @a s's batch; only on success apply its deltas and counters and
 * clean up the targets it touched.  Reads the clock once (twice for a
 * budgeted slice with a phase that staged rows: it measures the commit
 * and the cleanup).  A slice with a phase is recorded in htrim_stats,
 * committed or not.  The cleanup of a budgeted slice does at most 16
 * emptiness seeks and carries the rest of its touched targets to the next
 * committed slice (in memory: a restart drops them, and the start's
 * targets sweep reaps them); an unbudgeted slice checks its own touched
 * targets only, the carried ones staying with the budgeted slices.
 * Frees @a s.
 * @return the rows deleted, or -1 (nothing applied). */
int htrim_slice_commit(struct htrim_slice *s);

/** Discard @a s without committing anything.  Frees @a s. */
void htrim_slice_abort(struct htrim_slice *s);

/** Whether a targets cleanup could not finish (its batch failed, or an
 * emptiness check could not read a target), so targets-CF keys may have
 * outlived their rows: the targets sweep runs (once the accounting is
 * loaded).  The flag stays set until a sweep pass starts, or until
 * htrim_tsweep_clear. */
int htrim_tsweep_wanted(void);
void htrim_tsweep_clear(void);

/** Run one phase in one budgeted slice: round-robin from the phase after
 * the last one run, among the phases with work.  A failing phase still
 * records its slice (one extra clock read on that path) and describes
 * itself in htrim_last_error(); the engine does not log it (the caller
 * logs once per streak of failures).
 * @return 1 = work remains, 0 = idle, -1 = error. */
int htrim_run_slice(const struct htrim_params *p);

/** Open an age-out pass under @a p: HTRIM_PH_AGEOUT has work while
 * @a p->retention_days > 0 (a pass at retention 0 is closed at once).  The
 * walk resumes where the last one stopped, or at the oldest by_time row
 * indexed behind that point since (htrim_note_stored, the backfill) --
 * every other row behind it is gone.  A coverage floor older than the
 * cutoff is cleared (its meta row deleted, the coverage callback told).
 * Call it before the pass's first slice: each maintenance tick, and on a
 * retention change.  May log. */
void htrim_pass_start(const struct htrim_params *p);

/** @return non-zero while an age-out pass is open: rows past the
 * cutoff may remain (STATS "Backlog: age-out yes"). */
int htrim_ageout_pending(void);

/** What the last failed htrim_run_slice ran into ("" before any). */
const char *htrim_last_error(void);

/** "ageout", "backfill", "scan", "evict", "tsweep", "cleanup",
 * "incarnation" or "none". */
const char *htrim_phase_name(enum htrim_phase ph);

const struct htrim_stats *htrim_stats(void);

/** Zero max_slice_us (STATS reset). */
void htrim_reset_max_slice(void);

#endif /* INCLUDED_history_trim_h */
