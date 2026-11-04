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
 * the last alive stamp plus a slack (a downgrade window) deletes both, and
 * the walk runs again.
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

/** The phase one htrim_run_slice call ran. */
enum htrim_phase {
  HTRIM_PH_NONE,
  HTRIM_PH_AGEOUT,
  HTRIM_PH_BACKFILL,
  HTRIM_PH_ACCTSCAN,
  HTRIM_PH_EVICT
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
};

struct htrim_stats {
  uint64_t         deleted[HTRIM_PATH_COUNT];   /**< committed deletes per path */
  uint64_t         last_slice_us;               /**< begin to end of cleanup */
  uint64_t         max_slice_us;
  enum htrim_phase last_phase;
  uint64_t         oldest_seen_ms;
};

struct htrim_slice;

/** Start the engine over @a st (copied).  Reads the engine's meta rows
 * (the backfill's done marker and cursor, the alive stamp); logs nothing
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
 * after the commit.
 * @return 0, or -1: a key did not fit (nothing staged) or a put failed
 * (do not commit @a wb). */
int htrim_stage_index(struct db_writebatch *wb, uint64_t ms,
                      const char *target, const char *msgid,
                      const struct htc_rec *rec,
                      char *bo_key, size_t bo_size, size_t *bo_klen);

/** Account a row htrim_stage_index indexed, once its batch committed. */
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

/** The downgrade check, once at start (main thread; may log): when the
 * backfill is done but @a newest_row_ms is past the last alive stamp plus
 * @a slack_ms, rows were stored while this binary was not running (an
 * older binary wrote them unindexed) -- delete the done marker and the
 * cursor, and the backfill runs again (its skip rule keeps the rows
 * already indexed as they are). */
void htrim_check_index_gap(uint64_t newest_row_ms, uint64_t slack_ms);

/** Persist @a now_ms as the alive stamp (one small batch): call at each
 * pass start and at shutdown. */
void htrim_stamp_alive(uint64_t now_ms);

/** Open a slice with a budget of @a budget_ms (0 = no budget).
 * Reads the clock once.  @return NULL on allocation failure. */
struct htrim_slice *htrim_slice_begin(unsigned int budget_ms);

/** Whether the slice's budget is spent: one clock read per call (none for
 * an unbudgeted slice); expired when now - start >= budget_ms * 1000. */
int htrim_slice_expired(struct htrim_slice *s);

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
 * clean up the targets it touched.  Reads the clock once.  Frees @a s.
 * @return the rows deleted, or -1 (nothing applied). */
int htrim_slice_commit(struct htrim_slice *s);

/** Discard @a s without committing anything.  Frees @a s. */
void htrim_slice_abort(struct htrim_slice *s);

/** Whether a targets cleanup could not finish (its batch failed, or an
 * emptiness check could not read a target), so targets-CF keys may have
 * outlived their rows: the targets sweep (Task 8) should run.  The flag
 * stays set until htrim_tsweep_clear. */
int htrim_tsweep_wanted(void);
void htrim_tsweep_clear(void);

/** Run one phase in one budgeted slice: round-robin from the phase after
 * the last one run, among the phases with work.  A failing phase still
 * records its slice (one extra clock read on that path).
 * @return 1 = work remains, 0 = idle, -1 = error. */
int htrim_run_slice(const struct htrim_params *p);

const struct htrim_stats *htrim_stats(void);

/** Zero max_slice_us (STATS reset). */
void htrim_reset_max_slice(void);

#endif /* INCLUDED_history_trim_h */
