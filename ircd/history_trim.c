/* ircd/history_trim.c
 * Chathistory trimming -- the trim engine.  See include/history_trim.h.
 *
 * Depends only on the db_* storage API, the pure codec
 * (history_trim_codec.h, redact_index.h), history_stamp.h, ircd_alloc.h
 * and ircd_log.h: no feature_*, no struct Client, so the CMocka suite runs
 * it against the in-memory storage fake.
 *
 * A slice is one WriteBatch plus three growable arrays of what that batch
 * implies once it commits:
 *   - pending accounting deltas: a copy of the row's by_owner key (in one
 *     byte arena; the owner is the key's NUL-terminated prefix) and the
 *     signed delta, applied through acct_apply() after the commit;
 *   - touched targets: the folded target and the newest rec->ts deleted
 *     from it, deduplicated (qsort) at commit, then checked for emptiness;
 *   - per-path delete counters, added to htrim_stats after the commit.
 * A failed commit applies none of them.
 *
 * The boot accounting scan keeps its position as the last by_owner key it
 * read (scan_cursor).  Scan slices and delete/store paths never interleave
 * inside one slice (one phase per slice, one main loop), so a delta can be
 * judged against the cursor at apply time: a key at or before the cursor
 * has been counted by the scan and the delta must land; a key after it
 * will be read (store) or is gone before the scan gets there (delete) and
 * the delta must not land.
 *
 * The backfill keeps its position as the last messages key it processed
 * (bf_cursor), persisted under HTRIM_META_BACKFILL_CURSOR in the same
 * batch as the index rows and deletes of the rows up to it: a commit moves
 * the stored and the in-memory cursor together, a failed one neither.  Its
 * index rows count through the accounting rule like a store's (positive
 * pending deltas), so a backfill racing the boot scan counts each row once.
 *
 * Age-out keeps where its walk resumes (ao_lower): the successor of the
 * last by_time key a committed slice deleted, or the cutoff bound once a
 * walk reached it (so a pass that finds nothing to delete does not walk
 * the head either).  Every slice opens its iterator there, so the
 * tombstones the walk left behind it are never walked again -- on RocksDB
 * a seek from the first key walks every one not yet compacted away (the
 * bed, 2026-11-04: ~3000 of them, 316-433 ms in one slice).  Behind
 * ao_lower every row is gone except those indexed there since (a late
 * store, a backfill after a retention rise): the smallest such key is
 * kept (ao_late), and a pass start sends the walk back to it.
 *
 * The resume point is also persisted (HTRIM_META_AGEOUT_RESUME; its
 * in-memory mirror is ao_saved) so a restart does not walk the head from
 * the first key (the bed: 791 ms, nothing deleted).  The stored value is
 * never past a live row below the cutoff: each age-out slice's batch puts
 * its new resume point -- unless a late row is pending (ao_late), which
 * the stored value already covers -- and a store or backfill batch that
 * indexes a row behind the stored value puts that row's key instead.  So
 * ao_saved <= ao_lower, and <= every row indexed behind ao_lower.
 *
 * Eviction (the cap) keeps, for the drain under way: the owner step in
 * progress (ev_owner) and the last by_owner key it deleted (ev_bo), so a
 * step that spans slices resumes past its own tombstones; and where the
 * oldest-overall walk resumes (ev_lower; at a drain's start the age-out
 * resume point, below which every row is gone).  A row indexed behind
 * either sends that walk back to it.  Both are in memory: a restart
 * starts a new drain, if the store is still over high.  An emergency
 * slice (htrim_emergency, a store that found the env full) is the same
 * oldest-overall walk and moves ev_lower past its deletes too, drain or
 * not, so emergencies in a row never walk each other's tombstones; a
 * drain's start forgets it with the rest.
 *
 * Compaction hints: every delete staged on a tracked column family
 * (slice_del) widens that slice's [smallest, largest] key and count; a
 * commit folds them into the engine's, which hints a CF once its count
 * reaches compact_min_rows, and every CF at a drain's end.
 */
#include "config.h"

#include "history_trim.h"
#include "history_trim_codec.h"
#include "history_stamp.h"
#include "redact_index.h"
#include "db_cursor.h"
#include "db_env.h"
#include "db_txn.h"
#include "db_types.h"
#include "ircd_alloc.h"
#include "ircd_log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** Largest reply_index key: fold(target) \0 parent \0 ts \0 msgid. */
#define HTRIM_REPLY_KEY_MAX (HTC_TARGET_MAX + HTC_MSGID_MAX + HTC_TS_MAX + HTC_MSGID_MAX + 3)
/** Largest msgid_index key: msgid \0 fold(target). */
#define HTRIM_MSGID_KEY_MAX (HTC_MSGID_MAX + 1 + HTC_TARGET_MAX)
/** Emptiness checks (a messages-CF seek each) one budgeted slice's
 * cleanup does; the rest carry over to the next slice. */
#define HTRIM_CLEANUP_CHECKS 16
/** The deleted entries one emptiness check may step over (a bounded
 * iterator's max_skippable_internal_keys): a target a drain just emptied
 * holds a run of fresh tombstones no compaction has met yet, and a check
 * that walks all of it is a stall in itself.  Past this the check is
 * undecided -- the target keeps its key and is checked again by a later
 * sweep, after its range has been flushed and hinted for compaction. */
#define HTRIM_EMPTY_SKIP_MAX 10000
/** Late rows (indexed behind the age-out walk) kept exactly, by key, so
 * the next pass deletes them by key and resumes at its frontier; past
 * this many the pass falls back to rewinding the walk to the oldest. */
#define HTRIM_LATE_MAX 64
/** Phase slots (every enum htrim_phase value). */
#define HTRIM_PH_SLOTS ((int)HTRIM_PH_EMERGENCY + 1)
/** Unindexable keys a walk names in the log (then only counts). */
#define HTRIM_BF_LOG_KEYS 5
/** A logged key's printable form, quotes excluded. */
#define HTRIM_KEY_PREVIEW 128
/** Undecided targets' ranges hinted apart; past this many the last range
 * widens to take the rest. */
#define HTRIM_UND_MAX 8

/** The column families whose deletes the compaction hints track. */
enum htrim_hint_cf {
  HH_MESSAGES,
  HH_MSGID,
  HH_REPLY,
  HH_ML_CONTENT,
  HH_BY_TIME,
  HH_BY_OWNER,
  HH_UNDECIDED,      /* messages: the ranges of undecided targets */
  HH_COUNT
};

/** The keys deleted from one column family since its last hint (or, in a
 * slice, by that slice): the smallest, the largest, and how many. */
struct htrim_hint {
  char    *lo, *hi;
  size_t   lo_len, lo_cap, hi_len, hi_cap;
  uint64_t n;
};

/** One by_time key (a late row). */
struct htrim_btkey {
  char   k[HTC_BT_KEY_MAX];
  size_t len;
};

/** One pending accounting delta: a by_owner key copy in the slice's arena. */
struct htrim_pending {
  size_t  koff;
  size_t  klen;
  int64_t delta;
};

/** One touched target and the newest stored ts deleted from it. */
struct htrim_touch {
  char target[HTC_TARGET_MAX];   /* folded, as read from the by_time key */
  char ts[HTC_TS_MAX];
};

struct htrim_slice {
  struct db_writebatch *wb;
  uint64_t              start_us;
  uint64_t              budget_us;   /* 0 = no budget */
  enum htrim_phase      phase;       /* NONE: a caller's own slice, not recorded */
  int                   broken;      /* a staging op failed: never commit */
  int                   rows;
  uint64_t              counts[HTRIM_PATH_COUNT];

  char                 *keys;        /* arena of by_owner key copies */
  size_t                keys_len, keys_cap;
  struct htrim_pending *pend;
  size_t                npend, cap_pend;
  struct htrim_touch   *touch;
  size_t                ntouch, cap_touch;

  /* An age-out step, applied at commit. */
  int                   ao_step;     /* this slice walked by_time */
  int                   ao_finished; /* ... to the cutoff: the pass is over */
  int                   ao_bounded;  /* ao_upper is set (retention on) */
  unsigned char         ao_upper[8]; /* the walk's bound, be64(cutoff_ms) */
  char                 *ao_cursor;   /* the last by_time key it deleted */
  size_t                ao_cursor_len, ao_cursor_cap;

  /* A backfill step, applied at commit. */
  int                   bf_step;     /* this slice walked messages rows */
  int                   bf_finished; /* ... to the end of the CF */
  char                 *bf_cursor;   /* the last messages key it processed */
  size_t                bf_cursor_len, bf_cursor_cap;
  size_t                bf_rows, bf_indexed, bf_aged, bf_unindexed;
  size_t                bf_behind;   /* rows it indexed behind the age-out frontier */
  char                 *bf_min_bt;   /* the smallest by_time key it indexed */
  size_t                bf_min_bt_len, bf_min_bt_cap;
  /* Unindexable keys to name in the log once this slice commits. */
  char                  bf_bad[HTRIM_BF_LOG_KEYS][HTRIM_KEY_PREVIEW];
  size_t                bf_bad_klen[HTRIM_BF_LOG_KEYS];
  unsigned int          bf_nbad;

  /* Where the age-out walk resumes once this slice commits (0 = as it
   * was), and what this batch stores as the resume point (ao_store,
   * when ao_saved_put). */
  char                 *ao_next;
  size_t                ao_next_len, ao_next_cap;
  int                   ao_saved_put;
  char                 *ao_store;
  size_t                ao_store_len, ao_store_cap;
  unsigned char         due_done[HTRIM_LATE_MAX];   /* due late rows it took */
  unsigned int          ts_checks;   /* sweep emptiness seeks */
  unsigned int          ts_undecided;

  /* What the slice deleted from each tracked CF (compaction hints). */
  struct htrim_hint     hint[HH_COUNT];
  size_t                idx_only;    /* by_owner entries removed alone (no row) */

  /* An eviction step, applied at commit. */
  int                   ev_step;
  uint64_t              ev_cap;      /* the cap and the low watermark in bytes */
  uint64_t              ev_target;   /*   this slice planned under */
  uint64_t              ev_freed;    /* bytes the slice's deletes take off */
  char                  ev_owner[HTC_OWNER_MAX];  /* the owner step in progress
                                                     at the end ("" = none) */
  char                 *ev_bo;       /* ... and the last by_owner key it deleted */
  size_t                ev_bo_len, ev_bo_cap;
  int                   ev_below;    /* ... walking below where it started */
  char                 *ev_below_hi; /*     up to this key (exclusive) */
  size_t                ev_below_hi_len, ev_below_hi_cap;
  char                 *ev_start;    /* ... where it started (owner \0 ‖ floor) */
  size_t                ev_start_len, ev_start_cap;
  char                  ev_zero[HTC_OWNER_MAX];   /* an owner walked to the end of
                                                     its range: it holds 0 */
  char                 *ev_bt;       /* the last by_time key oldest-overall deleted */
  size_t                ev_bt_len, ev_bt_cap;
  int                   ev_exhausted; /* oldest-overall ran out of rows */
  int                   ev_recount;   /* an owner walk from the floor ran out */
  uint64_t              floor_ms;    /* the newest ms oldest-overall deleted */

  /* An emergency slice (htrim_emergency), applied at commit. */
  int                   em_step;
  int                   defer_cleanup; /* its touched targets go to the carry:
                                          the next engine slice checks (and
                                          reports) them, never the caller */

  /* A targets-sweep step, applied at commit. */
  int                   ts_step;
  int                   ts_finished; /* ... reached the end of the targets CF */
  char                 *ts_cursor;   /* the last targets key it checked */
  size_t                ts_cursor_len, ts_cursor_cap;
  char                (*ts_names)[HTC_TARGET_MAX];   /* the empty targets it removes */
  size_t                ts_n, ts_cap;
};

static struct {
  int                inited;
  struct htrim_store st;
  htrim_parse_fn     parse;
  htrim_clock_fn     clock;
  htrim_emptied_fn   emptied;

  struct htc_acct   *acct;
  int                acct_loaded;
  int                scan_started;
  char              *cursor;          /* last by_owner key the scan read */
  size_t             cursor_len, cursor_cap;

  /* The backfill (persisted in st.meta; in memory only without it). */
  int                bf_done;
  char              *bf_cursor;       /* last messages key processed */
  size_t             bf_cursor_len, bf_cursor_cap;
  size_t             bf_rows, bf_indexed, bf_aged, bf_unindexed;  /* since htrim_init */
  unsigned int       bf_bad_logged;   /* unindexable keys named this walk */
  int                bf_unread;       /* a backfill meta row could not be read */
  uint64_t           alive_ms;        /* the last alive stamp, 0 = none */

  /* Age-out: one pass per htrim_pass_start, in memory only (every start
   * opens a pass at its first maintenance tick, from the first key). */
  int                ao_pending;      /* a pass is open */
  char              *ao_lower;        /* where the walk resumes (inclusive), */
  size_t             ao_lower_len, ao_lower_cap;   /* 0 = the first key */
  char              *ao_late;         /* the smallest by_time key indexed behind */
  size_t             ao_late_len, ao_late_cap;     /* ao_lower since; 0 = none */
  char              *ao_saved;        /* what HTRIM_META_AGEOUT_RESUME holds; */
  size_t             ao_saved_len, ao_saved_cap;   /* 0 = none (the first key) */
  /* Late rows, exactly: noted since the last pass start (late), and
   * handed to the pass to delete by key first (due).  late_over: more
   * than HTRIM_LATE_MAX were noted -- the next pass start rewinds the
   * walk to ao_late, the oldest, instead. */
  struct htrim_btkey late[HTRIM_LATE_MAX];
  size_t             nlate;
  int                late_over;
  struct htrim_btkey due[HTRIM_LATE_MAX];
  size_t             ndue;

  /* The cap: the drain under way (in memory only). */
  int                draining;
  uint64_t           floor_ms;        /* the coverage floor, 0 = none */
  char               ev_owner[HTC_OWNER_MAX];      /* the owner step in progress */
  char              *ev_bo;           /* the last by_owner key that step deleted, */
  size_t             ev_bo_len, ev_bo_cap;         /* 0 = from the owner's first key */
  int                ev_below;        /* the step walks below where it started, */
  char              *ev_below_hi;     /* up to this key (exclusive) */
  size_t             ev_below_hi_len, ev_below_hi_cap;
  char              *ev_start;        /* where the step started (owner \0 ‖ floor; */
  size_t             ev_start_len, ev_start_cap;   /* 0 = its first key) */
  int                ev_lower_set;    /* 0: oldest-overall starts at the age-out point */
  char              *ev_lower;        /* where oldest-overall resumes (inclusive), */
  size_t             ev_lower_len, ev_lower_cap;   /* 0 = the first key */
  uint64_t           drain_owner, drain_oldest;    /* rows this drain deleted */

  /* The targets sweep. */
  int                ts_armed;        /* a pass is due (each start, each drain's end) */
  int                ts_running;      /* a pass is under way */
  int                ts_later;        /* an emptiness check was undecided: a pass at
                                         the next pass start, after compaction */
  char              *ts_cursor;       /* the last targets key it checked */
  size_t             ts_cursor_len, ts_cursor_cap;

  /* Compaction hints: what each tracked CF lost since its last hint, and
   * the hints due (issued one a slice: a flush switches the memtable on
   * this thread -- the bed, valgrind: 3-90 ms each). */
  struct htrim_hint  hint[HH_COUNT];
  unsigned char      hint_due[HH_COUNT];
  unsigned char      hint_defer[HH_COUNT];  /* slices its flush waited on a busy CF */
  uint64_t           hint_rearm[HH_COUNT];  /* after a failed or dropped hint: the
                                               count the cumulative trigger waits
                                               for, or ... */
  unsigned char      hint_backoff[HH_COUNT]; /* ... these many slices */
  unsigned char      hint_failed[HH_COUNT]; /* the last hint failed or was dropped
                                               (its count kept; one WARNING a streak) */
  /* Undecided targets' ranges [name 0x00, name 0x01), each apart (up to
   * HTRIM_UND_MAX; past that the last one widens): the HH_UNDECIDED slot. */
  struct {
    char   lo[HTC_TARGET_MAX + 1], hi[HTC_TARGET_MAX + 1];
    size_t lol, hil;
  }                  und[HTRIM_UND_MAX];
  size_t             nund;
  uint64_t           und_targets;           /* undecided targets they cover */
  unsigned int       compact_min_rows;

  char               last_error[192]; /* the last failed slice, for the caller's log */

  /* What a committed budgeted slice paid after its staging -- the batch
   * commit and the touched-target cleanup -- per row it staged, in ns, an
   * EWMA (alpha 1/4, seeded by the first sample) per phase: the budget
   * check charges it ahead for every row staged so far. */
  uint64_t           cost_ns[HTRIM_PH_SLOTS];
  /* What the touched-target cleanup paid per entry it examined, in ns,
   * an EWMA (alpha 1/4, seeded by the first sample): charged ahead for
   * the entries a slice's cleanup will examine (carried + touched, at
   * most HTRIM_CLEANUP_CHECKS), apart from the per-row commit cost --
   * the cleanup's work follows the targets a slice touched, not its
   * rows. */
  uint64_t           clean_ns;
  /* The last slice's breakdown (record_slice copies it onto the max). */
  uint64_t           last_walk_us, last_commit_us, last_cleanup_us, last_hint_us;
  unsigned int       last_seeks;

  /* Touched targets whose emptiness check a budgeted slice's cleanup had
   * no room for (HTRIM_CLEANUP_CHECKS), oldest first; the next committed
   * slice checks them before its own.  In memory only: a restart drops
   * them (the targets sweep at boot reaps what they would have). */
  struct htrim_touch *carry;
  size_t             ncarry, cap_carry;
  enum htrim_phase   last_run;
  uint64_t           last_elapsed_us; /* of the last committed/failed slice */
  int                tsweep_wanted;   /* a targets cleanup could not finish */
  struct htrim_stats stats;
} g;

/** The coverage callback: outside g, so a restart keeps it. */
static htrim_coverage_fn coverage_cb;

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int key_cmp(const void *a, size_t al, const void *b, size_t bl)
{
  size_t n = al < bl ? al : bl;
  int c = n ? memcmp(a, b, n) : 0;
  if (c)
    return c;
  return (al > bl) - (al < bl);
}

static const char *last_err(void)
{
  const char *e = db_env_last_error(g.st.env);
  return e ? e : "?";
}

static uint64_t elapsed_since(uint64_t start, uint64_t now)
{
  return now >= start ? now - start : 0;
}

/** Copy @a kl bytes of @a k into the growable buffer *@a buf. */
static void bytes_set(char **buf, size_t *len, size_t *cap,
                      const void *k, size_t kl)
{
  if (kl > *cap) {
    *cap = kl;
    *buf = (char *)MyRealloc(*buf, *cap);
  }
  if (kl)
    memcpy(*buf, k, kl);
  *len = kl;
}

static void cursor_set(const void *k, size_t kl)
{
  bytes_set(&g.cursor, &g.cursor_len, &g.cursor_cap, k, kl);
  g.scan_started = 1;
}

static void bf_cursor_clear(void)
{
  MyFree(g.bf_cursor);
  g.bf_cursor_len = g.bf_cursor_cap = 0;
}

/** Read meta row @a key into @a v (the caller frees it).
 * @return 1 read, 0 no such row (or no meta CF), -1 a read error. */
static int meta_get(const char *key, struct db_val *v)
{
  int rc;

  if (!g.st.meta)
    return 0;
  rc = db_get(g.st.env, g.st.meta, key, strlen(key), NULL, v);
  if (rc == DB_OK)
    return 1;
  return rc == DB_NOTFOUND ? 0 : -1;
}

/** A decimal meta value (at most 20 digits) as a number.
 * @return 0, or -1 when @a v is not one. */
static int parse_u64(const struct db_val *v, uint64_t *out)
{
  char buf[24];

  if (!v->base || !v->len || v->len >= sizeof buf)
    return -1;
  memcpy(buf, v->base, v->len);
  buf[v->len] = '\0';
  if (strspn(buf, "0123456789") != v->len)
    return -1;
  *out = strtoull(buf, NULL, 10);
  return 0;
}

/** Load the backfill's state and the alive stamp from the meta rows.
 *  - A cursor row means an unfinished walk, whatever the done marker says
 *    (a re-run whose marker delete did not commit still resumes).
 *  - A row that cannot be read is not a missing row: an unreadable cursor
 *    beside a done marker would read as "done".  Either read failing means
 *    an unfinished walk with no usable cursor -- it runs again from the
 *    first key (the skip rule keeps that exact) -- and bf_unread tells the
 *    gap check the store may still hold a marker or a cursor.
 *  - An unreadable alive stamp reads as none (0): a gap then resets. */
static void meta_load(void)
{
  struct db_val v = { NULL, 0 };
  uint64_t n;
  int rc;

  rc = meta_get(HTRIM_META_BACKFILL_CURSOR, &v);
  if (rc > 0 && v.len)
    bytes_set(&g.bf_cursor, &g.bf_cursor_len, &g.bf_cursor_cap, v.base, v.len);
  db_val_free(&v);
  if (rc < 0)
    g.bf_unread = 1;
  else if (!g.bf_cursor_len) {
    rc = meta_get(HTRIM_META_BACKFILL_DONE, &v);
    if (rc < 0)
      g.bf_unread = 1;
    else
      g.bf_done = rc > 0 && v.len == 4 && memcmp(v.base, "done", 4) == 0;
    db_val_free(&v);
  }

  if (meta_get(HTRIM_META_ALIVE, &v) > 0 && parse_u64(&v, &n) == 0)
    g.alive_ms = n;
  db_val_free(&v);

  /* The coverage floor (unreadable = none: the coverage claimed is then
   * the configured one, as before any eviction). */
  if (meta_get(HTRIM_META_FLOOR, &v) > 0 && parse_u64(&v, &n) == 0)
    g.floor_ms = n;
  db_val_free(&v);

  /* Where age-out resumes; a missing or unreadable row (or one no by_time
   * key bound could be) means the first key, as before it was stored. */
  if (meta_get(HTRIM_META_AGEOUT_RESUME, &v) > 0 && v.len && v.len <= HTC_BT_KEY_MAX + 1) {
    bytes_set(&g.ao_lower, &g.ao_lower_len, &g.ao_lower_cap, v.base, v.len);
    bytes_set(&g.ao_saved, &g.ao_saved_len, &g.ao_saved_cap, v.base, v.len);
  }
  db_val_free(&v);
}

/** Render a key for the log: printable ASCII as is, every other byte (the
 * NUL separators too), a backslash and a quote as \xHH; "..." marks a cut. */
static const char *key_preview(char *buf, size_t size, const void *key, size_t klen)
{
  static const char hex[] = "0123456789abcdef";
  const unsigned char *k = (const unsigned char *)key;
  size_t i, o = 0;

  for (i = 0; i < klen; i++) {
    unsigned char c = k[i];
    int plain = c >= 0x20 && c < 0x7f && c != '\\' && c != '\'';
    if (o + (plain ? 1 : 4) + 4 > size) {      /* room for "..." and the NUL */
      memcpy(buf + o, "...", 3);
      o += 3;
      break;
    }
    if (plain)
      buf[o++] = (char)c;
    else {
      buf[o++] = '\\';
      buf[o++] = 'x';
      buf[o++] = hex[c >> 4];
      buf[o++] = hex[c & 15];
    }
  }
  buf[o] = '\0';
  return buf;
}

static void record_slice(enum htrim_phase ph);
static void last_unmeasured(unsigned int seeks);

/** THE accounting rule: every store/delete delta goes through here. */
static void acct_apply(const char *owner, const void *bo_key, size_t bo_klen,
                       int64_t delta)
{
  if (!g.acct || !owner || !delta)
    return;
  if (!g.acct_loaded
      && (!g.scan_started
          || key_cmp(bo_key, bo_klen, g.cursor, g.cursor_len) > 0))
    return;
  htc_acct_add(g.acct, owner, delta);
}

/** Whether a by_time key @a bt about to be indexed sorts behind the
 * stored age-out resume point: its batch must store @a bt there instead
 * (a restart would otherwise resume past it). */
static int behind_saved(const void *bt, size_t btl)
{
  return g.st.meta && g.ao_saved_len && bt && btl
         && key_cmp(bt, btl, g.ao_saved, g.ao_saved_len) < 0;
}

/** A by_time key was just indexed (committed): if it sorts behind where
 * the age-out walk resumes, the next pass must go back for it (and its
 * batch stored it as the resume point, when behind that too); if behind
 * where the drain's oldest-overall walk resumes, that walk goes back. */
static void ageout_note_indexed(const void *bt, size_t btl)
{
  if (!bt || !btl)
    return;
  if (behind_saved(bt, btl))
    bytes_set(&g.ao_saved, &g.ao_saved_len, &g.ao_saved_cap, bt, btl);
  if (g.ev_lower_set && g.ev_lower_len
      && key_cmp(bt, btl, g.ev_lower, g.ev_lower_len) < 0)
    bytes_set(&g.ev_lower, &g.ev_lower_len, &g.ev_lower_cap, bt, btl);
  if (!g.ao_lower_len || key_cmp(bt, btl, g.ao_lower, g.ao_lower_len) >= 0)
    return;                                     /* ahead of the walk */
  if (!g.ao_late_len || key_cmp(bt, btl, g.ao_late, g.ao_late_len) < 0)
    bytes_set(&g.ao_late, &g.ao_late_len, &g.ao_late_cap, bt, btl);
  /* ... and exactly, while there is room: the pass deletes it by key. */
  if (!g.late_over) {
    size_t i;
    for (i = 0; i < g.nlate; i++)
      if (g.late[i].len == btl && memcmp(g.late[i].k, bt, btl) == 0)
        return;
    if (g.nlate == HTRIM_LATE_MAX || btl > sizeof g.late[0].k)
      g.late_over = 1;
    else {
      memcpy(g.late[g.nlate].k, bt, btl);
      g.late[g.nlate].len = btl;
      g.nlate++;
    }
  }
}

/** The oldest late row still to go at or after @a after (@a al bytes;
 * 0 = anywhere): of those noted since the last pass start and those due
 * in this pass.  After an overflow only the oldest noted one is known
 * (ao_late), so it counts wherever it sorts.  @return 0 when none. */
static int late_min_from(const char *after, size_t al, const char **k, size_t *kl)
{
  const char *m = NULL;
  size_t ml = 0, i;

#define LATE_TAKE(key, len) do {                                          \
    if ((!al || key_cmp((key), (len), after, al) >= 0)                    \
        && (!m || key_cmp((key), (len), m, ml) < 0)) {                    \
      m = (key);                                                          \
      ml = (len);                                                         \
    }                                                                     \
  } while (0)
  for (i = 0; i < g.nlate; i++)
    LATE_TAKE(g.late[i].k, g.late[i].len);
  for (i = 0; i < g.ndue; i++)
    LATE_TAKE(g.due[i].k, g.due[i].len);
#undef LATE_TAKE
  if (g.late_over && g.ao_late_len
      && (!m || key_cmp(g.ao_late, g.ao_late_len, m, ml) < 0)) {
    m = g.ao_late;
    ml = g.ao_late_len;
  }
  *k = m;
  *kl = ml;
  return m != NULL;
}

static int late_min(const char **k, size_t *kl)
{
  return late_min_from(NULL, 0, k, kl);
}

/** The smallest by_time key that may still be live: behind the age-out
 * walk (ao_lower) and behind this drain's oldest-overall walk (ev_lower)
 * every row is gone but the late rows, so it is the larger of the two,
 * or the oldest late row when that is smaller.  Length 0 = the first
 * key. */
static void live_floor(const char **k, size_t *kl)
{
  const char *b = g.ao_lower, *l;
  const char *ev = g.ev_lower_set && g.ev_lower_len ? g.ev_lower : NULL;
  size_t bl = g.ao_lower_len, evl = ev ? g.ev_lower_len : 0, ll;

  if (ev && (!bl || key_cmp(ev, evl, b, bl) > 0)) {
    b = ev;
    bl = evl;
  }
  /* A late row behind ev_lower is gone: the drain's walk started at or
   * below every late row noted before it, and one noted since moved
   * ev_lower back to it. */
  if (bl && late_min_from(ev, evl, &l, &ll) && key_cmp(l, ll, b, bl) < 0) {
    b = l;
    bl = ll;
  }
  *k = b;
  *kl = bl;
}

/* ------------------------------------------------------------------ */
/* Compaction hints                                                    */
/* ------------------------------------------------------------------ */

static int hint_slot(const struct db_cf *cf)
{
  if (!cf)
    return -1;
  if (cf == g.st.messages)   return HH_MESSAGES;
  if (cf == g.st.msgid)      return HH_MSGID;
  if (cf == g.st.reply)      return HH_REPLY;
  if (cf == g.st.ml_content) return HH_ML_CONTENT;
  if (cf == g.st.by_time)    return HH_BY_TIME;
  if (cf == g.st.by_owner)   return HH_BY_OWNER;
  return -1;
}

static struct db_cf *hint_cf(int i)
{
  switch (i) {
  case HH_MESSAGES:   return g.st.messages;
  case HH_MSGID:      return g.st.msgid;
  case HH_REPLY:      return g.st.reply;
  case HH_ML_CONTENT: return g.st.ml_content;
  case HH_BY_TIME:    return g.st.by_time;
  case HH_BY_OWNER:   return g.st.by_owner;
  case HH_UNDECIDED:  return g.st.messages;
  default:            return NULL;
  }
}

/** Widen @a h by @a n keys whose smallest is @a lo and largest @a hi. */
static void hint_add(struct htrim_hint *h, const void *lo, size_t lol,
                     const void *hi, size_t hil, uint64_t n)
{
  if (!n)
    return;
  if (!h->n || key_cmp(lo, lol, h->lo, h->lo_len) < 0)
    bytes_set(&h->lo, &h->lo_len, &h->lo_cap, lo, lol);
  if (!h->n || key_cmp(hi, hil, h->hi, h->hi_len) > 0)
    bytes_set(&h->hi, &h->hi_len, &h->hi_cap, hi, hil);
  h->n += n;
}

static void hint_free(struct htrim_hint *h)
{
  MyFree(h->lo);
  MyFree(h->hi);
  memset(h, 0, sizeof *h);
}

static const char *const hint_names[HH_COUNT] = {
  "messages", "msgid_index", "reply_index", "ml_content", "by_time", "by_owner",
  "messages (undecided targets)"
};

/** A flush the hints may not wait for: past this many slices on a busy
 * CF the hint is dropped (its count kept: the next trigger hints again). */
#define HTRIM_HINT_DEFER_MAX 60

/** Whether a flush of @a cf would block the calling thread: RocksDB's
 * FlushMemTable waits (WaitUntilFlushWouldNotStallWrites -- even with
 * wait off, and allow_write_stall has no C setter) while one more
 * immutable memtable would reach max_write_buffer_number (a flush of the
 * CF already in flight) or one more L0 file would reach
 * level0_slowdown_writes_trigger.  Read off the CF's properties and
 * options; unknown values count as not busy. */
static int cf_flush_would_wait(struct db_cf *cf)
{
  struct db_cf_stats cs;

  memset(&cs, 0, sizeof cs);
  if (db_cf_stats(g.st.env, cf, &cs) != DB_OK)
    return 0;
  return (cs.max_write_buffers && cs.imm_memtables + 1 >= cs.max_write_buffers)
         || (cs.l0_slowdown_trigger && cs.l0_files + 1 >= cs.l0_slowdown_trigger);
}

/** Whether slot @a i has deletes (or undecided targets) to hint. */
static int slot_pending(int i)
{
  return i == HH_UNDECIDED ? g.nund > 0 : g.hint[i].n > 0;
}

/** Suggest slot @a i's range(s) on @a cf: [smallest, largest ‖ 0x00) of
 * what it lost, or each undecided target's [name 0x00, name 0x01).
 * @return 0, or -1 when a suggestion failed. */
static int slot_suggest(int i, struct db_cf *cf)
{
  struct htrim_hint *h = &g.hint[i];
  char *end;
  size_t k;
  int rc = 0;

  if (i == HH_UNDECIDED) {
    for (k = 0; k < g.nund; k++)
      if (db_suggest_compact(g.st.env, cf, g.und[k].lo, g.und[k].lol,
                             g.und[k].hi, g.und[k].hil) != DB_OK)
        rc = -1;
    return rc;
  }
  end = (char *)MyMalloc(h->hi_len + 1);
  memcpy(end, h->hi, h->hi_len);
  end[h->hi_len] = '\0';
  if (db_suggest_compact(g.st.env, cf, h->lo, h->lo_len, end, h->hi_len + 1) != DB_OK)
    rc = -1;
  MyFree(end);
  return rc;
}

/** Slot @a i's hint went through: start counting again. */
static void slot_done(int i)
{
  if (i == HH_UNDECIDED) {
    g.nund = 0;
    g.und_targets = 0;
  } else
    g.hint[i].n = 0;
  g.hint_defer[i] = g.hint_backoff[i] = g.hint_failed[i] = 0;
  g.hint_rearm[i] = 0;
}

/** A hint on slot @a i did not go through: one WARNING a streak of
 * failures (slot_done ends the streak), and its count is kept -- a
 * drain's start keeps it too. */
static void slot_warn(int i, const char *what)
{
  if (!g.hint_failed[i])
    log_write(LS_SYSTEM, L_WARNING, 0,
              "history_trim: compaction hint on %s %s; kept for a later one "
              "(further failures not logged until one succeeds): %s",
              hint_names[i], what, last_err());
  g.hint_failed[i] = 1;
}

/** Slot @a i's hint failed, or was dropped after HTRIM_HINT_DEFER_MAX
 * busy slices: its count stays (the next hint covers this range too), a
 * drain's start keeps it, and the cumulative trigger backs off until
 * compact_min_rows more keys went or HTRIM_HINT_DEFER_MAX slices passed.
 * One WARNING a streak of failures. */
static void slot_failed(int i, const char *what)
{
  slot_warn(i, what);
  g.hint_defer[i] = 0;
  g.hint_backoff[i] = HTRIM_HINT_DEFER_MAX;
  g.hint_rearm[i] = i == HH_UNDECIDED ? 0 : g.hint[i].n + g.compact_min_rows;
}

/** Hint the compaction of slot @a i's CF -- and, on messages, of the
 * other messages slot when it is due too: one flush serves both.  A hint
 * marks SST files only, so the CF's memtable is flushed first, without
 * waiting for the flush itself -- but RocksDB still blocks the call while
 * the flush would stall writes, so a busy CF (cf_flush_would_wait) gets
 * the suggestion alone, once, and the hint stays due for a later slice
 * (up to HTRIM_HINT_DEFER_MAX).
 * @return 1 when a flush was attempted (one a slice), 0 otherwise. */
static int hint_flush(int i)
{
  struct db_cf *cf = hint_cf(i);
  struct db_cf_stats cs;
  uint64_t t0, us;
  int grp[2], ng = 0, k, flushed;

  if (!slot_pending(i))
    return 0;
  if (!cf) {
    slot_done(i);
    return 0;
  }
  grp[ng++] = i;
  if (cf == g.st.messages) {
    int o = i == HH_MESSAGES ? HH_UNDECIDED : HH_MESSAGES;
    if (g.hint_due[o] && slot_pending(o)) {
      g.hint_due[o] = 0;
      grp[ng++] = o;
    }
  }
  if (cf_flush_would_wait(cf)) {
    for (k = 0; k < ng; k++) {
      int j = grp[k];
      /* The suggestion alone, once; a failure is logged as a failed flush
       * is, and the flush stays due. */
      if (!g.hint_defer[j] && slot_suggest(j, cf) != 0)
        slot_warn(j, "failed (the suggestion alone: the column family is busy)");
      if (++g.hint_defer[j] < HTRIM_HINT_DEFER_MAX)
        g.hint_due[j] = 1;                      /* the flush, a later slice */
      else
        slot_failed(j, "dropped: the column family stayed busy");
    }
    return 0;
  }
  memset(&cs, 0, sizeof cs);
  db_cf_stats(g.st.env, cf, &cs);
  t0 = g.clock();
  flushed = db_flush_cf(g.st.env, cf, 0) == DB_OK;
  us = elapsed_since(t0, g.clock());
  for (k = 0; k < ng; k++) {
    int j = grp[k];
    if (j == HH_UNDECIDED)
      log_write(LS_SYSTEM, L_INFO, 0,
                "history: trim: compaction hint on messages: %llu undecided "
                "target%s, %zu deletes in its memtables; flush %llu us on the "
                "main thread", (unsigned long long)g.und_targets,
                g.und_targets == 1 ? "" : "s", cs.mem_deletes + cs.imm_deletes,
                (unsigned long long)us);
    else
      log_write(LS_SYSTEM, L_INFO, 0,
                "history: trim: compaction hint on %s: %llu keys deleted since "
                "the last hint, %zu deletes in its memtables; flush %llu us on "
                "the main thread", hint_names[j],
                (unsigned long long)g.hint[j].n, cs.mem_deletes + cs.imm_deletes,
                (unsigned long long)us);
    if (flushed && slot_suggest(j, cf) == 0) {
      if (g.hint_failed[j])
        log_write(LS_SYSTEM, L_INFO, 0,
                  "history_trim: compaction hints on %s go through again",
                  hint_names[j]);
      slot_done(j);
    } else
      slot_failed(j, flushed ? "failed" : "failed (flush)");
  }
  return 1;
}

static void hints_flush_all(void)
{
  int i;
  for (i = 0; i < HH_COUNT; i++)
    if (slot_pending(i))
      g.hint_due[i] = 1;
}

static int hints_pending(void)
{
  int i;
  for (i = 0; i < HH_COUNT; i++)
    if (g.hint_due[i])
      return 1;
  return 0;
}

/** Issue the due hints: at most one flush a slice; a busy CF's hint
 * (suggested alone, still due) does not hold up the others.  @return 1
 * when any hint was due. */
static int hint_issue_one(void)
{
  int i, any = 0;
  for (i = 0; i < HH_COUNT; i++)
    if (g.hint_due[i]) {
      g.hint_due[i] = 0;
      any = 1;
      if (hint_flush(i))
        return 1;
    }
  return any;
}

/** The CFs whose keys sort by time (by_time; msgid_index and ml_content
 * by msgid, which is time-ordered): what age-out deleted is one range at
 * the head, so the cumulative trigger hints them.  The prefix-keyed CFs
 * (messages, by_owner, reply_index: per target or owner) are spread over
 * the whole keyspace -- one hint would cover all of it -- and rely on the
 * deletion collector, plus the hint at a drain's end over what the drain
 * deleted. */
static int hint_time_ordered(int i)
{
  return i == HH_BY_TIME || i == HH_MSGID || i == HH_ML_CONTENT;
}

/* ------------------------------------------------------------------ */
/* Lifecycle                                                           */
/* ------------------------------------------------------------------ */

int htrim_init(const struct htrim_store *st, htrim_parse_fn parse,
               htrim_clock_fn clock, htrim_emptied_fn emptied)
{
  if (g.inited)
    htrim_shutdown();
  if (!st || !st->env || !st->messages || !st->msgid || !st->targets
      || !st->reply || !st->by_time || !st->by_owner || !clock)
    return -1;

  memset(&g, 0, sizeof g);
  g.acct = htc_acct_new();
  if (!g.acct)
    return -1;
  g.st = *st;
  g.parse = parse;
  g.clock = clock;
  g.emptied = emptied;
  g.last_run = HTRIM_PH_NONE;
  g.stats.last_phase = HTRIM_PH_NONE;
  /* The boot accounting scan always starts from the first by_owner key;
   * the backfill resumes where the meta rows say it stopped. */
  meta_load();
  /* Once per start: the carried emptiness checks and the "cleanup could
   * not finish" flag of the last run are gone with its memory. */
  g.ts_armed = 1;
  g.inited = 1;
  return 0;
}

void htrim_shutdown(void)
{
  int i;

  htc_acct_free(g.acct);
  MyFree(g.cursor);
  MyFree(g.bf_cursor);
  MyFree(g.ao_lower);
  MyFree(g.ao_late);
  MyFree(g.ao_saved);
  MyFree(g.ev_bo);
  MyFree(g.ev_below_hi);
  MyFree(g.ev_start);
  MyFree(g.ev_lower);
  MyFree(g.ts_cursor);
  MyFree(g.carry);
  for (i = 0; i < HH_COUNT; i++)
    hint_free(&g.hint[i]);
  memset(&g, 0, sizeof g);
}

/* ------------------------------------------------------------------ */
/* The store path                                                      */
/* ------------------------------------------------------------------ */

/** Stage the by_time row @a bt (@a btl bytes) and the by_owner row of
 * @a rec on @a wb; the by_owner key goes to @a bo_key, its length to
 * *@a bo_klen.  @return 0; -1 the record or the by_owner key does not fit
 * (nothing staged); -2 a put failed (do not commit @a wb). */
static int stage_index(struct db_writebatch *wb, const char *bt, size_t btl,
                       const struct htc_rec *rec,
                       char *bo_key, size_t bo_size, size_t *bo_klen)
{
  char rv[HTC_REC_MAX];
  unsigned char sz[4];
  int rvl, bol;

  rvl = htc_rec_pack(rv, sizeof rv, rec);
  if (rvl < 0)
    return -1;
  bol = htc_bo_key(bo_key, bo_size, rec->owner, bt, btl);
  if (bol < 0)
    return -1;
  htc_size_pack(sz, rec->bytes);
  if (db_writebatch_put(wb, g.st.by_time, bt, btl, rv, (size_t)rvl) != DB_OK
      || db_writebatch_put(wb, g.st.by_owner, bo_key, (size_t)bol, sz, sizeof sz) != DB_OK)
    return -2;
  *bo_klen = (size_t)bol;
  return 0;
}

int htrim_stage_index(struct db_writebatch *wb, uint64_t ms,
                      const char *target, const char *msgid,
                      const struct htc_rec *rec,
                      char *bo_key, size_t bo_size, size_t *bo_klen)
{
  char bt[HTC_BT_KEY_MAX];
  int btl;

  if (!g.inited || !wb || !target || !msgid || !rec || !bo_key || !bo_klen)
    return -1;
  btl = htc_bt_key(bt, sizeof bt, ms, target, msgid);
  if (btl < 0)
    return -1;
  if (stage_index(wb, bt, (size_t)btl, rec, bo_key, bo_size, bo_klen) != 0)
    return -1;
  /* Behind the stored age-out resume point (a late row): this batch moves
   * it back to the row, so a restart before the next pass still walks it
   * (htrim_note_stored moves the mirror once the batch committed). */
  if (behind_saved(bt, (size_t)btl)
      && db_writebatch_put(wb, g.st.meta, HTRIM_META_AGEOUT_RESUME,
                           strlen(HTRIM_META_AGEOUT_RESUME), bt, (size_t)btl) != DB_OK)
    return -1;
  return 0;
}

void htrim_note_stored(const char *owner, const void *bo_key, size_t bo_klen,
                       uint32_t bytes)
{
  const void *bt;
  size_t btl;

  if (!g.inited || !bo_key)
    return;
  acct_apply(owner, bo_key, bo_klen, (int64_t)bytes);
  if (htc_bo_split(bo_key, bo_klen, NULL, 0, &bt, &btl) == 0)
    ageout_note_indexed(bt, btl);
  /* A row of the owner step in progress, behind where its walk resumes:
   * the walk starts again from the owner's first key. */
  if (g.ev_owner[0] && g.ev_bo_len && owner && strcmp(owner, g.ev_owner) == 0
      && key_cmp(bo_key, bo_klen, g.ev_bo, g.ev_bo_len) < 0)
    g.ev_bo_len = 0;
}

int htrim_acct_loaded(void)
{
  return g.acct_loaded;
}

int htrim_backfill_done(void)
{
  return g.bf_done;
}

size_t htrim_backfill_rows(void)
{
  return g.bf_rows;
}

int htrim_check_index_gap(uint64_t newest_row_ms, uint64_t slack_ms)
{
  struct db_writebatch *wb;
  uint64_t limit;
  int was_done;

  if (!g.inited)
    return 0;
  limit = g.alive_ms + slack_ms;
  if (limit < g.alive_ms)
    limit = UINT64_MAX;
  if (newest_row_ms <= limit)
    return 0;
  /* Nothing to reset: the walk never started (a first start, an
   * unstamped store) -- it walks everything from the first key anyway. */
  if (!g.bf_done && !g.bf_cursor_len && !g.bf_unread)
    return 0;

  /* Done or mid-walk: an older binary's rows may sort before the cursor,
   * so the walk restarts from the first key.  Reset in memory whatever the
   * batch below does: this start re-runs either way. */
  was_done = g.bf_done;
  g.bf_done = 0;
  g.bf_unread = 0;
  g.bf_bad_logged = 0;
  bf_cursor_clear();
  log_write(LS_SYSTEM, L_INFO, 0,
            "history: trim index gap: newest row %llu ms is past the last alive "
            "stamp %llu ms + %llu ms; re-running the backfill from the first "
            "row (it was %s)",
            (unsigned long long)newest_row_ms, (unsigned long long)g.alive_ms,
            (unsigned long long)slack_ms, was_done ? "done" : "unfinished");
  if (!g.st.meta)
    return 1;
  wb = db_writebatch_new(g.st.env);
  if (!wb
      || db_writebatch_del(wb, g.st.meta, HTRIM_META_BACKFILL_DONE,
                           strlen(HTRIM_META_BACKFILL_DONE)) != DB_OK
      || db_writebatch_del(wb, g.st.meta, HTRIM_META_BACKFILL_CURSOR,
                           strlen(HTRIM_META_BACKFILL_CURSOR)) != DB_OK
      || db_writebatch_commit(wb, 0) != DB_OK) {
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history_trim: cannot clear the backfill marker and cursor: %s",
              last_err());
    db_writebatch_destroy(wb);
    return -1;
  }
  db_writebatch_destroy(wb);
  return 1;
}

void htrim_stamp_alive(uint64_t now_ms)
{
  struct db_writebatch *wb;
  char buf[24];
  int n;

  if (!g.inited)
    return;
  g.alive_ms = now_ms;
  if (!g.st.meta)
    return;
  n = snprintf(buf, sizeof buf, "%llu", (unsigned long long)now_ms);
  wb = db_writebatch_new(g.st.env);
  if (!wb
      || db_writebatch_put(wb, g.st.meta, HTRIM_META_ALIVE, strlen(HTRIM_META_ALIVE),
                           buf, (size_t)n) != DB_OK
      || db_writebatch_commit(wb, 0) != DB_OK)
    log_write(LS_SYSTEM, L_ERROR, 0,
              "history_trim: cannot stamp alive: %s", last_err());
  db_writebatch_destroy(wb);
}

const struct htc_acct *htrim_acct(void)
{
  return g.acct;
}

/* ------------------------------------------------------------------ */
/* Slices                                                              */
/* ------------------------------------------------------------------ */

static void slice_free(struct htrim_slice *s)
{
  int i;

  if (!s)
    return;
  db_writebatch_destroy(s->wb);
  MyFree(s->keys);
  MyFree(s->pend);
  MyFree(s->touch);
  MyFree(s->ao_cursor);
  MyFree(s->ao_next);
  MyFree(s->ao_store);
  MyFree(s->bf_cursor);
  MyFree(s->bf_min_bt);
  MyFree(s->ev_bo);
  MyFree(s->ev_below_hi);
  MyFree(s->ev_start);
  MyFree(s->ev_bt);
  MyFree(s->ts_cursor);
  MyFree(s->ts_names);
  for (i = 0; i < HH_COUNT; i++)
    hint_free(&s->hint[i]);
  MyFree(s);
}

struct htrim_slice *htrim_slice_begin(unsigned int budget_ms)
{
  struct htrim_slice *s;

  if (!g.inited)
    return NULL;
  s = (struct htrim_slice *)MyCalloc(1, sizeof *s);
  s->wb = db_writebatch_new(g.st.env);
  if (!s->wb) {
    MyFree(s);
    return NULL;
  }
  s->budget_us = (uint64_t)budget_ms * 1000u;
  s->start_us = g.clock();
  return s;
}

/** Rows a slice has staged: deletes, (backfill) index rows, by_owner
 * entries removed alone, and (sweep) targets keys. */
static size_t slice_staged(const struct htrim_slice *s)
{
  return (size_t)s->rows + s->bf_indexed + s->idx_only + s->ts_n;
}

/** Whether @a s is one of the engine's own slices (htrim_run_slice's),
 * not a caller's: the burst-loss prune (INCARNATION), an emergency
 * inside a store (EMERGENCY), a slice without a phase.  Only the
 * engine's slices take the carried emptiness checks and issue
 * compaction hints. */
static int engine_slice(const struct htrim_slice *s)
{
  return s->phase != HTRIM_PH_NONE && s->phase != HTRIM_PH_INCARNATION
         && s->phase != HTRIM_PH_EMERGENCY;
}

/** The entries @a s's cleanup will examine: the carried checks (an
 * engine slice takes them) and its touched targets, at most
 * HTRIM_CLEANUP_CHECKS (the rest carry over unexamined); none for a
 * slice whose cleanup is deferred. */
static size_t cleanup_entries(const struct htrim_slice *s)
{
  size_t n;

  if (s->defer_cleanup)
    return 0;                                   /* no cleanup in this slice */
  n = (engine_slice(s) ? g.ncarry : 0) + s->ntouch;
  return n < HTRIM_CLEANUP_CHECKS ? n : HTRIM_CLEANUP_CHECKS;
}

int htrim_slice_expired(struct htrim_slice *s)
{
  uint64_t ahead;

  if (!s || !g.inited)
    return 1;
  if (!s->budget_us)
    return 0;
  /* What the commit will cost for the rows staged so far, and the
   * cleanup for the targets its commit will examine, is spent from this
   * budget too. */
  ahead = (g.cost_ns[s->phase] * (uint64_t)slice_staged(s)
           + g.clean_ns * (uint64_t)cleanup_entries(s)) / 1000u;
  return elapsed_since(s->start_us, g.clock()) + ahead >= s->budget_us;
}

void htrim_slice_set_phase(struct htrim_slice *s, enum htrim_phase ph)
{
  if (s && (int)ph >= 0 && (int)ph < HTRIM_PH_SLOTS)
    s->phase = ph;
}

void htrim_slice_abort(struct htrim_slice *s)
{
  slice_free(s);
}

static void slice_add_delta(struct htrim_slice *s, const char *bo_key,
                            size_t bo_klen, int64_t delta)
{
  struct htrim_pending *p;

  if (s->keys_len + bo_klen > s->keys_cap) {
    size_t cap = s->keys_cap ? s->keys_cap * 2 : 4096;
    while (cap < s->keys_len + bo_klen)
      cap *= 2;
    s->keys = (char *)MyRealloc(s->keys, cap);
    s->keys_cap = cap;
  }
  if (s->npend == s->cap_pend) {
    s->cap_pend = s->cap_pend ? s->cap_pend * 2 : 64;
    s->pend = (struct htrim_pending *)MyRealloc(s->pend, s->cap_pend * sizeof *s->pend);
  }
  memcpy(s->keys + s->keys_len, bo_key, bo_klen);
  p = &s->pend[s->npend++];
  p->koff = s->keys_len;
  p->klen = bo_klen;
  p->delta = delta;
  s->keys_len += bo_klen;
}

/** Remember @a target as touched, keeping the newest deleted ts.  A long
 * single-target drain stays one entry (the last one is merged in place);
 * commit deduplicates the rest. */
static void slice_touch(struct htrim_slice *s, const char *target, const char *ts)
{
  struct htrim_touch *t;
  size_t tl = strlen(ts);

  if (s->ntouch) {
    t = &s->touch[s->ntouch - 1];
    if (strcmp(t->target, target) == 0) {
      if (history_stamp_newer(ts, tl, t->ts, strlen(t->ts)))
        memcpy(t->ts, ts, tl + 1);
      return;
    }
  }
  if (s->ntouch == s->cap_touch) {
    s->cap_touch = s->cap_touch ? s->cap_touch * 2 : 16;
    s->touch = (struct htrim_touch *)MyRealloc(s->touch, s->cap_touch * sizeof *s->touch);
  }
  t = &s->touch[s->ntouch++];
  memcpy(t->target, target, strlen(target) + 1);
  memcpy(t->ts, ts, tl + 1);
}

static int slice_del(struct htrim_slice *s, struct db_cf *cf,
                     const void *k, size_t kl)
{
  int h;

  if (db_writebatch_del(s->wb, cf, k, kl) != DB_OK) {
    s->broken = 1;
    return -1;
  }
  h = hint_slot(cf);
  if (h >= 0)
    hint_add(&s->hint[h], k, kl, k, kl, 1);
  return 0;
}

/** Stage the deletes of every ml_paste_secrets row that maps to @a msgid:
 * keys in [msgid "-", msgid ".") whose value is exactly @a msgid (the
 * range also holds rows of longer msgids such as "<msgid>-x"). */
static void stage_paste_deletes(struct htrim_slice *s, const char *msgid)
{
  char lo[HTC_MSGID_MAX + 1], hi[HTC_MSGID_MAX + 1];
  size_t ml = strlen(msgid);
  struct db_iter *it;
  int rc;

  if (!g.st.ml_paste || ml + 1 > sizeof lo)
    return;
  memcpy(lo, msgid, ml);
  lo[ml] = '-';
  memcpy(hi, msgid, ml);
  hi[ml] = '.';
  it = db_iter_open_bounded(g.st.env, g.st.ml_paste, NULL, lo, ml + 1, hi, ml + 1);
  /* An unreadable range leaves orphan paste rows behind, which are
   * harmless (the lookup they serve then fails at ml_content): not a
   * reason to keep the message row. */
  if (!it)
    return;
  for (rc = db_iter_seek_first(it); rc == DB_OK; rc = db_iter_next(it)) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    if (vl == ml && memcmp(v, msgid, ml) == 0)
      slice_del(s, g.st.ml_paste, k, kl);
  }
  db_iter_close(it);
}

/** The index-only delete for a row the engine cannot read: its by_time
 * key, and its by_owner key when @a rec names the owner (with the delta
 * when @a counted).  Nothing else -- the engine never guesses at a
 * message row it cannot name.  Counts under @a path so the caller's walk
 * over by_time advances past it. */
static int delete_index_only(struct htrim_slice *s, enum htrim_path path,
                             const void *bt_key, size_t bt_klen,
                             const struct htc_rec *rec, int counted)
{
  char bo[HTC_BO_KEY_MAX];
  int bol = -1;

  slice_del(s, g.st.by_time, bt_key, bt_klen);
  if (rec) {
    bol = htc_bo_key(bo, sizeof bo, rec->owner, bt_key, bt_klen);
    if (bol > 0)
      slice_del(s, g.st.by_owner, bo, (size_t)bol);
  }
  if (s->broken)
    return -2;
  if (counted && rec && bol > 0 && rec->bytes)
    slice_add_delta(s, bo, (size_t)bol, -(int64_t)rec->bytes);
  s->counts[path]++;
  s->rows++;
  return 0;
}

int htrim_delete_row(struct htrim_slice *s, enum htrim_path path,
                     const void *bt_key, size_t bt_klen,
                     const struct htc_rec *rec, int counted)
{
  uint64_t ms;
  char target[HTC_TARGET_MAX], msgid[HTC_MSGID_MAX];
  char mk[HTC_MSG_KEY_MAX];
  char ik[HTRIM_MSGID_KEY_MAX];
  char rk1[HTRIM_REPLY_KEY_MAX], rk2[HTRIM_REPLY_KEY_MAX];
  char bo[HTC_BO_KEY_MAX];
  unsigned char xk[RDX_KEY_MAX];
  int mkl, ikl = -1, rk1l = -1, rk2l = -1, xkl = -1, bol;

  if (!s || !g.inited || !bt_key || !bt_klen
      || (int)path < 0 || path >= HTRIM_PATH_COUNT)
    return -1;
  if (s->broken)
    return -2;
  if (!rec || !rec->ts[0]
      || htc_bt_key_parse(bt_key, bt_klen, &ms, target, sizeof target,
                          msgid, sizeof msgid) != 0 || !target[0])
    return delete_index_only(s, path, bt_key, bt_klen, rec, counted);

  /* Build every key first: a key that does not fit is a row the engine
   * cannot name, and gets the index-only delete. */
  mkl = htc_msg_key(mk, sizeof mk, target, rec->ts, msgid);
  if (mkl < 0)
    return delete_index_only(s, path, bt_key, bt_klen, rec, counted);
  if (msgid[0]) {
    ikl = htc_msgid_key(ik, sizeof ik, msgid, target);
    if (ikl < 0)
      return delete_index_only(s, path, bt_key, bt_klen, rec, counted);
    if ((rec->flags & HTC_F_REDACT) && g.st.redact) {
      xkl = rdx_key_build(xk, sizeof xk, ms, msgid);
      if (xkl < 0)
        return delete_index_only(s, path, bt_key, bt_klen, rec, counted);
    }
  }
  if (rec->reply_parent[0]) {
    rk1l = htc_reply_child_key(rk1, sizeof rk1, target, rec->reply_parent,
                               rec->ts, msgid);
    if (rk1l < 0)
      return delete_index_only(s, path, bt_key, bt_klen, rec, counted);
  }
  if (rec->redact_parent[0]) {
    rk2l = htc_reply_child_key(rk2, sizeof rk2, target, rec->redact_parent,
                               rec->ts, msgid);
    if (rk2l < 0)
      return delete_index_only(s, path, bt_key, bt_klen, rec, counted);
  }
  bol = htc_bo_key(bo, sizeof bo, rec->owner, bt_key, bt_klen);
  if (bol < 0)
    return delete_index_only(s, path, bt_key, bt_klen, rec, counted);

  slice_del(s, g.st.messages, mk, (size_t)mkl);
  if (msgid[0]) {
    slice_del(s, g.st.msgid, ik, (size_t)ikl);
    slice_del(s, g.st.msgid, msgid, strlen(msgid));   /* legacy bare-msgid row */
    if (rec->flags & HTC_F_ML) {
      if (g.st.ml_content)
        slice_del(s, g.st.ml_content, msgid, strlen(msgid));
      stage_paste_deletes(s, msgid);
    }
    if (xkl > 0)
      slice_del(s, g.st.redact, xk, (size_t)xkl);
  }
  if (rk1l > 0)
    slice_del(s, g.st.reply, rk1, (size_t)rk1l);
  if (rk2l > 0)
    slice_del(s, g.st.reply, rk2, (size_t)rk2l);
  slice_del(s, g.st.by_time, bt_key, bt_klen);
  slice_del(s, g.st.by_owner, bo, (size_t)bol);
  if (s->broken)
    return -2;

  if (counted && rec->bytes)
    slice_add_delta(s, bo, (size_t)bol, -(int64_t)rec->bytes);
  slice_touch(s, target, rec->ts);
  s->counts[path]++;
  s->rows++;
  return 0;
}

static int btkey_cmp(const void *a, const void *b)
{
  const struct htrim_btkey *x = (const struct htrim_btkey *)a;
  const struct htrim_btkey *y = (const struct htrim_btkey *)b;
  return key_cmp(x->k, x->len, y->k, y->len);
}

static int touch_cmp(const void *a, const void *b)
{
  return strcmp(((const struct htrim_touch *)a)->target,
                ((const struct htrim_touch *)b)->target);
}

/** Whether the messages CF holds a row of the target whose targets key is
 * @a name (@a nlen bytes, folded): the LAST key of [name 0x00, name 0x01),
 * never the first -- a drain deletes from the head, so a seek from the
 * head walks every tombstone it left so far; the tail is live.  RocksDB's
 * SeekToLast honours iterate_upper_bound (9.10 options.h: "SeekToLast()
 * will position the iterator at the first key smaller than
 * iterate_upper_bound") and the lower bound ends the backward walk
 * (pinned on both backends by db_api_cmocka's test_bounded_iter_seek_last).
 * A name too long for a stored target reads as live (it is left alone).
 * @return 1 rows, 0 none, -1 the check failed. */
static int target_has_rows(const void *name, size_t nlen)
{
  char lo[HTC_TARGET_MAX + 1], hi[HTC_TARGET_MAX + 1];
  struct db_iter *it;
  int rc;

  if (!nlen || nlen + 1 > sizeof lo)
    return 1;
  memcpy(lo, name, nlen);
  lo[nlen] = '\0';
  memcpy(hi, name, nlen);
  hi[nlen] = '\x01';
  it = db_iter_open_bounded_limited(g.st.env, g.st.messages, NULL, lo, nlen + 1,
                                    hi, nlen + 1, HTRIM_EMPTY_SKIP_MAX);
  if (!it)
    return -1;
  rc = db_iter_seek_last(it);
  db_iter_close(it);
  if (rc == DB_NOTFOUND)
    return 0;
  if (rc == DB_INCOMPLETE)
    return 2;
  return rc == DB_OK ? 1 : -1;
}

/** A target whose emptiness check was undecided (a tombstone run past
 * HTRIM_EMPTY_SKIP_MAX): its range [name 0x00, name 0x01) is due a
 * compaction hint (the messages memtable flushed first), and a later
 * sweep (at the next pass start) checks it again.  Its key stays; nothing
 * is reported.  A target whose range the undecided set already covers
 * (undecided again before the hint went out) is not added twice. */
static void target_undecided(const void *name, size_t nlen)
{
  char lo[HTC_TARGET_MAX + 1], hi[HTC_TARGET_MAX + 1];
  size_t k;

  g.ts_later = 1;
  if (!nlen || nlen + 1 > sizeof lo)
    return;
  memcpy(lo, name, nlen);
  lo[nlen] = '\0';
  memcpy(hi, name, nlen);
  hi[nlen] = '\x01';
  for (k = 0; k < g.nund; k++)
    if (key_cmp(lo, nlen + 1, g.und[k].lo, g.und[k].lol) >= 0
        && key_cmp(hi, nlen + 1, g.und[k].hi, g.und[k].hil) <= 0)
      return;                                   /* in the set already */
  /* A due hint (one an engine slice, never in a caller's): the flush
   * stays out of the cleanup and its cost.  Each target's range apart --
   * one wide range over unrelated targets would mark most of the CF -- up
   * to HTRIM_UND_MAX; past that the last range widens to take it. */
  if (g.nund < HTRIM_UND_MAX) {
    memcpy(g.und[g.nund].lo, lo, nlen + 1);
    g.und[g.nund].lol = nlen + 1;
    memcpy(g.und[g.nund].hi, hi, nlen + 1);
    g.und[g.nund].hil = nlen + 1;
    g.nund++;
  } else {
    size_t last = g.nund - 1;
    if (key_cmp(lo, nlen + 1, g.und[last].lo, g.und[last].lol) < 0) {
      memcpy(g.und[last].lo, lo, nlen + 1);
      g.und[last].lol = nlen + 1;
    }
    if (key_cmp(hi, nlen + 1, g.und[last].hi, g.und[last].hil) > 0) {
      memcpy(g.und[last].hi, hi, nlen + 1);
      g.und[last].hil = nlen + 1;
    }
  }
  g.und_targets++;
  g.hint_due[HH_UNDECIDED] = 1;
}

/** Whether @a target (folded) is now empty and its targets key should go.
 * @return 1 empty, 0 not (or no targets key), -1 the check failed,
 *         2 undecided (a tombstone run past HTRIM_EMPTY_SKIP_MAX).
 *
 * Skips without touching the messages CF when the targets stamp is newer
 * than the newest row deleted from it (a newer message row exists).
 * Otherwise it seeks the target's live tail (target_has_rows): the stamp
 * counts message rows only, so a target whose newest rows are
 * JOIN/PART/QUIT/... comes here on every slice of its drain.  A truly
 * empty target pays one walk over its tombstones, once. */
static int target_emptied(const char *target, const char *newest,
                          char *tkey, size_t tsize, size_t *tklen, int *seeked)
{
  struct db_val cur = { NULL, 0 };
  int kl, newer, rc;

  *seeked = 0;
  kl = htc_msg_key(tkey, tsize, target, NULL, NULL);   /* fold(t) \0 */
  if (kl < 2)
    return 0;
  *tklen = (size_t)kl - 1;                              /* targets key: fold(t) */
  rc = db_get(g.st.env, g.st.targets, tkey, *tklen, NULL, &cur);
  if (rc == DB_NOTFOUND)
    return 0;
  if (rc != DB_OK)
    return -1;
  newer = cur.base && history_stamp_newer((const char *)cur.base, cur.len,
                                          newest, strlen(newest));
  db_val_free(&cur);
  if (newer)
    return 0;

  *seeked = 1;
  rc = target_has_rows(tkey, *tklen);
  if (rc == 2)
    return 2;                                   /* undecided */
  return rc < 0 ? -1 : !rc;
}

/** Arm a targets sweep pass (it runs once the accounting is loaded). */
static void tsweep_arm(void)
{
  g.ts_armed = 1;
}

/** A cleanup that could not finish: its targets keys may outlive their
 * rows until the targets sweep runs. */
static void tsweep_want(const char *what, const char *target)
{
  g.tsweep_wanted = 1;
  log_write(LS_SYSTEM, L_ERROR, 0, "history_trim: targets cleanup: %s%s%s: %s",
            what, target ? " " : "", target ? target : "", last_err());
}

/** Keep @a t for the next slice's cleanup. */
static void carry_push(const struct htrim_touch *t)
{
  if (g.ncarry == g.cap_carry) {
    g.cap_carry = g.cap_carry ? g.cap_carry * 2 : 32;
    g.carry = (struct htrim_touch *)MyRealloc(g.carry, g.cap_carry * sizeof *g.carry);
  }
  g.carry[g.ncarry++] = *t;
}

/** Work-list order for deduplication: by target, then by position (the
 * entry's address in the list), so a group's first entry is its oldest. */
static int cand_cmp(const void *a, const void *b)
{
  const struct htrim_touch *x = *(const struct htrim_touch *const *)a;
  const struct htrim_touch *y = *(const struct htrim_touch *const *)b;
  int c = strcmp(x->target, y->target);
  if (c)
    return c;
  return (x > y) - (x < y);
}

/** After a committed slice: drop the targets key of every touched target
 * left without rows (one second batch), then tell the emptied callback.
 * Runs on the main loop (never from htrim_init), so it may log.
 *
 * The work list is the carried targets (oldest first) and then this
 * slice's, by name; each target once, with the newest deleted ts of all
 * its entries.  A budgeted slice does at most HTRIM_CLEANUP_CHECKS
 * emptiness seeks (a target its stamp clears costs one get, no seek);
 * the targets after that carry over, still in order, so every touched
 * target is checked within a few slices -- exactly, since a row stored
 * in between makes it non-empty and the check finds it.  Only the
 * engine's own slices take the carried targets: a caller's slice (the
 * burst-loss prune, inside BURST) checks its own touched targets, all of
 * them, and leaves the carried ones to the engine -- they are not its
 * work, and could be many; an emergency (inside a store) checks none,
 * its touched targets joining the carry (htrim_slice_commit). */
static size_t cleanup_touched(struct htrim_slice *s, unsigned int *nseeks)
{
  struct db_writebatch *wb = NULL;
  struct htrim_touch *w, **byname;
  unsigned char *dead;
  const char **names;
  size_t nw, i, j, n = 0, seeks = 0, examined = 0, undecided = 0;
  size_t limit = s->budget_us ? HTRIM_CLEANUP_CHECKS : (size_t)-1;
  size_t ncarry = engine_slice(s) ? g.ncarry : 0;
  int stop = 0;

  *nseeks = 0;
  nw = ncarry + s->ntouch;
  if (!nw)
    return 0;
  if (s->ntouch)
    qsort(s->touch, s->ntouch, sizeof *s->touch, touch_cmp);
  w = (struct htrim_touch *)MyMalloc(nw * sizeof *w);
  if (ncarry)
    memcpy(w, g.carry, ncarry * sizeof *w);
  if (s->ntouch)
    memcpy(w + ncarry, s->touch, s->ntouch * sizeof *w);
  if (ncarry)
    g.ncarry = 0;                               /* refilled below */

  byname = (struct htrim_touch **)MyMalloc(nw * sizeof *byname);
  dead = (unsigned char *)MyCalloc(nw, 1);
  for (i = 0; i < nw; i++)
    byname[i] = &w[i];
  qsort(byname, nw, sizeof *byname, cand_cmp);
  for (i = 0; i < nw; i = j) {
    struct htrim_touch *lead = byname[i];
    for (j = i + 1; j < nw && strcmp(byname[j]->target, lead->target) == 0; j++) {
      if (history_stamp_newer(byname[j]->ts, strlen(byname[j]->ts),
                              lead->ts, strlen(lead->ts)))
        memcpy(lead->ts, byname[j]->ts, sizeof lead->ts);
      dead[byname[j] - w] = 1;
    }
  }
  MyFree(byname);

  names = (const char **)MyMalloc(nw * sizeof *names);
  for (i = 0; i < nw; i++) {
    struct htrim_touch *t = &w[i];
    char tkey[HTC_MSG_KEY_MAX];
    size_t tklen = 0;
    int rc, seeked;

    if (dead[i])
      continue;
    if (stop || seeks >= limit) {
      carry_push(t);
      continue;
    }
    rc = target_emptied(t->target, t->ts, tkey, sizeof tkey, &tklen, &seeked);
    seeks += (size_t)seeked;
    examined++;
    if (rc < 0)
      tsweep_want("emptiness check failed for", t->target);
    if (rc == 2) {                              /* undecided: a later sweep */
      target_undecided(tkey, tklen);
      undecided++;
      continue;
    }
    if (rc <= 0)
      continue;
    if (!wb && !(wb = db_writebatch_new(g.st.env))) {
      tsweep_want("no batch", NULL);
      stop = 1;                                 /* the rest wait a slice */
      carry_push(t);
      continue;
    }
    if (db_writebatch_del(wb, g.st.targets, tkey, tklen) == DB_OK)
      names[n++] = t->target;
    else
      tsweep_want("cannot stage the delete of", t->target);
  }

  if (wb) {
    if (n) {
      if (db_writebatch_commit(wb, 0) == DB_OK) {
        if (g.emptied)
          g.emptied(names, (int)n);
      } else {
        tsweep_want("commit failed", NULL);
      }
    }
    db_writebatch_destroy(wb);
  }
  MyFree(names);
  MyFree(dead);
  MyFree(w);
  if (undecided)
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: trim: %zu emptied target%s undecided (more than %d "
              "tombstones in the way); hinted for compaction, checked again "
              "by the next sweep", undecided, undecided == 1 ? "" : "s",
              HTRIM_EMPTY_SKIP_MAX);
  *nseeks = (unsigned int)seeks;
  return examined;
}

/** A committed backfill step: move the in-memory cursor to the one the
 * batch stored, or finish. */
static void backfill_apply(struct htrim_slice *s)
{
  unsigned int i;

  /* Only the smallest key is noted: one row behind the frontier is kept
   * by key, but more than one would leave the others unwalked (the pass
   * deletes the noted one by key and resumes at the frontier) -- the next
   * pass rewinds to the smallest instead, walking them all. */
  ageout_note_indexed(s->bf_min_bt, s->bf_min_bt_len);
  if (s->bf_behind > 1)
    g.late_over = 1;
  g.bf_rows += s->bf_rows;
  g.bf_indexed += s->bf_indexed;
  g.bf_aged += s->bf_aged;
  g.bf_unindexed += s->bf_unindexed;
  for (i = 0; i < s->bf_nbad; i++)
    log_write(LS_SYSTEM, L_WARNING, 0,
              "history: trim backfill: messages key '%s' (%zu bytes) cannot be "
              "indexed; the trimmer never removes it", s->bf_bad[i],
              s->bf_bad_klen[i]);
  g.bf_bad_logged += s->bf_nbad;
  if (s->bf_finished) {
    g.bf_done = 1;
    bf_cursor_clear();
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: trim backfill complete: %zu rows indexed, %zu aged out",
              g.bf_indexed, g.bf_aged);
    if (g.bf_unindexed)
      log_write(LS_SYSTEM, L_WARNING, 0,
                "history: trim backfill: %zu rows have a key the trim index "
                "cannot hold; the trimmer never removes them (the first %u "
                "are named above)", g.bf_unindexed, g.bf_bad_logged);
  } else if (s->bf_cursor_len) {
    bytes_set(&g.bf_cursor, &g.bf_cursor_len, &g.bf_cursor_cap,
              s->bf_cursor, s->bf_cursor_len);
  }
}

/** Where a committed age-out step leaves the walk (s->ao_next): the
 * successor of the last key it deleted (that key ‖ 0x00); a walk that
 * reached the cutoff resumes at the cutoff bound itself -- every key below
 * it is gone, so no later pass walks their tombstones again, not even a
 * pass that finds nothing to delete -- unless the resume point is past it
 * already (a retention rise never moves it back).  The same bytes go in
 * the slice's batch as HTRIM_META_AGEOUT_RESUME, unless a late row is
 * pending: the stored point already covers it, and must keep doing so
 * until the pass start that sends the walk back to it. */
static int ageout_next(struct htrim_slice *s)
{
  const char *st;
  size_t stl, i;

  if (s->ao_finished && s->ao_bounded) {
    if (!g.ao_lower_len
        || key_cmp(s->ao_upper, sizeof s->ao_upper, g.ao_lower, g.ao_lower_len) > 0)
      bytes_set(&s->ao_next, &s->ao_next_len, &s->ao_next_cap,
                s->ao_upper, sizeof s->ao_upper);
  } else if (s->ao_cursor_len) {
    size_t n = s->ao_cursor_len + 1;
    if (n > s->ao_next_cap) {
      s->ao_next_cap = n;
      s->ao_next = (char *)MyRealloc(s->ao_next, n);
    }
    memcpy(s->ao_next, s->ao_cursor, s->ao_cursor_len);
    s->ao_next[s->ao_cursor_len] = '\0';
    s->ao_next_len = n;
  }

  /* What the batch stores: the frontier, or an older late row still to
   * go (due and not taken by this slice, or noted since the pass start). */
  st = s->ao_next_len ? s->ao_next : g.ao_lower;
  stl = s->ao_next_len ? s->ao_next_len : g.ao_lower_len;
  if (!stl || !g.st.meta)
    return 0;                                   /* the first key: nothing to store */
  for (i = 0; i < g.ndue; i++)
    if (!s->due_done[i] && key_cmp(g.due[i].k, g.due[i].len, st, stl) < 0) {
      st = g.due[i].k;
      stl = g.due[i].len;
    }
  if (g.ao_late_len && key_cmp(g.ao_late, g.ao_late_len, st, stl) < 0) {
    st = g.ao_late;
    stl = g.ao_late_len;
  }
  if (stl == g.ao_saved_len && memcmp(st, g.ao_saved, stl) == 0)
    return 0;                                   /* stored already */
  bytes_set(&s->ao_store, &s->ao_store_len, &s->ao_store_cap, st, stl);
  if (db_writebatch_put(s->wb, g.st.meta, HTRIM_META_AGEOUT_RESUME,
                        strlen(HTRIM_META_AGEOUT_RESUME),
                        s->ao_store, s->ao_store_len) != DB_OK) {
    s->broken = 1;
    return -1;
  }
  s->ao_saved_put = 1;
  return 0;
}

/** A committed age-out step: the walk resumes where ageout_next said,
 * the next start where the batch stored, and the due late rows it took
 * are gone from the list. */
static void ageout_apply(struct htrim_slice *s)
{
  size_t i, o = 0;

  if (s->ao_next_len)
    bytes_set(&g.ao_lower, &g.ao_lower_len, &g.ao_lower_cap,
              s->ao_next, s->ao_next_len);
  if (s->ao_saved_put)
    bytes_set(&g.ao_saved, &g.ao_saved_len, &g.ao_saved_cap,
              s->ao_store, s->ao_store_len);
  for (i = 0; i < g.ndue; i++)
    if (!s->due_done[i])
      g.due[o++] = g.due[i];
  g.ndue = o;
  if (s->ao_finished)
    g.ao_pending = 0;
}

static void evict_apply(struct htrim_slice *s);
static void tsweep_apply(struct htrim_slice *s);
static void emergency_apply(struct htrim_slice *s);

/** A committed slice's deletes widen the engine's hint ranges; a CF that
 * lost compact_min_rows keys since its last hint is hinted now. */
static void hints_apply(struct htrim_slice *s)
{
  int i;

  for (i = 0; i < HH_COUNT; i++)
    hint_add(&g.hint[i], s->hint[i].lo, s->hint[i].lo_len,
             s->hint[i].hi, s->hint[i].hi_len, s->hint[i].n);
}

static void hints_due(void)
{
  int i;

  if (!g.compact_min_rows)
    return;
  for (i = 0; i < HH_COUNT; i++)
    if (hint_time_ordered(i) && g.hint[i].n >= g.compact_min_rows) {
      /* After a failed or dropped hint: compact_min_rows more keys, or
       * HTRIM_HINT_DEFER_MAX slices. */
      if (g.hint_backoff[i] && g.hint[i].n < g.hint_rearm[i]) {
        g.hint_backoff[i]--;
        continue;
      }
      g.hint_due[i] = 1;
    }
}

/** Fold @a us spent over @a n units (staged rows, examined cleanup
 * entries) into the EWMA *@a c, in ns per unit. */
static void cost_learn(uint64_t *c, uint64_t us, size_t n)
{
  uint64_t sample = us * 1000u / (uint64_t)n;

  if (!*c)
    *c = sample;
  else if (sample >= *c)
    *c += (sample - *c) / 4;
  else
    *c -= (*c - sample) / 4;
}

int htrim_slice_commit(struct htrim_slice *s)
{
  uint64_t t0 = 0, t1 = 0, now;
  size_t staged, examined;
  unsigned int seeks;
  int rows, measure;
  size_t i;

  if (!s)
    return -1;
  if (!g.inited) {
    slice_free(s);
    return -1;
  }
  /* A budgeted slice of a phase that has a commit or a cleanup to pay for
   * measures both (two more clock reads), for the next slices' budget
   * checks and the slice breakdown. */
  staged = slice_staged(s);
  measure = s->budget_us && s->phase != HTRIM_PH_NONE
            && (staged > 0 || cleanup_entries(s) > 0);
  if (measure)
    t0 = g.clock();
  if (s->broken
      || (db_writebatch_count(s->wb) > 0
          && db_writebatch_commit(s->wb, /*sync_durably=*/0) != DB_OK)) {
    g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
    last_unmeasured(s->ts_checks);
    if (s->phase != HTRIM_PH_NONE)
      record_slice(s->phase);
    slice_free(s);
    return -1;
  }

  for (i = 0; i < s->npend; i++) {
    const char *k = s->keys + s->pend[i].koff;
    acct_apply(k, k, s->pend[i].klen, s->pend[i].delta);   /* owner = key prefix */
  }
  for (i = 0; i < HTRIM_PATH_COUNT; i++)
    g.stats.deleted[i] += s->counts[i];
  hints_apply(s);           /* before a drain's end hints everything */
  if (s->ao_step)
    ageout_apply(s);
  if (s->bf_step)
    backfill_apply(s);
  if (s->ev_step)
    evict_apply(s);
  if (s->ts_step)
    tsweep_apply(s);
  if (s->em_step)
    emergency_apply(s);
  hints_due();
  if (measure)
    t1 = g.clock();
  if (s->defer_cleanup) {
    /* Inside a caller that must not report (a store): every target this
     * slice touched waits for the next engine slice's cleanup. */
    for (i = 0; i < s->ntouch; i++)
      carry_push(&s->touch[i]);
    examined = 0;
    seeks = 0;
  } else
    examined = cleanup_touched(s, &seeks);

  now = g.clock();
  /* At most one compaction hint a slice, from the engine's own slices
   * only (never inside a caller's: the burst-loss prune, an emergency
   * inside a store); timed apart, and kept out of the cost EWMAs (a hint
   * is a one-off). */
  g.last_hint_us = 0;
  if (engine_slice(s) && hint_issue_one()) {
    uint64_t h = g.clock();
    g.last_hint_us = elapsed_since(now, h);
    g.last_elapsed_us = elapsed_since(s->start_us, h);
  } else
    g.last_elapsed_us = elapsed_since(s->start_us, now);
  if (measure) {
    if (staged)
      cost_learn(&g.cost_ns[s->phase], elapsed_since(t0, t1), staged);
    if (examined)
      cost_learn(&g.clean_ns, elapsed_since(t1, now), examined);
    g.last_walk_us = elapsed_since(s->start_us, t0);
    g.last_commit_us = elapsed_since(t0, t1);
    g.last_cleanup_us = elapsed_since(t1, now);
    g.last_seeks = seeks + s->ts_checks;
  } else {
    uint64_t hint_us = g.last_hint_us;
    last_unmeasured(seeks + s->ts_checks);
    g.last_walk_us -= hint_us;
    g.last_hint_us = hint_us;
  }
  if (s->phase != HTRIM_PH_NONE)
    record_slice(s->phase);
  rows = s->rows;
  slice_free(s);
  return rows;
}

/* ------------------------------------------------------------------ */
/* Phases                                                              */
/* ------------------------------------------------------------------ */

/** The retention cutoff under @a p: rows strictly older (ms < cutoff) are
 * past retention; 0 = no retention. */
static uint64_t retention_cutoff_ms(const struct htrim_params *p)
{
  uint64_t span;

  if (p->retention_days <= 0)
    return 0;
  span = (uint64_t)p->retention_days * 86400ULL * 1000ULL;
  return p->now_ms > span ? p->now_ms - span : 0;
}

/** The ms a by_time key starts with (0 for a key too short to hold one). */
static uint64_t bt_key_ms(const void *k, size_t kl)
{
  const unsigned char *b = (const unsigned char *)k;
  uint64_t ms = 0;
  size_t i;

  if (kl < 8)
    return 0;
  for (i = 0; i < 8; i++)
    ms = (ms << 8) | b[i];
  return ms;
}

/** Age-out: walk by_time over [ao_lower (or the first key), be64(cutoff))
 * -- every row past retention, oldest first -- and THE delete each one,
 * counted (every by_time row was counted when it was indexed), until the
 * budget is spent.  A record that does not parse still leaves the index
 * (htrim_delete_row's index-only form), so the walk never sticks on a bad
 * head row.  The resume point moves only when this slice commits; a walk
 * that reaches the bound closes the pass. */
static int phase_ageout(struct htrim_slice *s, const struct htrim_params *p)
{
  unsigned char upper[8];
  struct db_iter *it;
  uint64_t cutoff = retention_cutoff_ms(p);
  size_t i;
  int rc, first = 1;

  s->ao_step = 1;
  if (!cutoff) {                                /* retention went to 0 */
    s->ao_finished = 1;
    return 0;
  }
  htc_be64(upper, cutoff);
  memcpy(s->ao_upper, upper, sizeof upper);
  s->ao_bounded = 1;

  /* The late rows due this pass go first, each by key; the walk then
   * resumes at its frontier, never crossing the deleted run between them
   * and it.  A due row still inside retention (retention went up) waits
   * for a later pass. */
  for (i = 0; i < g.ndue; i++) {
    struct db_val dv = { NULL, 0 };
    struct htc_rec rec;
    int grc, parsed = 0;

    if (bt_key_ms(g.due[i].k, g.due[i].len) >= cutoff)
      continue;
    grc = db_get(g.st.env, g.st.by_time, g.due[i].k, g.due[i].len, NULL, &dv);
    if (grc != DB_OK && grc != DB_NOTFOUND)
      return -1;
    if (grc == DB_OK) {
      parsed = htc_rec_parse(dv.base, dv.len, &rec) == 0;
      db_val_free(&dv);
      if (htrim_delete_row(s, HTRIM_PATH_AGEOUT, g.due[i].k, g.due[i].len,
                           parsed ? &rec : NULL, 1) != 0)
        return -1;
    }
    s->due_done[i] = 1;                         /* gone either way */
    if (htrim_slice_expired(s))
      return ageout_next(s);                    /* the walk next slice */
  }

  /* The iterator copies its bounds: a walk that later moves ao_lower
   * cannot pull them from under it. */
  it = db_iter_open_bounded(g.st.env, g.st.by_time, NULL,
                            g.ao_lower_len ? g.ao_lower : NULL, g.ao_lower_len,
                            upper, sizeof upper);
  if (!it)
    return -1;

  rc = db_iter_seek_first(it);
  while (rc == DB_OK) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    struct htc_rec rec;
    int parsed;

    if (first) {
      g.stats.oldest_seen_ms = bt_key_ms(k, kl);
      first = 0;
    }
    parsed = v && htc_rec_parse(v, vl, &rec) == 0;
    if (htrim_delete_row(s, HTRIM_PATH_AGEOUT, k, kl, parsed ? &rec : NULL, 1) != 0) {
      db_iter_close(it);
      return -1;                                /* poisoned: abort the slice */
    }
    bytes_set(&s->ao_cursor, &s->ao_cursor_len, &s->ao_cursor_cap, k, kl);
    rc = db_iter_next(it);
    if (rc == DB_OK && htrim_slice_expired(s))
      break;
  }
  db_iter_close(it);
  if (rc != DB_OK && rc != DB_NOTFOUND)
    return -1;
  if (first)
    g.stats.oldest_seen_ms = 0;                 /* nothing past the cutoff */
  if (rc == DB_NOTFOUND)
    s->ao_finished = 1;
  return ageout_next(s);
}

/** The boot accounting scan: walk by_owner from the successor of the
 * cursor, add each entry's size, stop when the budget is spent; an
 * exhausted iterator completes the totals. */
static int phase_acctscan(struct htrim_slice *s)
{
  struct db_iter *it;
  char *lower = NULL;
  size_t llen = 0;
  int rc;

  if (g.scan_started) {
    llen = g.cursor_len + 1;
    lower = (char *)MyMalloc(llen);
    memcpy(lower, g.cursor, g.cursor_len);
    lower[g.cursor_len] = '\0';                 /* cursor ‖ 0x00 */
  }
  it = db_iter_open_bounded(g.st.env, g.st.by_owner, NULL, lower, llen, NULL, 0);
  MyFree(lower);                                /* the iterator owns its copy */
  if (!it)
    return -1;

  rc = db_iter_seek_first(it);
  while (rc == DB_OK) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    char owner[HTC_OWNER_MAX];
    uint32_t bytes;

    if (htc_bo_split(k, kl, owner, sizeof owner, NULL, NULL) == 0
        && htc_size_parse(v, vl, &bytes) == 0 && bytes)
      htc_acct_add(g.acct, owner, (int64_t)bytes);
    cursor_set(k, kl);
    rc = db_iter_next(it);
    if (rc == DB_OK && htrim_slice_expired(s)) {
      db_iter_close(it);
      return 0;
    }
  }
  db_iter_close(it);
  if (rc != DB_NOTFOUND)
    return -1;                                  /* the cursor keeps what was read */

  g.acct_loaded = 1;
  MyFree(g.cursor);
  g.cursor_len = g.cursor_cap = 0;
  return 0;
}

/** A messages key the backfill cannot index: counted, and among the
 * walk's first HTRIM_BF_LOG_KEYS named in the log once the slice commits
 * (a failed commit walks the row again, so it is not named twice). */
static void bf_unindexable(struct htrim_slice *s, const void *k, size_t kl)
{
  s->bf_unindexed++;
  if (g.bf_bad_logged + s->bf_nbad >= HTRIM_BF_LOG_KEYS)
    return;
  key_preview(s->bf_bad[s->bf_nbad], sizeof s->bf_bad[0], k, kl);
  s->bf_bad_klen[s->bf_nbad] = kl;
  s->bf_nbad++;
}

/** One messages row of the backfill walk (key @a k, value @a v).
 * @return 0 (indexed, aged out, skipped or left as unindexable), or -1:
 * a read failed or the slice is poisoned -- abort the slice. */
static int backfill_row(struct htrim_slice *s, const void *k, size_t kl,
                        const void *v, size_t vl, uint64_t cutoff_ms)
{
  char target[HTC_TARGET_MAX], ts[HTC_TS_MAX], msgid[HTC_MSGID_MAX];
  char mk[HTC_MSG_KEY_MAX], bt[HTC_BT_KEY_MAX], bo[HTC_BO_KEY_MAX];
  struct htrim_row_info info;
  struct htc_rec rec;
  size_t ml = 0, bol = 0;
  uint64_t ms;
  int mkl, btl, rc;

  /* A key the engine cannot rebuild byte for byte is one THE delete could
   * never remove: index it and age-out would drop its index rows while
   * the message row stayed.  Left alone and counted. */
  if (htc_msg_key_parse(k, kl, target, sizeof target, ts, sizeof ts,
                        msgid, sizeof msgid) != 0 || !target[0] || !ts[0]
      || (mkl = htc_msg_key(mk, sizeof mk, target, ts, msgid)) < 0
      || (size_t)mkl != kl || memcmp(mk, k, kl) != 0) {
    bf_unindexable(s, k, kl);
    return 0;
  }
  ms = htc_parse_ms(ts);
  btl = htc_bt_key(bt, sizeof bt, ms, target, msgid);
  if (btl < 0) {
    bf_unindexable(s, k, kl);
    return 0;
  }

  /* Indexed (and counted) at store time: age-out owns it. */
  rc = db_exists(g.st.env, g.st.by_time, bt, (size_t)btl, NULL);
  if (rc == DB_OK)
    return 0;
  if (rc != DB_NOTFOUND)
    return -1;

  memset(&info, 0, sizeof info);
  if (!g.parse || g.parse(v, vl, &info) != 0)
    memset(&info, 0, sizeof info);
  info.account[sizeof info.account - 1] = '\0';
  info.reply_parent[sizeof info.reply_parent - 1] = '\0';
  info.redact_parent[sizeof info.redact_parent - 1] = '\0';

  memset(&rec, 0, sizeof rec);
  rec.flags = info.flags & (HTC_F_REDACT | HTC_F_ML);
  memcpy(rec.ts, ts, strlen(ts) + 1);
  if (htc_owner_key(rec.owner, sizeof rec.owner, info.account, NULL, NULL) < 0)
    memcpy(rec.owner, HTC_OWNER_NONE, sizeof HTC_OWNER_NONE);
  memcpy(rec.reply_parent, info.reply_parent, strlen(info.reply_parent) + 1);
  memcpy(rec.redact_parent, info.redact_parent, strlen(info.redact_parent) + 1);

  /* Past retention and never counted: THE delete, uncounted. */
  if (cutoff_ms && ms < cutoff_ms) {
    if (htrim_delete_row(s, HTRIM_PATH_BACKFILL, bt, (size_t)btl, &rec, 0) != 0)
      return -1;
    s->bf_aged++;
    return 0;
  }

  if ((rec.flags & HTC_F_ML) && g.st.ml_content && msgid[0]) {
    struct db_val mv = { NULL, 0 };
    rc = db_get(g.st.env, g.st.ml_content, msgid, strlen(msgid), NULL, &mv);
    if (rc == DB_OK)
      ml = mv.len;
    else if (rc != DB_NOTFOUND)
      return -1;
    db_val_free(&mv);
  }
  rec.bytes = htc_row_bytes(kl, vl, ml, (size_t)btl, strlen(rec.owner));
  rc = stage_index(s->wb, bt, (size_t)btl, &rec, bo, sizeof bo, &bol);
  if (rc == -1) {
    bf_unindexable(s, k, kl);
    return 0;
  }
  if (rc < 0) {
    s->broken = 1;
    return -1;
  }
  if (rec.bytes)
    slice_add_delta(s, bo, bol, (int64_t)rec.bytes);
  if (g.ao_lower_len && key_cmp(bt, (size_t)btl, g.ao_lower, g.ao_lower_len) < 0)
    s->bf_behind++;
  if (!s->bf_min_bt_len
      || key_cmp(bt, (size_t)btl, s->bf_min_bt, s->bf_min_bt_len) < 0)
    bytes_set(&s->bf_min_bt, &s->bf_min_bt_len, &s->bf_min_bt_cap, bt, (size_t)btl);
  s->bf_indexed++;
  return 0;
}

/** The backfill: walk messages from the successor of the cursor, index
 * (or age out) every row the store path did not index, stop when the
 * budget is spent.  The cursor (or, at the end, the done marker) goes in
 * this slice's batch. */
static int phase_backfill(struct htrim_slice *s, const struct htrim_params *p)
{
  struct db_iter *it;
  char *lower = NULL;
  size_t llen = 0;
  uint64_t cutoff = retention_cutoff_ms(p);
  int rc;

  if (g.bf_cursor_len) {
    llen = g.bf_cursor_len + 1;
    lower = (char *)MyMalloc(llen);
    memcpy(lower, g.bf_cursor, g.bf_cursor_len);
    lower[g.bf_cursor_len] = '\0';             /* cursor ‖ 0x00 */
  }
  it = db_iter_open_bounded(g.st.env, g.st.messages, NULL, lower, llen, NULL, 0);
  MyFree(lower);                                /* the iterator owns its copy */
  if (!it)
    return -1;

  s->bf_step = 1;
  rc = db_iter_seek_first(it);
  while (rc == DB_OK) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);

    if (backfill_row(s, k, kl, v, vl, cutoff) < 0) {
      db_iter_close(it);
      return -1;
    }
    bytes_set(&s->bf_cursor, &s->bf_cursor_len, &s->bf_cursor_cap, k, kl);
    s->bf_rows++;
    rc = db_iter_next(it);
    if (rc == DB_OK && htrim_slice_expired(s))
      break;
  }
  db_iter_close(it);
  if (rc != DB_OK && rc != DB_NOTFOUND)
    return -1;

  if (rc == DB_NOTFOUND)
    s->bf_finished = 1;
  if (!g.st.meta)
    return 0;
  /* A row indexed behind the stored age-out resume point moves it back
   * (backfill_apply moves the mirror through ageout_note_indexed). */
  if (behind_saved(s->bf_min_bt, s->bf_min_bt_len)
      && db_writebatch_put(s->wb, g.st.meta, HTRIM_META_AGEOUT_RESUME,
                           strlen(HTRIM_META_AGEOUT_RESUME),
                           s->bf_min_bt, s->bf_min_bt_len) != DB_OK) {
    s->broken = 1;
    return -1;
  }
  if (s->bf_finished) {
    if (db_writebatch_put(s->wb, g.st.meta, HTRIM_META_BACKFILL_DONE,
                          strlen(HTRIM_META_BACKFILL_DONE), "done", 4) != DB_OK
        || db_writebatch_del(s->wb, g.st.meta, HTRIM_META_BACKFILL_CURSOR,
                             strlen(HTRIM_META_BACKFILL_CURSOR)) != DB_OK) {
      s->broken = 1;
      return -1;
    }
  } else if (db_writebatch_put(s->wb, g.st.meta, HTRIM_META_BACKFILL_CURSOR,
                               strlen(HTRIM_META_BACKFILL_CURSOR),
                               s->bf_cursor, s->bf_cursor_len) != DB_OK) {
    s->broken = 1;
    return -1;
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* The cap                                                             */
/* ------------------------------------------------------------------ */

static void plan_params(const struct htrim_params *p, struct htc_plan_params *pp)
{
  memset(pp, 0, sizeof *pp);
  pp->cap = p->cap_bytes;
  pp->high_pct = p->high_pct;
  pp->low_pct = p->low_pct;
  pp->quota_on = p->quota_on;
  pp->share_pct = p->share_pct;
  pp->draining = g.draining;
}

/** cap * high% in bytes, by the planner's watermark rule. */
static uint64_t evict_high_bytes(const struct htrim_params *p)
{
  int high = p->high_pct, low = p->low_pct;

  htc_plan_sanitize(&high, &low);
  return p->cap_bytes * (uint64_t)high / 100;
}

static void drain_forget(void)
{
  g.ev_owner[0] = '\0';
  g.ev_bo_len = 0;
  g.ev_below = 0;
  g.ev_start_len = 0;
  g.ev_lower_set = 0;
  g.ev_lower_len = 0;
}

static void drain_begin(uint64_t cap)
{
  int i;

  g.draining = 1;
  drain_forget();
  g.drain_owner = g.drain_oldest = 0;
  /* The prefix-keyed CFs are hinted at a drain's end only: over what the
   * drain deleted, not over everything since the last drain. */
  for (i = 0; i < HH_COUNT; i++)
    if (!hint_time_ordered(i) && i != HH_UNDECIDED && !g.hint_due[i]
        && !g.hint_failed[i])
      g.hint[i].n = 0;
  log_write(LS_SYSTEM, L_WARNING, 0,
            "history: store at %llu of cap %llu bytes: evicting inside "
            "retention, over-share owners first",
            (unsigned long long)htc_acct_total(g.acct), (unsigned long long)cap);
}

/** A drain's end: log what it took, hint compaction over every CF it
 * deleted from, and sweep the targets it may have emptied out of order. */
static void drain_end(uint64_t cap)
{
  g.draining = 0;
  drain_forget();
  log_write(LS_SYSTEM, L_INFO, 0,
            "history: eviction drain complete: %llu rows (%llu owner share, "
            "%llu oldest overall), store %llu of cap %llu bytes",
            (unsigned long long)(g.drain_owner + g.drain_oldest),
            (unsigned long long)g.drain_owner, (unsigned long long)g.drain_oldest,
            (unsigned long long)htc_acct_total(g.acct), (unsigned long long)cap);
  hints_flush_all();
  tsweep_arm();
}

/** Remove by_owner entry @a k alone -- it names no row this owner holds
 * (its by_time row is gone, unreadable, or another owner's) -- with its
 * size @a size off its owner's total, through the accounting rule. */
static int evict_entry_only(struct htrim_slice *s, const void *k, size_t kl,
                            uint32_t size)
{
  if (slice_del(s, g.st.by_owner, k, kl) < 0)
    return -1;
  if (size)
    slice_add_delta(s, (const char *)k, kl, -(int64_t)size);
  s->idx_only++;
  return 0;
}

/** Walk @a owner's by_owner entries in [@a lo, @a hi): THE delete each
 * (counted), or the entry alone when its by_time row is missing,
 * unreadable or another owner's, adding their sizes to *@a trimmed until
 * it reaches @a trim or the budget is spent.
 * @return 0 the range ran out, 1 @a trim reached, 2 the budget stopped
 * it, -1 a read failed or the slice is poisoned. */
static int owner_walk(struct htrim_slice *s, const char *owner,
                      const char *lo, size_t ll, const char *hi, size_t hl,
                      uint64_t trim, uint64_t *trimmed)
{
  struct db_iter *it;
  int rc;

  it = db_iter_open_bounded(g.st.env, g.st.by_owner, NULL, lo, ll, hi, hl);
  if (!it)
    return -1;
  rc = db_iter_seek_first(it);
  while (rc == DB_OK) {
    size_t kl, vl, btl = 0;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    const void *bt = NULL;
    struct db_val tv = { NULL, 0 };
    struct htc_rec rec;
    uint32_t size = 0;
    int grc, drc, parsed = 0;

    if (htc_size_parse(v, vl, &size) != 0)
      size = 0;
    grc = htc_bo_split(k, kl, NULL, 0, &bt, &btl) == 0
            ? db_get(g.st.env, g.st.by_time, bt, btl, NULL, &tv) : DB_NOTFOUND;
    if (grc != DB_OK && grc != DB_NOTFOUND) {
      db_iter_close(it);
      return -1;
    }
    if (grc == DB_OK)
      parsed = htc_rec_parse(tv.base, tv.len, &rec) == 0;
    db_val_free(&tv);
    if (parsed && strcmp(rec.owner, owner) == 0) {
      drc = htrim_delete_row(s, HTRIM_PATH_OWNER, bt, btl, &rec, 1);
      size = rec.bytes;
    } else if (grc == DB_OK && !parsed) {
      /* An unreadable record: the index-only delete takes its by_time
       * key; this entry goes alone. */
      drc = htrim_delete_row(s, HTRIM_PATH_OWNER, bt, btl, NULL, 1);
      if (drc == 0)
        drc = evict_entry_only(s, k, kl, size);
    } else                       /* no by_time row, or another owner's */
      drc = evict_entry_only(s, k, kl, size);
    if (drc != 0) {
      db_iter_close(it);
      return -1;
    }
    *trimmed += size;
    s->ev_freed += size;
    bytes_set(&s->ev_bo, &s->ev_bo_len, &s->ev_bo_cap, k, kl);
    rc = db_iter_next(it);
    if (*trimmed >= trim) {
      db_iter_close(it);
      return 1;
    }
    if (rc == DB_OK && htrim_slice_expired(s)) {
      db_iter_close(it);
      return 2;
    }
  }
  db_iter_close(it);
  return rc == DB_NOTFOUND ? 0 : -1;
}

/** One owner step: @a owner's own oldest rows -- a by_owner walk from
 * owner 0x00 ‖ the live floor (or, resuming the step in progress, from
 * the successor of the last key it deleted), THE delete each (counted),
 * until @a trim bytes are gone or the budget is spent.  An entry whose
 * by_time row is missing, unreadable or names another owner is removed
 * alone.
 *
 * A walk from the floor that runs out first goes on below where it
 * started, once: [owner 0x00, that start) holds the owner's aged-out
 * head (tombstones) and any orphan entries a boot scan counted, which
 * the per-entry check removes with their bytes -- an orphan over the
 * share would otherwise send every drain back to this owner.  Only a
 * walk over the whole range that still runs short of @a trim means the
 * total drifted: from the owner's first key in one go it holds 0; else
 * the totals are counted again.
 * @return 0 the step is done, 1 the budget stopped it (still in progress),
 *         -1 a read failed or the slice is poisoned. */
static int evict_owner(struct htrim_slice *s, const char *owner, uint64_t trim,
                       int resume)
{
  char lo[HTC_BO_KEY_MAX + 1], hi[HTC_OWNER_MAX + 1], top[HTC_BO_KEY_MAX + 1];
  uint64_t trimmed = 0;
  size_t ll, tl;
  int pl, rc, whole = 0, below = 0;

  pl = htc_bo_prefix(hi, sizeof hi, owner);           /* owner \0 */
  if (pl < 1)
    return 0;
  memcpy(top, hi, (size_t)pl);
  top[pl - 1] = '\x01';                               /* owner \x01 */
  tl = (size_t)pl;
  memcpy(lo, hi, (size_t)pl);
  ll = (size_t)pl;
  if (resume && strcmp(g.ev_owner, owner) == 0 && g.ev_below
      && g.ev_below_hi_len && g.ev_below_hi_len <= sizeof top) {
    below = 1;                                        /* resuming below the start */
    memcpy(top, g.ev_below_hi, g.ev_below_hi_len);
    tl = g.ev_below_hi_len;
    if (g.ev_bo_len && g.ev_bo_len < sizeof lo) {
      memcpy(lo, g.ev_bo, g.ev_bo_len);
      lo[g.ev_bo_len] = '\0';
      ll = g.ev_bo_len + 1;
    }
  } else if (resume && g.ev_bo_len && g.ev_bo_len < sizeof lo
             && strcmp(g.ev_owner, owner) == 0) {
    memcpy(lo, g.ev_bo, g.ev_bo_len);
    lo[g.ev_bo_len] = '\0';                           /* past its last delete */
    ll = g.ev_bo_len + 1;
    if (g.ev_start_len)
      bytes_set(&s->ev_start, &s->ev_start_len, &s->ev_start_cap,
                g.ev_start, g.ev_start_len);
    else
      whole = 1;                                      /* began at its first key */
  } else {
    /* A new step starts at owner \0 ‖ the live floor: the owner's entries
     * below it name by_time rows age-out (or this drain) already deleted,
     * and seeking from its first key would walk all their tombstones --
     * the largest owner's aged-out head, by construction. */
    const char *f;
    size_t fl;
    live_floor(&f, &fl);
    if (fl && ll + fl <= sizeof lo) {
      memcpy(lo + ll, f, fl);
      ll += fl;
      bytes_set(&s->ev_start, &s->ev_start_len, &s->ev_start_cap, lo, ll);
    } else {
      whole = 1;
      s->ev_start_len = 0;      /* never an earlier owner's, from this slice */
    }
  }

  snprintf(s->ev_owner, sizeof s->ev_owner, "%s", owner);
  rc = owner_walk(s, owner, lo, ll, top, tl, trim, &trimmed);
  if (rc == 0 && !whole && !below) {
    /* Ran out above the start: once, below it -- up to where the step
     * began (not a resume point: what lies between was this step's). */
    below = 1;
    if (s->ev_start_len && s->ev_start_len <= sizeof top) {
      memcpy(top, s->ev_start, s->ev_start_len);
      tl = s->ev_start_len;
    } else {
      memcpy(top, lo, ll);
      tl = ll;
    }
    if (slice_staged(s) && htrim_slice_expired(s))
      rc = 3;                                         /* below, next slice */
    else {
      s->ev_bo_len = 0;
      rc = owner_walk(s, owner, hi, (size_t)pl, top, tl, trim, &trimmed);
    }
  }
  if (rc < 0)
    return -1;
  if (rc == 2 || rc == 3) {                           /* still in progress */
    if (below) {
      s->ev_below = 1;
      bytes_set(&s->ev_below_hi, &s->ev_below_hi_len, &s->ev_below_hi_cap, top, tl);
      if (rc == 3)
        s->ev_bo_len = 0;                             /* below: from owner \0 */
    }
    return 1;
  }
  /* rc 1: trimmed to the share.  rc 0: the whole range ran out short of
   * it -- the total drifted. */
  if (rc == 0) {
    if (whole)
      snprintf(s->ev_zero, sizeof s->ev_zero, "%s", owner);
    else
      s->ev_recount = 1;
  }
  s->ev_owner[0] = '\0';
  s->ev_bo_len = 0;
  return 0;
}

/** Oldest overall: walk by_time from the live floor -- where this
 * drain's (or the last emergency's) walk stopped, at first the age-out
 * resume point, or the oldest row indexed behind it: every row below is
 * gone -- THE delete each row (counted) under @a path, until @a need
 * bytes are gone or the budget is spent; the coverage floor moves to the
 * newest ms deleted, in the same batch.  @return 0, or -1. */
static int oldest_walk(struct htrim_slice *s, enum htrim_path path, uint64_t need)
{
  const char *lower;
  size_t llen;
  struct db_iter *it;
  uint64_t freed = 0;
  int rc;

  live_floor(&lower, &llen);
  it = db_iter_open_bounded(g.st.env, g.st.by_time, NULL, llen ? lower : NULL, llen,
                            NULL, 0);
  if (!it)
    return -1;

  rc = db_iter_seek_first(it);
  while (rc == DB_OK) {
    size_t kl, vl;
    const void *k = db_iter_key(it, &kl);
    const void *v = db_iter_value(it, &vl);
    struct htc_rec rec;
    uint64_t ms;
    int parsed = v && htc_rec_parse(v, vl, &rec) == 0;

    if (htrim_delete_row(s, path, k, kl, parsed ? &rec : NULL, 1) != 0) {
      db_iter_close(it);
      return -1;
    }
    if (parsed) {
      freed += rec.bytes;
      s->ev_freed += rec.bytes;
    }
    ms = bt_key_ms(k, kl);
    if (ms > s->floor_ms)
      s->floor_ms = ms;
    bytes_set(&s->ev_bt, &s->ev_bt_len, &s->ev_bt_cap, k, kl);
    rc = db_iter_next(it);
    if (freed >= need)
      break;
    if (rc == DB_OK && htrim_slice_expired(s))
      break;
  }
  db_iter_close(it);
  if (rc != DB_OK && rc != DB_NOTFOUND)
    return -1;
  if (rc == DB_NOTFOUND && freed < need)
    s->ev_exhausted = 1;

  if (s->floor_ms > g.floor_ms && g.st.meta) {
    char buf[24];
    int n = snprintf(buf, sizeof buf, "%llu", (unsigned long long)s->floor_ms);
    if (db_writebatch_put(s->wb, g.st.meta, HTRIM_META_FLOOR,
                          strlen(HTRIM_META_FLOOR), buf, (size_t)n) != DB_OK) {
      s->broken = 1;
      return -1;
    }
  }
  return 0;
}

/** One eviction slice (see the header's "The cap"). */
static int phase_evict(struct htrim_slice *s, const struct htrim_params *p)
{
  struct htc_plan_params pp;
  struct htc_plan plan;
  char done[HTC_OWNER_MAX] = "";
  uint64_t total;
  size_t i;
  int rc;

  plan_params(p, &pp);
  htc_plan_eviction(g.acct, &pp, &plan);
  total = htc_acct_total(g.acct);
  /* The step in progress holds only while the share step is on (the
   * planner's own gate): a SET that turns the quota off, or its share to
   * an out-of-range percentage, ends it. */
  if (g.ev_owner[0] && !htc_share_active(&pp)) {
    g.ev_owner[0] = '\0';
    g.ev_bo_len = 0;
    g.ev_below = 0;
    g.ev_start_len = 0;
  }
  if (!g.draining) {
    if (!plan.active)
      return 0;
    drain_begin(p->cap_bytes);
  } else if (!plan.active && !g.ev_owner[0]) {
    drain_end(p->cap_bytes);             /* e.g. the cap was raised */
    return 0;
  }
  s->ev_step = 1;
  s->ev_cap = p->cap_bytes;
  s->ev_target = plan.target;

  /* 1. The step in progress first: an owner, once picked, goes down to
   *    its share (however low the total got meanwhile). */
  if (g.ev_owner[0]) {
    uint64_t have = htc_acct_owner(g.acct, g.ev_owner);
    uint64_t share = htc_owner_share(&pp, g.ev_owner);

    snprintf(done, sizeof done, "%s", g.ev_owner);
    if (have > share) {
      rc = evict_owner(s, g.ev_owner, have - share, 1);
      if (rc || s->ev_zero[0] || s->ev_recount)   /* one drifted owner a slice */
        return rc < 0 ? -1 : 0;
    }
  }

  /* 2. The plan's next steps, in order, while the total is above the low
   *    watermark. */
  for (i = 0; i < plan.nsteps; i++) {
    const struct htc_plan_step *st = &plan.steps[i];

    if (strcmp(st->owner, done) == 0)
      continue;
    if (total <= s->ev_freed || total - s->ev_freed <= plan.target)
      return 0;
    if (slice_staged(s) && htrim_slice_expired(s))
      return 0;
    rc = evict_owner(s, st->owner, st->trim, 0);
    if (rc || s->ev_zero[0] || s->ev_recount)
      return rc < 0 ? -1 : 0;
  }

  /* 3. Oldest overall: nobody over share, and the plan saw every owner --
   *    never when it was truncated (Review Focus 4). */
  if (!plan.nsteps && !plan.truncated && plan.oldest > 0
      && total > s->ev_freed && total - s->ev_freed > plan.target
      && !(slice_staged(s) && htrim_slice_expired(s)))
    return oldest_walk(s, HTRIM_PATH_OLDEST, total - s->ev_freed - plan.target);
  return 0;
}

/** The totals say more than the store holds (an oldest-overall walk ran
 * out of rows): count them again from by_owner.  Eviction waits for it. */
static void acct_recount(void)
{
  log_write(LS_SYSTEM, L_WARNING, 0,
            "history: eviction: an index walk ran out of rows with %llu bytes "
            "still accounted; counting the owner totals again",
            (unsigned long long)htc_acct_total(g.acct));
  htc_acct_clear(g.acct);
  g.acct_loaded = 0;
  g.scan_started = 0;
  MyFree(g.cursor);
  g.cursor = NULL;
  g.cursor_len = g.cursor_cap = 0;
}

/** A committed eviction step. */
static void evict_apply(struct htrim_slice *s)
{
  int moved = 0, recount = 0;

  snprintf(g.ev_owner, sizeof g.ev_owner, "%s", s->ev_owner);
  if (!g.ev_owner[0])
    g.ev_bo_len = 0;                            /* no step in progress */
  else if (s->ev_bo_len)
    bytes_set(&g.ev_bo, &g.ev_bo_len, &g.ev_bo_cap, s->ev_bo, s->ev_bo_len);
  else if (s->ev_below)
    g.ev_bo_len = 0;                            /* below: from owner \0 */
  g.ev_below = g.ev_owner[0] && s->ev_below;
  if (g.ev_owner[0] && s->ev_start_len)
    bytes_set(&g.ev_start, &g.ev_start_len, &g.ev_start_cap, s->ev_start, s->ev_start_len);
  else if (!g.ev_owner[0])
    g.ev_start_len = 0;
  if (g.ev_below)
    bytes_set(&g.ev_below_hi, &g.ev_below_hi_len, &g.ev_below_hi_cap,
              s->ev_below_hi, s->ev_below_hi_len);
  if (s->ev_zero[0]) {
    uint64_t left = htc_acct_owner(g.acct, s->ev_zero);
    if (left) {
      log_write(LS_SYSTEM, L_INFO, 0,
                "history: eviction: owner %s has no rows left but %llu bytes "
                "accounted; now 0", s->ev_zero, (unsigned long long)left);
      htc_acct_add(g.acct, s->ev_zero, -(int64_t)left);
    }
  }
  /* Out of rows -- from the live floor, below which nothing lives, or
   * from the first key -- with the total still above the target: the
   * totals are counted again (no walk from the first key). */
  if (s->ev_exhausted || s->ev_recount)
    recount = 1;
  else if (s->ev_bt_len) {
    size_t n = s->ev_bt_len + 1;
    if (n > g.ev_lower_cap) {
      g.ev_lower_cap = n;
      g.ev_lower = (char *)MyRealloc(g.ev_lower, n);
    }
    memcpy(g.ev_lower, s->ev_bt, s->ev_bt_len);
    g.ev_lower[s->ev_bt_len] = '\0';
    g.ev_lower_len = n;
    g.ev_lower_set = 1;
  }
  g.drain_owner += s->counts[HTRIM_PATH_OWNER];
  g.drain_oldest += s->counts[HTRIM_PATH_OLDEST];
  if (s->floor_ms > g.floor_ms) {
    g.floor_ms = s->floor_ms;
    moved = 1;
  }
  if (recount)
    acct_recount();
  if (g.draining && !g.ev_owner[0]
      && (recount || htc_acct_total(g.acct) <= s->ev_target))
    drain_end(s->ev_cap);
  if (moved && coverage_cb)
    coverage_cb();
}

/** A committed emergency slice: the next oldest-overall walk resumes
 * past its deletes (ev_lower: every row below is gone but the late rows
 * live_floor reads), the coverage floor moves, and a slice that deleted
 * rows arms the targets sweep (its cleanup went to the carry).  A walk
 * that ran out recounts nothing: no drain is judging the totals. */
static void emergency_apply(struct htrim_slice *s)
{
  if (s->ev_bt_len) {
    size_t n = s->ev_bt_len + 1;
    if (n > g.ev_lower_cap) {
      g.ev_lower_cap = n;
      g.ev_lower = (char *)MyRealloc(g.ev_lower, n);
    }
    memcpy(g.ev_lower, s->ev_bt, s->ev_bt_len);
    g.ev_lower[s->ev_bt_len] = '\0';
    g.ev_lower_len = n;
    g.ev_lower_set = 1;
  }
  if (s->rows)
    tsweep_arm();
  if (s->floor_ms > g.floor_ms) {
    g.floor_ms = s->floor_ms;
    if (coverage_cb)
      coverage_cb();
  }
}

int htrim_emergency(unsigned int budget_ms)
{
  struct htrim_slice *s;
  int rows;

  if (!g.inited) {
    snprintf(g.last_error, sizeof g.last_error, "trim engine not started");
    return -1;
  }
  s = htrim_slice_begin(budget_ms ? budget_ms : 1);    /* never unbudgeted */
  if (!s) {
    snprintf(g.last_error, sizeof g.last_error, "emergency slice not opened: %s",
             last_err());
    return -1;
  }
  htrim_slice_set_phase(s, HTRIM_PH_EMERGENCY);
  s->em_step = 1;
  s->defer_cleanup = 1;
  if (oldest_walk(s, HTRIM_PATH_EMERGENCY, UINT64_MAX) < 0) {
    g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
    last_unmeasured(0);
    htrim_slice_abort(s);
    record_slice(HTRIM_PH_EMERGENCY);
    snprintf(g.last_error, sizeof g.last_error, "emergency slice failed: %s",
             last_err());
    return -1;
  }
  rows = htrim_slice_commit(s);
  if (rows < 0)
    snprintf(g.last_error, sizeof g.last_error, "emergency slice commit failed: %s",
             last_err());
  return rows;
}

/* ------------------------------------------------------------------ */
/* The targets sweep                                                   */
/* ------------------------------------------------------------------ */

static void ts_name_push(struct htrim_slice *s, const void *k, size_t kl)
{
  if (s->ts_n == s->ts_cap) {
    s->ts_cap = s->ts_cap ? s->ts_cap * 2 : 16;
    s->ts_names = (char (*)[HTC_TARGET_MAX])MyRealloc(s->ts_names,
                                                     s->ts_cap * sizeof *s->ts_names);
  }
  memcpy(s->ts_names[s->ts_n], k, kl);
  s->ts_names[s->ts_n][kl] = '\0';
  s->ts_n++;
}

/** One sweep slice: the targets CF from the successor of the pass's
 * cursor, one live-tail seek per key; an empty target's key is deleted
 * in this slice's batch and reported once it commits.  Stamps are never
 * touched.  The first slice of a pass consumes what armed it. */
static int phase_tsweep(struct htrim_slice *s)
{
  struct db_iter *it;
  char *lower = NULL;
  size_t llen = 0;
  int rc;

  if (!g.ts_running) {
    g.ts_running = 1;
    g.ts_armed = 0;
    g.tsweep_wanted = 0;
    g.ts_cursor_len = 0;
  }
  if (g.ts_cursor_len) {
    llen = g.ts_cursor_len + 1;
    lower = (char *)MyMalloc(llen);
    memcpy(lower, g.ts_cursor, g.ts_cursor_len);
    lower[g.ts_cursor_len] = '\0';             /* cursor ‖ 0x00 */
  }
  it = db_iter_open_bounded(g.st.env, g.st.targets, NULL, lower, llen, NULL, 0);
  MyFree(lower);                                /* the iterator owns its copy */
  if (!it)
    return -1;

  s->ts_step = 1;
  rc = db_iter_seek_first(it);
  while (rc == DB_OK) {
    size_t kl;
    const void *k = db_iter_key(it, &kl);

    if (kl < HTC_TARGET_MAX) {
      int has = target_has_rows(k, kl);
      s->ts_checks++;
      if (has < 0) {
        db_iter_close(it);
        return -1;
      }
      if (has == 2) {                           /* undecided: a later sweep */
        target_undecided(k, kl);
        s->ts_undecided++;
      } else if (!has) {
        if (slice_del(s, g.st.targets, k, kl) < 0) {
          db_iter_close(it);
          return -1;
        }
        ts_name_push(s, k, kl);
      }
    }
    bytes_set(&s->ts_cursor, &s->ts_cursor_len, &s->ts_cursor_cap, k, kl);
    rc = db_iter_next(it);
    if (rc == DB_OK && htrim_slice_expired(s))
      break;
  }
  db_iter_close(it);
  if (rc != DB_OK && rc != DB_NOTFOUND)
    return -1;
  if (rc == DB_NOTFOUND)
    s->ts_finished = 1;
  return 0;
}

/** A committed sweep step: move the cursor (or end the pass), then report
 * the targets it removed. */
static void tsweep_apply(struct htrim_slice *s)
{
  if (s->ts_finished) {
    g.ts_running = 0;
    g.ts_cursor_len = 0;
  } else if (s->ts_cursor_len)
    bytes_set(&g.ts_cursor, &g.ts_cursor_len, &g.ts_cursor_cap,
              s->ts_cursor, s->ts_cursor_len);
  if (s->ts_undecided)
    log_write(LS_SYSTEM, L_INFO, 0,
              "history: trim: targets sweep: %u target%s undecided (more than "
              "%d tombstones in the way); hinted for compaction, checked again "
              "by the next sweep", s->ts_undecided, s->ts_undecided == 1 ? "" : "s",
              HTRIM_EMPTY_SKIP_MAX);
  if (s->ts_n && g.emptied) {
    const char **names = (const char **)MyMalloc(s->ts_n * sizeof *names);
    size_t i;
    for (i = 0; i < s->ts_n; i++)
      names[i] = s->ts_names[i];
    g.emptied(names, (int)s->ts_n);
    MyFree(names);
  }
}

static int phase_has_work(enum htrim_phase ph, const struct htrim_params *p)
{
  switch (ph) {
  case HTRIM_PH_AGEOUT:     /* a pass is open (and retention still on) */
    return g.ao_pending && p->retention_days > 0;
  case HTRIM_PH_ACCTSCAN:
    return !g.acct_loaded;
  case HTRIM_PH_BACKFILL:   /* indexing rows stored before by_time existed */
    return !g.bf_done;
  case HTRIM_PH_EVICT:      /* the cap: cap 0 is no cap; totals and index complete */
    if (!p->cap_bytes || !g.acct_loaded || !g.bf_done)
      return 0;
    return g.draining || htc_acct_total(g.acct) > evict_high_bytes(p);
  case HTRIM_PH_TSWEEP:
    return g.acct_loaded && (g.ts_running || g.ts_armed || g.tsweep_wanted);
  default:
    return 0;
  }
}

static int run_phase(enum htrim_phase ph, struct htrim_slice *s,
                     const struct htrim_params *p)
{
  switch (ph) {
  case HTRIM_PH_AGEOUT:
    return phase_ageout(s, p);
  case HTRIM_PH_ACCTSCAN:
    return phase_acctscan(s);
  case HTRIM_PH_BACKFILL:
    return phase_backfill(s, p);
  case HTRIM_PH_EVICT:
    return phase_evict(s, p);
  case HTRIM_PH_TSWEEP:
    return phase_tsweep(s);
  default:
    return 0;
  }
}

const char *htrim_phase_name(enum htrim_phase ph)
{
  switch (ph) {
  case HTRIM_PH_AGEOUT:   return "ageout";
  case HTRIM_PH_BACKFILL: return "backfill";
  case HTRIM_PH_ACCTSCAN: return "scan";
  case HTRIM_PH_EVICT:    return "evict";
  case HTRIM_PH_TSWEEP:   return "tsweep";
  case HTRIM_PH_CLEANUP:  return "cleanup";
  case HTRIM_PH_INCARNATION: return "incarnation";
  case HTRIM_PH_EMERGENCY: return "emergency";
  case HTRIM_PH_NONE:
  default:                return "none";
  }
}

/** Retention covers what eviction took: forget the coverage floor once
 * the cutoff is past it (rows at the cutoff ms are kept). */
static void floor_clear_if_aged(const struct htrim_params *p)
{
  struct db_writebatch *wb;
  uint64_t cutoff = retention_cutoff_ms(p);

  if (!g.floor_ms || !cutoff || g.floor_ms >= cutoff)
    return;
  if (g.st.meta) {
    wb = db_writebatch_new(g.st.env);
    if (!wb
        || db_writebatch_del(wb, g.st.meta, HTRIM_META_FLOOR,
                             strlen(HTRIM_META_FLOOR)) != DB_OK
        || db_writebatch_commit(wb, 0) != DB_OK) {
      log_write(LS_SYSTEM, L_ERROR, 0,
                "history_trim: cannot clear the coverage floor: %s", last_err());
      db_writebatch_destroy(wb);
      return;                                   /* the next pass start retries */
    }
    db_writebatch_destroy(wb);
  }
  g.floor_ms = 0;
  if (coverage_cb)
    coverage_cb();
}

void htrim_pass_start(const struct htrim_params *p)
{
  if (!g.inited || !p)
    return;
  g.compact_min_rows = p->compact_min_rows;
  /* Behind ao_lower every row is gone but those indexed there since.  Up
   * to HTRIM_LATE_MAX of them are known by key: they become due, and the
   * pass deletes them first and resumes at its frontier.  Past that, the
   * walk goes back to the oldest of them (due ones included), never
   * further, and walks forward from there. */
  if (g.late_over) {
    const char *m;
    size_t ml;
    if (late_min(&m, &ml)
        && (!g.ao_lower_len || key_cmp(m, ml, g.ao_lower, g.ao_lower_len) < 0))
      bytes_set(&g.ao_lower, &g.ao_lower_len, &g.ao_lower_cap, m, ml);
    g.ndue = 0;
    g.late_over = 0;
  } else {
    size_t i, j;
    for (i = 0; i < g.nlate; i++) {
      for (j = 0; j < g.ndue; j++)
        if (g.due[j].len == g.late[i].len
            && memcmp(g.due[j].k, g.late[i].k, g.late[i].len) == 0)
          break;
      if (j < g.ndue)
        continue;                               /* due already */
      if (g.ndue == HTRIM_LATE_MAX) {           /* no room: rewind instead */
        const char *m;
        size_t ml;
        if (late_min(&m, &ml)
            && (!g.ao_lower_len || key_cmp(m, ml, g.ao_lower, g.ao_lower_len) < 0))
          bytes_set(&g.ao_lower, &g.ao_lower_len, &g.ao_lower_cap, m, ml);
        g.ndue = 0;
        break;
      }
      g.due[g.ndue++] = g.late[i];
    }
    qsort(g.due, g.ndue, sizeof g.due[0], btkey_cmp);   /* oldest first */
  }
  g.nlate = 0;
  g.ao_late_len = 0;
  g.ao_pending = p->retention_days > 0;
  floor_clear_if_aged(p);
  /* An undecided emptiness check: a sweep now, compaction having had a
   * maintenance interval to drop the tombstones in its way. */
  if (g.ts_later) {
    g.ts_later = 0;
    g.ts_armed = 1;
  }
}

int htrim_ageout_pending(void)
{
  return g.ao_pending;
}

const char *htrim_last_error(void)
{
  return g.last_error;
}

/** Round-robin order of the phases. */
static const enum htrim_phase phase_order[] = {
  HTRIM_PH_AGEOUT, HTRIM_PH_BACKFILL, HTRIM_PH_ACCTSCAN, HTRIM_PH_EVICT,
  HTRIM_PH_TSWEEP
};
#define HTRIM_NPHASES (sizeof phase_order / sizeof phase_order[0])

static enum htrim_phase pick_phase(const struct htrim_params *p)
{
  size_t i, start = 0;

  for (i = 0; i < HTRIM_NPHASES; i++)
    if (phase_order[i] == g.last_run)
      start = i + 1;
  for (i = 0; i < HTRIM_NPHASES; i++) {
    enum htrim_phase ph = phase_order[(start + i) % HTRIM_NPHASES];
    if (phase_has_work(ph, p))
      return ph;
  }
  /* Carried emptiness checks and due compaction hints ride on every
   * committed slice; with no phase left to run, slices of their own
   * finish them. */
  return g.ncarry || hints_pending() ? HTRIM_PH_CLEANUP : HTRIM_PH_NONE;
}

static void record_slice(enum htrim_phase ph)
{
  g.stats.last_slice_us = g.last_elapsed_us;
  if (g.last_elapsed_us > g.stats.max_slice_us) {
    g.stats.max_slice_us = g.last_elapsed_us;
    g.stats.max_phase = ph;
    g.stats.max_walk_us = g.last_walk_us;
    g.stats.max_commit_us = g.last_commit_us;
    g.stats.max_cleanup_us = g.last_cleanup_us;
    g.stats.max_hint_us = g.last_hint_us;
    g.stats.max_seeks = g.last_seeks;
  }
  g.stats.last_phase = ph;
}

/** A slice whose time is not broken down: all of it is the walk. */
static void last_unmeasured(unsigned int seeks)
{
  g.last_walk_us = g.last_elapsed_us;
  g.last_commit_us = g.last_cleanup_us = g.last_hint_us = 0;
  g.last_seeks = seeks;
}

int htrim_run_slice(const struct htrim_params *p)
{
  struct htrim_slice *s;
  enum htrim_phase ph;

  /* A failure is described for the caller, which logs it once per
   * streak of failed slices (it retries each second, a few times). */
  if (!g.inited || !p) {
    snprintf(g.last_error, sizeof g.last_error, "%s",
             g.inited ? "slice without parameters" : "trim engine not started");
    return -1;
  }
  g.compact_min_rows = p->compact_min_rows;
  if (g.draining && !p->cap_bytes)
    drain_end(0);                               /* the cap went off mid-drain */
  ph = pick_phase(p);
  if (ph == HTRIM_PH_NONE)
    return 0;
  s = htrim_slice_begin(p->slice_ms);
  if (!s) {
    snprintf(g.last_error, sizeof g.last_error, "%s slice not opened: %s",
             htrim_phase_name(ph), last_err());
    return -1;
  }
  htrim_slice_set_phase(s, ph);  /* the commit records the slice */

  g.last_run = ph;            /* a failing phase still yields its turn */
  if (run_phase(ph, s, p) < 0) {
    g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
    last_unmeasured(s->ts_checks);
    htrim_slice_abort(s);
    record_slice(ph);
    snprintf(g.last_error, sizeof g.last_error, "%s slice failed: %s",
             htrim_phase_name(ph), last_err());
    return -1;
  }
  if (htrim_slice_commit(s) < 0) {
    snprintf(g.last_error, sizeof g.last_error, "%s slice commit failed: %s",
             htrim_phase_name(ph), last_err());
    return -1;
  }

  return pick_phase(p) != HTRIM_PH_NONE;
}

int htrim_tsweep_wanted(void)
{
  return g.tsweep_wanted;
}

int htrim_tsweep_pending(void)
{
  return g.ts_running || g.ts_armed || g.tsweep_wanted;
}

void htrim_set_coverage_cb(htrim_coverage_fn cb)
{
  coverage_cb = cb;
}

uint64_t htrim_coverage_floor_ms(void)
{
  return g.floor_ms;
}

int htrim_draining(void)
{
  return g.draining;
}

void htrim_tsweep_clear(void)
{
  g.tsweep_wanted = 0;
}

const struct htrim_stats *htrim_stats(void)
{
  return &g.stats;
}

void htrim_reset_max_slice(void)
{
  g.stats.max_slice_us = 0;
  g.stats.max_phase = HTRIM_PH_NONE;
  g.stats.max_walk_us = g.stats.max_commit_us = g.stats.max_cleanup_us = 0;
  g.stats.max_hint_us = 0;
  g.stats.max_seeks = 0;
}
