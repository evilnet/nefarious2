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
 * Age-out keeps where its walk resumes (ao_lower, in memory only): the
 * successor of the last by_time key a committed slice deleted.  Every
 * slice opens its iterator there, so the tombstones the walk left behind
 * it are never walked again -- on RocksDB a seek from the first key walks
 * every one not yet compacted away (the bed, 2026-11-04: ~3000 of them,
 * 316-433 ms in one slice).  Behind ao_lower every row is gone except
 * those indexed there since (a late store, a backfill after a retention
 * rise): the smallest such key is kept (ao_late), and a pass start sends
 * the walk back to it.  A restart begins at the first key, once.
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
/** Unindexable keys a walk names in the log (then only counts). */
#define HTRIM_BF_LOG_KEYS 5
/** A logged key's printable form, quotes excluded. */
#define HTRIM_KEY_PREVIEW 128

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
  char                 *ao_cursor;   /* the last by_time key it deleted */
  size_t                ao_cursor_len, ao_cursor_cap;

  /* A backfill step, applied at commit. */
  int                   bf_step;     /* this slice walked messages rows */
  int                   bf_finished; /* ... to the end of the CF */
  char                 *bf_cursor;   /* the last messages key it processed */
  size_t                bf_cursor_len, bf_cursor_cap;
  size_t                bf_rows, bf_indexed, bf_aged, bf_unindexed;
  char                 *bf_min_bt;   /* the smallest by_time key it indexed */
  size_t                bf_min_bt_len, bf_min_bt_cap;
  /* Unindexable keys to name in the log once this slice commits. */
  char                  bf_bad[HTRIM_BF_LOG_KEYS][HTRIM_KEY_PREVIEW];
  size_t                bf_bad_klen[HTRIM_BF_LOG_KEYS];
  unsigned int          bf_nbad;
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

  char               last_error[192]; /* the last failed slice, for the caller's log */
  enum htrim_phase   last_run;
  uint64_t           last_elapsed_us; /* of the last committed/failed slice */
  int                tsweep_wanted;   /* a targets cleanup could not finish */
  struct htrim_stats stats;
} g;

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
  char buf[24];
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

  if (meta_get(HTRIM_META_ALIVE, &v) > 0 && v.len && v.len < sizeof buf) {
    memcpy(buf, v.base, v.len);
    buf[v.len] = '\0';
    if (strspn(buf, "0123456789") == v.len)
      g.alive_ms = strtoull(buf, NULL, 10);
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

/** A by_time key was just indexed (committed): if it sorts behind where
 * the age-out walk resumes, the next pass must go back for it. */
static void ageout_note_indexed(const void *bt, size_t btl)
{
  if (!g.ao_lower_len || !bt || !btl
      || key_cmp(bt, btl, g.ao_lower, g.ao_lower_len) >= 0)
    return;                                     /* ahead of the walk */
  if (!g.ao_late_len || key_cmp(bt, btl, g.ao_late, g.ao_late_len) < 0)
    bytes_set(&g.ao_late, &g.ao_late_len, &g.ao_late_cap, bt, btl);
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
  g.inited = 1;
  return 0;
}

void htrim_shutdown(void)
{
  htc_acct_free(g.acct);
  MyFree(g.cursor);
  MyFree(g.bf_cursor);
  MyFree(g.ao_lower);
  MyFree(g.ao_late);
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
  return stage_index(wb, bt, (size_t)btl, rec, bo_key, bo_size, bo_klen) == 0 ? 0 : -1;
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
  if (!s)
    return;
  db_writebatch_destroy(s->wb);
  MyFree(s->keys);
  MyFree(s->pend);
  MyFree(s->touch);
  MyFree(s->ao_cursor);
  MyFree(s->bf_cursor);
  MyFree(s->bf_min_bt);
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

int htrim_slice_expired(struct htrim_slice *s)
{
  if (!s || !g.inited)
    return 1;
  if (!s->budget_us)
    return 0;
  return elapsed_since(s->start_us, g.clock()) >= s->budget_us;
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
  if (db_writebatch_del(s->wb, cf, k, kl) != DB_OK) {
    s->broken = 1;
    return -1;
  }
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

static int touch_cmp(const void *a, const void *b)
{
  return strcmp(((const struct htrim_touch *)a)->target,
                ((const struct htrim_touch *)b)->target);
}

/** Whether @a target (folded) is now empty and its targets key should go.
 * @return 1 empty, 0 not (or no targets key), -1 the check failed.
 *
 * Skips without touching the messages CF when the targets stamp is newer
 * than the newest row deleted from it (a newer message row exists).
 * Otherwise it seeks the LAST key of [fold(t) 0x00, fold(t) 0x01), never
 * the first: the stamp counts message rows only, so a target whose newest
 * rows are JOIN/PART/QUIT/... comes here on every slice of its drain, and
 * a drain deletes from the head -- a seek from the head walks every
 * tombstone it left so far, the tail is live.  RocksDB's SeekToLast honours
 * iterate_upper_bound (9.10 options.h: "SeekToLast() will position the
 * iterator at the first key smaller than iterate_upper_bound") and the
 * lower bound ends the backward walk (pinned on both backends by
 * db_api_cmocka's test_bounded_iter_seek_last).  A truly empty target pays
 * one walk over its tombstones, once. */
static int target_emptied(const char *target, const char *newest,
                          char *tkey, size_t tsize, size_t *tklen)
{
  char upper[HTC_MSG_KEY_MAX];
  struct db_val cur = { NULL, 0 };
  struct db_iter *it;
  int kl, newer, rc;

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

  memcpy(upper, tkey, (size_t)kl);
  upper[kl - 1] = '\x01';                              /* [fold(t) 0x00, fold(t) 0x01) */
  it = db_iter_open_bounded(g.st.env, g.st.messages, NULL, tkey, (size_t)kl,
                            upper, (size_t)kl);
  if (!it)
    return -1;
  rc = db_iter_seek_last(it);
  db_iter_close(it);
  if (rc == DB_NOTFOUND)
    return 1;
  return rc == DB_OK ? 0 : -1;
}

/** A cleanup that could not finish: its targets keys may outlive their
 * rows until the targets sweep runs. */
static void tsweep_want(const char *what, const char *target)
{
  g.tsweep_wanted = 1;
  log_write(LS_SYSTEM, L_ERROR, 0, "history_trim: targets cleanup: %s%s%s: %s",
            what, target ? " " : "", target ? target : "", last_err());
}

/** After a committed slice: drop the targets key of every touched target
 * left without rows (one second batch), then tell the emptied callback.
 * Runs on the main loop (never from htrim_init), so it may log. */
static void cleanup_touched(struct htrim_slice *s)
{
  struct db_writebatch *wb = NULL;
  const char **names;
  size_t i, j, n = 0;

  if (!s->ntouch)
    return;
  qsort(s->touch, s->ntouch, sizeof *s->touch, touch_cmp);
  names = (const char **)MyMalloc(s->ntouch * sizeof *names);

  for (i = 0; i < s->ntouch; i = j) {
    struct htrim_touch *t = &s->touch[i];
    char tkey[HTC_MSG_KEY_MAX];
    size_t tklen = 0;
    int rc;

    for (j = i + 1; j < s->ntouch && strcmp(s->touch[j].target, t->target) == 0; j++)
      if (history_stamp_newer(s->touch[j].ts, strlen(s->touch[j].ts),
                              t->ts, strlen(t->ts)))
        memcpy(t->ts, s->touch[j].ts, sizeof t->ts);

    rc = target_emptied(t->target, t->ts, tkey, sizeof tkey, &tklen);
    if (rc < 0)
      tsweep_want("emptiness check failed for", t->target);
    if (rc <= 0)
      continue;
    if (!wb && !(wb = db_writebatch_new(g.st.env))) {
      tsweep_want("no batch", NULL);
      break;
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
}

/** A committed backfill step: move the in-memory cursor to the one the
 * batch stored, or finish. */
static void backfill_apply(struct htrim_slice *s)
{
  unsigned int i;

  ageout_note_indexed(s->bf_min_bt, s->bf_min_bt_len);
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

/** A committed age-out step: the walk resumes at the successor of the
 * last key it deleted (that key ‖ 0x00); a walk that reached the cutoff
 * closes the pass. */
static void ageout_apply(struct htrim_slice *s)
{
  if (s->ao_cursor_len) {
    size_t n = s->ao_cursor_len + 1;
    if (n > g.ao_lower_cap) {
      g.ao_lower_cap = n;
      g.ao_lower = (char *)MyRealloc(g.ao_lower, n);
    }
    memcpy(g.ao_lower, s->ao_cursor, s->ao_cursor_len);
    g.ao_lower[s->ao_cursor_len] = '\0';
    g.ao_lower_len = n;
  }
  if (s->ao_finished)
    g.ao_pending = 0;
}

int htrim_slice_commit(struct htrim_slice *s)
{
  int rows;
  size_t i;

  if (!s)
    return -1;
  if (!g.inited) {
    slice_free(s);
    return -1;
  }
  if (s->broken
      || (db_writebatch_count(s->wb) > 0
          && db_writebatch_commit(s->wb, /*sync_durably=*/0) != DB_OK)) {
    g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
    slice_free(s);
    return -1;
  }

  for (i = 0; i < s->npend; i++) {
    const char *k = s->keys + s->pend[i].koff;
    acct_apply(k, k, s->pend[i].klen, s->pend[i].delta);   /* owner = key prefix */
  }
  for (i = 0; i < HTRIM_PATH_COUNT; i++)
    g.stats.deleted[i] += s->counts[i];
  if (s->ao_step)
    ageout_apply(s);
  if (s->bf_step)
    backfill_apply(s);
  cleanup_touched(s);

  g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
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
  int rc, first = 1;

  s->ao_step = 1;
  if (!cutoff) {                                /* retention went to 0 */
    s->ao_finished = 1;
    return 0;
  }
  htc_be64(upper, cutoff);
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
  if (rc == DB_NOTFOUND)
    s->ao_finished = 1;
  return 0;
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

static int phase_has_work(enum htrim_phase ph, const struct htrim_params *p)
{
  switch (ph) {
  case HTRIM_PH_AGEOUT:     /* a pass is open (and retention still on) */
    return g.ao_pending && p->retention_days > 0;
  case HTRIM_PH_ACCTSCAN:
    return !g.acct_loaded;
  case HTRIM_PH_BACKFILL:   /* indexing rows stored before by_time existed */
    return !g.bf_done;
  case HTRIM_PH_EVICT:      /* the cap */
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
  case HTRIM_PH_NONE:
  default:                return "none";
  }
}

void htrim_pass_start(const struct htrim_params *p)
{
  if (!g.inited || !p)
    return;
  /* Behind ao_lower every row is gone but those indexed there since: the
   * walk goes back to the oldest of them, never further. */
  if (g.ao_late_len) {
    bytes_set(&g.ao_lower, &g.ao_lower_len, &g.ao_lower_cap,
              g.ao_late, g.ao_late_len);
    g.ao_late_len = 0;
  }
  g.ao_pending = p->retention_days > 0;
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
  HTRIM_PH_AGEOUT, HTRIM_PH_BACKFILL, HTRIM_PH_ACCTSCAN, HTRIM_PH_EVICT
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
  return HTRIM_PH_NONE;
}

static void record_slice(enum htrim_phase ph)
{
  g.stats.last_slice_us = g.last_elapsed_us;
  if (g.last_elapsed_us > g.stats.max_slice_us)
    g.stats.max_slice_us = g.last_elapsed_us;
  g.stats.last_phase = ph;
}

int htrim_run_slice(const struct htrim_params *p)
{
  struct htrim_slice *s;
  enum htrim_phase ph;

  if (!g.inited || !p)
    return -1;
  ph = pick_phase(p);
  if (ph == HTRIM_PH_NONE)
    return 0;
  s = htrim_slice_begin(p->slice_ms);
  if (!s)
    return -1;

  /* A failure is described for the caller, which logs it once per
   * streak of failed slices (it retries each second, a few times). */
  g.last_run = ph;            /* a failing phase still yields its turn */
  if (run_phase(ph, s, p) < 0) {
    g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
    htrim_slice_abort(s);
    record_slice(ph);
    snprintf(g.last_error, sizeof g.last_error, "%s slice failed: %s",
             htrim_phase_name(ph), last_err());
    return -1;
  }
  if (htrim_slice_commit(s) < 0) {
    record_slice(ph);
    snprintf(g.last_error, sizeof g.last_error, "%s slice commit failed: %s",
             htrim_phase_name(ph), last_err());
    return -1;
  }
  record_slice(ph);

  return pick_phase(p) != HTRIM_PH_NONE;
}

int htrim_tsweep_wanted(void)
{
  return g.tsweep_wanted;
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
}
