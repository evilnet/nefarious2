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

#include <stdlib.h>
#include <string.h>

/** Largest reply_index key: fold(target) \0 parent \0 ts \0 msgid. */
#define HTRIM_REPLY_KEY_MAX (HTC_TARGET_MAX + HTC_MSGID_MAX + HTC_TS_MAX + HTC_MSGID_MAX + 3)
/** Largest msgid_index key: msgid \0 fold(target). */
#define HTRIM_MSGID_KEY_MAX (HTC_MSGID_MAX + 1 + HTC_TARGET_MAX)

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

  enum htrim_phase   last_run;
  uint64_t           last_elapsed_us; /* of the last committed/failed slice */
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

static void cursor_set(const void *k, size_t kl)
{
  if (kl > g.cursor_cap) {
    g.cursor_cap = kl;
    g.cursor = (char *)MyRealloc(g.cursor, g.cursor_cap);
  }
  if (kl)
    memcpy(g.cursor, k, kl);
  g.cursor_len = kl;
  g.scan_started = 1;
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
  /* The engine's meta rows (st->meta) hold no state the core needs yet:
   * the boot accounting scan always starts from the first by_owner key. */
  g.inited = 1;
  return 0;
}

void htrim_shutdown(void)
{
  htc_acct_free(g.acct);
  MyFree(g.cursor);
  memset(&g, 0, sizeof g);
}

/* ------------------------------------------------------------------ */
/* The store path                                                      */
/* ------------------------------------------------------------------ */

int htrim_stage_index(struct db_writebatch *wb, uint64_t ms,
                      const char *target, const char *msgid,
                      const struct htc_rec *rec,
                      char *bo_key, size_t bo_size, size_t *bo_klen)
{
  char bt[HTC_BT_KEY_MAX];
  char rv[HTC_REC_MAX];
  unsigned char sz[4];
  int btl, rvl, bol;

  if (!g.inited || !wb || !target || !msgid || !rec || !bo_key || !bo_klen)
    return -1;
  btl = htc_bt_key(bt, sizeof bt, ms, target, msgid);
  if (btl < 0)
    return -1;
  rvl = htc_rec_pack(rv, sizeof rv, rec);
  if (rvl < 0)
    return -1;
  bol = htc_bo_key(bo_key, bo_size, rec->owner, bt, (size_t)btl);
  if (bol < 0)
    return -1;
  htc_size_pack(sz, rec->bytes);
  if (db_writebatch_put(wb, g.st.by_time, bt, (size_t)btl, rv, (size_t)rvl) != DB_OK
      || db_writebatch_put(wb, g.st.by_owner, bo_key, (size_t)bol, sz, sizeof sz) != DB_OK)
    return -1;
  *bo_klen = (size_t)bol;
  return 0;
}

void htrim_note_stored(const char *owner, const void *bo_key, size_t bo_klen,
                       uint32_t bytes)
{
  if (!g.inited || !bo_key)
    return;
  acct_apply(owner, bo_key, bo_klen, (int64_t)bytes);
}

int htrim_acct_loaded(void)
{
  return g.acct_loaded;
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

  if (!s || !g.inited || s->broken || !bt_key || !rec
      || (int)path < 0 || path >= HTRIM_PATH_COUNT || !rec->ts[0])
    return -1;
  if (htc_bt_key_parse(bt_key, bt_klen, &ms, target, sizeof target,
                       msgid, sizeof msgid) != 0 || !target[0])
    return -1;

  /* Build every key first: a key that does not fit stages nothing. */
  mkl = htc_msg_key(mk, sizeof mk, target, rec->ts, msgid);
  if (mkl < 0)
    return -1;
  if (msgid[0]) {
    ikl = htc_msgid_key(ik, sizeof ik, msgid, target);
    if (ikl < 0)
      return -1;
    if ((rec->flags & HTC_F_REDACT) && g.st.redact) {
      xkl = rdx_key_build(xk, sizeof xk, ms, msgid);
      if (xkl < 0)
        return -1;
    }
  }
  if (rec->reply_parent[0]) {
    rk1l = htc_reply_child_key(rk1, sizeof rk1, target, rec->reply_parent,
                               rec->ts, msgid);
    if (rk1l < 0)
      return -1;
  }
  if (rec->redact_parent[0]) {
    rk2l = htc_reply_child_key(rk2, sizeof rk2, target, rec->redact_parent,
                               rec->ts, msgid);
    if (rk2l < 0)
      return -1;
  }
  bol = htc_bo_key(bo, sizeof bo, rec->owner, bt_key, bt_klen);
  if (bol < 0)
    return -1;

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
    return -1;

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
 * Skips without touching the messages CF when the targets stamp is newer
 * than the newest row deleted from it (a newer message row exists): a
 * prefix seek on a target mid-drain walks every head tombstone so far. */
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
  if (db_get(g.st.env, g.st.targets, tkey, *tklen, NULL, &cur) != DB_OK)
    return 0;
  newer = cur.base && history_stamp_newer((const char *)cur.base, cur.len,
                                          newest, strlen(newest));
  db_val_free(&cur);
  if (newer)
    return 0;

  memcpy(upper, tkey, (size_t)kl);
  upper[kl - 1] = '\x01';                               /* [fold(t) 0x00, fold(t) 0x01) */
  it = db_iter_open_bounded(g.st.env, g.st.messages, NULL, tkey, (size_t)kl,
                            upper, (size_t)kl);
  if (!it)
    return 0;
  rc = db_iter_seek_first(it);
  db_iter_close(it);
  return rc == DB_NOTFOUND;
}

/** After a committed slice: drop the targets key of every touched target
 * left without rows (one second batch), then tell the emptied callback. */
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

    for (j = i + 1; j < s->ntouch && strcmp(s->touch[j].target, t->target) == 0; j++)
      if (history_stamp_newer(s->touch[j].ts, strlen(s->touch[j].ts),
                              t->ts, strlen(t->ts)))
        memcpy(t->ts, s->touch[j].ts, sizeof t->ts);

    if (!target_emptied(t->target, t->ts, tkey, sizeof tkey, &tklen))
      continue;
    if (!wb && !(wb = db_writebatch_new(g.st.env)))
      break;
    if (db_writebatch_del(wb, g.st.targets, tkey, tklen) == DB_OK)
      names[n++] = t->target;
  }

  if (wb) {
    if (n && db_writebatch_commit(wb, 0) == DB_OK && g.emptied)
      g.emptied(names, (int)n);
    db_writebatch_destroy(wb);
  }
  MyFree(names);
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
  cleanup_touched(s);

  g.last_elapsed_us = elapsed_since(s->start_us, g.clock());
  rows = s->rows;
  slice_free(s);
  return rows;
}

/* ------------------------------------------------------------------ */
/* Phases                                                              */
/* ------------------------------------------------------------------ */

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

static int phase_has_work(enum htrim_phase ph, const struct htrim_params *p)
{
  (void)p;
  switch (ph) {
  case HTRIM_PH_ACCTSCAN:
    return !g.acct_loaded;
  case HTRIM_PH_AGEOUT:     /* age-out over by_time */
  case HTRIM_PH_BACKFILL:   /* indexing rows stored before by_time existed */
  case HTRIM_PH_EVICT:      /* the cap */
  default:
    return 0;
  }
}

static int run_phase(enum htrim_phase ph, struct htrim_slice *s,
                     const struct htrim_params *p)
{
  (void)p;
  switch (ph) {
  case HTRIM_PH_ACCTSCAN:
    return phase_acctscan(s);
  default:
    return 0;
  }
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

  g.last_run = ph;            /* a failing phase still yields its turn */
  if (run_phase(ph, s, p) < 0) {
    htrim_slice_abort(s);
    log_write(LS_SYSTEM, L_ERROR, 0, "history_trim: phase %d failed: %s",
              (int)ph, last_err());
    return -1;
  }
  if (htrim_slice_commit(s) < 0) {
    record_slice(ph);
    log_write(LS_SYSTEM, L_ERROR, 0, "history_trim: slice commit failed (phase %d): %s",
              (int)ph, last_err());
    return -1;
  }
  record_slice(ph);

  return pick_phase(p) != HTRIM_PH_NONE;
}

const struct htrim_stats *htrim_stats(void)
{
  return &g.stats;
}

void htrim_reset_max_slice(void)
{
  g.stats.max_slice_us = 0;
}
