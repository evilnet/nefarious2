/*
 * IRC - Internet Relay Chat, ircd/history_rename.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/** @file
 * @brief Chathistory follows a channel RENAME (history_rename.h): the
 *   renames record, and the walk over a channel's rows under every name
 *   it has had.
 */
#include "config.h"

#include "history_rename.h"
#include "db_casefold.h"
#include "db_cursor.h"
#include "db_txn.h"
#include "db_types.h"
#include "history_trim_codec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/** The record's version byte. */
#define HREN_VERSION 0x02

/** One encoded entry without its name: three be64 and the length byte. */
#define HREN_ENT_FIXED 25

/** Room for a whole record. */
#define HREN_VAL_MAX (1 + HREN_REC_MAX * (HREN_ENT_FIXED + CHANNELLEN))

/** Room for the part of a messages key after the target: the timestamp,
 * its separator and the msgid.  Far more than any row has; a row whose
 * tail does not fit is not given. */
#define HREN_TAIL_MAX 256

/** A key timestamp, "sec.mmm". */
#define HREN_TS_LEN 32

/* ------------------------------------------------------------------ */
/* The record                                                          */
/* ------------------------------------------------------------------ */

static void put_be64(unsigned char *p, uint64_t v)
{
  int i;
  for (i = 7; i >= 0; i--) {
    p[i] = (unsigned char)(v & 0xff);
    v >>= 8;
  }
}

static uint64_t get_be64(const unsigned char *p)
{
  uint64_t v = 0;
  int i;
  for (i = 0; i < 8; i++)
    v = (v << 8) | p[i];
  return v;
}

/** Fold @a name into @a out (CHANNELLEN + 1 bytes).
 * @return Its length, or -1: no name, or longer than a channel name. */
static int fold_name(char *out, const char *name)
{
  size_t len;

  if (!name || !*name)
    return -1;
  len = strlen(name);
  if (len > CHANNELLEN)
    return -1;
  db_casefold_bytes(out, name, len);
  out[len] = '\0';
  return (int)len;
}

/** Decode a record value into @a ents (room for HREN_REC_MAX).  A value
 * this build does not know -- another version, a cut entry -- is no
 * entries: a channel with no earlier names, never a failed query.
 * @return The entry count. */
static int rec_decode(const void *val, size_t vlen, struct hren_seg *ents)
{
  const unsigned char *p = (const unsigned char *)val;
  const unsigned char *end = p + vlen;
  int n = 0;

  if (!val || vlen < 1 || p[0] != HREN_VERSION)
    return 0;
  p++;
  while (p < end) {
    size_t nl;

    if ((size_t)(end - p) < HREN_ENT_FIXED)
      return 0;
    nl = p[HREN_ENT_FIXED - 1];
    if (nl == 0 || nl > CHANNELLEN || (size_t)(end - p) < HREN_ENT_FIXED + nl)
      return 0;
    if (n < HREN_REC_MAX) {
      ents[n].incarnation = get_be64(p);
      ents[n].until_ms = get_be64(p + 8);
      ents[n].since_ms = get_be64(p + 16);
      memcpy(ents[n].name, p + HREN_ENT_FIXED, nl);
      ents[n].name[nl] = '\0';
      n++;
    }
    p += HREN_ENT_FIXED + nl;
  }
  return n;
}

/** Encode @a n entries into @a buf (HREN_VAL_MAX bytes).
 * @return The value length. */
static size_t rec_encode(unsigned char *buf, const struct hren_seg *ents, int n)
{
  unsigned char *p = buf;
  int i;

  *p++ = HREN_VERSION;
  for (i = 0; i < n && i < HREN_REC_MAX; i++) {
    size_t nl = strlen(ents[i].name);
    put_be64(p, ents[i].incarnation);
    put_be64(p + 8, ents[i].until_ms);
    put_be64(p + 16, ents[i].since_ms);
    p[HREN_ENT_FIXED - 1] = (unsigned char)nl;
    memcpy(p + HREN_ENT_FIXED, ents[i].name, nl);
    p += HREN_ENT_FIXED + nl;
  }
  return (size_t)(p - buf);
}

/** Read the record of the folded name @a key into @a ents.
 * @return The entry count (0 when there is none), or -1 on a read error. */
static int rec_read(struct db_env *env, struct db_cf *cf,
                    struct db_snapshot *snap, const char *key, size_t klen,
                    struct hren_seg *ents)
{
  struct db_val v = { NULL, 0 };
  int rc, n;

  rc = db_get(env, cf, key, klen, snap, &v);
  if (rc == DB_NOTFOUND)
    return 0;
  if (rc != DB_OK)
    return -1;
  n = rec_decode(v.base, v.len, ents);
  db_val_free(&v);
  return n;
}

/** Stage the record of @a key on @a wb: @a n entries, or its delete when
 * there are none. */
static int rec_stage(struct db_writebatch *wb, struct db_cf *cf,
                     const char *key, size_t klen,
                     const struct hren_seg *ents, int n)
{
  unsigned char val[HREN_VAL_MAX];

  if (n <= 0)
    return db_writebatch_del(wb, cf, key, klen);
  return db_writebatch_put(wb, cf, key, klen, val, rec_encode(val, ents, n));
}

/** qsort: the name left last first; names in order within one time, so a
 * record's bytes do not depend on the order its entries came in. */
static int ent_cmp(const void *a, const void *b)
{
  const struct hren_seg *x = (const struct hren_seg *)a;
  const struct hren_seg *y = (const struct hren_seg *)b;

  if (x->until_ms != y->until_ms)
    return x->until_ms > y->until_ms ? -1 : 1;
  if (x->incarnation != y->incarnation)
    return x->incarnation > y->incarnation ? -1 : 1;
  return strcmp(x->name, y->name);
}

/** Add (@a name, @a incarnation, @a since_ms to @a until_ms) to the
 * @a n entries of the record of @a self: not an entry for the record's
 * own name, not one behind @a floor_ms, and one name once per
 * incarnation (the later stay).
 * @return The new count. */
static int ent_add(struct hren_seg *ents, int n, int max, const char *self,
                   const char *name, uint64_t incarnation, uint64_t since_ms,
                   uint64_t until_ms, uint64_t floor_ms)
{
  int i;

  if (!strcmp(name, self) || (floor_ms && until_ms < floor_ms))
    return n;
  for (i = 0; i < n; i++) {
    if (ents[i].incarnation == incarnation && !strcmp(ents[i].name, name)) {
      if (until_ms > ents[i].until_ms) {
        ents[i].until_ms = until_ms;
        ents[i].since_ms = since_ms;
      }
      return n;
    }
  }
  if (n >= max)
    return n;
  memset(&ents[n], 0, sizeof ents[n]);
  strcpy(ents[n].name, name);
  ents[n].incarnation = incarnation;
  ents[n].until_ms = until_ms;
  ents[n].since_ms = since_ms;
  return n + 1;
}

/** Drop the entries behind @a floor_ms (0 = none).
 * @return The new count. */
static int ents_floor(struct hren_seg *ents, int n, uint64_t floor_ms)
{
  int i, k = 0;

  if (!floor_ms)
    return n;
  for (i = 0; i < n; i++)
    if (ents[i].until_ms >= floor_ms)
      ents[k++] = ents[i];
  return k;
}

/** Start the record a channel of @a incarnation arrives at with what the
 * name's record held (@a have): the other incarnations' entries.  Those
 * of the arriving incarnation are not this channel's -- its own are in
 * the record of the name it leaves -- but a dead channel's with the same
 * creation second, and are not inherited.
 * @return The entry count. */
static int ents_arrive(struct hren_seg *ents, int max, const char *self,
                       const struct hren_seg *have, int nhave,
                       uint64_t incarnation, uint64_t floor_ms)
{
  int i, n = 0;

  for (i = 0; i < nhave; i++)
    if (have[i].incarnation != incarnation)
      n = ent_add(ents, n, max, self, have[i].name, have[i].incarnation,
                  have[i].since_ms, have[i].until_ms, floor_ms);
  return n;
}

/** The caps: @a incarnation's HREN_MAX_SEGS latest entries, then the
 * record's HREN_REC_MAX latest.  Sorts @a ents.
 * @param[out] dropped Entries of @a incarnation that went; may be NULL.
 * @return The new count. */
static int ents_cap(struct hren_seg *ents, int n, uint64_t incarnation,
                    int *dropped)
{
  int i, k, kept, lost = 0;

  qsort(ents, (size_t)n, sizeof ents[0], ent_cmp);
  for (i = 0, k = 0, kept = 0; i < n; i++) {
    if (ents[i].incarnation == incarnation && ++kept > HREN_MAX_SEGS) {
      lost++;
      continue;
    }
    ents[k++] = ents[i];
  }
  for (i = HREN_REC_MAX; i < k; i++)
    if (ents[i].incarnation == incarnation)
      lost++;
  if (dropped)
    *dropped = lost;
  return k < HREN_REC_MAX ? k : HREN_REC_MAX;
}

int hren_note(struct db_env *env, struct db_cf *cf,
              const char *oldname, const char *newname,
              uint64_t incarnation, uint64_t until_ms, uint64_t floor_ms,
              int *dropped)
{
  /* The new name's record, what the old name's held for this channel,
   * and the old name itself. */
  struct hren_seg have[HREN_REC_MAX], from[HREN_REC_MAX];
  struct hren_seg ents[2 * HREN_REC_MAX + 1];
  char oldkey[CHANNELLEN + 1], newkey[CHANNELLEN + 1];
  struct db_writebatch *wb;
  uint64_t since = 0;
  int oldlen, newlen, nhave, nfrom, n, i, k, rc, lost_old = 0;

  if (dropped)
    *dropped = 0;
  if (!env || !cf || !incarnation)
    return -1;
  oldlen = fold_name(oldkey, oldname);
  newlen = fold_name(newkey, newname);
  if (oldlen < 0 || newlen < 0)
    return -1;
  if (!strcmp(oldkey, newkey))
    return 0;   /* one key: the rows are where they were */

  /* Towards showing less: a record of the new name that cannot be read
   * is replaced (what it held is nobody's the arriving channel may
   * show); when the old name's cannot be read, the names before it are
   * lost to the channel and that record goes whole. */
  nhave = rec_read(env, cf, NULL, newkey, (size_t)newlen, have);
  if (nhave < 0)
    nhave = 0;
  nfrom = rec_read(env, cf, NULL, oldkey, (size_t)oldlen, from);
  if (nfrom < 0) {
    nfrom = 0;
    lost_old = 1;
  }
  /* When the channel took the old name: when it left the one before, the
   * latest time among its earlier names.  With none it was made under
   * the old name (0) -- unless they could not be read: then nothing is
   * known of the time before now (an empty stay). */
  for (i = 0; i < nfrom; i++)
    if (from[i].incarnation == incarnation && from[i].until_ms > since)
      since = from[i].until_ms;
  if (lost_old || since > until_ms)
    since = until_ms;

  /* The new name's record: what it held for other incarnations, the name
   * just left, and the names this channel had before that one (they
   * leave the old name's record: it describes whatever channel has that
   * name next). */
  n = ents_arrive(ents, 2 * HREN_REC_MAX + 1, newkey, have, nhave,
                  incarnation, floor_ms);
  n = ent_add(ents, n, 2 * HREN_REC_MAX + 1, newkey, oldkey, incarnation,
              since, until_ms, floor_ms);
  for (i = 0, k = 0; i < nfrom; i++) {
    if (from[i].incarnation == incarnation)
      n = ent_add(ents, n, 2 * HREN_REC_MAX + 1, newkey, from[i].name,
                  incarnation, from[i].since_ms, from[i].until_ms, floor_ms);
    else
      from[k++] = from[i];
  }
  nfrom = ents_floor(from, k, floor_ms);
  n = ents_cap(ents, n, incarnation, dropped);

  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  rc = rec_stage(wb, cf, newkey, (size_t)newlen, ents, n);
  if (rc == DB_OK)
    rc = rec_stage(wb, cf, oldkey, (size_t)oldlen, from, nfrom);
  if (rc == DB_OK)
    rc = db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);
  if (rc != DB_OK)
    return -1;
  return lost_old;
}

int hren_handover(struct db_env *env, struct db_cf *cf, const char *oldname,
                  const char *losername, const char *winnername,
                  uint64_t incarnation, uint64_t floor_ms, int *dropped)
{
  struct hren_seg have[HREN_REC_MAX], from[HREN_REC_MAX];
  struct hren_seg ents[2 * HREN_REC_MAX + 1];
  char oldkey[CHANNELLEN + 1], losekey[CHANNELLEN + 1], winkey[CHANNELLEN + 1];
  struct db_writebatch *wb;
  uint64_t left = 0;
  int oldlen, loselen, winlen, nhave, nfrom, n, i, k, rc, found = 0;

  if (dropped)
    *dropped = 0;
  if (!env || !cf || !incarnation)
    return -1;
  oldlen = fold_name(oldkey, oldname);
  loselen = fold_name(losekey, losername);
  winlen = fold_name(winkey, winnername);
  if (oldlen < 0 || loselen < 0 || winlen < 0)
    return -1;
  if (!strcmp(losekey, winkey))
    return 0;   /* one record: it has them */

  nfrom = rec_read(env, cf, NULL, losekey, (size_t)loselen, from);
  if (nfrom < 0)
    return -1;
  /* When the loser's relocation left the old name: that entry and all
   * the incarnation has from before it are what the relocation moved. */
  for (i = 0; i < nfrom; i++) {
    if (from[i].incarnation == incarnation && !strcmp(from[i].name, oldkey)) {
      left = from[i].until_ms;
      found = 1;
    }
  }
  if (!found)
    return 0;
  nhave = rec_read(env, cf, NULL, winkey, (size_t)winlen, have);
  if (nhave < 0)
    return -1;

  n = ents_arrive(ents, 2 * HREN_REC_MAX + 1, winkey, have, nhave,
                  incarnation, floor_ms);
  for (i = 0, k = 0; i < nfrom; i++) {
    if (from[i].incarnation == incarnation && from[i].until_ms <= left)
      n = ent_add(ents, n, 2 * HREN_REC_MAX + 1, winkey, from[i].name,
                  incarnation, from[i].since_ms, from[i].until_ms, floor_ms);
    else
      from[k++] = from[i];
  }
  nfrom = ents_floor(from, k, floor_ms);
  n = ents_cap(ents, n, incarnation, dropped);

  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  rc = rec_stage(wb, cf, winkey, (size_t)winlen, ents, n);
  if (rc == DB_OK)
    rc = rec_stage(wb, cf, losekey, (size_t)loselen, from, nfrom);
  if (rc == DB_OK)
    rc = db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);
  return rc == DB_OK ? 1 : -1;
}

int hren_drop(struct db_env *env, struct db_cf *cf, const char *name)
{
  char key[CHANNELLEN + 1];
  struct db_writebatch *wb;
  int klen, rc;

  if (!env || !cf)
    return -1;
  klen = fold_name(key, name);
  if (klen < 0)
    return -1;
  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  rc = db_writebatch_del(wb, cf, key, (size_t)klen);
  if (rc == DB_OK)
    rc = db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);
  return rc == DB_OK ? 0 : -1;
}

/** Does the record of @a key (@a n entries) take in a row under @a name
 * stamped @a ms, of @a incarnation: under the record's own name, or
 * under an entry of the incarnation that reaches the stamp? */
static int rec_takes(const char *key, const struct hren_seg *ents, int n,
                     const char *name, uint64_t ms, uint64_t incarnation)
{
  int i;

  if (!strcmp(name, key))
    return 1;
  for (i = 0; i < n; i++)
    if (ents[i].incarnation == incarnation && ms <= ents[i].until_ms
        && !strcmp(ents[i].name, name))
      return 1;
  return 0;
}

int hren_same_channel(struct db_env *env, struct db_cf *cf, const char *aname,
                      uint64_t a_ms, const char *bname, uint64_t b_ms,
                      uint64_t incarnation)
{
  struct hren_seg ents[HREN_REC_MAX];
  char akey[CHANNELLEN + 1], bkey[CHANNELLEN + 1];
  struct db_iter *it;
  int alen, blen, n, rc, yes = 0;

  if (!env || !cf)
    return -1;
  if (!incarnation)
    return 0;   /* rows from before the stamp are nobody's for sure */
  alen = fold_name(akey, aname);
  blen = fold_name(bkey, bname);
  if (alen < 0 || blen < 0)
    return 0;
  if (!strcmp(akey, bkey))
    return 1;

  /* The usual case first: the channel still has one of the two names. */
  n = rec_read(env, cf, NULL, akey, (size_t)alen, ents);
  if (n < 0)
    return -1;
  if (rec_takes(akey, ents, n, bkey, b_ms, incarnation))
    return 1;
  n = rec_read(env, cf, NULL, bkey, (size_t)blen, ents);
  if (n < 0)
    return -1;
  if (rec_takes(bkey, ents, n, akey, a_ms, incarnation))
    return 1;

  /* It moved on from both: the record is under whatever name it has now.
   * A walk of the column family -- one small record per renamed channel
   * -- asked only when a REDACT row's original turned up under another
   * name (hren_find_parent). */
  it = db_iter_open(env, cf, NULL);
  if (!it)
    return -1;
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it) && !yes;
       rc = db_iter_next(it)) {
    char key[CHANNELLEN + 1];
    size_t klen, vlen;
    const void *k = db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);

    if (!k || klen == 0 || klen > CHANNELLEN)
      continue;
    memcpy(key, k, klen);
    key[klen] = '\0';
    n = rec_decode(v, vlen, ents);
    yes = rec_takes(key, ents, n, akey, a_ms, incarnation)
          && rec_takes(key, ents, n, bkey, b_ms, incarnation);
  }
  db_iter_close(it);
  if (yes)
    return 1;
  return rc == DB_OK || rc == DB_NOTFOUND ? 0 : -1;
}

int hren_find_parent(struct db_env *env, struct db_cf *cf,
                     struct db_cf *msgid_index, struct db_cf *messages,
                     hren_row_inc_fn inc_fn, const char *child_name,
                     uint64_t child_ms, uint64_t incarnation,
                     const char *parent_msgid, char *name, char *ts, size_t tssz)
{
  char childkey[CHANNELLEN + 1];
  char lo[HREN_TAIL_MAX + 2], hi[HREN_TAIL_MAX + 2];
  struct db_iter *it;
  size_t mlen;
  int rc, failed = 0, found = 0;

  if (!env || !cf || !msgid_index || !messages || !inc_fn || !name || !ts
      || !tssz)
    return -1;
  if (!incarnation || !parent_msgid || !*parent_msgid
      || fold_name(childkey, child_name) < 0)
    return 0;
  mlen = strlen(parent_msgid);
  if (mlen > HREN_TAIL_MAX)
    return 0;

  /* Every name that holds the msgid: the index keys msgid \0 name. */
  memcpy(lo, parent_msgid, mlen);
  lo[mlen] = '\0';
  memcpy(hi, parent_msgid, mlen);
  hi[mlen] = '\x01';
  it = db_iter_open_bounded(env, msgid_index, NULL, lo, mlen + 1, hi, mlen + 1);
  if (!it)
    return -1;
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it) && !found;
       rc = db_iter_next(it)) {
    char held[CHANNELLEN + 1], pts[HREN_TS_LEN];
    char mk[CHANNELLEN + 2 + HREN_TAIL_MAX + HREN_TS_LEN];
    struct db_val row = { NULL, 0 };
    size_t klen, vlen, nlen;
    const char *k = (const char *)db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);
    uint64_t pms;
    int mkl, grc, same;

    if (!k || klen <= mlen + 1 || memcmp(k, lo, mlen + 1) != 0)
      continue;
    nlen = klen - mlen - 1;
    if (nlen > CHANNELLEN || !v || vlen == 0 || vlen >= sizeof pts
        || vlen >= tssz)
      continue;   /* a PM pair's key, or no timestamp to go by */
    memcpy(held, k + mlen + 1, nlen);
    held[nlen] = '\0';
    if (!strcmp(held, childkey))
      continue;   /* the REDACT row's own name: the caller looked there */
    memcpy(pts, v, vlen);
    pts[vlen] = '\0';
    pms = htc_parse_ms(pts);
    mkl = htc_msg_key(mk, sizeof mk, held, pts, parent_msgid);
    if (mkl <= 0)
      continue;
    grc = db_get(env, messages, mk, (size_t)mkl, NULL, &row);
    if (grc != DB_OK) {
      if (grc != DB_NOTFOUND)
        failed = 1;
      continue;
    }
    same = inc_fn(row.base, row.len) == incarnation;
    db_val_free(&row);
    if (!same)
      continue;
    same = hren_same_channel(env, cf, childkey, child_ms, held, pms,
                             incarnation);
    if (same < 0)
      failed = 1;
    if (same == 1) {
      memcpy(name, held, nlen + 1);
      memcpy(ts, pts, vlen + 1);
      found = 1;
    }
  }
  db_iter_close(it);
  if (found)
    return 1;
  if (rc != DB_OK && rc != DB_NOTFOUND)
    failed = 1;
  return failed ? -1 : 0;
}

int hren_lookup(struct db_env *env, struct db_cf *cf, struct db_snapshot *snap,
                const char *name, uint64_t incarnation, uint64_t floor_ms,
                struct hren_span *out)
{
  struct hren_seg ents[HREN_REC_MAX];
  char key[CHANNELLEN + 1];
  int klen, n, i;

  if (!out)
    return -1;
  out->count = 0;
  if (!env || !cf)
    return -1;
  klen = fold_name(key, name);
  if (klen < 0)
    return 0;   /* longer than any stored name: never renamed */
  n = rec_read(env, cf, snap, key, (size_t)klen, ents);
  if (n < 0)
    return -1;
  n = ents_floor(ents, n, floor_ms);
  qsort(ents, (size_t)n, sizeof ents[0], ent_cmp);
  for (i = 0; i < n && out->count < HREN_MAX_SEGS; i++) {
    if (incarnation && ents[i].incarnation != incarnation)
      continue;
    if (!strcmp(ents[i].name, key))
      continue;
    out->seg[out->count++] = ents[i];
  }
  return out->count;
}

int hren_forget(struct db_env *env, struct db_cf *cf, const char *name,
                uint64_t incarnation)
{
  struct hren_seg ents[HREN_REC_MAX];
  char key[CHANNELLEN + 1];
  struct db_writebatch *wb;
  int klen, n, i, k = 0, rc;

  if (!env || !cf)
    return -1;
  klen = fold_name(key, name);
  if (klen < 0)
    return 0;
  n = rec_read(env, cf, NULL, key, (size_t)klen, ents);
  if (n < 0)
    return -1;
  for (i = 0; i < n; i++)
    if (ents[i].incarnation != incarnation)
      ents[k++] = ents[i];
  if (k == n)
    return 0;
  wb = db_writebatch_new(env);
  if (!wb)
    return -1;
  rc = rec_stage(wb, cf, key, (size_t)klen, ents, k);
  if (rc == DB_OK)
    rc = db_writebatch_commit(wb, 0);
  db_writebatch_destroy(wb);
  return rc == DB_OK ? 0 : -1;
}

int hren_sweep(struct db_env *env, struct db_cf *cf, uint64_t floor_ms)
{
  struct hren_seg ents[HREN_REC_MAX];
  struct db_writebatch *wb;
  struct db_iter *it;
  int dropped = 0, rc;

  if (!env || !cf)
    return -1;
  if (!floor_ms)
    return 0;
  it = db_iter_open(env, cf, NULL);
  if (!it)
    return -1;
  wb = db_writebatch_new(env);
  if (!wb) {
    db_iter_close(it);
    return -1;
  }
  /* One batch: the column family holds a small record per renamed
   * channel that still has rows under an earlier name. */
  for (rc = db_iter_seek_first(it);
       rc == DB_OK && db_iter_valid(it);
       rc = db_iter_next(it)) {
    size_t klen, vlen;
    const void *k = db_iter_key(it, &klen);
    const void *v = db_iter_value(it, &vlen);
    int n, kept;

    /* A record this build cannot read is another build's: left alone. */
    n = rec_decode(v, vlen, ents);
    if (n == 0)
      continue;
    kept = ents_floor(ents, n, floor_ms);
    if (kept == n)
      continue;
    if (rec_stage(wb, cf, (const char *)k, klen, ents, kept) != DB_OK) {
      rc = DB_ERR_OTHER;
      break;
    }
    dropped += n - kept;
  }
  db_iter_close(it);
  if (rc != DB_OK && rc != DB_NOTFOUND) {
    db_writebatch_destroy(wb);
    return -1;
  }
  rc = dropped ? db_writebatch_commit(wb, 0) : DB_OK;
  db_writebatch_destroy(wb);
  return rc == DB_OK ? dropped : -1;
}

/* ------------------------------------------------------------------ */
/* The walk                                                            */
/* ------------------------------------------------------------------ */

/** Which way the walk's iterators stand around its current row. */
enum hren_dir {
  HREN_FWD,   /**< each at its first row at or after the current one */
  HREN_REV    /**< each at its last row at or before it */
};

/** One name's rows: sub 0 is the target's own, the others its segments. */
struct hren_sub {
  struct db_iter *it;
  char prefix[CHANNELLEN + 2];    /**< fold(name) \0 */
  size_t plen;
  const struct hren_seg *seg;     /**< NULL for the target's own rows */
  int valid;                      /**< stands on a row that counts */
};

struct hren_iter {
  struct hren_span span;          /**< the subs' segments point in here */
  struct hren_sub sub[1 + HREN_MAX_SEGS];
  int nsub;
  int cur;                        /**< the sub the current row is in, or -1 */
  enum hren_dir dir;
  int err;                        /**< a backend error ended the walk */
  hren_row_inc_fn inc_fn;
  char key[CHANNELLEN + 2 + HREN_TAIL_MAX];   /**< the canonical key */
};

static void fmt_ts(char *buf, size_t size, uint64_t ms)
{
  snprintf(buf, size, "%llu.%03llu", (unsigned long long)(ms / 1000),
           (unsigned long long)(ms % 1000));
}

/** The part of @a sub's current key after its name, or NULL. */
static const char *sub_tail(const struct hren_sub *sub, size_t *tlen)
{
  size_t klen;
  const char *k = (const char *)db_iter_key(sub->it, &klen);

  if (!k || klen < sub->plen)
    return NULL;
  *tlen = klen - sub->plen;
  return k + sub->plen;
}

/** Does the row @a sub stands on count?  The target's own rows all do.
 * A segment's must carry its incarnation: the range its iterator is
 * bounded to can hold another channel's rows (one made behind a split
 * that later lost the burst, or rows from before incarnations were
 * stamped). */
static int sub_row_counts(const struct hren_iter *it, const struct hren_sub *sub)
{
  size_t tlen, vlen;
  const void *v;

  if (!sub_tail(sub, &tlen) || tlen > HREN_TAIL_MAX)
    return 0;
  if (!sub->seg)
    return 1;
  v = db_iter_value(sub->it, &vlen);
  return v && it->inc_fn && it->inc_fn(v, vlen) == sub->seg->incarnation;
}

/** @a sub was just positioned (@a rc): step on in @a dir past rows that
 * do not count, and note whether it stands on one. */
static void sub_settle(struct hren_iter *it, struct hren_sub *sub, int rc,
                       enum hren_dir dir)
{
  while (rc == DB_OK && db_iter_valid(sub->it) && !sub_row_counts(it, sub))
    rc = dir == HREN_FWD ? db_iter_next(sub->it) : db_iter_prev(sub->it);
  if (rc != DB_OK && rc != DB_NOTFOUND && !it->err)
    it->err = rc;
  sub->valid = rc == DB_OK && db_iter_valid(sub->it);
}

/** Order two key tails as the keys they end: bytes, then length. */
static int tail_cmp(const char *a, size_t alen, const char *b, size_t blen)
{
  int c = memcmp(a, b, alen < blen ? alen : blen);

  if (c)
    return c;
  return alen < blen ? -1 : alen > blen;
}

/** Choose the current row among the subs: going forwards the least
 * (the lowest sub among equals), going back the greatest (the highest
 * sub among equals) -- one total order, (tail, sub), in both directions.
 * @return DB_OK, DB_NOTFOUND, or the error that ended the walk. */
static int pick(struct hren_iter *it)
{
  const char *best = NULL;
  size_t bestlen = 0;
  int i;

  it->cur = -1;
  if (it->err)
    return it->err;
  for (i = 0; i < it->nsub; i++) {
    const char *t;
    size_t tlen;
    int c;

    if (!it->sub[i].valid || !(t = sub_tail(&it->sub[i], &tlen)))
      continue;
    if (best) {
      c = tail_cmp(t, tlen, best, bestlen);
      if (it->dir == HREN_FWD ? c >= 0 : c < 0)
        continue;
    }
    best = t;
    bestlen = tlen;
    it->cur = i;
  }
  return it->cur >= 0 ? DB_OK : DB_NOTFOUND;
}

/** Seek @a sub to its own key for @a tail.
 * @return The backend's status. */
static int sub_seek(struct hren_sub *sub, const char *tail, size_t tlen)
{
  char key[CHANNELLEN + 2 + HREN_TAIL_MAX];

  if (tlen > HREN_TAIL_MAX)
    return DB_ERR_OTHER;
  memcpy(key, sub->prefix, sub->plen);
  memcpy(key + sub->plen, tail, tlen);
  return db_iter_seek(sub->it, key, sub->plen + tlen);
}

struct hren_iter *hren_iter_open(struct db_env *env, struct db_cf *messages,
                                 struct db_snapshot *snap, const char *target,
                                 const struct hren_span *span,
                                 hren_row_inc_fn inc_fn)
{
  struct hren_iter *it;
  char upper[CHANNELLEN + 2];
  int plen, i;

  if (!env || !messages || !target)
    return NULL;
  it = (struct hren_iter *)calloc(1, sizeof *it);
  if (!it)
    return NULL;
  it->cur = -1;
  it->dir = HREN_FWD;
  it->inc_fn = inc_fn;
  if (span && inc_fn)
    it->span = *span;
  if (it->span.count > HREN_MAX_SEGS)
    it->span.count = HREN_MAX_SEGS;

  /* The target's own rows: exactly its prefix, fold(target) \0 up to
   * (not including) fold(target) \x01, so a seek that finds nothing
   * stops at the range's end instead of walking the next target's
   * aged-out head (history.c's history_prefix_iter). */
  plen = htc_msg_key(it->sub[0].prefix, sizeof it->sub[0].prefix, target,
                     NULL, NULL);
  if (plen <= 0) {
    free(it);
    return NULL;
  }
  it->sub[0].plen = (size_t)plen;
  memcpy(upper, it->sub[0].prefix, (size_t)plen);
  upper[plen - 1] = '\x01';
  it->sub[0].it = db_iter_open_bounded(env, messages, snap, it->sub[0].prefix,
                                       (size_t)plen, upper, (size_t)plen);
  if (!it->sub[0].it) {
    free(it);
    return NULL;
  }
  it->nsub = 1;

  /* Each segment: the earlier name's rows from the incarnation's
   * creation (none of its rows is older: history_purge_incarnation
   * starts there too) to the millisecond it left the name. */
  for (i = 0; i < it->span.count; i++) {
    const struct hren_seg *seg = &it->span.seg[i];
    struct hren_sub *sub = &it->sub[it->nsub];
    char lo[CHANNELLEN + 2 + HREN_TS_LEN], hi[CHANNELLEN + 2 + HREN_TS_LEN];
    char ts[HREN_TS_LEN];
    int lolen, hilen;

    plen = htc_msg_key(sub->prefix, sizeof sub->prefix, seg->name, NULL, NULL);
    fmt_ts(ts, sizeof ts, seg->incarnation * 1000ULL);
    lolen = htc_msg_key(lo, sizeof lo, seg->name, ts, NULL);
    fmt_ts(ts, sizeof ts, seg->until_ms + 1);
    hilen = htc_msg_key(hi, sizeof hi, seg->name, ts, NULL);
    if (plen <= 0 || lolen <= 0 || hilen <= 0)
      continue;
    sub->it = db_iter_open_bounded(env, messages, snap, lo, (size_t)lolen,
                                   hi, (size_t)hilen);
    if (!sub->it) {
      hren_iter_close(it);
      return NULL;
    }
    sub->plen = (size_t)plen;
    sub->seg = seg;
    it->nsub++;
  }
  return it;
}

void hren_iter_close(struct hren_iter *it)
{
  int i;

  if (!it)
    return;
  for (i = 0; i < it->nsub; i++)
    db_iter_close(it->sub[i].it);
  free(it);
}

int hren_iter_seek(struct hren_iter *it, const void *key, size_t klen)
{
  const struct hren_sub *own;
  const char *tail;
  size_t tlen;
  int i;

  if (!it)
    return DB_ERR_OTHER;
  own = &it->sub[0];
  if (!key || klen < own->plen || memcmp(key, own->prefix, own->plen) != 0)
    return DB_ERR_OTHER;   /* not a key of this target */
  tail = (const char *)key + own->plen;
  tlen = klen - own->plen;
  it->dir = HREN_FWD;
  for (i = 0; i < it->nsub; i++)
    sub_settle(it, &it->sub[i], sub_seek(&it->sub[i], tail, tlen), HREN_FWD);
  return pick(it);
}

int hren_iter_seek_first(struct hren_iter *it)
{
  int i;

  if (!it)
    return DB_ERR_OTHER;
  it->dir = HREN_FWD;
  for (i = 0; i < it->nsub; i++)
    sub_settle(it, &it->sub[i], db_iter_seek_first(it->sub[i].it), HREN_FWD);
  return pick(it);
}

int hren_iter_seek_last(struct hren_iter *it)
{
  int i;

  if (!it)
    return DB_ERR_OTHER;
  it->dir = HREN_REV;
  for (i = 0; i < it->nsub; i++)
    sub_settle(it, &it->sub[i], db_iter_seek_last(it->sub[i].it), HREN_REV);
  return pick(it);
}

/** The walk turns around at its current row: every other sub is put on
 * the far side of it in the order (tail, sub) -- going back, its last
 * row before the current one; going forwards, its first after. */
static void turn(struct hren_iter *it, enum hren_dir dir)
{
  char tail[HREN_TAIL_MAX];
  const char *t;
  size_t tlen;
  int i;

  t = sub_tail(&it->sub[it->cur], &tlen);
  if (!t || tlen > sizeof tail) {
    it->err = DB_ERR_OTHER;
    return;
  }
  memcpy(tail, t, tlen);
  for (i = 0; i < it->nsub; i++) {
    struct hren_sub *sub = &it->sub[i];
    const char *st;
    size_t stlen;
    int rc, same;

    if (i == it->cur)
      continue;
    rc = sub_seek(sub, tail, tlen);
    same = rc == DB_OK && (st = sub_tail(sub, &stlen))
           && tail_cmp(st, stlen, tail, tlen) == 0;
    if (dir == HREN_REV) {
      /* At or after the current row: step back before it, unless it is
       * the same key in a lower sub (that one comes before). */
      if (rc == DB_NOTFOUND)
        rc = db_iter_seek_last(sub->it);
      else if (rc == DB_OK && !(same && i < it->cur))
        rc = db_iter_prev(sub->it);
    } else if (rc == DB_OK && same && i < it->cur) {
      rc = db_iter_next(sub->it);   /* the same key in a lower sub: passed */
    }
    sub_settle(it, sub, rc, dir);
  }
  it->dir = dir;
}

int hren_iter_next(struct hren_iter *it)
{
  struct hren_sub *sub;

  if (!it)
    return DB_ERR_OTHER;
  if (it->cur < 0)
    return it->err ? it->err : DB_NOTFOUND;
  if (it->dir != HREN_FWD)
    turn(it, HREN_FWD);
  sub = &it->sub[it->cur];
  sub_settle(it, sub, db_iter_next(sub->it), HREN_FWD);
  return pick(it);
}

int hren_iter_prev(struct hren_iter *it)
{
  struct hren_sub *sub;

  if (!it)
    return DB_ERR_OTHER;
  if (it->cur < 0)
    return it->err ? it->err : DB_NOTFOUND;
  if (it->dir != HREN_REV)
    turn(it, HREN_REV);
  sub = &it->sub[it->cur];
  sub_settle(it, sub, db_iter_prev(sub->it), HREN_REV);
  return pick(it);
}

int hren_iter_valid(const struct hren_iter *it)
{
  return it && it->cur >= 0;
}

const void *hren_iter_key(struct hren_iter *it, size_t *klen)
{
  const struct hren_sub *sub;
  const char *tail;
  size_t tlen;

  if (!it || it->cur < 0)
    return NULL;
  sub = &it->sub[it->cur];
  if (it->cur == 0)
    return db_iter_key(sub->it, klen);   /* stored under the target itself */
  tail = sub_tail(sub, &tlen);
  if (!tail || tlen > HREN_TAIL_MAX)
    return NULL;
  memcpy(it->key, it->sub[0].prefix, it->sub[0].plen);
  memcpy(it->key + it->sub[0].plen, tail, tlen);
  if (klen)
    *klen = it->sub[0].plen + tlen;
  return it->key;
}

const void *hren_iter_value(const struct hren_iter *it, size_t *vlen)
{
  if (!it || it->cur < 0)
    return NULL;
  return db_iter_value(it->sub[it->cur].it, vlen);
}

const struct hren_seg *hren_iter_seg(const struct hren_iter *it)
{
  if (!it || it->cur < 0)
    return NULL;
  return it->sub[it->cur].seg;
}

